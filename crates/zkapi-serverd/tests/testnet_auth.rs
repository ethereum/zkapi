use std::sync::Arc;

use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use tower::ServiceExt;
use zkapi_serverd::{
    config::{OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig},
    native_billing::NativeBillingConfig,
    nullifier_store::NullifierStore,
    processor::RequestProcessor,
    routes::create_router,
    signer::ServerSigner,
    testnet_auth::{TestnetPassword, SEPOLIA_CHAIN_ID, TESTNET_PASSWORD_HEADER},
};
use zkapi_types::Felt252;

const PASSWORD: &str = "testnet-integration-password";

fn router(protected: bool) -> axum::Router {
    let config = ServerConfig {
        chain_id: if protected { SEPOLIA_CHAIN_ID } else { 1 },
        contract_address: Felt252::from_u64(123),
        testnet_password: protected.then(|| TestnetPassword::new(PASSWORD).unwrap()),
        openrouter_leases: Some(OpenRouterLeaseConfig {
            source: OpenRouterLeaseSourceConfig::OpenRouter {
                management_key: "test-management-key".into(),
                api_base: "http://127.0.0.1:9".into(),
            },
            ttl_seconds: 300,
            settlement_grace_seconds: 5,
            settlement_poll_seconds: 5,
        }),
        native_billing: Some(NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x0000000000000000000000000000000000000001".into(),
            decimals: 8,
            max_age_seconds: 4500,
        }),
        proof_setup_dir: format!("{}/../../protocol/setup/v2", env!("CARGO_MANIFEST_DIR")),
        ..Default::default()
    };
    create_router(Arc::new(
        RequestProcessor::try_new(
            config,
            Arc::new(NullifierStore::in_memory().unwrap()),
            Arc::new(ServerSigner::new(&Felt252::ONE, &Felt252::from_u64(2))),
            Felt252::ZERO,
        )
        .unwrap(),
    ))
}

#[tokio::test]
async fn all_service_routes_reject_missing_or_wrong_password_before_body_parsing() {
    let app = router(true);
    for (method, path) in [
        ("GET", "/v2/auth"),
        ("POST", "/v2/requests"),
        ("GET", "/v2/billing/quote"),
        ("GET", "/v2/time"),
        ("POST", "/v2/openrouter/leases"),
        ("GET", "/v2/openrouter/leases/example"),
        ("POST", "/v2/openrouter/leases/example"),
        ("POST", "/v2/openrouter/leases/example/expire"),
        ("POST", "/v2/withdraw/clearance"),
        ("GET", "/v2/requests/example"),
        ("GET", "/v2/nullifiers/invalid"),
        ("GET", "/v1/dashboard/summary"),
        ("GET", "/v1/dashboard/recent"),
        ("GET", "/v1/dashboard/events"),
        ("POST", "/health"),
        ("GET", "/unknown-future-service"),
    ] {
        for candidate in [None, Some("incorrect-test-password")] {
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json");
            if let Some(candidate) = candidate {
                request = request.header(TESTNET_PASSWORD_HEADER, candidate);
            }
            let response = app
                .clone()
                .oneshot(request.body(Body::from("not json")).unwrap())
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
            let body: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap())
                    .unwrap();
            assert_eq!(body["error_code"], "testnet_password_required");
            assert_eq!(body["retriable"], false);
            assert!(!body.to_string().contains("incorrect-test-password"));
        }
    }
}

#[tokio::test]
async fn authentication_is_exact_and_allows_authenticated_handlers() {
    let app = router(true);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/auth")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body, serde_json::json!({"authenticated": true}));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v2/auth")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .header(TESTNET_PASSWORD_HEADER, "duplicate")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/openrouter/leases")
                .header(TESTNET_PASSWORD_HEADER, PASSWORD)
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn health_and_attestation_stay_public_with_no_store_and_browser_preflight_works() {
    let app = router(true);
    for path in ["/", "/health", "/v1/attestation"] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("origin", "https://client.example")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert_eq!(response.headers()["access-control-allow-origin"], "*");
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
        if path != "/v1/attestation" {
            assert_eq!(body["testnet_password_required"], true);
            assert_eq!(body["chain_id"], SEPOLIA_CHAIN_ID);
        }
        assert!(!body.to_string().contains(PASSWORD));
    }
    let response = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v2/openrouter/leases")
                .header("origin", "https://client.example")
                .header("access-control-request-method", "POST")
                .header(
                    "access-control-request-headers",
                    "content-type,x-zkapi-testnet-password",
                )
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_success());
    assert_eq!(response.headers()["access-control-allow-origin"], "*");
    assert!(response.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .contains(TESTNET_PASSWORD_HEADER));
    assert!(!response
        .headers()
        .contains_key("access-control-allow-credentials"));
}

#[tokio::test]
async fn mainnet_remains_ungated_and_rejects_accidental_password_configuration() {
    let app = router(false);
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_eq!(body["testnet_password_required"], false);
    assert_eq!(body["chain_id"], 1);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v2/openrouter/leases")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let config = ServerConfig {
        testnet_password: Some(TestnetPassword::new(PASSWORD).unwrap()),
        ..Default::default()
    };
    assert!(config.validate_testnet_auth().is_err());
}

async fn time_response(
    app: &axum::Router,
    method: &str,
    password: Option<&str>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri("/v2/time")
        .header("origin", "https://client.example");
    if let Some(password) = password {
        request = request.header(TESTNET_PASSWORD_HEADER, password);
    }
    app.clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .unwrap()
}

fn assert_time_body(body: &serde_json::Value, chain_id: u64) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let server = body["server_time_ms"].as_u64().unwrap();
    assert!(server <= now && now - server < 5_000);
    assert_eq!(body["chain_id"], chain_id);
    assert_eq!(body["max_request_age_seconds"], 300);
    assert_eq!(body["max_future_skew_seconds"], 30);
    assert_eq!(
        body.as_object().unwrap().len(),
        5,
        "no identifiers or state: {body}"
    );
}

#[tokio::test]
async fn ungated_server_time_is_public_non_cacheable_and_browser_readable() {
    let app = router(false);
    let response = time_response(&app, "GET", None).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response
            .headers()
            .get_all("access-control-allow-origin")
            .iter()
            .collect::<Vec<_>>(),
        ["*"]
    );
    assert!(!response
        .headers()
        .contains_key("access-control-allow-credentials"));
    assert!(!response.headers().contains_key("set-cookie"));
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_time_body(&body, 1);

    let head = time_response(&app, "HEAD", None).await;
    assert_eq!(head.status(), StatusCode::OK);
    assert_eq!(head.headers()["cache-control"], "no-store");
    // Mutating methods do not exist on this read-only route.
    assert_eq!(
        time_response(&app, "POST", None).await.status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[tokio::test]
async fn gated_server_time_requires_the_password_and_keeps_single_cors_policy() {
    let app = router(true);
    assert_eq!(
        time_response(&app, "GET", None).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let response = time_response(&app, "GET", Some(PASSWORD)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(
        response
            .headers()
            .get_all("access-control-allow-origin")
            .iter()
            .collect::<Vec<_>>(),
        ["*"]
    );
    let body: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap();
    assert_time_body(&body, SEPOLIA_CHAIN_ID);
    assert!(!body.to_string().contains(PASSWORD));
    let preflight = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/v2/time")
                .header("origin", "https://client.example")
                .header("access-control-request-method", "GET")
                .header("access-control-request-headers", TESTNET_PASSWORD_HEADER)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(preflight.status().is_success());
    assert!(preflight.headers()["access-control-allow-headers"]
        .to_str()
        .unwrap()
        .contains(TESTNET_PASSWORD_HEADER));
}
