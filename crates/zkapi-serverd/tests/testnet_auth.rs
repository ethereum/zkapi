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

fn config(protected: bool) -> ServerConfig {
    ServerConfig {
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
            settlement_deadline_seconds: zkapi_serverd::config::DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
        }),
        native_billing: Some(NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x0000000000000000000000000000000000000001".into(),
            decimals: 8,
            max_age_seconds: 4500,
        }),
        proof_setup_dir: format!(
            "{}/../../protocol/setup/v2-concession-dev",
            env!("CARGO_MANIFEST_DIR")
        ),
        ..Default::default()
    }
}

fn router(protected: bool) -> axum::Router {
    create_router(Arc::new(
        RequestProcessor::try_new(
            config(protected),
            Arc::new(NullifierStore::in_memory().unwrap()),
            // Fixture seeds: serving processors refuse the published 0x1/0x2 keys.
            Arc::new(ServerSigner::new(
                &Felt252::from_u64(7),
                &Felt252::from_u64(8),
            )),
            Felt252::ZERO,
        )
        .unwrap(),
    ))
}

#[test]
fn serving_processors_refuse_the_published_development_keys() {
    for (state, clearance) in [(1, 2), (2, 1), (7, 7)] {
        let error = RequestProcessor::try_new(
            config(false),
            Arc::new(NullifierStore::in_memory().unwrap()),
            Arc::new(ServerSigner::new(
                &Felt252::from_u64(state),
                &Felt252::from_u64(clearance),
            )),
            Felt252::ZERO,
        )
        .err()
        .expect("a serving processor accepted a published or reused key")
        .to_string();
        assert!(
            error.contains("refusing to serve"),
            "seeds {state:#x}/{clearance:#x}: {error}"
        );
    }
}

#[tokio::test]
async fn all_service_routes_reject_missing_or_wrong_password_before_body_parsing() {
    let app = router(true);
    for (method, path) in [
        ("GET", "/v2/auth"),
        ("POST", "/v2/requests"),
        ("GET", "/v2/billing/quote"),
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
        ("GET", "/v1/dashboard/settlement"),
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
