//! Axum HTTP routes for the zkAPI server.
//!
//! Endpoints:
//! - GET  /health                   -- process health and config summary
//! - GET  /v1/attestation           -- published signer metadata for deployments
//! - GET  /v2/time                  -- non-cacheable server clock for request_time
//! - POST /v2/openrouter/leases     -- open a prompt-private runtime-key lease
//! - POST /v2/openrouter/leases/:id -- retire a rejected runtime-key lease
//! - POST /v2/withdraw/clearance    -- request mutual-close clearance
//! - GET  /v2/requests/:id          -- recover by client_request_id
//! - GET  /v2/nullifiers/:nullifier -- recover by nullifier

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::RETRY_AFTER;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::Stream;
use serde::Serialize;
use tower_http::cors::{Any, CorsLayer};

use zkapi_types::wire::{
    ApiRequestV2, ClearanceRequest, ClearanceResponseV2, CurvePointWire, ErrorResponse,
    OpenRouterLeaseStatusResponse, RecoveryResponseV2,
};
use zkapi_types::Felt252;

use crate::dashboard::{DashboardEvent, DashboardHub, DashboardTotals};
use crate::error::ServerError;
use crate::oa_org::IssuedOpenRouterLease;
use crate::processor::RequestProcessor;
use crate::testnet_auth::{
    handle_auth_check, require_testnet_password, TestnetPassword, TESTNET_PASSWORD_HEADER,
};

/// Shared application state.
type AppState = Arc<RequestProcessor>;

// Keep handler error variants small without changing their status, headers or body.
struct ErrorHttpResponse(Box<(StatusCode, HeaderMap, Json<ErrorResponse>)>);

impl IntoResponse for ErrorHttpResponse {
    fn into_response(self) -> Response {
        (*self.0).into_response()
    }
}

// Compact proofs are small; leave headroom for ordinary API payloads.
const PROTOCOL_BODY_LIMIT_BYTES: usize = 1024 * 1024;

/// Start the HTTP server with the given config.
pub async fn run_server(mut config: crate::config::ServerConfig) -> anyhow::Result<()> {
    if let Some(password) = TestnetPassword::from_env()? {
        config.testnet_password = Some(password);
    }
    config.validate_native_mode()?;
    let store = Arc::new(crate::nullifier_store::NullifierStore::new(
        &config.db_path,
    )?);
    let signer = Arc::new(crate::signer::ServerSigner::new(
        &config.state_seed,
        &config.clear_seed,
    ));
    let initial_root = if let Some(indexer_url) = config.indexer_url.as_deref() {
        match fetch_indexer_root(indexer_url).await {
            Ok(root) => root,
            Err(err) => {
                tracing::warn!("failed to fetch initial root from indexer: {}", err);
                config.initial_root
            }
        }
    } else {
        config.initial_root
    };
    let dashboard = Arc::new(DashboardHub::new(500));
    let processor = Arc::new(
        RequestProcessor::try_new(config.clone(), store, signer, initial_root)?
            .with_dashboard(dashboard),
    );
    if let Some(indexer_url) = config.indexer_url.clone() {
        spawn_root_poller(
            processor.clone(),
            indexer_url,
            Duration::from_millis(config.root_poll_interval_ms),
        );
    }
    if let Some(lease) = config.openrouter_leases.as_ref() {
        spawn_openrouter_lease_settler(
            processor.clone(),
            Duration::from_secs(lease.settlement_poll_seconds.max(1)),
        );
    }
    let router = create_router(processor);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Server listening on {}", config.listen_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

/// Create the Axum router with all zkAPI server routes.
pub fn create_router(processor: Arc<RequestProcessor>) -> Router {
    let password = processor.config().testnet_password.clone();
    // Preserve the local dashboard's existing CORS policy. Password-gated
    // Sepolia additionally permits explicit credential headers below.
    let dashboard = Router::new()
        .route("/v1/dashboard/summary", get(handle_dashboard_summary))
        .route("/v1/dashboard/recent", get(handle_dashboard_recent))
        .route("/v1/dashboard/events", get(handle_dashboard_events))
        .layer(CorsLayer::very_permissive());

    // Read-only, state-free server clock for new clients. Ungated deployments
    // give it the same simple GET/HEAD CORS as /health so a direct browser
    // read works; a Sepolia gate keeps it behind the password and its outer
    // CORS policy alone, so the response never carries duplicate CORS headers.
    let time = Router::new().route("/v2/time", get(handle_server_time));
    let time = if password.is_some() {
        time
    } else {
        time.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD]),
        )
    };

    let router = Router::new()
        .route("/", get(handle_health))
        .route("/health", get(handle_health))
        .route("/v1/attestation", get(handle_attestation))
        .layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD]),
        )
        .route("/v2/auth", get(handle_auth_check))
        .route("/v2/billing/quote", get(handle_native_billing_quote))
        .route("/v2/openrouter/leases", post(handle_openrouter_lease))
        .route(
            "/v2/openrouter/leases/{client_request_id}",
            get(handle_openrouter_lease_status).post(handle_openrouter_lease_retirement),
        )
        .route(
            "/v2/openrouter/leases/{client_request_id}/expire",
            post(handle_native_lease_expiry),
        )
        .route("/v2/withdraw/clearance", post(handle_clearance))
        .route(
            "/v2/requests/{client_request_id}",
            get(handle_recovery_by_id),
        )
        .route(
            "/v2/nullifiers/{nullifier}",
            get(handle_recovery_by_nullifier),
        )
        .merge(time)
        .merge(dashboard)
        .layer(DefaultBodyLimit::max(PROTOCOL_BODY_LIMIT_BYTES))
        .layer(middleware::from_fn_with_state(
            password.clone(),
            require_testnet_password,
        ))
        .with_state(processor);

    if password.is_some() {
        // The shared password is not an account cookie; no credentialed CORS.
        router.layer(
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods([Method::GET, Method::HEAD, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderName::from_static(TESTNET_PASSWORD_HEADER),
                ]),
        )
    } else {
        router
    }
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    indexer_url: Option<String>,
    policy_enabled: bool,
    auth_scheme: &'static str,
    request_modes: Vec<&'static str>,
    testnet_password_required: bool,
}

#[derive(Debug, Serialize)]
struct AttestationResponse {
    status: &'static str,
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
    auth_scheme: &'static str,
}

async fn handle_health(State(processor): State<AppState>) -> Json<HealthResponse> {
    let config = processor.config();
    Json(HealthResponse {
        status: "ok",
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        provider: "native_leases",
        indexer_url: config.indexer_url.clone(),
        policy_enabled: false,
        auth_scheme: "state-anchor",
        request_modes: vec!["direct_openrouter"],
        testnet_password_required: config.testnet_password.is_some(),
    })
}

async fn handle_attestation(State(processor): State<AppState>) -> Json<AttestationResponse> {
    let config = processor.config();
    Json(AttestationResponse {
        status: "ok",
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
        auth_scheme: "state-anchor",
    })
}

async fn handle_openrouter_lease(
    State(processor): State<AppState>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<(StatusCode, Json<IssuedOpenRouterLease>), ErrorHttpResponse> {
    processor
        .issue_openrouter_lease(&api_request)
        .await
        .map(|response| (StatusCode::CREATED, Json(response)))
        .map_err(|error| error_to_response(&error, &api_request.client_request_id, &processor))
}

async fn handle_openrouter_lease_status(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, StatusCode> {
    processor
        .openrouter_lease_status(&client_request_id)
        .map(Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn handle_openrouter_lease_retirement(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
    Json(api_request): Json<ApiRequestV2>,
) -> Result<Json<OpenRouterLeaseStatusResponse>, ErrorHttpResponse> {
    processor
        .retire_openrouter_lease(&client_request_id, &api_request)
        .await
        .map(Json)
        .map_err(|error| error_to_response(&error, &client_request_id, &processor))
}

/// POST /v1/withdraw/clearance -- request a clearance signature.
async fn handle_clearance(
    State(processor): State<AppState>,
    Json(clearance_req): Json<ClearanceRequest>,
) -> Result<Json<ClearanceResponseV2>, ErrorHttpResponse> {
    processor
        .process_clearance(&clearance_req)
        .map(Json)
        .map_err(|e| {
            error_to_response(&e, &clearance_req.withdrawal_nullifier.to_hex(), &processor)
        })
}

/// GET /v1/requests/:client_request_id -- recover a response by client request ID.
async fn handle_recovery_by_id(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    processor
        .recover_by_client_id(&client_request_id)
        .map(Json)
        .map_err(|e| error_to_response(&e, &client_request_id, &processor))
}

/// GET /v1/nullifiers/:nullifier -- recover a response by nullifier hex.
async fn handle_recovery_by_nullifier(
    State(processor): State<AppState>,
    Path(nullifier_hex): Path<String>,
) -> Result<Json<RecoveryResponseV2>, ErrorHttpResponse> {
    let nullifier = Felt252::from_hex(&nullifier_hex).map_err(|e| {
        let err = ServerError::InvalidRequest(format!("invalid nullifier hex: {}", e));
        error_to_response(&err, &nullifier_hex, &processor)
    })?;

    processor
        .recover_by_nullifier(&nullifier)
        .map(Json)
        .map_err(|e| error_to_response(&e, &nullifier_hex, &processor))
}

async fn handle_native_lease_expiry(
    State(processor): State<AppState>,
    Path(client_request_id): Path<String>,
    Json(request): Json<ApiRequestV2>,
) -> Result<(HeaderMap, Json<serde_json::Value>), ErrorHttpResponse> {
    let status = processor
        .expire_unaccepted_native_lease(&client_request_id, &request)
        .await
        .map_err(|error| error_to_response(&error, &client_request_id, &processor))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok((headers, Json(status)))
}

async fn handle_server_time(
    State(processor): State<AppState>,
) -> (HeaderMap, Json<crate::processor::ServerTimeResponse>) {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    (headers, Json(processor.server_time()))
}

async fn handle_native_billing_quote(
    State(processor): State<AppState>,
) -> Result<(HeaderMap, Json<crate::native_billing::NativeBillingQuote>), ErrorHttpResponse> {
    let quote = processor
        .native_billing_quote()
        .await
        .map_err(|error| error_to_response(&error, "billing-quote", &processor))?;
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    Ok((headers, Json(quote)))
}

/// Server identity + signing capacity for the dashboard header panel.
#[derive(Debug, Serialize)]
struct ServerIdentity {
    protocol_version: u16,
    chain_id: u64,
    contract_address: Felt252,
    current_root: Felt252,
    provider: &'static str,
    upstream_kind: Option<String>,
    upstream_api_base: Option<String>,
    auth_scheme: &'static str,
    policy_enabled: bool,
    request_charge_cap: u128,
    request_charge_cap_usd: Option<f64>,
    credits_per_usd: Option<f64>,
    billing_asset: &'static str,
    state_signing_key: CurvePointWire,
    clearance_signing_key: CurvePointWire,
    openrouter_leases_enabled: bool,
}

#[derive(Debug, Serialize)]
struct DashboardSummary {
    server: ServerIdentity,
    totals: DashboardTotals,
    started_ms: u64,
    recent_count: usize,
}

/// GET /v1/dashboard/summary -- server identity + running totals.
async fn handle_dashboard_summary(State(processor): State<AppState>) -> Json<DashboardSummary> {
    let config = processor.config();
    let (upstream_kind, upstream_api_base) = config
        .openrouter_leases
        .as_ref()
        .map(|lease| match &lease.source {
            crate::config::OpenRouterLeaseSourceConfig::OpenRouter { api_base, .. } => {
                (Some("openrouter".to_string()), Some(api_base.clone()))
            }
            crate::config::OpenRouterLeaseSourceConfig::OaOrg { org_base_url, .. } => {
                (Some("oa_org".to_string()), Some(org_base_url.clone()))
            }
        })
        .unwrap_or_default();
    let server = ServerIdentity {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        current_root: processor.current_root(),
        provider: "native_leases",
        upstream_kind,
        upstream_api_base,
        auth_scheme: "state-anchor",
        policy_enabled: false,
        request_charge_cap: config.request_charge_cap,
        request_charge_cap_usd: None,
        credits_per_usd: None,
        billing_asset: "native_eth",
        state_signing_key: processor.state_signing_key(),
        clearance_signing_key: processor.clearance_signing_key(),
        openrouter_leases_enabled: processor.openrouter_leases_enabled(),
    };
    let (totals, started_ms, recent_count) = match processor.dashboard() {
        Some(hub) => (hub.totals(), hub.started_ms, hub.recent().len()),
        None => (DashboardTotals::default(), 0, 0),
    };
    Json(DashboardSummary {
        server,
        totals,
        started_ms,
        recent_count,
    })
}

/// GET /v1/dashboard/recent -- the recent request feed (newest last).
async fn handle_dashboard_recent(State(processor): State<AppState>) -> Json<Vec<DashboardEvent>> {
    let events = processor
        .dashboard()
        .map(|hub| hub.recent())
        .unwrap_or_default();
    Json(events)
}

/// GET /v1/dashboard/events -- Server-Sent-Events stream of live requests.
async fn handle_dashboard_events(
    State(processor): State<AppState>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let rx = processor.dashboard().map(|hub| hub.subscribe());
    let stream = futures_util::stream::unfold(rx, |state| async move {
        let mut rx = state?;
        loop {
            match rx.recv().await {
                Ok(event) => {
                    let data = serde_json::to_string(&event).unwrap_or_default();
                    let sse = Event::default().event("request").data(data);
                    return Some((Ok(sse), Some(rx)));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });
    Sse::new(stream).keep_alive(KeepAlive::default())
}

/// Convert a ServerError into an HTTP error response.
fn error_to_response(
    err: &ServerError,
    client_request_id: &str,
    processor: &RequestProcessor,
) -> ErrorHttpResponse {
    let latest_root = if matches!(err, ServerError::StaleRoot { .. }) {
        Some(processor.current_root())
    } else {
        None
    };
    ErrorHttpResponse(Box::new(build_error_response(
        err,
        client_request_id,
        latest_root,
    )))
}

fn build_error_response(
    err: &ServerError,
    client_request_id: &str,
    latest_root: Option<Felt252>,
) -> (StatusCode, HeaderMap, Json<ErrorResponse>) {
    let status_code = match err {
        ServerError::InvalidProof(_)
        | ServerError::InvalidRequest(_)
        | ServerError::OaKeyPolicyRejected
        | ServerError::ProtocolMismatch(_) => StatusCode::BAD_REQUEST,
        ServerError::StaleRoot { .. }
        | ServerError::NativeQuoteExpired
        | ServerError::NativeQuoteSuperseded => StatusCode::CONFLICT,
        ServerError::Replay | ServerError::NullifierUsed => StatusCode::CONFLICT,
        ServerError::LeasePending | ServerError::LeaseSettlementPending { .. } => {
            StatusCode::CONFLICT
        }
        ServerError::NoteExpired => StatusCode::GONE,
        ServerError::CapacityExhausted => StatusCode::SERVICE_UNAVAILABLE,
        ServerError::Internal(_) | ServerError::Database(_) => StatusCode::INTERNAL_SERVER_ERROR,
        ServerError::OaRateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
    };

    let retry_after_seconds = match err {
        ServerError::OaRateLimited {
            retry_after_seconds,
            ..
        }
        | ServerError::LeaseSettlementPending {
            retry_after_seconds,
        } => Some(*retry_after_seconds),
        _ => None,
    };
    let mut headers = HeaderMap::new();
    if let Some(retry_after_seconds) = retry_after_seconds {
        let retry_after = HeaderValue::from_str(&retry_after_seconds.to_string())
            .expect("a decimal u64 is always a valid Retry-After header");
        headers.insert(RETRY_AFTER, retry_after);
    }

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    let body = ErrorResponse {
        status: "error".to_string(),
        client_request_id: client_request_id.to_string(),
        error_code: err.error_code().to_string(),
        error_message: err.to_string(),
        retriable: err.is_retriable(),
        latest_root,
        server_time_ms: Some(now_ms),
        retry_after_seconds,
    };

    (status_code, headers, Json(body))
}

fn spawn_openrouter_lease_settler(processor: Arc<RequestProcessor>, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            processor.settle_due_openrouter_leases().await;
        }
    });
}

fn spawn_root_poller(processor: Arc<RequestProcessor>, indexer_url: String, interval: Duration) {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            match fetch_indexer_root(&indexer_url).await {
                Ok(root) => processor.update_root(root),
                Err(err) => tracing::warn!("failed to refresh root from indexer: {}", err),
            }
        }
    });
}

async fn fetch_indexer_root(indexer_url: &str) -> anyhow::Result<Felt252> {
    #[derive(serde::Deserialize)]
    struct RootResponse {
        root: Felt252,
    }

    let base = indexer_url.trim_end_matches('/');
    let url = format!("{base}/v1/tree/root");
    let response = reqwest::get(&url).await?;
    let response = response.error_for_status()?;
    Ok(response.json::<RootResponse>().await?.root)
}

#[cfg(test)]
mod rate_limit_tests {
    use super::*;

    #[tokio::test]
    async fn startup_requires_native_billing_before_opening_database() {
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("must-not-exist.db");
        let config = crate::config::ServerConfig {
            db_path: db_path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let error = run_server(config).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("native ETH billing configuration is required"));
        assert!(!db_path.exists());
    }

    #[tokio::test]
    async fn compact_http_errors_preserve_status_headers_and_json() {
        for error in [
            ServerError::OaRateLimited {
                reason: "oa_hourly_issuance_budget".to_string(),
                retry_after_seconds: 37,
            },
            ServerError::LeaseSettlementPending {
                retry_after_seconds: 15,
            },
            ServerError::InvalidRequest("invalid request".to_string()),
        ] {
            let (status, headers, Json(body)) =
                build_error_response(&error, "lease-request-123", None);
            let expected_headers = headers.clone();
            let expected_body = serde_json::to_value(&body).unwrap();
            let response =
                ErrorHttpResponse(Box::new((status, headers, Json(body)))).into_response();

            assert_eq!(response.status(), status);
            assert_eq!(
                response.headers().get(RETRY_AFTER),
                expected_headers.get(RETRY_AFTER)
            );
            assert_eq!(response.headers()["content-type"], "application/json");
            let bytes = axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap();
            let actual_body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(actual_body, expected_body);
        }
    }

    #[test]
    fn oa_rate_limit_maps_to_retriable_429_with_retry_metadata() {
        let error = ServerError::OaRateLimited {
            reason: "oa_hourly_issuance_budget".to_string(),
            retry_after_seconds: 37,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "37");
        assert_eq!(response.error_code, "oa_hourly_issuance_budget");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(37));

        let serialized = serde_json::to_value(response).unwrap();
        assert_eq!(serialized["retry_after_seconds"], 37);
        assert_eq!(serialized["error_code"], "oa_hourly_issuance_budget");
    }

    #[test]
    fn lease_settlement_pending_maps_to_retriable_409_with_retry_metadata() {
        let error = ServerError::LeaseSettlementPending {
            retry_after_seconds: 15,
        };

        let (status, headers, Json(response)) =
            build_error_response(&error, "lease-request-123", None);

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(headers.get(RETRY_AFTER).unwrap(), "15");
        assert_eq!(response.error_code, "lease_settlement_pending");
        assert!(response.retriable);
        assert_eq!(response.retry_after_seconds, Some(15));
    }
}
