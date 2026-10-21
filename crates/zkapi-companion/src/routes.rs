//! HTTP routing layer for `zkapi-clientd`.
//!
//! Wires every endpoint the daemon exposes onto an [`AuthService`]:
//! - upstream-compatible request endpoints (`/v1/chat/completions`,
//!   `/v1/responses`, `/api/chat`) and model listings;
//! - the deposit endpoints (`/deposit/prepare`, `/deposit/confirm`);
//! - local credit management at `/status` (and `/wallet/status`), reporting
//!   whether a note is active, the current balance, expiry timestamp, and a
//!   link to the funding page;
//! - crash recovery (`/wallet/recover`) and the funding-page UI assets and
//!   demo endpoints under `/funding`.
//!
//! Errors are rendered in either a generic or OpenAI-style envelope, with a
//! funding-page hint attached on `402 Payment Required`.

use std::collections::VecDeque;
use std::io;
use std::sync::Arc;

use axum::body::{Body, Bytes};
use axum::extract::{Path as AxumPath, Request, State};
use axum::http::{header, HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt;
use serde::Deserialize;
use serde_json::{json, Value};
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::compat;
use crate::error::AuthError;
use crate::service::{
    AuthService, ConfirmDepositRequest, CoreRequest, StreamingCoreResponse, WithdrawalMode,
};

const SESSION_ID_HEADER: &str = "x-zkapi-session-id";

#[derive(Debug, Deserialize)]
struct PrepareDepositBody {
    amount: u128,
}

#[derive(Debug, Deserialize)]
struct WithdrawBody {
    /// "mutual" (server clearance) or "escape" (unilateral escape hatch).
    mode: String,
    /// 20-byte payout address (0x-prefixed or bare hex).
    destination: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OaWithdrawalBody {
    destination: String,
    /// The owner's acknowledgement that an expired note at a state with an
    /// unsettled request may send its ownership proof anyway.
    #[serde(default)]
    accept_unsettled_request_risk: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OaWithdrawalConfirmBody {
    transaction_hash: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OaWithdrawalReleaseBody {
    note_id: u32,
    withdrawal_nullifier: zkapi_types::Felt252,
}

pub fn build_router(service: Arc<AuthService>) -> Router {
    build_router_with_token(service, std::env::var("OA_ZKAPI_BRIDGE_TOKEN").ok())
}

/// Build the mandatory-authentication router with an explicitly supplied local token.
pub fn build_router_with_token(service: Arc<AuthService>, token: Option<String>) -> Router {
    Router::new()
        .route("/", get(funding_index))
        .route("/favicon.ico", get(funding_favicon))
        .route("/health", get(healthz))
        .route("/oa/v1/status", get(oa_bridge_status))
        .route("/oa/v1/session-events", get(oa_session_events))
        .route("/oa/v1/lease", post(oa_bridge_lease))
        .route("/oa/v1/billing/quote", get(oa_billing_quote))
        .route("/oa/v1/withdraw/status", get(oa_withdrawal_status))
        .route("/oa/v1/withdraw/prepare", post(oa_prepare_withdrawal))
        .route("/oa/v1/withdraw/confirm", post(oa_confirm_withdrawal))
        .route("/oa/v1/withdraw/release", post(oa_release_withdrawal))
        .route("/oa/v1/withdraw/escape/prepare", post(oa_escape_prepare))
        .route("/oa/v1/withdraw/escape/submit", post(oa_escape_submit))
        .route("/oa/v1/withdraw/escape/status", get(oa_escape_status))
        .route("/oa/v1/withdraw/escape/finalize", post(oa_escape_finalize))
        .route("/oa/v1/withdraw/escape/cancel", post(oa_escape_cancel))
        .route("/oa/v1/deposit/path", get(oa_deposit_path))
        .route("/healthz", get(healthz))
        .route("/request", post(core_request))
        .route("/status", get(wallet_status))
        .route("/deposit/prepare", post(prepare_deposit))
        .route("/deposit/confirm", post(confirm_deposit))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses_api))
        .route("/api/chat", post(ollama_chat))
        .route("/v1/models", get(models))
        .route("/api/tags", get(tags))
        .route("/funding/config", get(funding_config))
        .route("/wallet/status", get(wallet_status))
        .route("/wallet/recover", post(wallet_recover))
        .route("/wallet/settle", post(wallet_settle))
        .route("/wallet/reset", post(wallet_reset))
        .route("/funding/api/reset", post(wallet_reset))
        .route("/funding", get(funding_index))
        .route("/funding/", get(funding_index))
        .route("/funding/api/status", get(wallet_status))
        .route("/funding/api/demo", get(demo_overview))
        .route("/funding/api/deposit/prepare", post(prepare_deposit))
        .route("/funding/api/deposit/confirm", post(confirm_deposit))
        .route("/funding/api/request/preview", post(request_preview))
        .route("/funding/api/request/submit", post(request_submit))
        .route("/funding/api/recover", post(wallet_recover))
        .route("/wallet/withdraw", post(wallet_withdraw))
        .route("/funding/api/withdraw", post(wallet_withdraw))
        .route("/wallet/withdraw/confirm", post(wallet_withdraw_confirm))
        .route(
            "/funding/api/withdraw/confirm",
            post(wallet_withdraw_confirm),
        )
        // Browser client endpoints: full zkAPI inspection per call.
        .route("/zkapi/v1/config", get(zkapi_config))
        .route("/zkapi/v1/inference", post(zkapi_inference))
        .route("/funding/{*path}", get(funding_asset))
        .layer(local_cors_layer())
        .layer(middleware::from_fn_with_state(token, oa_bridge_auth))
        .with_state(service)
}

// A packaged companion is private to the Go daemon. The token is generated
// locally and inherited via environment, never command-line arguments. No
// unauthenticated route (including funding and reset) is left accessible.
async fn oa_bridge_auth(
    State(token): State<Option<String>>,
    request: Request,
    next: Next,
) -> Response {
    let expected = match token {
        Some(token) if token.len() >= 32 => format!("Bearer {token}"),
        _ => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
    };
    let actual = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");
    let different = actual.len() != expected.len()
        || actual
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            != 0;
    if different {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut response = next.run(request).await;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn oa_bridge_status(State(service): State<Arc<AuthService>>) -> Json<Value> {
    Json(service.oa_bridge_status())
}

async fn oa_session_events(
    State(service): State<Arc<AuthService>>,
    headers: HeaderMap,
) -> Response {
    if headers.contains_key(header::ORIGIN) {
        return StatusCode::FORBIDDEN.into_response();
    }
    Json(service.oa_session_events()).into_response()
}

async fn oa_deposit_path(State(service): State<Arc<AuthService>>) -> Response {
    match service.oa_deposit_path().await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_billing_quote(State(service): State<Arc<AuthService>>) -> Response {
    match service.oa_billing_quote().await {
        Ok(quote) => Json(quote).into_response(),
        Err(error) => openai_error(error),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OaLeaseBody {
    request_limit_micro_usd: u64,
}

async fn oa_bridge_lease(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaLeaseBody>,
) -> Response {
    if !matches!(
        body.request_limit_micro_usd,
        1_000_000 | 2_000_000 | 3_000_000 | 4_500_000 | 6_000_000
    ) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match service
        .oa_bridge_lease(body.request_limit_micro_usd.into())
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_withdrawal_status(State(service): State<Arc<AuthService>>) -> Response {
    match service.oa_withdrawal_status().await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_prepare_withdrawal(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaWithdrawalBody>,
) -> Response {
    let destination = match crate::oa_withdrawal::destination(&body.destination) {
        Ok(value) => value,
        Err(error) => return generic_error(error),
    };
    match service
        .oa_prepare_withdrawal(destination, body.accept_unsettled_request_risk)
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_confirm_withdrawal(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaWithdrawalConfirmBody>,
) -> Response {
    match service.oa_confirm_withdrawal(body.transaction_hash).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_release_withdrawal(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaWithdrawalReleaseBody>,
) -> Response {
    match service
        .oa_release_withdrawal(body.note_id, body.withdrawal_nullifier)
        .await
    {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_escape_prepare(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<crate::service::exit::EscapePrepareRequest>,
) -> Response {
    match service.oa_escape_prepare(body).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_escape_submit(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaWithdrawalConfirmBody>,
) -> Response {
    match service.oa_escape_submit(body.transaction_hash).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_escape_status(State(service): State<Arc<AuthService>>) -> Response {
    match service.oa_escape_status().await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_escape_cancel(State(service): State<Arc<AuthService>>) -> Response {
    match service.oa_escape_cancel().await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

async fn oa_escape_finalize(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<OaWithdrawalConfirmBody>,
) -> Response {
    match service.oa_escape_finalize(body.transaction_hash).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => generic_error(error),
    }
}

/// A deliberately narrow CORS policy.
///
/// The funding UI is served by this same daemon, so it is same-origin and does
/// not depend on CORS at all. Cross-origin access is restricted to loopback
/// origins (any port) for local browser tooling, and credentials are never
/// enabled — so this is never the unsafe wildcard-origin-with-credentials
/// combination.
fn local_cors_layer() -> CorsLayer {
    CorsLayer::new()
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([
            header::CONTENT_TYPE,
            HeaderName::from_static(SESSION_ID_HEADER),
        ])
        .allow_origin(AllowOrigin::predicate(|origin, _request| {
            let origin = origin.as_bytes();
            origin.starts_with(b"http://localhost") || origin.starts_with(b"http://127.0.0.1")
        }))
}

pub async fn run(service: Arc<AuthService>, listen_addr: &str) -> anyhow::Result<()> {
    let reconciler = service.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(5));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            reconciler.reconcile_direct_openrouter().await;
        }
    });
    let router = build_router(service);
    let listener = tokio::net::TcpListener::bind(listen_addr).await?;
    tracing::info!("zkapi-clientd listening on {}", listen_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

async fn healthz() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn core_request(
    State(service): State<Arc<AuthService>>,
    Json(request): Json<CoreRequest>,
) -> Response {
    match service.execute_request(request).await {
        Ok(response) => Json(response).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn chat_completions(
    State(service): State<Arc<AuthService>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    if compat::stream_requested(&body) {
        return match service
            .execute_streaming_request_in_session(
                compat::core_request("/v1/chat/completions", body),
                session_id(&headers),
            )
            .await
        {
            Ok(upstream) => streaming_openrouter_response(upstream),
            Err(err) => openai_error(err),
        };
    }
    let model = compat::extract_model(&body, service.default_model());
    match service
        .execute_request_in_session(
            compat::core_request("/v1/chat/completions", body),
            session_id(&headers),
        )
        .await
    {
        Ok(response) => Json(compat::chat_completion(&model, &response)).into_response(),
        Err(err) => openai_error(err),
    }
}

fn streaming_openrouter_response(upstream: StreamingCoreResponse) -> Response {
    let mut response = Response::new(Body::from_stream(upstream.body));
    *response.status_mut() = upstream.status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        upstream
            .content_type
            .unwrap_or_else(|| HeaderValue::from_static("text/event-stream")),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        upstream
            .cache_control
            .unwrap_or_else(|| HeaderValue::from_static("no-cache")),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    response
}

async fn responses_api(
    State(service): State<Arc<AuthService>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let model = compat::extract_model(&body, service.default_model());
    match service
        .execute_request_in_session(
            compat::core_request("/v1/responses", body),
            session_id(&headers),
        )
        .await
    {
        Ok(response) => Json(compat::responses_api(&model, &response)).into_response(),
        Err(err) => openai_error(err),
    }
}

async fn ollama_chat(
    State(service): State<Arc<AuthService>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let model = compat::extract_model(&body, service.default_model());
    if compat::ollama_stream_requested(&body) {
        let mut body = body;
        if let Some(object) = body.as_object_mut() {
            // Ollama defaults to streaming. Make that default explicit before
            // normalizing the request into OpenRouter's chat format.
            object.insert("stream".to_string(), Value::Bool(true));
        }
        return match service
            .execute_streaming_request_in_session(
                compat::core_request("/api/chat", body),
                session_id(&headers),
            )
            .await
        {
            Ok(upstream) => streaming_ollama_response(upstream, model),
            Err(err) => generic_error(err),
        };
    }
    match service
        .execute_request_in_session(
            compat::core_request("/api/chat", body),
            session_id(&headers),
        )
        .await
    {
        Ok(response) => Json(compat::ollama_chat(&model, &response)).into_response(),
        Err(err) => generic_error(err),
    }
}

struct OllamaStreamState {
    upstream: BoxStream<'static, Result<Bytes, io::Error>>,
    model: String,
    input: Vec<u8>,
    output: VecDeque<Result<Bytes, io::Error>>,
    prompt_tokens: u64,
    completion_tokens: u64,
    finish_reason: String,
    finished: bool,
}

impl OllamaStreamState {
    fn consume_complete_lines(&mut self) {
        while !self.finished {
            let Some(newline) = self.input.iter().position(|byte| *byte == b'\n') else {
                break;
            };
            let mut line = self.input.drain(..=newline).collect::<Vec<_>>();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.consume_sse_line(&line);
        }
    }

    fn consume_sse_line(&mut self, line: &[u8]) {
        let Some(payload) = line.strip_prefix(b"data:") else {
            // OpenRouter emits `: OPENROUTER PROCESSING` SSE comments while a
            // provider is starting. They are valid SSE but not Ollama JSON.
            return;
        };
        let payload = payload.strip_prefix(b" ").unwrap_or(payload);
        if payload.is_empty() {
            return;
        }
        if payload == b"[DONE]" {
            self.enqueue_done();
            return;
        }
        let chunk: Value = match serde_json::from_slice(payload) {
            Ok(chunk) => chunk,
            Err(error) => {
                self.output.push_back(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid OpenRouter SSE event: {error}"),
                )));
                self.finished = true;
                return;
            }
        };

        if let Some(usage) = chunk.get("usage") {
            self.prompt_tokens = usage
                .get("prompt_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(self.prompt_tokens);
            self.completion_tokens = usage
                .get("completion_tokens")
                .and_then(Value::as_u64)
                .unwrap_or(self.completion_tokens);
        }
        if let Some(error) = chunk.get("error") {
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("OpenRouter streaming error");
            self.enqueue_json(json!({ "error": message }));
            self.finished = true;
            return;
        }

        let choice = chunk.get("choices").and_then(|choices| choices.get(0));
        if let Some(reason) = choice
            .and_then(|choice| choice.get("finish_reason"))
            .and_then(Value::as_str)
        {
            self.finish_reason = reason.to_string();
        }
        let delta = choice.and_then(|choice| choice.get("delta"));
        let content = delta
            .and_then(|delta| delta.get("content"))
            .and_then(Value::as_str)
            .filter(|content| !content.is_empty());
        let thinking = delta
            .and_then(|delta| {
                delta
                    .get("reasoning_content")
                    .or_else(|| delta.get("reasoning"))
            })
            .and_then(Value::as_str)
            .filter(|thinking| !thinking.is_empty());
        let tool_calls = delta
            .and_then(|delta| delta.get("tool_calls"))
            .filter(|tool_calls| !tool_calls.is_null());
        if content.is_none() && thinking.is_none() && tool_calls.is_none() {
            return;
        }

        let mut message = serde_json::Map::from_iter([
            ("role".to_string(), Value::String("assistant".to_string())),
            (
                "content".to_string(),
                Value::String(content.unwrap_or_default().to_string()),
            ),
        ]);
        if let Some(thinking) = thinking {
            message.insert("thinking".to_string(), Value::String(thinking.to_string()));
        }
        if let Some(tool_calls) = tool_calls {
            message.insert("tool_calls".to_string(), tool_calls.clone());
        }
        self.enqueue_json(json!({
            "model": self.model,
            "created_at": "1970-01-01T00:00:00Z",
            "message": message,
            "done": false,
        }));
    }

    fn enqueue_done(&mut self) {
        if self.finished {
            return;
        }
        self.enqueue_json(json!({
            "model": self.model,
            "created_at": "1970-01-01T00:00:00Z",
            "message": { "role": "assistant", "content": "" },
            "done": true,
            "done_reason": self.finish_reason,
            "total_duration": 0,
            "load_duration": 0,
            "prompt_eval_count": self.prompt_tokens,
            "eval_count": self.completion_tokens,
        }));
        self.finished = true;
    }

    fn enqueue_json(&mut self, value: Value) {
        let mut line = serde_json::to_vec(&value).expect("serializing an Ollama stream chunk");
        line.push(b'\n');
        self.output.push_back(Ok(Bytes::from(line)));
    }
}

fn streaming_ollama_response(upstream: StreamingCoreResponse, model: String) -> Response {
    let status = upstream.status;
    let state = OllamaStreamState {
        upstream: upstream.body,
        model,
        input: Vec::new(),
        output: VecDeque::new(),
        prompt_tokens: 0,
        completion_tokens: 0,
        finish_reason: "stop".to_string(),
        finished: false,
    };
    let output = stream::unfold(state, |mut state| async move {
        loop {
            if let Some(chunk) = state.output.pop_front() {
                return Some((chunk, state));
            }
            if state.finished {
                return None;
            }
            match state.upstream.next().await {
                Some(Ok(chunk)) => {
                    state.input.extend_from_slice(&chunk);
                    state.consume_complete_lines();
                }
                Some(Err(error)) => {
                    state.finished = true;
                    return Some((Err(io::Error::other(error)), state));
                }
                None => {
                    if !state.input.is_empty() {
                        let line = std::mem::take(&mut state.input);
                        state.consume_sse_line(&line);
                    }
                    state.enqueue_done();
                }
            }
        }
    });

    let mut response = Response::new(Body::from_stream(output));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/x-ndjson"),
    );
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-cache, no-transform"),
    );
    response.headers_mut().insert(
        HeaderName::from_static("x-accel-buffering"),
        HeaderValue::from_static("no"),
    );
    response
}

async fn models(State(service): State<Arc<AuthService>>) -> Json<Value> {
    Json(compat::openai_models(service.models()))
}

async fn tags(State(service): State<Arc<AuthService>>) -> Json<Value> {
    Json(compat::ollama_tags(service.models()))
}

async fn wallet_status(State(service): State<Arc<AuthService>>) -> Response {
    match service.status().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn wallet_recover(State(service): State<Arc<AuthService>>) -> Response {
    match service.recover().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn wallet_settle(State(service): State<Arc<AuthService>>) -> Response {
    match service.settle_for_withdrawal().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn wallet_reset(State(service): State<Arc<AuthService>>) -> Response {
    match service.reset_wallet().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn wallet_withdraw(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<WithdrawBody>,
) -> Response {
    let mode = match body.mode.trim().to_ascii_lowercase().as_str() {
        "mutual" | "mutual-close" | "mutualclose" => WithdrawalMode::Mutual,
        "escape" | "escape-hatch" | "escapehatch" => WithdrawalMode::Escape,
        other => {
            return generic_error(AuthError::InvalidInput(format!(
                "unknown withdrawal mode '{other}' (expected 'mutual' or 'escape')"
            )))
        }
    };
    let destination = match parse_destination(&body.destination) {
        Ok(dest) => dest,
        Err(msg) => return generic_error(AuthError::InvalidInput(msg)),
    };
    match service.create_withdrawal(mode, destination).await {
        Ok(plan) => Json(plan).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn wallet_withdraw_confirm(State(service): State<Arc<AuthService>>) -> Response {
    match service.confirm_withdrawal().await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

fn parse_destination(value: &str) -> Result<[u8; 20], String> {
    let hex = value.strip_prefix("0x").unwrap_or(value);
    if hex.len() != 40 {
        return Err("destination must be a 20-byte hex address".to_string());
    }
    let mut bytes = [0u8; 20];
    for (idx, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let part = std::str::from_utf8(chunk).map_err(|e| e.to_string())?;
        bytes[idx] = u8::from_str_radix(part, 16).map_err(|e| e.to_string())?;
    }
    Ok(bytes)
}

async fn demo_overview(State(service): State<Arc<AuthService>>) -> Response {
    match service.demo_overview().await {
        Ok(overview) => Json(overview).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn funding_config(State(service): State<Arc<AuthService>>) -> Json<Value> {
    Json(json!(service.funding_config()))
}

async fn funding_index(State(service): State<Arc<AuthService>>) -> Response {
    let mut response = Html(service.funding_index_html()).into_response();
    add_local_asset_headers(&mut response);
    response
}

async fn funding_favicon(State(service): State<Arc<AuthService>>) -> Response {
    match service.funding_asset("favicon.svg") {
        Some((body, content_type)) => {
            let mut response = Response::new(axum::body::Body::from(body));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            add_local_asset_headers(&mut response);
            response
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn funding_asset(
    State(service): State<Arc<AuthService>>,
    AxumPath(path): AxumPath<String>,
) -> Response {
    match service.funding_asset(path.trim_start_matches('/')) {
        Some((body, content_type)) => {
            let mut response = Response::new(axum::body::Body::from(body));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            add_local_asset_headers(&mut response);
            response
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn prepare_deposit(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<PrepareDepositBody>,
) -> Response {
    match service.prepare_deposit(body.amount).await {
        Ok(plan) => Json(plan).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn confirm_deposit(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<ConfirmDepositRequest>,
) -> Response {
    match service.confirm_deposit(body).await {
        Ok(status) => Json(status).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn request_preview(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<CoreRequest>,
) -> Response {
    match service.preview_request(body).await {
        Ok(preview) => Json(preview).into_response(),
        Err(err) => generic_error(err),
    }
}

async fn request_submit(
    State(service): State<Arc<AuthService>>,
    Json(body): Json<CoreRequest>,
) -> Response {
    match service.execute_request_demo(body).await {
        Ok(result) => Json(result).into_response(),
        Err(err) => generic_error(err),
    }
}

/// GET /zkapi/v1/config -- integration config for the client (credit scale,
/// caps, upstream metadata, and funding parameters).
async fn zkapi_config(State(service): State<Arc<AuthService>>) -> Response {
    Json(service.zkapi_config().await).into_response()
}

/// POST /zkapi/v1/inference -- run an OpenAI-style chat through the configured
/// proxy/direct request mode and return the daemon's core response envelope.
async fn zkapi_inference(
    State(service): State<Arc<AuthService>>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    let request = CoreRequest::post_json("/v1/chat/completions", body);
    match service
        .execute_request_in_session(request, session_id(&headers))
        .await
    {
        Ok(result) => Json(result).into_response(),
        Err(err) => generic_error(err),
    }
}

fn session_id(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(SESSION_ID_HEADER)
        .and_then(|value| value.to_str().ok())
}

fn add_local_asset_headers(response: &mut Response) {
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        ),
    );

    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
}

fn generic_error(err: AuthError) -> Response {
    let status = err.status_code();
    let funding_url = err.funding_url();
    let mut body = json!({
        "error": {
            "code": err.code(),
            "message": err.to_string(),
            "funding_url": funding_url,
        }
    });
    if let Some(nullifier) = err.nullifier() {
        body["error"]["nullifier"] = json!(nullifier);
    }
    if let Some(detail) = err.detail() {
        body["error"]["detail"] = detail.clone();
    }
    (status, Json(body)).into_response()
}

fn openai_error(err: AuthError) -> Response {
    let status = err.status_code();
    let funding_url = err.funding_url();
    let mut body = json!({
        "error": {
            "message": err.to_string(),
            "type": err.code(),
            "param": Value::Null,
            "code": err.code(),
            "funding_url": funding_url,
        }
    });
    if let Some(nullifier) = err.nullifier() {
        body["error"]["nullifier"] = json!(nullifier);
    }
    (status, Json(body)).into_response()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn session_events_are_authenticated_browser_blocked_and_no_store() {
        let directory = tempfile::tempdir().unwrap();
        let service = AuthService::new(AuthConfig {
            state_dir: directory.path().to_path_buf(),
            ..Default::default()
        })
        .unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );
        for (token, origin, expected) in [
            (None, None, StatusCode::UNAUTHORIZED),
            (Some("Bearer wrong"), None, StatusCode::UNAUTHORIZED),
            (
                Some("Bearer companion-test-token-thirty-two-characters"),
                Some("http://localhost"),
                StatusCode::FORBIDDEN,
            ),
            (
                Some("Bearer companion-test-token-thirty-two-characters"),
                Some("https://external.example"),
                StatusCode::FORBIDDEN,
            ),
            (
                Some("Bearer companion-test-token-thirty-two-characters"),
                None,
                StatusCode::OK,
            ),
        ] {
            let mut request = axum::http::Request::builder().uri("/oa/v1/session-events");
            if let Some(token) = token {
                request = request.header("Authorization", token);
            }
            if let Some(origin) = origin {
                request = request.header("Origin", origin);
            }
            let response = router
                .clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), expected);
            if expected == StatusCode::OK {
                assert_eq!(response.headers()["cache-control"], "no-store");
                let body = response.into_body().collect().await.unwrap().to_bytes();
                let value: Value = serde_json::from_slice(&body).unwrap();
                assert_eq!(value.as_object().unwrap().len(), 5);
                assert_eq!(value["version"], 1);
                assert_eq!(value["first_sequence"], 1);
                assert_eq!(value["next_sequence"], 1);
                assert!(value["events"].as_array().unwrap().is_empty());
                assert_eq!(value["instance_id"].as_str().unwrap().len(), 32);
            }
        }
    }

    #[tokio::test]
    async fn oa_bridge_budget_rejects_missing_unreviewed_and_extra_input_before_wallet_work() {
        let service = AuthService::new(AuthConfig::default()).unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );
        for body in [
            "{}",
            "null",
            "[]",
            r#"{"request_limit_micro_usd":0}"#,
            r#"{"request_limit_micro_usd":7000000}"#,
            r#"{"request_limit_micro_usd":1000001}"#,
            r#"{"request_limit_micro_usd":1.5}"#,
            r#"{"request_limit_micro_usd":-1000000}"#,
            r#"{"request_limit_micro_usd":"1000000"}"#,
            r#"{"request_limit_micro_usd":18446744073709551616}"#,
            r#"{"request_limit_micro_usd":1000000,"model":"private"}"#,
            r#"{"request_limit_micro_usd":1000000,"messages":[]}"#,
            r#"{"request_limit_micro_usd":1000000,"request_limit_micro_usd":6000000}"#,
        ] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/oa/v1/lease")
                        .header(
                            "Authorization",
                            "Bearer companion-test-token-thirty-two-characters",
                        )
                        .header("Content-Type", "application/json")
                        .body(Body::from(body))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
                ),
                "{}: {}",
                body,
                response.status()
            );
        }
        for limit in [1_000_000u64, 2_000_000, 3_000_000, 4_500_000, 6_000_000] {
            let parsed: OaLeaseBody =
                serde_json::from_value(json!({"request_limit_micro_usd":limit})).unwrap();
            assert_eq!(parsed.request_limit_micro_usd, limit);
        }
    }

    #[tokio::test]
    async fn oa_bridge_requires_authentication_for_every_route() {
        let service = AuthService::new(AuthConfig::default()).unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );
        for path in [
            "/oa/v1/status",
            "/oa/v1/session-events",
            "/oa/v1/lease",
            "/oa/v1/billing/quote",
            "/oa/v1/deposit/path",
            "/oa/v1/withdraw/status",
            "/oa/v1/withdraw/prepare",
            "/oa/v1/withdraw/confirm",
            "/oa/v1/withdraw/release",
            "/funding",
            "/wallet/reset",
            "/health",
        ] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn oa_status_advertises_the_concession_exit_and_bridge_version_5() {
        let directory = tempfile::tempdir().unwrap();
        let service = AuthService::new(AuthConfig {
            state_dir: directory.path().to_path_buf(),
            ..Default::default()
        })
        .unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri("/oa/v1/status")
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["clearance_ownership_proof_version"], 1);
        assert_eq!(value["unsettled_request_override_version"], 1);
        assert_eq!(value["withdrawal_bridge_version"], 1);
        assert_eq!(value["bridge_version"], 5);
        assert_eq!(value["exit_concession"], 1);
        assert_eq!(value["escape_routes_version"], 2);
        assert_eq!(value["setup_id"], "dev");
        assert_eq!(value["settlement_window_seconds"], 21_905);
        assert_eq!(value["circuit_id"], "zkapi-v2-concession-v1");
    }

    #[test]
    fn withdrawal_preparation_takes_an_explicit_unsettled_request_acknowledgement() {
        let destination = "0x2222222222222222222222222222222222222222";
        let plain: super::OaWithdrawalBody =
            serde_json::from_value(serde_json::json!({ "destination": destination })).unwrap();
        assert!(!plain.accept_unsettled_request_risk);
        let accepted: super::OaWithdrawalBody = serde_json::from_value(
            serde_json::json!({ "destination": destination, "accept_unsettled_request_risk": true }),
        )
        .unwrap();
        assert!(accepted.accept_unsettled_request_risk);
        assert!(serde_json::from_value::<super::OaWithdrawalBody>(
            serde_json::json!({ "destination": destination, "override": true })
        )
        .is_err());
    }

    #[tokio::test]
    async fn oa_withdrawal_release_rejects_malformed_bodies_before_wallet_work() {
        let directory = tempfile::tempdir().unwrap();
        let service = AuthService::new(AuthConfig {
            state_dir: directory.path().to_path_buf(),
            ..Default::default()
        })
        .unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );
        let nullifier = format!("0x{}", "1".repeat(64));
        for body in [
            "{}".to_string(),
            "null".into(),
            json!({"note_id":7}).to_string(),
            json!({"withdrawal_nullifier":nullifier}).to_string(),
            json!({"note_id":4294967296u64,"withdrawal_nullifier":nullifier}).to_string(),
            json!({"note_id":-1,"withdrawal_nullifier":nullifier}).to_string(),
            json!({"note_id":7,"withdrawal_nullifier":"0xnot-hex"}).to_string(),
            json!({"note_id":7,"withdrawal_nullifier":format!("0x{}", "f".repeat(64))}).to_string(),
            json!({"note_id":7,"withdrawal_nullifier":nullifier,"destination":"0x"}).to_string(),
        ] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .method("POST")
                        .uri("/oa/v1/withdraw/release")
                        .header(
                            "Authorization",
                            "Bearer companion-test-token-thirty-two-characters",
                        )
                        .header("Content-Type", "application/json")
                        .body(Body::from(body.clone()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(
                matches!(
                    response.status(),
                    StatusCode::BAD_REQUEST | StatusCode::UNPROCESSABLE_ENTITY
                ),
                "{}: {}",
                body,
                response.status()
            );
        }
        // A well-formed body without any reservation is a conflict, not a release.
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/oa/v1/withdraw/release")
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .header("Content-Type", "application/json")
                    .body(Body::from(
                        json!({"note_id":7,"withdrawal_nullifier":nullifier}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
    }

    use axum::body::Body;
    use axum::http::StatusCode;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    use super::*;
    use crate::config::{AuthConfig, ModelDescriptor};

    #[tokio::test]
    async fn receipt_journal_missing_carries_the_nullifier_for_the_operator() {
        let nullifier = zkapi_types::Felt252::from_u64(0x1234);
        for response in [
            generic_error(AuthError::ReceiptJournalMissing(nullifier)),
            openai_error(AuthError::ReceiptJournalMissing(nullifier)),
        ] {
            assert_eq!(response.status(), StatusCode::CONFLICT);
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let value: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(value["error"]["code"], "receipt_journal_missing");
            assert_eq!(value["error"]["nullifier"], nullifier.to_string());
        }
        let body = generic_error(AuthError::PendingSettlement)
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert!(value["error"].get("nullifier").is_none());
    }

    #[tokio::test]
    async fn openai_errors_preserve_upstream_status_without_wallet_funding_hint() {
        let response = openai_error(AuthError::UpstreamResponse {
            status: StatusCode::PAYMENT_REQUIRED,
            message: "lease credit exhausted".to_string(),
        });
        assert_eq!(response.status(), StatusCode::PAYMENT_REQUIRED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["error"]["code"], "upstream_error");
        assert_eq!(value["error"]["funding_url"], Value::Null);
    }

    #[tokio::test]
    async fn serves_funding_page_assets_and_model_lists() {
        let state_dir = std::env::temp_dir().join("zkapi_clientd_routes_assets");
        let service = AuthService::new(AuthConfig {
            state_dir,
            models: vec![ModelDescriptor::new("demo-model")],
            suggested_deposit_amount: 2468,
            demo_rpc_url: Some("http://127.0.0.1:48654".to_string()),
            demo_billing_token_address: Some("0xabc".to_string()),
            demo_mint_enabled: true,
            demo_note_ttl_seconds: Some(1234),
            ..Default::default()
        })
        .unwrap();
        let router = build_router_with_token(
            service,
            Some("companion-test-token-thirty-two-characters".into()),
        );

        let funding = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .uri("/funding")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(funding.status(), StatusCode::OK);
        assert_eq!(funding.headers()[header::CACHE_CONTROL], "no-store");
        assert!(funding
            .headers()
            .get(header::CONTENT_SECURITY_POLICY)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.contains("script-src 'self'")));
        let body = funding.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(!html.is_empty());
        if crate::service::EMBEDDED_FUNDING_IS_DEFAULT {
            assert!(html.contains("<title>zkAPI local client</title>"));
            assert!(html.contains("OA Chat is a separate app"));
            assert!(html.contains("--fund-with-cast"));
            assert!(html.contains("zkapi withdraw --destination"));
            assert!(!html.contains("<script"));
            assert!(!html.contains("id=\"message-input\""));
            let stylesheet = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .header(
                            "Authorization",
                            "Bearer companion-test-token-thirty-two-characters",
                        )
                        .uri("/funding/styles.css")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(stylesheet.status(), StatusCode::OK);
            assert_eq!(
                stylesheet.headers()[header::CONTENT_TYPE],
                "text/css; charset=utf-8"
            );
            assert_eq!(stylesheet.headers()[header::CACHE_CONTROL], "no-store");
            assert_eq!(stylesheet.headers()["x-content-type-options"], "nosniff");
            // Optional app assets are ordinary lookups, not panicking handlers
            // that assume the daemon embeds a particular chat application.
            for path in [
                "/funding/wallet.js",
                "/funding/app.js",
                "/funding/OA_CHAT_LICENSE",
                "/funding/build.json",
                "/funding/.env",
                "/funding/../Cargo.toml",
            ] {
                let response = router
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .header(
                                "Authorization",
                                "Bearer companion-test-token-thirty-two-characters",
                            )
                            .uri(path)
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::NOT_FOUND, "{path}");
            }
        }
        for path in ["/", "/funding/", "/funding/index.html"] {
            let response = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .header(
                            "Authorization",
                            "Bearer companion-test-token-thirty-two-characters",
                        )
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{path}");
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            assert!(response.headers()[header::CONTENT_SECURITY_POLICY]
                .to_str()
                .unwrap()
                .contains("connect-src 'self'"));
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            assert_eq!(bytes.as_ref(), html.as_bytes());
        }

        let models = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .uri("/v1/models")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = models.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["data"][0]["id"], "demo-model");

        let health = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::OK);

        let settled = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .method("POST")
                    .uri("/wallet/settle")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(settled.status(), StatusCode::OK);

        let config = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .uri("/funding/config")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = config.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["models"][0]["id"], "demo-model");
        assert_eq!(value["chain_id"], 1);
        assert_eq!(value["demo_rpc_url"], "http://127.0.0.1:48654");
        assert_eq!(value["demo_billing_token_address"], "0xabc");
        assert_eq!(value["demo_mint_enabled"], false);
        assert_eq!(value["suggested_deposit_amount"], 2468);
        assert!(value.get("demo_private_key").is_none());
        assert_eq!(value["demo_note_ttl_seconds"], 1234);

        for path in ["/zkapi/v1/ephemeral/issue", "/zkapi/v1/ephemeral/settle"] {
            let removed = router
                .clone()
                .oneshot(
                    axum::http::Request::builder()
                        .header(
                            "Authorization",
                            "Bearer companion-test-token-thirty-two-characters",
                        )
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(removed.status(), StatusCode::NOT_FOUND);
        }

        let withdrawal_confirm = router
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .method("POST")
                    .uri("/wallet/withdraw/confirm")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(withdrawal_confirm.status(), StatusCode::PAYMENT_REQUIRED);

        let demo = router
            .oneshot(
                axum::http::Request::builder()
                    .header(
                        "Authorization",
                        "Bearer companion-test-token-thirty-two-characters",
                    )
                    .uri("/funding/api/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(demo.status(), StatusCode::OK);
        let body = demo.into_body().collect().await.unwrap().to_bytes();
        let value: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(value["runtime_proof_backend"], "groth16_bn254");
        assert_eq!(value["funding"]["models"][0]["id"], "demo-model");
    }
}
