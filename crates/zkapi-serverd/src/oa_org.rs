//! OA org client for verifier-backed OpenRouter runtime keys.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkapi_types::wire::OpenRouterLeaseResponse;

use crate::error::ServerError;

const DEFAULT_OA_RETRY_AFTER_SECONDS: u64 = 60;
const OA_RATE_LIMITED: &str = "oa_rate_limited";
const OA_HOURLY_ISSUANCE_BUDGET: &str = "oa_hourly_issuance_budget";
const OA_MINUTE_REQUEST_LIMIT: &str = "oa_minute_request_limit";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OaKeyVerificationEvidence {
    pub verifier_url: String,
    pub station_id: String,
    pub station_recently_attested: bool,
    pub key_valid_till: u64,
    pub station_signature: String,
    pub org_signature: String,
}

#[derive(Clone, Serialize)]
pub struct IssuedOpenRouterLease {
    #[serde(flatten)]
    pub lease: OpenRouterLeaseResponse,
    pub key_source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<OaKeyVerificationEvidence>,
    pub billing_quote: crate::native_billing::NativeBillingQuote,
}

#[derive(Debug, Clone)]
pub struct OaOrgCreatedKey {
    pub key: String,
    pub hash: String,
    pub expires_at: u64,
    pub openrouter_api_base: String,
    pub verification: OaKeyVerificationEvidence,
}

#[derive(Debug, Clone)]
pub enum OaOrgUsage {
    Pending { retry_after_seconds: u64 },
    Finalized(OaOrgFinalUsage),
}

#[derive(Debug, Clone)]
pub struct OaOrgFinalUsage {
    pub usage_credits: u128,
    pub expires_at: u64,
    pub closed_at: u64,
    pub finalized_at: u64,
    pub station_id: String,
    pub station_signature: String,
    pub org_signature: String,
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct OaOrgUsageExpectation {
    pub credit_limit_usd: f64,
    pub duration_minutes: u64,
    pub limit_credits: u128,
    pub minimum_expires_at: u64,
    pub maximum_expires_at: u64,
}

pub struct OaOrgProvisioner {
    http: reqwest::Client,
    base_url: String,
    shared_secret: String,
}

#[derive(Deserialize)]
struct OaOrgKeyResponse {
    source: String,
    #[serde(default)]
    replayed: bool,
    key: String,
    key_hash: String,
    credit_limit: f64,
    duration_minutes: u64,
    expires_at_unix: u64,
    station_id: String,
    station_recently_attested: bool,
    station_signature: String,
    org_signature: String,
    verifier_url: String,
    openrouter_api_base: String,
}

#[derive(Deserialize)]
struct OaOrgUsageResponse {
    source: String,
    version: u64,
    status: String,
    client_request_id: String,
    station_request_id: String,
    key_hash: String,
    retry_after_seconds: Option<u64>,
    usage_credits: Option<u128>,
    credit_limit_credits: Option<u128>,
    expires_at_unix: Option<u64>,
    closed_at_unix: Option<u64>,
    finalized_at_unix: Option<u64>,
    station_id: Option<String>,
    station_signature: Option<String>,
    org_signature: Option<String>,
}

impl OaOrgProvisioner {
    pub fn new(base_url: String, shared_secret: String) -> Result<Self, ServerError> {
        let parsed = reqwest::Url::parse(&base_url)
            .map_err(|_| ServerError::InvalidRequest("invalid OA org URL".to_string()))?;
        if !is_secure_or_loopback_url(parsed.as_str())
            || parsed.username() != ""
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(ServerError::InvalidRequest(
                "OA org URL must be HTTPS (or explicit loopback HTTP) without credentials, query, or fragment"
                    .to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(35))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| {
                ServerError::Internal(format!("failed to build OA org client: {error}"))
            })?;
        Ok(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            shared_secret,
        })
    }

    pub async fn create_key(
        &self,
        client_request_id: &str,
        limit_usd: f64,
        limit_credits: u128,
        ttl_seconds: u64,
    ) -> Result<OaOrgCreatedKey, ServerError> {
        if ttl_seconds == 0 || !ttl_seconds.is_multiple_of(60) {
            return Err(ServerError::InvalidRequest(
                "OA org lease TTL must be a positive whole number of minutes".to_string(),
            ));
        }
        let duration_minutes = ttl_seconds / 60;
        let response = self
            .http
            .post(format!("{}/api/zkapi/request_key", self.base_url))
            .bearer_auth(&self.shared_secret)
            .json(&json!({
                "client_request_id": client_request_id,
                "credit_limit": limit_usd,
                "credit_limit_credits": limit_credits,
                "duration_minutes": duration_minutes,
            }))
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OA org key request failed: {error}"))
            })?;
        let status = response.status();
        let headers = response.headers().clone();
        let text_result = response.text().await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(parse_oa_rate_limit(
                &headers,
                text_result.as_deref().unwrap_or_default(),
            ));
        }
        let text = text_result.map_err(|error| {
            ServerError::Internal(format!("OA org key response failed: {error}"))
        })?;
        if is_definitive_policy_rejection(status, &text) {
            return Err(ServerError::OaKeyPolicyRejected);
        }
        if !status.is_success() {
            return Err(ServerError::Internal(format!(
                "OA org key request returned {status}"
            )));
        }
        let response: OaOrgKeyResponse = serde_json::from_str(&text).map_err(|error| {
            ServerError::Internal(format!("invalid OA org key response: {error}"))
        })?;
        validate_response(&response, limit_usd, duration_minutes, ttl_seconds)?;
        Ok(OaOrgCreatedKey {
            key: response.key,
            hash: response.key_hash,
            expires_at: response.expires_at_unix,
            openrouter_api_base: response.openrouter_api_base,
            verification: OaKeyVerificationEvidence {
                verifier_url: response.verifier_url,
                station_id: response.station_id,
                station_recently_attested: response.station_recently_attested,
                key_valid_till: response.expires_at_unix,
                station_signature: response.station_signature,
                org_signature: response.org_signature,
            },
        })
    }

    pub(crate) async fn get_key_usage(
        &self,
        client_request_id: &str,
        key_hash: &str,
        expectation: OaOrgUsageExpectation,
    ) -> Result<OaOrgUsage, ServerError> {
        let response = self
            .http
            .post(format!("{}/api/zkapi/key_usage", self.base_url))
            .bearer_auth(&self.shared_secret)
            .json(&json!({
                "client_request_id": client_request_id,
                "key_hash": key_hash,
                // The org persists this metadata for new leases. Supplying it
                // here also lets the authenticated relay settle leases issued
                // before that metadata existed; the station independently
                // checks both values against its signed issuance binding.
                "credit_limit": expectation.credit_limit_usd,
                "credit_limit_credits": expectation.limit_credits,
                "duration_minutes": expectation.duration_minutes,
                "expires_at_unix": expectation.maximum_expires_at,
            }))
            .send()
            .await
            .map_err(|error| {
                ServerError::Internal(format!("OA org usage request failed: {error}"))
            })?;
        let status = response.status();
        let headers = response.headers().clone();
        let text_result = response.text().await;
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
            return Err(parse_oa_rate_limit(
                &headers,
                text_result.as_deref().unwrap_or_default(),
            ));
        }
        let text = text_result.map_err(|error| {
            ServerError::Internal(format!("OA org usage response failed: {error}"))
        })?;
        if !status.is_success() {
            return Err(ServerError::Internal(format!(
                "OA org usage request returned {status}"
            )));
        }
        let response: OaOrgUsageResponse = serde_json::from_str(&text).map_err(|error| {
            ServerError::Internal(format!("invalid OA org usage response: {error}"))
        })?;
        let pending_retry_after_seconds = retry_after_header(&headers)
            .or(response.retry_after_seconds)
            .unwrap_or(1)
            .max(1);
        validate_usage_response(
            response,
            client_request_id,
            key_hash,
            expectation.limit_credits,
            expectation.minimum_expires_at,
            expectation.maximum_expires_at,
            pending_retry_after_seconds,
        )
    }
}

fn parse_oa_rate_limit(headers: &reqwest::header::HeaderMap, body: &str) -> ServerError {
    let parsed = serde_json::from_str::<Value>(body).ok();
    let reason = parsed
        .as_ref()
        .and_then(machine_rate_limit_reason)
        .or_else(|| {
            parsed
                .as_ref()
                .and_then(classify_rate_limit_value)
                .map(str::to_string)
        })
        .or_else(|| classify_rate_limit_text(body).map(str::to_string))
        .unwrap_or_else(|| OA_RATE_LIMITED.to_string());
    let retry_after_seconds = retry_after_header(headers)
        .or_else(|| parsed.as_ref().and_then(retry_after_value))
        .unwrap_or(DEFAULT_OA_RETRY_AFTER_SECONDS);

    ServerError::OaRateLimited {
        reason,
        retry_after_seconds,
    }
}

fn retry_after_header(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn retry_after_value(value: &Value) -> Option<u64> {
    match value {
        Value::Object(values) => {
            for key in [
                "retry_after_seconds",
                "retryAfterSeconds",
                "retry_after",
                "retryAfter",
            ] {
                if let Some(retry_after) = values.get(key).and_then(retry_after_scalar) {
                    return Some(retry_after);
                }
            }
            values.get("detail").and_then(retry_after_value)
        }
        _ => None,
    }
}

fn retry_after_scalar(value: &Value) -> Option<u64> {
    match value {
        Value::Number(value) => value.as_u64(),
        Value::String(value) => value.trim().parse::<u64>().ok(),
        _ => None,
    }
}

fn classify_rate_limit_value(value: &Value) -> Option<&'static str> {
    match value {
        Value::String(value) => classify_rate_limit_text(value),
        Value::Object(values) => {
            for key in [
                "reason",
                "code",
                "error_code",
                "type",
                "message",
                "error",
                "detail",
            ] {
                if let Some(reason) = values.get(key).and_then(classify_rate_limit_value) {
                    return Some(reason);
                }
            }
            None
        }
        Value::Array(values) => values.iter().find_map(classify_rate_limit_value),
        _ => None,
    }
}

fn classify_rate_limit_text(value: &str) -> Option<&'static str> {
    let value = value.to_ascii_lowercase();
    let hourly = value.contains("hourly")
        || value.contains("per hour")
        || value.contains("per_hour")
        || value.contains("hour_limit");
    if hourly
        && (value.contains("issuance")
            || value.contains("budget")
            || value.contains("credit")
            || value.contains("limit"))
    {
        return Some(OA_HOURLY_ISSUANCE_BUDGET);
    }
    if value.contains("requests per minute")
        || value.contains("requests_per_minute")
        || value.contains("per-minute request")
        || value.contains("request rate")
    {
        return Some(OA_MINUTE_REQUEST_LIMIT);
    }
    None
}

fn machine_rate_limit_reason(value: &Value) -> Option<String> {
    let values = value.as_object()?;
    if let Some(reason) = values
        .get("reason")
        .and_then(Value::as_str)
        .and_then(normalize_machine_reason)
    {
        return Some(reason);
    }
    if let Some(reason) = values.get("detail").and_then(machine_rate_limit_reason) {
        return Some(reason);
    }
    for key in ["code", "error_code", "type"] {
        if let Some(code) = values
            .get(key)
            .and_then(Value::as_str)
            .and_then(normalize_machine_reason)
        {
            return Some(code);
        }
    }
    None
}

fn normalize_machine_reason(value: &str) -> Option<String> {
    let mut normalized = String::with_capacity(value.len().min(80));
    let mut separator_pending = false;
    for character in value.chars().take(160) {
        if character.is_ascii_alphanumeric() {
            if separator_pending && !normalized.is_empty() {
                normalized.push('_');
            }
            normalized.push(character.to_ascii_lowercase());
            separator_pending = false;
        } else if !normalized.is_empty() {
            separator_pending = true;
        }
        if normalized.len() >= 80 {
            break;
        }
    }
    let normalized = normalized.trim_end_matches('_');
    if normalized.is_empty() {
        return None;
    }
    match normalized {
        "minute_request_limit"
        | "oa_minute_request_limit"
        | "requests_per_minute_exceeded"
        | "request_rate_exceeded" => Some(OA_MINUTE_REQUEST_LIMIT.to_string()),
        "hourly_issuance_budget"
        | "oa_hourly_issuance_budget"
        | "hourly_issuance_budget_exceeded" => Some(OA_HOURLY_ISSUANCE_BUDGET.to_string()),
        _ => Some(OA_RATE_LIMITED.to_string()),
    }
}

fn validate_response(
    response: &OaOrgKeyResponse,
    requested_limit_usd: f64,
    requested_duration_minutes: u64,
    ttl_seconds: u64,
) -> Result<(), ServerError> {
    let now = current_timestamp();
    let limit_matches = response.credit_limit.is_finite()
        && (response.credit_limit - requested_limit_usd).abs()
            <= f64::EPSILON.max(requested_limit_usd * 1e-9);
    let expected_expiry = now.saturating_add(ttl_seconds);
    // An explicit idempotent station replay retains its original expiry. It
    // may have less lifetime remaining, but cannot extend the requested TTL.
    let expiry_is_bounded = response.expires_at_unix > now
        && (response.replayed || response.expires_at_unix >= expected_expiry.saturating_sub(30))
        && response.expires_at_unix <= expected_expiry.saturating_add(30);
    let verifier_is_secure = is_secure_or_loopback_url(&response.verifier_url);
    let inference_is_secure = is_secure_or_loopback_url(&response.openrouter_api_base);
    let signatures_are_hex =
        is_hex_signature(&response.station_signature) && is_hex_signature(&response.org_signature);
    if response.source != "oa_org"
        || response.key.is_empty()
        || response.key_hash.is_empty()
        || response.station_id.is_empty()
        || response.duration_minutes != requested_duration_minutes
        || !limit_matches
        || !expiry_is_bounded
        || !verifier_is_secure
        || !inference_is_secure
        || !signatures_are_hex
    {
        return Err(ServerError::Internal(
            "OA org returned unusable or unbounded key evidence".to_string(),
        ));
    }
    Ok(())
}

fn validate_usage_response(
    response: OaOrgUsageResponse,
    client_request_id: &str,
    key_hash: &str,
    expected_limit_credits: u128,
    minimum_expires_at: u64,
    maximum_expires_at: u64,
    pending_retry_after_seconds: u64,
) -> Result<OaOrgUsage, ServerError> {
    let common_matches = response.source == "oa_org"
        && response.version == 1
        && response.client_request_id == client_request_id
        && response.key_hash == key_hash
        && response.station_request_id.len() == 64
        && response
            .station_request_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit());
    if !common_matches {
        return Err(ServerError::Internal(
            "OA org returned mismatched usage evidence".to_string(),
        ));
    }
    if response.status == "pending" {
        return Ok(OaOrgUsage::Pending {
            retry_after_seconds: pending_retry_after_seconds.max(1),
        });
    }
    let (
        Some(usage_credits),
        Some(credit_limit_credits),
        Some(expires_at),
        Some(closed_at),
        Some(finalized_at),
        Some(station_id),
        Some(station_signature),
        Some(org_signature),
    ) = (
        response.usage_credits,
        response.credit_limit_credits,
        response.expires_at_unix,
        response.closed_at_unix,
        response.finalized_at_unix,
        response.station_id,
        response.station_signature,
        response.org_signature,
    )
    else {
        return Err(ServerError::Internal(
            "OA org returned incomplete final usage evidence".to_string(),
        ));
    };
    // Reported usage above the issued limit is returned as is: settlement
    // clamps it to the proof-bound budget. Rejecting it here would leave the
    // lease unsettleable. The limit itself must match the issued binding.
    if response.status != "finalized"
        || credit_limit_credits != expected_limit_credits
        || expires_at < minimum_expires_at
        || expires_at > maximum_expires_at
        || closed_at > expires_at
        || finalized_at < closed_at
        || station_id.is_empty()
        || !is_hex_signature(&station_signature)
        || !is_hex_signature(&org_signature)
    {
        return Err(ServerError::Internal(
            "OA org returned usage outside the issued lease bounds".to_string(),
        ));
    }
    Ok(OaOrgUsage::Finalized(OaOrgFinalUsage {
        usage_credits,
        expires_at,
        closed_at,
        finalized_at,
        station_id,
        station_signature,
        org_signature,
    }))
}

/// These exact OA request_key validation errors occur before station/provider
/// I/O. This says nothing about an earlier attempt: the processor must preserve
/// any durable uncertainty from that attempt. Never infer nonissuance from an
/// arbitrary HTTP status, transport error, malformed success or missing key.
fn is_definitive_policy_rejection(status: reqwest::StatusCode, body: &str) -> bool {
    if status != reqwest::StatusCode::BAD_REQUEST {
        return false;
    }
    let Ok(value) = serde_json::from_str::<Value>(body) else {
        return false;
    };
    matches!(
        value.get("detail").and_then(Value::as_str),
        Some(
            "credit_limit exceeds zkAPI policy"
                | "credit_limit_credits exceeds zkAPI policy"
                | "duration_minutes exceeds zkAPI policy"
        )
    )
}

fn is_hex_signature(value: &str) -> bool {
    value.len() == 128 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn is_secure_or_loopback_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://localhost:")
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    use axum::http::StatusCode;
    use axum::routing::post;
    use axum::{Json, Router};

    #[test]
    fn only_exact_pre_provider_policy_rejections_confirm_nonissuance() {
        for detail in [
            "credit_limit exceeds zkAPI policy",
            "credit_limit_credits exceeds zkAPI policy",
            "duration_minutes exceeds zkAPI policy",
        ] {
            let body = json!({"detail": detail}).to_string();
            assert!(is_definitive_policy_rejection(
                StatusCode::BAD_REQUEST,
                &body
            ));
            for status in [
                StatusCode::OK,
                StatusCode::UNAUTHORIZED,
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::INTERNAL_SERVER_ERROR,
            ] {
                assert!(!is_definitive_policy_rejection(status, &body));
            }
        }
        for body in [
            "",
            "null",
            r#"{"detail":"provider failed"}"#,
            r#"{"detail":{"message":"credit_limit exceeds zkAPI policy"}}"#,
            r#"{"detail":"credit_limit exceeds zkAPI policy after issuance"}"#,
        ] {
            assert!(!is_definitive_policy_rejection(
                StatusCode::BAD_REQUEST,
                body
            ));
        }
    }

    #[test]
    fn delayed_issuance_requires_explicit_replay_and_preserves_expiry_bounds() {
        let now = current_timestamp();
        let value = json!({
            "source":"oa_org", "key":"runtime-key", "key_hash":"hash", "credit_limit":1.0,
            "duration_minutes":5, "expires_at_unix":now + 120,
            "station_id":"station", "station_recently_attested":true,
            "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64),
            "verifier_url":"https://verifier.example", "openrouter_api_base":"https://openrouter.ai/api/v1"
        });
        let mut response: OaOrgKeyResponse = serde_json::from_value(value).unwrap();
        assert!(!response.replayed);
        assert!(validate_response(&response, 1.0, 5, 300).is_err());
        response.replayed = true;
        assert!(validate_response(&response, 1.0, 5, 300).is_ok());
        assert_eq!(response.expires_at_unix, now + 120);
        response.expires_at_unix = now;
        assert!(validate_response(&response, 1.0, 5, 300).is_err());
        response.expires_at_unix = now + 1000;
        assert!(validate_response(&response, 1.0, 5, 300).is_err());
        response.expires_at_unix = now + 120;
        response.credit_limit = 2.0;
        assert!(validate_response(&response, 1.0, 5, 300).is_err());
        response.credit_limit = 1.0;
        response.duration_minutes = 10;
        assert!(validate_response(&response, 1.0, 5, 300).is_err());
    }

    #[test]
    fn string_detail_identifies_the_hourly_issuance_guard() {
        let error = parse_oa_rate_limit(
            &reqwest::header::HeaderMap::new(),
            r#"{"detail":"zkAPI hourly issuance budget exceeded"}"#,
        );

        assert!(matches!(
            error,
            ServerError::OaRateLimited {
                ref reason,
                retry_after_seconds: DEFAULT_OA_RETRY_AFTER_SECONDS,
            } if reason == OA_HOURLY_ISSUANCE_BUDGET
        ));
    }

    #[test]
    fn object_detail_prefers_explicit_reason_and_retry_after_header() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            reqwest::header::HeaderValue::from_static("42"),
        );
        let error = parse_oa_rate_limit(
            &headers,
            r#"{
                "detail": {
                    "code": "zkapi_rate_limited",
                    "reason": "minute_request_limit",
                    "message": "hourly issuance budget text must not override reason",
                    "retry_after_seconds": "17"
                }
            }"#,
        );

        assert!(matches!(
            error,
            ServerError::OaRateLimited {
                ref reason,
                retry_after_seconds: 42,
            } if reason == OA_MINUTE_REQUEST_LIMIT
        ));
    }

    #[test]
    fn unknown_object_reason_uses_the_stable_generic_fallback() {
        let error = parse_oa_rate_limit(
            &reqwest::header::HeaderMap::new(),
            r#"{
                "detail": {
                    "code": "Concurrent Lease Limit",
                    "retryAfterSeconds": 9
                }
            }"#,
        );

        assert!(matches!(
            error,
            ServerError::OaRateLimited {
                ref reason,
                retry_after_seconds: 9,
            } if reason == OA_RATE_LIMITED
        ));
    }

    #[tokio::test]
    async fn create_key_turns_an_oa_429_into_a_typed_retriable_error() {
        async fn rate_limited() -> (
            StatusCode,
            [(axum::http::HeaderName, &'static str); 1],
            Json<Value>,
        ) {
            (
                StatusCode::TOO_MANY_REQUESTS,
                [(axum::http::header::RETRY_AFTER, "23")],
                Json(json!({
                    "detail": {
                        "code": "zkapi_rate_limited",
                        "reason": "hourly_issuance_budget",
                        "retry_after_seconds": 11
                    }
                })),
            )
        }

        let app = Router::new().route("/api/zkapi/request_key", post(rate_limited));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let provisioner = OaOrgProvisioner::new(
            format!("http://127.0.0.1:{}", address.port()),
            "shared-secret".to_string(),
        )
        .unwrap();

        let error = provisioner
            .create_key("request-12345678", 3.0, 3_000_000, 300)
            .await
            .unwrap_err();
        server.abort();

        assert!(matches!(
            &error,
            ServerError::OaRateLimited {
                reason,
                retry_after_seconds: 23,
            } if reason == OA_HOURLY_ISSUANCE_BUDGET
        ));
        assert!(error.is_retriable());
    }

    #[tokio::test]
    async fn get_key_usage_preserves_pending_retry_after_header() {
        async fn pending() -> (
            StatusCode,
            [(axum::http::HeaderName, &'static str); 1],
            Json<Value>,
        ) {
            (
                StatusCode::OK,
                [(axum::http::header::RETRY_AFTER, "15")],
                Json(json!({
                    "source": "oa_org",
                    "version": 1,
                    "status": "pending",
                    "client_request_id": "request-12345678",
                    "station_request_id": "ab".repeat(32),
                    "key_hash": "provider-hash",
                    "retry_after_seconds": 7
                })),
            )
        }

        let app = Router::new().route("/api/zkapi/key_usage", post(pending));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let provisioner = OaOrgProvisioner::new(
            format!("http://127.0.0.1:{}", address.port()),
            "shared-secret".to_string(),
        )
        .unwrap();

        let usage = provisioner
            .get_key_usage(
                "request-12345678",
                "provider-hash",
                OaOrgUsageExpectation {
                    credit_limit_usd: 10.0,
                    duration_minutes: 5,
                    limit_credits: 10_000_000,
                    minimum_expires_at: 1_000,
                    maximum_expires_at: 1_030,
                },
            )
            .await
            .unwrap();
        server.abort();

        assert!(matches!(
            usage,
            OaOrgUsage::Pending {
                retry_after_seconds: 15
            }
        ));
    }

    #[test]
    fn signatures_require_exact_ed25519_hex_encoding() {
        assert!(is_hex_signature(&"ab".repeat(64)));
        assert!(!is_hex_signature(&"ab".repeat(63)));
        assert!(!is_hex_signature(&"zz".repeat(64)));
    }

    #[test]
    fn only_https_or_explicit_loopback_urls_are_accepted() {
        assert!(is_secure_or_loopback_url("https://verifier.example"));
        assert!(is_secure_or_loopback_url("http://127.0.0.1:8080"));
        assert!(!is_secure_or_loopback_url("http://verifier.example"));
    }

    #[test]
    fn org_client_refuses_to_send_a_secret_over_plaintext_http() {
        assert!(
            OaOrgProvisioner::new("http://org.example".to_string(), "secret".to_string()).is_err()
        );
        assert!(
            OaOrgProvisioner::new("http://127.0.0.1:8005".to_string(), "secret".to_string())
                .is_ok()
        );
    }

    #[test]
    fn final_usage_must_match_the_exact_issued_lease() {
        let response = OaOrgUsageResponse {
            source: "oa_org".to_string(),
            version: 1,
            status: "finalized".to_string(),
            client_request_id: "request-12345678".to_string(),
            station_request_id: "ab".repeat(32),
            key_hash: "provider-hash".to_string(),
            retry_after_seconds: None,
            usage_credits: Some(123),
            credit_limit_credits: Some(10_000),
            expires_at_unix: Some(1_000),
            closed_at_unix: Some(900),
            finalized_at_unix: Some(1_020),
            station_id: Some("station".to_string()),
            station_signature: Some("ab".repeat(64)),
            org_signature: Some("cd".repeat(64)),
        };
        let usage = validate_usage_response(
            response,
            "request-12345678",
            "provider-hash",
            10_000,
            970,
            1_000,
            1,
        )
        .unwrap();
        assert!(matches!(usage, OaOrgUsage::Finalized(_)));
    }

    #[test]
    fn usage_above_limit_is_returned_for_clamping() {
        let response = |usage_credits, credit_limit_credits| OaOrgUsageResponse {
            source: "oa_org".to_string(),
            version: 1,
            status: "finalized".to_string(),
            client_request_id: "request-12345678".to_string(),
            station_request_id: "ab".repeat(32),
            key_hash: "provider-hash".to_string(),
            retry_after_seconds: None,
            usage_credits: Some(usage_credits),
            credit_limit_credits: Some(credit_limit_credits),
            expires_at_unix: Some(1_000),
            closed_at_unix: Some(900),
            finalized_at_unix: Some(1_020),
            station_id: Some("station".to_string()),
            station_signature: Some("ab".repeat(64)),
            org_signature: Some("cd".repeat(64)),
        };
        let validate = |response| {
            validate_usage_response(
                response,
                "request-12345678",
                "provider-hash",
                10_000,
                970,
                1_000,
                1,
            )
        };
        assert!(matches!(
            validate(response(20_000, 10_000)).unwrap(),
            OaOrgUsage::Finalized(OaOrgFinalUsage {
                usage_credits: 20_000,
                ..
            })
        ));
        // The issued limit is evidence identity, not a usage bound.
        assert!(validate(response(5_000, 20_000)).is_err());
    }

    #[test]
    fn pending_usage_preserves_the_oa_retry_boundary() {
        let response = OaOrgUsageResponse {
            source: "oa_org".to_string(),
            version: 1,
            status: "pending".to_string(),
            client_request_id: "request-12345678".to_string(),
            station_request_id: "ab".repeat(32),
            key_hash: "provider-hash".to_string(),
            retry_after_seconds: Some(7),
            usage_credits: None,
            credit_limit_credits: None,
            expires_at_unix: None,
            closed_at_unix: None,
            finalized_at_unix: None,
            station_id: None,
            station_signature: None,
            org_signature: None,
        };

        let usage = validate_usage_response(
            response,
            "request-12345678",
            "provider-hash",
            10_000,
            970,
            1_000,
            15,
        )
        .unwrap();

        assert!(matches!(
            usage,
            OaOrgUsage::Pending {
                retry_after_seconds: 15
            }
        ));
    }
}
