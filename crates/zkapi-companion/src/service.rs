//! Core client daemon service.
//!
//! [`AuthService`] is the central handle behind every clientd HTTP route. It
//! owns the wallet lifecycle — deposit preparation/confirmation, request
//! execution, status reporting, crash recovery, and withdrawal-proof
//! generation — and talks to the indexer for tree state and to serverd for
//! request processing.
//!
//! All wallet access is serialized by an in-process mutex and guarded by an
//! exclusive on-disk lock file (`.wallet.lock`), so concurrent requests and a
//! second daemon instance pointed at the same state directory cannot corrupt
//! the persisted note state. Blocking wallet/proof work runs on a blocking
//! task so the async runtime stays responsive.

use crate::oa_station_trust::{StationTrust, TRUSTED_STATION};

#[path = "exit.rs"]
pub(crate) mod exit;
use std::collections::BTreeMap;
use std::fs::OpenOptions;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use fs2::FileExt;
use futures_util::stream::{self, BoxStream};
use futures_util::StreamExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use zkapi_client::config::{ClientConfig, ClientProofMode};
use zkapi_client::wallet::Wallet;
use zkapi_core::v2 as core_v2;
use zkapi_types::wire::{
    ApiRequestV2, ErrorResponse, Groth16ProofWire, OpenRouterLeaseAuthorization,
    OpenRouterLeaseResponse, OpenRouterLeaseStatusResponse, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2C};

// A generic OpenAI request has no authenticated conversation boundary. Never
// hand the same provider key to two calls, including after a lost reply or a
// daemon restart. A consumed lease remains reserved until server settlement
// allows the wallet to create a different lease.
/// Waits before resending a byte-identical lease request that the server
/// called stale while the pinned vault still has its root.
#[cfg(not(test))]
const STALE_ROOT_RESEND_DELAYS: [Duration; 4] = [
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
];
#[cfg(test)]
const STALE_ROOT_RESEND_DELAYS: [Duration; 4] = [Duration::from_millis(1); 4];

/// `currentRoot()` of the vault.
const VAULT_CURRENT_ROOT_SELECTOR: &str = "0xfdab463d";

fn reserve_oa_bridge_lease(state_dir: &Path, lease_id: &str) -> Result<(), AuthError> {
    use sha3::{Digest, Keccak256};
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let directory = state_dir.join("oa-issued-leases");
    std::fs::create_dir_all(&directory)
        .map_err(|_| AuthError::Wallet("cannot persist lease reservation".into()))?;
    std::fs::File::open(state_dir)
        .and_then(|file| file.sync_all())
        .map_err(|_| AuthError::Wallet("cannot sync lease reservation parent".into()))?;
    let name = format!("{:x}", Keccak256::digest(lease_id.as_bytes()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let file = options.open(directory.join(name)).map_err(|error| {
        if error.kind() == std::io::ErrorKind::AlreadyExists {
            AuthError::LeasePending(
                "this key has already been used; wait for settlement before requesting another"
                    .into(),
            )
        } else {
            AuthError::Wallet("cannot persist lease reservation".into())
        }
    })?;
    file.sync_all()
        .map_err(|_| AuthError::Wallet("cannot sync lease reservation".into()))?;
    std::fs::File::open(&directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| AuthError::Wallet("cannot sync lease reservation directory".into()))?;
    Ok(())
}

// OA server leases stop before the signed provider key expires. Match the
// browser's bounded safety margin; never extend the lease's usable deadline.
fn testnet_http_error(error: reqwest::Error) -> AuthError {
    if error.status() == Some(reqwest::StatusCode::UNAUTHORIZED) {
        AuthError::TestnetPasswordRequired
    } else {
        AuthError::Wallet("protocol server request failed".into())
    }
}

fn oa_key_expiry_covers_lease(key_valid_till: u64, lease_expires_at: u64) -> bool {
    key_valid_till
        .checked_sub(lease_expires_at)
        .is_some_and(|safety_margin| safety_margin <= MAX_OA_EVIDENCE_EXPIRY_SKEW_SECONDS)
}

fn oa_verifier_binds_key(result: &Value, station_id: &str, api_key: &str) -> bool {
    use sha2::{Digest, Sha256};
    let expected_hash = format!("{:x}", Sha256::digest(api_key.as_bytes()));
    result.get("status").and_then(Value::as_str) == Some("verified")
        && result.get("station_id").and_then(Value::as_str) == Some(station_id)
        && result
            .get("key_hash")
            .and_then(Value::as_str)
            .is_some_and(|hash| match hash.len() {
                // The deployed verifier and browser use an exact eight-byte
                // SHA-256 prefix. Full hashes are accepted without weakening
                // their comparison to a prefix-only match.
                16 => hash == &expected_hash[..16],
                64 => hash == expected_hash,
                _ => false,
            })
}

// A new client has neither a connection pool nor prior TLS session state.
// It inherits the authenticated local CONNECT proxy for direct TCP or Wisp.
pub(crate) fn fresh_private_http() -> Result<reqwest::Client, AuthError> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(180))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| AuthError::Wallet("cannot initialize private transport".into()))
}

fn compute_payload_hash(payload: impl AsRef<[u8]>) -> Felt252 {
    // Must match the protocol's canonical request-payload binding; the wallet
    // re-derives and rejects on mismatch (`request_flow`), and the value feeds
    // the request public inputs.
    zkapi_types::canonical_payload_hash(payload.as_ref())
}

use crate::config::{AuthConfig, ModelDescriptor, RequestMode};
use crate::error::AuthError;
use crate::indexer::IndexerClient;

const DIRECT_REMOTE_MAX_ATTEMPTS: usize = 3;
const DIRECT_REMOTE_RETRY_BASE_DELAY: Duration = Duration::from_millis(250);
const DIRECT_REMOTE_RETRY_MAX_DELAY: Duration = Duration::from_secs(5);
const DIRECT_LEASE_RETIRE_POLL_INTERVAL: Duration = Duration::from_secs(2);
const DIRECT_LEASE_RETIRE_MAX_WAIT: Duration = Duration::from_secs(45);
include!(concat!(env!("OUT_DIR"), "/embedded_funding_assets.rs"));

fn embedded_funding_text(path: &str) -> &'static str {
    let (bytes, _) = embedded_funding_asset(path).expect("frontend index is embedded");
    std::str::from_utf8(bytes).expect("frontend index is UTF-8")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoreRequest {
    #[serde(default = "default_method")]
    pub method: String,
    pub path: String,
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    #[serde(default = "default_body")]
    pub body: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CoreResponse {
    pub client_request_id: String,
    pub response_code: u16,
    pub raw_payload: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<Value>,
    pub charge_applied: u128,
    pub next_anchor: Felt252,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remaining_balance: Option<u128>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NoteStatus {
    pub note_id: u32,
    pub deposit_amount: u128,
    pub current_balance: u128,
    pub expiry_ts: u64,
    pub is_genesis: bool,
    pub current_anchor: Felt252,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WalletStatus {
    pub has_note: bool,
    pub pending_request: bool,
    pub funding_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<NoteStatus>,
}

/// A low-balance note moved out of the active wallet slot.
///
/// `state_dir` remains a complete wallet state directory, so the note can be
/// selected later for withdrawal without keeping it in the daemon's active
/// request path.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RetiredNote {
    pub note_id: u32,
    pub remaining_balance: u128,
    pub state_dir: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FundingConfig {
    pub deployment_id: String,
    pub billing_asset: String,
    pub billing_unit: String,
    pub native_asset_wei_per_unit: String,
    pub native_price_feed_address: String,
    pub native_price_feed_decimals: u8,
    pub native_price_max_age_seconds: u64,

    pub contract_address: Felt252,
    pub chain_id: u64,
    pub indexer_url: String,
    pub protocol_server_url: String,
    pub models: Vec<ModelDescriptor>,
    /// Suggested ERC-20 base-unit amount for a fresh note. The browser can
    /// override this, but should present a safe default with request headroom.
    pub suggested_deposit_amount: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demo_rpc_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demo_billing_token_address: Option<String>,
    pub demo_mint_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demo_note_ttl_seconds: Option<u64>,
}

/// Integration credit unit: 1 credit = 1 micro-US-dollar. Mirrors
/// `zkapi_serverd::pricing::CREDITS_PER_USD`; used by the client UI to render
/// USD next to credit amounts when the server doesn't report its own scale.
pub const CREDITS_PER_USD: f64 = 1_000_000.0;

/// Integration configuration surfaced to browser clients: the credit scale,
/// per-request cap, funding parameters, and upstream metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ZkapiConfig {
    pub credits_per_usd: f64,
    pub request_charge_cap: u128,
    pub request_charge_cap_usd: f64,
    pub policy_charge_cap: u128,
    pub policy_enabled: bool,
    pub funding: FundingConfig,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upstream_kind: Option<String>,
    pub direct_openrouter_available: bool,
    pub request_mode: RequestMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_lease: Option<DirectLeaseStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prepared_withdrawal: Option<PreparedWithdrawalStatus>,
}

/// Non-secret metadata for the prompt-private key currently held in memory.
/// The API key itself is intentionally never exposed by the local daemon.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectLeaseStatus {
    pub session_id: String,
    pub client_request_id: String,
    pub expires_at: u64,
    pub settle_after: u64,
}

/// Non-secret metadata for an on-chain withdrawal prepared by the daemon.
/// The full proof stays in memory and is returned idempotently only from the
/// withdrawal endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PreparedWithdrawalStatus {
    pub mode: WithdrawalMode,
    pub note_id: u32,
    pub destination: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DemoOverview {
    pub wallet: WalletStatus,
    pub funding: FundingConfig,
    pub indexer: IndexerSnapshot,
    pub server: ServerSnapshot,
    pub runtime_proof_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IndexerSnapshot {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_note_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerSnapshot {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ServerHealthSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation: Option<ServerAttestationSnapshot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerHealthSnapshot {
    pub status: String,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub current_root: Felt252,
    pub provider: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub indexer_url: Option<String>,
    pub policy_enabled: bool,
    #[serde(default)]
    pub auth_scheme: String,
    #[serde(default)]
    pub request_modes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerAttestationSnapshot {
    pub status: String,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub current_root: Felt252,
    pub state_signing_key: zkapi_types::wire::CurvePointWire,
    pub clearance_signing_key: zkapi_types::wire::CurvePointWire,
    #[serde(default)]
    pub auth_scheme: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestPreview {
    pub request: CoreRequest,
    pub payload: String,
    pub payload_hash: Felt252,
    pub registration_commitment: Felt252,
    pub note_leaf: Felt252,
    pub request_nullifier: Felt252,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    pub solvency_bound: u128,
    pub wallet_note: NoteStatus,
    pub state_sig_epoch: u32,
    pub state_sig_root: Felt252,
    pub runtime_proof_backend: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProtocolResponseTrace {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment_x: Felt252,
    pub next_commitment_y: Felt252,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_sig_epoch: u32,
    pub next_state_sig_root: Felt252,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RequestDemoResult {
    pub preview: RequestPreview,
    pub response: CoreResponse,
    pub protocol_response: ProtocolResponseTrace,
    pub wallet: WalletStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DepositPlan {
    pub amount: u128,
    pub secret: Felt252,
    pub commitment: Felt252,
    pub next_note_id: u32,
    pub active_root: Felt252,
    pub zero_path: Vec<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ConfirmDepositRequest {
    pub secret: Felt252,
    pub note_id: u32,
    pub amount: u128,
    pub expiry_ts: u64,
    /// Amendment A1: the root the deposit set (`NoteDeposited.newRoot`) and
    /// the note's siblings at it (the zero path the deposit was made with).
    /// Kept for every later exit when they prove the note's leaf.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_root: Option<Felt252>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_siblings: Option<Vec<Felt252>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RecoverResult {
    pub recovered: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<CoreResponse>,
    pub wallet: WalletStatus,
}

#[derive(Clone)]
struct ActiveOpenRouterLease {
    session_id: String,
    client_request_id: String,
    api_key: String,
    openrouter_api_base: String,
    expires_at: u64,
    settle_after: u64,
    verification: Option<OaKeyVerificationEvidence>,
    verified: bool,
    verification_detail: Option<String>,
    requests_served: u32,
}

/// What withdrawal settlement found for a pending lease request that has no
/// live key in this daemon.
enum PendingLease {
    /// The server's record of the lease.
    Lease(OpenRouterLeaseStatusResponse),
    /// The server never admitted the request and never will, or recovery
    /// already settled the state: set the journal aside, if still pending,
    /// into the request archive with this disposition.
    SetAside(&'static str),
}

/// An upstream response whose body owns the local inference lock.
///
/// The time-bounded OpenRouter lease remains in memory after EOF and can serve
/// later local LLM calls. Consuming or dropping the body only releases the
/// lock that prevents two streams from using the same key concurrently.
pub struct StreamingCoreResponse {
    pub status: reqwest::StatusCode,
    pub content_type: Option<reqwest::header::HeaderValue>,
    pub cache_control: Option<reqwest::header::HeaderValue>,
    pub body: BoxStream<'static, Result<Bytes, io::Error>>,
}

struct DirectOpenRouterStreamFinalizer {
    service: Arc<AuthService>,
    client_request_id: Option<String>,
    request_guard: Option<tokio::sync::OwnedRwLockReadGuard<()>>,
}

impl Drop for DirectOpenRouterStreamFinalizer {
    fn drop(&mut self) {
        let Some(client_request_id) = self.client_request_id.take() else {
            return;
        };
        let service = self.service.clone();
        let request_guard = self.request_guard.take();
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            tracing::warn!(
                %client_request_id,
                "stream ended outside the async runtime; lease settlement will resume on the next request"
            );
            return;
        };
        runtime.spawn(async move {
            drop(request_guard);
            let _request_guard = service.direct_request_mutex.clone().write_owned().await;
            service
                .finish_direct_openrouter_lease(client_request_id)
                .await;
        });
    }
}

#[derive(Debug, Deserialize)]
struct OpenRouterLeaseExtensions {
    #[serde(default = "default_openrouter_key_source")]
    key_source: String,
    #[serde(default)]
    verification: Option<OaKeyVerificationEvidence>,
    #[serde(default)]
    billing_quote: Option<crate::oa_native::Quote>,
}

#[derive(Debug, Clone, Deserialize)]
struct OaKeyVerificationEvidence {
    verifier_url: String,
    station_id: String,
    // Retained for wire compatibility; this untrusted hint never grants fallback.
    #[allow(dead_code)]
    #[serde(default)]
    station_recently_attested: bool,
    key_valid_till: u64,
    station_signature: String,
    org_signature: String,
}

const MAX_OA_SIGNATURE_ENCODING_LEN: usize = 4_096;
const MAX_OA_EVIDENCE_EXPIRY_SKEW_SECONDS: u64 = 60;

fn validate_oa_key_evidence(
    expires_at: u64,
    evidence: &OaKeyVerificationEvidence,
) -> Result<(), AuthError> {
    if evidence.station_id.trim().is_empty() {
        return Err(AuthError::KeyVerification(
            "OA key evidence omitted the station ID".to_string(),
        ));
    }
    if !oa_key_expiry_covers_lease(evidence.key_valid_till, expires_at) {
        return Err(AuthError::KeyVerification(format!(
            "OA key evidence expiry {} does not safely cover lease expiry {expires_at}",
            evidence.key_valid_till
        )));
    }
    for (label, signature) in [
        ("station", evidence.station_signature.as_str()),
        ("org", evidence.org_signature.as_str()),
    ] {
        if signature.is_empty() {
            return Err(AuthError::KeyVerification(format!(
                "OA key evidence omitted the {label} signature"
            )));
        }
        if signature.len() > MAX_OA_SIGNATURE_ENCODING_LEN {
            return Err(AuthError::KeyVerification(format!(
                "OA key evidence {label} signature encoding is oversized"
            )));
        }
    }
    Ok(())
}

#[derive(Debug)]
struct OaVerificationOutcome {
    verified: bool,
    detail: Option<&'static str>,
}

fn oa_transport_unavailable(error: &reqwest::Error) -> bool {
    use std::error::Error;
    let mut network_outage = false;
    let mut source: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(cause) = source {
        let text = cause.to_string().to_ascii_lowercase();
        if [
            "certificate",
            "cert ",
            "tls",
            "ssl",
            "invalid peer",
            "unknown issuer",
            "proxy authentication",
            "canceled",
            "cancelled",
        ]
        .iter()
        .any(|term| text.contains(term))
        {
            return false;
        }
        if let Some(io) = cause.downcast_ref::<io::Error>() {
            network_outage |= matches!(
                io.kind(),
                io::ErrorKind::ConnectionRefused
                    | io::ErrorKind::NetworkUnreachable
                    | io::ErrorKind::HostUnreachable
                    | io::ErrorKind::TimedOut
            );
        }
        source = cause.source();
    }
    // is_connect also includes failed TLS handshakes. Unknown connection errors
    // must fail closed rather than silently admitting a verifier transport failure.
    network_outage || error.is_timeout()
}

fn oa_verifier_hard_failure(result: &Value, temporary_ownership: bool) -> bool {
    let status = result.get("status").and_then(Value::as_str).unwrap_or("");
    if result.get("status").is_some_and(|value| !value.is_string())
        || result
            .get("banned_station")
            .is_some_and(|value| !value.is_null() && *value != Value::Bool(false))
        || ["banned", "rejected", "denied", "invalid"].contains(&status)
        || (status == "unverified" && !temporary_ownership)
        || result.get("ownership_passed") == Some(&Value::Bool(false))
        || result.pointer("/ownership/ownership_passed") == Some(&Value::Bool(false))
    {
        return true;
    }
    for field in ["error", "detail", "message"] {
        let text = result
            .get(field)
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| value.to_string())
            })
            .unwrap_or_default()
            .to_ascii_lowercase();
        if [
            "invalid signature",
            "signature mismatch",
            "expired",
            "invalid key",
            "privacy",
            "logging",
            "training",
            "banned",
        ]
        .iter()
        .any(|term| text.contains(term))
            || (text.contains("ownership")
                && (text.contains("mismatch") || text.contains("failed")))
        {
            return true;
        }
    }
    false
}

fn oa_verifier_banned(result: &Value) -> bool {
    result["status"] == "banned"
        || result
            .get("banned_station")
            .is_some_and(|v| !v.is_null() && *v != Value::Bool(false))
        || ["error", "detail", "message"].iter().any(|field| {
            result
                .get(field)
                .is_some_and(|v| v.to_string().to_ascii_lowercase().contains("banned"))
        })
}

fn oa_verifier_outage(
    status: Option<u16>,
    result: &Value,
    expires_at: u64,
    evidence: &OaKeyVerificationEvidence,
    api_key: &str,
    configured_verifier: &str,
    trust: StationTrust<'_>,
) -> Result<OaVerificationOutcome, AuthError> {
    let fail =
        || AuthError::KeyVerification("verifier did not approve a trusted station key".into());
    if expires_at <= now_seconds()
        || evidence.key_valid_till <= now_seconds()
        || !oa_key_expiry_covers_lease(evidence.key_valid_till, expires_at)
        || status.is_some_and(|s| !(200..300).contains(&s) && !(400..600).contains(&s))
        || result.get("status").is_some_and(|v| !v.is_string())
        || oa_verifier_banned(result)
        || ["status", "error", "detail", "message"]
            .iter()
            .any(|field| {
                result
                    .get(field)
                    .is_some_and(|v| v.to_string().to_ascii_lowercase().contains("expired"))
            })
        || !trust.authenticates(
            configured_verifier,
            &evidence.verifier_url,
            &evidence.station_id,
            api_key,
            evidence.key_valid_till,
            &evidence.station_signature,
        )
    {
        return Err(fail());
    }
    // The locally pinned station authenticated this key. Its provider ownership
    // and privacy settings remain unconfirmed, even for an explicit refusal.
    Ok(OaVerificationOutcome {
        verified: false,
        detail: Some("trusted_station_fallback"),
    })
}

fn default_openrouter_key_source() -> String {
    "openrouter".to_string()
}

fn is_secure_or_loopback_url(value: &str) -> bool {
    value.starts_with("https://")
        || value.starts_with("http://127.0.0.1:")
        || value.starts_with("http://localhost:")
}

fn matches_trusted_url(supplied: &str, expected: &str) -> bool {
    let expected = expected.trim_end_matches('/');
    is_secure_or_loopback_url(expected) && supplied.trim_end_matches('/') == expected
}

fn enforce_required_key_source(require_oa: bool, source: &str) -> Result<(), AuthError> {
    if require_oa && source != "oa_org" {
        return Err(AuthError::KeyVerification(
            "client policy requires an OA-org verifier-backed key".to_string(),
        ));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WithdrawalMode {
    Mutual,
    Escape,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WithdrawalPlan {
    pub mode: WithdrawalMode,
    pub public_inputs: WithdrawalPublicInputsV2C,
    /// The note's Merkle sibling path, so the on-chain submitter (cast or the
    /// browser wallet) can call `mutualClose`/escape without a per-slot lookup.
    pub siblings: Vec<Felt252>,
    /// Complete opaque proof artifact, including backend and public-output hash.
    pub proof: Groth16ProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WithdrawalChainStatus {
    pub note_id: u32,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub challenge_deadline: Option<u64>,
    pub wallet: WalletStatus,
}

pub struct AuthService {
    config: AuthConfig,
    wallet_mutex: Arc<Mutex<()>>,
    indexer: IndexerClient,
    direct_lease: tokio::sync::Mutex<Option<ActiveOpenRouterLease>>,
    direct_request_mutex: Arc<tokio::sync::RwLock<()>>,
    prepared_withdrawal: tokio::sync::Mutex<Option<WithdrawalPlan>>,
    oa_banned_stations: Mutex<std::collections::HashSet<String>>,
    oa_session_events: Arc<crate::oa_events::SessionEvents>,
}

impl AuthService {
    pub fn new(config: AuthConfig) -> Result<Arc<Self>, AuthError> {
        std::fs::create_dir_all(&config.state_dir)
            .map_err(|err| AuthError::Wallet(err.to_string()))?;
        let prepared_withdrawal = load_prepared_withdrawal(&config.state_dir)?;
        // C1: the one process-wide lock of this wallet.
        let wallet_mutex = crate::wallet_lock::WalletLock::for_state_dir(&config.state_dir);
        Ok(Arc::new(Self {
            indexer: IndexerClient::new(config.indexer_url.clone()),
            config,
            wallet_mutex,
            direct_lease: tokio::sync::Mutex::new(None),
            direct_request_mutex: Arc::new(tokio::sync::RwLock::new(())),
            prepared_withdrawal: tokio::sync::Mutex::new(prepared_withdrawal),
            oa_banned_stations: Mutex::new(Default::default()),
            oa_session_events: Arc::new(crate::oa_events::SessionEvents::new()),
        }))
    }

    // The Go gateway receives only an admitted provider lease with explicit verification status. Prompt content
    // never enters the wallet/prover bridge or the zkAPI payment server.
    pub fn oa_bridge_status(&self) -> serde_json::Value {
        serde_json::json!({
            // 5: circuit zkapi-v2-concession-v1 with the escape routes
            // /oa/v1/withdraw/escape/{prepare,submit,status,finalize};
            // escape_routes_version 2 adds /oa/v1/withdraw/escape/cancel.
            "bridge_version": 5,
            "exit_concession": 1,
            "setup_id": self.config.setup_id,
            "settlement_window_seconds": self.config.settlement_window_seconds,
            "escape_routes_version": 2,
            "session_events_version": 1,
            "deployment_id": self.config.deployment_id,
            "contract_address": self.config.contract_address,
            "billing_asset": self.config.billing_asset,
            "billing_unit": self.config.billing_unit,
            "circuit_id": zkapi_proof::compact::CIRCUIT_ID,
            "withdrawal_bridge_version": 1,
            // Clearance requests carry an ownership proof (kind 2 on
            // circuit zkapi-v2-concession-v1).
            "clearance_ownership_proof_version": 1,
            // /oa/v1/withdraw/prepare accepts accept_unsettled_request_risk
            // (ignored: the exit rules of §6.4 decide).
            "unsettled_request_override_version": 1,
            "chain_id": self.config.chain_id,
            "mode": self.config.request_mode,
            "require_oa_org_key_source": self.config.require_oa_org_key_source,
        })
    }

    pub(crate) fn oa_session_events(&self) -> crate::oa_events::SessionEventsSnapshot {
        self.oa_session_events.snapshot()
    }

    async fn oa_check_spending(&self) -> Result<(), AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(&config, wallet.state().map(|state| state.note_id))
        })
        .await
    }

    pub async fn oa_withdrawal_status(&self) -> Result<Value, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            Ok(crate::oa_withdrawal::public_status(
                crate::oa_withdrawal::load(&config)?.as_ref(),
            ))
        })
        .await
    }

    /// Reserve the note and obtain a mutual close (kind 1). The clearance
    /// request always carries the state's ownership proof (kind 2), which a
    /// `zkapi-v2-concession-v1` server requires and no vault entry point
    /// accepts. `_accept_unsettled_request_risk` is accepted for the bridge's
    /// request shape and ignored: it only chose between a proof-less and a
    /// proof-carrying clearance on a legacy vault.
    pub async fn oa_prepare_withdrawal(
        &self,
        destination: [u8; 20],
        _accept_unsettled_request_risk: bool,
    ) -> Result<WithdrawalPlan, AuthError> {
        crate::oa_withdrawal::check_destination(&self.config, &destination)?;
        // A lease journal without a live key in this daemon (after a restart,
        // or one the server can no longer admit, as after the operator
        // released a stuck state) was otherwise settled only by the next
        // chat, so the withdrawal waited for it indefinitely. Settle it first,
        // exactly as /wallet/settle does; when it does not settle, the
        // pending check below reports it as before.
        if self.config.request_mode == RequestMode::DirectOpenrouter
            && self.direct_lease.lock().await.is_none()
            && self
                .status()
                .await
                .is_ok_and(|status| status.pending_request)
        {
            if let Err(error) = self.settle_for_withdrawal().await {
                tracing::debug!(%error, "the pending lease did not settle before withdrawal preparation");
            }
        }
        // Same order as issuance: lease mutex, wallet mutex, then filesystem lock.
        // Hold all three through the decision and the clearance so no
        // inference can race the snapshot (C1).
        let mut lease = self.direct_lease.lock().await;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let session_events = self.oa_session_events.clone();
        let indexer = self.indexer.clone();
        let result = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            let existing = crate::oa_withdrawal::load(&config)?;
            // Parse errors must never be treated as absence of a pending lease.
            let pending = wallet.get_pending_journal()?.is_some();
            // A missing active file after finalized close can be the last crash
            // boundary. Never recreate a note or ask for a second clearance.
            if wallet.state().is_none() {
                if pending {
                    return Err(AuthError::PendingSettlement);
                }
                if let Some(record) = &existing {
                    if record.destination != destination {
                        return Err(AuthError::WithdrawalConflict);
                    }
                    return record.plan.clone().ok_or(AuthError::WithdrawalConflict);
                }
                return Err(AuthError::NoActiveNote);
            }
            let runtime = current_thread_runtime()?;
            runtime.block_on(async move {
                // A reservation that already holds its close hands it out
                // again while it stays valid. A close nearer its valid_until
                // is proved again (the vault refuses it afterwards, L6): from
                // the kept clearance signature, which signs only the
                // nullifier, at the plan's own root and path. A reservation
                // saved before the signature was kept asks for the clearance
                // again below (the server signs a reserved nullifier again).
                // Only a close of the wallet's current state: a reservation
                // of an earlier state (its closes dead, then a successor
                // installed) is archived below by `reserve`, and the current
                // state gets its own clearance.
                let current = wallet.current_nullifier();
                if let Some(record) = existing
                    .as_ref()
                    .filter(|record| !record.complete && Some(record.nullifier) == current)
                {
                    if let Some(plan) = &record.plan {
                        if record.destination != destination {
                            return Err(AuthError::WithdrawalConflict);
                        }
                        if plan.public_inputs.valid_until
                            > now_seconds() + exit::PLAN_REUSE_MARGIN_SECONDS
                        {
                            return Ok(plan.clone());
                        }
                        if let Some(signature) = record.clearance_signature {
                            return reprove_close(&config, &wallet, record.clone(), &signature);
                        }
                    }
                }
                let result = mutual_close_locked(
                    &config,
                    &indexer,
                    &mut wallet,
                    &session_events,
                    destination,
                )
                .await;
                // E3's wait, a refusal or a failure before any proof left
                // releases nothing: the lock this attempt set is removed and
                // chats resume. A lock that released a proof stays.
                if result.is_err() {
                    exit::drop_unused_lock(&mut wallet)?;
                }
                result
            })
        })
        .await;
        if result.is_ok() {
            *lease = None;
        }
        result
    }

    pub async fn oa_confirm_withdrawal(
        &self,
        transaction_hash: String,
    ) -> Result<Value, AuthError> {
        let mut lease = self.direct_lease.lock().await;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let result = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut record =
                crate::oa_withdrawal::load(&config)?.ok_or(AuthError::WithdrawalConflict)?;
            if record.complete {
                if record
                    .transaction_hash
                    .as_ref()
                    .is_some_and(|hash| hash.eq_ignore_ascii_case(&transaction_hash))
                {
                    return Ok((crate::oa_withdrawal::public_status(Some(&record)), false));
                }
                return Err(AuthError::WithdrawalConflict);
            }
            let evidence = current_thread_runtime()?.block_on(
                crate::oa_withdrawal::confirm_receipt(&config, &record, &transaction_hash),
            )?;
            crate::oa_withdrawal::complete_confirmed(
                &config,
                &mut record,
                &transaction_hash,
                evidence,
            )?;
            Ok((crate::oa_withdrawal::public_status(Some(&record)), true))
        })
        .await;
        if result.as_ref().is_ok_and(|(_, changed)| *changed) {
            *lease = None;
        }
        result.map(|(status, _)| status)
    }

    /// Release an incomplete reservation that never obtained a clearance, for
    /// example a wrongly bound note whose ownership proof could not be built,
    /// so the note can be rebound. Requires the caller's exact note and
    /// nullifier, no plan, the unchanged reserved note, no pending request,
    /// on a vault below revision 2 no ownership proof that may have left (for
    /// a reservation saved before that was recorded: no note leaf in the
    /// indexer's tree from which one could have been built), and the server
    /// reporting the nullifier unknown.
    pub async fn oa_release_withdrawal(
        &self,
        note_id: u32,
        nullifier: Felt252,
    ) -> Result<Value, AuthError> {
        // Same lock order as preparation: no clearance request can start meanwhile.
        let mut lease = self.direct_lease.lock().await;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        let result = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            let record =
                crate::oa_withdrawal::load(&config)?.ok_or(AuthError::WithdrawalConflict)?;
            if record.snapshot.note_id != note_id || record.nullifier != nullifier {
                return Err(AuthError::WithdrawalConflict);
            }
            if wallet.get_pending_journal()?.is_some() {
                return Err(AuthError::PendingSettlement);
            }
            let state = wallet.state().ok_or(AuthError::WithdrawalConflict)?;
            let runtime = current_thread_runtime()?;
            // Read at most once, and only for a reservation saved before
            // `ownership_proof_sent` existed.
            let mut leaf_in_tree = None;
            crate::oa_withdrawal::check_release(&config, &record, state, || {
                let found =
                    runtime.block_on(crate::oa_withdrawal::note_leaf_in_tree(&indexer, state))?;
                leaf_in_tree = Some(found);
                Ok(found)
            })?;
            // Ask while holding the wallet locks, so this daemon cannot request
            // a clearance between the answer and the release.
            let recovery = runtime.block_on(nullifier_recovery(&config, &record.nullifier))?;
            if recovery.status != "not_found" || recovery.nullifier_status != "unknown" {
                return Err(AuthError::WithdrawalPending(format!(
                    "the server reports nullifier status {}; finish this withdrawal instead",
                    recovery.nullifier_status
                )));
            }
            crate::oa_withdrawal::release(&config, &record, state, || {
                Ok(leaf_in_tree.unwrap_or(true))
            })?;
            // E6: the owner cancels an exit that released no exit proof.
            let mut wallet = wallet;
            wallet.cancel_exit_lock()?;
            Ok(crate::oa_withdrawal::public_status(None))
        })
        .await;
        if result.is_ok() {
            *lease = None;
        }
        result
    }

    pub async fn oa_deposit_path(&self) -> Result<serde_json::Value, AuthError> {
        let (_, _, siblings) = self.indexer.next_deposit_path().await?;
        Ok(serde_json::json!({"zero_path": siblings}))
    }

    pub async fn oa_billing_quote(&self) -> Result<serde_json::Value, AuthError> {
        let quote = crate::oa_native::verified_quote(&self.config).await?;
        serde_json::to_value(quote).map_err(|error| AuthError::Serialization(error.to_string()))
    }

    pub async fn oa_bridge_lease(
        &self,
        request_limit_micro_usd: u128,
    ) -> Result<serde_json::Value, AuthError> {
        if self.config.request_mode != RequestMode::DirectOpenrouter
            || !self.config.require_oa_org_key_source
        {
            return Err(AuthError::KeyVerification(
                "OA bridge requires verified direct mode".into(),
            ));
        }
        if !matches!(
            request_limit_micro_usd,
            1_000_000 | 2_000_000 | 3_000_000 | 4_500_000 | 6_000_000
        ) {
            return Err(AuthError::Wallet("unreviewed request budget".into()));
        }
        let guard = self.ready_direct_lease(request_limit_micro_usd).await?;
        let lease = guard
            .as_ref()
            .ok_or_else(|| AuthError::Wallet("lease disappeared".into()))?;
        self.check_cached_lease_station(lease)?;
        reserve_oa_bridge_lease(&self.config.state_dir, &lease.client_request_id)?;
        self.oa_session_events.started(&lease.client_request_id);
        Ok(serde_json::json!({
            "api_key": lease.api_key,
            "base_url": lease.openrouter_api_base,
            "expires_at": lease.expires_at,
            "verified": lease.verified,
            "verification_status": if lease.verified { "verified" } else { "verifier-unavailable" },
            "verification_detail": lease.verification_detail,
        }))
    }

    async fn ready_direct_lease(
        &self,
        request_limit_micro_usd: u128,
    ) -> Result<tokio::sync::MutexGuard<'_, Option<ActiveOpenRouterLease>>, AuthError> {
        use sha3::{Digest, Keccak256};
        self.ensure_scheme_agreement().await?;
        let mut slot = self.direct_lease.lock().await;
        self.oa_check_spending().await?;
        if let Some(lease) = slot.as_ref() {
            let marker = self.config.state_dir.join("oa-issued-leases").join(format!(
                "{:x}",
                Keccak256::digest(lease.client_request_id.as_bytes())
            ));
            if marker.exists() {
                let recovered = self.recover().await?;
                if recovered.wallet.pending_request {
                    return Err(AuthError::LeasePending(
                        "the previous API request is awaiting lease settlement".into(),
                    ));
                }
                *slot = None;
            }
        }
        self.ensure_direct_openrouter_lease(
            &mut slot,
            "oa-single-use",
            Some(request_limit_micro_usd),
        )
        .await?;
        let request = self.prepare_direct_lease_request(None).await?;
        self.check_request_budget(&request, request_limit_micro_usd)?;
        let lease = slot
            .as_mut()
            .ok_or_else(|| AuthError::Wallet("lease disappeared".into()))?;
        let evidence = lease
            .verification
            .as_ref()
            .ok_or_else(|| AuthError::KeyVerification("missing OA key evidence".into()))?;
        let outcome = self
            .verify_oa_key(&lease.api_key, lease.expires_at, evidence)
            .await?;
        if now_seconds().saturating_add(1) >= lease.expires_at {
            return Err(AuthError::KeyVerification(
                "key expired during verification".into(),
            ));
        }
        lease.verified = outcome.verified;
        lease.verification_detail = outcome.detail.map(str::to_string);
        Ok(slot)
    }

    pub fn default_model(&self) -> &str {
        self.config
            .models
            .first()
            .map(|model| model.id.as_str())
            .unwrap_or("zkapi-echo")
    }

    pub fn models(&self) -> &[ModelDescriptor] {
        &self.config.models
    }

    pub async fn status(&self) -> Result<WalletStatus, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            Ok(wallet_status(&wallet))
        })
        .await
    }

    /// Preserve a note that cannot safely authorize another maximum-cost
    /// request and clear the active wallet slot for a fresh deposit.
    ///
    /// The balance check and filesystem move happen under the same wallet
    /// locks as request execution. A pending request is never retired because
    /// its eventual response may still advance the note state.
    pub async fn retire_low_balance_note(&self) -> Result<Option<RetiredNote>, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            let Some(state) = wallet.state() else {
                return Ok(None);
            };
            let proof_bound = if config.policy_enabled {
                config.policy_charge_cap
            } else {
                config.request_charge_cap
            };
            if state.current_balance >= proof_bound {
                return Ok(None);
            }
            // The wallet normally removes this file after settlement. Treat
            // any surviving journal (including one too damaged to parse) as
            // in-flight state and fail closed instead of separating it from
            // its note.
            if config.state_dir.join("pending_journal.json").exists() {
                return Err(AuthError::PendingRequest);
            }

            let note_id = state.note_id;
            let remaining_balance = state.current_balance;
            let retired_dir = next_retired_note_dir(&config.state_dir, note_id)?;
            create_private_dir(&retired_dir)?;

            let active_state_path = config.state_dir.join("note_state.json");
            let retired_state_path = retired_dir.join("note_state.json");
            std::fs::rename(&active_state_path, &retired_state_path).map_err(|err| {
                AuthError::Wallet(format!(
                    "failed to retire note {note_id} from {} to {}: {err}",
                    active_state_path.display(),
                    retired_state_path.display()
                ))
            })?;

            Ok(Some(RetiredNote {
                note_id,
                remaining_balance,
                state_dir: retired_dir,
            }))
        })
        .await
    }

    pub async fn prepare_deposit(&self, amount: u128) -> Result<DepositPlan, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            if wallet.state().is_some() {
                return Err(AuthError::InvalidInput(
                    "wallet already has an active note".to_string(),
                ));
            }

            let runtime = current_thread_runtime()?;
            runtime.block_on(async move {
                let (next_note_id, active_root, zero_path) = indexer.next_deposit_path().await?;
                let (secret, commitment) = wallet.generate_deposit_params();

                Ok(DepositPlan {
                    amount,
                    secret,
                    commitment,
                    next_note_id,
                    active_root,
                    zero_path,
                })
            })
        })
        .await
    }

    pub async fn confirm_deposit(
        &self,
        request: ConfirmDepositRequest,
    ) -> Result<WalletStatus, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            crate::oa_withdrawal::check_spending(&config, Some(request.note_id))?;
            let path = match (request.deposit_root, request.deposit_siblings) {
                (Some(root), Some(siblings)) => {
                    let leaf = core_v2::note_leaf(
                        request.note_id,
                        &core_v2::registration_commitment(&request.secret),
                        request.amount,
                        request.expiry_ts,
                    );
                    let proves = <[Felt252; zkapi_types::MERKLE_DEPTH]>::try_from(siblings.clone())
                        .is_ok_and(|array| {
                            core_v2::merkle_root(request.note_id, &leaf, &array) == root
                        });
                    if proves {
                        Some(zkapi_client::note_state::DepositPath { root, siblings })
                    } else {
                        // The note is still confirmed; exits then find their
                        // path through the indexer or a log rebuild.
                        tracing::warn!(
                            note_id = request.note_id,
                            "the deposit path does not prove the note's leaf at the deposit root; not kept"
                        );
                        None
                    }
                }
                _ => None,
            };
            wallet.confirm_deposit_with_path(
                request.secret,
                request.note_id,
                request.amount,
                request.expiry_ts,
                path,
            )?;
            Ok(wallet_status(&wallet))
        })
        .await
    }

    /// Install a finalized response for the pending request, or else for a
    /// request archived at the note's current state.
    pub async fn recover(&self) -> Result<RecoverResult, AuthError> {
        self.recover_with_archive(true).await
    }

    /// `archive` false asks only about the pending request, and sends
    /// nothing when none is pending: the periodic reconcile must not poll the
    /// server's record of the note's current nullifier while the note is
    /// idle. Explicit recovery, chats, settlement and withdrawal preparation
    /// still consult the archive.
    async fn recover_with_archive(&self, archive: bool) -> Result<RecoverResult, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let session_events = self.oa_session_events.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let runtime = current_thread_runtime()?;
            let recovered = if archive {
                runtime.block_on(wallet.recover())?
            } else {
                runtime.block_on(wallet.recover_pending())?
            };
            if let Some(response) = recovered.as_ref() {
                session_events.settled(response, wallet.state().map(|state| state.current_balance));
            }
            let request = recovered.as_ref().map(|response| {
                core_response(response, wallet.state().map(|state| state.current_balance))
            });
            Ok(RecoverResult {
                recovered: recovered.is_some(),
                request,
                wallet: wallet_status(&wallet),
            })
        })
        .await
    }

    /// Build the integration config for the client UI. Capabilities come from
    /// public health, as at startup; the optional operator dashboard supplies
    /// only upstream metadata and credit scale.
    pub async fn zkapi_config(&self) -> ZkapiConfig {
        let summary_url = format!(
            "{}/v1/dashboard/summary",
            self.config.protocol_server_url.trim_end_matches('/')
        );
        let health_url = format!(
            "{}/health",
            self.config.protocol_server_url.trim_end_matches('/')
        );
        let (summary, health) = tokio::join!(
            tokio::time::timeout(Duration::from_secs(2), fetch_json::<Value>(&summary_url)),
            tokio::time::timeout(
                Duration::from_secs(2),
                fetch_json::<ServerHealthSnapshot>(&health_url)
            ),
        );
        let summary = summary.ok().and_then(Result::ok);
        let health = health.ok().and_then(Result::ok);
        let server = summary.as_ref().map(|s| &s["server"]);
        let upstream_kind = server
            .and_then(|s| s["upstream_kind"].as_str())
            .map(|s| s.to_string());
        let credits_per_usd = server
            .and_then(|s| s["credits_per_usd"].as_f64())
            .filter(|v| *v > 0.0)
            .unwrap_or(CREDITS_PER_USD);
        let direct_openrouter_available = health.as_ref().is_some_and(|health| {
            health
                .request_modes
                .iter()
                .any(|mode| mode == "direct_openrouter")
        });
        let active_lease = self
            .direct_lease
            .lock()
            .await
            .as_ref()
            .map(|lease| DirectLeaseStatus {
                session_id: lease.session_id.clone(),
                client_request_id: lease.client_request_id.clone(),
                expires_at: lease.expires_at,
                settle_after: lease.settle_after,
            });
        let prepared_withdrawal =
            self.prepared_withdrawal
                .lock()
                .await
                .as_ref()
                .map(|plan| PreparedWithdrawalStatus {
                    mode: plan.mode,
                    note_id: plan.public_inputs.note_id,
                    destination: format_address(&plan.public_inputs.destination),
                });

        ZkapiConfig {
            credits_per_usd,
            request_charge_cap: self.config.request_charge_cap,
            request_charge_cap_usd: self.config.request_charge_cap as f64 / credits_per_usd,
            policy_charge_cap: self.config.policy_charge_cap,
            policy_enabled: self.config.policy_enabled,
            funding: self.funding_config(),
            upstream_kind,
            direct_openrouter_available,
            request_mode: self.config.request_mode,
            active_lease,
            prepared_withdrawal,
        }
    }

    /// Fail before funding or listening when a requested transport is not
    /// advertised by the selected server deployment.
    pub async fn ensure_request_mode_available(&self) -> Result<(), AuthError> {
        if self.config.request_mode == RequestMode::Proxy {
            return Ok(());
        }
        let health_url = format!(
            "{}/health",
            self.config.protocol_server_url.trim_end_matches('/')
        );
        let health = fetch_json::<ServerHealthSnapshot>(&health_url)
            .await
            .map_err(AuthError::Wallet)?;
        if health
            .request_modes
            .iter()
            .any(|mode| mode == "direct_openrouter")
        {
            Ok(())
        } else {
            Err(AuthError::InvalidInput(format!(
                "server {} does not advertise direct_openrouter mode",
                self.config.protocol_server_url
            )))
        }
    }

    /// Clear the active note after its on-chain settlement (mutual close or
    /// finalized escape), archiving the closed state so a fresh deposit can
    /// start. Only call once the note is closed on chain — otherwise this drops
    /// the local secret while funds are still escrowed.
    pub async fn reset_wallet(&self) -> Result<WalletStatus, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let status = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let state_path = config.state_dir.join("note_state.json");
            let journal_path = config.state_dir.join("pending_journal.json");
            let prepared_path = prepared_withdrawal_path(&config.state_dir);
            if state_path.exists() {
                // Best-effort archive (moves to archive/note_<id>_closed.json),
                // then ensure the active state file is gone.
                if let Ok(wallet) = load_wallet(&config) {
                    if let Some(state) = wallet.state() {
                        let _ = state.archive(&state_path);
                    }
                }
                let _ = std::fs::remove_file(&state_path);
            }
            // A readable request journal may belong to a transmitted request:
            // it moves into the request archive, never the bin. Only one too
            // damaged to parse (and so never installable) is removed.
            match zkapi_client::journal::PendingRequestJournal::read(&journal_path) {
                Ok(Some(_)) => zkapi_client::journal::PendingRequestJournal::archive(
                    &journal_path,
                    &config.state_dir.join("request_archive"),
                    "wallet_reset",
                )?,
                _ => {
                    let _ = std::fs::remove_file(&journal_path);
                }
            }
            let _ = std::fs::remove_file(&prepared_path);
            let wallet = load_wallet(&config)?;
            Ok(wallet_status(&wallet))
        })
        .await?;
        *self.prepared_withdrawal.lock().await = None;
        *self.direct_lease.lock().await = None;
        Ok(status)
    }

    pub fn funding_config(&self) -> FundingConfig {
        FundingConfig {
            deployment_id: self.config.deployment_id.clone(),
            billing_asset: self.config.billing_asset.clone(),
            billing_unit: self.config.billing_unit.clone(),
            native_asset_wei_per_unit: self.config.native_asset_wei_per_unit.clone(),
            native_price_feed_address: self.config.native_price_feed_address.clone(),
            native_price_feed_decimals: self.config.native_price_feed_decimals,
            native_price_max_age_seconds: self.config.native_price_max_age_seconds,
            contract_address: self.config.contract_address,
            chain_id: self.config.chain_id,
            indexer_url: self.config.indexer_url.clone(),
            protocol_server_url: self.config.protocol_server_url.clone(),
            models: self.config.models.clone(),
            suggested_deposit_amount: self.config.suggested_deposit_amount,
            demo_rpc_url: self.config.demo_rpc_url.clone(),
            demo_billing_token_address: self.config.demo_billing_token_address.clone(),
            demo_mint_enabled: self.config.demo_mint_enabled && self.config.chain_id == 11_155_111,
            demo_note_ttl_seconds: self.config.demo_note_ttl_seconds,
        }
    }

    pub async fn execute_request(
        self: &Arc<Self>,
        request: CoreRequest,
    ) -> Result<CoreResponse, AuthError> {
        self.execute_request_in_session(request, None).await
    }

    /// Execute an application request, binding direct-mode key reuse to an
    /// explicit chat session. Calls with the same session ID share one bounded
    /// ephemeral key and may run concurrently; a different session cannot
    /// silently inherit that key.
    pub async fn execute_request_in_session(
        self: &Arc<Self>,
        request: CoreRequest,
        session_id: Option<&str>,
    ) -> Result<CoreResponse, AuthError> {
        self.oa_check_spending().await?;
        if let Some(plan) = self.prepared_withdrawal.lock().await.as_ref() {
            return Err(AuthError::WithdrawalPending(format!(
                "{} withdrawal for note {} is prepared; finish it before sending more requests",
                withdrawal_mode_label(plan.mode),
                plan.public_inputs.note_id
            )));
        }
        match self.config.request_mode {
            RequestMode::Proxy => Ok(self.execute_request_demo(request).await?.response),
            RequestMode::DirectOpenrouter => {
                let session_id = normalize_session_id(session_id)?;
                self.execute_direct_openrouter(request, session_id).await
            }
        }
    }

    /// Forward a direct OpenRouter response without buffering its body. The
    /// HTTP route wraps the returned byte stream in an Axum body so SSE chunks
    /// reach OpenAI-compatible callers as soon as OpenRouter emits them. The
    /// returned body owns the inference lock until it is consumed or dropped.
    pub async fn execute_streaming_request(
        self: &Arc<Self>,
        request: CoreRequest,
    ) -> Result<StreamingCoreResponse, AuthError> {
        self.execute_streaming_request_in_session(request, None)
            .await
    }

    pub async fn execute_streaming_request_in_session(
        self: &Arc<Self>,
        request: CoreRequest,
        session_id: Option<&str>,
    ) -> Result<StreamingCoreResponse, AuthError> {
        self.oa_check_spending().await?;
        if let Some(plan) = self.prepared_withdrawal.lock().await.as_ref() {
            return Err(AuthError::WithdrawalPending(format!(
                "{} withdrawal for note {} is prepared; finish it before sending more requests",
                withdrawal_mode_label(plan.mode),
                plan.public_inputs.note_id
            )));
        }
        match self.config.request_mode {
            RequestMode::DirectOpenrouter => {
                let session_id = normalize_session_id(session_id)?;
                self.execute_direct_openrouter_streaming(request, session_id)
                    .await
            }
            RequestMode::Proxy => Err(AuthError::InvalidInput(
                "streaming is available only in direct-openrouter mode".to_string(),
            )),
        }
    }

    /// Reconcile a pending direct-mode lease with the server. `run()` calls
    /// this periodically so the wallet advances soon after authoritative usage
    /// settlement even if no new LLM request arrives.
    pub async fn reconcile_direct_openrouter(&self) {
        if self.config.request_mode != RequestMode::DirectOpenrouter {
            return;
        }
        // A streaming response owns this lock through its final body chunk.
        // Do not race its lease state with periodic crash recovery.
        let Ok(_request_guard) = self.direct_request_mutex.try_write() else {
            return;
        };
        match self.recover_with_archive(false).await {
            Ok(result) if result.recovered => {
                let mut lease = self.direct_lease.lock().await;
                *lease = None;
                tracing::info!("installed settled OpenRouter lease state");
            }
            Ok(_) => {}
            Err(error) => tracing::debug!(error = %error, "OpenRouter lease is not settled yet"),
        }
    }

    /// Finish any request that still owns the wallet before producing a
    /// withdrawal proof. In direct mode this deliberately retires a live
    /// child key immediately, so withdrawal charges measured usage without
    /// waiting for the provider-enforced lease expiry.
    pub async fn settle_for_withdrawal(&self) -> Result<WalletStatus, AuthError> {
        let _request_guard = self.direct_request_mutex.write().await;

        if self.config.request_mode == RequestMode::DirectOpenrouter {
            let live_lease_id = self
                .direct_lease
                .lock()
                .await
                .take()
                .map(|lease| lease.client_request_id);

            if let Some(client_request_id) = live_lease_id {
                tracing::info!(
                    %client_request_id,
                    "retiring active OpenRouter lease before withdrawal"
                );
                self.retire_direct_openrouter_lease(&client_request_id)
                    .await?;
            } else if self.status().await?.pending_request {
                // After a daemon restart the plaintext child key is gone, but
                // the retryable prompt-free proof remains in the wallet
                // journal. Use it to retire or recover the authoritative
                // server-side lease.
                let request = self.prepare_direct_lease_request(None).await?;
                let lease = match self.find_direct_lease_for_withdrawal(&request).await? {
                    PendingLease::Lease(lease) => lease,
                    PendingLease::SetAside(disposition) => {
                        tracing::warn!(
                            client_request_id = %request.client_request_id,
                            disposition,
                            "setting aside a local lease proof that the server never accepted"
                        );
                        self.clear_pending_request(disposition).await?;
                        let status = self.status().await?;
                        if status.pending_request {
                            return Err(AuthError::PendingRequest);
                        }
                        return Ok(status);
                    }
                };
                match lease.status.as_str() {
                    "provisioning" => {
                        self.finish_interrupted_direct_lease(&request).await?;
                    }
                    "active" | "retiring" | "disabled" | "revoking" => {
                        self.retire_direct_openrouter_lease(&request.client_request_id)
                            .await?;
                    }
                    "finalized" => {
                        let recovered = self.recover().await?;
                        if !recovered.recovered && recovered.wallet.pending_request {
                            return Err(AuthError::LeasePending(format!(
                                "finalized lease {} is not yet recoverable",
                                request.client_request_id
                            )));
                        }
                    }
                    status => {
                        return Err(AuthError::LeasePending(format!(
                            "lease {} is {status}; key expiry {}, settlement after {}",
                            request.client_request_id, lease.expires_at, lease.settle_after
                        )));
                    }
                }
            }
        } else if self.status().await?.pending_request {
            let recovered = self.recover().await?;
            if !recovered.recovered && recovered.wallet.pending_request {
                return Err(AuthError::PendingRequest);
            }
        }

        let status = self.status().await?;
        if status.pending_request {
            return Err(AuthError::PendingRequest);
        }
        Ok(status)
    }

    /// Resolve an interrupted lease issuance without guessing. A missing
    /// lease is considered safely orphaned only when the current request is
    /// unknown and its nullifier is either also unknown (once the vault's
    /// root moved) or reserved for a clearance.
    async fn find_direct_lease_for_withdrawal(
        &self,
        request: &ApiRequestV2,
    ) -> Result<PendingLease, AuthError> {
        const ATTEMPTS: usize = 3;
        let client_request_id = &request.client_request_id;
        for attempt in 0..ATTEMPTS {
            if let Some(lease) = self
                .fetch_optional_direct_lease_status(client_request_id)
                .await?
            {
                return Ok(PendingLease::Lease(lease));
            }
            let recovery = self.fetch_request_recovery(client_request_id).await?;
            if recovery.request_response.is_some() || recovery.nullifier_status == "finalized" {
                let recovered = self.recover().await?;
                if recovered.recovered || !recovered.wallet.pending_request {
                    return Ok(PendingLease::SetAside("discarded_unknown_to_server"));
                }
                return Err(AuthError::LeasePending(format!(
                    "request {client_request_id} is finalized but not yet recoverable"
                )));
            }
            if recovery.status != "not_found" || recovery.nullifier_status != "unknown" {
                return Err(AuthError::LeasePending(format!(
                    "request {client_request_id} has server status {} and nullifier status {}",
                    recovery.status, recovery.nullifier_status
                )));
            }
            let nullifier_recovery = self
                .fetch_nullifier_recovery(&request.public_inputs.request_nullifier)
                .await?;
            if nullifier_recovery.request_response.is_some() {
                // The server finalized another request at this state, for
                // example one set aside into the archive after an unsigned
                // rejection. Recovery installs its receipt when it verifies.
                let recovered = self.recover().await?;
                if recovered.recovered || !recovered.wallet.pending_request {
                    return Ok(PendingLease::SetAside("discarded_unknown_to_server"));
                }
                return Err(AuthError::LeasePending(format!(
                    "request {client_request_id} is unknown, but its nullifier is finalized for a request that is not recoverable yet"
                )));
            }
            if nullifier_recovery.nullifier_status == "clearance_reserved" {
                // A clearance owns this deterministic state nullifier: an
                // earlier mutual withdrawal, or the operator's release of a
                // stuck state. Reservations are permanent, and the server
                // refuses every request at such a nullifier as a replay,
                // before any root check, so this request can never be
                // admitted and no request can settle the state. The vault's
                // root says nothing about that, so it is not asked: on a
                // quiet vault it may never move, and the withdrawal would
                // wait forever. The reading is unsigned, but setting the
                // journal aside only moves it into the archive, from where
                // a later finalized receipt still installs; on a vault below
                // revision 2 the state then sends no ownership proof without
                // the owner's acknowledgement. Chats prove no new request
                // from the state while the server reports the reservation
                // (`prepare_direct_lease_request`).
                return Ok(PendingLease::SetAside("discarded_clearance_reserved"));
            }
            if nullifier_recovery.status != "not_found"
                || nullifier_recovery.nullifier_status != "unknown"
            {
                return Err(AuthError::LeasePending(format!(
                    "request {client_request_id} is unknown, but its nullifier has server status {} and nullifier status {}",
                    nullifier_recovery.status, nullifier_recovery.nullifier_status
                )));
            }
            if attempt + 1 < ATTEMPTS {
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
        // Unsigned 'unknown' readings alone never set a journal aside, here
        // or after stale_root: the pinned vault is the first witness.
        self.require_moved_vault_root(request).await?;
        Ok(PendingLease::SetAside("discarded_unknown_to_server"))
    }

    /// The vault-root witness before a transmitted request is set aside on
    /// unsigned readings. While the pinned vault still has the request's
    /// root, the request may still be admitted (a lagging server, or a
    /// forged reply), so it stays pending and the next lease attempt resends
    /// it unchanged. An unreadable root keeps it too.
    async fn require_moved_vault_root(&self, request: &ApiRequestV2) -> Result<(), AuthError> {
        match self.vault_current_root().await {
            Ok(root) if root != request.public_inputs.active_root => Ok(()),
            Ok(_) => Err(AuthError::LeasePending(format!(
                "request {} is unknown to the server, but the vault still has its root; the saved authorization is preserved and the next request resends it",
                request.client_request_id
            ))),
            Err(error) => Err(AuthError::LeasePending(format!(
                "request {} is unknown to the server, but the vault root could not be read ({error}); the saved authorization is preserved",
                request.client_request_id
            ))),
        }
    }

    async fn execute_direct_openrouter(
        self: &Arc<Self>,
        request: CoreRequest,
        session_id: String,
    ) -> Result<CoreResponse, AuthError> {
        let (client_request_id, upstream, retire_after_response, request_guard) = self
            .open_direct_openrouter_response(request, &session_id)
            .await?;
        let status = upstream.status();
        let result = upstream
            .text()
            .await
            .map(|raw_payload| (status, raw_payload))
            .map_err(|error| AuthError::Upstream(error.to_string()));
        if retire_after_response {
            drop(request_guard);
            let _request_guard = self.direct_request_mutex.clone().write_owned().await;
            self.finish_direct_openrouter_lease(client_request_id.clone())
                .await;
        } else {
            drop(request_guard);
        }

        let (status, raw_payload) = result?;
        let response_code = status.as_u16();
        let wallet = self.status().await?;
        let (remaining_balance, next_anchor) = wallet
            .note
            .map(|note| (Some(note.current_balance), note.current_anchor))
            .unwrap_or((None, Felt252::ZERO));
        Ok(CoreResponse {
            client_request_id,
            response_code,
            payload: serde_json::from_str(&raw_payload).ok(),
            raw_payload,
            // The authoritative charge is intentionally unknown until the
            // whole lease settles. Zero here means "not yet applied".
            charge_applied: 0,
            next_anchor,
            remaining_balance,
        })
    }

    async fn ensure_direct_openrouter_lease(
        &self,
        lease_slot: &mut Option<ActiveOpenRouterLease>,
        session_id: &str,
        request_limit_micro_usd: Option<u128>,
    ) -> Result<(), AuthError> {
        if lease_slot
            .as_ref()
            .is_some_and(|lease| now_seconds().saturating_add(1) < lease.expires_at)
        {
            let lease = lease_slot.as_ref().expect("checked above");
            if lease.session_id != session_id {
                return Err(AuthError::LeaseSessionConflict {
                    active_session_id: lease.session_id.clone(),
                    expires_at: lease.expires_at,
                });
            }
            return Ok(());
        }

        if let Some(finished) = lease_slot.take() {
            tracing::info!(
                client_request_id = %finished.client_request_id,
                expires_at = finished.expires_at,
                requests_served = finished.requests_served,
                "retiring expired OpenRouter lease before opening its replacement"
            );
            self.retire_direct_openrouter_lease(&finished.client_request_id)
                .await?;
        }

        // Recover any state finalized since daemon startup before proving the
        // next lease request. The resulting child key stays in memory and is
        // reused for this OA chat until its provider-enforced expiration, an
        // explicit settlement, credit exhaustion, or a key rejection.
        let _ = self.recover().await?;
        *lease_slot = Some(
            self.issue_direct_openrouter_lease(session_id.to_string(), request_limit_micro_usd)
                .await?,
        );
        Ok(())
    }

    async fn execute_direct_openrouter_streaming(
        self: &Arc<Self>,
        request: CoreRequest,
        session_id: String,
    ) -> Result<StreamingCoreResponse, AuthError> {
        let (client_request_id, upstream, retire_after_response, request_guard) = self
            .open_direct_openrouter_response(request, &session_id)
            .await?;
        let status = upstream.status();
        let content_type = upstream
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .cloned();
        let cache_control = upstream
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .cloned();
        let finalizer = DirectOpenRouterStreamFinalizer {
            service: self.clone(),
            client_request_id: retire_after_response.then_some(client_request_id),
            request_guard: Some(request_guard),
        };
        let state = (upstream.bytes_stream().boxed(), Some(finalizer), false);
        let body = stream::unfold(state, |(mut upstream, mut finalizer, done)| async move {
            if done {
                return None;
            }
            match upstream.next().await {
                Some(Ok(chunk)) => Some((Ok(chunk), (upstream, finalizer, false))),
                Some(Err(error)) => {
                    drop(finalizer.take());
                    Some((Err(io::Error::other(error)), (upstream, finalizer, true)))
                }
                None => {
                    drop(finalizer.take());
                    None
                }
            }
        })
        .boxed();
        Ok(StreamingCoreResponse {
            status,
            content_type,
            cache_control,
            body,
        })
    }

    async fn open_direct_openrouter_response(
        self: &Arc<Self>,
        request: CoreRequest,
        session_id: &str,
    ) -> Result<
        (
            String,
            reqwest::Response,
            bool,
            tokio::sync::OwnedRwLockReadGuard<()>,
        ),
        AuthError,
    > {
        self.ensure_scheme_agreement().await?;
        let (upstream_path, upstream_body) =
            crate::compat::openrouter_request(&request.path, request.body);
        let mut replaced_rejected_key = false;
        loop {
            let request_guard = self.direct_request_mutex.clone().read_owned().await;
            let mut lease_slot = self.direct_lease.lock().await;
            self.ensure_direct_openrouter_lease(&mut lease_slot, session_id, None)
                .await?;
            let lease = lease_slot
                .as_mut()
                .ok_or_else(|| AuthError::Wallet("OpenRouter lease disappeared".to_string()))?;
            if !lease.verified {
                let evidence = lease.verification.clone().ok_or_else(|| {
                    AuthError::KeyVerification(
                        "OA lease lost its verification evidence".to_string(),
                    )
                })?;
                let outcome = self
                    .verify_oa_key(&lease.api_key, lease.expires_at, &evidence)
                    .await?;
                if now_seconds().saturating_add(1) >= lease.expires_at {
                    return Err(AuthError::KeyVerification(
                        "OA key expired while verification was in progress".to_string(),
                    ));
                }
                lease.verified = outcome.verified;
                lease.verification_detail = outcome.detail.map(str::to_string);
            }
            self.check_cached_lease_station(lease)?;
            let client_request_id = lease.client_request_id.clone();
            let mut reserved_lease = lease.clone();
            lease.requests_served = lease.requests_served.saturating_add(1);
            let retire_after_response = false;
            drop(lease_slot);
            match self
                .send_verified_openrouter_request(
                    &mut reserved_lease,
                    &upstream_path,
                    &upstream_body,
                )
                .await
            {
                Ok(response) => {
                    return Ok((
                        client_request_id,
                        response,
                        retire_after_response,
                        request_guard,
                    ))
                }
                Err(error)
                    if !replaced_rejected_key
                        && (is_rejected_openrouter_key(&error)
                            || (reserved_lease.requests_served > 0
                                && is_exhausted_openrouter_key(&error))) =>
                {
                    tracing::warn!(
                        %client_request_id,
                        error = %error,
                        "retiring rejected OpenRouter lease and opening one replacement"
                    );
                    drop(request_guard);
                    let _request_guard = self.direct_request_mutex.clone().write_owned().await;
                    let mut lease_slot = self.direct_lease.lock().await;
                    if lease_slot
                        .as_ref()
                        .is_some_and(|lease| lease.client_request_id == client_request_id)
                    {
                        *lease_slot = None;
                    }
                    drop(lease_slot);
                    self.retire_direct_openrouter_lease(&client_request_id)
                        .await?;
                    replaced_rejected_key = true;
                }
                Err(error) => {
                    drop(request_guard);
                    let _request_guard = self.direct_request_mutex.clone().write_owned().await;
                    let mut lease_slot = self.direct_lease.lock().await;
                    if lease_slot
                        .as_ref()
                        .is_some_and(|lease| lease.client_request_id == client_request_id)
                    {
                        *lease_slot = None;
                    }
                    drop(lease_slot);
                    if let Err(cleanup_error) = self
                        .retire_direct_openrouter_lease(&client_request_id)
                        .await
                    {
                        tracing::warn!(
                            %client_request_id,
                            error = %cleanup_error,
                            "could not retire rejected OpenRouter lease"
                        );
                    }
                    return Err(error);
                }
            }
        }
    }

    fn check_cached_lease_station(&self, lease: &ActiveOpenRouterLease) -> Result<(), AuthError> {
        if lease.expires_at <= now_seconds() {
            return Err(AuthError::KeyVerification("key is expired".into()));
        }
        if let Some(evidence) = &lease.verification {
            if self
                .oa_banned_stations
                .lock()
                .map_err(|_| AuthError::KeyVerification("station policy unavailable".into()))?
                .contains(&evidence.station_id)
            {
                return Err(AuthError::KeyVerification("station is banned".into()));
            }
        }
        Ok(())
    }

    async fn send_verified_openrouter_request(
        &self,
        lease: &mut ActiveOpenRouterLease,
        upstream_path: &str,
        upstream_body: &Value,
    ) -> Result<reqwest::Response, AuthError> {
        self.check_cached_lease_station(lease)?;
        if !lease.verified {
            let evidence = lease.verification.clone().ok_or_else(|| {
                AuthError::KeyVerification("OA lease lost its verification evidence".to_string())
            })?;
            let outcome = self
                .verify_oa_key(&lease.api_key, lease.expires_at, &evidence)
                .await?;
            if now_seconds().saturating_add(1) >= lease.expires_at {
                return Err(AuthError::KeyVerification(
                    "OA key expired while verification was in progress".to_string(),
                ));
            }
            lease.verified = outcome.verified;
            lease.verification_detail = outcome.detail.map(str::to_string);
        }
        let url = format!(
            "{}{}",
            lease.openrouter_api_base.trim_end_matches('/'),
            upstream_path
        );
        self.send_openrouter_request(&url, &lease.api_key, upstream_body, lease.expires_at)
            .await
    }

    async fn send_openrouter_request(
        &self,
        url: &str,
        api_key: &str,
        body: &Value,
        expires_at: u64,
    ) -> Result<reqwest::Response, AuthError> {
        for attempt in 1..=DIRECT_REMOTE_MAX_ATTEMPTS {
            let response = match fresh_private_http()?
                .post(url)
                .bearer_auth(api_key)
                .header("content-type", "application/json")
                .json(body)
                .send()
                .await
            {
                Ok(response) => response,
                Err(error) => {
                    if attempt < DIRECT_REMOTE_MAX_ATTEMPTS {
                        let delay = direct_remote_retry_delay(attempt, None);
                        if retry_fits_lease(expires_at, delay) {
                            tracing::warn!(
                                attempt,
                                error = %error,
                                "retrying transient OpenRouter transport failure"
                            );
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                    }
                    return Err(AuthError::Upstream(error.to_string()));
                }
            };
            let status = response.status();
            let retry_after = retry_after_delay(response.headers());
            if status.is_success() {
                return Ok(response);
            }
            let raw_payload = response
                .text()
                .await
                .map_err(|error| AuthError::Upstream(error.to_string()))?;
            if is_transient_remote_status(status) && attempt < DIRECT_REMOTE_MAX_ATTEMPTS {
                let delay = direct_remote_retry_delay(attempt, retry_after);
                if retry_fits_lease(expires_at, delay) {
                    tracing::warn!(
                        attempt,
                        %status,
                        delay_ms = delay.as_millis(),
                        "retrying transient OpenRouter inference failure"
                    );
                    tokio::time::sleep(delay).await;
                    continue;
                }
            }
            return Err(AuthError::UpstreamResponse {
                status,
                message: truncate_for_error(&raw_payload, 500),
            });
        }
        Err(AuthError::Upstream(
            "OpenRouter request exhausted its retry budget".to_string(),
        ))
    }

    async fn issue_direct_openrouter_lease(
        &self,
        session_id: String,
        request_limit_micro_usd: Option<u128>,
    ) -> Result<ActiveOpenRouterLease, AuthError> {
        let mut retried_stale_root = false;
        let mut stale_root_resends = STALE_ROOT_RESEND_DELAYS.iter();
        let mut reconciled_lost_key = false;
        let mut refreshed_native_quote = false;
        loop {
            let request = self
                .prepare_direct_lease_request(request_limit_micro_usd)
                .await?;
            if let Some(limit) = request_limit_micro_usd {
                self.check_request_budget(&request, limit)?;
            }
            let response = zkapi_client::testnet_auth::request(
                self.config.chain_id,
                &self.config.protocol_server_url,
                reqwest::Method::POST,
                format!(
                    "{}/v2/openrouter/leases",
                    self.config.protocol_server_url.trim_end_matches('/')
                ),
            )?
            .json(&request)
            .send()
            .await
            .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let response = zkapi_client::testnet_auth::check_response(response)?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            if status.is_success() {
                return self.parse_direct_openrouter_lease(&request, session_id, &body);
            }
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if !refreshed_native_quote
                    && self.config.billing_asset == "native_eth"
                    && matches!(
                        error.error_code.as_str(),
                        "native_quote_expired" | "native_quote_superseded"
                    )
                {
                    self.refresh_unaccepted_native_request(request.clone())
                        .await?;
                    refreshed_native_quote = true;
                    continue;
                }
                if !refreshed_native_quote
                    && self.config.billing_asset == "native_eth"
                    && error.error_code == "invalid_request"
                    && crate::oa_native::expired_under_earlier_pins(&self.config, &request.payload)
                {
                    // A journaled request quoted under earlier pins is refused
                    // as invalid_request, never native_quote_expired. Retire it
                    // only on the same server acknowledgement as above;
                    // otherwise keep it and report the server's refusal.
                    refreshed_native_quote = true;
                    match self
                        .refresh_unaccepted_native_request(request.clone())
                        .await
                    {
                        Ok(()) => continue,
                        Err(refresh) => tracing::warn!(
                            client_request_id = %request.client_request_id,
                            error = %refresh,
                            "server did not confirm that a request quoted under earlier native-price pins expired unaccepted; keeping it"
                        ),
                    }
                }
                if error.error_code == "stale_root" && !retried_stale_root {
                    // The proof has been transmitted and this error body is
                    // unsigned. The pinned vault is the first witness: while
                    // it still has this proof's root, the server lags or the
                    // reply was forged, so the byte-identical request is sent
                    // again. Only once the vault's root moved is the server's
                    // nullifier record consulted, and only an unknown reading
                    // sets the journal aside, into the request archive.
                    let chain_root = self.vault_current_root().await.map_err(|error| {
                        AuthError::LeasePending(format!(
                            "request {} was rejected as stale, but the vault root could not be read ({error}); the saved authorization is preserved",
                            request.client_request_id
                        ))
                    })?;
                    if chain_root == request.public_inputs.active_root {
                        if let Some(delay) = stale_root_resends.next() {
                            tokio::time::sleep(*delay).await;
                            continue;
                        }
                        return Err(AuthError::LeasePending(format!(
                            "request {} was rejected as stale, but the vault still has its root; the saved authorization is preserved",
                            request.client_request_id
                        )));
                    }
                    self.clear_unadmitted_request(&request).await?;
                    retried_stale_root = true;
                    continue;
                }
                if matches!(
                    error.error_code.as_str(),
                    "oa_key_policy_rejected" | "replay"
                ) {
                    // The server can safely finalize an unissued authorization.
                    // Only signed recovery may advance the wallet; an error
                    // response alone never authorizes removal of the journal.
                    let recovered = self.recover().await?;
                    if error.error_code == "replay"
                        && !reconciled_lost_key
                        && (recovered.recovered || !recovered.wallet.pending_request)
                    {
                        reconciled_lost_key = true;
                        continue;
                    }
                    if error.error_code == "replay"
                        && recovered.wallet.pending_request
                        && receipt_journal_missing(
                            &self.config,
                            &request.public_inputs.request_nullifier,
                            Some(&request.client_request_id),
                        )
                        .await
                    {
                        return Err(AuthError::ReceiptJournalMissing(
                            request.public_inputs.request_nullifier,
                        ));
                    }
                    // A clearance owns this state's nullifier (as after the
                    // operator released a stuck state): every request at it
                    // is a replay, so no chat can settle the state. The
                    // retry stays pending, so later chats resend these same
                    // bytes instead of proving new requests from this state;
                    // withdrawal settlement sets it aside.
                    if error.error_code == "replay"
                        && recovered.wallet.pending_request
                        && nullifier_clearance_reserved(
                            &self.config,
                            &request.public_inputs.request_nullifier,
                        )
                        .await
                    {
                        return Err(AuthError::ClearanceReservedState);
                    }
                }
                if error.error_code == "lease_pending" {
                    let lease_status = self
                        .fetch_direct_lease_status(&request.client_request_id)
                        .await?;
                    if reconciled_lost_key {
                        return Err(AuthError::LeasePending(format!(
                            "lease {} is still {} after local recovery",
                            lease_status.client_request_id, lease_status.status
                        )));
                    }
                    match lease_status.status.as_str() {
                        "active" => {
                            // A restarted daemon intentionally has no copy of
                            // the one-show runtime key. Retire that unusable
                            // lease immediately, recover its wallet update,
                            // and prove a fresh lease in this same request.
                            tracing::warn!(
                                client_request_id = %lease_status.client_request_id,
                                expires_at = lease_status.expires_at,
                                "retiring active OpenRouter lease whose local key was lost"
                            );
                            self.retire_direct_openrouter_lease(&lease_status.client_request_id)
                                .await?;
                        }
                        "finalized" => {
                            let recovered = self.recover().await?;
                            if !recovered.recovered && recovered.wallet.pending_request {
                                return Err(AuthError::LeasePending(format!(
                                    "finalized lease {} is not yet recoverable",
                                    lease_status.client_request_id
                                )));
                            }
                        }
                        _ => {
                            return Err(AuthError::LeasePending(format!(
                                "lease {} is {}; key expiry {}, settlement after {}",
                                lease_status.client_request_id,
                                lease_status.status,
                                lease_status.expires_at,
                                lease_status.settle_after
                            )));
                        }
                    }
                    reconciled_lost_key = true;
                    continue;
                }
                return Err(AuthError::Wallet(format!(
                    "{}: {}",
                    error.error_code, error.error_message
                )));
            }
            return Err(AuthError::Wallet(format!("HTTP {status}: {body}")));
        }
    }

    /// Replay only the saved provisioning authorization, then retire it. Never
    /// cache or return its credential to inference, refresh its quote, or create
    /// another proof from this settlement path. A lost reply is reconciled via
    /// the wallet's verified signed recovery, never by clearing its journal.
    async fn finish_interrupted_direct_lease(
        &self,
        request: &ApiRequestV2,
    ) -> Result<(), AuthError> {
        // A current server can retire this exact authorization without issuing
        // a new key. Older servers return lease_pending for provisioning; only
        // that explicit response permits the browser-compatible replay below.
        if self.try_retire_direct_request(request, false).await? {
            return Ok(());
        }
        let response = zkapi_client::testnet_auth::request(
            self.config.chain_id,
            &self.config.protocol_server_url,
            reqwest::Method::POST,
            format!(
                "{}/v2/openrouter/leases",
                self.config.protocol_server_url.trim_end_matches('/')
            ),
        )?
        .timeout(Duration::from_secs(15))
        .json(request)
        .send()
        .await;
        if let Ok(response) = response {
            let response = zkapi_client::testnet_auth::check_response(response)?;
            if response.status().is_success() {
                let body = response
                    .text()
                    .await
                    .map_err(|error| AuthError::Wallet(error.to_string()))?;
                let lease =
                    self.parse_direct_openrouter_lease(request, "oa-recovery-only".into(), &body)?;
                if let Some(evidence) = lease.verification.as_ref() {
                    self.verify_oa_key(&lease.api_key, lease.expires_at, evidence)
                        .await?;
                }
                self.check_cached_lease_station(&lease)?;
                // Deliberately drop the key before requesting settlement.
                drop(lease);
                return self.retire_direct_request(request).await;
            }
        }
        // A definitive no-issuance rejection may already have produced a signed
        // zero-charge cancellation. A concurrent worker may also have finalized
        // the original lease. The status/error alone never authorizes a reset.
        let recovered = self.recover().await?;
        if recovered.recovered || !recovered.wallet.pending_request {
            return Ok(());
        }
        let lease = self
            .fetch_direct_lease_status(&request.client_request_id)
            .await?;
        if matches!(
            lease.status.as_str(),
            "active" | "retiring" | "disabled" | "revoking"
        ) {
            return self.retire_direct_request(request).await;
        }
        Err(AuthError::LeasePending(
            "interrupted key issuance is not yet recoverable; the saved request is preserved"
                .into(),
        ))
    }

    fn parse_direct_openrouter_lease(
        &self,
        request: &ApiRequestV2,
        session_id: String,
        body: &str,
    ) -> Result<ActiveOpenRouterLease, AuthError> {
        let lease: OpenRouterLeaseResponse = serde_json::from_str(body)
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        let extensions: OpenRouterLeaseExtensions = serde_json::from_str(body)
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        let expected_quote = crate::oa_native::saved_quote(&self.config, &request.payload)?;
        let expected_micros = match &expected_quote {
            Some(quote) => quote.usd_micros(request.public_inputs.solvency_bound)?,
            None => request.public_inputs.solvency_bound,
        };
        if lease.status != "active"
            || lease.client_request_id != request.client_request_id
            || extensions.billing_quote != expected_quote
            || !lease.spending_limit_usd.is_finite()
            || lease.spending_limit_usd != expected_micros as f64 / 1_000_000.0
        {
            return Err(AuthError::KeyVerification(
                "lease identity, native quote, or spending cap mismatch".into(),
            ));
        }
        if lease.api_key.is_empty() || lease.expires_at <= now_seconds() {
            return Err(AuthError::Wallet(
                "server returned an unusable OpenRouter lease".to_string(),
            ));
        }
        let expected_inference = &self.config.openrouter_inference_base;
        if !matches_trusted_url(&lease.openrouter_api_base, expected_inference) {
            return Err(AuthError::KeyVerification(
                "lease inference origin does not match the client's trusted OpenRouter origin"
                    .to_string(),
            ));
        }
        let (verification, verified) = match extensions.key_source.as_str() {
            "openrouter" => {
                enforce_required_key_source(self.config.require_oa_org_key_source, "openrouter")?;
                if extensions.verification.is_some() {
                    return Err(AuthError::KeyVerification(
                        "direct OpenRouter lease included unexpected OA evidence".to_string(),
                    ));
                }
                (None, true)
            }
            "oa_org" => {
                let evidence = extensions.verification.ok_or_else(|| {
                    AuthError::KeyVerification(
                        "OA org lease omitted verification evidence".to_string(),
                    )
                })?;
                (Some(evidence), false)
            }
            source => {
                return Err(AuthError::KeyVerification(format!(
                    "server returned unsupported key source {source}"
                )))
            }
        };
        Ok(ActiveOpenRouterLease {
            session_id,
            client_request_id: lease.client_request_id,
            api_key: lease.api_key,
            openrouter_api_base: lease.openrouter_api_base,
            expires_at: lease.expires_at,
            settle_after: lease.settle_after,
            verification,
            verified,
            verification_detail: None,
            requests_served: 0,
        })
    }

    async fn verify_oa_key(
        &self,
        api_key: &str,
        expires_at: u64,
        evidence: &OaKeyVerificationEvidence,
    ) -> Result<OaVerificationOutcome, AuthError> {
        self.verify_oa_key_with_trust(api_key, expires_at, evidence, TRUSTED_STATION)
            .await
    }

    // Production always passes TRUSTED_STATION. The private argument lets tests
    // sign synthetic keys and run local HTTP cases without any operator secrets.
    async fn verify_oa_key_with_trust(
        &self,
        api_key: &str,
        expires_at: u64,
        evidence: &OaKeyVerificationEvidence,
        trust: StationTrust<'_>,
    ) -> Result<OaVerificationOutcome, AuthError> {
        let expected_verifier = self.config.oa_verifier_url.trim_end_matches('/');
        if !matches_trusted_url(&evidence.verifier_url, expected_verifier) {
            return Err(AuthError::KeyVerification(
                "lease verifier does not match trusted verifier".into(),
            ));
        }
        validate_oa_key_evidence(expires_at, evidence)?;
        if self
            .oa_banned_stations
            .lock()
            .map_err(|_| AuthError::KeyVerification("station policy unavailable".into()))?
            .contains(&evidence.station_id)
        {
            return Err(AuthError::KeyVerification("station is banned".into()));
        }
        if api_key.is_empty() || expires_at <= now_seconds() {
            return Err(AuthError::KeyVerification("key is empty or expired".into()));
        }
        // Each attempt has fresh TLS state. Use a bounded verifier timeout;
        // transport failure is availability evidence, never successful verification.
        let response = fresh_private_http()?
            .post(format!("{expected_verifier}/submit_key"))
            .timeout(Duration::from_secs(5))
            .json(&serde_json::json!({
                "station_id": evidence.station_id, "api_key": api_key,
                "key_valid_till": evidence.key_valid_till,
                "station_signature": evidence.station_signature,
                "org_signature": evidence.org_signature,
            }))
            .send()
            .await;
        let mut response = match response {
            Ok(response) => response,
            Err(error) if oa_transport_unavailable(&error) => {
                return oa_verifier_outage(
                    None,
                    &Value::Null,
                    expires_at,
                    evidence,
                    api_key,
                    expected_verifier,
                    trust,
                );
            }
            Err(_) => {
                return Err(AuthError::KeyVerification(
                    "verifier transport failed".into(),
                ))
            }
        };
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| AuthError::KeyVerification("invalid verifier response".into()))?
        {
            if bytes.len() + chunk.len() > 1 << 20 {
                return Err(AuthError::KeyVerification(
                    "oversized verifier response".into(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        let result: Value = serde_json::from_slice(&bytes)
            .map_err(|_| AuthError::KeyVerification("invalid verifier response".into()))?;
        if !result.is_object() {
            return Err(AuthError::KeyVerification(
                "invalid verifier response".into(),
            ));
        }
        if oa_verifier_banned(&result) {
            self.oa_banned_stations
                .lock()
                .map_err(|_| AuthError::KeyVerification("station policy unavailable".into()))?
                .insert(evidence.station_id.clone());
            return Err(AuthError::KeyVerification("station is banned".into()));
        }
        if result["status"] == "verified" {
            if (200..300).contains(&status)
                && expires_at > now_seconds()
                && evidence.key_valid_till > now_seconds()
                && !oa_verifier_hard_failure(&result, false)
                && oa_verifier_binds_key(&result, &evidence.station_id, api_key)
            {
                return Ok(OaVerificationOutcome {
                    verified: true,
                    detail: None,
                });
            }
            return Err(AuthError::KeyVerification(
                "verifier did not approve this station and key".into(),
            ));
        }
        // Present binding fields must always agree, including in outage errors.
        if result
            .get("station_id")
            .is_some_and(|id| id.as_str() != Some(&evidence.station_id))
            || result.get("key_hash").is_some_and(|_| {
                let mut bound = result.clone();
                bound["status"] = serde_json::json!("verified");
                if bound.get("station_id").is_none() {
                    bound["station_id"] = serde_json::json!(evidence.station_id);
                }
                !oa_verifier_binds_key(&bound, &evidence.station_id, api_key)
            })
        {
            return Err(AuthError::KeyVerification(
                "verifier response binding mismatch".into(),
            ));
        }
        oa_verifier_outage(
            Some(status),
            &result,
            expires_at,
            evidence,
            api_key,
            expected_verifier,
            trust,
        )
    }

    /// The request's bound must be the budget of the model tier `limit` at
    /// the request's own quote, or, by C2, the one bound already fixed at
    /// the request's state when that covers the tier: every request proof at
    /// a state carries `bound_at_state`, and `state_solvency_bound` reuses a
    /// larger one for a cheaper tier.
    fn check_request_budget(&self, request: &ApiRequestV2, limit: u128) -> Result<(), AuthError> {
        if let Some(quote) = crate::oa_native::saved_quote(&self.config, &request.payload)? {
            let expected = quote
                .budget_units(limit)?
                .max(self.config.request_charge_cap);
            let bound = request.public_inputs.solvency_bound;
            if bound != expected && !(bound > expected && bound == self.fixed_bound_of(request)?) {
                return Err(AuthError::LeasePending("saved authorization uses another model budget; resume the original tier or wait for settlement".into()));
            }
        }
        Ok(())
    }

    /// `bound_at_state` of the note state `request` was made at, or 0 when
    /// the wallet is at another state (or holds none).
    fn fixed_bound_of(&self, request: &ApiRequestV2) -> Result<u128, AuthError> {
        let path = self.config.state_dir.join("note_state.json");
        if !path.exists() {
            return Ok(0);
        }
        let state = zkapi_client::note_state::NoteState::load(&path)?;
        let nullifier = core_v2::nullifier(&state.secret_s, state.note_id, &state.current_anchor);
        Ok(if nullifier == request.public_inputs.request_nullifier {
            state.bound_at_state
        } else {
            0
        })
    }

    async fn prepare_direct_lease_request(
        &self,
        request_limit_micro_usd: Option<u128>,
    ) -> Result<ApiRequestV2, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(&config, wallet.state().map(|state| state.note_id))?;
            let authorization = serde_json::to_string(&OpenRouterLeaseAuthorization::default())
                .map_err(|error| AuthError::Serialization(error.to_string()))?;
            if wallet.has_pending_request() {
                let request = wallet.pending_api_request()?.ok_or_else(|| {
                    AuthError::LeasePending(
                        "an older pending request has no retryable request body".to_string(),
                    )
                })?;
                if crate::oa_native::saved_quote(&config, &request.payload).is_err() {
                    return Err(AuthError::LeasePending(
                        "a non-lease zkAPI request is still pending".to_string(),
                    ));
                }
                return Ok(request);
            }
            // C3, C4, C5 before any proof work.
            wallet.check_request_allowed()?;
            let state = wallet.state().ok_or(AuthError::NoActiveNote)?;
            let note_id = state.note_id;
            let bound_at_state = state.bound_at_state;
            let runtime = current_thread_runtime()?;
            // Withdrawal settlement sets aside a retry whose nullifier the
            // server reports reserved for a clearance
            // (`discarded_clearance_reserved`), leaving no pending journal.
            // The server refuses every request at such a nullifier, so a
            // new proof from this state could never settle it and would
            // only hand out one more request proof at that nullifier. Ask
            // again: while the server still reports the reservation, or
            // cannot be asked, no request is proved from this state.
            if wallet
                .archive_at_current_state()?
                .records
                .iter()
                .any(|record| record.disposition == "discarded_clearance_reserved")
            {
                let nullifier = core_v2::nullifier(&state.secret_s, state.note_id, &state.current_anchor);
                match runtime.block_on(nullifier_recovery(&config, &nullifier)) {
                    Ok(recovery)
                        if recovery.nullifier_status == "clearance_reserved"
                            && recovery.request_response.is_none() =>
                    {
                        return Err(AuthError::ClearanceReservedState);
                    }
                    Ok(_) => {}
                    Err(error) => {
                        return Err(AuthError::Wallet(format!(
                            "the server's record of this note state's nullifier, which it reported reserved for a clearance, could not be read ({error}); no request is proved from this state"
                        )));
                    }
                }
            }
            let (active_root, siblings) =
                runtime.block_on(async move { indexer.root_and_path(note_id).await })?;
            let mut solvency_bound = wallet.configured_solvency_bound();
            let authorization = if config.billing_asset == "native_eth" {
                let quote = runtime.block_on(crate::oa_native::verified_quote(&config))?;
                solvency_bound = quote.budget_units(request_limit_micro_usd.ok_or_else(|| AuthError::Wallet("native lease requires a reviewed model budget".into()))?)?.max(config.request_charge_cap);
                serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote}).to_string()
            } else { authorization };
            let solvency_bound = state_solvency_bound(bound_at_state, solvency_bound)?;
            let payload_hash = compute_payload_hash(authorization.as_bytes());
            wallet
                .prepare_request_with_bound(&authorization, payload_hash, active_root, siblings, solvency_bound)
                .map_err(Into::into)
        })
        .await
    }

    async fn refresh_unaccepted_native_request(
        &self,
        request: ApiRequestV2,
    ) -> Result<(), AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let saved = wallet
                .pending_api_request()?
                .ok_or(AuthError::PendingRequest)?;
            if serde_json::to_value(&saved).ok() != serde_json::to_value(&request).ok() {
                return Err(AuthError::PendingRequest);
            }
            crate::oa_native::saved_quote(&config, &request.payload)?;
            current_thread_runtime()?.block_on(async {
                let response = zkapi_client::testnet_auth::request(
                    config.chain_id,
                    &config.protocol_server_url,
                    reqwest::Method::POST,
                    format!(
                        "{}/v2/openrouter/leases/{}/expire",
                        config.protocol_server_url.trim_end_matches('/'),
                        request.client_request_id
                    ),
                )?
                .json(&request)
                .send()
                .await
                .map_err(|_| AuthError::PendingRequest)?;
                let mut response = zkapi_client::testnet_auth::check_response(response)?;
                if !response.status().is_success() {
                    return Err(AuthError::PendingRequest);
                }
                let mut body = Vec::new();
                while let Some(chunk) = response
                    .chunk()
                    .await
                    .map_err(|_| AuthError::PendingRequest)?
                {
                    if body.len() + chunk.len() > 65536 {
                        return Err(AuthError::PendingRequest);
                    }
                    body.extend_from_slice(&chunk);
                }
                let value: Value =
                    serde_json::from_slice(&body).map_err(|_| AuthError::PendingRequest)?;
                if !matches!(
                    value["status"].as_str(),
                    Some("expired_unaccepted" | "superseded_unaccepted")
                ) || value["client_request_id"] != request.client_request_id
                    || serde_json::from_value::<Felt252>(value["request_nullifier"].clone()).ok()
                        != Some(request.public_inputs.request_nullifier)
                    || serde_json::from_value::<Felt252>(value["payload_hash"].clone()).ok()
                        != Some(request.payload_hash)
                {
                    return Err(AuthError::PendingRequest);
                }
                // The server's atomic issuance check attested that the old
                // request can no longer be admitted. Only now may its quote be
                // replaced. The answer is unsigned and only echoes the
                // request's own identifiers, so the journal is archived, from
                // where a later finalized receipt still installs.
                wallet.archive_pending_request("discarded_expired_unaccepted")?;
                Ok(())
            })
        })
        .await
    }

    async fn clear_pending_request(&self, disposition: &'static str) -> Result<(), AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            // The server reported the request unknown, and its nullifier
            // unknown or reserved for a clearance; the unsigned answer only
            // moves the journal into the archive.
            wallet.archive_pending_request(disposition)?;
            Ok(())
        })
        .await
    }

    /// Set aside a transmitted lease request after an unsigned stale_root,
    /// once the vault's root moved, only when the server also reports its
    /// nullifier as unknown, and only while the journal still holds that
    /// exact request. It moves into the request archive, where a later
    /// finalized receipt still installs. Anything else keeps it; a nullifier
    /// reserved for a clearance is reported as `ClearanceReservedState`.
    async fn clear_unadmitted_request(&self, request: &ApiRequestV2) -> Result<(), AuthError> {
        let recovery = self
            .fetch_nullifier_recovery(&request.public_inputs.request_nullifier)
            .await?;
        if recovery.nullifier_status == "clearance_reserved" && recovery.request_response.is_none()
        {
            // No request at this nullifier can be admitted; only withdrawal
            // can close the state. The journal stays for withdrawal
            // settlement to set aside.
            return Err(AuthError::ClearanceReservedState);
        }
        if recovery.status != "not_found" || recovery.nullifier_status != "unknown" {
            return Err(AuthError::LeasePending(format!(
            "request {} was rejected as stale, but its nullifier status is {}; the saved authorization is preserved",
            request.client_request_id, recovery.nullifier_status
        )));
        }
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let request = request.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let saved = wallet
                .pending_api_request()?
                .ok_or(AuthError::PendingRequest)?;
            if serde_json::to_value(&saved).ok() != serde_json::to_value(&request).ok() {
                return Err(AuthError::PendingRequest);
            }
            wallet.archive_pending_request("discarded_stale_root")?;
            Ok(())
        })
        .await
    }

    async fn fetch_direct_lease_status(
        &self,
        client_request_id: &str,
    ) -> Result<OpenRouterLeaseStatusResponse, AuthError> {
        zkapi_client::testnet_auth::request(
            self.config.chain_id,
            &self.config.protocol_server_url,
            reqwest::Method::GET,
            format!(
                "{}/v2/openrouter/leases/{client_request_id}",
                self.config.protocol_server_url.trim_end_matches('/')
            ),
        )?
        .send()
        .await
        .map_err(|error| AuthError::Wallet(error.to_string()))?
        .error_for_status()
        .map_err(testnet_http_error)?
        .json()
        .await
        .map_err(|error| AuthError::Serialization(error.to_string()))
    }

    async fn fetch_optional_direct_lease_status(
        &self,
        client_request_id: &str,
    ) -> Result<Option<OpenRouterLeaseStatusResponse>, AuthError> {
        let response = zkapi_client::testnet_auth::request(
            self.config.chain_id,
            &self.config.protocol_server_url,
            reqwest::Method::GET,
            format!(
                "{}/v2/openrouter/leases/{client_request_id}",
                self.config.protocol_server_url.trim_end_matches('/')
            ),
        )?
        .send()
        .await
        .map_err(|error| AuthError::Wallet(error.to_string()))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let response = response.error_for_status().map_err(testnet_http_error)?;
        response
            .json()
            .await
            .map(Some)
            .map_err(|error| AuthError::Serialization(error.to_string()))
    }

    async fn fetch_request_recovery(
        &self,
        client_request_id: &str,
    ) -> Result<RecoveryResponseV2, AuthError> {
        zkapi_client::testnet_auth::request(
            self.config.chain_id,
            &self.config.protocol_server_url,
            reqwest::Method::GET,
            format!(
                "{}/v2/requests/{client_request_id}",
                self.config.protocol_server_url.trim_end_matches('/')
            ),
        )?
        .send()
        .await
        .map_err(|error| AuthError::Wallet(error.to_string()))?
        .error_for_status()
        .map_err(testnet_http_error)?
        .json()
        .await
        .map_err(|error| AuthError::Serialization(error.to_string()))
    }

    async fn fetch_nullifier_recovery(
        &self,
        nullifier: &Felt252,
    ) -> Result<RecoveryResponseV2, AuthError> {
        nullifier_recovery(&self.config, nullifier).await
    }

    async fn retire_direct_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<(), AuthError> {
        let request = self.prepare_direct_lease_request(None).await?;
        if request.client_request_id != client_request_id {
            return Err(AuthError::LeasePending(
                "pending proof does not match the rejected OpenRouter lease".to_string(),
            ));
        }
        self.retire_direct_request(&request).await
    }

    async fn retire_direct_request(&self, request: &ApiRequestV2) -> Result<(), AuthError> {
        if self.try_retire_direct_request(request, true).await? {
            return Ok(());
        }
        Err(AuthError::LeasePending(
            "key usage is not finalized yet; the saved request is preserved".into(),
        ))
    }

    // False means only an explicit HTTP lease_pending response. A finalized
    // status without a verifiable receipt must never trigger issuance replay.
    async fn try_retire_direct_request(
        &self,
        request: &ApiRequestV2,
        wait: bool,
    ) -> Result<bool, AuthError> {
        let client_request_id = &request.client_request_id;
        let deadline = Instant::now() + DIRECT_LEASE_RETIRE_MAX_WAIT;
        let status = loop {
            let response = zkapi_client::testnet_auth::request(
                self.config.chain_id,
                &self.config.protocol_server_url,
                reqwest::Method::POST,
                format!(
                    "{}/v2/openrouter/leases/{client_request_id}",
                    self.config.protocol_server_url.trim_end_matches('/')
                ),
            )?
            .json(&request)
            .send()
            .await
            .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let response = zkapi_client::testnet_auth::check_response(response)?;
            let http_status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            if http_status.is_success() {
                break serde_json::from_str::<OpenRouterLeaseStatusResponse>(&body)
                    .map_err(|error| AuthError::Serialization(error.to_string()))?;
            }
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if wait
                    && error.retriable
                    && Instant::now() + DIRECT_LEASE_RETIRE_POLL_INTERVAL < deadline
                {
                    tokio::time::sleep(DIRECT_LEASE_RETIRE_POLL_INTERVAL).await;
                    continue;
                }
                if error.error_code == "lease_pending" {
                    return Ok(false);
                }
                return Err(AuthError::Wallet(format!(
                    "{}: {}",
                    error.error_code, error.error_message
                )));
            }
            return Err(AuthError::Wallet(format!("HTTP {http_status}: {body}")));
        };
        if status.client_request_id != *client_request_id {
            return Err(AuthError::Wallet(
                "retirement response belongs to another request".into(),
            ));
        }
        if status.status != "finalized" {
            return Err(AuthError::LeasePending(format!(
                "lease {} was not finalized during retirement",
                status.client_request_id
            )));
        }
        let recovered = self.recover().await?;
        if !recovered.recovered && recovered.wallet.pending_request {
            return Err(AuthError::LeasePending(format!(
                "lease {client_request_id} retired but its wallet update is not recoverable"
            )));
        }
        Ok(true)
    }

    async fn finish_direct_openrouter_lease(&self, client_request_id: String) {
        tracing::info!(
            %client_request_id,
            "retiring OpenRouter lease"
        );
        if let Err(error) = self
            .retire_direct_openrouter_lease(&client_request_id)
            .await
        {
            tracing::warn!(
                %client_request_id,
                error = %error,
                "OpenRouter lease settlement will resume on the next request"
            );
        }
    }

    pub async fn demo_overview(&self) -> Result<DemoOverview, AuthError> {
        let wallet = self.status().await?;
        let funding = self.funding_config();
        let indexer = self.fetch_indexer_snapshot().await;
        let server = self.fetch_server_snapshot().await;

        Ok(DemoOverview {
            wallet,
            funding,
            indexer,
            server,
            runtime_proof_backend: self.config.proof_backend_label().to_string(),
        })
    }

    pub async fn preview_request(&self, request: CoreRequest) -> Result<RequestPreview, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            let runtime = current_thread_runtime()?;
            runtime.block_on(async move {
                build_request_preview(&config, &indexer, &wallet, request).await
            })
        })
        .await
    }

    pub async fn execute_request_demo(
        &self,
        request: CoreRequest,
    ) -> Result<RequestDemoResult, AuthError> {
        self.ensure_scheme_agreement().await?;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let session_events = self.oa_session_events.clone();
        let indexer = self.indexer.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let payload = serde_json::to_string(&request)
                .map_err(|err| AuthError::Serialization(err.to_string()))?;
            let payload_hash = hash_payload(&payload);
            let runtime = current_thread_runtime()?;

            runtime.block_on(async move {
                if wallet.has_pending_request() {
                    if let Some(response) = wallet.recover().await? {
                        session_events
                            .settled(&response, wallet.state().map(|state| state.current_balance));
                    }
                }

                wallet.check_request_allowed()?;
                let state = wallet.state().ok_or(AuthError::NoActiveNote)?;
                let note_id = state.note_id;
                let started = Instant::now();
                tracing::info!(
                    note_id,
                    method = %request.method,
                    path = %request.path,
                    "preparing local Groth16 authorization proof"
                );
                for attempt in 0..2 {
                    let preview =
                        build_request_preview(&config, &indexer, &wallet, request.clone()).await?;
                    match wallet
                        .request_flow(
                            &payload,
                            payload_hash,
                            preview.active_root,
                            preview.merkle_siblings.clone(),
                        )
                        .await
                    {
                        Ok(response) => {
                            tracing::info!(
                                note_id,
                                elapsed_ms = started.elapsed().as_millis(),
                                charge_applied = response.charge_applied,
                                "local proof and upstream request completed"
                            );
                            let wallet_status = wallet_status(&wallet);
                            let core = core_response(
                                &response,
                                wallet.state().map(|state| state.current_balance),
                            );
                            return Ok(RequestDemoResult {
                                preview,
                                response: core,
                                protocol_response: protocol_response_trace(&response),
                                wallet: wallet_status,
                            });
                        }
                        Err(zkapi_client::error::ClientError::StaleRoot) if attempt == 0 => {
                            let _ = note_id;
                            continue;
                        }
                        Err(err) => {
                            tracing::warn!(
                                note_id,
                                elapsed_ms = started.elapsed().as_millis(),
                                error = %err,
                                "local proof or upstream request failed"
                            );
                            return Err(err.into());
                        }
                    }
                }

                Err(AuthError::Wallet(
                    "request failed after retrying stale root".to_string(),
                ))
            })
        })
        .await
    }

    pub async fn create_withdrawal(
        &self,
        mode: WithdrawalMode,
        destination: [u8; 20],
    ) -> Result<WithdrawalPlan, AuthError> {
        crate::oa_withdrawal::check_destination(&self.config, &destination)?;
        let mut prepared = self.prepared_withdrawal.lock().await;
        if let Some(plan) = prepared.as_ref() {
            let same_destination = plan.public_inputs.destination == destination;
            if plan.mode == mode && same_destination {
                return Ok(plan.clone());
            }
            // A cancelled mutual close cannot safely return to ordinary
            // spending because its clearance nullifier has been reserved by
            // the server. Falling back to the unilateral escape path for the
            // same destination is the recovery mechanism.
            if !(plan.mode == WithdrawalMode::Mutual
                && mode == WithdrawalMode::Escape
                && same_destination)
            {
                return Err(AuthError::WithdrawalPending(format!(
                    "{} withdrawal for note {} is already prepared for {}",
                    withdrawal_mode_label(plan.mode),
                    plan.public_inputs.note_id,
                    format_address(&plan.public_inputs.destination)
                )));
            }
        }

        // A proof must bind the authoritative post-lease wallet state. Hold
        // the prepared-withdrawal lock while reconciling so no new UI/API
        // request can pass the withdrawal guard and open a competing lease.
        self.reconcile_direct_openrouter().await;
        if let Some(lease) = self.direct_lease.lock().await.as_ref() {
            return Err(AuthError::LeasePending(format!(
                "chat {} owns an unsettled key until {}; wait for settlement before withdrawing",
                lease.session_id, lease.expires_at
            )));
        }

        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        let session_events = self.oa_session_events.clone();
        let plan = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|err| AuthError::Wallet(err.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            let runtime = current_thread_runtime()?;

            runtime.block_on(async move {
                // As in oa_prepare_withdrawal: install a verified receipt for
                // the pending request, or for a request set aside at this
                // state that has since been finalized, before the checks
                // below.
                if wallet.get_pending_journal()?.is_some()
                    || !wallet.archive_at_current_state()?.is_empty()
                {
                    if let Some(response) = wallet.recover().await? {
                        session_events
                            .settled(&response, wallet.state().map(|state| state.current_balance));
                    }
                }
                // As in oa_prepare_withdrawal: a request still pending at this
                // state may yet be admitted, so no withdrawal proof is made
                // from the state.
                if wallet.get_pending_journal()?.is_some() {
                    return Err(AuthError::PendingSettlement);
                }
                let note_id = wallet.state().ok_or(AuthError::NoActiveNote)?.note_id;
                let (root, siblings) = indexer.root_and_path(note_id).await?;
                let plan_siblings = siblings.clone();
                // The exit lock is durable before any exit proof exists; the
                // wallet records each proof as released before returning it
                // and marks the state for C5 when an ownership proof leaves.
                let (public_inputs, proof) = match mode {
                    WithdrawalMode::Mutual => {
                        wallet.set_exit_lock(zkapi_client::exit_lock::ExitMode::Mutual)?;
                        wallet
                            .withdrawal_mutual_close(destination, root, siblings)
                            .await?
                    }
                    // Concedes nothing. The concession rules of an exit from
                    // a state with a released request are the exit routes'.
                    WithdrawalMode::Escape => {
                        wallet.set_exit_lock(zkapi_client::exit_lock::ExitMode::Escape)?;
                        wallet.withdrawal_escape_hatch(destination, 0, root, siblings)?
                    }
                };

                Ok(WithdrawalPlan {
                    mode,
                    public_inputs,
                    siblings: plan_siblings,
                    proof,
                })
            })
        })
        .await?;
        *prepared = Some(plan.clone());
        persist_prepared_withdrawal(&self.config.state_dir, &plan)?;
        Ok(plan)
    }

    /// Read the vault's canonical note status before changing local wallet
    /// state. Closed notes are archived locally; pending escape withdrawals
    /// retain their secret until finalization; challenged escapes return to
    /// active use and clear the prepared-withdrawal guard.
    pub async fn confirm_withdrawal(&self) -> Result<WithdrawalChainStatus, AuthError> {
        let wallet_before = self.status().await?;
        let note_id = wallet_before
            .note
            .as_ref()
            .ok_or(AuthError::NoActiveNote)?
            .note_id;
        let (status, challenge_deadline) = self.onchain_withdrawal_status(note_id).await?;
        match status.as_str() {
            "closed" => {
                *self.prepared_withdrawal.lock().await = None;
                *self.direct_lease.lock().await = None;
                let wallet = self.reset_wallet().await?;
                Ok(WithdrawalChainStatus {
                    note_id,
                    status,
                    challenge_deadline: None,
                    wallet,
                })
            }
            "active" => {
                // An escape withdrawal can return to Active only after a
                // successful challenge. Its old proof must never be reused.
                let mut prepared = self.prepared_withdrawal.lock().await;
                if prepared
                    .as_ref()
                    .is_some_and(|plan| plan.mode == WithdrawalMode::Escape)
                {
                    *prepared = None;
                    remove_prepared_withdrawal(&self.config.state_dir)?;
                }
                Ok(WithdrawalChainStatus {
                    note_id,
                    status,
                    challenge_deadline: None,
                    wallet: wallet_before,
                })
            }
            "pending_withdrawal" => Ok(WithdrawalChainStatus {
                note_id,
                status,
                challenge_deadline,
                wallet: wallet_before,
            }),
            other => Err(AuthError::Wallet(format!(
                "vault returned unsupported note status {other}"
            ))),
        }
    }

    async fn onchain_withdrawal_status(
        &self,
        note_id: u32,
    ) -> Result<(String, Option<u64>), AuthError> {
        let notes_data = format!("0x9f18e4ed{:064x}", note_id);
        let encoded_note = self.vault_eth_call(&notes_data).await?;
        let note_words = abi_words(&encoded_note)?;
        if note_words.len() < 4 {
            return Err(AuthError::Wallet(
                "vault notes() returned a truncated response".to_string(),
            ));
        }
        let raw_status = abi_word_u64(note_words[3])?;
        match raw_status {
            1 => Ok(("active".to_string(), None)),
            2 => {
                let pending_data = format!("0xa2f9f1ce{:064x}", note_id);
                let encoded_pending = self.vault_eth_call(&pending_data).await?;
                let pending_words = abi_words(&encoded_pending)?;
                if pending_words.len() < 6 || abi_word_u64(pending_words[0])? != 1 {
                    return Err(AuthError::Wallet(
                        "vault pending-withdrawal record is missing".to_string(),
                    ));
                }
                Ok((
                    "pending_withdrawal".to_string(),
                    Some(abi_word_u64(pending_words[5])?),
                ))
            }
            3 => Ok(("closed".to_string(), None)),
            0 => Err(AuthError::Wallet(format!(
                "vault note {note_id} is uninitialized"
            ))),
            other => Err(AuthError::Wallet(format!(
                "vault note {note_id} has unknown status {other}"
            ))),
        }
    }

    /// The pinned vault's `currentRoot()`, read over the deployment's RPC.
    async fn vault_current_root(&self) -> Result<Felt252, AuthError> {
        let word = self.vault_eth_call(VAULT_CURRENT_ROOT_SELECTOR).await?;
        word.strip_prefix("0x")
            .filter(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
            .and_then(|hex| Felt252::from_hex(hex).ok())
            .ok_or_else(|| AuthError::Wallet("invalid vault root".into()))
    }

    async fn vault_eth_call(&self, data: &str) -> Result<String, AuthError> {
        let rpc_url = self.config.demo_rpc_url.as_ref().ok_or_else(|| {
            AuthError::InvalidInput(
                "deployment does not advertise an RPC URL for withdrawal confirmation".to_string(),
            )
        })?;
        let response = fresh_private_http()?
            .post(rpc_url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "eth_call",
                "params": [{
                    "to": format_felt_address(&self.config.contract_address),
                    "data": data,
                }, "latest"],
            }))
            .send()
            .await
            .map_err(|error| AuthError::Wallet(format!("RPC call failed: {error}")))?;
        let status = response.status();
        let payload: Value = response
            .json()
            .await
            .map_err(|error| AuthError::Wallet(format!("invalid RPC response: {error}")))?;
        if !status.is_success() || payload.get("error").is_some() {
            return Err(AuthError::Wallet(format!(
                "RPC eth_call failed: {}",
                payload
                    .get("error")
                    .cloned()
                    .unwrap_or_else(|| Value::String(status.to_string()))
            )));
        }
        payload
            .get("result")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| AuthError::Wallet("RPC eth_call omitted result".to_string()))
    }

    pub fn funding_index_html(&self) -> &'static str {
        embedded_funding_text("index.html")
    }

    pub fn funding_asset(&self, path: &str) -> Option<(&'static [u8], &'static str)> {
        embedded_funding_asset(path)
    }

    async fn fetch_indexer_snapshot(&self) -> IndexerSnapshot {
        match tokio::try_join!(self.indexer.root(), self.indexer.next_note_id()) {
            Ok((root, next_note_id)) => IndexerSnapshot {
                available: true,
                root: Some(root),
                next_note_id: Some(next_note_id),
                error: None,
            },
            Err(err) => IndexerSnapshot {
                available: false,
                root: None,
                next_note_id: None,
                error: Some(err.to_string()),
            },
        }
    }

    async fn fetch_server_snapshot(&self) -> ServerSnapshot {
        let health_url = format!(
            "{}/health",
            self.config.protocol_server_url.trim_end_matches('/')
        );
        let attestation_url = format!(
            "{}/v1/attestation",
            self.config.protocol_server_url.trim_end_matches('/')
        );

        match tokio::try_join!(
            fetch_json::<ServerHealthSnapshot>(&health_url),
            fetch_json::<ServerAttestationSnapshot>(&attestation_url),
        ) {
            Ok((health, attestation)) => ServerSnapshot {
                available: true,
                health: Some(health),
                attestation: Some(attestation),
                error: None,
            },
            Err(err) => ServerSnapshot {
                available: false,
                health: None,
                attestation: None,
                error: Some(err),
            },
        }
    }

    /// Fail fast if the server runs a different authentication method than this
    /// client is configured for (the swappable-auth handshake). Servers that
    /// predate scheme reporting return an empty value and are not rejected.
    async fn ensure_scheme_agreement(&self) -> Result<(), AuthError> {
        let attestation_url = format!(
            "{}/v1/attestation",
            self.config.protocol_server_url.trim_end_matches('/')
        );
        if let Ok(att) = fetch_json::<ServerAttestationSnapshot>(&attestation_url).await {
            let want = self.config.auth_scheme.as_str();
            if !att.auth_scheme.is_empty() && att.auth_scheme != want {
                return Err(AuthError::Wallet(format!(
                    "auth scheme mismatch: client is '{}', server is '{}'",
                    want, att.auth_scheme
                )));
            }
        }
        Ok(())
    }
}

impl CoreRequest {
    pub fn post_json(path: &str, body: Value) -> Self {
        Self {
            method: "POST".to_string(),
            path: path.to_string(),
            headers: BTreeMap::from([("content-type".to_string(), "application/json".to_string())]),
            body,
        }
    }
}

fn core_response(response: &RequestResponseV2, remaining_balance: Option<u128>) -> CoreResponse {
    CoreResponse {
        client_request_id: response.client_request_id.clone(),
        response_code: response.response_code,
        raw_payload: response.response_payload.clone(),
        payload: serde_json::from_str(&response.response_payload).ok(),
        charge_applied: response.charge_applied,
        next_anchor: response.next_anchor,
        remaining_balance,
    }
}

fn protocol_response_trace(response: &RequestResponseV2) -> ProtocolResponseTrace {
    ProtocolResponseTrace {
        client_request_id: response.client_request_id.clone(),
        request_nullifier: response.request_nullifier,
        response_code: response.response_code,
        response_hash: response.response_hash,
        charge_applied: response.charge_applied,
        next_commitment_x: response.next_commitment.x,
        next_commitment_y: response.next_commitment.y,
        next_anchor: response.next_anchor,
        blind_delta_srv: response.blind_delta_srv,
        next_state_sig_epoch: 0,
        next_state_sig_root: response.next_state_signature.r_x,
        policy_reason_code: response.policy_reason_code,
        policy_evidence_hash: response.policy_evidence_hash,
    }
}

fn wallet_status(wallet: &Wallet) -> WalletStatus {
    WalletStatus {
        has_note: wallet.state().is_some(),
        pending_request: wallet.has_pending_request(),
        funding_url: "/funding".to_string(),
        note: wallet.state().map(|state| NoteStatus {
            note_id: state.note_id,
            deposit_amount: state.deposit_amount,
            current_balance: state.current_balance,
            expiry_ts: state.expiry_ts,
            is_genesis: state.is_genesis,
            current_anchor: state.current_anchor,
            current_commitment_x: state.current_commitment_x,
            current_commitment_y: state.current_commitment_y,
        }),
    }
}

fn withdrawal_mode_label(mode: WithdrawalMode) -> &'static str {
    match mode {
        WithdrawalMode::Mutual => "mutual-close",
        WithdrawalMode::Escape => "escape-hatch",
    }
}

fn format_address(address: &[u8; 20]) -> String {
    let body = address
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("0x{body}")
}

fn format_felt_address(address: &Felt252) -> String {
    let raw = address.to_hex();
    let body = raw.strip_prefix("0x").unwrap_or(&raw);
    format!("0x{body:0>40}")
}

fn abi_words(value: &str) -> Result<Vec<&str>, AuthError> {
    let encoded = value.strip_prefix("0x").unwrap_or(value);
    if encoded.is_empty() || !encoded.len().is_multiple_of(64) || !encoded.is_ascii() {
        return Err(AuthError::Wallet(
            "RPC returned malformed ABI data".to_string(),
        ));
    }
    encoded
        .as_bytes()
        .as_chunks::<64>()
        .0
        .iter()
        .map(|chunk| {
            std::str::from_utf8(chunk)
                .map_err(|_| AuthError::Wallet("RPC returned malformed ABI data".to_string()))
        })
        .collect()
}

fn abi_word_u64(word: &str) -> Result<u64, AuthError> {
    if word.len() != 64
        || !word.bytes().all(|byte| byte.is_ascii_hexdigit())
        || word[..48].bytes().any(|byte| byte != b'0')
    {
        return Err(AuthError::Wallet(
            "RPC ABI integer does not fit in u64".to_string(),
        ));
    }
    u64::from_str_radix(&word[48..], 16)
        .map_err(|_| AuthError::Wallet("RPC returned malformed ABI integer".to_string()))
}

fn hash_payload(payload: &str) -> Felt252 {
    compute_payload_hash(payload.as_bytes())
}

pub(crate) fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn normalize_session_id(session_id: Option<&str>) -> Result<String, AuthError> {
    const DEFAULT_SESSION: &str = "default";
    let value = session_id.unwrap_or(DEFAULT_SESSION).trim();
    if value.is_empty() || value.len() > 128 {
        return Err(AuthError::InvalidInput(
            "x-zkapi-session-id must contain 1 to 128 characters".to_string(),
        ));
    }
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(AuthError::InvalidInput(
            "x-zkapi-session-id may contain only letters, digits, '-', '_', '.', and ':'"
                .to_string(),
        ));
    }
    Ok(value.to_string())
}

fn truncate_for_error(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_string();
    }
    let end = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= max)
        .last()
        .unwrap_or(0);
    format!("{}…", &value[..end])
}

fn is_transient_remote_status(status: reqwest::StatusCode) -> bool {
    matches!(
        status.as_u16(),
        408 | 425 | 429 | 500 | 502 | 503 | 504 | 524 | 529
    )
}

fn is_rejected_openrouter_key(error: &AuthError) -> bool {
    match error {
        AuthError::UpstreamResponse { status, .. }
            if *status == reqwest::StatusCode::UNAUTHORIZED =>
        {
            true
        }
        AuthError::UpstreamResponse { status, message }
            if *status == reqwest::StatusCode::FORBIDDEN =>
        {
            // OpenRouter also reports an exhausted total key limit as 403.
            // Match the structured error message narrowly because unrelated
            // permission and guardrail failures use the same status.
            is_openrouter_total_key_limit_error(message)
        }
        _ => false,
    }
}

fn is_exhausted_openrouter_key(error: &AuthError) -> bool {
    matches!(
        error,
        AuthError::UpstreamResponse { status, .. }
            if *status == reqwest::StatusCode::PAYMENT_REQUIRED
    )
}

fn is_openrouter_total_key_limit_error(message: &str) -> bool {
    serde_json::from_str::<Value>(message)
        .ok()
        .and_then(|body| {
            body.get("error")?
                .get("message")?
                .as_str()
                .map(str::to_owned)
        })
        .is_some_and(|message| message.starts_with("Key limit exceeded (total limit)"))
}

fn retry_after_delay(headers: &reqwest::header::HeaderMap) -> Option<Duration> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
        .map(Duration::from_secs)
}

fn direct_remote_retry_delay(attempt: usize, retry_after: Option<Duration>) -> Duration {
    let shift = attempt.saturating_sub(1).min(8) as u32;
    let backoff = DIRECT_REMOTE_RETRY_BASE_DELAY.saturating_mul(1u32 << shift);
    retry_after.unwrap_or_else(|| backoff.min(DIRECT_REMOTE_RETRY_MAX_DELAY))
}

fn retry_fits_lease(expires_at: u64, delay: Duration) -> bool {
    let delay_seconds = delay
        .as_secs()
        .saturating_add(u64::from(delay.subsec_nanos() > 0));
    now_seconds()
        .saturating_add(delay_seconds)
        .saturating_add(1)
        < expires_at
}

async fn build_request_preview(
    config: &AuthConfig,
    indexer: &IndexerClient,
    wallet: &Wallet,
    request: CoreRequest,
) -> Result<RequestPreview, AuthError> {
    let payload =
        serde_json::to_string(&request).map_err(|err| AuthError::Serialization(err.to_string()))?;
    let payload_hash = hash_payload(&payload);
    let state = wallet.state().ok_or(AuthError::NoActiveNote)?;
    let (active_root, merkle_siblings) = indexer.root_and_path(state.note_id).await?;
    let registration_commitment = core_v2::registration_commitment(&state.secret_s);
    let note_leaf = core_v2::note_leaf(
        state.note_id,
        &registration_commitment,
        state.deposit_amount,
        state.expiry_ts,
    );
    let request_nullifier =
        core_v2::nullifier(&state.secret_s, state.note_id, &state.current_anchor);
    let solvency_bound = state.solvency_bound(
        config.policy_enabled,
        config.request_charge_cap,
        config.policy_charge_cap,
    );
    let wallet_note = NoteStatus {
        note_id: state.note_id,
        deposit_amount: state.deposit_amount,
        current_balance: state.current_balance,
        expiry_ts: state.expiry_ts,
        is_genesis: state.is_genesis,
        current_anchor: state.current_anchor,
        current_commitment_x: state.current_commitment_x,
        current_commitment_y: state.current_commitment_y,
    };

    Ok(RequestPreview {
        request,
        payload,
        payload_hash,
        registration_commitment,
        note_leaf,
        request_nullifier,
        active_root,
        merkle_siblings,
        solvency_bound,
        wallet_note,
        state_sig_epoch: 0,
        state_sig_root: config.state_signing_key.x,
        runtime_proof_backend: config.proof_backend_label().to_string(),
    })
}

/// E2 for the mutual close, under the wallet's locks: the exit lock in
/// mutual mode before E1, the decision, then the ownership proof (kind 2),
/// the clearance and the close (kind 1). The caller removes a lock that
/// released nothing when this fails.
async fn mutual_close_locked(
    config: &AuthConfig,
    indexer: &IndexerClient,
    wallet: &mut Wallet,
    session_events: &crate::oa_events::SessionEvents,
    destination: [u8; 20],
) -> Result<WithdrawalPlan, AuthError> {
    use zkapi_client::error::ClientError;
    use zkapi_client::exit_policy::{ExitDecision, MutualOutcome};
    // E2 step 1: the exit lock, in mutual mode, before E1. An escape already
    // released from this state keeps the exit in escape mode.
    if let Err(ClientError::ExitLockConflict(_)) =
        wallet.set_exit_lock(zkapi_client::exit_lock::ExitMode::Mutual)
    {
        return Err(AuthError::EscapeRequired(serde_json::json!({
            "action": "escape", "reason": "escape_in_progress"
        })));
    }
    // An explicit mutual retry asks for the clearance again; a refusal
    // recorded earlier steers only the escape route.
    let decided = exit::decide(config, wallet, None, None, true).await?;
    if let Some(response) = &decided.installed {
        session_events.settled(response, wallet.state().map(|state| state.current_balance));
    }
    match decided.decision {
        ExitDecision::Mutual => {}
        // E3: a released request is unresolved; wait for it.
        ExitDecision::Wait { .. } => return Err(AuthError::PendingSettlement),
        ExitDecision::Escape { .. } => return Err(AuthError::EscapeRequired(decided.to_json())),
    }
    let state = wallet.state().ok_or(AuthError::NoActiveNote)?.clone();
    crate::oa_withdrawal::check_reservable(config, &state, destination)?;
    // The path first, bounded (E0): the indexer is the operator's, these
    // locks are the ones every exit route takes, and an indexer that does
    // not answer leaves no reservation behind.
    let mut path = Some(indexer.root_and_path(state.note_id).await?);
    let mut record = crate::oa_withdrawal::reserve(config, &state, destination)?;
    if record.complete {
        return record.plan.ok_or(AuthError::WithdrawalConflict);
    }
    // E2 step 3: ownership proof, clearance, close. A retry resends the
    // ownership proof still valid from an earlier attempt (at most one is
    // live, C3).
    let mut reproved = false;
    let (public_inputs, proof, siblings, signature) = loop {
        let (root, siblings) = match path.take() {
            Some(path) => path,
            None => indexer.root_and_path(state.note_id).await?,
        };
        // Saved before the request leaves: whatever answer follows (a
        // gateway 429, a 5xx, none at all), the ownership proof may have
        // reached someone, and it names this state's nullifier.
        let mut storage_failure = None;
        let closed = wallet
            .withdrawal_mutual_close_cleared(destination, root, siblings.clone(), || {
                crate::oa_withdrawal::record_ownership_proof_sent(config, &mut record).map_err(
                    |error| {
                        let message = error.to_string();
                        storage_failure = Some(error);
                        ClientError::Serialization(message)
                    },
                )
            })
            .await;
        if let Some(error) = storage_failure {
            return Err(error);
        }
        let outcome = match closed {
            Ok((public_inputs, proof, signature)) => {
                break (public_inputs, proof, siblings, signature)
            }
            Err(ClientError::StaleRoot) if !reproved => {
                reproved = true;
                continue;
            }
            // E2 step 4: the server claims a reservation.
            Err(ClientError::ClearanceRefused(code)) if code == "nullifier_used" => {
                MutualOutcome::NullifierUsed
            }
            // Not the operator's answer.
            Err(
                error @ (ClientError::TestnetPasswordRequired
                | ClientError::ProofGeneration(_)
                | ClientError::Io(_)
                | ClientError::Serialization(_)
                | ClientError::ExitLockConflict(_)
                | ClientError::NoActiveNote),
            ) => return Err(error.into()),
            // E2 step 5: any other refusal, or unreachable.
            Err(error) => {
                tracing::warn!(%error, "the clearance was refused or unreachable; the exit continues as an escape");
                MutualOutcome::RefusedOrUnreachable
            }
        };
        record.clearance_outcome = Some(outcome);
        crate::oa_withdrawal::save(config, &record)?;
        if outcome == MutualOutcome::RefusedOrUnreachable {
            wallet.set_exit_lock(zkapi_client::exit_lock::ExitMode::Escape)?;
        }
        let decided = exit::decide(config, wallet, Some(outcome), None, false).await?;
        return Err(match decided.decision {
            ExitDecision::Wait { .. } => AuthError::PendingSettlement,
            _ => AuthError::EscapeRequired(decided.to_json()),
        });
    };
    let plan = WithdrawalPlan {
        mode: WithdrawalMode::Mutual,
        public_inputs,
        siblings,
        proof,
    };
    crate::oa_withdrawal::validate_plan(&record, &plan)?;
    record.plan = Some(plan.clone());
    record.clearance_signature = Some(signature);
    crate::oa_withdrawal::save(config, &record)?;
    Ok(plan)
}

/// A close of `record`'s state proved again from its kept clearance
/// signature, with a new `valid_until`, at the saved plan's root and path
/// (any root the vault ever held stays known, Amendment A1). Needs the exit
/// lock in mutual mode at that state: an escape released since keeps the
/// exit in escape mode.
fn reprove_close(
    config: &AuthConfig,
    wallet: &Wallet,
    mut record: crate::oa_withdrawal::Reservation,
    signature: &zkapi_types::SchnorrSignature,
) -> Result<WithdrawalPlan, AuthError> {
    let saved = record.plan.clone().ok_or(AuthError::WithdrawalConflict)?;
    if wallet.current_nullifier() != Some(record.nullifier) {
        return Err(AuthError::WithdrawalConflict);
    }
    // The lock is durable before the proof (§6.2): still held in mutual mode
    // here, unless E6 released it once the earlier closes were dead.
    let locked = wallet.set_exit_lock(zkapi_client::exit_lock::ExitMode::Mutual);
    let (public_inputs, proof) = match locked.and_then(|_| {
        wallet.mutual_close_from_clearance(
            record.destination,
            saved.public_inputs.active_root,
            saved.siblings.clone(),
            signature,
        )
    }) {
        Ok(built) => built,
        Err(zkapi_client::error::ClientError::ExitLockConflict(_)) => {
            return Err(AuthError::EscapeRequired(serde_json::json!({
                "action": "escape", "reason": "escape_in_progress"
            })))
        }
        Err(error) => return Err(error.into()),
    };
    let plan = WithdrawalPlan {
        mode: WithdrawalMode::Mutual,
        public_inputs,
        siblings: saved.siblings,
        proof,
    };
    crate::oa_withdrawal::validate_plan(&record, &plan)?;
    record.plan = Some(plan.clone());
    crate::oa_withdrawal::save(config, &record)?;
    Ok(plan)
}

/// C2: the bound of a request at a state whose earlier request proofs carry
/// `bound_at_state` (0: none yet). Every request proof at a state carries
/// that one bound: a later request reuses it when it covers the request's
/// own `budget`, and otherwise waits for the state to change.
fn state_solvency_bound(bound_at_state: u128, budget: u128) -> Result<u128, AuthError> {
    match bound_at_state {
        0 => Ok(budget),
        bound if bound >= budget => Ok(bound),
        bound => Err(AuthError::BoundFixedAtState {
            bound,
            requested: budget,
        }),
    }
}

fn wallet_lock_path(state_dir: &Path) -> PathBuf {
    state_dir.join(".wallet.lock")
}

fn next_retired_note_dir(state_dir: &Path, note_id: u32) -> Result<PathBuf, AuthError> {
    let retired_root = state_dir.join("retired");
    create_private_dir(&retired_root)?;
    for suffix in 1u32.. {
        let name = if suffix == 1 {
            format!("note_{note_id}")
        } else {
            format!("note_{note_id}_{suffix}")
        };
        let candidate = retired_root.join(name);
        if !candidate.exists() {
            return Ok(candidate);
        }
    }
    unreachable!("the retired-note suffix space is non-empty")
}

fn create_private_dir(path: &Path) -> Result<(), AuthError> {
    std::fs::create_dir_all(path).map_err(|err| AuthError::Wallet(err.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
            .map_err(|err| AuthError::Wallet(err.to_string()))?;
    }
    Ok(())
}

fn prepared_withdrawal_path(state_dir: &Path) -> PathBuf {
    state_dir.join("prepared_withdrawal.json")
}

fn load_prepared_withdrawal(state_dir: &Path) -> Result<Option<WithdrawalPlan>, AuthError> {
    let path = prepared_withdrawal_path(state_dir);
    if !path.exists() {
        return Ok(None);
    }
    let encoded = std::fs::read(&path).map_err(|error| {
        AuthError::Wallet(format!("failed to read {}: {error}", path.display()))
    })?;
    serde_json::from_slice(&encoded).map(Some).map_err(|error| {
        AuthError::Wallet(format!(
            "prepared withdrawal state {} is invalid: {error}",
            path.display()
        ))
    })
}

fn persist_prepared_withdrawal(state_dir: &Path, plan: &WithdrawalPlan) -> Result<(), AuthError> {
    let path = prepared_withdrawal_path(state_dir);
    let temporary = state_dir.join("prepared_withdrawal.json.tmp");
    let encoded = serde_json::to_vec_pretty(plan)
        .map_err(|error| AuthError::Serialization(error.to_string()))?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temporary)
        .map_err(|error| AuthError::Wallet(error.to_string()))?;
    use std::io::Write;
    file.write_all(&encoded)
        .and_then(|_| file.sync_all())
        .map_err(|error| AuthError::Wallet(error.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|error| AuthError::Wallet(error.to_string()))?;
    }
    drop(file);
    std::fs::rename(&temporary, &path).map_err(|error| AuthError::Wallet(error.to_string()))
}

fn remove_prepared_withdrawal(state_dir: &Path) -> Result<(), AuthError> {
    let path = prepared_withdrawal_path(state_dir);
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AuthError::Wallet(error.to_string())),
    }
}

fn client_config(config: &AuthConfig) -> ClientConfig {
    ClientConfig {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        request_charge_cap: config.request_charge_cap,
        policy_charge_cap: config.policy_charge_cap,
        policy_enabled: config.policy_enabled,
        server_url: config.protocol_server_url.clone(),
        state_dir: config.state_dir.to_string_lossy().to_string(),
        proof_mode: ClientProofMode::Groth16 {
            setup_dir: config.proof_setup_dir.clone(),
        },
        state_signing_key: config.state_signing_key.clone(),
        clearance_signing_key: config.clearance_signing_key.clone(),
        settlement_window_seconds: config.settlement_window_seconds,
    }
}

/// Map the configured proof-mode name to the protocol's `ClientProofMode`.
fn load_wallet(config: &AuthConfig) -> Result<Wallet, AuthError> {
    let mut wallet_config = client_config(config);
    if config.billing_asset == "native_eth" {
        if let Some(journal) = zkapi_client::journal::PendingRequestJournal::read(
            &config.state_dir.join("pending_journal.json"),
        )? {
            let request = journal.prepared_request.ok_or_else(|| {
                AuthError::Wallet("native pending request has no durable authorization".into())
            })?;
            crate::oa_native::saved_quote(config, &request.payload)?;
            if request.public_inputs.solvency_bound < config.request_charge_cap
                || request.public_inputs.solvency_bound > 9_007_199_254_740_991
            {
                return Err(AuthError::Wallet(
                    "invalid saved native request bound".into(),
                ));
            }
            wallet_config.request_charge_cap = request.public_inputs.solvency_bound;
        }
    }
    Wallet::new(wallet_config).map_err(Into::into)
}

fn acquire_wallet_lock(state_dir: &Path) -> Result<std::fs::File, AuthError> {
    let path = wallet_lock_path(state_dir);
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|err| AuthError::Wallet(err.to_string()))?;
    file.try_lock_exclusive()
        .map_err(|_| AuthError::WalletBusy)?;
    Ok(file)
}

fn current_thread_runtime() -> Result<tokio::runtime::Runtime, AuthError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|err| AuthError::Wallet(err.to_string()))
}

/// Whether the server reports `nullifier` settled by a request this wallet
/// holds neither as its pending journal (`pending_id`) nor in its request
/// archive: an earlier release deleted that request's journal, so its receipt
/// can never be installed here and the state can never move. Only a readable
/// archive counts as holding no such record. A lying server can make the same
/// claim; only the operator's records settle it (receipt_journal_missing).
async fn receipt_journal_missing(
    config: &AuthConfig,
    nullifier: &Felt252,
    pending_id: Option<&str>,
) -> bool {
    let Ok(recovery) = nullifier_recovery(config, nullifier).await else {
        return false;
    };
    let Some(response) = recovery.request_response else {
        return false;
    };
    if pending_id == Some(response.client_request_id.as_str()) {
        return false;
    }
    zkapi_client::journal::read_archive(&config.state_dir.join("request_archive"), nullifier)
        .is_ok_and(|listing| {
            listing.unreadable.is_empty()
                && !listing
                    .records
                    .iter()
                    .any(|record| record.journal.client_request_id == response.client_request_id)
        })
}

/// Whether the server reports `nullifier` reserved for a clearance (an
/// earlier mutual withdrawal, or the operator's release of a stuck state).
/// The server then refuses every request at it as a replay. A failed read is
/// no such report.
async fn nullifier_clearance_reserved(config: &AuthConfig, nullifier: &Felt252) -> bool {
    nullifier_recovery(config, nullifier)
        .await
        .is_ok_and(|recovery| {
            recovery.nullifier_status == "clearance_reserved" && recovery.request_response.is_none()
        })
}

async fn nullifier_recovery(
    config: &AuthConfig,
    nullifier: &Felt252,
) -> Result<RecoveryResponseV2, AuthError> {
    zkapi_client::testnet_auth::request(
        config.chain_id,
        &config.protocol_server_url,
        reqwest::Method::GET,
        format!(
            "{}/v2/nullifiers/{}",
            config.protocol_server_url.trim_end_matches('/'),
            nullifier
        ),
    )?
    .send()
    .await
    .map_err(|error| AuthError::Wallet(error.to_string()))?
    .error_for_status()
    .map_err(testnet_http_error)?
    .json()
    .await
    .map_err(|error| AuthError::Serialization(error.to_string()))
}

async fn fetch_json<T>(url: &str) -> Result<T, String>
where
    T: DeserializeOwned,
{
    let response = reqwest::get(url)
        .await
        .map_err(|err| format!("request failed for {url}: {err}"))?;
    let response = response
        .error_for_status()
        .map_err(|err| format!("non-success response from {url}: {err}"))?;
    response
        .json::<T>()
        .await
        .map_err(|err| format!("invalid JSON from {url}: {err}"))
}

async fn spawn_blocking<T>(
    task: impl FnOnce() -> Result<T, AuthError> + Send + 'static,
) -> Result<T, AuthError>
where
    T: Send + 'static,
{
    tokio::task::spawn_blocking(task)
        .await
        .map_err(|err| AuthError::Wallet(err.to_string()))?
}

fn default_method() -> String {
    "POST".to_string()
}

fn default_body() -> Value {
    Value::Object(Default::default())
}

#[cfg(test)]
mod security_tests {
    use std::time::Duration;

    use reqwest::StatusCode;

    use super::{
        abi_word_u64, abi_words, direct_remote_retry_delay, enforce_required_key_source,
        format_address, format_felt_address, is_exhausted_openrouter_key,
        is_rejected_openrouter_key, is_transient_remote_status, matches_trusted_url,
        normalize_session_id, state_solvency_bound, validate_oa_key_evidence,
        OaKeyVerificationEvidence, MAX_OA_EVIDENCE_EXPIRY_SKEW_SECONDS,
        MAX_OA_SIGNATURE_ENCODING_LEN,
    };
    use crate::error::AuthError;
    use zkapi_types::Felt252;

    #[test]
    fn endpoint_pinning_rejects_inference_origin_substitution() {
        assert!(matches_trusted_url(
            "https://openrouter.ai/api/v1/",
            "https://openrouter.ai/api/v1"
        ));
        assert!(!matches_trusted_url(
            "https://attacker.example/api/v1",
            "https://openrouter.ai/api/v1"
        ));
        assert!(!matches_trusted_url(
            "http://openrouter.ai/api/v1",
            "https://openrouter.ai/api/v1"
        ));
    }

    #[test]
    fn required_oa_policy_rejects_direct_and_legacy_downgrades() {
        assert!(enforce_required_key_source(true, "openrouter").is_err());
        assert!(enforce_required_key_source(true, "").is_err());
        assert!(enforce_required_key_source(true, "oa_org").is_ok());
        assert!(enforce_required_key_source(false, "openrouter").is_ok());
    }

    #[test]
    fn direct_remote_retries_only_transient_statuses_and_honors_retry_after() {
        assert!(is_transient_remote_status(StatusCode::BAD_GATEWAY));
        assert!(is_transient_remote_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_transient_remote_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(!is_transient_remote_status(StatusCode::BAD_REQUEST));
        assert!(!is_transient_remote_status(StatusCode::UNAUTHORIZED));
        assert_eq!(
            direct_remote_retry_delay(1, Some(Duration::from_secs(60))),
            Duration::from_secs(60)
        );
    }
    #[test]
    fn bounded_key_replacement_is_narrow() {
        let unauthorized = AuthError::UpstreamResponse {
            status: StatusCode::UNAUTHORIZED,
            message: "invalid key".to_string(),
        };
        assert!(is_rejected_openrouter_key(&unauthorized));

        let key_limit = AuthError::UpstreamResponse {
            status: StatusCode::PAYMENT_REQUIRED,
            message: r#"{"error":{"metadata":{"limit_source":"openrouter_key_limit"}}}"#
                .to_string(),
        };
        assert!(!is_rejected_openrouter_key(&key_limit));
        assert!(is_exhausted_openrouter_key(&key_limit));

        let total_key_limit = AuthError::UpstreamResponse {
            status: StatusCode::FORBIDDEN,
            message: r#"{"error":{"message":"Key limit exceeded (total limit). Manage it using https://openrouter.ai/workspaces/default/keys/216fb8653233c25e6e60bbf30158f3e74c474b2b584ac1bfd40e0adec6c80f8b","code":403}}"#.to_string(),
        };
        assert!(is_rejected_openrouter_key(&total_key_limit));

        let permission_denied = AuthError::UpstreamResponse {
            status: StatusCode::FORBIDDEN,
            message: r#"{"error":{"message":"Request blocked by guardrail","code":403}}"#
                .to_string(),
        };
        assert!(!is_rejected_openrouter_key(&permission_denied));
    }

    #[test]
    fn session_ids_are_bounded_and_header_safe() {
        assert_eq!(normalize_session_id(None).unwrap(), "default");
        assert_eq!(
            normalize_session_id(Some("chat:abc-123")).unwrap(),
            "chat:abc-123"
        );
        assert!(normalize_session_id(Some("")).is_err());
        assert!(normalize_session_id(Some("contains spaces")).is_err());
        assert!(normalize_session_id(Some(&"x".repeat(129))).is_err());
    }

    #[test]
    fn withdrawal_rpc_abi_helpers_are_strict() {
        let encoded = format!("0x{:064x}{:064x}", 1u64, u64::MAX);
        let words = abi_words(&encoded).unwrap();
        assert_eq!(words.len(), 2);
        assert_eq!(abi_word_u64(words[0]).unwrap(), 1);
        assert_eq!(abi_word_u64(words[1]).unwrap(), u64::MAX);
        assert!(abi_words("0x1234").is_err());
        assert!(abi_words("0x").is_err());
        assert!(abi_words(&"0".repeat(63)).is_err());
        assert!(abi_words(&"0".repeat(65)).is_err());
        assert!(abi_words(&format!("{}é", "0".repeat(62))).is_err());
        assert!(abi_word_u64(&format!("1{:063x}", 0)).is_err());
    }

    /// C2 at the companion: a lease at a state that already released a
    /// request reuses that request's bound when it covers the new budget,
    /// and is refused (bound_fixed_at_state) when it does not.
    #[test]
    fn a_later_request_at_a_state_reuses_its_bound() {
        assert_eq!(state_solvency_bound(0, 400_000).unwrap(), 400_000);
        assert_eq!(state_solvency_bound(900_000, 400_000).unwrap(), 900_000);
        assert_eq!(state_solvency_bound(400_000, 400_000).unwrap(), 400_000);
        let refused = state_solvency_bound(400_000, 900_000).unwrap_err();
        assert_eq!(refused.code(), "bound_fixed_at_state");
        assert_eq!(refused.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn withdrawal_addresses_are_canonical() {
        assert_eq!(
            format_address(&[0x22; 20]),
            "0x2222222222222222222222222222222222222222"
        );
        assert_eq!(
            format_felt_address(&Felt252::from_u64(0x1234)),
            "0x0000000000000000000000000000000000001234"
        );
    }

    #[test]
    fn oa_evidence_defers_signature_encoding_to_the_pinned_verifier() {
        let evidence = OaKeyVerificationEvidence {
            verifier_url: "https://verifier.example".to_string(),
            station_id: "station-1".to_string(),
            station_recently_attested: true,
            key_valid_till: 123,
            station_signature: "provider-specific-encoding".to_string(),
            org_signature: "another-provider-specific-encoding".to_string(),
        };

        assert!(validate_oa_key_evidence(123, &evidence).is_ok());
        assert!(validate_oa_key_evidence(124, &evidence).is_err());

        let mut bounded_skew = evidence.clone();
        bounded_skew.key_valid_till = 123 + MAX_OA_EVIDENCE_EXPIRY_SKEW_SECONDS;
        assert!(validate_oa_key_evidence(123, &bounded_skew).is_ok());
        bounded_skew.key_valid_till += 1;
        assert!(validate_oa_key_evidence(123, &bounded_skew).is_err());

        let mut missing = evidence.clone();
        missing.org_signature.clear();
        assert!(validate_oa_key_evidence(123, &missing).is_err());

        let mut oversized = evidence;
        oversized.station_signature = "x".repeat(MAX_OA_SIGNATURE_ENCODING_LEN + 1);
        assert!(validate_oa_key_evidence(123, &oversized).is_err());
    }
}

#[cfg(test)]
mod wallet_lifecycle_tests {
    use tempfile::tempdir;
    use zkapi_client::journal::PendingRequestJournal;
    use zkapi_client::note_state::NoteState;

    use super::*;

    async fn service_with_note(
        balance: u128,
        request_charge_cap: u128,
    ) -> (tempfile::TempDir, Arc<AuthService>) {
        let directory = tempdir().unwrap();
        let service = AuthService::new(AuthConfig {
            state_dir: directory.path().to_path_buf(),
            request_charge_cap,
            ..Default::default()
        })
        .unwrap();
        service
            .confirm_deposit(ConfirmDepositRequest {
                secret: Felt252::ONE,
                note_id: 18,
                amount: balance,
                expiry_ts: 4_000_000_000,
                deposit_root: None,
                deposit_siblings: None,
            })
            .await
            .unwrap();
        (directory, service)
    }

    #[tokio::test]
    async fn low_balance_note_is_preserved_and_active_slot_is_cleared() {
        let (directory, service) = service_with_note(49_999, 50_000).await;

        let retired = service
            .retire_low_balance_note()
            .await
            .unwrap()
            .expect("low-balance note should be retired");

        assert_eq!(retired.note_id, 18);
        assert_eq!(retired.remaining_balance, 49_999);
        assert_eq!(retired.state_dir, directory.path().join("retired/note_18"));
        assert!(!directory.path().join("note_state.json").exists());
        let preserved = NoteState::load(&retired.state_dir.join("note_state.json")).unwrap();
        assert_eq!(preserved.note_id, 18);
        assert_eq!(preserved.current_balance, 49_999);
        assert!(!service.status().await.unwrap().has_note);
    }

    #[tokio::test]
    async fn healthy_or_pending_note_is_never_retired() {
        let (_healthy_directory, healthy) = service_with_note(50_000, 50_000).await;
        assert!(healthy.retire_low_balance_note().await.unwrap().is_none());
        assert!(healthy.status().await.unwrap().has_note);

        let (pending_directory, pending) = service_with_note(49_999, 50_000).await;
        PendingRequestJournal::write(
            &pending_directory.path().join("pending_journal.json"),
            &PendingRequestJournal {
                exists: true,
                client_request_id: "pending-request".to_string(),
                nullifier: Felt252::ONE,
                payload_hash: Felt252::ONE,
                user_rerandomization: Felt252::ONE,
                created_at_ms: 1,
                prepared_request: None,
            },
        )
        .unwrap();

        assert!(matches!(
            pending.retire_low_balance_note().await,
            Err(AuthError::PendingRequest)
        ));
        assert!(pending_directory.path().join("note_state.json").exists());
        assert!(!pending_directory.path().join("retired").exists());
    }
}

#[cfg(test)]
mod deployment_capability_tests {
    use axum::{routing::get, Json, Router};
    use serde_json::json;

    use super::{AuthConfig, AuthService, RequestMode};

    #[tokio::test]
    async fn direct_capability_matches_public_health_even_when_dashboard_is_private_or_stale() {
        // Reproduce a public deployment that blocks all dashboard routes, and
        // ensure a stale positive dashboard flag cannot enable absent health
        // capabilities (including a failed health request).
        for (health_modes, public_dashboard, expected) in [
            (Some(vec!["proxy", "direct_openrouter"]), false, true),
            (Some(vec!["proxy"]), true, false),
            (None, true, false),
        ] {
            let mut router = Router::new();
            if let Some(modes) = health_modes {
                let health = json!({
                    "status": "ok", "protocol_version": 2, "chain_id": 11155111,
                    "contract_address": "0x1234", "current_root": "0x0",
                    "provider": "metered", "policy_enabled": false,
                    "request_modes": modes,
                });
                router = router.route("/health", get(move || async move { Json(health) }));
            }
            if public_dashboard {
                router = router.route(
                    "/v1/dashboard/summary",
                    get(|| async { Json(json!({"server": {"openrouter_leases_enabled": true}})) }),
                );
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let state_dir = tempfile::tempdir().unwrap();
            let service = AuthService::new(AuthConfig {
                state_dir: state_dir.path().to_path_buf(),
                protocol_server_url: url,
                request_mode: RequestMode::DirectOpenrouter,
                ..Default::default()
            })
            .unwrap();
            assert_eq!(
                service.ensure_request_mode_available().await.is_ok(),
                expected
            );
            let config = service.zkapi_config().await;
            assert_eq!(config.request_mode, RequestMode::DirectOpenrouter);
            assert_eq!(config.direct_openrouter_available, expected);
            server.abort();
        }
    }
}

#[cfg(test)]
mod oa_withdrawal_tests {
    use super::*;
    use crate::oa_withdrawal::{self, tests::fixture};

    #[tokio::test]
    async fn reservation_survives_failed_prepare_and_blocks_all_spending_paths() {
        let (_directory, config, note) = fixture();
        let service = AuthService::new(config.clone()).unwrap();
        // The indexer fixture is unreachable: the mutual close fails before
        // anything is reserved or proved (its path is read first, E0).
        assert!(matches!(
            service.oa_prepare_withdrawal([1; 20], false).await,
            Err(AuthError::Indexer(_))
        ));
        assert_eq!(
            service.oa_withdrawal_status().await.unwrap()["phase"],
            "none"
        );
        assert!(load_wallet(&config).unwrap().exit_lock().unwrap().is_none());
        // A reservation, once made, blocks every spending path.
        oa_withdrawal::reserve(&config, &note, [1; 20]).unwrap();
        assert_eq!(
            service.oa_withdrawal_status().await.unwrap()["phase"],
            "reserved"
        );
        drop(service);
        let service = AuthService::new(config.clone()).unwrap();
        for result in [
            service.prepare_deposit(1).await.map(|_| ()),
            service
                .confirm_deposit(ConfirmDepositRequest {
                    secret: Felt252::ONE,
                    note_id: note.note_id + 1,
                    amount: 1,
                    expiry_ts: 4_000_000_000,
                    deposit_root: None,
                    deposit_siblings: None,
                })
                .await
                .map(|_| ()),
            service.reset_wallet().await.map(|_| ()),
            service.recover().await.map(|_| ()),
            service.prepare_direct_lease_request(None).await.map(|_| ()),
            service
                .clear_pending_request("discarded_unknown_to_server")
                .await,
            service
                .create_withdrawal(WithdrawalMode::Mutual, [2; 20])
                .await
                .map(|_| ()),
            service
                .execute_request_demo(CoreRequest::post_json("/chat", serde_json::json!({})))
                .await
                .map(|_| ()),
        ] {
            assert!(
                matches!(result, Err(AuthError::WithdrawalConflict)),
                "{result:?}"
            );
        }
        *service.direct_lease.lock().await = Some(ActiveOpenRouterLease {
            session_id: "oa-single-use".into(),
            requests_served: 0,
            verification_detail: None,
            client_request_id: "cached-before-reservation".into(),
            api_key: "fixture-key".into(),
            openrouter_api_base: "https://openrouter.ai/api/v1".into(),
            expires_at: now_seconds() + 300,
            settle_after: now_seconds() + 360,
            verified: true,
            verification: None,
        });
        assert!(matches!(
            service.ready_direct_lease(1_000_000).await,
            Err(AuthError::WithdrawalConflict)
        ));
        assert!(matches!(
            service.oa_prepare_withdrawal([2; 20], false).await,
            Err(AuthError::WithdrawalConflict)
        ));
        assert!(config.state_dir.join("note_state.json").exists());
    }

    /// The vault cannot pay itself: a vault with vault_revision 2 reverts
    /// InvalidDestination, and a legacy vault cannot receive the payout. A
    /// withdrawal to the vault's address used to reserve the note and ask
    /// for a permanent clearance pinned to that destination, so every close
    /// reverted and the note waited for expiry. Both routes now refuse it
    /// before anything is reserved, proved or sent.
    #[tokio::test]
    async fn the_vault_address_is_refused_as_a_destination_before_anything_is_reserved() {
        let (_directory, config, _note) = fixture();
        let service = AuthService::new(config.clone()).unwrap();
        let vault = zkapi_types::serialization::felt_to_address(&config.contract_address).unwrap();
        // The indexer fixture is unreachable, so a withdrawal that got past
        // the destination would fail later, after reserving the note.
        let refused = service.oa_prepare_withdrawal(vault, false).await;
        assert!(
            matches!(refused, Err(AuthError::InvalidInput(_))),
            "{refused:?}"
        );
        assert!(oa_withdrawal::load(&config).unwrap().is_none());
        for mode in [WithdrawalMode::Mutual, WithdrawalMode::Escape] {
            let refused = service.create_withdrawal(mode, vault).await;
            assert!(
                matches!(refused, Err(AuthError::InvalidInput(_))),
                "{mode:?}: {refused:?}"
            );
        }
        // Any other address still reaches the indexer.
        assert!(matches!(
            service
                .create_withdrawal(WithdrawalMode::Escape, [1; 20])
                .await,
            Err(AuthError::Indexer(_))
        ));
        assert!(matches!(
            service.oa_prepare_withdrawal([1; 20], false).await,
            Err(AuthError::Indexer(_))
        ));
    }

    #[tokio::test]
    async fn pending_settlement_is_recovered_before_reserving_and_parse_errors_fail_closed() {
        use axum::{routing::get, Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (_directory, mut config, note) = fixture();
        let attempts = Arc::new(AtomicUsize::new(0));
        let seen = attempts.clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.protocol_server_url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new().route(
            "/v2/requests/pending",
            get(move || {
                seen.fetch_add(1, Ordering::SeqCst);
                async {
                    Json(serde_json::json!({"status":"pending", "nullifier_status":"reserved"}))
                }
            }),
        );
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        // The §6.2 write order: the request fixed the state's bound first.
        let mut note = note;
        note.bound_at_state = 1_000;
        note.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        let journal_path = config.state_dir.join("pending_journal.json");
        zkapi_client::journal::PendingRequestJournal::write(
            &journal_path,
            &zkapi_client::journal::PendingRequestJournal {
                exists: true,
                client_request_id: "pending".into(),
                nullifier: core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor),
                payload_hash: Felt252::ONE,
                user_rerandomization: Felt252::ONE,
                // Just sent: E3 waits for its settlement.
                created_at_ms: now_seconds() * 1_000,
                prepared_request: None,
            },
        )
        .unwrap();
        let service = AuthService::new(config.clone()).unwrap();
        let prepared = service.oa_prepare_withdrawal([1; 20], false).await;
        assert!(
            matches!(prepared, Err(AuthError::PendingSettlement)),
            "{prepared:?}"
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(oa_withdrawal::load(&config).unwrap().is_none());
        std::fs::write(&journal_path, "malformed").unwrap();
        assert!(service.oa_prepare_withdrawal([1; 20], false).await.is_err());
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(oa_withdrawal::load(&config).unwrap().is_none());
        server.abort();
    }

    #[tokio::test]
    async fn lost_completion_reply_is_idempotent_and_cannot_clear_new_note_lease() {
        let (_directory, config, note) = fixture();
        let mut record = oa_withdrawal::reserve(&config, &note, [1; 20]).unwrap();
        record.plan = Some(oa_withdrawal::tests::plan(&record));
        oa_withdrawal::save(&config, &record).unwrap();
        let hash = format!("0x{}", "ab".repeat(32));
        oa_withdrawal::complete(&config, &mut record, &hash).unwrap();
        let service = AuthService::new(config.clone()).unwrap();
        assert_eq!(
            service.oa_prepare_withdrawal([1; 20], false).await.unwrap(),
            record.plan.clone().unwrap()
        );
        let mut next = note.clone();
        next.note_id += 1;
        next.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        *service.direct_lease.lock().await = Some(ActiveOpenRouterLease {
            session_id: "oa-single-use".into(),
            requests_served: 0,
            verification_detail: None,
            client_request_id: "new-note-lease".into(),
            api_key: "fixture-key".into(),
            openrouter_api_base: "https://openrouter.ai/api/v1".into(),
            expires_at: now_seconds() + 300,
            settle_after: now_seconds() + 360,
            verified: true,
            verification: None,
        });
        assert_eq!(
            service.oa_confirm_withdrawal(hash).await.unwrap()["phase"],
            "complete"
        );
        assert_eq!(
            service
                .direct_lease
                .lock()
                .await
                .as_ref()
                .unwrap()
                .client_request_id,
            "new-note-lease"
        );
        assert_eq!(
            zkapi_client::note_state::NoteState::load(&config.state_dir.join("note_state.json"))
                .unwrap()
                .note_id,
            next.note_id
        );
    }

    #[tokio::test]
    async fn prepare_proves_note_ownership_with_a_kind_2_proof_before_clearance() {
        use axum::{
            extract::State,
            routing::{get, post},
            Json, Router,
        };
        use zkapi_proof::compact::{CompactSigner, WithdrawalVerifier};
        let directory = tempfile::tempdir().unwrap();
        let setup_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/setup/v2-concession-dev"
        );
        let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(12));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdeadbeef),
            protocol_server_url: url.clone(),
            indexer_url: url,
            proof_setup_dir: setup_dir.into(),
            state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
            clearance_signing_key: clearance_signer.public_key(),
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 0, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap().clone();
        let leaf = core_v2::note_leaf(
            0,
            &core_v2::registration_commitment(&note.secret_s),
            note.deposit_amount,
            note.expiry_ts,
        );
        let siblings = core_v2::zero_hashes()[..zkapi_types::MERKLE_DEPTH].to_vec();
        let root = core_v2::merkle_root(0, &leaf, &siblings.clone().try_into().unwrap());
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let clearance = zkapi_types::wire::ClearanceResponseV2 {
            status: "ok".into(),
            withdrawal_nullifier: nullifier,
            signature: clearance_signer.sign(&core_v2::clearance_message(
                2,
                1,
                &config.contract_address,
                &nullifier,
            )),
        };
        let bodies = Arc::new(Mutex::new(Vec::<Value>::new()));
        let router = Router::new()
            .route(
                "/v1/tree/snapshot",
                get(move || async move {
                    Json(serde_json::json!({"root": root, "next_note_id": 1, "leaves": [leaf]}))
                }),
            )
            .route(
                "/v2/withdraw/clearance",
                post(
                    move |State(bodies): State<Arc<Mutex<Vec<Value>>>>, Json(body): Json<Value>| {
                        bodies.lock().unwrap().push(body);
                        let clearance = clearance.clone();
                        async move { Json(clearance) }
                    },
                ),
            )
            .with_state(bodies.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let destination = [0x22; 20];
        let plan = service
            .oa_prepare_withdrawal(destination, false)
            .await
            .unwrap();
        assert_eq!(plan.mode, WithdrawalMode::Mutual);
        assert_eq!(
            plan.public_inputs.withdrawal_kind(),
            Some(zkapi_types::WithdrawalKind::MutualClose)
        );
        assert_eq!(plan.public_inputs.destination, destination);

        let bodies = bodies.lock().unwrap().clone();
        assert_eq!(bodies.len(), 1);
        let request: zkapi_types::wire::ClearanceRequestV2C =
            serde_json::from_value(bodies[0].clone()).unwrap();
        let ownership = request.ownership_proof;
        assert_eq!(request.withdrawal_nullifier, nullifier);
        // The ownership proof is the close's statement as kind 2: no
        // destination, no concession, no successor nullifier, its own
        // valid_until.
        let mut expected = plan.public_inputs.clone();
        expected.kind = zkapi_types::WithdrawalKind::Ownership.as_u8();
        expected.destination = [0; 20];
        expected.valid_until = ownership.public_inputs.valid_until;
        assert_eq!(ownership.public_inputs, expected);
        assert_eq!(ownership.public_inputs.active_root, root);
        assert!(ownership.public_inputs.valid_until <= now_seconds() + 3_600);
        let verifier = WithdrawalVerifier::load(setup_dir).unwrap();
        assert!(verifier
            .verify(&ownership.public_inputs, &ownership.proof)
            .unwrap());
        assert!(verifier.verify(&plan.public_inputs, &plan.proof).unwrap());
        // The mutual plan is saved in the reservation. The ownership proof is
        // kept only in the exit lock and C5's marker (which keeps it past a
        // cancelled lock), so a retry resends it instead of releasing
        // another (it is kind 2: no vault entry point accepts it).
        assert_eq!(
            oa_withdrawal::load(&config).unwrap().unwrap().plan.unwrap(),
            plan
        );
        let lock = load_wallet(&config).unwrap().exit_lock().unwrap().unwrap();
        assert_eq!(
            lock.released
                .iter()
                .map(|proof| proof.kind)
                .collect::<Vec<_>>(),
            [2, 1]
        );
        for entry in std::fs::read_dir(directory.path()).unwrap() {
            let path = entry.unwrap().path();
            if path.is_file()
                && !path.ends_with("exit_lock.json")
                && !path.ends_with(zkapi_client::wallet::OWNERSHIP_PROOF_MARKER_FILE)
            {
                assert!(
                    !std::fs::read_to_string(&path)
                        .unwrap_or_default()
                        .contains(&ownership.proof.proof),
                    "{path:?}"
                );
            }
        }
        server.abort();
    }

    /// How the clearance fixture answers.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Clearance {
        Grant,
        NullifierUsed,
        /// A `zkapi-v2-concession-v1` server: grants only a request that
        /// carries a kind-2 ownership proof.
        RequireProof,
        /// A gateway in front of the server answers 429 to every request.
        GatewayThrottled,
        /// The first request gets a gateway 429, later ones are granted.
        ThrottledOnce,
        /// The server fails with a 500.
        ServerFailure,
        /// An answer that is no clearance at all, as when the real one is
        /// lost or rewritten on the way.
        Garbled,
    }

    /// What the starting state's request archive holds.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Archive {
        Empty,
        /// A lease request sent from this state, set aside unsettled.
        Record,
        /// Only a damaged record, beside a file that is not a record.
        Unreadable,
    }

    /// One fixture run's setup; see `prepare_with`.
    #[derive(Clone, Copy, Debug)]
    struct Setup {
        route: Route,
        vault_revision: u32,
        archive: Archive,
        clearance: Clearance,
        nullifier_status: &'static str,
        expiry_ts: u64,
        /// Prepare once more, as approving the quote does.
        again: bool,
        /// Direct mode with a pending lease journal "retry" from the starting
        /// state that the server reports unknown, and no live key in the
        /// daemon.
        pending_retry: bool,
        /// Whether the vault's root moved past the retry's since it was
        /// proved; otherwise the vault still has it.
        vault_root_moved: bool,
        /// Afterwards, ask to release the reservation and, on a vault below
        /// revision 2, for a lease request (see `Prepared::follow_up`).
        follow_up: bool,
        /// Before `again`, leave a damaged record in the starting state's
        /// request archive, which marks that state unsettled.
        archive_before_again: bool,
    }

    impl Setup {
        fn new(archive: Archive, clearance: Clearance, nullifier_status: &'static str) -> Self {
            Self {
                route: Route::Oa,
                vault_revision: 0,
                archive,
                clearance,
                nullifier_status,
                expiry_ts: 4_000_000_000,
                again: false,
                pending_retry: false,
                vault_root_moved: true,
                follow_up: false,
                archive_before_again: false,
            }
        }
    }

    /// The withdrawal route used.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Route {
        /// `/oa/v1/withdraw/prepare`, the route zkapi-clientd uses.
        Oa,
        /// The generic `/wallet/withdraw`, mutual close or escape.
        Generic(WithdrawalMode),
    }

    /// The release's result, the lease request's result and the server
    /// reads of the release (see `Prepared::follow_up`).
    type FollowUp = (
        Result<Value, AuthError>,
        Option<Result<ApiRequestV2, AuthError>>,
        usize,
    );

    /// What one fixture run observed.
    struct Prepared {
        result: Result<WithdrawalPlan, AuthError>,
        /// Every clearance request body.
        requests: Vec<zkapi_types::wire::ClearanceRequestV2C>,
        /// The reservation phase afterwards.
        phase: Value,
        /// Reads of the server's record for the starting state's nullifier.
        reads: usize,
        /// That nullifier.
        nullifier: Felt252,
        /// The repeated preparation's result, with `Setup::again`.
        again: Option<Result<WithdrawalPlan, AuthError>>,
        /// Whether a request journal is still pending afterwards.
        pending: bool,
        /// The dispositions of the requests archived at the starting state.
        archived: Vec<String>,
        /// The reservation's `ownership_proof_sent` afterwards.
        ownership_proof_sent: Option<bool>,
        /// With `Setup::follow_up`: the release's result, the lease request's
        /// result (after a refused release on a vault below revision 2), and
        /// the server reads of the nullifier that the release made.
        follow_up: Option<FollowUp>,
        /// With `Setup::follow_up`, after a refused release on a vault below
        /// revision 2: the proxied request's result (`RequestMode::Proxy`).
        proxied: Option<Result<(), AuthError>>,
    }

    /// Prepare a withdrawal against a mock server and indexer with the
    /// development setup. `archived` sets aside a lease request sent from the
    /// starting state; the server's record for that state's nullifier reads
    /// `nullifier_status`, and "finalized" carries a valid signed receipt for
    /// the archived request.
    async fn prepare_with(
        route: Route,
        vault_revision: u32,
        archived: bool,
        clearance: Clearance,
        nullifier_status: &'static str,
    ) -> Prepared {
        let archive = if archived {
            Archive::Record
        } else {
            Archive::Empty
        };
        prepare_with_setup(Setup {
            route,
            vault_revision,
            ..Setup::new(archive, clearance, nullifier_status)
        })
        .await
    }

    async fn prepare_with_setup(setup: Setup) -> Prepared {
        let Setup {
            route,
            vault_revision,
            archive,
            clearance,
            nullifier_status,
            expiry_ts,
            again,
            pending_retry,
            vault_root_moved,
            follow_up,
            archive_before_again,
        } = setup;
        use axum::{
            extract::State,
            http::StatusCode,
            routing::{get, post},
            Json, Router,
        };
        use zkapi_proof::compact::{rerandomize, server_update, CompactSigner, WithdrawalVerifier};
        let directory = tempfile::tempdir().unwrap();
        let setup_dir = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/setup/v2-concession-dev"
        );
        let clearance_signer = CompactSigner::from_seed(&Felt252::from_u64(12));
        let state_signer = CompactSigner::from_seed(&Felt252::from_u64(11));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0xdeadbeef),
            protocol_server_url: url.clone(),
            indexer_url: url.clone(),
            proof_setup_dir: setup_dir.into(),
            state_signing_key: state_signer.public_key(),
            clearance_signing_key: clearance_signer.public_key(),
            vault_revision,
            request_mode: if pending_retry {
                RequestMode::DirectOpenrouter
            } else {
                RequestMode::default()
            },
            demo_rpc_url: Some(format!("{url}/rpc")),
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 0, 1_500_000, expiry_ts)
            .unwrap();
        // The §6.2 write order: a request released at this state fixed the
        // state's bound before its journal existed.
        if pending_retry || archive == Archive::Record {
            let path = config.state_dir.join("note_state.json");
            let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
            state.bound_at_state = 1_000;
            state.save(&path).unwrap();
            wallet = load_wallet(&config).unwrap();
        }
        let note = wallet.state().unwrap().clone();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let damage_archive = || {
            // A torn record and a file another program left beside it.
            let directory = config.state_dir.join("request_archive").join(
                nullifier
                    .0
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            );
            std::fs::create_dir_all(&directory).unwrap();
            let torn = directory.join("1700000000000-0.json");
            std::fs::write(&torn, b"").unwrap();
            // Damaged long ago: the exit decision bounds an unreadable
            // record's request time by its modification time.
            std::fs::File::options()
                .write(true)
                .open(&torn)
                .unwrap()
                .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000))
                .unwrap();
            std::fs::write(directory.join(".DS_Store"), b"\0\0\0\x01Bud1").unwrap();
        };
        if archive == Archive::Unreadable {
            damage_archive();
        }
        if pending_retry {
            let payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
            let retry = ApiRequestV2 {
                client_request_id: "retry".into(),
                payload_hash: compute_payload_hash(payload.as_bytes()),
                payload,
                public_inputs: zkapi_types::RequestPublicInputsV2 {
                    protocol_version: 2,
                    chain_id: 1,
                    contract_address: config.contract_address,
                    active_root: Felt252::ONE,
                    state_signing_key_x: config.state_signing_key.x,
                    state_signing_key_y: config.state_signing_key.y,
                    request_time: 1,
                    solvency_bound: 1_000,
                    request_nullifier: nullifier,
                    authorization_tag: Felt252::ONE,
                    anonymous_commitment_x: Felt252::ONE,
                    anonymous_commitment_y: Felt252::ONE,
                },
                proof: Groth16ProofWire {
                    backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                    proof: "retry-proof".into(),
                },
            };
            zkapi_client::journal::PendingRequestJournal::write(
                &config.state_dir.join("pending_journal.json"),
                &zkapi_client::journal::PendingRequestJournal {
                    exists: true,
                    client_request_id: "retry".into(),
                    nullifier,
                    payload_hash: retry.payload_hash,
                    user_rerandomization: Felt252::from_u64(3),
                    created_at_ms: 2,
                    prepared_request: Some(retry),
                },
            )
            .unwrap();
        }
        if archive == Archive::Record {
            // A lease request sent from this state, set aside unsettled.
            zkapi_client::journal::PendingRequestJournal::write(
                &config.state_dir.join("pending_journal.json"),
                &zkapi_client::journal::PendingRequestJournal {
                    exists: true,
                    client_request_id: "withheld".into(),
                    nullifier,
                    payload_hash: Felt252::ONE,
                    user_rerandomization: Felt252::ONE,
                    created_at_ms: 1,
                    prepared_request: None,
                },
            )
            .unwrap();
            wallet
                .archive_pending_request("discarded_unknown_to_server")
                .unwrap();
        }
        // The server's finalized receipt for the archived request.
        let anonymous = rerandomize(
            &zkapi_types::wire::CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::ONE,
        )
        .unwrap();
        let next_commitment = server_update(&anonymous, 0, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let payload = serde_json::json!({"type":"openrouter_lease_settlement"}).to_string();
        let next_state_signature = state_signer.sign(&core_v2::state_message(
            2,
            1,
            &config.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        ));
        let receipt = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: "withheld".into(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: 0,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature,
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let leaf = core_v2::note_leaf(
            0,
            &core_v2::registration_commitment(&note.secret_s),
            note.deposit_amount,
            note.expiry_ts,
        );
        let siblings = core_v2::zero_hashes()[..zkapi_types::MERKLE_DEPTH].to_vec();
        let root = core_v2::merkle_root(0, &leaf, &siblings.clone().try_into().unwrap());
        let contract = config.contract_address;
        type Seen = Arc<Mutex<(Vec<Value>, usize)>>;
        let seen: Seen = Arc::default();
        let router = Router::new()
            .route("/v2/openrouter/leases/retry", get(|| async { StatusCode::NOT_FOUND }))
            .route("/v2/requests/retry", get(|| async {
                Json(serde_json::json!({"status":"not_found","nullifier_status":"unknown"}))
            }))
            .route("/rpc", post(move || async move {
                // The retry was proved at root 1.
                let root = if vault_root_moved { 5 } else { 1 };
                Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":format!("0x{root:064x}")}))
            }))
            .route("/v1/tree/snapshot", get(move || async move {
                Json(serde_json::json!({"root": root, "next_note_id": 1, "leaves": [leaf]}))
            }))
            .route("/v2/withdraw/clearance", post(move |State(seen): State<Seen>, Json(body): Json<Value>| {
                let requested: Felt252 = serde_json::from_value(body["withdrawal_nullifier"].clone()).unwrap();
                let proved = body["ownership_proof"]["public_inputs"]["kind"] == 2;
                let count = {
                    let mut seen = seen.lock().unwrap();
                    seen.0.push(body);
                    seen.0.len()
                };
                let granted = zkapi_types::wire::ClearanceResponseV2 {
                    status: "ok".into(),
                    withdrawal_nullifier: requested,
                    signature: clearance_signer.sign(&core_v2::clearance_message(2, 1, &contract, &requested)),
                };
                async move {
                    let refusal = |status: StatusCode, code: &str| (status, Json(serde_json::json!({"status":"error",
                        "client_request_id":"","error_code":code,"error_message":"refused","retriable":false})));
                    let throttled = || (StatusCode::TOO_MANY_REQUESTS, Json(serde_json::json!({"error":
                        {"code":"gateway_rate_limited","message":"too many requests"},"retry_after_seconds":60})));
                    match clearance {
                        Clearance::GatewayThrottled => throttled(),
                        Clearance::ThrottledOnce if count == 1 => throttled(),
                        Clearance::ServerFailure => refusal(StatusCode::INTERNAL_SERVER_ERROR, "internal_error"),
                        Clearance::Garbled => (StatusCode::OK, Json(serde_json::json!({"status":"ok"}))),
                        Clearance::Grant | Clearance::ThrottledOnce => (StatusCode::OK, Json(serde_json::to_value(granted).unwrap())),
                        Clearance::RequireProof if proved => (StatusCode::OK, Json(serde_json::to_value(granted).unwrap())),
                        Clearance::RequireProof => refusal(StatusCode::BAD_REQUEST, "clearance_ownership_required"),
                        Clearance::NullifierUsed => refusal(StatusCode::CONFLICT, "nullifier_used"),
                    }
                }
            }))
            .route(&format!("/v2/nullifiers/{nullifier}"), get(move |State(seen): State<Seen>| {
                seen.lock().unwrap().1 += 1;
                let receipt = receipt.clone();
                async move {
                    Json(match nullifier_status {
                        "unknown" => serde_json::json!({"status":"not_found","nullifier_status":"unknown"}),
                        "finalized" => serde_json::json!({"status":"ok","nullifier_status":"finalized","request_response":receipt}),
                        status => serde_json::json!({"status":"ok","nullifier_status":status}),
                    })
                }
            }))
            .with_state(seen.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let result = match route {
            Route::Oa => service.oa_prepare_withdrawal([0x22; 20], false).await,
            Route::Generic(mode) => service.create_withdrawal(mode, [0x22; 20]).await,
        };
        if archive_before_again {
            damage_archive();
        }
        let again = if again {
            Some(match route {
                Route::Oa => service.oa_prepare_withdrawal([0x22; 20], false).await,
                Route::Generic(mode) => service.create_withdrawal(mode, [0x22; 20]).await,
            })
        } else {
            None
        };
        let ownership_proof_sent = oa_withdrawal::load(&config)
            .unwrap()
            .and_then(|record| record.ownership_proof_sent);
        let follow_up = if follow_up {
            let reads = seen.lock().unwrap().1;
            let released = service.oa_release_withdrawal(note.note_id, nullifier).await;
            let reads = seen.lock().unwrap().1 - reads;
            // Only while something still stands in the way: a lease after
            // a release proves a real request.
            let lease = if released.is_err() {
                Some(service.prepare_direct_lease_request(None).await)
            } else {
                None
            };
            Some((released, lease, reads))
        } else {
            None
        };
        let proxied = if follow_up_proxied(&follow_up) {
            Some(
                service
                    .execute_request_demo(CoreRequest::post_json("/chat", serde_json::json!({})))
                    .await
                    .map(|_| ()),
            )
        } else {
            None
        };
        let phase = service.oa_withdrawal_status().await.unwrap()["phase"].clone();
        let (bodies, reads) = seen.lock().unwrap().clone();
        let requests: Vec<zkapi_types::wire::ClearanceRequestV2C> = bodies
            .into_iter()
            .map(|body| serde_json::from_value(body).unwrap())
            .collect();
        if let Ok(plan) = &result {
            let verifier = WithdrawalVerifier::load(setup_dir).unwrap();
            assert!(verifier.verify(&plan.public_inputs, &plan.proof).unwrap());
            assert_eq!(
                plan.public_inputs.withdrawal_kind(),
                Some(match plan.mode {
                    WithdrawalMode::Mutual => zkapi_types::WithdrawalKind::MutualClose,
                    WithdrawalMode::Escape => zkapi_types::WithdrawalKind::Escape,
                })
            );
        }
        // Every clearance request carries a verifying ownership proof (kind 2).
        for request in &requests {
            let verifier = WithdrawalVerifier::load(setup_dir).unwrap();
            assert!(is_ownership_proof(request, &verifier), "{request:?}");
        }
        let pending = config.state_dir.join("pending_journal.json").exists();
        let archived = zkapi_client::journal::read_archive(
            &config.state_dir.join("request_archive"),
            &nullifier,
        )
        .unwrap()
        .records
        .into_iter()
        .map(|record| record.disposition)
        .collect();
        server.abort();
        Prepared {
            result,
            requests,
            phase,
            reads,
            nullifier,
            again,
            pending,
            archived,
            ownership_proof_sent,
            follow_up,
            proxied,
        }
    }

    /// Whether a clearance request carries a verifying kind-2 ownership proof
    /// of its own nullifier, with no destination and nothing conceded.
    fn is_ownership_proof(
        request: &zkapi_types::wire::ClearanceRequestV2C,
        verifier: &zkapi_proof::compact::WithdrawalVerifier,
    ) -> bool {
        let public = &request.ownership_proof.public_inputs;
        public.withdrawal_kind() == Some(zkapi_types::WithdrawalKind::Ownership)
            && public.destination == [0; 20]
            && public.conceded == 0
            && public.next_nullifier == Felt252::ZERO
            && public.withdrawal_nullifier == request.withdrawal_nullifier
            && verifier
                .verify(public, &request.ownership_proof.proof)
                .unwrap_or(false)
    }

    /// A proxied request follows a lease request (see `Prepared::proxied`).
    fn follow_up_proxied(follow_up: &Option<FollowUp>) -> bool {
        follow_up
            .as_ref()
            .is_some_and(|(_, lease, _)| lease.is_some())
    }

    /// A `zkapi-v2-concession-v1` server grants a clearance only against an
    /// ownership proof, which no vault entry point accepts. Every clearance
    /// request therefore carries one, also from a state with a request that
    /// was set aside unsettled (the legacy proof-less clearance is gone).
    #[tokio::test]
    async fn every_clearance_request_carries_an_ownership_proof() {
        // A manifest without `vault_revision` (0) once chose a proof-less
        // clearance at a state with a request set aside.
        for (vault_revision, archived) in [(0, false), (0, true), (3, false), (3, true)] {
            let case = format!("revision {vault_revision}, archived {archived}");
            let run = prepare_with(
                Route::Oa,
                vault_revision,
                archived,
                Clearance::RequireProof,
                "unknown",
            )
            .await;
            assert!(run.result.is_ok(), "{case}: {:?}", run.result);
            assert_eq!(run.requests.len(), 1, "{case}");
            assert_eq!(run.requests[0].withdrawal_nullifier, run.nullifier);
            assert_eq!(run.phase, "reserved");
            assert_eq!(run.ownership_proof_sent, Some(true));
            // The recovery attempt before the gate found nothing to install
            // (it reads only when something was archived), and the exit
            // decision read the nullifier once.
            assert_eq!(run.reads, 1 + usize::from(archived), "{case}");
        }
        // E2 step 4: a clearance refused as nullifier_used means the server
        // claims a reservation: E3 from the newest release, here long past
        // T, so the exit is an escape conceding the state's bound.
        let run = prepare_with(Route::Oa, 3, true, Clearance::NullifierUsed, "unknown").await;
        assert_eq!(run.requests.len(), 1);
        match &run.result {
            Err(error @ AuthError::EscapeRequired(detail)) => {
                assert_eq!(error.code(), "escape_required");
                assert_eq!(detail["action"], "escape");
                assert_eq!(detail["reason"], "at_deadline");
            }
            other => panic!("{other:?}"),
        }
        // E3: a reading of `reserved` leaves the archived request unresolved;
        // no clearance is asked for at all.
        let run = prepare_with(Route::Oa, 3, true, Clearance::Grant, "reserved").await;
        assert!(run.requests.is_empty(), "{:?}", run.requests);
        assert!(
            matches!(&run.result, Err(AuthError::EscapeRequired(detail)) if detail["reason"] == "at_deadline"),
            "{:?}",
            run.result
        );
    }

    /// When the request set aside at this state was finalized after all,
    /// preparation installs its verified receipt first and closes the settled
    /// successor state, which has no unsettled request: its ownership proof
    /// is for a nullifier no withheld request proof can match.
    #[tokio::test]
    async fn a_finalized_archived_request_is_installed_before_the_withdrawal_gate() {
        let run = prepare_with(Route::Oa, 0, true, Clearance::Grant, "finalized").await;
        let plan = run.result.expect("withdrawal at the settled state");
        assert_eq!(run.reads, 1);
        assert_eq!(run.requests.len(), 1);
        assert_ne!(run.requests[0].withdrawal_nullifier, run.nullifier);
        assert_eq!(
            plan.public_inputs.withdrawal_nullifier,
            run.requests[0].withdrawal_nullifier
        );
        assert_eq!(run.phase, "reserved");
    }

    /// The generic withdrawal route proves both modes: a mutual close whose
    /// clearance carries the ownership proof, and an escape (kind 0) that
    /// concedes nothing and asks the server nothing, also from a state with
    /// a request set aside unsettled.
    #[tokio::test]
    async fn the_generic_withdrawal_route_proves_both_modes() {
        for archived in [false, true] {
            let run = prepare_with(
                Route::Generic(WithdrawalMode::Mutual),
                3,
                archived,
                Clearance::RequireProof,
                "unknown",
            )
            .await;
            assert!(run.result.is_ok(), "{archived}: {:?}", run.result);
            assert_eq!(run.requests.len(), 1, "{archived}");
            let run = prepare_with(
                Route::Generic(WithdrawalMode::Escape),
                3,
                archived,
                Clearance::RequireProof,
                "unknown",
            )
            .await;
            let plan = run.result.expect("escape plan");
            assert!(run.requests.is_empty(), "{archived}");
            assert_eq!(plan.public_inputs.withdrawal_nullifier, run.nullifier);
            assert_eq!(plan.public_inputs.conceded, 0);
            assert_eq!(plan.public_inputs.final_balance, 1_500_000);
            assert_ne!(plan.public_inputs.next_nullifier, Felt252::ZERO);
            assert_ne!(plan.public_inputs.next_nullifier, run.nullifier);
        }
    }

    /// The generic `/wallet/withdraw` used to build an escape, or send an
    /// escape-form ownership proof with a clearance request, at the
    /// nullifier of a transmitted request that was still pending rather
    /// than archived: its gate read only the archive. Whoever withheld that
    /// request could escape with the proof and challenge the escape with it,
    /// which burns the nullifier on a vault below revision 2. The route now
    /// refuses while a request is pending, as the OA route does, and sends
    /// nothing.
    #[tokio::test]
    async fn the_generic_withdrawal_route_refuses_while_a_request_is_pending() {
        for vault_revision in [0, 2] {
            for mode in [WithdrawalMode::Escape, WithdrawalMode::Mutual] {
                let run = prepare_with_setup(Setup {
                    route: Route::Generic(mode),
                    vault_revision,
                    pending_retry: true,
                    vault_root_moved: false,
                    ..Setup::new(Archive::Empty, Clearance::Grant, "unknown")
                })
                .await;
                let case = format!("revision {vault_revision}, {mode:?}");
                assert!(
                    matches!(run.result, Err(AuthError::PendingSettlement)),
                    "{case}: {:?}",
                    run.result
                );
                assert!(run.requests.is_empty(), "{case}");
                assert!(run.pending && run.archived.is_empty(), "{case}");
            }
        }
    }

    /// A damaged archive record, or a file another program left in the
    /// archive, does not fail the withdrawal with an opaque wallet error.
    #[tokio::test]
    async fn an_unreadable_archive_record_does_not_fail_the_withdrawal() {
        let run = prepare_with_setup(Setup::new(
            Archive::Unreadable,
            Clearance::RequireProof,
            "unknown",
        ))
        .await;
        assert!(run.result.is_ok(), "{:?}", run.result);
        assert_eq!(run.requests.len(), 1);
        assert_eq!(run.phase, "reserved");
    }

    /// The operator's release of a state stuck by an earlier release's
    /// discarded journal turns its nullifier into a clearance reservation.
    /// The companion's own retry at that state, refused as a replay and never
    /// admitted, used to stay pending with no live key, so withdrawal waited
    /// for its settlement forever. Preparation now settles it first: the
    /// server reports the retry unknown and its nullifier reserved for a
    /// clearance, so the retry is archived, whether or not the vault's root
    /// moved since it was proved (on a quiet vault it may never move), and
    /// the withdrawal proceeds with its ownership proof.
    #[tokio::test]
    async fn withdrawal_settles_a_stranded_retry_and_reaches_the_released_state() {
        for vault_root_moved in [true, false] {
            let case = format!("vault root moved: {vault_root_moved}");
            let run = prepare_with_setup(Setup {
                pending_retry: true,
                vault_root_moved,
                ..Setup::new(
                    Archive::Empty,
                    Clearance::RequireProof,
                    "clearance_reserved",
                )
            })
            .await;
            assert!(run.result.is_ok(), "{case}: {:?}", run.result);
            assert_eq!(run.requests.len(), 1, "{case}");
            assert!(!run.pending, "{case}");
            assert_eq!(run.phase, "reserved", "{case}");
            assert_eq!(run.archived, ["discarded_clearance_reserved"], "{case}");
        }
    }

    /// A note state settled by a request whose journal an earlier release
    /// deleted can never move: its receipt cannot be installed. E3 "lost ε":
    /// the withdrawal is an escape conceding the reported charge (at most the
    /// state's bound), at once, and no clearance is asked for. It used to end
    /// in receipt_journal_missing, waiting for the operator.
    #[tokio::test]
    async fn a_state_settled_by_a_request_without_a_journal_escapes_conceding_the_reported_charge()
    {
        for setup in [
            Setup {
                pending_retry: true,
                ..Setup::new(Archive::Empty, Clearance::RequireProof, "finalized")
            },
            Setup::new(Archive::Empty, Clearance::NullifierUsed, "finalized"),
        ] {
            let run = prepare_with_setup(setup).await;
            let case = format!("{setup:?}");
            match &run.result {
                Err(error @ AuthError::EscapeRequired(detail)) => {
                    assert_eq!(
                        error.status_code(),
                        axum::http::StatusCode::CONFLICT,
                        "{case}"
                    );
                    assert_eq!(detail["reason"], "lost_epsilon", "{case}");
                    assert_eq!(detail["conceded"], "0", "{case}");
                }
                other => panic!("{case}: {other:?}"),
            }
            assert!(run.requests.is_empty(), "{case}");
        }
    }

    /// sdk cross-component request 2: once a clearance request carrying an
    /// ownership proof has left, whatever answer follows (a gateway 429, a
    /// 5xx, an answer that is no clearance) may come from someone who kept
    /// the proof. The reservation records the proof before the request leaves
    /// and is then never released on any vault (C5), not even on the server's
    /// unsigned "unknown" reading, so no lease is made from that state. The
    /// refusal turns the exit into an escape conceding nothing (E2 step 5);
    /// closing again still works.
    #[tokio::test]
    async fn an_ownership_proof_that_left_keeps_the_reservation_and_offers_the_escape() {
        for clearance in [
            Clearance::GatewayThrottled,
            Clearance::ServerFailure,
            Clearance::Garbled,
        ] {
            for vault_revision in [0, 3] {
                let case = format!("{clearance:?}, vault_revision {vault_revision}");
                let run = prepare_with_setup(Setup {
                    vault_revision,
                    follow_up: true,
                    ..Setup::new(Archive::Empty, clearance, "unknown")
                })
                .await;
                match &run.result {
                    Err(AuthError::EscapeRequired(detail)) => {
                        assert_eq!(detail["reason"], "mutual_refused", "{case}");
                        assert_eq!(detail["conceded"], "0", "{case}");
                    }
                    other => panic!("{case}: {other:?}"),
                }
                assert!(!run.requests.is_empty(), "{case}");
                assert_eq!(run.ownership_proof_sent, Some(true), "{case}");
                let (released, lease, reads) = run.follow_up.unwrap();
                match &released {
                    Err(error @ AuthError::OwnershipProofSent) => {
                        assert_eq!(error.code(), "ownership_proof_sent", "{case}");
                        assert_eq!(
                            error.status_code(),
                            axum::http::StatusCode::CONFLICT,
                            "{case}"
                        );
                    }
                    other => panic!("{case}: {other:?}"),
                }
                assert_eq!(reads, 0, "{case}: refused before asking the server");
                assert_eq!(run.phase, "reserved", "{case}");
                assert!(
                    matches!(lease, Some(Err(AuthError::WithdrawalConflict))),
                    "{case}: {lease:?}"
                );
            }
        }

        // Closing again completes the close, resending the same ownership
        // proof (at most one is live).
        let run = prepare_with_setup(Setup {
            again: true,
            ..Setup::new(Archive::Empty, Clearance::ThrottledOnce, "unknown")
        })
        .await;
        assert!(run.result.is_err(), "{:?}", run.result);
        assert!(matches!(run.again, Some(Ok(_))), "{:?}", run.again);
        assert_eq!(run.requests.len(), 2);
        assert_eq!(
            run.requests[0].ownership_proof.proof,
            run.requests[1].ownership_proof.proof
        );
        assert_eq!(run.ownership_proof_sent, Some(true));
        assert_eq!(run.phase, "reserved");

        // A record damaged after the proof left changes nothing: the retry
        // sends the proof again and closes.
        let run = prepare_with_setup(Setup {
            again: true,
            archive_before_again: true,
            ..Setup::new(Archive::Empty, Clearance::ThrottledOnce, "unknown")
        })
        .await;
        assert!(matches!(run.again, Some(Ok(_))), "{:?}", run.again);
    }

    /// The generic `/wallet/withdraw` mutual close has no reservation. It
    /// holds the exit lock and marks the state (C5) before the request
    /// carrying its ownership proof leaves; whatever the answer, no lease or
    /// proxied request proof is made from that state afterwards (C3 while
    /// the lock is held), while closing again still works.
    #[tokio::test]
    async fn the_generic_mutual_close_keeps_a_state_whose_ownership_proof_left_withdrawal_only() {
        let run = prepare_with_setup(Setup {
            route: Route::Generic(WithdrawalMode::Mutual),
            follow_up: true,
            again: true,
            ..Setup::new(Archive::Empty, Clearance::ThrottledOnce, "unknown")
        })
        .await;
        assert!(run.result.is_err(), "{:?}", run.result);
        assert!(!run.requests.is_empty());
        let (_, lease, _) = run.follow_up.unwrap();
        assert!(
            matches!(lease, Some(Err(AuthError::ExitLocked))),
            "{lease:?}"
        );
        // A proxied request (`RequestMode::Proxy`) from that state is refused
        // as well, before it makes a request proof or journal.
        assert!(
            matches!(run.proxied, Some(Err(AuthError::ExitLocked))),
            "{:?}",
            run.proxied
        );
        assert!(matches!(run.again, Some(Ok(_))), "{:?}", run.again);
        assert!(!run.pending, "no request journal was made");
    }

    #[tokio::test]
    async fn release_requires_an_unplanned_reservation_and_an_unknown_server_nullifier() {
        use axum::{extract::State, routing::get, Json, Router};
        let (_directory, mut config, note) = fixture();
        let reply = Arc::new(Mutex::new(
            serde_json::json!({"status":"ok","nullifier_status":"clearance_reserved"}),
        ));
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.protocol_server_url = format!("http://{}", listener.local_addr().unwrap());
        let record = oa_withdrawal::reserve(&config, &note, [1; 20]).unwrap();
        let counted = calls.clone();
        let router = Router::new()
            .route(
                &format!("/v2/nullifiers/{}", record.nullifier),
                get(move |State(reply): State<Arc<Mutex<Value>>>| {
                    counted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    async move { Json(reply.lock().unwrap().clone()) }
                }),
            )
            .with_state(reply.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let calls_made = || calls.load(std::sync::atomic::Ordering::SeqCst);

        // The caller must name the exact reservation it observed.
        for (note_id, nullifier) in [
            (note.note_id + 1, record.nullifier),
            (note.note_id, Felt252::ONE),
        ] {
            assert!(matches!(
                service.oa_release_withdrawal(note_id, nullifier).await,
                Err(AuthError::WithdrawalConflict)
            ));
        }
        // A pending request or a changed note is never released.
        let journal_path = config.state_dir.join("pending_journal.json");
        zkapi_client::journal::PendingRequestJournal::write(
            &journal_path,
            &zkapi_client::journal::PendingRequestJournal {
                exists: true,
                client_request_id: "pending".into(),
                nullifier: record.nullifier,
                payload_hash: Felt252::ONE,
                user_rerandomization: Felt252::ONE,
                created_at_ms: 1,
                prepared_request: None,
            },
        )
        .unwrap();
        assert!(matches!(
            service
                .oa_release_withdrawal(note.note_id, record.nullifier)
                .await,
            Err(AuthError::PendingSettlement)
        ));
        std::fs::remove_file(&journal_path).unwrap();
        let mut changed = note.clone();
        changed.current_balance -= 1;
        changed
            .save(&config.state_dir.join("note_state.json"))
            .unwrap();
        assert!(matches!(
            service
                .oa_release_withdrawal(note.note_id, record.nullifier)
                .await,
            Err(AuthError::WithdrawalConflict)
        ));
        note.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        assert_eq!(
            calls_made(),
            0,
            "local refusals happen before any server request"
        );

        // Any server answer other than unknown may mean a clearance exists.
        for status in [
            serde_json::json!({"status":"ok","nullifier_status":"clearance_reserved"}),
            serde_json::json!({"status":"ok","nullifier_status":"reserved"}),
            serde_json::json!({"status":"ok","nullifier_status":"finalized"}),
            serde_json::json!({"status":"not_found","nullifier_status":"reserved"}),
        ] {
            *reply.lock().unwrap() = status;
            assert!(matches!(
                service
                    .oa_release_withdrawal(note.note_id, record.nullifier)
                    .await,
                Err(AuthError::WithdrawalPending(_))
            ));
            assert_eq!(
                service.oa_withdrawal_status().await.unwrap()["phase"],
                "reserved"
            );
        }
        *reply.lock().unwrap() =
            serde_json::json!({"status":"not_found","nullifier_status":"unknown"});
        assert_eq!(
            service
                .oa_release_withdrawal(note.note_id, record.nullifier)
                .await
                .unwrap()["phase"],
            "none"
        );
        assert_eq!(
            service.oa_withdrawal_status().await.unwrap()["phase"],
            "none"
        );
        assert!(config.state_dir.join("note_state.json").exists());
        assert!(
            service.reset_wallet().await.is_ok(),
            "the note is spendable or replaceable again"
        );

        // A reservation that already holds a mutual plan is never released.
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(
                note.secret_s,
                note.note_id,
                note.deposit_amount,
                note.expiry_ts,
            )
            .unwrap();
        let state = wallet.state().unwrap().clone();
        let mut planned = oa_withdrawal::reserve(&config, &state, [1; 20]).unwrap();
        planned.plan = Some(oa_withdrawal::tests::plan(&planned));
        oa_withdrawal::save(&config, &planned).unwrap();
        let before = calls_made();
        assert!(matches!(
            service
                .oa_release_withdrawal(state.note_id, planned.nullifier)
                .await,
            Err(AuthError::WithdrawalConflict)
        ));
        assert_eq!(calls_made(), before);
        server.abort();
    }

    /// A reservation saved before `ownership_proof_sent` existed, by
    /// zkapi-clientd 0.1.6 (whose clearance requests carried no ownership
    /// proof) or a development build after it (which sent one whenever it
    /// could build it). Release finds the note's leaf in a verified snapshot: a
    /// wrongly bound note, whose leaf is not in the tree, never had a proof
    /// built and is released on the server's unknown reading; a note whose
    /// leaf is there stays reserved before any server read.
    #[tokio::test]
    async fn a_reservation_saved_before_the_marker_releases_only_without_a_buildable_proof() {
        use axum::{extract::State, routing::get, Json, Router};
        let (_directory, mut config, note) = fixture();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        config.protocol_server_url = url.clone();
        config.indexer_url = url;
        let record = oa_withdrawal::reserve(&config, &note, [1; 20]).unwrap();
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("ownership_proof_sent");
        let legacy = serde_json::to_vec(&legacy).unwrap();
        let reservation = config.state_dir.join("oa-withdrawal.json");
        let note_leaf = core_v2::note_leaf(
            note.note_id,
            &core_v2::registration_commitment(&note.secret_s),
            note.deposit_amount,
            note.expiry_ts,
        );
        // What the indexer answers for the whole tree, and the reads made.
        type Seen = Arc<Mutex<(Value, usize, usize)>>;
        let seen: Seen = Arc::new(Mutex::new((Value::Null, 0, 0)));
        let router = Router::new()
            .route(
                "/v1/tree/snapshot",
                get(|State(seen): State<Seen>| async move {
                    let mut seen = seen.lock().unwrap();
                    seen.1 += 1;
                    Json(seen.0.clone())
                }),
            )
            .route(
                &format!("/v2/nullifiers/{}", record.nullifier),
                get(|State(seen): State<Seen>| async move {
                    seen.lock().unwrap().2 += 1;
                    Json(serde_json::json!({"status":"not_found","nullifier_status":"unknown"}))
                }),
            )
            .with_state(seen.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let snapshot = |leaf| {
            let mut tree = zkapi_core::merkle::MerkleTree::new();
            tree.set_leaf(note.note_id, leaf);
            let leaves: Vec<_> = (0..=note.note_id).map(|id| tree.get_leaf(id)).collect();
            serde_json::json!({"root": tree.root(), "next_note_id": leaves.len(), "leaves": leaves})
        };
        let mut other_leaf = note_leaf;
        other_leaf.0[31] ^= 1;
        for (case, answer, released) in [
            ("leaf in the tree", snapshot(note_leaf), false),
            ("missing snapshot", serde_json::json!({}), false),
            ("another note's leaf", snapshot(other_leaf), true),
        ] {
            std::fs::write(&reservation, &legacy).unwrap();
            assert_eq!(
                oa_withdrawal::load(&config)
                    .unwrap()
                    .unwrap()
                    .ownership_proof_sent,
                None
            );
            *seen.lock().unwrap() = (answer, 0, 0);
            let result = service
                .oa_release_withdrawal(note.note_id, record.nullifier)
                .await;
            let (_, leaf_reads, server_reads) = seen.lock().unwrap().clone();
            assert_eq!(leaf_reads, 1, "{case}");
            if released {
                assert_eq!(result.unwrap()["phase"], "none", "{case}");
                assert_eq!(server_reads, 1, "{case}");
                assert!(oa_withdrawal::load(&config).unwrap().is_none(), "{case}");
            } else {
                match result {
                    Err(AuthError::OwnershipProofSent) => assert_eq!(case, "leaf in the tree"),
                    Err(AuthError::Indexer(_)) => assert_eq!(case, "missing snapshot"),
                    other => panic!("{case}: {other:?}"),
                }
                assert_eq!(server_reads, 0, "{case}: refused before asking the server");
                assert_eq!(
                    service.oa_withdrawal_status().await.unwrap()["phase"],
                    "reserved",
                    "{case}"
                );
            }
        }
        // A reservation that records the field is never judged by the leaf.
        for sent in [false, true] {
            let mut marked = record.clone();
            marked.ownership_proof_sent = Some(sent);
            oa_withdrawal::save(&config, &marked).unwrap();
            *seen.lock().unwrap() = (Value::Null, 0, 0);
            let result = service
                .oa_release_withdrawal(note.note_id, record.nullifier)
                .await;
            assert_eq!(result.is_ok(), !sent, "{sent}: {result:?}");
            assert_eq!(seen.lock().unwrap().1, 0, "{sent}");
        }
        server.abort();
    }

    /// contracts cross-component request 3, through the service's confirm
    /// route: the credited escape's evidence reaches the saved reservation,
    /// so `/oa/v1/withdraw/confirm` and `/oa/v1/withdraw/status` report
    /// `escape_payout_credited`, and a paid escape reports nothing of it.
    #[tokio::test]
    async fn the_confirm_route_reports_a_credited_escape_payout() {
        use axum::{routing::post, Json, Router};
        for credited in [true, false] {
            let (_directory, mut config, note) = fixture();
            let mut record = oa_withdrawal::reserve(&config, &note, [1; 20]).unwrap();
            record.plan = Some(oa_withdrawal::tests::plan(&record));
            oa_withdrawal::save(&config, &record).unwrap();
            let hash = format!("0x{}", "04".repeat(32));
            let mut receipt = oa_withdrawal::tests::escape_finalized(&record, &hash);
            if credited {
                receipt["logs"] = serde_json::json!([
                    oa_withdrawal::tests::escape_payout_deferred(&record),
                    receipt["logs"][0]
                ]);
            }
            let chain_id = config.chain_id;
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.demo_rpc_url = Some(format!("http://{}/rpc", listener.local_addr().unwrap()));
            let router = Router::new().route(
                "/rpc",
                post(move |Json(body): Json<Value>| {
                    let receipt = receipt.clone();
                    async move {
                        let result = match body["method"].as_str().unwrap() {
                            "eth_chainId" => serde_json::json!(format!("0x{chain_id:x}")),
                            "eth_getTransactionReceipt" => receipt,
                            "eth_getBlockByNumber" if body["params"][0] == "finalized" => {
                                serde_json::json!({"number": "0x64"})
                            }
                            "eth_getBlockByNumber" => serde_json::json!({
                                "number": "0x64",
                                "hash": format!("0x{}", "03".repeat(32))
                            }),
                            other => panic!("unexpected RPC {other}"),
                        };
                        Json(serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": result}))
                    }
                }),
            );
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let service = AuthService::new(config.clone()).unwrap();
            let confirmed = service.oa_confirm_withdrawal(hash.clone()).await.unwrap();
            assert_eq!(confirmed["phase"], "complete", "{credited}");
            assert!(!config.state_dir.join("note_state.json").exists());
            let status = service.oa_withdrawal_status().await.unwrap();
            for reported in [&confirmed, &status] {
                assert_eq!(
                    reported.get("escape_payout_credited") == Some(&serde_json::json!(true)),
                    credited,
                    "{credited}: {reported}"
                );
            }
            // A lost reply is answered again from the saved reservation.
            assert_eq!(
                service.oa_confirm_withdrawal(hash).await.unwrap(),
                confirmed
            );
            server.abort();
        }
    }
}

#[cfg(test)]
mod oa_stale_root_tests {
    use super::*;
    use axum::{
        extract::State,
        http::StatusCode,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use zkapi_client::journal::PendingRequestJournal;

    type Events = Arc<Mutex<Vec<&'static str>>>;

    /// What the pinned vault answers for `currentRoot()`.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Chain {
        RootMoved,
        StillHasRoot,
        Unreadable,
    }

    #[tokio::test]
    async fn stale_root_sets_a_transmitted_lease_aside_only_after_the_vault_root_moved_and_an_unknown_reading(
    ) {
        let cases = [
            (Chain::RootMoved, "reserved"),
            (Chain::RootMoved, "finalized"),
            (Chain::RootMoved, "clearance_reserved"),
            (Chain::RootMoved, "unavailable"),
            (Chain::RootMoved, "unknown"),
            (Chain::StillHasRoot, "unknown"),
            (Chain::Unreadable, "unknown"),
        ];
        for (chain, answer) in cases {
            let directory = tempfile::tempdir().unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let config = AuthConfig {
                state_dir: directory.path().to_path_buf(),
                protocol_version: 2,
                chain_id: 1,
                protocol_server_url: url.clone(),
                indexer_url: url.clone(),
                demo_rpc_url: Some(format!("{url}/rpc")),
                request_mode: RequestMode::DirectOpenrouter,
                ..Default::default()
            };
            let mut wallet = load_wallet(&config).unwrap();
            wallet
                .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
                .unwrap();
            let note = wallet.state().unwrap();
            let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
            let payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
            let request = ApiRequestV2 {
                client_request_id: "transmitted".into(),
                payload_hash: compute_payload_hash(payload.as_bytes()),
                payload,
                public_inputs: zkapi_types::RequestPublicInputsV2 {
                    protocol_version: 2,
                    chain_id: 1,
                    contract_address: config.contract_address,
                    active_root: Felt252::ONE,
                    state_signing_key_x: config.state_signing_key.x,
                    state_signing_key_y: config.state_signing_key.y,
                    request_time: 1,
                    solvency_bound: 1_000_000,
                    request_nullifier: nullifier,
                    authorization_tag: Felt252::ONE,
                    anonymous_commitment_x: Felt252::ONE,
                    anonymous_commitment_y: Felt252::ONE,
                },
                proof: Groth16ProofWire {
                    backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                    proof: "transmitted-proof".into(),
                },
            };
            let journal_path = config.state_dir.join("pending_journal.json");
            let saved = PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::from_u64(77),
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            };
            PendingRequestJournal::write(&journal_path, &saved).unwrap();
            let journal = std::fs::read(&journal_path).unwrap();
            let events = Events::default();
            let transmitted = serde_json::to_value(&request).unwrap();
            let router = Router::new()
                .route("/v2/openrouter/leases", post(move |State(events): State<Events>, Json(body): Json<Value>| async move {
                    events.lock().unwrap().push("lease");
                    assert_eq!(body, transmitted);
                    (StatusCode::CONFLICT, Json(json!({"status":"error","client_request_id":"transmitted",
                        "error_code":"stale_root","error_message":"stale root","retriable":true,"latest_root":"0x5"})))
                }))
                .route("/rpc", post(move |State(events): State<Events>, Json(body): Json<Value>| async move {
                    events.lock().unwrap().push("rpc");
                    assert_eq!(body["method"], "eth_call");
                    assert_eq!(body["params"][0]["data"], VAULT_CURRENT_ROOT_SELECTOR);
                    let root = match chain {
                        Chain::Unreadable => return (StatusCode::BAD_GATEWAY, Json(json!({}))),
                        Chain::StillHasRoot => format!("0x{:064x}", 1),
                        Chain::RootMoved => format!("0x{:064x}", 5),
                    };
                    (StatusCode::OK, Json(json!({"jsonrpc":"2.0","id":1,"result":root})))
                }))
                .route(&format!("/v2/nullifiers/{nullifier}"), get(move |State(events): State<Events>| async move {
                    events.lock().unwrap().push("nullifier");
                    match answer {
                        "unavailable" => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))),
                        "unknown" => (StatusCode::OK, Json(json!({"status":"not_found","nullifier_status":"unknown"}))),
                        status => (StatusCode::OK, Json(json!({"status":"ok","nullifier_status":status}))),
                    }
                }))
                .route("/v1/tree/snapshot", get(|State(events): State<Events>| async move {
                    events.lock().unwrap().push("indexer");
                    StatusCode::SERVICE_UNAVAILABLE
                }))
                .with_state(events.clone());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let service = AuthService::new(config.clone()).unwrap();
            let result = service
                .issue_direct_openrouter_lease("chat".into(), None)
                .await;
            let events = events.lock().unwrap().clone();
            let archived = zkapi_client::journal::archived_requests(
                &config.state_dir.join("request_archive"),
                &nullifier,
            )
            .unwrap();
            let case = format!("{chain:?}/{answer}");
            match (chain, answer) {
                (Chain::RootMoved, "unknown") => {
                    // Corroborated by the chain and the server: the journal is
                    // set aside into the archive, whole, and the next attempt
                    // proves afresh at the indexer's current root.
                    assert!(matches!(result, Err(AuthError::Indexer(_))), "{case}");
                    assert!(!journal_path.exists(), "{case}");
                    assert_eq!(events, ["lease", "rpc", "nullifier", "indexer"], "{case}");
                    assert_eq!(archived.len(), 1, "{case}");
                    assert_eq!(archived[0].disposition, "discarded_stale_root");
                    assert_eq!(
                        serde_json::to_value(&archived[0].journal).unwrap(),
                        serde_json::to_value(&saved).unwrap(),
                        "the archive keeps the rerandomization and the proved request"
                    );
                }
                (Chain::StillHasRoot, _) => {
                    // The vault contradicts the reply: the byte-identical
                    // request is resent, never discarded, and the server's
                    // nullifier record is not consulted.
                    assert!(matches!(result, Err(AuthError::LeasePending(_))), "{case}");
                    assert_eq!(std::fs::read(&journal_path).unwrap(), journal, "{case}");
                    let mut expected = Vec::new();
                    for _ in 0..=STALE_ROOT_RESEND_DELAYS.len() {
                        expected.extend(["lease", "rpc"]);
                    }
                    assert_eq!(events, expected, "{case}");
                    assert!(archived.is_empty(), "{case}");
                }
                (Chain::Unreadable, _) => {
                    assert!(matches!(result, Err(AuthError::LeasePending(_))), "{case}");
                    assert_eq!(std::fs::read(&journal_path).unwrap(), journal, "{case}");
                    assert_eq!(events, ["lease", "rpc"], "{case}");
                    assert!(archived.is_empty(), "{case}");
                }
                _ => {
                    // An unsigned stale_root never sets aside a possibly
                    // admitted proof. A nullifier held by a clearance is
                    // reported as such: no chat can settle that state.
                    assert!(result.is_err(), "{case}");
                    match answer {
                        "unavailable" => {}
                        "clearance_reserved" => assert!(
                            matches!(result, Err(AuthError::ClearanceReservedState)),
                            "{case}: {:?}",
                            result.as_ref().err()
                        ),
                        _ => assert!(
                            matches!(result, Err(AuthError::LeasePending(_))),
                            "{case}: {:?}",
                            result.as_ref().err()
                        ),
                    }
                    assert_eq!(std::fs::read(&journal_path).unwrap(), journal, "{case}");
                    assert_eq!(events, ["lease", "rpc", "nullifier"], "{case}");
                    assert!(archived.is_empty(), "{case}");
                }
            }
            server.abort();
        }
    }
    /// The vault-root witness holds end to end. zkapi-clientd answers the
    /// stale_root path's lease_pending with /wallet/settle, which must not
    /// set the same journal aside on the same unsigned 'unknown' readings
    /// while the vault still has the request's root, or while that root
    /// cannot be read. Once the root moved, settlement archives it as
    /// before. A nullifier reserved for a clearance is different: the server
    /// refuses every request at it, before any root check, so the root is
    /// not asked and settlement archives the request whatever it is (a quiet
    /// vault's root may never move).
    #[tokio::test]
    async fn withdrawal_settlement_applies_the_vault_root_witness_too() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            protocol_server_url: url.clone(),
            indexer_url: url.clone(),
            demo_rpc_url: Some(format!("{url}/rpc")),
            request_mode: RequestMode::DirectOpenrouter,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
        let request = ApiRequestV2 {
            client_request_id: "transmitted".into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: config.contract_address,
                active_root: Felt252::ONE,
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1,
                solvency_bound: 1_000_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: Felt252::ONE,
                anonymous_commitment_y: Felt252::ONE,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "transmitted-proof".into(),
            },
        };
        let journal_path = config.state_dir.join("pending_journal.json");
        PendingRequestJournal::write(
            &journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::from_u64(77),
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            },
        )
        .unwrap();
        let journal = std::fs::read(&journal_path).unwrap();
        type Answers = Arc<Mutex<(Chain, &'static str, Vec<&'static str>)>>;
        let answers: Answers = Arc::new(Mutex::new((Chain::StillHasRoot, "unknown", Vec::new())));
        let router = Router::new()
            .route(
                "/v2/openrouter/leases",
                post(|State(answers): State<Answers>| async move {
                    answers.lock().unwrap().2.push("lease");
                    (
                        StatusCode::CONFLICT,
                        Json(json!({"status":"error","client_request_id":"transmitted",
                    "error_code":"stale_root","error_message":"stale root","retriable":true})),
                    )
                }),
            )
            .route(
                "/v2/openrouter/leases/transmitted",
                get(|State(answers): State<Answers>| async move {
                    answers.lock().unwrap().2.push("lease_status");
                    StatusCode::NOT_FOUND
                }),
            )
            .route(
                "/v2/requests/transmitted",
                get(|State(answers): State<Answers>| async move {
                    answers.lock().unwrap().2.push("request");
                    Json(json!({"status":"not_found","nullifier_status":"unknown"}))
                }),
            )
            .route(
                "/rpc",
                post(|State(answers): State<Answers>| async move {
                    let chain = {
                        let mut answers = answers.lock().unwrap();
                        answers.2.push("rpc");
                        answers.0
                    };
                    let root = match chain {
                        Chain::Unreadable => return (StatusCode::BAD_GATEWAY, Json(json!({}))),
                        Chain::StillHasRoot => format!("0x{:064x}", 1),
                        Chain::RootMoved => format!("0x{:064x}", 5),
                    };
                    (
                        StatusCode::OK,
                        Json(json!({"jsonrpc":"2.0","id":1,"result":root})),
                    )
                }),
            )
            .route(
                &format!("/v2/nullifiers/{nullifier}"),
                get(|State(answers): State<Answers>| async move {
                    let answer = {
                        let mut answers = answers.lock().unwrap();
                        answers.2.push("nullifier");
                        answers.1
                    };
                    Json(match answer {
                        "unknown" => json!({"status":"not_found","nullifier_status":"unknown"}),
                        status => json!({"status":"ok","nullifier_status":status}),
                    })
                }),
            )
            .with_state(answers.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let archive = config.state_dir.join("request_archive");

        // The stale_root path keeps the journal while the vault has its root.
        let issued = service
            .issue_direct_openrouter_lease("chat".into(), None)
            .await;
        assert!(
            matches!(issued, Err(AuthError::LeasePending(_))),
            "{:?}",
            issued.as_ref().err()
        );
        for (chain, answer) in [
            (Chain::StillHasRoot, "unknown"),
            (Chain::Unreadable, "unknown"),
        ] {
            {
                let mut answers = answers.lock().unwrap();
                *answers = (chain, answer, Vec::new());
            }
            let settled = service.settle_for_withdrawal().await;
            let case = format!("{chain:?}/{answer}");
            assert!(
                matches!(settled, Err(AuthError::LeasePending(_))),
                "{case}: {settled:?}"
            );
            assert_eq!(settled.unwrap_err().code(), "lease_pending", "{case}");
            assert_eq!(std::fs::read(&journal_path).unwrap(), journal, "{case}");
            assert!(
                zkapi_client::journal::archived_requests(&archive, &nullifier)
                    .unwrap()
                    .is_empty(),
                "{case}"
            );
            assert_eq!(answers.lock().unwrap().2.last(), Some(&"rpc"), "{case}");
        }

        // A clearance holds the nullifier while the vault still has the
        // request's root: the request is set aside, whole, without asking
        // the vault.
        *answers.lock().unwrap() = (Chain::StillHasRoot, "clearance_reserved", Vec::new());
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request && !journal_path.exists());
        assert_eq!(
            answers.lock().unwrap().2,
            ["lease_status", "request", "nullifier"]
        );
        let archived = zkapi_client::journal::archived_requests(&archive, &nullifier).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].disposition, "discarded_clearance_reserved");
        assert_eq!(
            serde_json::to_value(&archived[0].journal).unwrap(),
            serde_json::from_slice::<Value>(&journal).unwrap(),
            "the archive keeps the rerandomization and the proved request"
        );

        // Once the vault's root moved, the unknown request is set aside, into
        // the archive.
        std::fs::write(&journal_path, &journal).unwrap();
        *answers.lock().unwrap() = (Chain::RootMoved, "unknown", Vec::new());
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request && !journal_path.exists());
        let archived = zkapi_client::journal::archived_requests(&archive, &nullifier).unwrap();
        assert_eq!(archived.len(), 2);
        assert_eq!(archived[1].disposition, "discarded_unknown_to_server");
        server.abort();
    }

    /// After the operator released a stuck state, its nullifier is reserved
    /// for a clearance and the server refuses the companion's pending retry
    /// as a replay, forever. A chat used to fail with an opaque wallet_error,
    /// and /wallet/settle kept the retry while the vault still had its root,
    /// claiming the next request would resend it. Chats now report
    /// clearance_reserved_state and keep resending the same bytes (never a
    /// new proof from that state); settlement sets the retry aside without
    /// asking the vault. Once it is set aside no journal is pending, and
    /// chats used to prove a fresh request at the same nullifier: they now
    /// ask the server again and prove nothing while it still reports the
    /// reservation, or cannot be asked.
    #[tokio::test]
    async fn a_released_state_stops_chats_with_an_actionable_code_and_settles_its_retry() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            protocol_server_url: url.clone(),
            indexer_url: url.clone(),
            demo_rpc_url: Some(format!("{url}/rpc")),
            request_mode: RequestMode::DirectOpenrouter,
            vault_revision: 0,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
        let request = ApiRequestV2 {
            client_request_id: "transmitted".into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: config.contract_address,
                active_root: Felt252::ONE,
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1,
                solvency_bound: 1_000_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: Felt252::ONE,
                anonymous_commitment_y: Felt252::ONE,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "transmitted-proof".into(),
            },
        };
        let journal_path = config.state_dir.join("pending_journal.json");
        PendingRequestJournal::write(
            &journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::from_u64(77),
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            },
        )
        .unwrap();
        let journal = std::fs::read(&journal_path).unwrap();
        let events = Events::default();
        let transmitted = serde_json::to_value(&request).unwrap();
        // What the server's record of the state's nullifier answers.
        let reading: Arc<Mutex<&'static str>> = Arc::new(Mutex::new("clearance_reserved"));
        let router = Router::new()
            .route(
                "/v2/openrouter/leases",
                post(
                    move |State(events): State<Events>, Json(body): Json<Value>| async move {
                        events.lock().unwrap().push("lease");
                        // Only the saved request is ever sent from this state.
                        assert_eq!(body, transmitted);
                        (
                            StatusCode::CONFLICT,
                            Json(json!({"status":"error","client_request_id":"transmitted",
                    "error_code":"replay","error_message":"replay","retriable":false})),
                        )
                    },
                ),
            )
            .route(
                "/v2/openrouter/leases/transmitted",
                get(|State(events): State<Events>| async move {
                    events.lock().unwrap().push("lease_status");
                    StatusCode::NOT_FOUND
                }),
            )
            .route(
                "/v2/requests/transmitted",
                get(|State(events): State<Events>| async move {
                    events.lock().unwrap().push("request");
                    Json(json!({"status":"not_found","nullifier_status":"unknown"}))
                }),
            )
            .route(
                "/rpc",
                post(|State(events): State<Events>| async move {
                    // The vault still has the retry's root.
                    events.lock().unwrap().push("rpc");
                    Json(json!({"jsonrpc":"2.0","id":1,"result":format!("0x{:064x}", 1)}))
                }),
            )
            .route(
                &format!("/v2/nullifiers/{nullifier}"),
                get({
                    let reading = reading.clone();
                    move |State(events): State<Events>| async move {
                        events.lock().unwrap().push("nullifier");
                        match *reading.lock().unwrap() {
                            "unreadable" => (StatusCode::BAD_GATEWAY, Json(json!({}))),
                            "unknown" => (
                                StatusCode::OK,
                                Json(json!({"status":"not_found","nullifier_status":"unknown"})),
                            ),
                            status => (
                                StatusCode::OK,
                                Json(json!({"status":"ok","nullifier_status":status})),
                            ),
                        }
                    }
                }),
            )
            .route(
                "/v1/tree/snapshot",
                get(|State(events): State<Events>| async move {
                    // Every new request proof starts by reading a snapshot.
                    events.lock().unwrap().push("snapshot");
                    StatusCode::SERVICE_UNAVAILABLE
                }),
            )
            .with_state(events.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let archive = config.state_dir.join("request_archive");

        for chat in 0..2 {
            let issued = service
                .issue_direct_openrouter_lease("chat".into(), None)
                .await;
            let error = issued.err().expect("no chat can settle a released state");
            assert!(
                matches!(error, AuthError::ClearanceReservedState),
                "chat {chat}: {error:?}"
            );
            assert_eq!(error.code(), "clearance_reserved_state");
            assert_eq!(error.status_code(), StatusCode::CONFLICT);
            assert_eq!(
                std::fs::read(&journal_path).unwrap(),
                journal,
                "chat {chat}"
            );
            assert!(
                zkapi_client::journal::archived_requests(&archive, &nullifier)
                    .unwrap()
                    .is_empty(),
                "chat {chat}"
            );
        }
        assert_eq!(
            events
                .lock()
                .unwrap()
                .iter()
                .filter(|event| **event == "lease")
                .count(),
            2
        );

        events.lock().unwrap().clear();
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request && !journal_path.exists());
        assert!(!events.lock().unwrap().contains(&"rpc"));
        let archived = zkapi_client::journal::archived_requests(&archive, &nullifier).unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].disposition, "discarded_clearance_reserved");
        assert_eq!(
            serde_json::to_value(&archived[0].journal).unwrap(),
            serde_json::from_slice::<Value>(&journal).unwrap()
        );

        // Later chats prove nothing new from this state: not while the
        // server still reports the reservation, and not while its record
        // cannot be read.
        for answer in ["clearance_reserved", "unreadable", "clearance_reserved"] {
            *reading.lock().unwrap() = answer;
            events.lock().unwrap().clear();
            let issued = service
                .issue_direct_openrouter_lease("chat".into(), None)
                .await;
            let error = issued
                .err()
                .expect("no request is proved from a released state");
            if answer == "unreadable" {
                assert!(matches!(error, AuthError::Wallet(_)), "{error:?}");
            } else {
                assert!(
                    matches!(error, AuthError::ClearanceReservedState),
                    "{error:?}"
                );
            }
            assert_eq!(*events.lock().unwrap(), ["nullifier"], "{answer}");
            assert!(!journal_path.exists(), "{answer}");
            assert_eq!(
                zkapi_client::journal::archived_requests(&archive, &nullifier)
                    .unwrap()
                    .len(),
                1
            );
        }
        // A server that no longer reports the reservation lets a chat prove
        // a request again, as at any state whose retry was set aside.
        *reading.lock().unwrap() = "unknown";
        events.lock().unwrap().clear();
        let issued = service
            .issue_direct_openrouter_lease("chat".into(), None)
            .await;
        assert!(
            matches!(issued, Err(AuthError::Indexer(_))),
            "{:?}",
            issued.err()
        );
        assert_eq!(*events.lock().unwrap(), ["nullifier", "snapshot"]);
        server.abort();
    }
}

#[cfg(test)]
mod oa_request_archive_tests {
    use super::*;
    use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
    use serde_json::json;
    use zkapi_client::journal::{archived_requests, PendingRequestJournal};
    use zkapi_proof::compact::{rerandomize, server_update, CompactSigner};
    use zkapi_types::wire::CurvePointWire;

    fn lease_request(id: &str, nullifier: Felt252, bound: u128) -> ApiRequestV2 {
        let payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
        ApiRequestV2 {
            client_request_id: id.into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::ZERO,
                active_root: Felt252::ONE,
                state_signing_key_x: Felt252::ZERO,
                state_signing_key_y: Felt252::ONE,
                request_time: 1,
                solvency_bound: bound,
                request_nullifier: nullifier,
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: Felt252::ONE,
                anonymous_commitment_y: Felt252::ONE,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: format!("{id}-proof"),
            },
        }
    }

    /// How the wallet is asked to resolve its state.
    #[derive(Clone, Copy, PartialEq, Debug)]
    enum Driver {
        Recover,
        SettleForWithdrawal,
        LeaseReplay,
    }

    /// A request set aside into the archive after an unsigned rejection was in
    /// fact admitted; its retry at the same state is refused as a replay. When
    /// the server finalizes the original, every recovery path installs its
    /// verified receipt from the archive, charged up to the archived request's
    /// own proved bound, and archives the retry as superseded. A receipt that
    /// does not verify installs nothing.
    #[tokio::test]
    async fn every_recovery_path_installs_a_later_receipt_for_an_archived_request() {
        for driver in [
            Driver::Recover,
            Driver::SettleForWithdrawal,
            Driver::LeaseReplay,
        ] {
            archived_receipt_installs(driver).await;
        }
    }

    /// A wallet reset (used only to replace an unspent note) moves a request
    /// journal into the archive rather than deleting it.
    #[tokio::test]
    async fn a_wallet_reset_archives_its_request_journal() {
        let directory = tempfile::tempdir().unwrap();
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap().clone();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let journal_path = config.state_dir.join("pending_journal.json");
        let request = lease_request("sent", nullifier, 1_000_000);
        let saved = PendingRequestJournal {
            exists: true,
            client_request_id: "sent".into(),
            nullifier,
            payload_hash: request.payload_hash,
            user_rerandomization: Felt252::from_u64(9),
            created_at_ms: 1,
            prepared_request: Some(request),
        };
        PendingRequestJournal::write(&journal_path, &saved).unwrap();
        let service = AuthService::new(config.clone()).unwrap();
        let status = service.reset_wallet().await.unwrap();
        assert!(!status.has_note && !status.pending_request);
        assert!(!journal_path.exists());
        let records =
            archived_requests(&config.state_dir.join("request_archive"), &nullifier).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].disposition, "wallet_reset");
        assert_eq!(
            serde_json::to_value(&records[0].journal).unwrap(),
            serde_json::to_value(&saved).unwrap()
        );
    }

    /// Withdrawal settlement sets aside a lease journal the server reports
    /// unknown (request and nullifier) into the archive, not the bin: the
    /// readings are unsigned, and if the request was in fact admitted its
    /// receipt still installs once the server finalizes it.
    #[tokio::test]
    async fn an_orphaned_lease_journal_is_archived_and_its_later_receipt_installs() {
        let directory = tempfile::tempdir().unwrap();
        let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            state_signing_key: signer.public_key(),
            protocol_server_url: url.clone(),
            demo_rpc_url: Some(format!("{url}/rpc")),
            request_mode: RequestMode::DirectOpenrouter,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap().clone();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let journal_path = config.state_dir.join("pending_journal.json");
        let withheld = lease_request("withheld", nullifier, 1_000_000);
        let saved = PendingRequestJournal {
            exists: true,
            client_request_id: "withheld".into(),
            nullifier,
            payload_hash: withheld.payload_hash,
            user_rerandomization: Felt252::from_u64(5),
            created_at_ms: 1,
            prepared_request: Some(withheld),
        };
        PendingRequestJournal::write(&journal_path, &saved).unwrap();
        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::from_u64(5),
        )
        .unwrap();
        let next_commitment = server_update(&anonymous, 0, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let message = core_v2::state_message(
            note.protocol_version,
            note.chain_id,
            &note.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let payload = json!({"type":"openrouter_lease_settlement"}).to_string();
        let receipt = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: "withheld".into(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: 0,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature: signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let finalized = Arc::new(Mutex::new(false));
        let router = Router::new()
            // The vault's root moved past the request's (see
            // withdrawal_settlement_applies_the_vault_root_witness_too).
            .route("/rpc", axum::routing::post(|| async {
                Json(json!({"jsonrpc":"2.0","id":1,"result":format!("0x{:064x}", 5)}))
            }))
            .route("/v2/openrouter/leases/withheld", get(|| async { StatusCode::NOT_FOUND }))
            .route("/v2/requests/withheld", get(|| async { Json(json!({"status":"not_found","nullifier_status":"unknown"})) }))
            .route(&format!("/v2/nullifiers/{nullifier}"), get(move |State(finalized): State<Arc<Mutex<bool>>>| async move {
                Json(if *finalized.lock().unwrap() {
                    json!({"status":"ok","nullifier_status":"finalized","request_response":receipt})
                } else {
                    json!({"status":"not_found","nullifier_status":"unknown"})
                })
            }))
            .with_state(finalized.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request && !journal_path.exists());
        let records =
            archived_requests(&config.state_dir.join("request_archive"), &nullifier).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].disposition, "discarded_unknown_to_server");
        assert_eq!(
            serde_json::to_value(&records[0].journal).unwrap(),
            serde_json::to_value(&saved).unwrap()
        );
        // The gateway had forwarded it after all; the server finalizes it.
        *finalized.lock().unwrap() = true;
        let recovered = service.recover().await.unwrap();
        assert!(recovered.recovered);
        assert_eq!(
            service.status().await.unwrap().note.unwrap().current_anchor,
            next_anchor
        );
        server.abort();
    }

    /// A wallet whose request "original" was archived at its current state
    /// and whose retry "retry" at that state is pending, with the server's
    /// valid finalized receipt for "original" (charge 0, next anchor 123).
    /// The server counts its reads of that state's nullifier record.
    struct Archived {
        _directory: tempfile::TempDir,
        config: AuthConfig,
        nullifier: Felt252,
        retry: PendingRequestJournal,
        reads: Arc<Mutex<usize>>,
        server: tokio::task::JoinHandle<()>,
    }

    async fn archived_with_finalized_receipt() -> Archived {
        let directory = tempfile::tempdir().unwrap();
        let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            state_signing_key: signer.public_key(),
            protocol_server_url: url.clone(),
            indexer_url: url,
            request_mode: RequestMode::DirectOpenrouter,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap().clone();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let journal_path = config.state_dir.join("pending_journal.json");
        let original = lease_request("original", nullifier, 400_000);
        PendingRequestJournal::write(
            &journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id: "original".into(),
                nullifier,
                payload_hash: original.payload_hash,
                user_rerandomization: Felt252::from_u64(5),
                created_at_ms: 1,
                prepared_request: Some(original),
            },
        )
        .unwrap();
        wallet
            .archive_pending_request("discarded_stale_root")
            .unwrap();
        let retry_request = lease_request("retry", nullifier, 50_000);
        let retry = PendingRequestJournal {
            exists: true,
            client_request_id: "retry".into(),
            nullifier,
            payload_hash: retry_request.payload_hash,
            user_rerandomization: Felt252::from_u64(6),
            created_at_ms: 2,
            prepared_request: Some(retry_request),
        };
        PendingRequestJournal::write(&journal_path, &retry).unwrap();
        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::from_u64(5),
        )
        .unwrap();
        let next_commitment = server_update(&anonymous, 0, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let message = core_v2::state_message(
            note.protocol_version,
            note.chain_id,
            &note.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let payload = json!({"type":"openrouter_lease_settlement"}).to_string();
        let receipt = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: "original".into(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: 0,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature: signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let reads = Arc::new(Mutex::new(0usize));
        let router = Router::new()
            .route("/v2/requests/retry", get(|| async { Json(json!({"status":"not_found","nullifier_status":"unknown"})) }))
            .route("/v2/openrouter/leases/retry", get(|| async { StatusCode::NOT_FOUND }))
            .route("/v2/openrouter/leases", axum::routing::post(|| async {
                (StatusCode::CONFLICT, Json(json!({"status":"error","client_request_id":"retry",
                    "error_code":"replay","error_message":"nullifier already reserved","retriable":false})))
            }))
            .route(&format!("/v2/nullifiers/{nullifier}"), get(move |State(reads): State<Arc<Mutex<usize>>>| {
                *reads.lock().unwrap() += 1;
                let receipt = receipt.clone();
                async move { Json(json!({"status":"ok","nullifier_status":"finalized","request_response":receipt})) }
            }))
            .with_state(reads.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Archived {
            _directory: directory,
            config,
            nullifier,
            retry,
            reads,
            server,
        }
    }

    /// A crash after the archived request's receipt was saved, but before
    /// the retry journal of the old state was set aside, used to leave a
    /// journal that nothing could resolve: its request is unknown, the
    /// archive of the new state is empty, and settlement reported the
    /// nullifier finalized for a request "not recoverable yet". Recovery
    /// now sets aside a journal of an earlier state as superseded.
    #[tokio::test]
    async fn a_journal_left_from_an_earlier_state_is_set_aside_by_recovery() {
        let fixture = archived_with_finalized_receipt().await;
        let journal_path = fixture.config.state_dir.join("pending_journal.json");
        let service = AuthService::new(fixture.config.clone()).unwrap();
        assert!(service.recover().await.unwrap().recovered);
        assert!(!journal_path.exists());
        // The crash window: the successor state is saved, the retry is not
        // yet archived.
        PendingRequestJournal::write(&journal_path, &fixture.retry).unwrap();
        assert!(service.status().await.unwrap().pending_request);
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request);
        assert_eq!(
            status.note.unwrap().current_anchor,
            core_v2::next_anchor(&fixture.nullifier)
        );
        let records = archived_requests(
            &fixture.config.state_dir.join("request_archive"),
            &fixture.nullifier,
        )
        .unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| (r.journal.client_request_id.as_str(), r.disposition.as_str()))
                .collect::<Vec<_>>(),
            [
                ("original", "discarded_stale_root"),
                ("retry", "superseded"),
                ("original", "installed"),
                ("retry", "superseded")
            ]
        );
        fixture.server.abort();
    }

    /// Installing an archived request's receipt sets the pending retry
    /// aside before it saves the successor state. When setting it aside
    /// fails, nothing is saved: the wallet never holds the successor state
    /// beside a journal of the state before it, and the next recovery
    /// installs the same receipt.
    #[cfg(unix)]
    #[tokio::test]
    async fn the_retry_is_archived_before_the_successor_state_is_saved() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = archived_with_finalized_receipt().await;
        let directory = fixture.config.state_dir.join("request_archive").join(
            fixture
                .nullifier
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o500)).unwrap();
        let service = AuthService::new(fixture.config.clone()).unwrap();
        let failed = service.recover().await;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(failed.is_err(), "{failed:?}");
        let status = service.status().await.unwrap();
        assert!(status.pending_request);
        let note = status.note.unwrap();
        assert_ne!(
            note.current_anchor,
            core_v2::next_anchor(&fixture.nullifier),
            "the successor was saved beside the old journal"
        );
        assert_eq!(note.current_balance, 1_500_000);
        assert!(service.recover().await.unwrap().recovered);
        let status = service.status().await.unwrap();
        assert!(!status.pending_request);
        assert_eq!(
            status.note.unwrap().current_anchor,
            core_v2::next_anchor(&fixture.nullifier)
        );
        fixture.server.abort();
    }

    /// A file another program left in the archive, or a damaged record, no
    /// longer disables recovery of the readable records beside it.
    #[tokio::test]
    async fn unreadable_archive_entries_do_not_stop_a_readable_record_from_installing() {
        let fixture = archived_with_finalized_receipt().await;
        let directory = fixture.config.state_dir.join("request_archive").join(
            fixture
                .nullifier
                .0
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        );
        std::fs::write(directory.join(".DS_Store"), b"\0\0\0\x01Bud1").unwrap();
        std::fs::write(directory.join("1-0.json"), b"").unwrap();
        let service = AuthService::new(fixture.config.clone()).unwrap();
        let recovered = service.recover().await.unwrap();
        assert!(recovered.recovered);
        assert_eq!(*fixture.reads.lock().unwrap(), 1);
        assert!(!recovered.wallet.pending_request);
        assert_eq!(
            recovered.wallet.note.unwrap().current_anchor,
            core_v2::next_anchor(&fixture.nullifier)
        );
        fixture.server.abort();
    }

    /// A chat at a state settled by a request whose journal an earlier
    /// release deleted (here: no archive record of "original") is refused as
    /// a replay forever. The chat reports receipt_journal_missing with the
    /// nullifier instead of an opaque wallet error, and keeps the retry.
    #[tokio::test]
    async fn a_chat_at_a_state_settled_without_a_journal_reports_receipt_journal_missing() {
        // The server's receipt for an archived request that does not verify
        // (here under another state key) is never reported as a missing
        // journal: this wallet holds that request's journal.
        let fixture = archived_with_finalized_receipt().await;
        let mut config = fixture.config.clone();
        config.state_signing_key = CompactSigner::from_seed(&Felt252::from_u64(98)).public_key();
        let service = AuthService::new(config).unwrap();
        let issued = service
            .issue_direct_openrouter_lease("chat".into(), None)
            .await;
        assert!(
            matches!(&issued, Err(AuthError::Wallet(message)) if message.contains("replay")),
            "{:?}",
            issued.as_ref().err()
        );
        fixture.server.abort();

        let fixture = archived_with_finalized_receipt().await;
        let archive = fixture.config.state_dir.join("request_archive");
        std::fs::remove_dir_all(&archive).unwrap();
        let service = AuthService::new(fixture.config.clone()).unwrap();
        let issued = service
            .issue_direct_openrouter_lease("chat".into(), None)
            .await;
        match issued {
            Err(AuthError::ReceiptJournalMissing(nullifier)) => {
                assert_eq!(nullifier, fixture.nullifier)
            }
            other => panic!("{:?}", other.err()),
        }
        assert!(service.status().await.unwrap().pending_request);
        fixture.server.abort();
    }

    /// receipt_journal_missing never names the wallet's own pending
    /// request. When the server's nullifier record already carries the
    /// pending retry's receipt (its request record lagging, or a receipt
    /// that does not install here), neither a chat nor a withdrawal tells
    /// the owner to take the nullifier to the operator.
    #[tokio::test]
    async fn the_pending_requests_own_receipt_is_never_reported_as_a_missing_journal() {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            protocol_server_url: url.clone(),
            indexer_url: url,
            request_mode: RequestMode::DirectOpenrouter,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        // The §6.2 write order: the retry fixed the state's bound first.
        let mut note = wallet.state().unwrap().clone();
        note.bound_at_state = 50_000;
        note.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let retry = lease_request("retry", nullifier, 50_000);
        PendingRequestJournal::write(
            &config.state_dir.join("pending_journal.json"),
            &PendingRequestJournal {
                exists: true,
                client_request_id: "retry".into(),
                nullifier,
                payload_hash: retry.payload_hash,
                user_rerandomization: Felt252::from_u64(6),
                // Just sent: E3 waits for its settlement.
                created_at_ms: now_seconds() * 1_000,
                prepared_request: Some(retry),
            },
        )
        .unwrap();
        // Signed by a key that is not the deployment's state key.
        let signer = CompactSigner::from_seed(&Felt252::from_u64(97));
        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::from_u64(6),
        )
        .unwrap();
        let next_commitment = server_update(&anonymous, 0, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let payload = json!({"type":"openrouter_lease_settlement"}).to_string();
        let next_state_signature = signer.sign(&core_v2::state_message(
            note.protocol_version,
            note.chain_id,
            &note.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        ));
        let receipt = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: "retry".into(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: 0,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature,
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let router = Router::new()
            .route("/v2/requests/retry", get(|| async { Json(json!({"status":"not_found","nullifier_status":"unknown"})) }))
            .route("/v2/openrouter/leases/retry", get(|| async { StatusCode::NOT_FOUND }))
            .route("/v2/openrouter/leases", axum::routing::post(|| async {
                (StatusCode::CONFLICT, Json(json!({"status":"error","client_request_id":"retry",
                    "error_code":"replay","error_message":"nullifier already reserved","retriable":false})))
            }))
            .route(&format!("/v2/nullifiers/{nullifier}"), get(move || {
                let receipt = receipt.clone();
                async move { Json(json!({"status":"ok","nullifier_status":"finalized","request_response":receipt})) }
            }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config).unwrap();
        let issued = service
            .issue_direct_openrouter_lease("chat".into(), None)
            .await;
        assert!(
            matches!(&issued, Err(AuthError::Wallet(message)) if message.contains("replay")),
            "{:?}",
            issued.as_ref().err()
        );
        let prepared = service.oa_prepare_withdrawal([0x22; 20], false).await;
        assert!(
            matches!(prepared, Err(AuthError::PendingSettlement)),
            "{:?}",
            prepared.as_ref().err()
        );
        assert!(service.status().await.unwrap().pending_request);
        server.abort();
    }

    /// The daemon's 5-second reconcile asks only about a pending request. It
    /// never polls the server's record of the note's current nullifier for
    /// archived requests, which would link the client's address and uptime
    /// to that nullifier every tick while the note is idle; explicit
    /// recovery still asks.
    #[tokio::test]
    async fn the_periodic_reconcile_never_polls_the_current_nullifier() {
        let fixture = archived_with_finalized_receipt().await;
        let service = AuthService::new(fixture.config.clone()).unwrap();
        for _ in 0..3 {
            service.reconcile_direct_openrouter().await;
        }
        assert_eq!(*fixture.reads.lock().unwrap(), 0, "with a pending retry");
        assert!(service.status().await.unwrap().pending_request);
        std::fs::remove_file(fixture.config.state_dir.join("pending_journal.json")).unwrap();
        for _ in 0..3 {
            service.reconcile_direct_openrouter().await;
        }
        assert_eq!(*fixture.reads.lock().unwrap(), 0, "with nothing pending");
        assert!(service.recover().await.unwrap().recovered);
        assert_eq!(*fixture.reads.lock().unwrap(), 1);
        fixture.server.abort();
    }

    async fn archived_receipt_installs(driver: Driver) {
        use axum::routing::post;
        let directory = tempfile::tempdir().unwrap();
        let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            request_charge_cap: 50_000,
            state_signing_key: signer.public_key(),
            protocol_server_url: url.clone(),
            indexer_url: url,
            request_mode: RequestMode::DirectOpenrouter,
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap().clone();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let journal_path = config.state_dir.join("pending_journal.json");
        let archive = config.state_dir.join("request_archive");
        let rerandomization = Felt252::from_u64(5);
        let original = lease_request("original", nullifier, 400_000);
        PendingRequestJournal::write(
            &journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id: "original".into(),
                nullifier,
                payload_hash: original.payload_hash,
                user_rerandomization: rerandomization,
                created_at_ms: 1,
                prepared_request: Some(original),
            },
        )
        .unwrap();
        wallet
            .archive_pending_request("discarded_stale_root")
            .unwrap();
        let retry = lease_request("retry", nullifier, 50_000);
        PendingRequestJournal::write(
            &journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id: "retry".into(),
                nullifier,
                payload_hash: retry.payload_hash,
                user_rerandomization: Felt252::from_u64(6),
                created_at_ms: 2,
                prepared_request: Some(retry.clone()),
            },
        )
        .unwrap();

        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &rerandomization,
        )
        .unwrap();
        let charge = 300_000; // Above the wallet's cap, within the archived request's bound.
        let next_commitment = server_update(&anonymous, charge, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let message = core_v2::state_message(
            note.protocol_version,
            note.chain_id,
            &note.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let payload = json!({"type":"openrouter_lease_settlement"}).to_string();
        let receipt = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: "original".into(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: charge,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature: signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let mut forged = receipt.clone();
        forged.next_state_signature.s = Felt252::ZERO;
        let reply = Arc::new(Mutex::new(forged));
        let retried = serde_json::to_value(&retry).unwrap();
        let router = Router::new()
            .route("/v2/requests/retry", get(|| async { Json(json!({"status":"not_found","nullifier_status":"unknown"})) }))
            .route("/v2/openrouter/leases/retry", get(|| async { StatusCode::NOT_FOUND }))
            .route("/v2/openrouter/leases", post(move |Json(body): Json<Value>| async move {
                assert_eq!(body, retried);
                (StatusCode::CONFLICT, Json(json!({"status":"error","client_request_id":"retry",
                    "error_code":"replay","error_message":"nullifier already reserved","retriable":false})))
            }))
            .route(&format!("/v2/nullifiers/{nullifier}"), get(|State(reply): State<Arc<Mutex<RequestResponseV2>>>| async move {
                Json(json!({"status":"ok","nullifier_status":"finalized","request_response":*reply.lock().unwrap()}))
            }))
            .route("/v1/tree/snapshot", get(|| async { StatusCode::SERVICE_UNAVAILABLE }))
            .with_state(reply.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        let drive = || async {
            match driver {
                Driver::Recover => service.recover().await.map(|_| ()),
                Driver::SettleForWithdrawal => service.settle_for_withdrawal().await.map(|_| ()),
                // After the receipt installs, the fresh proof at the new state
                // stops at the unreachable indexer.
                Driver::LeaseReplay => service
                    .issue_direct_openrouter_lease("chat".into(), None)
                    .await
                    .map(|_| ()),
            }
        };

        assert!(
            drive().await.is_err() || driver == Driver::Recover,
            "{driver:?}"
        );
        let status = service.status().await.unwrap();
        assert!(
            status.pending_request,
            "{driver:?}: a forged receipt installed"
        );
        assert_eq!(
            status.note.unwrap().current_balance,
            1_500_000,
            "{driver:?}"
        );

        *reply.lock().unwrap() = receipt;
        let result = drive().await;
        match driver {
            Driver::LeaseReplay => {
                assert!(matches!(result, Err(AuthError::Indexer(_))), "{result:?}")
            }
            _ => assert!(result.is_ok(), "{driver:?}: {result:?}"),
        }
        let status = service.status().await.unwrap();
        assert!(!status.pending_request, "{driver:?}");
        assert_eq!(
            status.note.unwrap().current_balance,
            1_500_000 - charge,
            "{driver:?}"
        );
        assert!(!journal_path.exists(), "{driver:?}");
        let records = archived_requests(&archive, &nullifier).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|r| (r.journal.client_request_id.as_str(), r.disposition.as_str()))
                .collect::<Vec<_>>(),
            [
                ("original", "discarded_stale_root"),
                ("retry", "superseded"),
                ("original", "installed")
            ],
            "{driver:?}"
        );
        server.abort();
    }
}

#[cfg(test)]
mod oa_bridge_security_tests {
    #[test]
    fn oa_verifier_accepts_only_exact_protocol_hash_forms() {
        use sha2::{Digest, Sha256};
        let hash = format!("{:x}", Sha256::digest(b"test-secret"));
        for accepted in [&hash[..16], &hash] {
            let valid = serde_json::json!({"status":"verified","station_id":"station-one","key_hash":accepted});
            assert!(super::oa_verifier_binds_key(
                &valid,
                "station-one",
                "test-secret"
            ));
        }
        let wrong_suffix = format!("{}{}", &hash[..16], "0".repeat(48));
        assert_ne!(wrong_suffix, hash);
        for invalid in [
            serde_json::json!({"status":"pending","station_id":"station-one","key_hash":&hash[..16]}),
            serde_json::json!({"status":"verified","station_id":"station-two","key_hash":&hash[..16]}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":&hash[..15]}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":&hash[..17]}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":&hash[..63]}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":format!("{}0",hash)}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":"0".repeat(16)}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":wrong_suffix}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":"g".repeat(16)}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":hash[..16].to_uppercase()}),
            serde_json::json!({"status":"verified","station_id":"station-one","key_hash":hash.to_uppercase()}),
            serde_json::json!({"status":"verified"}),
        ] {
            assert!(!super::oa_verifier_binds_key(
                &invalid,
                "station-one",
                "test-secret"
            ));
        }
    }

    #[test]
    fn oa_bridge_reservation_is_durable_and_single_use() {
        let directory = tempfile::tempdir().unwrap();
        super::reserve_oa_bridge_lease(directory.path(), "first").unwrap();
        assert!(matches!(
            super::reserve_oa_bridge_lease(directory.path(), "first"),
            Err(super::AuthError::LeasePending(_))
        ));
        assert!(super::reserve_oa_bridge_lease(directory.path(), "first").is_err());
        super::reserve_oa_bridge_lease(directory.path(), "../../second").unwrap();
        assert_eq!(
            std::fs::read_dir(directory.path().join("oa-issued-leases"))
                .unwrap()
                .count(),
            2
        );
    }
}

#[cfg(test)]
mod oa_outage_tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use serde_json::json;
    use sha2::{Digest, Sha256};

    struct SignedEvidence {
        public: String,
        evidence: OaKeyVerificationEvidence,
    }

    impl SignedEvidence {
        fn new(url: &str) -> Self {
            let pair = Ed25519KeyPair::from_seed_unchecked(&[7; 32]).unwrap();
            let key_valid_till = now_seconds() + 330;
            let signature = pair.sign(format!("oa-station|test-key|{key_valid_till}").as_bytes());
            Self {
                public: pair
                    .public_key()
                    .as_ref()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect(),
                evidence: OaKeyVerificationEvidence {
                    verifier_url: url.into(),
                    station_id: "oa-station".into(),
                    station_recently_attested: false,
                    key_valid_till,
                    station_signature: signature
                        .as_ref()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect(),
                    org_signature: "cd".repeat(64),
                },
            }
        }
        fn trust<'a>(&'a self, url: &'a str) -> StationTrust<'a> {
            StationTrust {
                station_id: "oa-station",
                public_key_hex: &self.public,
                verifier_url: url,
            }
        }
        fn expiry(&self) -> u64 {
            self.evidence.key_valid_till - 30
        }
    }

    fn service(url: &str, directory: &std::path::Path) -> Arc<AuthService> {
        AuthService::new(AuthConfig {
            state_dir: directory.into(),
            oa_verifier_url: url.into(),
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn every_advisory_fallback_requires_a_pinned_signed_key() {
        let url = TRUSTED_STATION.verifier_url;
        let signed = SignedEvidence::new(url);
        let trust = signed.trust(url);
        let mut unknown = signed.evidence.clone();
        unknown.station_id = "unknown".into();
        unknown.station_recently_attested = true;
        for (status, body) in [
            (None, Value::Null),
            (
                Some(200),
                json!({"status":"unverified","ownership_passed":false}),
            ),
            (Some(200), json!({"status":"pending"})),
            (Some(401), json!({"detail":"Invalid org signature"})),
            (
                Some(403),
                json!({"status":"rejected","detail":"ownership check failed"}),
            ),
            (Some(408), json!({"status":"error"})),
            (Some(429), json!({"status":"error"})),
            (Some(500), json!({"status":"error"})),
            (Some(502), json!({"status":"error"})),
            (
                Some(503),
                json!({"status":"unverified","detail":"ownership_check_error"}),
            ),
            (Some(504), json!({"status":"error"})),
        ] {
            let result = oa_verifier_outage(
                status,
                &body,
                signed.expiry(),
                &signed.evidence,
                "test-key",
                url,
                trust,
            )
            .unwrap();
            assert!(!result.verified);
            assert_eq!(result.detail, Some("trusted_station_fallback"));
            assert!(
                oa_verifier_outage(
                    status,
                    &body,
                    signed.expiry(),
                    &unknown,
                    "test-key",
                    url,
                    trust
                )
                .is_err(),
                "{status:?} {body}"
            );
        }
        for (status, body) in [
            (307, json!({})),
            (308, json!({})),
            (200, json!({"status":123})),
            (401, json!({"detail":"Station is banned"})),
            (503, json!({"status":"banned"})),
            (503, json!({"banned_station":{"station_id":"oa-station"}})),
            (503, json!({"error":{"detail":"key expired"}})),
            (200, json!({"status":"expired"})),
        ] {
            assert!(oa_verifier_outage(
                Some(status),
                &body,
                signed.expiry(),
                &signed.evidence,
                "test-key",
                url,
                trust
            )
            .is_err());
        }
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            now_seconds() - 1,
            &signed.evidence,
            "test-key",
            url,
            trust
        )
        .is_err());
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &signed.evidence,
            "swapped-key",
            url,
            trust
        )
        .is_err());
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &signed.evidence,
            "test-key",
            "https://other.example",
            trust
        )
        .is_err());
        let mut swapped = signed.evidence.clone();
        swapped.key_valid_till += 1;
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &swapped,
            "test-key",
            url,
            trust
        )
        .is_err());
        swapped = signed.evidence.clone();
        swapped.station_signature = "ab".repeat(64);
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &swapped,
            "test-key",
            url,
            trust
        )
        .is_err());
        swapped = signed.evidence.clone();
        swapped.verifier_url = "https://other.example".into();
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &swapped,
            "test-key",
            url,
            trust
        )
        .is_err());
        // Tests cannot accidentally depend on possession of the real operator signing key.
        assert!(oa_verifier_outage(
            None,
            &Value::Null,
            signed.expiry(),
            &signed.evidence,
            "test-key",
            url,
            TRUSTED_STATION
        )
        .is_err());
    }

    #[tokio::test]
    async fn http_policy_binds_verified_replies_and_remembers_textual_bans_before_checkout() {
        use axum::{extract::State, routing::post, Json, Router};
        let reply = Arc::new(Mutex::new((200u16, "{}".to_string())));
        let capture = Arc::new(Mutex::new(Vec::<Value>::new()));
        type VerifierState = (Arc<Mutex<(u16, String)>>, Arc<Mutex<Vec<Value>>>);
        let state = (reply.clone(), capture.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router =
            Router::new()
                .route(
                    "/submit_key",
                    post(
                        |State((reply, capture)): State<VerifierState>,
                         Json(request): Json<Value>| async move {
                            capture.lock().unwrap().push(request);
                            let (status, body) = reply.lock().unwrap().clone();
                            (
                                axum::http::StatusCode::from_u16(status).unwrap(),
                                [("location", "/redirect-target")],
                                body,
                            )
                        },
                    ),
                )
                .with_state(state);
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let directory = tempfile::tempdir().unwrap();
        let service = service(&url, directory.path());
        let signed = SignedEvidence::new(&url);
        let ev = &signed.evidence;
        let trust = signed.trust(&url);
        let hash = format!("{:x}", Sha256::digest(b"test-key"));
        let mut unknown = ev.clone();
        unknown.station_id = "unknown".into();
        unknown.station_recently_attested = true;
        *reply.lock().unwrap() = (
            200,
            json!({"status":"verified","station_id":"unknown","key_hash":&hash[..16]}).to_string(),
        );
        // Normal verifier approval does not require a locally pinned station.
        assert!(
            service
                .verify_oa_key("test-key", signed.expiry(), &unknown)
                .await
                .unwrap()
                .verified
        );
        assert_eq!(
            capture.lock().unwrap()[0]["key_valid_till"],
            ev.key_valid_till
        );
        assert_eq!(
            capture.lock().unwrap()[0]["station_signature"],
            ev.station_signature
        );
        for (status, body) in [
            (401, json!({"detail":"Invalid org signature"})),
            (200, json!({"status":"unverified","ownership_passed":false})),
            (403, json!({"status":"rejected"})),
            (429, json!({"status":"error"})),
            (
                503,
                json!({"status":"unverified","detail":"ownership_check_error"}),
            ),
        ] {
            *reply.lock().unwrap() = (status, body.to_string());
            let outcome = service
                .verify_oa_key_with_trust("test-key", signed.expiry(), ev, trust)
                .await
                .unwrap();
            assert!(!outcome.verified);
            assert_eq!(outcome.detail, Some("trusted_station_fallback"));
            assert!(service
                .verify_oa_key_with_trust("test-key", signed.expiry(), &unknown, trust)
                .await
                .is_err());
            assert!(service
                .verify_oa_key_with_trust("swapped-key", signed.expiry(), ev, trust)
                .await
                .is_err());
            // A production call never trusts this test pin or loopback verifier.
            assert!(service
                .verify_oa_key("test-key", signed.expiry(), ev)
                .await
                .is_err());
        }
        for (status, body) in [
            (200, json!({"status":"verified"}).to_string()),
            (
                200,
                json!({"status":"verified","station_id":"other","key_hash":&hash[..16]})
                    .to_string(),
            ),
            (
                200,
                json!({"status":"verified","station_id":"oa-station","key_hash":"0".repeat(16)})
                    .to_string(),
            ),
            (
                503,
                json!({"status":"verified","station_id":"oa-station","key_hash":&hash[..16]})
                    .to_string(),
            ),
            (
                503,
                json!({"status":"error","station_id":"other"}).to_string(),
            ),
            (429, json!({"key_hash":"0".repeat(16)}).to_string()),
            (503, "[]".into()),
            (503, "<html>unavailable</html>".into()),
            (307, "{}".into()),
            (308, "{}".into()),
            (503, "x".repeat((1 << 20) + 1)),
        ] {
            *reply.lock().unwrap() = (status, body);
            let before = capture.lock().unwrap().len();
            assert!(service
                .verify_oa_key_with_trust("test-key", signed.expiry(), ev, trust)
                .await
                .is_err());
            assert_eq!(capture.lock().unwrap().len(), before + 1);
        }
        let mut changed = ev.clone();
        changed.key_valid_till += 1;
        *reply.lock().unwrap() = (401, json!({"detail":"Invalid org signature"}).to_string());
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), &changed, trust)
            .await
            .is_err());
        changed = ev.clone();
        changed.station_signature = "00".repeat(64);
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), &changed, trust)
            .await
            .is_err());
        changed = ev.clone();
        changed.verifier_url = "https://other.example".into();
        let before = capture.lock().unwrap().len();
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), &changed, trust)
            .await
            .is_err());
        assert_eq!(capture.lock().unwrap().len(), before);
        assert!(service
            .verify_oa_key_with_trust("test-key", now_seconds() - 1, ev, trust)
            .await
            .is_err());
        *reply.lock().unwrap() = (401, json!({"detail":"Station is banned"}).to_string());
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), ev, trust)
            .await
            .is_err());
        let count = capture.lock().unwrap().len();
        *reply.lock().unwrap() = (
            200,
            json!({"status":"verified","station_id":"oa-station","key_hash":&hash[..16]})
                .to_string(),
        );
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), ev, trust)
            .await
            .is_err());
        assert_eq!(capture.lock().unwrap().len(), count);
        let mut cached = ActiveOpenRouterLease {
            session_id: "test-session".into(),
            client_request_id: "test-lease".into(),
            api_key: "test-key".into(),
            openrouter_api_base: url.clone(),
            expires_at: signed.expiry(),
            settle_after: signed.expiry() + 30,
            verification: Some(ev.clone()),
            verified: true,
            verification_detail: None,
            requests_served: 0,
        };
        assert!(service.check_cached_lease_station(&cached).is_err());
        assert!(service
            .send_verified_openrouter_request(&mut cached, "/submit_key", &json!({}))
            .await
            .is_err());
        assert_eq!(capture.lock().unwrap().len(), count);
        assert!(!directory.path().join("oa-issued-leases").exists());
        server.abort();
    }

    #[tokio::test]
    async fn transport_outage_still_requires_exact_trust_and_tls_errors_fail_closed() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let directory = tempfile::tempdir().unwrap();
        let service = service(&url, directory.path());
        let signed = SignedEvidence::new(&url);
        let outcome = service
            .verify_oa_key_with_trust(
                "test-key",
                signed.expiry(),
                &signed.evidence,
                signed.trust(&url),
            )
            .await
            .unwrap();
        assert!(!outcome.verified);
        assert_eq!(outcome.detail, Some("trusted_station_fallback"));
        let mut unknown = signed.evidence.clone();
        unknown.station_id = "unknown".into();
        unknown.station_recently_attested = true;
        assert!(service
            .verify_oa_key_with_trust("test-key", signed.expiry(), &unknown, signed.trust(&url))
            .await
            .is_err());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_url = format!("https://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\n\r\nnot a TLS server")
                .await
                .unwrap();
        });
        let tls_service = self::service(&tls_url, directory.path());
        let tls_signed = SignedEvidence::new(&tls_url);
        let result = tls_service
            .verify_oa_key_with_trust(
                "test-key",
                tls_signed.expiry(),
                &tls_signed.evidence,
                tls_signed.trust(&tls_url),
            )
            .await;
        assert!(
            result.is_err(),
            "TLS failure must not become trusted fallback"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn canceled_verification_does_not_activate_or_reserve_a_lease() {
        use axum::{extract::State, routing::post, Router};
        let entered = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/submit_key",
                post(
                    |State(entered): State<Arc<tokio::sync::Notify>>| async move {
                        entered.notify_one();
                        std::future::pending::<()>().await;
                        "unreachable"
                    },
                ),
            )
            .with_state(entered.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let directory = tempfile::tempdir().unwrap();
        let service = service(&url, directory.path());
        let task_service = service.clone();
        let task = tokio::spawn(async move {
            let signed = SignedEvidence::new(&url);
            task_service
                .verify_oa_key_with_trust(
                    "test-key",
                    signed.expiry(),
                    &signed.evidence,
                    signed.trust(&url),
                )
                .await
        });
        tokio::time::timeout(Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(service.direct_lease.lock().await.is_none());
        assert!(!directory.path().join("oa-issued-leases").exists());
        assert!(service.oa_banned_stations.lock().unwrap().is_empty());
        server.abort();
    }
}

#[cfg(test)]
mod oa_native_recovery_tests {
    use super::*;
    use serde_json::json;
    use zkapi_client::journal::PendingRequestJournal;
    fn fixture() -> (tempfile::TempDir, AuthConfig, ApiRequestV2) {
        let (directory, mut config, note) = crate::oa_withdrawal::tests::fixture();
        config.billing_asset = "native_eth".into();
        config.billing_unit = "gwei".into();
        config.native_asset_wei_per_unit = "1000000000".into();
        config.native_price_feed_address = format!("0x{}", "12".repeat(20));
        config.request_charge_cap = 50_000;
        // Saved one-dollar authorization must survive a new six-dollar model selection.
        let quote = json!({"asset":"native_eth","units_per_eth":1_000_000_000,"chain_id":config.chain_id,"feed_address":config.native_price_feed_address,
            "round_id":"123","answer":"250000000000","decimals":8,"updated_at":1,"expires_at":3601});
        let payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        let request = ApiRequestV2 {
            client_request_id: "saved-native".into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: config.chain_id,
                contract_address: config.contract_address,
                active_root: Felt252::ZERO,
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1,
                solvency_bound: 400_000,
                request_nullifier: core_v2::nullifier(
                    &note.secret_s,
                    note.note_id,
                    &note.current_anchor,
                ),
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: Felt252::ONE,
                anonymous_commitment_y: Felt252::ONE,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "fixture".into(),
            },
        };
        PendingRequestJournal::write(
            &config.state_dir.join("pending_journal.json"),
            &PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier: request.public_inputs.request_nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::ONE,
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            },
        )
        .unwrap();
        (directory, config, request)
    }
    #[test]
    fn native_model_cap_accepts_balance_equality_and_rejects_one_unit_below() {
        let (_directory, mut config, mut note) = crate::oa_withdrawal::tests::fixture();
        config.request_charge_cap = 400_000;
        let payload = "coarse authorized lease";
        for (balance, insufficient) in [(399_999, true), (400_000, false), (400_001, false)] {
            note.current_balance = balance;
            note.save(&config.state_dir.join("note_state.json"))
                .unwrap();
            let mut wallet = load_wallet(&config).unwrap();
            // An invalid witness deliberately stops before expensive proving;
            // the actual protocol balance gate precedes witness validation.
            let failure = wallet
                .prepare_request(
                    payload,
                    compute_payload_hash(payload.as_bytes()),
                    Felt252::ZERO,
                    Vec::new(),
                )
                .unwrap_err();
            assert_eq!(
                matches!(
                    failure,
                    zkapi_client::error::ClientError::InsufficientBalance { .. }
                ),
                insufficient,
                "balance {balance}: {failure}"
            );
            assert!(!wallet.has_pending_request());
        }
    }

    #[tokio::test]
    async fn restart_replays_expired_frozen_quote_and_bound_without_new_oracle() {
        let (_directory, config, request) = fixture();
        let service = AuthService::new(config).unwrap();
        let restored = service
            .prepare_direct_lease_request(Some(6_000_000))
            .await
            .unwrap();
        assert!(service.check_request_budget(&restored, 6_000_000).is_err());
        service.check_request_budget(&restored, 1_000_000).unwrap();
        assert_eq!(
            serde_json::to_value(restored).unwrap(),
            serde_json::to_value(request).unwrap()
        );
    }
    /// C2 then the native lease's budget check: a state whose bound was
    /// fixed by an earlier request (set aside, say, after stale_root) proves
    /// a cheaper tier's request at that bound, and the lease check accepts
    /// it instead of leaving a never-sent journal that blocks every tier. A
    /// tier the bound does not cover, or a bound at another state, is still
    /// refused.
    #[tokio::test]
    async fn a_reused_state_bound_passes_the_native_budget_check() {
        let (_directory, config, mut request) = fixture();
        // 1,200,000 units: the three-dollar tier at the fixture's quote.
        request.public_inputs.solvency_bound = 1_200_000;
        let path = config.state_dir.join("note_state.json");
        let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
        state.bound_at_state = 1_200_000;
        state.save(&path).unwrap();
        let service = AuthService::new(config.clone()).unwrap();
        assert_eq!(state_solvency_bound(1_200_000, 400_000).unwrap(), 1_200_000);
        for limit in [1_000_000, 2_000_000, 3_000_000] {
            service.check_request_budget(&request, limit).unwrap();
        }
        assert!(service.check_request_budget(&request, 4_500_000).is_err());
        // Without a fixed bound at the request's state, only the tier's own
        // budget passes.
        state.bound_at_state = 0;
        state.save(&path).unwrap();
        assert!(service.check_request_budget(&request, 1_000_000).is_err());
        service.check_request_budget(&request, 3_000_000).unwrap();
        state.bound_at_state = 1_200_000;
        state.current_anchor = Felt252::from_u64(77);
        state.save(&path).unwrap();
        assert!(service.check_request_budget(&request, 1_000_000).is_err());
    }
    #[test]
    fn settlement_changed_quote_preserves_note_and_journal() {
        let (_directory, config, request) = fixture();
        let before = std::fs::read(config.state_dir.join("note_state.json")).unwrap();
        let mut wallet = load_wallet(&config).unwrap();
        let response:RequestResponseV2=serde_json::from_value(json!({"status":"finalized","client_request_id":request.client_request_id,"request_nullifier":request.public_inputs.request_nullifier,
            "response_code":200,"response_payload":"{}","response_hash":"0x0","charge_applied":0,"next_commitment":{"x":"0x0","y":"0x1"},
            "next_anchor":"0x1","blind_delta_srv":"0x0","next_state_signature":{"r_x":"0x0","r_y":"0x1","s":"0x0"}})).unwrap();
        let failure = wallet.complete_pending_response(&response).unwrap_err();
        assert!(failure.to_string().contains("changed the authorized quote"));
        assert_eq!(
            std::fs::read(config.state_dir.join("note_state.json")).unwrap(),
            before
        );
        assert!(
            PendingRequestJournal::read(&config.state_dir.join("pending_journal.json"))
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn quote_refresh_requires_atomic_matching_unaccepted_acknowledgement() {
        use axum::{extract::State, routing::post, Json, Router};
        let (_directory, mut config, request) = fixture();
        let reply = Arc::new(Mutex::new(
            json!({"status":"expired_unaccepted","client_request_id":request.client_request_id,"request_nullifier":request.public_inputs.request_nullifier,"payload_hash":request.payload_hash}),
        ));
        let original = reply.lock().unwrap().clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.protocol_server_url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/v2/openrouter/leases/saved-native/expire",
                post(|State(reply): State<Arc<Mutex<Value>>>| async move {
                    Json(reply.lock().unwrap().clone())
                }),
            )
            .with_state(reply.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config.clone()).unwrap();
        for (field, value) in [
            ("status", json!("not_found")),
            ("client_request_id", json!("other")),
            ("request_nullifier", json!("0x0")),
            ("payload_hash", json!("0x0")),
        ] {
            let mut altered = original.clone();
            altered[field] = value;
            *reply.lock().unwrap() = altered;
            assert!(service
                .refresh_unaccepted_native_request(request.clone())
                .await
                .is_err());
            assert!(
                PendingRequestJournal::read(&config.state_dir.join("pending_journal.json"))
                    .unwrap()
                    .is_some()
            );
        }
        *reply.lock().unwrap() = original;
        service
            .refresh_unaccepted_native_request(request.clone())
            .await
            .unwrap();
        assert!(
            PendingRequestJournal::read(&config.state_dir.join("pending_journal.json"))
                .unwrap()
                .is_none()
        );
        // The acknowledgement is unsigned and only echoes the request's own
        // identifiers: the journal is archived whole, never deleted.
        let archived = zkapi_client::journal::archived_requests(
            &config.state_dir.join("request_archive"),
            &request.public_inputs.request_nullifier,
        )
        .unwrap();
        assert_eq!(archived.len(), 1);
        assert_eq!(archived[0].disposition, "discarded_expired_unaccepted");
        assert_eq!(
            serde_json::to_value(archived[0].journal.prepared_request.as_ref().unwrap()).unwrap(),
            serde_json::to_value(&request).unwrap()
        );
        assert_eq!(archived[0].journal.user_rerandomization, Felt252::ONE);
        server.abort();
    }

    /// A release may move the pinned feed, its decimals or the maximum quote
    /// age while a native request is journaled. Its quote is bound into the
    /// request proof, so the wallet still opens and both recovery and
    /// withdrawal settlement install the finalized receipt.
    #[tokio::test]
    async fn pin_change_keeps_a_journaled_native_request_recoverable() {
        use axum::{routing::get, Json, Router};
        use zkapi_proof::compact::{rerandomize, server_update, CompactSigner};
        use zkapi_types::wire::CurvePointWire;
        let changes = ["unchanged", "maximum age", "feed address", "feed decimals"];
        for pins in changes {
            for withdraw in [false, true] {
                let case = format!("{pins} pins, withdrawal settlement {withdraw}");
                let directory = tempfile::tempdir().unwrap();
                let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let mut config = AuthConfig {
                    state_dir: directory.path().to_path_buf(),
                    chain_id: 11_155_111,
                    contract_address: Felt252::from_u64(0x12345),
                    billing_asset: "native_eth".into(),
                    billing_unit: "gwei".into(),
                    native_asset_wei_per_unit: "1000000000".into(),
                    native_price_feed_address: format!("0x{}", "12".repeat(20)),
                    request_charge_cap: 50_000,
                    state_signing_key: signer.public_key(),
                    protocol_server_url: format!("http://{}", listener.local_addr().unwrap()),
                    request_mode: RequestMode::DirectOpenrouter,
                    ..Default::default()
                };
                let mut wallet = load_wallet(&config).unwrap();
                wallet
                    .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
                    .unwrap();
                let note = wallet.state().unwrap().clone();
                let updated_at = now_seconds() - 60;
                let quote = json!({"asset":"native_eth","units_per_eth":1_000_000_000,
                    "chain_id":config.chain_id,"feed_address":config.native_price_feed_address,
                    "round_id":"123","answer":"250000000000","decimals":8,
                    "updated_at":updated_at,"expires_at":updated_at + 3600});
                let payload =
                    json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                        .to_string();
                let nullifier =
                    core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
                let request = ApiRequestV2 {
                    client_request_id: "saved-native".into(),
                    payload_hash: compute_payload_hash(payload.as_bytes()),
                    payload,
                    public_inputs: zkapi_types::RequestPublicInputsV2 {
                        protocol_version: 2,
                        chain_id: config.chain_id,
                        contract_address: config.contract_address,
                        active_root: Felt252::ZERO,
                        state_signing_key_x: config.state_signing_key.x,
                        state_signing_key_y: config.state_signing_key.y,
                        request_time: 1,
                        solvency_bound: 400_000,
                        request_nullifier: nullifier,
                        authorization_tag: Felt252::ONE,
                        anonymous_commitment_x: Felt252::ONE,
                        anonymous_commitment_y: Felt252::ONE,
                    },
                    proof: Groth16ProofWire {
                        backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                        proof: "fixture".into(),
                    },
                };
                PendingRequestJournal::write(
                    &config.state_dir.join("pending_journal.json"),
                    &PendingRequestJournal {
                        exists: true,
                        client_request_id: request.client_request_id.clone(),
                        nullifier,
                        payload_hash: request.payload_hash,
                        user_rerandomization: Felt252::ONE,
                        created_at_ms: 1,
                        prepared_request: Some(request.clone()),
                    },
                )
                .unwrap();
                // The server's signed receipt repeats the proof-bound quote.
                let anonymous = rerandomize(
                    &CurvePointWire {
                        x: note.current_commitment_x,
                        y: note.current_commitment_y,
                    },
                    &Felt252::ONE,
                )
                .unwrap();
                let charge = 120_000;
                let next_commitment = server_update(&anonymous, charge, &Felt252::ONE).unwrap();
                let next_anchor = core_v2::next_anchor(&nullifier);
                let message = core_v2::state_message(
                    note.protocol_version,
                    note.chain_id,
                    &note.contract_address,
                    &next_commitment.x,
                    &next_commitment.y,
                    &next_anchor,
                );
                let settlement =
                    json!({"type":"oa_org_ephemeral_lease_settlement","billing_quote":quote})
                        .to_string();
                let response = RequestResponseV2 {
                    status: "finalized".into(),
                    client_request_id: request.client_request_id.clone(),
                    request_nullifier: nullifier,
                    response_code: 200,
                    response_hash: zkapi_types::canonical_response_hash(settlement.as_bytes()),
                    response_payload: settlement,
                    charge_applied: charge,
                    next_commitment,
                    next_anchor,
                    blind_delta_srv: Felt252::ONE,
                    next_state_signature: signer.sign(&message),
                    policy_reason_code: None,
                    policy_evidence_hash: None,
                };
                let recovery = json!({"status":"finalized","nullifier_status":"finalized",
                    "request_response":response});
                // No lease route: the withdrawal path finds the receipt by request.
                let router = Router::new().route(
                    "/v2/requests/saved-native",
                    get(move || {
                        let recovery = recovery.clone();
                        async move { Json(recovery) }
                    }),
                );
                let server =
                    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
                match pins {
                    "maximum age" => config.native_price_max_age_seconds = 4500,
                    "feed address" => {
                        config.native_price_feed_address = format!("0x{}", "34".repeat(20))
                    }
                    "feed decimals" => config.native_price_feed_decimals = 18,
                    _ => {}
                }
                load_wallet(&config).expect(&case);
                let service = AuthService::new(config.clone()).unwrap();
                assert!(service.status().await.expect(&case).pending_request);
                let status = if withdraw {
                    service.settle_for_withdrawal().await.expect(&case)
                } else {
                    let recovered = service.recover().await.expect(&case);
                    assert!(recovered.recovered, "{case}");
                    recovered.wallet
                };
                assert!(!status.pending_request, "{case}");
                assert_eq!(status.note.unwrap().current_balance, 1_500_000 - charge);
                assert!(!config.state_dir.join("pending_journal.json").exists());
                server.abort();
            }
        }
    }

    /// The server checks a new admission's pins before its freshness, so it
    /// refuses a never-admitted request journaled under pins a release has
    /// since changed with invalid_request, never native_quote_expired. Once
    /// that quote has expired the companion asks the server to confirm it
    /// expired unaccepted, as for native_quote_expired, and retires the
    /// request only on that acknowledgement.
    #[tokio::test]
    async fn expired_request_under_earlier_pins_is_retired_on_server_acknowledgement() {
        use axum::{http::StatusCode, routing::post, Json, Router};
        use std::sync::atomic::{AtomicUsize, Ordering};
        let pin_refusal =
            "invalid request: native billing quote does not match the pinned deployment";
        for (case, pin) in [
            ("feed migrated", "feed address"),
            ("maximum age raised", "maximum age"),
            ("feed decimals changed", "feed decimals"),
            ("expiry not confirmed", "feed address"),
            ("quote not yet expired", "feed address"),
            ("pins unchanged", "none"),
            ("another refusal", "feed address"),
        ] {
            let expired = case != "quote not yet expired";
            let code = match case {
                "another refusal" => "rate_limited",
                _ => "invalid_request",
            };
            let confirms = case != "expiry not confirmed";
            // Only an expired quote under changed pins, refused as
            // invalid_request, asks the server; only its confirmation retires.
            let asked = expired && pin != "none" && code == "invalid_request";
            let retired = asked && confirms;
            let (_directory, mut config, mut request) = fixture();
            config.request_mode = RequestMode::DirectOpenrouter;
            let journal = config.state_dir.join("pending_journal.json");
            if !expired {
                let updated_at = now_seconds() - 60;
                let quote = json!({"asset":"native_eth","units_per_eth":1_000_000_000,
                    "chain_id":config.chain_id,"feed_address":config.native_price_feed_address,
                    "round_id":"123","answer":"250000000000","decimals":8,
                    "updated_at":updated_at,"expires_at":updated_at + 3600});
                request.payload =
                    json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                        .to_string();
                request.payload_hash = compute_payload_hash(request.payload.as_bytes());
                PendingRequestJournal::write(
                    &journal,
                    &PendingRequestJournal {
                        exists: true,
                        client_request_id: request.client_request_id.clone(),
                        nullifier: request.public_inputs.request_nullifier,
                        payload_hash: request.payload_hash,
                        user_rerandomization: Felt252::ONE,
                        created_at_ms: 1,
                        prepared_request: Some(request.clone()),
                    },
                )
                .unwrap();
            }
            match pin {
                "feed address" => {
                    config.native_price_feed_address = format!("0x{}", "34".repeat(20))
                }
                "maximum age" => config.native_price_max_age_seconds = 4500,
                "feed decimals" => config.native_price_feed_decimals = 18,
                _ => {}
            }
            let lease_posts = Arc::new(AtomicUsize::new(0));
            let expiry_posts = Arc::new(AtomicUsize::new(0));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            config.protocol_server_url = format!("http://{}", listener.local_addr().unwrap());
            let refusal = match code {
                "invalid_request" => pin_refusal,
                _ => "too many lease requests; retry later",
            };
            let rejection = json!({"status":"error","client_request_id":request.client_request_id,
                "error_code":code,"error_message":refusal,"retriable":false});
            let expiry = if confirms {
                let acknowledgement = json!({"status":"expired_unaccepted",
                    "client_request_id":request.client_request_id,
                    "request_nullifier":request.public_inputs.request_nullifier,
                    "payload_hash":request.payload_hash});
                (StatusCode::OK, acknowledgement)
            } else {
                // A server whose clock has not reached the expiry checks pins.
                (StatusCode::BAD_REQUEST, rejection.clone())
            };
            let lease_status = match code {
                "invalid_request" => StatusCode::BAD_REQUEST,
                _ => StatusCode::TOO_MANY_REQUESTS,
            };
            let (leases, expiries) = (lease_posts.clone(), expiry_posts.clone());
            let router = Router::new()
                .route(
                    "/v2/openrouter/leases",
                    post(move || {
                        let (leases, body) = (leases.clone(), rejection.clone());
                        async move {
                            leases.fetch_add(1, Ordering::SeqCst);
                            (lease_status, Json(body))
                        }
                    }),
                )
                .route(
                    "/v2/openrouter/leases/saved-native/expire",
                    post(move || {
                        let (expiries, (status, body)) = (expiries.clone(), expiry.clone());
                        async move {
                            expiries.fetch_add(1, Ordering::SeqCst);
                            (status, Json(body))
                        }
                    }),
                );
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let saved = std::fs::read(&journal).unwrap();
            let note = std::fs::read(config.state_dir.join("note_state.json")).unwrap();
            let service = AuthService::new(config.clone()).unwrap();
            let failure = service
                .issue_direct_openrouter_lease("chat".into(), Some(1_000_000))
                .await
                .err()
                .expect(case);
            assert_eq!(lease_posts.load(Ordering::SeqCst), 1, "{case}");
            assert_eq!(
                expiry_posts.load(Ordering::SeqCst),
                usize::from(asked),
                "{case}"
            );
            if retired {
                // The next proof starts from the unchanged note; the fixture's
                // unreachable indexer stops it before any new quote.
                assert!(
                    matches!(failure, AuthError::Indexer(_)),
                    "{case}: {failure}"
                );
                assert!(
                    PendingRequestJournal::read(&journal).unwrap().is_none(),
                    "{case}"
                );
            } else {
                let expected = format!("wallet error: {code}: {refusal}");
                assert_eq!(failure.to_string(), expected, "{case}");
                assert_eq!(std::fs::read(&journal).unwrap(), saved, "{case}");
            }
            let unchanged = std::fs::read(config.state_dir.join("note_state.json")).unwrap();
            assert_eq!(unchanged, note, "{case}");
            server.abort();
        }
    }
}

#[cfg(test)]
mod oa_session_recovery_tests {
    use super::*;
    use axum::{extract::State, routing::get, Json, Router};
    use serde_json::json;
    use zkapi_client::journal::PendingRequestJournal;
    use zkapi_proof::compact::{rerandomize, server_update, CompactSigner};
    use zkapi_types::wire::CurvePointWire;

    #[tokio::test]
    async fn session_events_only_follow_verified_recovery_and_never_repeat() {
        for charge in [0u128, 7] {
            let directory = tempfile::tempdir().unwrap();
            let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let config = AuthConfig {
                state_dir: directory.path().to_path_buf(),
                protocol_version: 2,
                chain_id: 1,
                request_charge_cap: 100,
                state_signing_key: signer.public_key(),
                protocol_server_url: format!("http://{}", listener.local_addr().unwrap()),
                ..Default::default()
            };
            let mut wallet = load_wallet(&config).unwrap();
            wallet
                .confirm_deposit(Felt252::from_u64(42), 7, 1000, 4_000_000_000)
                .unwrap();
            let note = wallet.state().unwrap();
            let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
            let anonymous = rerandomize(
                &CurvePointWire {
                    x: note.current_commitment_x,
                    y: note.current_commitment_y,
                },
                &Felt252::ONE,
            )
            .unwrap();
            let next_commitment = server_update(&anonymous, charge, &Felt252::ONE).unwrap();
            let next_anchor = core_v2::next_anchor(&nullifier);
            let message = core_v2::state_message(
                note.protocol_version,
                note.chain_id,
                &note.contract_address,
                &next_commitment.x,
                &next_commitment.y,
                &next_anchor,
            );
            let payload =
                json!({"type":"oa_org_ephemeral_lease_settlement", "secret":"receipt-metadata"})
                    .to_string();
            let response = RequestResponseV2 {
                status: "finalized".into(),
                client_request_id: "receipt-session".into(),
                request_nullifier: nullifier,
                response_code: 200,
                response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
                response_payload: payload,
                charge_applied: charge,
                next_commitment,
                next_anchor,
                blind_delta_srv: Felt252::ONE,
                next_state_signature: signer.sign(&message),
                policy_reason_code: None,
                policy_evidence_hash: None,
            };
            PendingRequestJournal::write(
                &config.state_dir.join("pending_journal.json"),
                &PendingRequestJournal {
                    exists: true,
                    client_request_id: response.client_request_id.clone(),
                    nullifier,
                    payload_hash: Felt252::ONE,
                    user_rerandomization: Felt252::ONE,
                    created_at_ms: 1,
                    prepared_request: None,
                },
            )
            .unwrap();
            let reply = Arc::new(Mutex::new(
                json!({"status":"pending","nullifier_status":"reserved"}),
            ));
            let router = Router::new()
                .route(
                    "/v2/requests/receipt-session",
                    get(|State(reply): State<Arc<Mutex<Value>>>| async move {
                        Json(reply.lock().unwrap().clone())
                    }),
                )
                .with_state(reply.clone());
            let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
            let service = AuthService::new(config.clone()).unwrap();
            service
                .oa_session_events
                .started(&response.client_request_id);
            assert!(!service.recover().await.unwrap().recovered);
            for failure in ["identity", "hash", "signature"] {
                let mut invalid = response.clone();
                match failure {
                    "identity" => invalid.client_request_id = "another-request".into(),
                    "hash" => invalid.response_payload = "{}".into(),
                    _ => invalid.next_state_signature.s = Felt252::ZERO,
                }
                *reply.lock().unwrap() = json!({"status":"finalized","nullifier_status":"finalized","request_response":invalid});
                assert!(service.recover().await.is_err(), "{failure}");
                let snapshot = serde_json::to_value(service.oa_session_events()).unwrap();
                assert_eq!(snapshot["events"].as_array().unwrap().len(), 1);
                assert!(config.state_dir.join("pending_journal.json").exists());
            }
            *reply.lock().unwrap() = json!({"status":"finalized","nullifier_status":"finalized","request_response":response});
            // Two observers race recovery. The wallet mutex must produce just
            // one signed settlement event before either can issue new access.
            let (first, second) = tokio::join!(service.recover(), service.recover());
            assert_ne!(first.unwrap().recovered, second.unwrap().recovered);
            let snapshot = serde_json::to_value(service.oa_session_events()).unwrap();
            let events = snapshot["events"].as_array().unwrap();
            assert_eq!(events.len(), 2);
            assert_eq!(events[0]["kind"], "started");
            assert_eq!(events[1]["kind"], "settled");
            assert_eq!(events[0]["session_id"], events[1]["session_id"]);
            assert_eq!(events[1]["charge_units"], charge.to_string());
            assert_eq!(events[1]["balance_units"], (1000 - charge).to_string());
            assert!(!snapshot.to_string().contains("receipt-metadata"));
            assert!(!snapshot.to_string().contains("receipt-session"));
            assert!(!config.state_dir.join("pending_journal.json").exists());
            server.abort();
        }
    }
}

#[cfg(test)]
mod oa_interrupted_provisioning_tests {
    use super::*;
    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use zkapi_client::journal::PendingRequestJournal;
    use zkapi_proof::compact::{rerandomize, server_update, CompactSigner};
    use zkapi_types::wire::CurvePointWire;

    struct Replies {
        request: Value,
        key: Value,
        lease: Value,
        response: RequestResponseV2,
        finalized: bool,
        reject: bool,
        settle_cancels: bool,
        unavailable: bool,
        withhold_receipt: bool,
        replay_lost_key: bool,
        verifier_valid: bool,
        events: Vec<&'static str>,
    }
    async fn fixture() -> (
        tempfile::TempDir,
        Arc<AuthService>,
        Arc<Mutex<Replies>>,
        tokio::task::JoinHandle<()>,
    ) {
        let directory = tempfile::tempdir().unwrap();
        let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            request_charge_cap: 400_000,
            state_signing_key: signer.public_key(),
            protocol_server_url: url.clone(),
            oa_verifier_url: url.clone(),
            openrouter_inference_base: "https://openrouter.ai/api/v1".into(),
            request_mode: RequestMode::DirectOpenrouter,
            require_oa_org_key_source: true,
            billing_asset: "native_eth".into(),
            billing_unit: "gwei".into(),
            native_asset_wei_per_unit: "1000000000".into(),
            native_price_feed_address: format!("0x{}", "12".repeat(20)),
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, 1_500_000, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::ONE,
        )
        .unwrap();
        // This intentionally expired quote must be replayed byte-for-byte.
        let quote = json!({"asset":"native_eth","units_per_eth":1_000_000_000,"chain_id":1,
            "feed_address":config.native_price_feed_address,"round_id":"123","answer":"250000000000",
            "decimals":8,"updated_at":1,"expires_at":3601});
        let payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        let request = ApiRequestV2 {
            client_request_id: "interrupted".into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: config.contract_address,
                active_root: Felt252::ZERO,
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1,
                solvency_bound: 400_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: anonymous.x,
                anonymous_commitment_y: anonymous.y,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "saved-proof-only".into(),
            },
        };
        PendingRequestJournal::write(
            &config.state_dir.join("pending_journal.json"),
            &PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::ONE,
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            },
        )
        .unwrap();
        let next_commitment = server_update(&anonymous, 0, &Felt252::ONE).unwrap();
        let next_anchor = core_v2::next_anchor(&nullifier);
        let message = core_v2::state_message(
            note.protocol_version,
            note.chain_id,
            &note.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let settled_payload =
            json!({"type":"oa_org_unissued_lease_cancellation", "billing_quote":quote}).to_string();
        let response = RequestResponseV2 {
            status: "finalized".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(settled_payload.as_bytes()),
            response_payload: settled_payload,
            charge_applied: 0,
            next_commitment,
            next_anchor,
            blind_delta_srv: Felt252::ONE,
            next_state_signature: signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        };
        let expires = now_seconds() + 300;
        let lease = json!({"status":"provisioning","client_request_id":"interrupted","issued_at":1,
            "expires_at":expires,"settle_after":expires+5,"spending_limit_usd":1.0});
        let mut key = lease.clone();
        key["status"] = json!("active");
        key["api_key"] = json!("private-recovered-key");
        key["openrouter_api_base"] = json!(config.openrouter_inference_base);
        key["valid_for_seconds"] = json!(300);
        key["billing_quote"] = quote;
        key["key_source"] = json!("oa_org");
        key["verification"] = json!({"station_id":"test-station","key_valid_till":expires,
            "station_signature":"synthetic-signature","org_signature":"synthetic-org-signature","verifier_url":url});
        let replies = Arc::new(Mutex::new(Replies {
            request: serde_json::to_value(request).unwrap(),
            key,
            lease,
            response,
            finalized: false,
            reject: false,
            settle_cancels: false,
            unavailable: false,
            withhold_receipt: false,
            replay_lost_key: false,
            verifier_valid: true,
            events: Vec::new(),
        }));
        let router = Router::new()
            .route("/v2/openrouter/leases/interrupted", get(|State(state):State<Arc<Mutex<Replies>>>|async move {
                let mut state=state.lock().unwrap(); state.events.push("status"); Json(state.lease.clone())
            }).post(|State(state):State<Arc<Mutex<Replies>>>,Json(request):Json<Value>|async move {
                let mut state=state.lock().unwrap(); assert_eq!(request,state.request);
                state.events.push("retire");
                if state.lease["status"]=="provisioning" && !state.settle_cancels {
                    return (axum::http::StatusCode::CONFLICT,Json(json!({"status":"error","client_request_id":"interrupted","error_code":"lease_pending","error_message":"provisioning","retriable":true})));
                }
                state.finalized=true; state.lease["status"]=json!("finalized");
                (axum::http::StatusCode::OK,Json(state.lease.clone()))
            }))
            .route("/v2/openrouter/leases", post(|State(state):State<Arc<Mutex<Replies>>>,Json(request):Json<Value>|async move {
                let mut state=state.lock().unwrap(); assert_eq!(request,state.request);
                state.events.push("replay");
                if state.unavailable {
                    if state.replay_lost_key {state.lease["status"]=json!("active");}
                    (axum::http::StatusCode::SERVICE_UNAVAILABLE,Json(json!({"status":"error","client_request_id":"interrupted","error_code":"unavailable","error_message":"ambiguous provider response","retriable":true})))
                } else if state.reject {
                    state.finalized=true; state.lease["status"]=json!("finalized");
                    (axum::http::StatusCode::BAD_REQUEST,Json(json!({"status":"error","client_request_id":"interrupted","error_code":"oa_key_policy_rejected","error_message":"policy rejection","retriable":false})))
                } else {
                    state.lease["status"]=json!("active");
                    (axum::http::StatusCode::OK,Json(state.key.clone()))
                }
            }))
            .route("/submit_key", post(|State(state):State<Arc<Mutex<Replies>>>,Json(request):Json<Value>|async move {
                let mut state=state.lock().unwrap(); state.events.push("verify");
                assert_eq!(request["api_key"],"private-recovered-key");
                let hash = format!("{:x}",Sha256::digest(b"private-recovered-key"));
                Json(json!({"status":"verified","station_id":"test-station",
                    "key_hash":if state.verifier_valid {hash[..16].to_string()} else {"00".repeat(8)}}))
            }))
            .route("/v2/requests/interrupted", get(|State(state):State<Arc<Mutex<Replies>>>|async move {
                let mut state=state.lock().unwrap(); state.events.push("recover");
                Json(if state.finalized && !state.withhold_receipt {json!({"status":"finalized","nullifier_status":"finalized","request_response":state.response})}
                    else {json!({"status":"pending","nullifier_status":"reserved"})})
            }))
            .with_state(replies.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let service = AuthService::new(config).unwrap();
        (directory, service, replies, server)
    }

    #[tokio::test]
    async fn provisioning_settlement_replays_verifies_and_retires_without_exposing_key() {
        let (directory, service, replies, server) = fixture().await;
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request);
        assert_eq!(status.note.unwrap().current_balance, 1_500_000);
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "replay", "verify", "retire", "recover"]
        );
        assert!(service.direct_lease.lock().await.is_none());
        assert!(!directory.path().join("oa-issued-leases").exists());
        assert!(!directory.path().join("pending_journal.json").exists());
        assert!(
            !std::fs::read_to_string(directory.path().join("note_state.json"))
                .unwrap()
                .contains("private-recovered-key")
        );
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_is_installed_only_from_the_matching_signed_response() {
        for failure in ["none", "identity", "signature", "quote"] {
            let (directory, service, replies, server) = fixture().await;
            let before = std::fs::read(directory.path().join("pending_journal.json")).unwrap();
            {
                let mut replies = replies.lock().unwrap();
                replies.reject = true;
                match failure {
                    "identity" => replies.response.client_request_id = "other".into(),
                    "signature" => replies.response.next_state_signature.s = Felt252::ZERO,
                    "quote" => {
                        replies.response.response_payload = "{}".into();
                        replies.response.response_hash =
                            zkapi_types::canonical_response_hash(b"{}");
                    }
                    _ => (),
                }
            }
            let result = service.settle_for_withdrawal().await;
            if failure == "none" {
                assert!(!result.unwrap().pending_request);
                assert!(!directory.path().join("pending_journal.json").exists());
            } else {
                assert!(result.is_err(), "{failure}");
                assert_eq!(
                    std::fs::read(directory.path().join("pending_journal.json")).unwrap(),
                    before
                );
            }
            assert_eq!(
                replies.lock().unwrap().events,
                ["status", "retire", "replay", "recover"]
            );
            assert!(service.direct_lease.lock().await.is_none());
            server.abort();
        }
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // the lock is test bookkeeping, held across a loop iteration
    async fn invalid_replayed_key_preserves_authorization_without_retirement_or_inference() {
        for failure in ["identity", "cap", "quote", "origin", "evidence", "verifier"] {
            let (directory, service, replies, server) = fixture().await;
            let journal = std::fs::read(directory.path().join("pending_journal.json")).unwrap();
            let note = std::fs::read(directory.path().join("note_state.json")).unwrap();
            {
                let mut replies = replies.lock().unwrap();
                match failure {
                    "identity" => replies.key["client_request_id"] = json!("other"),
                    "cap" => replies.key["spending_limit_usd"] = json!(20.0),
                    "quote" => replies.key["billing_quote"]["round_id"] = json!("124"),
                    "origin" => {
                        replies.key["openrouter_api_base"] = json!("https://other.example/api/v1")
                    }
                    "evidence" => replies.key["verification"] = Value::Null,
                    _ => replies.verifier_valid = false,
                }
            }
            assert!(service.settle_for_withdrawal().await.is_err(), "{failure}");
            let replies = replies.lock().unwrap();
            assert_eq!(
                replies
                    .events
                    .iter()
                    .filter(|event| **event == "retire")
                    .count(),
                1
            );
            assert!(!replies.events.contains(&"recover"));
            assert_eq!(
                std::fs::read(directory.path().join("pending_journal.json")).unwrap(),
                journal
            );
            assert_eq!(
                std::fs::read(directory.path().join("note_state.json")).unwrap(),
                note
            );
            assert!(service.direct_lease.lock().await.is_none());
            assert!(!directory.path().join("oa-issued-leases").exists());
            server.abort();
        }
    }

    #[tokio::test]
    async fn initial_policy_rejection_installs_cancellation_without_retrying_issuance() {
        let (directory, service, replies, server) = fixture().await;
        replies.lock().unwrap().reject = true;
        assert!(service
            .issue_direct_openrouter_lease("initial".into(), Some(1_000_000))
            .await
            .is_err());
        assert_eq!(replies.lock().unwrap().events, ["replay", "recover"]);
        assert!(!directory.path().join("pending_journal.json").exists());
        assert!(service.direct_lease.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn server_side_cancellation_does_not_replay_or_verify_a_key() {
        let (directory, service, replies, server) = fixture().await;
        replies.lock().unwrap().settle_cancels = true;
        assert!(
            !service
                .settle_for_withdrawal()
                .await
                .unwrap()
                .pending_request
        );
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "recover"]
        );
        assert!(!directory.path().join("pending_journal.json").exists());
        assert!(service.direct_lease.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn ambiguous_provisioning_preserves_the_original_request_and_note() {
        let (directory, service, replies, server) = fixture().await;
        replies.lock().unwrap().unavailable = true;
        let journal = std::fs::read(directory.path().join("pending_journal.json")).unwrap();
        let note = std::fs::read(directory.path().join("note_state.json")).unwrap();
        assert!(matches!(
            service.settle_for_withdrawal().await,
            Err(AuthError::LeasePending(_))
        ));
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "replay", "recover", "status"]
        );
        assert_eq!(
            std::fs::read(directory.path().join("pending_journal.json")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(directory.path().join("note_state.json")).unwrap(),
            note
        );
        assert!(service.direct_lease.lock().await.is_none());
        server.abort();
    }

    #[tokio::test]
    async fn concurrent_settlements_replay_once_and_finalized_without_key_recovers() {
        let (_directory, service, replies, server) = fixture().await;
        let (first, second) = tokio::join!(
            service.settle_for_withdrawal(),
            service.settle_for_withdrawal()
        );
        assert!(!first.unwrap().pending_request);
        assert!(!second.unwrap().pending_request);
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "replay", "verify", "retire", "recover"]
        );
        server.abort();

        let (directory, service, replies, server) = fixture().await;
        {
            let mut replies = replies.lock().unwrap();
            replies.finalized = true;
            replies.lease["status"] = json!("finalized");
            // Lease metadata has no key_hash, plaintext key or provider receipt.
        }
        assert!(
            !service
                .settle_for_withdrawal()
                .await
                .unwrap()
                .pending_request
        );
        assert_eq!(replies.lock().unwrap().events, ["status", "recover"]);
        assert!(!directory.path().join("pending_journal.json").exists());
        server.abort();
    }

    #[tokio::test]
    async fn finalized_retirement_without_signed_receipt_never_replays_issuance() {
        let (directory, service, replies, server) = fixture().await;
        {
            let mut replies = replies.lock().unwrap();
            replies.settle_cancels = true;
            replies.withhold_receipt = true;
        }
        let journal = std::fs::read(directory.path().join("pending_journal.json")).unwrap();
        let note = std::fs::read(directory.path().join("note_state.json")).unwrap();
        assert!(matches!(
            service.settle_for_withdrawal().await,
            Err(AuthError::LeasePending(_))
        ));
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "recover"]
        );
        assert_eq!(
            std::fs::read(directory.path().join("pending_journal.json")).unwrap(),
            journal
        );
        assert_eq!(
            std::fs::read(directory.path().join("note_state.json")).unwrap(),
            note
        );
        replies.lock().unwrap().withhold_receipt = false;
        assert!(
            !service
                .settle_for_withdrawal()
                .await
                .unwrap()
                .pending_request
        );
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "recover", "status", "recover"]
        );
        server.abort();
    }

    #[tokio::test]
    async fn failed_replay_with_active_server_metadata_retires_without_a_local_key() {
        let (directory, service, replies, server) = fixture().await;
        {
            let mut replies = replies.lock().unwrap();
            replies.unavailable = true;
            replies.replay_lost_key = true;
        }
        assert!(
            !service
                .settle_for_withdrawal()
                .await
                .unwrap()
                .pending_request
        );
        assert_eq!(
            replies.lock().unwrap().events,
            ["status", "retire", "replay", "recover", "status", "retire", "recover"]
        );
        assert!(service.direct_lease.lock().await.is_none());
        assert!(!directory.path().join("oa-issued-leases").exists());
        assert!(!directory.path().join("pending_journal.json").exists());
        server.abort();
    }
}
