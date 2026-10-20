//! Wire format types for HTTP APIs.
//!
//! Field elements use 0x-prefixed lowercase hex strings; curve points have
//! x and y fields. Proofs contain base64-encoded Groth16 proofs as eight
//! 32-byte big-endian coordinates. Integer fields retain the existing v2 serde
//! representation. Request types are unchanged from circuit
//! `zkapi-v2-note-bound-v1`; the withdrawal and clearance types are the V2C
//! (`zkapi-v2-concession-v1`) statements.

use serde::{Deserialize, Serialize};

use crate::Felt252;

/// Supported proof backend on the wire.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProofBackendWire {
    Groth16Bn254,
}

/// Compact Groth16 proof artifact. Public inputs are carried in the enclosing
/// request and are verified directly; there is no separately trusted output
/// hash or witness envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Groth16ProofWire {
    pub backend: ProofBackendWire,
    /// Base64 of 256 bytes: `A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y`,
    /// each a canonical 32-byte big-endian BN254 base-field coordinate.
    pub proof: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiRequestV2 {
    pub client_request_id: String,
    pub payload: String,
    pub payload_hash: Felt252,
    pub public_inputs: crate::RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// Prompt-free payload authorized by a client when opening a short-lived
/// OpenRouter lease. The server rejects extra fields so this protocol message
/// cannot accidentally carry an LLM prompt or response.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OpenRouterLeaseAuthorization {
    pub mode: String,
    pub version: u16,
}

impl Default for OpenRouterLeaseAuthorization {
    fn default() -> Self {
        Self {
            mode: "openrouter_ephemeral_lease".to_string(),
            version: 1,
        }
    }
}

/// A freshly-issued, short-lived OpenRouter key. The plaintext key is only
/// present in this live response; server recovery responses never contain it.
#[derive(Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseResponse {
    pub status: String,
    pub client_request_id: String,
    pub api_key: String,
    /// OpenRouter inference base, normally `https://openrouter.ai/api/v1`.
    pub openrouter_api_base: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub valid_for_seconds: u64,
    /// The server will not finalize usage before this UNIX timestamp.
    pub settle_after: u64,
    pub spending_limit_usd: f64,
}

/// Non-secret lease metadata, safe to return during crash recovery. It never
/// contains the plaintext OpenRouter runtime key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpenRouterLeaseStatusResponse {
    /// provisioning, active, retiring, disabled, revoking, finalized, or
    /// cancelled (a corrupt server record that was never signed).
    pub status: String,
    pub client_request_id: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub charge_applied: Option<u128>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// How a finalized charge was determined: "measured", "clamped",
    /// "worst_case" or "unissued".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub charge_basis: Option<String>,
    /// UNIX time by which a pending lease is finalized, at worst at the
    /// request's solvency bound. Absent once the lease is terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_deadline: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestResponseV2 {
    pub status: String,
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub response_code: u16,
    pub response_payload: String,
    pub response_hash: Felt252,
    pub charge_applied: u128,
    pub next_commitment: CurvePointWire,
    pub next_anchor: Felt252,
    pub blind_delta_srv: Felt252,
    pub next_state_signature: crate::SchnorrSignature,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason_code: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_evidence_hash: Option<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClearanceResponseV2 {
    pub status: String,
    pub withdrawal_nullifier: Felt252,
    pub signature: crate::SchnorrSignature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryResponseV2 {
    pub status: String,
    pub nullifier_status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_response: Option<RequestResponseV2>,
    /// For a reserved lease request: the UNIX time by which the server
    /// finalizes it. Wait for that response rather than escaping.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settlement_deadline: Option<u64>,
}

/// A curve point serialized as {x, y} hex fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CurvePointWire {
    pub x: Felt252,
    pub y: Felt252,
}

/// Error response from the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub status: String,
    pub client_request_id: String,
    pub error_code: String,
    pub error_message: String,
    pub retriable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_root: Option<Felt252>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_time_ms: Option<u64>,
    /// Present for retriable throttling errors and mirrored in the HTTP
    /// `Retry-After` header when the transport supports response headers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_seconds: Option<u64>,
}

/// Clearance request for a mutual close on a `zkapi-v2-concession-v1`
/// deployment. The ownership proof is required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClearanceRequestV2C {
    pub withdrawal_nullifier: Felt252,
    pub ownership_proof: ClearanceOwnershipProofV2C,
}

/// A kind-2 (ownership) withdrawal proof for the nullifier being cleared:
/// `kind == 2`, `next_nullifier == 0`, `conceded == 0`, `destination == 0`,
/// `withdrawal_nullifier` equal to the cleared nullifier and a fresh
/// `valid_until`. It publishes no successor nullifier and no destination and
/// is rejected by every vault entry point.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClearanceOwnershipProofV2C {
    pub public_inputs: crate::WithdrawalPublicInputsV2C,
    pub proof: Groth16ProofWire,
}

/// `payload.mode` of a close-relay fee request.
pub const CLOSE_RELAY_FEE_MODE: &str = "close_relay_fee";
/// `payload.version` of a close-relay fee request.
pub const CLOSE_RELAY_FEE_VERSION: u16 = 1;
/// Domain of [`close_relay_ticket_hash`].
pub const CLOSE_RELAY_TICKET_DOMAIN: &[u8] = b"zkapi:v2c:close-relay-ticket\0";

/// The prompt-free payload of a close-relay fee request
/// (`POST /v2/withdraw/relay/fee`): one metered request at the note's current
/// state whose charge is exactly the relay fee. Its successor carries the fee
/// as spent, so the cooperative close proved from that successor pays the fee
/// inside the treasury share (`deposit - finalBalance`) and needs no circuit
/// change. The ticket links the paid fee to exactly one relay submission:
/// only the holder of the 32-byte secret behind `ticket_hash` can redeem it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloseRelayFeeAuthorization {
    /// Always [`CLOSE_RELAY_FEE_MODE`].
    pub mode: String,
    /// Always [`CLOSE_RELAY_FEE_VERSION`].
    pub version: u16,
    /// The fee the client accepts, in the vault's native units (gwei), as a
    /// decimal string. It must equal the server's current terms exactly.
    pub fee_units: String,
    /// `0x` and 64 lowercase hex digits: [`close_relay_ticket_hash`] of the
    /// client's ticket secret.
    pub ticket_hash: String,
}

impl CloseRelayFeeAuthorization {
    /// The canonical payload for `fee_units` and the ticket secret's hash.
    pub fn new(fee_units: u128, ticket_secret: &[u8; 32]) -> Self {
        Self {
            mode: CLOSE_RELAY_FEE_MODE.to_string(),
            version: CLOSE_RELAY_FEE_VERSION,
            fee_units: fee_units.to_string(),
            ticket_hash: format!("0x{}", hex32(&close_relay_ticket_hash(ticket_secret))),
        }
    }
}

/// `keccak256(CLOSE_RELAY_TICKET_DOMAIN || secret)`: the public handle of a
/// relay ticket. The secret itself is sent only with the relay submission.
pub fn close_relay_ticket_hash(secret: &[u8; 32]) -> [u8; 32] {
    use sha3::{Digest, Keccak256};
    let mut digest = Keccak256::new();
    digest.update(CLOSE_RELAY_TICKET_DOMAIN);
    digest.update(secret);
    digest.finalize().into()
}

fn hex32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// A finished cooperative close handed to the operator's relay
/// (`POST /v2/withdraw/relay`): the kind-1 statement and its proof exactly as
/// `mutualClose` takes them, and the secret of the ticket whose fee paid for
/// it. The payout stays bound by the proof: the relay can only submit it or
/// not.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CloseRelaySubmissionV2C {
    pub public_inputs: crate::WithdrawalPublicInputsV2C,
    pub proof: Groth16ProofWire,
    /// `0x` and 64 hex digits.
    pub ticket_secret: String,
}

/// The relay's view of one submitted close (`GET /v2/withdraw/relay/{N}`).
///
/// `status` is one of
/// * `queued`: accepted, waiting for a batch;
/// * `submitted`: in a relay transaction that has not been confirmed yet;
/// * `landed`: the vault's `MutualClose` for this nullifier was emitted in the
///   relay's transaction (`transaction_hash`);
/// * `closed`: the note was closed by another transaction (the client's own
///   submission, or anyone's);
/// * `failed`: the relay will never submit it again (for example the payout
///   push to the destination failed, or the vault refused it): submit it
///   yourself;
/// * `expired`: it came too close to its `valid_until` before landing.
///
/// Neither `landed` nor `closed` replaces the client's own check of the
/// vault's `MutualClose` event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloseRelayStatusResponse {
    pub status: String,
    pub withdrawal_nullifier: crate::Felt252,
    pub note_id: u32,
    pub valid_until: u64,
    pub queued_at: u64,
    pub updated_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_number: Option<u64>,
    /// Why a close failed or was closed elsewhere, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// True when the client should submit the close itself now (`failed`
    /// or `expired`).
    pub self_submit: bool,
}

/// The relay's terms (`GET /v2/withdraw/relay/terms`). When `enabled` is
/// false the other fields are absent and clients submit their closes
/// themselves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CloseRelayTermsResponse {
    pub enabled: bool,
    /// Decimal native units (gwei) of the one fee request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fee_units: Option<String>,
    /// A submission's `valid_until` must be at least this far ahead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_validity_seconds: Option<u64>,
    /// The relay sends a batch once this many closes are queued...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_target: Option<u64>,
    /// ...or once the oldest has waited this long...
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flush_age_seconds: Option<u64>,
    /// ...or at once when a close comes within this many seconds of its
    /// `valid_until`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urgent_margin_seconds: Option<u64>,
    /// No relay transaction is sent for a close this near its `valid_until`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cutoff_seconds: Option<u64>,
    /// The `ZkApiExitBatcher` the relay submits through.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_batcher: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ClearanceRequestV2C, ErrorResponse};

    #[test]
    fn clearance_request_requires_an_exact_v2c_ownership_proof() {
        let zero_destination = [0u8; 20];
        let legacy_destination = [17u8; 20];
        let inputs = serde_json::json!({
            "protocol_version":2, "chain_id":11155111, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4",
            "clearance_signing_key_x":"0x5", "clearance_signing_key_y":"0x6",
            "note_id":7, "final_balance":1950000, "destination":zero_destination,
            "withdrawal_nullifier":"0x7", "kind":2, "next_nullifier":"0x0", "conceded":0,
            "valid_until":2000003600u64
        });
        let proof = serde_json::json!({"backend":"groth16_bn254","proof":"AA=="});
        let body = serde_json::json!({"withdrawal_nullifier":"0x7",
            "ownership_proof":{"public_inputs":inputs, "proof":proof}});
        let parsed: ClearanceRequestV2C = serde_json::from_value(body.clone()).unwrap();
        let ownership = &parsed.ownership_proof.public_inputs;
        assert_eq!(ownership.final_balance, 1_950_000);
        assert_eq!(ownership.kind, 2);
        assert_eq!(ownership.valid_until, 2_000_003_600);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), body);

        // The ownership proof is mandatory.
        assert!(
            serde_json::from_str::<ClearanceRequestV2C>(r#"{"withdrawal_nullifier":"0x7"}"#)
                .is_err()
        );
        // Unknown fields are rejected at every level.
        let mut extra = body.clone();
        extra["prompt"] = "not allowed".into();
        assert!(serde_json::from_value::<ClearanceRequestV2C>(extra).is_err());
        let mut extra = body.clone();
        extra["ownership_proof"]["prompt"] = "not allowed".into();
        assert!(serde_json::from_value::<ClearanceRequestV2C>(extra).is_err());
        let mut extra = body.clone();
        extra["ownership_proof"]["public_inputs"]["has_clearance"] = false.into();
        assert!(serde_json::from_value::<ClearanceRequestV2C>(extra).is_err());

        // A legacy 14-field withdrawal statement and a request statement are rejected.
        let legacy = serde_json::json!({
            "protocol_version":2, "chain_id":11155111, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4",
            "clearance_signing_key_x":"0x5", "clearance_signing_key_y":"0x6",
            "note_id":7, "final_balance":1950000, "destination":legacy_destination,
            "withdrawal_nullifier":"0x7", "has_clearance":false, "withdrawal_tag":"0x8"
        });
        let mut legacy_body = body.clone();
        legacy_body["ownership_proof"]["public_inputs"] = legacy;
        assert!(serde_json::from_value::<ClearanceRequestV2C>(legacy_body).is_err());
        let request_statement = serde_json::json!({
            "protocol_version":2, "chain_id":1, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4", "request_time":5,
            "solvency_bound":6, "request_nullifier":"0x7", "authorization_tag":"0x8",
            "anonymous_commitment_x":"0x9", "anonymous_commitment_y":"0xa"
        });
        let mut request_proof = body;
        request_proof["ownership_proof"]["public_inputs"] = request_statement;
        assert!(serde_json::from_value::<ClearanceRequestV2C>(request_proof).is_err());
    }

    #[test]
    fn legacy_error_response_without_retry_delay_remains_compatible() {
        let response: ErrorResponse = serde_json::from_str(
            r#"{
                "status":"error",
                "client_request_id":"request-1",
                "error_code":"internal_error",
                "error_message":"temporary failure",
                "retriable":true
            }"#,
        )
        .unwrap();

        assert_eq!(response.retry_after_seconds, None);
        let serialized = serde_json::to_value(response).unwrap();
        assert!(serialized.get("retry_after_seconds").is_none());
    }

    /// The cross-language vector of the ticket hash (the Go and JS clients
    /// pin the same value) and the strict fee payload and submission.
    #[test]
    fn close_relay_ticket_hash_and_payloads_are_pinned_and_strict() {
        use super::{close_relay_ticket_hash, CloseRelayFeeAuthorization, CloseRelaySubmissionV2C};
        assert_eq!(
            close_relay_ticket_hash(&[0x11; 32]),
            [
                0x09, 0x1e, 0xa4, 0x39, 0x25, 0x9b, 0x6c, 0x58, 0x73, 0x7d, 0xd5, 0x12, 0xe9, 0x17,
                0x7a, 0x15, 0x36, 0xe0, 0x8c, 0xfe, 0xc8, 0xc2, 0x7c, 0xb5, 0xc2, 0xae, 0xcc, 0x45,
                0x24, 0x48, 0x0f, 0xfe
            ]
        );
        let payload = CloseRelayFeeAuthorization::new(250_000, &[0x11; 32]);
        assert_eq!(
            serde_json::to_string(&payload).unwrap(),
            r#"{"mode":"close_relay_fee","version":1,"fee_units":"250000","ticket_hash":"0x091ea439259b6c58737dd512e9177a1536e08cfec8c27cb5c2aecc4524480ffe"}"#
        );
        let mut extra = serde_json::to_value(&payload).unwrap();
        extra["prompt"] = "not allowed".into();
        assert!(serde_json::from_value::<CloseRelayFeeAuthorization>(extra).is_err());

        let destination = [17u8; 20];
        let inputs = serde_json::json!({
            "protocol_version":2, "chain_id":11155111, "contract_address":"0x1", "active_root":"0x2",
            "state_signing_key_x":"0x3", "state_signing_key_y":"0x4",
            "clearance_signing_key_x":"0x5", "clearance_signing_key_y":"0x6",
            "note_id":7, "final_balance":1950000, "destination":destination,
            "withdrawal_nullifier":"0x7", "kind":1, "next_nullifier":"0x0", "conceded":0,
            "valid_until":2000003600u64
        });
        let body = serde_json::json!({"public_inputs":inputs,
            "proof":{"backend":"groth16_bn254","proof":"AA=="},
            "ticket_secret":format!("0x{}", "11".repeat(32))});
        let parsed: CloseRelaySubmissionV2C = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(parsed.public_inputs.kind, 1);
        let mut extra = body;
        extra["fee"] = 1.into();
        assert!(serde_json::from_value::<CloseRelaySubmissionV2C>(extra).is_err());
    }
}
