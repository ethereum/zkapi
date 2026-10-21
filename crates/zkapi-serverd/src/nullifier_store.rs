//! SQLite-backed nullifier and transcript store.
//!
//! Stores nullifier reservations, the append-only request evidence and the
//! transcripts of signed successors. A request nullifier progresses through
//!
//! ```text
//! Reserved --settle--> Reserved + settled_charge --sign--> Finalized
//!                                  |  (consumed on chain)
//!                                  +--> exit_deferred_since --> Finalized (exit defeated)
//!                                                          \--> ExitedUnsigned (terminal)
//! ```
//!
//! and a withdrawal nullifier is reserved for good as ClearanceReserved. The
//! charge of a request is written once, when it settles; its successor is
//! signed at most once, only while its nullifier is unspent on chain (O7).

use rusqlite::{params, Connection, OpenFlags, OptionalExtension, TransactionBehavior};
use sha3::{Digest, Keccak256};
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use zkapi_core::v2 as core;
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::wire::{ApiRequestV2, CurvePointWire};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, Felt252, RequestPublicInputsV2,
    SchnorrSignature,
};

use crate::error::ServerError;

/// The state of a nullifier row (column `nullifiers.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NullifierStatus {
    /// A request is reserved at this nullifier. Once `settled_charge` is set,
    /// its charge is final and only its successor's signature is pending.
    Reserved,
    /// The successor of the request at this nullifier is signed.
    Finalized,
    /// Reserved for good by a mutual-close clearance.
    ClearanceReserved,
    /// Terminal: the request settled, but its nullifier stayed consumed on
    /// chain by an exit that was not defeated within the deferral window, so
    /// no successor is ever signed for it (O7).
    ExitedUnsigned,
}

/// A request's final charge, persisted on its reservation before its
/// successor is signed (`NullifierStore::settle_openrouter_lease`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledCharge {
    pub charge: u128,
    /// "measured", "clamped", "worst_case", "unissued" or "operator_conceded".
    pub basis: String,
    pub response_code: u16,
    /// The settlement payload the successor's response will carry.
    pub response_payload: String,
    pub settled_at: u64,
}

/// What the settlement of a lease found (`settle_openrouter_lease`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettleOutcome {
    /// The charge is persisted (or was already, and is kept) and the lease
    /// row is finalized; the successor still has to be signed.
    Settled(SettledCharge),
    /// The lease row no longer satisfied its guard; nothing was written.
    LeaseChanged,
}

/// One row of the append-only `request_evidence` table: a request proof the
/// server accepted (or a verified copy restored by `--rebind`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestEvidence {
    pub id: i64,
    pub nullifier: Felt252,
    pub client_request_id: String,
    pub solvency_bound: u128,
    pub public_inputs: RequestPublicInputsV2,
    /// The 256-byte Groth16 proof.
    pub proof: Vec<u8>,
    /// "reserve" or "rebind".
    pub source: String,
    pub created_at: u64,
}

/// A transcript record stored in the database.
#[derive(Debug, Clone)]
pub struct TranscriptRecord {
    pub nullifier: Felt252,
    pub status: NullifierStatus,
    pub reservation_kind: String,
    pub client_request_id: Option<String>,
    pub payload_hash: Option<Felt252>,
    pub charge_applied: Option<u128>,
    pub response_code: Option<u16>,
    pub response_payload: Option<String>,
    pub response_hash: Option<Felt252>,
    pub next_commitment_x: Option<Felt252>,
    pub next_commitment_y: Option<Felt252>,
    pub next_anchor: Option<Felt252>,
    pub blind_delta_srv: Option<Felt252>,
    pub next_state_sig: Option<SchnorrSignature>,
    pub policy_reason_code: Option<u32>,
    pub policy_evidence_hash: Option<Felt252>,
    pub proof_blob: Option<Vec<u8>>,
    pub request_inputs_json: Option<String>,
    /// Domain-separated digest of the complete canonical v2 API request.
    /// Reserved retries must match this before proof verification is skipped.
    pub api_request_binding: Option<String>,
    pub created_at: u64,
    pub finalized_at: Option<u64>,
    /// The final charge, written once when the request settles, before its
    /// successor is signed. Kept after signing.
    pub settled_charge: Option<u128>,
    pub settled_basis: Option<String>,
    pub settled_at: Option<u64>,
    /// First time the settled request's nullifier was found consumed on
    /// chain while its successor was due to be signed (O7).
    pub exit_deferred_since: Option<u64>,
}

impl TranscriptRecord {
    /// A reserved request whose charge is final and whose successor is not
    /// signed yet (possibly deferred).
    pub fn settled_unsigned(&self) -> bool {
        self.status == NullifierStatus::Reserved && self.settled_charge.is_some()
    }
}

/// Where a page of `settled_unsigned_requests` ended: the `(settled_at,
/// nullifier)` of its last row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SettledScanKey {
    settled_at: i64,
    nullifier: String,
}

impl SettledScanKey {
    pub(crate) fn of(record: &TranscriptRecord) -> Self {
        Self {
            settled_at: record.settled_at.map(sql_time).unwrap_or(0),
            nullifier: record.nullifier.to_hex(),
        }
    }
}

/// Whether an OA provisioning attempt can safely be cancelled without usage.
/// An absent key hash does not establish non-issuance: the upstream response
/// may have been lost after a key was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OaProvisioningOutcome {
    NotStarted,
    MayHaveIssued,
    ConfirmedUnissued,
}

impl OaProvisioningOutcome {
    fn from_db(value: &str) -> Self {
        match value {
            "not_started" => Self::NotStarted,
            "confirmed_unissued" => Self::ConfirmedUnissued,
            // Historical rows and unknown values must never enable a refund.
            _ => Self::MayHaveIssued,
        }
    }
}

/// Durable metadata for one prompt-private OpenRouter lease. The plaintext
/// runtime key is deliberately never stored.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseRecord {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub api_request: ApiRequestV2,
    /// Native OA requests use a deployment/proof-bound upstream namespace.
    /// Optional for decoding historical rows; new OA leases require a bound ID.
    pub oa_client_request_id: Option<String>,
    pub key_hash: Option<String>,
    pub key_source: String,
    pub(crate) oa_provisioning_outcome: OaProvisioningOutcome,
    pub status: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    pub usage_usd: Option<f64>,
    pub charge_applied: Option<u128>,
    pub last_error: Option<String>,
    /// Lease TTL frozen at creation; None for rows from before it was kept.
    pub ttl_seconds: Option<u64>,
    /// Write-once settlement deadline; None until first assigned.
    pub settlement_deadline_at: Option<u64>,
    /// Failed settlement attempts, never reset.
    pub settlement_attempts: u64,
    /// First failed settlement attempt, never reset by phase transitions.
    pub first_error_at: Option<u64>,
    /// "measured", "clamped", "worst_case", "unissued" or "operator_conceded"
    /// once finalized. Set earlier only on a lease committed to a zero
    /// settlement ("unissued", see `fence_unissued_settlement`) or whose
    /// charge the operator conceded when or after reopening it
    /// ("operator_conceded"): its key is never delivered from then on.
    pub charge_basis: Option<String>,
    /// Key provenance: Some(true) once the runtime key was returned to the
    /// client; Some(false) while it never was (including issuer-side
    /// activations); None for rows recorded without provenance.
    pub delivered: Option<bool>,
    pub updated_at: u64,
}

/// A new lease row; see `NullifierStore::create_openrouter_lease_bound`.
pub struct NewOpenRouterLease<'a> {
    pub request: &'a ApiRequestV2,
    pub key_source: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
    pub settle_after: u64,
    pub spending_limit_usd: f64,
    pub oa_client_request_id: Option<&'a str>,
    pub ttl_seconds: Option<u64>,
    /// Written once: never changed by later transitions.
    pub settlement_deadline_at: Option<u64>,
    /// Some(false) for issuance rows: delivered only once marked.
    pub delivered: Option<bool>,
}

/// An operator-visible record of a settlement that needs review: a clamped
/// or worst-case charge, a key that could not be deleted first, a corrupt
/// binding that was cancelled without signing, or such a lease reopened by
/// the operator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettlementReview {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub key_source: String,
    /// One of `SETTLEMENT_REVIEW_REASONS`.
    pub reason: String,
    pub charge_basis: Option<String>,
    /// Truncated to 500 characters when stored.
    pub detail: String,
    pub reported_usage_micro_usd: Option<u128>,
    pub charge_applied: Option<u128>,
    pub solvency_bound: u128,
}

/// The closed set of review reasons.
pub const SETTLEMENT_REVIEW_REASONS: &[&str] = &[
    "usage_clamped",
    "deadline_worst_case",
    "unsettleable_worst_case",
    "finalized_before_key_deletion",
    "binding_corrupt",
    "binding_reopened",
];

/// A stored review with its timestamps.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredSettlementReview {
    pub review: SettlementReview,
    pub created_at: u64,
    pub acknowledged_at: Option<u64>,
}

/// A provider key of a terminal direct lease still to be disabled and
/// deleted: by hash when known, otherwise by the lease's request-unique name.
#[derive(Debug, Clone, Copy)]
pub(crate) struct KeyCleanup<'a> {
    pub key_source: &'a str,
    pub key_hash: Option<&'a str>,
    pub key_name: &'a str,
}

/// What only one key source's credential can still settle or delete.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct KeySourceBacklog {
    /// Leases that may have been delivered and have no committed charge:
    /// only their source can measure their usage. (Never-delivered leases,
    /// and leases committed to a zero or conceded charge, finalize without
    /// any provider I/O, under any configuration.)
    pub unsettled_leases: u64,
    /// Queued deletions of keys that may still be usable (their lease has not
    /// expired, or is unknown). An expired key cannot be used any more.
    pub queued_key_deletions: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PendingKeyCleanup {
    pub client_request_id: String,
    pub key_source: String,
    pub key_hash: Option<String>,
    pub key_name: String,
    pub attempts: u64,
}

/// How a lease row is finalized; see `finalize_openrouter_lease_with`.
pub(crate) struct LeaseFinalization<'a> {
    pub usage_usd: f64,
    pub charge_applied: u128,
    pub charge_basis: &'a str,
    pub review: Option<&'a SettlementReview>,
    pub key_cleanup: Option<KeyCleanup<'a>>,
    pub guard: FinalizeGuard,
}

/// The lease rows a finalization may still update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FinalizeGuard {
    /// Any row that is not cancelled.
    NotCancelled,
    /// A zero settlement fenced by `fence_unissued_settlement`: still fenced,
    /// never delivered and, while provisioning, without a key.
    Unissued,
    /// A lease reopened with a concession: still marked `operator_conceded`.
    Conceded,
}

impl FinalizeGuard {
    /// The SQL condition on an `openrouter_leases` row.
    fn condition(self) -> &'static str {
        match self {
            Self::NotCancelled => "status != 'cancelled'",
            // Never a delivered key: the fence refused delivery from signing on.
            Self::Unissued => {
                "charge_basis = 'unissued' AND COALESCE(delivered, 0) = 0
                 AND ((status = 'provisioning' AND key_hash IS NULL)
                      OR status IN ('active', 'retiring', 'disabled', 'revoking'))"
            }
            Self::Conceded => {
                "charge_basis = 'operator_conceded'
                 AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')"
            }
        }
    }
}

/// What `NullifierStore::defer_signature` recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SignatureDeferral {
    /// Deferred since this first observation of the consumed nullifier.
    Deferred { since: u64 },
    /// Terminal: no successor is ever signed.
    ExitedUnsigned,
}

/// The deployment a server database serves (table `deployment_binding`, single
/// row id=1). `zkapi db init` writes it from the deployment manifest
/// (`source` "manifest"); serverd writes it (`source` "vault") only after
/// verifying its derived signing keys, the challenge period and the statement
/// identity against the vault and its adapter. serverd, zkapi-challenged and
/// zkapi-indexerd refuse a database bound to anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeploymentBinding {
    pub chain_id: u64,
    /// 0x followed by 40 lowercase hex digits.
    pub contract_address: String,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    pub challenge_period_seconds: u64,
    /// UNIX seconds of the successful vault read (or of `zkapi db init`).
    pub verified_at: u64,
    pub verified_block: Option<u64>,
    /// The statement this database serves (`zkapi_proof::compact::CIRCUIT_ID`).
    /// None only in a database bound before circuit identifiers were recorded,
    /// which served circuit `zkapi-v2-note-bound-v1`.
    pub circuit_id: Option<String>,
    /// The setup of its verifying keys (`dev`, `rehearsal` or `mpc-1`).
    pub setup_id: Option<String>,
    /// keccak256 of the request and withdrawal verifying keys without their
    /// headers (the adapter's `REQUEST_VK_HASH` and `WITHDRAWAL_VK_HASH`),
    /// 0x-prefixed lowercase hex.
    pub request_vk_keccak256: Option<String>,
    pub withdrawal_vk_keccak256: Option<String>,
    /// [`BINDING_SOURCE_VAULT`] or [`BINDING_SOURCE_MANIFEST`].
    pub source: String,
}

/// A binding serverd verified against the vault.
pub const BINDING_SOURCE_VAULT: &str = "vault";
/// A binding `zkapi db init` recorded from the deployment manifest; serverd
/// verifies it against the vault before its first start.
pub const BINDING_SOURCE_MANIFEST: &str = "manifest";

/// The statement identity a database binding records, for comparison.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatementIdentity {
    pub circuit_id: String,
    pub setup_id: String,
    pub request_vk_keccak256: String,
    pub withdrawal_vk_keccak256: String,
}

impl StatementIdentity {
    /// The identity of the verifying keys in `proof_setup_dir`, as loaded by
    /// this build (which refuses keys of a setup it does not accept).
    pub fn load(proof_setup_dir: &str) -> anyhow::Result<Self> {
        use anyhow::Context;
        use zkapi_proof::compact::{hex32, WithdrawalVerifier, CIRCUIT_ID};
        let request = RequestVerifier::load(proof_setup_dir)
            .with_context(|| format!("load the request verifying key from {proof_setup_dir}"))?;
        let withdrawal = WithdrawalVerifier::load(proof_setup_dir)
            .with_context(|| format!("load the withdrawal verifying key from {proof_setup_dir}"))?;
        anyhow::ensure!(
            request.setup_id() == withdrawal.setup_id(),
            "the request key is of setup {:?} but the withdrawal key of setup {:?}",
            request.setup_id(),
            withdrawal.setup_id()
        );
        Ok(Self {
            circuit_id: CIRCUIT_ID.to_string(),
            setup_id: request.setup_id().to_string(),
            request_vk_keccak256: hex32(&request.verifying_key_keccak256()),
            withdrawal_vk_keccak256: hex32(&withdrawal.verifying_key_keccak256()),
        })
    }

    /// Why `binding` records another statement, if it does.
    pub fn mismatch(&self, binding: &DeploymentBinding) -> Option<String> {
        let recorded = |value: &Option<String>| {
            value
                .clone()
                .unwrap_or_else(|| "none (bound before circuit identifiers were recorded: circuit zkapi-v2-note-bound-v1)".into())
        };
        for (name, local, stored) in [
            ("circuit_id", &self.circuit_id, &binding.circuit_id),
            ("setup_id", &self.setup_id, &binding.setup_id),
            (
                "request_vk_keccak256",
                &self.request_vk_keccak256,
                &binding.request_vk_keccak256,
            ),
            (
                "withdrawal_vk_keccak256",
                &self.withdrawal_vk_keccak256,
                &binding.withdrawal_vk_keccak256,
            ),
        ] {
            if stored.as_deref() != Some(local.as_str()) {
                return Some(format!(
                    "{name} is {} in the database but {local} here",
                    recorded(stored)
                ));
            }
        }
        None
    }
}

/// SQLite-backed nullifier store.
pub struct NullifierStore {
    conn: Mutex<Connection>,
}

/// Bind the complete semantically decoded v2 wire request. Serde emits struct
/// fields in declaration order, so equivalent JSON input has one canonical
/// representation while every downstream request field affects the digest.
pub(crate) fn api_request_binding(request: &ApiRequestV2) -> Result<String, ServerError> {
    let request = serde_json::to_vec(request).map_err(|error| {
        ServerError::Internal(format!("failed to serialize v2 request binding: {error}"))
    })?;
    let mut digest = Keccak256::new();
    digest.update(b"zkapi:v2:api-request-binding\0");
    digest.update(request);
    Ok(hex::encode(digest.finalize()))
}

/// Where a lease row disagrees with its nullifier reservation, named as the
/// operator finds it in the database. Such a lease is never signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindingMismatch {
    /// `table.column` of the first disagreeing field.
    pub field: &'static str,
    pub detail: &'static str,
}

impl std::fmt::Display for BindingMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}", self.field, self.detail)
    }
}

impl BindingMismatch {
    /// The operator's repair. The saved request in
    /// `openrouter_leases.api_request_json` is verified first: the request its
    /// owner's proof authorized decides which side is corrupt.
    pub fn remedy(&self) -> &'static str {
        if self.field == SAVED_REQUEST_FIELD {
            "the saved request is the corrupt side: run this command again with --saved-request \
             and the authentic request (from a backup of the server database, or its owner's \
             copy), which is accepted only if it verifies and its binding is \
             nullifiers.api_request_binding; never re-derive the reservation from the saved \
             request"
        } else if self.field.starts_with("nullifiers.") {
            "the saved request verifies, so the reservation is the corrupt side: run this \
             command again with --rebind to rewrite it from that request"
        } else {
            "the saved request verifies, so the lease row is the corrupt side: run this command \
             again with --rebind to rewrite it from that request"
        }
    }
}

/// The lease column holding the saved request.
pub const SAVED_REQUEST_FIELD: &str = "openrouter_leases.api_request_json";

/// The detail of a saved request whose Groth16 proof does not verify. Of the
/// saved-request checks, only this one depends on the proof setup the
/// verifier was loaded from.
pub const GROTH16_UNVERIFIED: &str =
    "is not the request its proof authorized: its Groth16 proof does not verify";

/// Checks a lease's saved request as admission did; None when it is the
/// request its owner's proof authorized. Production passes
/// `saved_request_mismatch` with the server's verifier.
pub(crate) type SavedRequestCheck<'a> = &'a dyn Fn(&ApiRequestV2) -> Option<BindingMismatch>;

/// Verify a lease's saved request as admission verified it: its payload
/// hashes to its payload_hash, its proof's authorization tag binds its
/// client_request_id and payload, and its Groth16 proof verifies against its
/// public inputs. Together these cover every field of the request, so a
/// request that passes is one its owner authorized, and the reservation's
/// authenticators may be derived from it. A request that fails is corrupt
/// (or tampered with); nothing may be signed or derived from it.
pub(crate) fn saved_request_mismatch(
    verifier: &RequestVerifier,
    request: &ApiRequestV2,
) -> Option<BindingMismatch> {
    let unverified = |detail| {
        Some(BindingMismatch {
            field: SAVED_REQUEST_FIELD,
            detail,
        })
    };
    let payload_hash = canonical_payload_hash(request.payload.as_bytes());
    if payload_hash != request.payload_hash {
        return unverified("holds a payload that does not hash to its payload_hash");
    }
    let public = &request.public_inputs;
    let context = canonical_request_context(&request.client_request_id, &payload_hash);
    if core::authorization_tag(&public.request_nullifier, &context) != public.authorization_tag {
        return unverified(
            "is not the request its proof authorized: the authorization tag does not bind its \
             client_request_id and payload",
        );
    }
    match verifier.verify(public, &request.proof) {
        Ok(true) => None,
        _ => unverified(GROTH16_UNVERIFIED),
    }
}

/// The store-level binding checks of a lease row against its nullifier
/// reservation (`record`, None when the nullifier has no row). The signer
/// additionally checks the request's deployment and signing key, and, for a
/// reopened lease, verifies the saved request (`saved_request_mismatch`).
pub(crate) fn lease_binding_mismatch(
    lease: &OpenRouterLeaseRecord,
    record: Option<&TranscriptRecord>,
) -> Result<Option<BindingMismatch>, ServerError> {
    let request = &lease.api_request;
    let mismatch = |field, detail| Ok(Some(BindingMismatch { field, detail }));
    if lease.client_request_id != request.client_request_id {
        return mismatch(
            "openrouter_leases.client_request_id",
            "differs from the client_request_id in api_request_json",
        );
    }
    if lease.request_nullifier != request.public_inputs.request_nullifier {
        return mismatch(
            "openrouter_leases.request_nullifier",
            "differs from the request_nullifier in api_request_json",
        );
    }
    if canonical_payload_hash(request.payload.as_bytes()) != request.payload_hash {
        return mismatch(
            "openrouter_leases.api_request_json",
            "holds a payload that does not hash to its payload_hash",
        );
    }
    let Some(record) = record else {
        return mismatch(
            "nullifiers.nullifier",
            "has no reservation row for the lease's request_nullifier",
        );
    };
    if record.status == NullifierStatus::ClearanceReserved {
        return mismatch(
            "nullifiers.status",
            "is ClearanceReserved: the nullifier is reserved for a withdrawal clearance",
        );
    }
    if record.reservation_kind != "openrouter_lease" {
        return mismatch("nullifiers.reservation_kind", "is not openrouter_lease");
    }
    if record.client_request_id.as_deref() != Some(request.client_request_id.as_str()) {
        return mismatch(
            "nullifiers.client_request_id",
            "differs from the lease request's client_request_id",
        );
    }
    if record.payload_hash != Some(request.payload_hash) {
        return mismatch(
            "nullifiers.payload_hash",
            "differs from the lease request's payload_hash",
        );
    }
    if record.api_request_binding.as_deref() != Some(api_request_binding(request)?.as_str()) {
        return mismatch(
            "nullifiers.api_request_binding",
            "differs from the binding of the lease request in api_request_json",
        );
    }
    Ok(None)
}

impl NullifierStore {
    /// Open or create a nullifier store at the given path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let conn = Connection::open(path)
            .map_err(|e| ServerError::Database(format!("failed to open db: {}", e)))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS nullifiers (
                nullifier TEXT PRIMARY KEY,
                status TEXT NOT NULL,
                reservation_kind TEXT NOT NULL DEFAULT 'proxy',
                client_request_id TEXT,
                payload_hash TEXT,
                charge_applied INTEGER,
                response_code INTEGER,
                response_payload TEXT,
                response_hash TEXT,
                next_commitment_x TEXT,
                next_commitment_y TEXT,
                next_anchor TEXT,
                blind_delta_srv TEXT,
                next_state_sig_epoch INTEGER,
                next_state_sig_root TEXT,
                next_state_sig_json TEXT,
                policy_reason_code INTEGER,
                policy_evidence_hash TEXT,
                proof_blob BLOB,
                request_inputs_json TEXT,
                api_request_binding TEXT,
                clearance_auth TEXT,
                created_at INTEGER NOT NULL,
                finalized_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS openrouter_leases (
                client_request_id TEXT PRIMARY KEY,
                request_nullifier TEXT NOT NULL UNIQUE,
                api_request_json TEXT NOT NULL,
                oa_client_request_id TEXT,
                key_hash TEXT UNIQUE,
                key_source TEXT NOT NULL DEFAULT 'openrouter',
                oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
                status TEXT NOT NULL,
                issued_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                settle_after INTEGER NOT NULL,
                spending_limit_usd REAL NOT NULL,
                usage_usd REAL,
                charge_applied INTEGER,
                last_error TEXT,
                updated_at INTEGER NOT NULL,
                ttl_seconds INTEGER,
                settlement_deadline_at INTEGER,
                settlement_attempts INTEGER NOT NULL DEFAULT 0,
                first_error_at INTEGER,
                charge_basis TEXT,
                delivered INTEGER,
                next_attempt_at INTEGER,
                key_source_identity TEXT
            );
            CREATE TABLE IF NOT EXISTS deployment_binding (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                chain_id INTEGER NOT NULL,
                contract_address TEXT NOT NULL,
                state_key_x TEXT NOT NULL,
                state_key_y TEXT NOT NULL,
                clearance_key_x TEXT NOT NULL,
                clearance_key_y TEXT NOT NULL,
                challenge_period_seconds INTEGER NOT NULL,
                verified_at INTEGER NOT NULL,
                verified_block INTEGER,
                circuit_id TEXT,
                setup_id TEXT,
                request_vk_keccak256 TEXT,
                withdrawal_vk_keccak256 TEXT,
                source TEXT NOT NULL DEFAULT 'vault'
            );
            CREATE TABLE IF NOT EXISTS settlement_reviews (
                review_id INTEGER PRIMARY KEY,
                client_request_id TEXT NOT NULL,
                request_nullifier TEXT NOT NULL,
                key_source TEXT NOT NULL,
                reason TEXT NOT NULL,
                charge_basis TEXT,
                detail TEXT NOT NULL,
                reported_usage_micro_usd TEXT,
                charge_applied INTEGER,
                solvency_bound TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                acknowledged_at INTEGER
            );
            CREATE TABLE IF NOT EXISTS provider_key_cleanup (
                client_request_id TEXT PRIMARY KEY,
                key_source TEXT NOT NULL,
                key_hash TEXT,
                key_name TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                next_attempt_at INTEGER NOT NULL,
                last_error TEXT,
                created_at INTEGER NOT NULL
            );",
        )
        .map_err(|e| ServerError::Database(format!("failed to create table: {}", e)))?;

        // Checked, idempotent column migrations: a column a decoder reads by
        // name must exist, or opening fails instead of every row being
        // silently unreadable.
        for (table, column, definition) in [
            ("nullifiers", "next_state_sig_root", "TEXT"),
            ("nullifiers", "response_payload", "TEXT"),
            (
                "nullifiers",
                "reservation_kind",
                "TEXT NOT NULL DEFAULT 'proxy'",
            ),
            ("nullifiers", "api_request_binding", "TEXT"),
            ("nullifiers", "clearance_auth", "TEXT"),
            // The settle/sign split (O7): the final charge, written once
            // before the successor is signed, and the deferral of a signature
            // while the nullifier is consumed on chain.
            ("nullifiers", "settled_charge", "INTEGER"),
            ("nullifiers", "settled_basis", "TEXT"),
            ("nullifiers", "settled_at", "INTEGER"),
            ("nullifiers", "exit_deferred_since", "INTEGER"),
            ("deployment_binding", "circuit_id", "TEXT"),
            ("deployment_binding", "setup_id", "TEXT"),
            ("deployment_binding", "request_vk_keccak256", "TEXT"),
            ("deployment_binding", "withdrawal_vk_keccak256", "TEXT"),
            (
                "deployment_binding",
                "source",
                "TEXT NOT NULL DEFAULT 'vault'",
            ),
            (
                "openrouter_leases",
                "key_source",
                "TEXT NOT NULL DEFAULT 'openrouter'",
            ),
            ("openrouter_leases", "oa_client_request_id", "TEXT"),
            ("openrouter_leases", "ttl_seconds", "INTEGER"),
            ("openrouter_leases", "settlement_deadline_at", "INTEGER"),
            (
                "openrouter_leases",
                "settlement_attempts",
                "INTEGER NOT NULL DEFAULT 0",
            ),
            ("openrouter_leases", "first_error_at", "INTEGER"),
            ("openrouter_leases", "charge_basis", "TEXT"),
            ("openrouter_leases", "delivered", "INTEGER"),
            // Read only by the settlement scan, never by a row decoder, so
            // that read-only readers accept databases from before it.
            ("openrouter_leases", "next_attempt_at", "INTEGER"),
            // Read only by the startup key-source check, likewise.
            ("openrouter_leases", "key_source_identity", "TEXT"),
        ] {
            ensure_column(&conn, table, column, definition)?;
        }
        migrate_oa_provisioning_outcome(&conn)?;
        migrate_settlement_review_log(&conn)?;
        conn.execute_batch(REQUEST_EVIDENCE_SCHEMA).map_err(|e| {
            ServerError::Database(format!("failed to create request_evidence: {e}"))
        })?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS nullifiers_settled_unsigned
                ON nullifiers(status, settled_charge);
             CREATE INDEX IF NOT EXISTS openrouter_leases_status
                ON openrouter_leases(status, settle_after);
             CREATE INDEX IF NOT EXISTS openrouter_leases_deadline
                ON openrouter_leases(settlement_deadline_at);
             CREATE INDEX IF NOT EXISTS settlement_reviews_open
                ON settlement_reviews(acknowledged_at, created_at);
             CREATE INDEX IF NOT EXISTS settlement_reviews_lease
                ON settlement_reviews(client_request_id);",
        )
        .map_err(|e| ServerError::Database(format!("failed to create index: {e}")))?;
        backfill_openrouter_request_bindings(&conn)?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Create an in-memory store (for testing).
    pub fn in_memory() -> Result<Self, ServerError> {
        Self::new(":memory:")
    }

    /// Open an existing server database for reading only: no DDL, migrations
    /// or backfills run, and every write fails. Refuses a schema that lacks a
    /// column the record decoders read, rather than misreporting evidence.
    pub fn open_read_only<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_ONLY
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| ServerError::Database(format!("failed to open db read-only: {e}")))?;
        conn.execute_batch("PRAGMA query_only = ON")
            .map_err(|e| ServerError::Database(format!("failed to make db query-only: {e}")))?;
        check_reader_schema(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// The deployment binding recorded in the database file at `path`, read
    /// before the database is opened for writes, whatever release wrote it:
    /// unlike [`Self::open_read_only`], an older schema is no reason to skip
    /// the binding. A column an older release did not record reads as absent
    /// (None, and `source` "vault"), so a binding recorded before circuit
    /// identifiers names no circuit (zkapi-v2-note-bound-v1) and matches no
    /// statement of this release. None only when no binding row exists.
    /// Nothing is written: the file is opened query-only, read-write only so
    /// that SQLite can roll back a hot journal as any opener does.
    pub fn read_recorded_deployment_binding<P: AsRef<Path>>(
        path: P,
    ) -> Result<Option<DeploymentBinding>, ServerError> {
        let failed = |error: rusqlite::Error| {
            ServerError::Database(format!("deployment binding read failed: {error}"))
        };
        let conn = Connection::open_with_flags(
            path,
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_URI
                | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(failed)?;
        conn.execute_batch("PRAGMA query_only = ON")
            .map_err(failed)?;
        let present = conn
            .prepare("SELECT name FROM pragma_table_info('deployment_binding')")
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(failed)?;
        if present.is_empty() {
            // No binding table: a database older than the binding.
            return Ok(None);
        }
        let column = |name: &str, absent: &str| {
            if present.iter().any(|column| column == name) {
                name.to_string()
            } else {
                format!("{absent} AS {name}")
            }
        };
        // The columns every binding table has are read as they are: one
        // missing fails the read.
        conn.query_row(
            &format!(
                "SELECT chain_id, contract_address, state_key_x, state_key_y, clearance_key_x,
                    clearance_key_y, challenge_period_seconds, verified_at, {}, {}, {}, {}, {}, {}
                 FROM deployment_binding WHERE id = 1",
                column("verified_block", "NULL"),
                column("circuit_id", "NULL"),
                column("setup_id", "NULL"),
                column("request_vk_keccak256", "NULL"),
                column("withdrawal_vk_keccak256", "NULL"),
                column("source", "'vault'"),
            ),
            [],
            row_to_deployment_binding,
        )
        .optional()
        .map_err(failed)
    }

    /// Record the vault-verified deployment this database serves.
    pub fn write_deployment_binding(&self, binding: &DeploymentBinding) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "INSERT INTO deployment_binding (
                id, chain_id, contract_address, state_key_x, state_key_y, clearance_key_x,
                clearance_key_y, challenge_period_seconds, verified_at, verified_block,
                circuit_id, setup_id, request_vk_keccak256, withdrawal_vk_keccak256, source
             ) VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)
             ON CONFLICT(id) DO UPDATE SET
                chain_id = excluded.chain_id, contract_address = excluded.contract_address,
                state_key_x = excluded.state_key_x, state_key_y = excluded.state_key_y,
                clearance_key_x = excluded.clearance_key_x,
                clearance_key_y = excluded.clearance_key_y,
                challenge_period_seconds = excluded.challenge_period_seconds,
                verified_at = excluded.verified_at, verified_block = excluded.verified_block,
                circuit_id = excluded.circuit_id, setup_id = excluded.setup_id,
                request_vk_keccak256 = excluded.request_vk_keccak256,
                withdrawal_vk_keccak256 = excluded.withdrawal_vk_keccak256,
                source = excluded.source",
            // u64 values above i64::MAX fail to bind instead of wrapping.
            params![
                binding.chain_id,
                binding.contract_address,
                binding.state_signing_key.x.to_hex(),
                binding.state_signing_key.y.to_hex(),
                binding.clearance_signing_key.x.to_hex(),
                binding.clearance_signing_key.y.to_hex(),
                binding.challenge_period_seconds,
                binding.verified_at,
                binding.verified_block,
                binding.circuit_id,
                binding.setup_id,
                binding.request_vk_keccak256,
                binding.withdrawal_vk_keccak256,
                binding.source,
            ],
        )
        .map_err(|error| {
            ServerError::Database(format!("deployment binding write failed: {error}"))
        })?;
        Ok(())
    }

    /// The recorded deployment, or None for a database that predates it.
    pub fn read_deployment_binding(&self) -> Result<Option<DeploymentBinding>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master
                 WHERE type = 'table' AND name = 'deployment_binding')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| {
                ServerError::Database(format!("deployment binding lookup failed: {error}"))
            })?;
        if !exists {
            return Ok(None);
        }
        conn.query_row(
            "SELECT chain_id, contract_address, state_key_x, state_key_y, clearance_key_x,
                clearance_key_y, challenge_period_seconds, verified_at, verified_block,
                circuit_id, setup_id, request_vk_keccak256, withdrawal_vk_keccak256, source
             FROM deployment_binding WHERE id = 1",
            [],
            row_to_deployment_binding,
        )
        .optional()
        .map_err(|error| ServerError::Database(format!("deployment binding read failed: {error}")))
    }

    /// Acquire the long-lived server writer lock for the actual SQLite file,
    /// not a possibly different config path. In-memory test stores are exempt.
    /// Ordinary store users such as the challenger do not acquire this lock.
    pub(crate) fn acquire_writer_lock(
        &self,
    ) -> Result<Option<crate::writer_lock::ServerWriterLock>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        match conn.path().filter(|path| !path.is_empty()) {
            Some(path) => crate::writer_lock::ServerWriterLock::acquire(Path::new(path)).map(Some),
            None => Ok(None),
        }
    }

    /// Reserve a nullifier. Returns Ok(()) if the nullifier was successfully reserved.
    /// Returns Err(Replay) if the nullifier already exists.
    #[cfg(test)]
    pub fn reserve(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
    ) -> Result<(), ServerError> {
        self.reserve_with_kind(nullifier, client_request_id, payload_hash, "proxy", None)
    }

    /// Raw SQL for tests that simulate database faults and operator repairs.
    #[cfg(test)]
    pub(crate) fn execute_for_test(&self, sql: &str, params: impl rusqlite::Params) -> usize {
        self.conn.lock().unwrap().execute(sql, params).unwrap()
    }

    /// A single integer read for tests.
    #[cfg(test)]
    pub(crate) fn query_i64_for_test(&self, sql: &str, params: impl rusqlite::Params) -> i64 {
        self.conn
            .lock()
            .unwrap()
            .query_row(sql, params, |row| row.get(0))
            .unwrap()
    }

    /// Reserve a verified lease request's nullifier and record its proof as
    /// evidence (`request_evidence`, source "reserve") in one transaction:
    /// either both rows exist or neither does (O2). A request whose proof is
    /// not a 256-byte Groth16 proof reserves nothing.
    pub fn reserve_openrouter_lease(&self, request: &ApiRequestV2) -> Result<(), ServerError> {
        self.reserve_openrouter_lease_with(request, None)
    }

    /// `reserve_openrouter_lease`, also inserting the lease's issuance row
    /// (`lease`) in the same transaction, so that no reservation is ever left
    /// without the lease row that settles it.
    pub fn reserve_openrouter_lease_with(
        &self,
        request: &ApiRequestV2,
        lease: Option<&NewOpenRouterLease<'_>>,
    ) -> Result<(), ServerError> {
        if let Some(lease) = lease {
            if lease.request.client_request_id != request.client_request_id
                || lease.request.public_inputs.request_nullifier
                    != request.public_inputs.request_nullifier
            {
                return Err(ServerError::Internal(
                    "the lease row is not the reserved request's".into(),
                ));
            }
        }
        let binding = api_request_binding(request)?;
        request_proof_bytes(request)?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|e| ServerError::Database(format!("reservation failed: {e}")))?;
        let now = current_timestamp();
        insert_reservation(
            &transaction,
            &request.public_inputs.request_nullifier,
            &request.client_request_id,
            &request.payload_hash,
            "openrouter_lease",
            Some(&binding),
            now,
        )?;
        insert_evidence(&transaction, request, "reserve", now)?;
        if let Some(lease) = lease {
            insert_lease_row(&transaction, lease)?;
        }
        transaction
            .commit()
            .map_err(|e| ServerError::Database(format!("reservation commit failed: {e}")))
    }

    #[cfg(test)]
    fn reserve_with_kind(
        &self,
        nullifier: &Felt252,
        client_request_id: &str,
        payload_hash: &Felt252,
        reservation_kind: &str,
        api_request_binding: Option<&str>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        insert_reservation(
            &conn,
            nullifier,
            client_request_id,
            payload_hash,
            reservation_kind,
            api_request_binding,
            current_timestamp(),
        )
    }

    /// The evidence rows at `nullifier`, oldest first.
    pub fn request_evidence(
        &self,
        nullifier: &Felt252,
    ) -> Result<Vec<RequestEvidence>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        let mut statement = conn
            .prepare("SELECT * FROM request_evidence WHERE nullifier = ?1 ORDER BY id ASC")
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?;
        let rows = statement
            .query_map(params![nullifier.to_hex()], row_to_evidence)
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))
    }

    /// Drill builds (`--adversary overcharge`): rewrite a settled, unsigned
    /// request's charge, which no honest path ever does.
    #[cfg(feature = "adversary")]
    pub(crate) fn overcharge_for_adversary(
        &self,
        nullifier: &Felt252,
        charge: u128,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        conn.execute(
            "UPDATE nullifiers SET settled_charge = ?1
             WHERE nullifier = ?2 AND status = 'Reserved' AND settled_charge IS NOT NULL",
            params![sql_charge(charge)?, nullifier.to_hex()],
        )
        .map_err(|e| ServerError::Database(format!("overcharge failed: {e}")))?;
        Ok(())
    }

    /// The evidence rows at `nullifier`, oldest first, each decoded on its
    /// own: a row that does not decode is reported with its id and why,
    /// without hiding the others (the challenger may defeat with any row
    /// that verifies). A failed read is an error.
    pub fn request_evidence_rows(
        &self,
        nullifier: &Felt252,
    ) -> Result<Vec<Result<RequestEvidence, String>>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        let mut statement = conn
            .prepare("SELECT * FROM request_evidence WHERE nullifier = ?1 ORDER BY id ASC")
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?;
        let mut rows = statement
            .query(params![nullifier.to_hex()])
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?;
        let mut decoded = Vec::new();
        while let Some(row) = rows
            .next()
            .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?
        {
            let id: i64 = row
                .get("id")
                .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))?;
            decoded
                .push(row_to_evidence(row).map_err(|error| {
                    format!("request_evidence row {id} does not decode: {error}")
                }));
        }
        Ok(decoded)
    }

    /// The earliest evidence row the reservation of `nullifier` wrote (source
    /// "reserve"), as `GET /v2/nullifiers/{N}/evidence` serves it.
    pub fn earliest_reserve_evidence(
        &self,
        nullifier: &Felt252,
    ) -> Result<Option<RequestEvidence>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        conn.query_row(
            "SELECT * FROM request_evidence WHERE nullifier = ?1 AND source = 'reserve'
             ORDER BY id ASC LIMIT 1",
            params![nullifier.to_hex()],
            row_to_evidence,
        )
        .optional()
        .map_err(|e| ServerError::Database(format!("evidence read failed: {e}")))
    }

    /// Settle a lease: persist its final charge on its reservation, which
    /// stays Reserved until its successor is signed (`finalize_signed`), and
    /// finalize the lease row under `finalization.guard`, with its review and
    /// key cleanup, in one transaction. The charge is written once: a
    /// reservation settled earlier keeps its charge, basis and payload, and
    /// the lease row records those. Nothing is written when the lease row no
    /// longer satisfies its guard (`LeaseChanged`), and the reservation must
    /// be Reserved.
    pub(crate) fn settle_openrouter_lease(
        &self,
        client_request_id: &str,
        nullifier: &Felt252,
        settlement: &SettledCharge,
        finalization: &LeaseFinalization<'_>,
    ) -> Result<SettleOutcome, ServerError> {
        let failed = |error: rusqlite::Error| {
            ServerError::Database(format!("lease settlement failed: {error}"))
        };
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let record = transaction
            .query_row(
                "SELECT * FROM nullifiers WHERE nullifier = ?1",
                params![nullifier.to_hex()],
                row_to_record,
            )
            .optional()
            .map_err(failed)?
            .ok_or_else(|| ServerError::Internal("the request has no reservation".into()))?;
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::Internal(format!(
                "the request's reservation is {:?}, not Reserved; nothing is settled",
                record.status
            )));
        }
        let settled = match (record.settled_charge, record.settled_basis.clone()) {
            (Some(charge), Some(basis)) => SettledCharge {
                charge,
                basis,
                response_code: record.response_code.unwrap_or(200),
                response_payload: record.response_payload.clone().unwrap_or_default(),
                settled_at: record.settled_at.unwrap_or(settlement.settled_at),
            },
            _ => {
                let rows = transaction
                    .execute(
                        "UPDATE nullifiers SET settled_charge = ?1, settled_basis = ?2,
                            settled_at = ?3, response_code = ?4, response_payload = ?5
                         WHERE nullifier = ?6 AND status = 'Reserved' AND settled_charge IS NULL",
                        params![
                            sql_charge(settlement.charge)?,
                            settlement.basis,
                            sql_time(settlement.settled_at),
                            settlement.response_code,
                            settlement.response_payload,
                            nullifier.to_hex(),
                        ],
                    )
                    .map_err(failed)?;
                if rows != 1 {
                    return Err(ServerError::Internal(
                        "the reservation changed while settling".into(),
                    ));
                }
                settlement.clone()
            }
        };
        let now = current_timestamp() as i64;
        let condition = finalization.guard.condition();
        let rows = transaction
            .execute(
                &format!(
                    "UPDATE openrouter_leases SET
                        status = 'finalized', usage_usd = ?1, charge_applied = ?2,
                        charge_basis = ?3, last_error = NULL, updated_at = ?4
                     WHERE client_request_id = ?5 AND request_nullifier = ?6
                       AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')
                       AND {condition}"
                ),
                params![
                    finalization.usage_usd,
                    sql_charge(settled.charge)?,
                    settled.basis,
                    now,
                    client_request_id,
                    nullifier.to_hex(),
                ],
            )
            .map_err(failed)?;
        if rows != 1 {
            return Ok(SettleOutcome::LeaseChanged);
        }
        if let Some(review) = finalization.review {
            insert_review(&transaction, review, now)?;
        }
        if let Some(cleanup) = finalization.key_cleanup {
            insert_key_cleanup(&transaction, client_request_id, &cleanup, now)?;
        }
        transaction.commit().map_err(failed)?;
        Ok(SettleOutcome::Settled(settled))
    }

    /// Record the signed successor of a settled request: Reserved (with
    /// `settled_charge` equal to the transcript's charge) becomes Finalized,
    /// at most once. A lease deferred by O7 (`exit_deferred`) returns to
    /// `finalized` in the same transaction.
    pub(crate) fn finalize_signed(&self, transcript: &TranscriptRecord) -> Result<(), ServerError> {
        let failed =
            |error: rusqlite::Error| ServerError::Database(format!("finalize failed: {error}"));
        let charge = transcript
            .charge_applied
            .ok_or_else(|| ServerError::Internal("signed transcript has no charge".into()))?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let sig_json = transcript
            .next_state_sig
            .as_ref()
            .map(|sig| serde_json::to_string(sig).unwrap_or_default());
        let rows = transaction
            .execute(
                "UPDATE nullifiers SET
                    status = 'Finalized', charge_applied = ?1, response_code = ?2,
                    response_payload = ?3, response_hash = ?4, next_commitment_x = ?5,
                    next_commitment_y = ?6, next_anchor = ?7, blind_delta_srv = ?8,
                    next_state_sig_json = ?9, proof_blob = ?10, request_inputs_json = ?11,
                    finalized_at = ?12
                 WHERE nullifier = ?13 AND status = 'Reserved' AND settled_charge = ?1",
                params![
                    sql_charge(charge)?,
                    transcript.response_code.map(i64::from),
                    transcript.response_payload.as_deref(),
                    transcript.response_hash.map(|h| h.to_hex()),
                    transcript.next_commitment_x.map(|c| c.to_hex()),
                    transcript.next_commitment_y.map(|c| c.to_hex()),
                    transcript.next_anchor.map(|a| a.to_hex()),
                    transcript.blind_delta_srv.map(|b| b.to_hex()),
                    sig_json,
                    transcript.proof_blob.as_deref(),
                    transcript.request_inputs_json.as_deref(),
                    sql_time(transcript.finalized_at.unwrap_or_else(current_timestamp)),
                    transcript.nullifier.to_hex(),
                ],
            )
            .map_err(failed)?;
        if rows == 0 {
            return Err(ServerError::Internal(
                "nullifier is not a settled reservation at this charge, or its successor is \
                 already signed"
                    .to_string(),
            ));
        }
        if let Some(id) = transcript.client_request_id.as_deref() {
            transaction
                .execute(
                    "UPDATE openrouter_leases SET status = 'finalized', updated_at = ?1
                     WHERE client_request_id = ?2 AND request_nullifier = ?3
                       AND status = 'exit_deferred'",
                    params![
                        current_timestamp() as i64,
                        id,
                        transcript.nullifier.to_hex()
                    ],
                )
                .map_err(failed)?;
        }
        transaction.commit().map_err(failed)
    }

    /// O7: the settled request's nullifier is consumed on chain, so its
    /// successor is not signed. Records the first observation
    /// (`exit_deferred_since`) and marks its lease `exit_deferred`. Once
    /// `window` seconds have passed since that first observation, the
    /// reservation becomes ExitedUnsigned (terminal) and its lease
    /// `exited_unsigned`. `window` None never ends the deferral.
    pub(crate) fn defer_signature(
        &self,
        nullifier: &Felt252,
        now: u64,
        window: Option<u64>,
    ) -> Result<SignatureDeferral, ServerError> {
        let failed =
            |error: rusqlite::Error| ServerError::Database(format!("deferral failed: {error}"));
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let record = transaction
            .query_row(
                "SELECT * FROM nullifiers WHERE nullifier = ?1",
                params![nullifier.to_hex()],
                row_to_record,
            )
            .optional()
            .map_err(failed)?
            .ok_or_else(|| ServerError::Internal("the request has no reservation".into()))?;
        match record.status {
            NullifierStatus::ExitedUnsigned => return Ok(SignatureDeferral::ExitedUnsigned),
            NullifierStatus::Reserved if record.settled_charge.is_some() => {}
            status => {
                return Err(ServerError::Internal(format!(
                    "only a settled, unsigned request can be deferred (it is {status:?})"
                )))
            }
        }
        let since = record.exit_deferred_since.unwrap_or(now);
        let exited = window.is_some_and(|window| now >= since.saturating_add(window));
        let (status, lease_status) = if exited {
            ("ExitedUnsigned", "exited_unsigned")
        } else {
            ("Reserved", "exit_deferred")
        };
        transaction
            .execute(
                "UPDATE nullifiers SET exit_deferred_since = ?1, status = ?2
                 WHERE nullifier = ?3 AND status = 'Reserved' AND settled_charge IS NOT NULL",
                params![sql_time(since), status, nullifier.to_hex()],
            )
            .map_err(failed)?;
        if let Some(id) = record.client_request_id.as_deref() {
            transaction
                .execute(
                    "UPDATE openrouter_leases SET status = ?1, updated_at = ?2
                     WHERE client_request_id = ?3 AND request_nullifier = ?4
                       AND status IN ('finalized', 'exit_deferred')",
                    params![lease_status, sql_time(now), id, nullifier.to_hex()],
                )
                .map_err(failed)?;
        }
        transaction.commit().map_err(failed)?;
        Ok(if exited {
            SignatureDeferral::ExitedUnsigned
        } else {
            SignatureDeferral::Deferred { since }
        })
    }

    /// One page of the settled requests whose successors are not signed yet:
    /// those never found consumed (`deferred == false`), or those O7 deferred
    /// (`deferred == true`). Pages run in `(settled_at, nullifier)` order,
    /// strictly after `after` (a previous page's last `SettledScanKey`), so a
    /// caller walking the pages visits every row however many sit before it.
    pub(crate) fn settled_unsigned_requests(
        &self,
        deferred: bool,
        after: Option<&SettledScanKey>,
        limit: usize,
    ) -> Result<Vec<TranscriptRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        let class = if deferred {
            "exit_deferred_since IS NOT NULL"
        } else {
            "exit_deferred_since IS NULL"
        };
        let mut statement = conn
            .prepare(&format!(
                "SELECT * FROM nullifiers
                 WHERE status = 'Reserved' AND settled_charge IS NOT NULL AND {class}
                   AND (?1 IS NULL OR (COALESCE(settled_at, 0), nullifier) > (?1, ?2))
                 ORDER BY COALESCE(settled_at, 0) ASC, nullifier ASC LIMIT ?3"
            ))
            .map_err(|e| ServerError::Database(format!("settled scan failed: {e}")))?;
        let rows = statement
            .query_map(
                params![
                    after.map(|key| key.settled_at),
                    after.map(|key| key.nullifier.as_str()),
                    limit as i64
                ],
                row_to_record,
            )
            .map_err(|e| ServerError::Database(format!("settled scan failed: {e}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| ServerError::Database(format!("settled scan failed: {e}")))
    }

    /// Write a transcript over a Reserved row without the settle/sign
    /// protocol: test fixtures only. Production signs through
    /// `settle_openrouter_lease` and `finalize_signed`.
    #[cfg(test)]
    pub(crate) fn finalize(
        &self,
        nullifier: &Felt252,
        transcript: &TranscriptRecord,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        let sig_json = transcript
            .next_state_sig
            .as_ref()
            .map(|sig| serde_json::to_string(sig).unwrap_or_default());

        let rows = conn
            .execute(
                "UPDATE nullifiers SET
                    status = ?1,
                    charge_applied = ?2,
                    response_code = ?3,
                    response_payload = ?4,
                    response_hash = ?5,
                    next_commitment_x = ?6,
                    next_commitment_y = ?7,
                    next_anchor = ?8,
                    blind_delta_srv = ?9,
                    next_state_sig_epoch = ?10,
                    next_state_sig_root = ?11,
                    next_state_sig_json = ?12,
                    policy_reason_code = ?13,
                    policy_evidence_hash = ?14,
                    proof_blob = ?15,
                    request_inputs_json = ?16,
                    finalized_at = ?17
                 WHERE nullifier = ?18 AND status = ?19",
                params![
                    status_to_str(NullifierStatus::Finalized),
                    transcript.charge_applied.map(|c| c as i64),
                    transcript.response_code.map(|c| c as i32),
                    transcript.response_payload.as_deref(),
                    transcript.response_hash.map(|h| h.to_hex()),
                    transcript.next_commitment_x.map(|c| c.to_hex()),
                    transcript.next_commitment_y.map(|c| c.to_hex()),
                    transcript.next_anchor.map(|a| a.to_hex()),
                    transcript.blind_delta_srv.map(|b| b.to_hex()),
                    Option::<i32>::None,
                    Option::<String>::None,
                    sig_json,
                    transcript.policy_reason_code.map(|c| c as i32),
                    transcript.policy_evidence_hash.map(|h| h.to_hex()),
                    transcript.proof_blob.as_deref(),
                    transcript.request_inputs_json.as_deref(),
                    now as i64,
                    null_hex,
                    status_to_str(NullifierStatus::Reserved),
                ],
            )
            .map_err(|e| ServerError::Database(format!("finalize failed: {}", e)))?;

        if rows == 0 {
            return Err(ServerError::Internal(
                "nullifier not in Reserved state or does not exist".to_string(),
            ));
        }

        Ok(())
    }

    /// Look up a transcript record by nullifier.
    pub fn lookup_by_nullifier(&self, nullifier: &Felt252) -> Option<TranscriptRecord> {
        self.try_lookup_by_nullifier(nullifier).ok().flatten()
    }

    /// Like `lookup_by_nullifier`, but a lock or SQLite failure is an error,
    /// never a missing record.
    pub fn try_lookup_by_nullifier(
        &self,
        nullifier: &Felt252,
    ) -> Result<Option<TranscriptRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        conn.query_row(
            "SELECT * FROM nullifiers WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            row_to_record,
        )
        .optional()
        .map_err(|e| ServerError::Database(format!("nullifier lookup failed: {}", e)))
    }

    /// Look up a transcript record by client request ID.
    pub fn lookup_by_client_id(&self, client_request_id: &str) -> Option<TranscriptRecord> {
        self.try_lookup_by_client_id(client_request_id)
            .ok()
            .flatten()
    }

    /// Like `lookup_by_client_id`, but a lock or SQLite failure is an error,
    /// never a missing record.
    pub fn try_lookup_by_client_id(
        &self,
        client_request_id: &str,
    ) -> Result<Option<TranscriptRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        conn.query_row(
            "SELECT * FROM nullifiers WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_record,
        )
        .optional()
        .map_err(|e| ServerError::Database(format!("request lookup failed: {e}")))
    }

    /// Reserve a nullifier for clearance (withdrawal signing). `auth` records
    /// how the caller proved note ownership: "ownership_proof" or "legacy".
    /// The reservation is permanent: the clearance signature never expires.
    pub fn reserve_clearance(&self, nullifier: &Felt252, auth: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {}", e)))?;
        let now = current_timestamp();
        let null_hex = nullifier.to_hex();

        conn.execute(
            "INSERT INTO nullifiers (nullifier, status, clearance_auth, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![
                null_hex,
                status_to_str(NullifierStatus::ClearanceReserved),
                auth,
                now as i64,
            ],
        )
        .map_err(|e| {
            if let rusqlite::Error::SqliteFailure(ref err, _) = e {
                if err.code == rusqlite::ErrorCode::ConstraintViolation {
                    return ServerError::NullifierUsed;
                }
            }
            ServerError::Database(format!("clearance reserve failed: {}", e))
        })?;

        Ok(())
    }

    /// How a clearance reservation was authorized (None: before this was
    /// recorded, or not a clearance reservation).
    pub fn clearance_auth(&self, nullifier: &Felt252) -> Result<Option<String>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| ServerError::Database(format!("lock poisoned: {e}")))?;
        conn.query_row(
            "SELECT clearance_auth FROM nullifiers WHERE nullifier = ?1",
            params![nullifier.to_hex()],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map(Option::flatten)
        .map_err(|e| ServerError::Database(format!("clearance lookup failed: {e}")))
    }

    /// Get all reserved (not yet finalized) entries, for crash recovery.
    pub fn get_reserved_entries(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers WHERE status = ?1") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map(
            params![status_to_str(NullifierStatus::Reserved)],
            row_to_record,
        ) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Get all nullifiers (for challenge watcher).
    pub fn get_all_nullifiers(&self) -> Vec<TranscriptRecord> {
        let conn = match self.conn.lock() {
            Ok(c) => c,
            Err(_) => return Vec::new(),
        };

        let mut stmt = match conn.prepare("SELECT * FROM nullifiers") {
            Ok(s) => s,
            Err(_) => return Vec::new(),
        };

        let rows = match stmt.query_map([], row_to_record) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

        rows.filter_map(|r| r.ok()).collect()
    }

    /// Persist a lease before contacting OpenRouter, closing the normal crash
    /// window between nullifier reservation and external key provisioning.
    pub fn create_openrouter_lease(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
    ) -> Result<(), ServerError> {
        self.create_openrouter_lease_with_oa_id(
            request,
            key_source,
            issued_at,
            expires_at,
            settle_after,
            spending_limit_usd,
            None,
        )
    }

    // Extends the legacy constructor without changing existing callers.
    #[allow(clippy::too_many_arguments)]
    pub fn create_openrouter_lease_with_oa_id(
        &self,
        request: &ApiRequestV2,
        key_source: &str,
        issued_at: u64,
        expires_at: u64,
        settle_after: u64,
        spending_limit_usd: f64,
        oa_client_request_id: Option<&str>,
    ) -> Result<(), ServerError> {
        self.create_openrouter_lease_bound(&NewOpenRouterLease {
            request,
            key_source,
            issued_at,
            expires_at,
            settle_after,
            spending_limit_usd,
            oa_client_request_id,
            ttl_seconds: None,
            settlement_deadline_at: None,
            delivered: None,
        })
    }

    /// Persist a lease with its frozen TTL and write-once settlement
    /// deadline. A row created without a deadline is assigned one, once, the
    /// first time the settler sees it.
    pub fn create_openrouter_lease_bound(
        &self,
        lease: &NewOpenRouterLease<'_>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        insert_lease_row(&conn, lease)
    }

    /// Durably fence upstream I/O before sending an OA issuance request. Only
    /// the first attempt may establish confirmed non-issuance from a definitive
    /// rejection; a retry cannot erase an earlier ambiguous result. The caller
    /// must hold its issuance lock through the upstream call and classification.
    pub(crate) fn begin_oa_issuance(&self, client_request_id: &str) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| {
                ServerError::Database(format!("OA issuance transaction failed: {error}"))
            })?;
        let prior = transaction
            .query_row(
                "SELECT oa_provisioning_outcome FROM openrouter_leases
                 WHERE client_request_id = ?1 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL",
                params![client_request_id],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|error| {
                ServerError::Database(format!("OA issuance state read failed: {error}"))
            })?
            .ok_or_else(|| ServerError::Internal("lease cannot begin OA issuance".to_string()))?;
        let outcome = OaProvisioningOutcome::from_db(&prior);
        if outcome == OaProvisioningOutcome::ConfirmedUnissued {
            return Err(ServerError::Internal(
                "confirmed unissued lease cannot resume issuance".to_string(),
            ));
        }
        let rows = transaction
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'may_have_issued', updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL AND oa_provisioning_outcome = ?3",
                params![current_timestamp() as i64, client_request_id, prior],
            )
            .map_err(|error| ServerError::Database(format!("OA issuance fence failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        transaction.commit().map_err(|error| {
            ServerError::Database(format!("OA issuance commit failed: {error}"))
        })?;
        Ok(outcome == OaProvisioningOutcome::NotStarted)
    }

    /// Mark a first attempt's definitive pre-issuance rejection for zero-charge
    /// recovery. This must never be called for an ambiguous or retried attempt.
    pub(crate) fn confirm_oa_unissued(&self, client_request_id: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let now = current_timestamp() as i64;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET oa_provisioning_outcome = 'confirmed_unissued',
                    settle_after = ?1, updated_at = ?1
                 WHERE client_request_id = ?2 AND key_source = 'oa_org'
                   AND status = 'provisioning' AND key_hash IS NULL
                   AND oa_provisioning_outcome = 'may_have_issued'",
                params![now, client_request_id],
            )
            .map_err(|error| {
                ServerError::Database(format!("OA non-issuance update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "OA issuance state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn update_openrouter_lease_timing(
        &self,
        client_request_id: &str,
        expires_at: u64,
        settle_after: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET expires_at = ?1, settle_after = ?2, updated_at = ?3
                 WHERE client_request_id = ?4 AND status = 'provisioning'",
                params![
                    expires_at as i64,
                    settle_after as i64,
                    current_timestamp() as i64,
                    client_request_id,
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease timing update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    pub fn activate_openrouter_lease(
        &self,
        client_request_id: &str,
        key_hash: &str,
    ) -> Result<(), ServerError> {
        self.activate_openrouter_lease_from(client_request_id, key_hash, None)
    }

    /// Activate a lease with the key `key_hash`, recording the identity of
    /// the key source that issued it (`OpenRouterLeaseSourceConfig::identity`)
    /// for the startup key-source check. None keeps the recorded identity.
    pub(crate) fn activate_openrouter_lease_from(
        &self,
        client_request_id: &str,
        key_hash: &str,
        key_source_identity: Option<&str>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        // A lease committed to a zero settlement never activates a key.
        let rows = conn
            .execute(
                "UPDATE openrouter_leases
                 SET status = 'active', key_hash = ?1, updated_at = ?2,
                     key_source_identity = COALESCE(?4, key_source_identity)
                 WHERE client_request_id = ?3 AND status = 'provisioning'
                   AND charge_basis IS NULL",
                params![
                    key_hash,
                    current_timestamp() as i64,
                    client_request_id,
                    key_source_identity
                ],
            )
            .map_err(|error| ServerError::Database(format!("lease activation failed: {error}")))?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not in provisioning state".to_string(),
            ));
        }
        Ok(())
    }

    /// Record that the runtime key of an activated lease is being returned to
    /// the client. Only such a lease can be charged more than zero. Refused
    /// once the lease is committed to a zero settlement (or conceded): its key
    /// must then never be returned.
    pub(crate) fn mark_openrouter_lease_delivered(
        &self,
        client_request_id: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET delivered = 1, updated_at = ?1
                 WHERE client_request_id = ?2 AND status = 'active' AND charge_basis IS NULL",
                params![current_timestamp() as i64, client_request_id],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease delivery update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease was not active, or was settling, when its key was returned".to_string(),
            ));
        }
        Ok(())
    }

    /// Commit a never-delivered lease to its zero settlement before the
    /// successor is signed (`charge_basis = 'unissued'`). From then on its key
    /// can neither be activated nor marked delivered, so it is never returned.
    /// Returns false, changing nothing, when the key was delivered (or the
    /// row changed) first. Idempotent for a row already fenced.
    pub(crate) fn fence_unissued_settlement(
        &self,
        client_request_id: &str,
    ) -> Result<bool, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET charge_basis = 'unissued', updated_at = ?1
                 WHERE client_request_id = ?2
                   AND (charge_basis IS NULL OR charge_basis = 'unissued')
                   AND ((status = 'provisioning' AND key_hash IS NULL
                         AND COALESCE(delivered, 0) = 0)
                        OR (status IN ('active', 'retiring', 'disabled', 'revoking')
                            AND delivered = 0))",
                params![current_timestamp() as i64, client_request_id],
            )
            .map_err(|error| ServerError::Database(format!("lease fence failed: {error}")))?;
        Ok(rows == 1)
    }

    /// Assign the write-once settlement deadline of a lease recorded without
    /// one (rows from before the upgrade) and return the stored value.
    pub(crate) fn assign_settlement_deadline(
        &self,
        client_request_id: &str,
        deadline: u64,
    ) -> Result<u64, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "UPDATE openrouter_leases SET settlement_deadline_at = ?1
             WHERE client_request_id = ?2 AND settlement_deadline_at IS NULL",
            params![sql_time(deadline), client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("deadline assignment failed: {error}")))?;
        conn.query_row(
            "SELECT settlement_deadline_at FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .map_err(|error| ServerError::Database(format!("deadline read failed: {error}")))?
        .map(|value| value.max(0) as u64)
        .ok_or_else(|| ServerError::Internal("lease deadline was not stored".into()))
    }

    /// Non-terminal leases still without a settlement deadline:
    /// (client_request_id, expires_at).
    pub(crate) fn leases_without_settlement_deadline(
        &self,
    ) -> Result<Vec<(String, u64)>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, expires_at FROM openrouter_leases
                 WHERE settlement_deadline_at IS NULL
                   AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
            )
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?.max(0) as u64,
                ))
            })
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("deadline scan failed: {error}")))
    }

    pub fn remove_failed_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "DELETE FROM openrouter_leases
             WHERE client_request_id = ?1 AND status = 'provisioning' AND key_hash IS NULL",
            params![client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("lease cleanup failed: {error}")))?;
        Ok(())
    }

    pub fn lookup_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Option<OpenRouterLeaseRecord> {
        self.try_lookup_openrouter_lease(client_request_id)
            .ok()
            .flatten()
    }

    /// Like `lookup_openrouter_lease`, but a lock or SQLite failure is a
    /// (retriable) database error, and a row that cannot be decoded is
    /// `LeaseRecordUnreadable`; neither is ever a missing lease.
    pub fn try_lookup_openrouter_lease(
        &self,
        client_request_id: &str,
    ) -> Result<Option<OpenRouterLeaseRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.query_row(
            "SELECT * FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            row_to_openrouter_lease,
        )
        .optional()
        .map_err(|error| match error {
            rusqlite::Error::FromSqlConversionFailure(..)
            | rusqlite::Error::InvalidColumnType(..)
            | rusqlite::Error::IntegralValueOutOfRange(..) => {
                tracing::error!(
                    %client_request_id,
                    error = %error,
                    "lease row cannot be decoded; operator repair required"
                );
                ServerError::LeaseRecordUnreadable
            }
            error => ServerError::Database(format!("lease lookup failed: {error}")),
        })
    }

    /// Leases to settle now, least recently attempted first: delivered or
    /// possibly delivered leases after their drain and any deferral of a
    /// pending result (or at their settlement deadline, whatever the
    /// deferral), never-issued provisioning rows of a known source, which
    /// finalize at zero, and leases already committed to a zero (or
    /// conceded) charge. Unreadable rows are logged by id, never silently
    /// skipped; they are also counted by `settlement_counts`. Such a row is
    /// not settled, not even at its deadline, until its saved request is
    /// restored (`reopen_cancelled_lease` with `saved_request`).
    pub fn due_openrouter_leases(&self, now: u64) -> Vec<OpenRouterLeaseRecord> {
        let conn = match self.conn.lock() {
            Ok(conn) => conn,
            Err(_) => {
                tracing::error!("settlement scan failed: database lock poisoned");
                return Vec::new();
            }
        };
        let mut statement = match conn.prepare(
            "SELECT * FROM openrouter_leases
             WHERE (status IN ('active', 'retiring', 'disabled', 'revoking')
                    AND ((settle_after <= ?1 AND COALESCE(next_attempt_at, 0) <= ?1)
                         OR settlement_deadline_at <= ?1))
                OR (status = 'provisioning' AND key_hash IS NULL
                    AND key_source IN ('openrouter', 'oa_org')
                    AND (settle_after <= ?1 OR settlement_deadline_at <= ?1
                         OR oa_provisioning_outcome = 'confirmed_unissued'))
                OR (status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')
                    AND charge_basis IS NOT NULL AND key_source IN ('openrouter', 'oa_org'))
             ORDER BY updated_at ASC, settle_after ASC",
        ) {
            Ok(statement) => statement,
            Err(error) => {
                tracing::error!(error = %error, "settlement scan failed");
                return Vec::new();
            }
        };
        // The row's id is read apart from its decoding, so that an unreadable
        // row is named for its repair.
        let rows = match statement.query_map(params![sql_time(now)], |row| {
            Ok((
                row.get::<_, String>("client_request_id"),
                row_to_openrouter_lease(row),
            ))
        }) {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(error = %error, "settlement scan failed");
                return Vec::new();
            }
        };
        rows.filter_map(|row| match row {
            Ok((_, Ok(lease))) => Some(lease),
            Ok((client_request_id, Err(error))) => {
                tracing::error!(
                    client_request_id = client_request_id.as_deref().unwrap_or("<unreadable>"),
                    error = %error,
                    "unreadable OpenRouter lease row cannot be settled, and its settlement \
                     deadline does not apply, until an operator repairs it (an unreadable \
                     saved request: zkapi settlement reopen --saved-request)"
                );
                None
            }
            Err(error) => {
                tracing::error!(error = %error, "settlement scan failed on a lease row");
                None
            }
        })
        .collect()
    }

    /// Record a failed settlement attempt. `first_error_at` is set once and
    /// never reset; `settlement_attempts` only grows. A failure ends any
    /// deferral of an earlier pending result: the lease is retried next tick.
    pub fn record_openrouter_lease_error(
        &self,
        client_request_id: &str,
        error: &str,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|cause| ServerError::Database(format!("lock poisoned: {cause}")))?;
        let now = current_timestamp() as i64;
        conn.execute(
            "UPDATE openrouter_leases SET last_error = ?1, updated_at = ?2,
                settlement_attempts = settlement_attempts + 1,
                first_error_at = COALESCE(first_error_at, ?2), next_attempt_at = NULL
             WHERE client_request_id = ?3 AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
            params![error, now, client_request_id],
        )
        .map_err(|cause| ServerError::Database(format!("lease error update failed: {cause}")))?;
        Ok(())
    }

    /// Record a settlement attempt that ended pending (an OA receipt not yet
    /// final, or a direct key's drain interval): not a failure, so neither
    /// the attempt count nor the errors change. The lease moves behind every
    /// other lease in the least-recently-attempted order and is not due for
    /// provider I/O again before `next_attempt_at`; its settlement deadline
    /// still applies.
    pub(crate) fn defer_openrouter_lease_settlement(
        &self,
        client_request_id: &str,
        next_attempt_at: u64,
        now: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "UPDATE openrouter_leases SET next_attempt_at = ?1, updated_at = ?2
             WHERE client_request_id = ?3
               AND status IN ('active', 'retiring', 'disabled', 'revoking')",
            params![sql_time(next_attempt_at), sql_time(now), client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("lease deferral failed: {error}")))?;
        Ok(())
    }

    /// When a deferred pending settlement of a lease is next asked
    /// (`defer_openrouter_lease_settlement`); None when it was never deferred
    /// or the lease is unknown.
    pub(crate) fn openrouter_lease_next_attempt_at(
        &self,
        client_request_id: &str,
    ) -> Result<Option<u64>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.query_row(
            "SELECT next_attempt_at FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            |row| row.get::<_, Option<i64>>(0),
        )
        .optional()
        .map(|value| value.flatten().map(|value| value.max(0) as u64))
        .map_err(|error| ServerError::Database(format!("lease deferral read failed: {error}")))
    }

    /// Persist the direct-key retirement state before each external side
    /// effect, so revocation and settlement resume after failures or restarts.
    /// A new phase is scheduled by its `settle_after` alone.
    pub fn advance_openrouter_retirement(
        &self,
        client_request_id: &str,
        from: &str,
        to: &str,
        settle_after: u64,
        usage_usd: Option<f64>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let rows = conn
            .execute(
                "UPDATE openrouter_leases SET status = ?1, settle_after = ?2,
                usage_usd = COALESCE(?3, usage_usd), last_error = NULL, updated_at = ?4,
                next_attempt_at = NULL
             WHERE client_request_id = ?5 AND key_source = 'openrouter' AND status = ?6",
                params![
                    to,
                    settle_after as i64,
                    usage_usd,
                    current_timestamp() as i64,
                    client_request_id,
                    from
                ],
            )
            .map_err(|error| {
                ServerError::Database(format!("lease retirement update failed: {error}"))
            })?;
        if rows != 1 {
            return Err(ServerError::Internal(
                "lease retirement state changed".to_string(),
            ));
        }
        Ok(())
    }

    pub fn finalize_openrouter_lease(
        &self,
        client_request_id: &str,
        usage_usd: f64,
        charge_applied: u128,
    ) -> Result<(), ServerError> {
        self.finalize_openrouter_lease_with(
            client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied,
                charge_basis: "measured",
                review: None,
                key_cleanup: None,
                guard: FinalizeGuard::NotCancelled,
            },
        )
        .map(|_| ())
    }

    /// Finalize a lease row after its signed transcript committed, recording
    /// how the charge was determined, an optional review, and an optional
    /// provider-key cleanup, in one transaction. Returns false (and changes
    /// nothing) when the row no longer satisfies `finalization.guard`.
    pub(crate) fn finalize_openrouter_lease_with(
        &self,
        client_request_id: &str,
        finalization: &LeaseFinalization<'_>,
    ) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        let now = current_timestamp() as i64;
        let condition = finalization.guard.condition();
        let rows = transaction
            .execute(
                &format!(
                    "UPDATE openrouter_leases SET
                        status = 'finalized', usage_usd = ?1, charge_applied = ?2,
                        charge_basis = ?3, last_error = NULL, updated_at = ?4
                     WHERE client_request_id = ?5 AND {condition}"
                ),
                params![
                    finalization.usage_usd,
                    finalization.charge_applied as i64,
                    finalization.charge_basis,
                    now,
                    client_request_id,
                ],
            )
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        if rows != 1 {
            return Ok(false);
        }
        if let Some(review) = finalization.review {
            insert_review(&transaction, review, now)?;
        }
        if let Some(cleanup) = finalization.key_cleanup {
            insert_key_cleanup(&transaction, client_request_id, &cleanup, now)?;
        }
        transaction
            .commit()
            .map_err(|error| ServerError::Database(format!("lease finalize failed: {error}")))?;
        Ok(true)
    }

    #[cfg(test)]
    pub(crate) fn cancel_openrouter_lease(
        &self,
        client_request_id: &str,
        review: &SettlementReview,
    ) -> Result<(), ServerError> {
        self.cancel_corrupt_openrouter_lease(client_request_id, review, None)
    }

    /// Record the `binding_corrupt` review of a pending lease as soon as its
    /// corrupt binding is found, while its cancellation waits for the usage
    /// capture of its direct key: once, unless the lease has such a review
    /// since its last reopening. The cancellation records its own. Returns
    /// whether it was recorded.
    pub(crate) fn review_corrupt_binding(
        &self,
        review: &SettlementReview,
    ) -> Result<bool, ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServerError::Database(format!("review insert failed: {error}")))?;
        if binding_corrupt_reviewed(&transaction, &review.client_request_id)? {
            return Ok(false);
        }
        insert_review(&transaction, review, current_timestamp() as i64)?;
        transaction
            .commit()
            .map_err(|error| ServerError::Database(format!("review insert failed: {error}")))?;
        Ok(true)
    }

    /// Mark a lease whose binding is corrupt as cancelled, with its review
    /// and, for a direct key, its queued cleanup, in one transaction: once
    /// that cleanup row is gone, the key is deleted. Nothing is signed for
    /// the lease; its reservation stays Reserved until the operator repairs
    /// the binding and reopens it (`reopen_cancelled_lease`).
    pub(crate) fn cancel_corrupt_openrouter_lease(
        &self,
        client_request_id: &str,
        review: &SettlementReview,
        key_cleanup: Option<KeyCleanup<'_>>,
    ) -> Result<(), ServerError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))?;
        let now = current_timestamp() as i64;
        // A charge basis committed before the cancellation no longer applies;
        // a reopening decides afresh.
        let rows = transaction
            .execute(
                "UPDATE openrouter_leases SET status = 'cancelled', charge_basis = NULL,
                    last_error = ?1, updated_at = ?2
                 WHERE client_request_id = ?3
                   AND status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')",
                params![truncate_detail(&review.detail), now, client_request_id],
            )
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))?;
        if rows == 0 {
            // Already terminal: nothing to cancel or review.
            return Ok(());
        }
        insert_review(&transaction, review, now)?;
        if let Some(cleanup) = key_cleanup {
            insert_key_cleanup(&transaction, client_request_id, &cleanup, now)?;
        }
        transaction
            .commit()
            .map_err(|error| ServerError::Database(format!("lease cancel failed: {error}")))
    }

    /// Whether the operator reopened this lease (`binding_reopened` review):
    /// the server then verifies its saved request again before signing.
    pub(crate) fn lease_reopened(&self, client_request_id: &str) -> Result<bool, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM settlement_reviews
                            WHERE client_request_id = ?1 AND reason = 'binding_reopened')",
            params![client_request_id],
            |row| row.get(0),
        )
        .map_err(|error| ServerError::Database(format!("review lookup failed: {error}")))
    }

    /// Operator remediation of a lease cancelled with a `binding_corrupt`
    /// review: return it to the settlement state machine, keeping its
    /// write-once deadline. Refuses, changing nothing, unless the lease is
    /// cancelled with such a review, its nullifier is not reserved for a
    /// clearance, its saved request is the one its owner's proof authorized
    /// (`verify`, as admission verified it), and its row agrees with its
    /// reservation. A review left under an id the lease row no longer has (an
    /// id repaired by hand) is found by the row's nullifier, and joins it.
    ///
    /// `options.saved_request` restores a saved request that does not verify
    /// or cannot be read, from a copy whose authenticity the database proves
    /// (`restore_saved_request`). The request verifying, a disagreement on the
    /// other side is repaired from it with `options.rebind`: the lease row's
    /// client_request_id and request_nullifier are rewritten (its reviews
    /// move with its id), a Reserved row's authenticators are rewritten, or a
    /// missing row is re-created.
    ///
    /// A lease without a key resumes provisioning, a direct lease whose usage
    /// was captured resumes revoking, and any other resumes active. A lease
    /// never delivered is committed to its zero settlement (`unissued`), so
    /// its key is never returned. Any other settles at its captured usage, or
    /// from measured usage until its deadline; at its solvency bound when no
    /// usage can be measured (its deadline passed, or its direct key was
    /// deleted before its usage was captured). A key deletion queued by the
    /// cancellation is withdrawn, also one queued under an id the row no
    /// longer has: settlement reads the key's usage first.
    /// `options.zero_charge` commits it to a zero charge instead
    /// (`operator_conceded`), also for a lease reopened earlier and not yet
    /// signed, after the same checks and repairs. Either way, records a
    /// `binding_reopened` review and acknowledges the lease's open
    /// `binding_corrupt` reviews. The server verifies a reopened lease's
    /// request, binding, deployment and signing key again before it signs
    /// anything.
    ///
    /// A pending lease whose saved request cannot be read is skipped by the
    /// settlement scan, so neither its deadline nor a cancellation ever
    /// reaches it. `options.saved_request` restores that request, after the
    /// same checks, keeping the lease's status, deadline and any committed
    /// charge (`restored_pending`): the server then settles it as any pending
    /// lease, verifying the restored request again first. A `binding_reopened`
    /// review records the repair, so that `options.zero_charge` (in the same
    /// run or a later one) can concede its charge.
    pub(crate) fn reopen_cancelled_lease(
        &self,
        client_request_id: &str,
        options: ReopenOptions<'_>,
        verify: SavedRequestCheck<'_>,
        now: u64,
    ) -> Result<ReopenedLease, ReopenRefusal> {
        let failed =
            |error: rusqlite::Error| ServerError::Database(format!("lease reopen failed: {error}"));
        let mut conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let transaction = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(failed)?;
        let (status, row_nullifier): (String, String) = transaction
            .query_row(
                "SELECT status, request_nullifier FROM openrouter_leases
                 WHERE client_request_id = ?1",
                params![client_request_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(failed)?
            .ok_or_else(|| ReopenRefusal::UnknownLease(client_request_id.to_string()))?;
        // Reviews record the nullifier in canonical hex.
        let row_nullifier = Felt252::from_hex(&row_nullifier)
            .map(|nullifier| nullifier.to_hex())
            .unwrap_or(row_nullifier);
        let reviewed = |reason: &str| -> Result<bool, ServerError> {
            transaction
                .query_row(
                    "SELECT EXISTS (SELECT 1 FROM settlement_reviews
                                    WHERE reason = ?3
                                      AND (client_request_id = ?1
                                           OR (request_nullifier = ?2 AND client_request_id
                                               NOT IN (SELECT client_request_id
                                                       FROM openrouter_leases))))",
                    params![client_request_id, row_nullifier, reason],
                    |row| row.get(0),
                )
                .map_err(failed)
        };
        // A lease reopened earlier can still be conceded until it is signed.
        let conceding = status != "cancelled";
        let pending = PENDING_LEASE_STATUSES.contains(&status.as_str());
        // A pending lease whose saved request cannot be read is skipped by
        // every settlement tick, its deadline included, and cannot be
        // cancelled either: only restoring its saved request (keeping its
        // status) returns it to settlement.
        let restoring_pending = pending
            && options.saved_request.is_some()
            && !saved_request_readable(&transaction, client_request_id)?;
        if !conceding {
            if !reviewed("binding_corrupt")? {
                return Err(ReopenRefusal::NotBindingCorrupt);
            }
        } else if !restoring_pending
            && !(options.zero_charge && pending && reviewed("binding_reopened")?)
        {
            // Another undecodable column keeps a pending row with a readable
            // saved request from every scan too: name it instead.
            if pending && saved_request_readable(&transaction, client_request_id)? {
                if let Some(detail) = lease_row_undecodable(&transaction, client_request_id)? {
                    return Err(ReopenRefusal::RowUndecodable { status, detail });
                }
            }
            // A possibly delivered direct lease is reviewed when its binding
            // is found corrupt, and cancelled once its key's usage is
            // captured.
            if pending && binding_corrupt_reviewed(&transaction, client_request_id)? {
                return Err(ReopenRefusal::CapturePending(status));
            }
            return Err(ReopenRefusal::NotCancelled(status));
        }
        let saved_request = match options.saved_request {
            Some(supplied) => restore_saved_request(
                &transaction,
                client_request_id,
                &row_nullifier,
                supplied,
                verify,
            )?,
            None => "unchanged",
        };
        let read_lease = |id: &str| {
            transaction.query_row(
                "SELECT * FROM openrouter_leases WHERE client_request_id = ?1",
                params![id],
                row_to_openrouter_lease,
            )
        };
        let mut lease = match read_lease(client_request_id) {
            Ok(lease) => lease,
            Err(_)
                if saved_request == "unchanged"
                    && !saved_request_readable(&transaction, client_request_id)? =>
            {
                return Err(ReopenRefusal::BindingCorrupt(BindingMismatch {
                    field: SAVED_REQUEST_FIELD,
                    detail: "is not a readable request",
                }))
            }
            Err(error) => return Err(failed(error).into()),
        };
        if !matches!(lease.key_source.as_str(), "openrouter" | "oa_org") {
            return Err(ReopenRefusal::UnsupportedKeySource(lease.key_source));
        }
        let reservation_of = |lease: &OpenRouterLeaseRecord| {
            transaction
                .query_row(
                    "SELECT * FROM nullifiers WHERE nullifier = ?1",
                    params![lease.request_nullifier.to_hex()],
                    row_to_record,
                )
                .optional()
                .map_err(failed)
        };
        let clearance_reserved = |record: &Option<TranscriptRecord>| {
            record
                .as_ref()
                .is_some_and(|record| record.status == NullifierStatus::ClearanceReserved)
        };
        let mut record = reservation_of(&lease)?;
        if clearance_reserved(&record) {
            return Err(ReopenRefusal::ClearanceReserved);
        }
        // The saved request first: only a request its owner's proof
        // authorized tells which side of a disagreement is corrupt, and only
        // such a request may be signed or have the other side derived from it.
        if let Some(mismatch) = verify(&lease.api_request) {
            return Err(ReopenRefusal::BindingCorrupt(mismatch));
        }
        let mut lease_row = "unchanged";
        let mut reservation = "unchanged";
        if let Some(mismatch) = lease_binding_mismatch(&lease, record.as_ref())? {
            if !options.rebind {
                return Err(ReopenRefusal::BindingCorrupt(mismatch));
            }
            if LEASE_ROW_FIELDS.contains(&mismatch.field) {
                rebind_lease_row(&transaction, &lease)?;
                lease_row = "rewritten";
                lease = read_lease(&lease.api_request.client_request_id).map_err(failed)?;
                record = reservation_of(&lease)?;
                if clearance_reserved(&record) {
                    return Err(ReopenRefusal::ClearanceReserved);
                }
            }
            if let Some(mismatch) = lease_binding_mismatch(&lease, record.as_ref())? {
                if !mismatch.field.starts_with("nullifiers.") {
                    return Err(ReopenRefusal::BindingCorrupt(mismatch));
                }
                reservation = rebind_reservation(&transaction, &lease, record.as_ref(), now)?;
                record = reservation_of(&lease)?;
                if let Some(mismatch) = lease_binding_mismatch(&lease, record.as_ref())? {
                    return Err(ReopenRefusal::BindingCorrupt(mismatch));
                }
            }
        }
        let id = lease.client_request_id.clone();
        let signed = record
            .as_ref()
            .is_some_and(|record| record.status == NullifierStatus::Finalized);
        if signed && options.zero_charge {
            return Err(ReopenRefusal::AlreadySigned);
        }
        // Settled (charge written once) but not signed yet: the lease settles
        // at that charge again, and it cannot be conceded.
        let settled = record
            .as_ref()
            .is_some_and(TranscriptRecord::settled_unsigned);
        if settled && options.zero_charge {
            return Err(ReopenRefusal::AlreadySettled);
        }
        // Reviews left under a former id of this row, repaired by hand, join
        // it, so that they are acknowledged with it.
        transaction
            .execute(
                "UPDATE settlement_reviews SET client_request_id = ?1
                 WHERE request_nullifier IN (?2, ?3) AND client_request_id != ?1
                   AND client_request_id NOT IN (SELECT client_request_id FROM openrouter_leases)",
                params![id, lease.request_nullifier.to_hex(), row_nullifier],
            )
            .map_err(failed)?;
        // Reopened or conceded, the lease's corrupt binding is handled, also
        // one found again after an earlier reopening.
        transaction
            .execute(
                "UPDATE settlement_reviews SET acknowledged_at = ?1
                 WHERE client_request_id = ?2 AND reason = 'binding_corrupt'
                   AND acknowledged_at IS NULL",
                params![sql_time(now), id],
            )
            .map_err(failed)?;
        let repaired = repair_note(
            saved_request,
            lease_row,
            client_request_id,
            &id,
            reservation,
        );
        let solvency_bound = lease.api_request.public_inputs.solvency_bound;
        let review = |charge_basis: Option<&str>, detail: String| SettlementReview {
            client_request_id: id.clone(),
            request_nullifier: lease.request_nullifier,
            key_source: lease.key_source.clone(),
            reason: "binding_reopened".into(),
            charge_basis: charge_basis.map(str::to_string),
            detail,
            reported_usage_micro_usd: None,
            charge_applied: None,
            solvency_bound,
        };
        if conceding && options.zero_charge {
            let conceded = transaction
                .execute(
                    "UPDATE openrouter_leases SET charge_basis = 'operator_conceded',
                        last_error = NULL, updated_at = ?1
                     WHERE client_request_id = ?2 AND status = ?3",
                    params![sql_time(now), id, status],
                )
                .map_err(failed)?;
            if conceded != 1 {
                return Err(
                    ServerError::Internal("reopened lease changed while conceding".into()).into(),
                );
            }
            let which = if restoring_pending {
                "pending"
            } else {
                "reopened"
            };
            insert_review(
                &transaction,
                &review(
                    Some("operator_conceded"),
                    format!(
                        "the operator conceded the charge of the {which} lease, still \
                         {status}{repaired}; settles: operator_conceded"
                    ),
                ),
                sql_time(now),
            )?;
            transaction.commit().map_err(failed)?;
            return Ok(ReopenedLease {
                client_request_id: lease.client_request_id,
                key_source: lease.key_source,
                status,
                delivered: lease.delivered,
                settlement_deadline_at: lease.settlement_deadline_at,
                settles: "operator_conceded",
                key_cleanup_withdrawn: false,
                reservation,
                lease_row,
                saved_request,
                warning: None,
                restored_pending: restoring_pending,
            });
        }
        if conceding {
            // A pending lease whose unreadable saved request was restored:
            // its status, deadline and any committed charge are kept, and
            // the next tick settles it as any pending lease. Its review makes
            // the server verify the restored request again before signing,
            // and lets a later run concede its charge (--zero-charge).
            let settles = if signed {
                "signed_transcript"
            } else if settled {
                "settled_charge"
            } else if lease.charge_basis.as_deref() == Some("operator_conceded") {
                "operator_conceded"
            } else if lease.charge_basis.is_some()
                || status == "provisioning"
                || lease.delivered == Some(false)
            {
                "zero_never_delivered"
            } else if lease.key_source == "openrouter"
                && status == "revoking"
                && lease.usage_usd.is_some()
            {
                "captured_usage"
            } else if lease
                .settlement_deadline_at
                .is_some_and(|deadline| deadline <= now)
            {
                "deadline_fallback"
            } else {
                "measured_until_deadline"
            };
            insert_review(
                &transaction,
                &review(
                    None,
                    format!("repaired pending lease kept {status}{repaired}; settles: {settles}"),
                ),
                sql_time(now),
            )?;
            transaction.commit().map_err(failed)?;
            return Ok(ReopenedLease {
                client_request_id: lease.client_request_id,
                key_source: lease.key_source,
                status,
                delivered: lease.delivered,
                settlement_deadline_at: lease.settlement_deadline_at,
                settles,
                key_cleanup_withdrawn: false,
                reservation,
                lease_row,
                saved_request,
                warning: (settles == "deadline_fallback").then_some(DEADLINE_FALLBACK_WARNING),
                restored_pending: true,
            });
        }
        let status = if lease.key_hash.is_none() {
            "provisioning"
        } else if lease.key_source == "openrouter" && lease.usage_usd.is_some() {
            "revoking"
        } else {
            "active"
        };
        // A key never returned to the client stays unreturned: the lease is
        // committed to its zero settlement now, as the settler commits it
        // before signing, so an exact retry can neither issue its key again
        // nor re-create its row with a new deadline.
        let never_delivered = status == "provisioning" || lease.delivered == Some(false);
        let charge_basis = if options.zero_charge {
            Some("operator_conceded")
        } else if never_delivered {
            Some("unissued")
        } else {
            None
        };
        let reopened = transaction
            .execute(
                "UPDATE openrouter_leases SET status = ?1, charge_basis = ?2, last_error = NULL,
                    updated_at = ?3, next_attempt_at = NULL
                 WHERE client_request_id = ?4 AND status = 'cancelled'",
                params![status, charge_basis, sql_time(now), id],
            )
            .map_err(failed)?;
        if reopened != 1 {
            return Err(
                ServerError::Internal("cancelled lease changed while reopening".into()).into(),
            );
        }
        // The cancellation queued it under the row's id then. That id may
        // since have been repaired (also by hand), so any queued deletion of
        // the lease's own key is withdrawn too.
        let key_cleanup_withdrawn = transaction
            .execute(
                "DELETE FROM provider_key_cleanup
                 WHERE client_request_id IN (?1, ?2) OR key_hash = ?3",
                params![client_request_id, id, lease.key_hash],
            )
            .map_err(failed)?
            > 0;
        // The cancellation queued the deletion of a direct key in its own
        // transaction. With that row gone, the key was deleted: a direct
        // lease resuming active (its usage never captured) cannot be measured.
        let unmeasurable =
            lease.key_source == "openrouter" && status == "active" && !key_cleanup_withdrawn;
        let settles = if signed {
            "signed_transcript"
        } else if settled {
            "settled_charge"
        } else if options.zero_charge {
            "operator_conceded"
        } else if never_delivered {
            "zero_never_delivered"
        } else if status == "revoking" {
            "captured_usage"
        } else if unmeasurable
            || lease
                .settlement_deadline_at
                .is_some_and(|deadline| deadline <= now)
        {
            "deadline_fallback"
        } else {
            "measured_until_deadline"
        };
        let warning = (settles == "deadline_fallback").then_some(DEADLINE_FALLBACK_WARNING);
        insert_review(
            &transaction,
            &review(
                charge_basis,
                format!(
                    "repaired binding reopened by the operator as {status}{repaired}; \
                     settles: {settles}"
                ),
            ),
            sql_time(now),
        )?;
        transaction.commit().map_err(failed)?;
        Ok(ReopenedLease {
            client_request_id: lease.client_request_id,
            key_source: lease.key_source,
            status: status.to_string(),
            delivered: lease.delivered,
            settlement_deadline_at: lease.settlement_deadline_at,
            settles,
            key_cleanup_withdrawn,
            reservation,
            lease_row,
            saved_request,
            warning,
            restored_pending: false,
        })
    }

    /// Queue a terminal direct lease's provider key for background cleanup.
    pub(crate) fn enqueue_key_cleanup(
        &self,
        client_request_id: &str,
        cleanup: &KeyCleanup<'_>,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        insert_key_cleanup(
            &conn,
            client_request_id,
            cleanup,
            current_timestamp() as i64,
        )
    }

    /// Queued key cleanups whose next attempt is due, oldest first.
    pub(crate) fn due_key_cleanups(
        &self,
        now: u64,
        limit: usize,
    ) -> Result<Vec<PendingKeyCleanup>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, key_source, key_hash, key_name, attempts
                 FROM provider_key_cleanup WHERE next_attempt_at <= ?1
                 ORDER BY next_attempt_at ASC LIMIT ?2",
            )
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))?;
        let rows = statement
            .query_map(params![sql_time(now), limit as i64], |row| {
                Ok(PendingKeyCleanup {
                    client_request_id: row.get(0)?,
                    key_source: row.get(1)?,
                    key_hash: row.get(2)?,
                    key_name: row.get(3)?,
                    attempts: row.get::<_, i64>(4)?.max(0) as u64,
                })
            })
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("key cleanup scan failed: {error}")))
    }

    pub(crate) fn complete_key_cleanup(&self, client_request_id: &str) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        conn.execute(
            "DELETE FROM provider_key_cleanup WHERE client_request_id = ?1",
            params![client_request_id],
        )
        .map_err(|error| ServerError::Database(format!("key cleanup update failed: {error}")))?;
        Ok(())
    }

    pub(crate) fn defer_key_cleanup(
        &self,
        client_request_id: &str,
        error: &str,
        next_attempt_at: u64,
    ) -> Result<(), ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|cause| ServerError::Database(format!("lock poisoned: {cause}")))?;
        conn.execute(
            "UPDATE provider_key_cleanup SET attempts = attempts + 1, last_error = ?1,
                next_attempt_at = ?2
             WHERE client_request_id = ?3",
            params![
                truncate_detail(error),
                sql_time(next_attempt_at),
                client_request_id
            ],
        )
        .map_err(|cause| ServerError::Database(format!("key cleanup update failed: {cause}")))?;
        Ok(())
    }

    /// Per key source and recorded identity of its issuer (None for a lease
    /// activated by an earlier release, or a deletion queued without a
    /// lease), what only that issuer's credential can still settle or delete
    /// (`KeySourceBacklog`), at `now`. Read-only.
    pub(crate) fn key_source_backlog(
        &self,
        now: u64,
    ) -> Result<std::collections::BTreeMap<(String, Option<String>), KeySourceBacklog>, ServerError>
    {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let failed = |error: rusqlite::Error| {
            ServerError::Database(format!("key source backlog scan failed: {error}"))
        };
        let mut backlog =
            std::collections::BTreeMap::<(String, Option<String>), KeySourceBacklog>::new();
        let now = sql_time(now);
        for (sql, leases) in [
            // A lease past its settlement deadline does not count: any
            // configuration finalizes it without provider I/O, at the same
            // charge.
            (
                "SELECT key_source, key_source_identity, COUNT(*) FROM openrouter_leases
                 WHERE status IN ('active', 'retiring', 'disabled', 'revoking')
                   AND COALESCE(delivered, 1) != 0 AND charge_basis IS NULL
                   AND (settlement_deadline_at IS NULL OR settlement_deadline_at > ?1)
                 GROUP BY key_source, key_source_identity",
                true,
            ),
            (
                "SELECT cleanup.key_source, lease.key_source_identity, COUNT(*)
                 FROM provider_key_cleanup AS cleanup
                 LEFT JOIN openrouter_leases AS lease
                   ON lease.client_request_id = cleanup.client_request_id
                 WHERE lease.expires_at IS NULL OR lease.expires_at > ?1
                 GROUP BY cleanup.key_source, lease.key_source_identity",
                false,
            ),
        ] {
            let mut statement = conn.prepare(sql).map_err(failed)?;
            let rows = statement
                .query_map(params![now], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, Option<String>>(1)?,
                        row.get::<_, i64>(2)?.max(0) as u64,
                    ))
                })
                .map_err(failed)?;
            for row in rows {
                let (source, identity, count) = row.map_err(failed)?;
                let entry = backlog.entry((source, identity)).or_default();
                if leases {
                    entry.unsettled_leases = count;
                } else {
                    entry.queued_key_deletions = count;
                }
            }
        }
        Ok(backlog)
    }

    /// Non-terminal leases, nearest settlement deadline first. Read-only.
    pub fn pending_openrouter_leases(
        &self,
        limit: usize,
    ) -> Result<Vec<OpenRouterLeaseRecord>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT * FROM openrouter_leases
                 WHERE status IN ('provisioning', 'active', 'retiring', 'disabled', 'revoking')
                 ORDER BY settlement_deadline_at IS NULL, settlement_deadline_at, expires_at
                 LIMIT ?1",
            )
            .map_err(|error| {
                ServerError::Database(format!("pending lease scan failed: {error}"))
            })?;
        let rows = statement
            .query_map(params![limit as i64], row_to_openrouter_lease)
            .map_err(|error| {
                ServerError::Database(format!("pending lease scan failed: {error}"))
            })?;
        // A view: unreadable rows are reported by settlement_counts instead.
        Ok(rows.filter_map(Result::ok).collect())
    }

    /// Settlement reviews, newest first. Read-only.
    pub fn settlement_reviews(
        &self,
        limit: usize,
    ) -> Result<Vec<StoredSettlementReview>, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, request_nullifier, key_source, reason, charge_basis,
                    detail, reported_usage_micro_usd, charge_applied, solvency_bound, created_at,
                    acknowledged_at
                 FROM settlement_reviews ORDER BY created_at DESC, review_id DESC LIMIT ?1",
            )
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))?;
        let rows = statement
            .query_map(params![limit as i64], |row| {
                let decimal = |value: Option<String>| value.and_then(|v| v.parse::<u128>().ok());
                Ok(StoredSettlementReview {
                    review: SettlementReview {
                        client_request_id: row.get(0)?,
                        request_nullifier: Felt252::from_hex(&row.get::<_, String>(1)?)
                            .unwrap_or(Felt252::ZERO),
                        key_source: row.get(2)?,
                        reason: row.get(3)?,
                        charge_basis: row.get(4)?,
                        detail: row.get(5)?,
                        reported_usage_micro_usd: decimal(row.get(6)?),
                        charge_applied: row.get::<_, Option<i64>>(7)?.map(|value| value as u128),
                        solvency_bound: decimal(row.get(8)?).unwrap_or_default(),
                    },
                    created_at: row.get::<_, i64>(9)?.max(0) as u64,
                    acknowledged_at: row.get::<_, Option<i64>>(10)?.map(|value| value as u64),
                })
            })
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|error| ServerError::Database(format!("review scan failed: {error}")))
    }

    /// Aggregate settlement state from raw SQL, so rows that cannot be
    /// decoded are still counted. Read-only.
    pub fn settlement_counts(
        &self,
        now: u64,
    ) -> Result<crate::dashboard::SettlementCounts, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|error| ServerError::Database(format!("lock poisoned: {error}")))?;
        let count = |sql: &str| -> Result<u64, ServerError> {
            conn.query_row(sql, [], |row| row.get::<_, i64>(0))
                .map(|value| value.max(0) as u64)
                .map_err(|error| ServerError::Database(format!("settlement count failed: {error}")))
        };
        let pending = count(
            "SELECT COUNT(*) FROM openrouter_leases
             WHERE status NOT IN ('finalized', 'cancelled', 'exit_deferred', 'exited_unsigned')",
        )?;
        let retrying = count(
            "SELECT COUNT(*) FROM openrouter_leases
             WHERE status NOT IN ('finalized', 'cancelled', 'exit_deferred', 'exited_unsigned')
               AND (settlement_attempts > 0 OR last_error IS NOT NULL)",
        )?;
        let exit_deferred =
            count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'exit_deferred'")?;
        let exited_unsigned =
            count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'exited_unsigned'")?;
        let provisioning =
            count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'provisioning'")?;
        let cancelled = count("SELECT COUNT(*) FROM openrouter_leases WHERE status = 'cancelled'")?;
        let unknown_status = count(
            "SELECT COUNT(*) FROM openrouter_leases WHERE status NOT IN
                ('provisioning', 'active', 'retiring', 'disabled', 'revoking', 'finalized',
                 'cancelled', 'exit_deferred', 'exited_unsigned')",
        )?;
        let open_reviews =
            count("SELECT COUNT(*) FROM settlement_reviews WHERE acknowledged_at IS NULL")?;
        let pending_key_cleanups = count("SELECT COUNT(*) FROM provider_key_cleanup")?;
        let next_deadline: Option<i64> = conn
            .query_row(
                "SELECT MIN(settlement_deadline_at) FROM openrouter_leases
                 WHERE status NOT IN ('finalized', 'cancelled', 'exit_deferred', 'exited_unsigned')",
                [],
                |row| row.get(0),
            )
            .map_err(|error| ServerError::Database(format!("settlement count failed: {error}")))?;
        Ok(crate::dashboard::SettlementCounts {
            pending,
            exit_deferred,
            exited_unsigned,
            retrying,
            provisioning,
            cancelled,
            unknown_status,
            open_reviews,
            pending_key_cleanups,
            next_deadline_in_seconds: next_deadline
                .map(|deadline| (deadline.max(0) as u64).saturating_sub(now)),
        })
    }
}

/// Statuses of a lease still to be settled.
const PENDING_LEASE_STATUSES: &[&str] =
    &["provisioning", "active", "retiring", "disabled", "revoking"];

/// What `zkapi settlement reopen` does beyond returning the lease to
/// settlement.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReopenOptions<'a> {
    /// Finalize at zero instead (`operator_conceded`): the operator concedes
    /// the request's charge. Also concedes a lease reopened earlier and not
    /// yet signed.
    pub zero_charge: bool,
    /// Once the saved request verifies, repair the other side from it: the
    /// lease row's client_request_id and request_nullifier (its reviews move
    /// with a changed id), and the nullifier reservation (a Reserved row's
    /// authenticators are rewritten, a missing row is re-created). Also
    /// before a concession of a lease reopened earlier.
    pub rebind: bool,
    /// The authentic request, restoring a saved request that does not verify
    /// or cannot be read. Accepted only if it verifies, its binding is the
    /// one its reservation recorded at admission, and it shares the lease
    /// row's client_request_id or request_nullifier. Also restores the
    /// unreadable saved request of a pending lease, keeping its status.
    pub saved_request: Option<&'a ApiRequestV2>,
}

/// Why `reopen_cancelled_lease` refused; nothing was changed.
#[derive(Debug, thiserror::Error)]
pub enum ReopenRefusal {
    #[error("no lease has client_request_id {0}")]
    UnknownLease(String),
    #[error(
        "the lease is {0}, not cancelled; only a cancelled lease can be reopened (with \
         --zero-charge, also a lease reopened earlier that is not settled yet), and a pending \
         lease's saved request is restored (--saved-request) only when it cannot be read"
    )]
    NotCancelled(String),
    /// A pending lease whose saved request can be read, but whose row
    /// another column keeps undecodable.
    #[error(
        "the lease is {status} and its saved request can be read, but another column of its \
         row cannot be decoded ({detail}): every settlement tick skips the lease, its settlement \
         deadline included, and lease routes answer lease_record_unreadable, until that column \
         is repaired by hand from a backup (see \"Reopening a cancelled lease\" in \
         docs/native-eth-billing.md); --saved-request cannot repair it"
    )]
    RowUndecodable { status: String, detail: String },
    #[error(
        "the lease is {0}, not cancelled yet: its binding_corrupt review was recorded while the \
         usage of its direct key is still being captured; start the server again, and reopen \
         the lease once it is cancelled (at its settlement deadline at the latest)"
    )]
    CapturePending(String),
    #[error("the lease was not cancelled for a corrupt binding: it has no binding_corrupt review")]
    NotBindingCorrupt,
    #[error("this server does not settle leases of key source {0}")]
    UnsupportedKeySource(String),
    #[error(
        "the request nullifier is ClearanceReserved: its owner already holds a mutual-close \
         clearance for that state and exits by mutual close; there is nothing to settle"
    )]
    ClearanceReserved,
    /// The field and its repair; see `BindingMismatch::remedy`.
    #[error("the binding is still corrupt: {0}; {remedy}", remedy = .0.remedy())]
    BindingCorrupt(BindingMismatch),
    /// A `saved_request_mismatch` detail of the supplied request.
    #[error("the request in --saved-request {0}")]
    SuppliedRequestUnverified(&'static str),
    #[error(
        "the request in --saved-request is not this lease's: neither its client_request_id nor \
         its request_nullifier is the lease row's"
    )]
    SuppliedRequestForAnotherLease,
    #[error(
        "the request in --saved-request is not the request this lease reserved: {0}; only that \
         request can be restored (if nullifiers.api_request_binding is corrupt too, restore it \
         from a backup first)"
    )]
    SuppliedRequestNotReserved(&'static str),
    #[error(
        "lease row {0} already holds the verified request's client_request_id or \
         request_nullifier, so --rebind cannot rewrite this row to them: find out which row is \
         that request's lease before reopening either"
    )]
    LeaseElsewhere(String),
    #[error(
        "the reservation is Finalized: a successor is already signed for the request it records, \
         so --rebind cannot rewrite it; restore the nullifiers row from a backup, then run this \
         command again"
    )]
    RebindSigned,
    #[error(
        "the request's reservation row is kept under nullifier {nullifier} ({status}): its \
         nullifiers.nullifier is corrupt, not missing, and the row may hold a signed transcript; \
         set it to the lease's request_nullifier instead of re-creating the row, then run this \
         command again"
    )]
    ReservationElsewhere { nullifier: String, status: String },
    #[error(
        "a successor for this request is already signed: the lease settles from that transcript \
         and its charge cannot be conceded"
    )]
    AlreadySigned,
    #[error(
        "the request's charge is already settled (nullifiers.settled_charge): its successor is \
         signed at that charge once its nullifier is unspent on chain, and the charge cannot be \
         conceded or its reservation rewritten"
    )]
    AlreadySettled,
    #[error(
        "the reservation's charge is already settled (nullifiers.settled_charge), so --rebind \
         cannot rewrite it; restore the nullifiers row from a backup, then run this command again"
    )]
    RebindSettled,
    #[error(transparent)]
    Store(#[from] ServerError),
}

/// A lease returned to settlement by `reopen_cancelled_lease`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReopenedLease {
    pub client_request_id: String,
    pub key_source: String,
    /// The settlement status the lease resumes from.
    pub status: String,
    pub delivered: Option<bool>,
    /// Unchanged by the reopening.
    pub settlement_deadline_at: Option<u64>,
    /// How the restarted server settles it: `zero_never_delivered`,
    /// `captured_usage` (the usage captured when its direct key was
    /// disabled), `measured_until_deadline`, `deadline_fallback` (no usage
    /// can be measured: the solvency bound, at its deadline),
    /// `operator_conceded`, `settled_charge` (its charge was settled before:
    /// it is kept, and its successor is signed once its nullifier is unspent)
    /// or `signed_transcript`.
    pub settles: &'static str,
    /// A key deletion queued by the cancellation was withdrawn, so the key
    /// can still be measured. Otherwise a direct key was deleted.
    pub key_cleanup_withdrawn: bool,
    /// The nullifier reservation: `unchanged`, or, with `--rebind`,
    /// `rewritten` or `recreated` from the verified request.
    pub reservation: &'static str,
    /// The lease row's client_request_id and request_nullifier: `unchanged`,
    /// or, with `--rebind`, `rewritten` from the verified request.
    pub lease_row: &'static str,
    /// The saved request: `unchanged`, or `restored` from `--saved-request`.
    pub saved_request: &'static str,
    /// Set when the lease is charged its full solvency bound.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<&'static str>,
    /// The lease was pending, not cancelled: its unreadable saved request
    /// was restored from `--saved-request` and its status kept.
    #[serde(skip)]
    pub restored_pending: bool,
}

/// `ReopenedLease::warning` for a lease charged its full solvency bound.
const DEADLINE_FALLBACK_WARNING: &str =
    "no usage of this lease can be measured: it is charged its full solvency bound at its \
     settlement deadline (at once when that has passed); to concede its charge instead, run \
     this command again with --zero-charge before restarting the server";

/// Whether the lease row's saved request (`api_request_json`) can be decoded,
/// as `row_to_openrouter_lease` decodes it: text holding an `ApiRequestV2`.
/// The settlement scan skips a pending row whose request cannot be.
fn saved_request_readable(conn: &Connection, client_request_id: &str) -> Result<bool, ServerError> {
    conn.query_row(
        "SELECT api_request_json FROM openrouter_leases WHERE client_request_id = ?1",
        params![client_request_id],
        |row| {
            Ok(row
                .get_ref(0)?
                .as_str()
                .is_ok_and(|saved| serde_json::from_str::<ApiRequestV2>(saved).is_ok()))
        },
    )
    .map_err(|error| ServerError::Database(format!("saved request read failed: {error}")))
}

/// Why the lease row cannot be decoded as `row_to_openrouter_lease` decodes
/// it (and as the settlement scan reads it), if it cannot.
fn lease_row_undecodable(
    conn: &Connection,
    client_request_id: &str,
) -> Result<Option<String>, ServerError> {
    match conn.query_row(
        "SELECT * FROM openrouter_leases WHERE client_request_id = ?1",
        params![client_request_id],
        row_to_openrouter_lease,
    ) {
        Ok(_) | Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(error @ rusqlite::Error::SqliteFailure(..)) => Err(ServerError::Database(format!(
            "lease row read failed: {error}"
        ))),
        Err(error) => Ok(Some(error.to_string())),
    }
}

/// The lease-row columns that `lease_binding_mismatch` compares with the
/// saved request.
const LEASE_ROW_FIELDS: &[&str] = &[
    "openrouter_leases.client_request_id",
    "openrouter_leases.request_nullifier",
];

/// Whether the lease has a `binding_corrupt` review since its last
/// reopening: its corrupt binding was found, and reviewed, already.
fn binding_corrupt_reviewed(
    conn: &Connection,
    client_request_id: &str,
) -> Result<bool, ServerError> {
    conn.query_row(
        "SELECT EXISTS (
            SELECT 1 FROM settlement_reviews
            WHERE client_request_id = ?1 AND reason = 'binding_corrupt'
              AND review_id > COALESCE((SELECT MAX(review_id) FROM settlement_reviews
                                        WHERE client_request_id = ?1
                                          AND reason = 'binding_reopened'), 0))",
        params![client_request_id],
        |row| row.get(0),
    )
    .map_err(|error| ServerError::Database(format!("review lookup failed: {error}")))
}

/// Restore a lease's saved request from a supplied copy (a backup, or its
/// owner's) whose authenticity the database proves: it verifies as admission
/// verified it (`verify`), its binding is the one its reservation recorded at
/// admission, and it shares the lease row's client_request_id or
/// request_nullifier (`row_nullifier`, canonical hex). Another request its
/// owner authorized for the same note state is refused: it was never
/// admitted. Returns `restored`, or `unchanged` when it is already saved: the
/// saved request is then checked as any other.
fn restore_saved_request(
    conn: &Connection,
    client_request_id: &str,
    row_nullifier: &str,
    supplied: &ApiRequestV2,
    verify: SavedRequestCheck<'_>,
) -> Result<&'static str, ReopenRefusal> {
    let failed =
        |error: rusqlite::Error| ServerError::Database(format!("request restore failed: {error}"));
    if let Some(mismatch) = verify(supplied) {
        return Err(ReopenRefusal::SuppliedRequestUnverified(mismatch.detail));
    }
    let nullifier = supplied.public_inputs.request_nullifier.to_hex();
    if supplied.client_request_id != client_request_id && nullifier != row_nullifier {
        return Err(ReopenRefusal::SuppliedRequestForAnotherLease);
    }
    let binding = api_request_binding(supplied)?;
    // Not text (or not a request) reads as unreadable, as the row decoder
    // reads it.
    let saved: Option<String> = conn
        .query_row(
            "SELECT api_request_json FROM openrouter_leases WHERE client_request_id = ?1",
            params![client_request_id],
            |row| Ok(row.get_ref(0)?.as_str().ok().map(str::to_string)),
        )
        .map_err(failed)?;
    if saved
        .and_then(|saved| serde_json::from_str::<ApiRequestV2>(&saved).ok())
        .and_then(|saved| api_request_binding(&saved).ok())
        .is_some_and(|saved| saved == binding)
    {
        return Ok("unchanged");
    }
    let reservation = conn
        .query_row(
            "SELECT * FROM nullifiers WHERE nullifier = ?1",
            params![nullifier],
            row_to_record,
        )
        .optional()
        .map_err(failed)?
        .ok_or(ReopenRefusal::SuppliedRequestNotReserved(
            "no nullifiers row has its request_nullifier",
        ))?;
    if reservation.status == NullifierStatus::ClearanceReserved {
        return Err(ReopenRefusal::ClearanceReserved);
    }
    if reservation.api_request_binding.as_deref() != Some(binding.as_str()) {
        return Err(ReopenRefusal::SuppliedRequestNotReserved(
            "its binding is not nullifiers.api_request_binding",
        ));
    }
    let request_json = serde_json::to_string(supplied)
        .map_err(|error| ServerError::Internal(format!("request serialization failed: {error}")))?;
    let restored = conn
        .execute(
            "UPDATE openrouter_leases SET api_request_json = ?1 WHERE client_request_id = ?2",
            params![request_json, client_request_id],
        )
        .map_err(failed)?;
    if restored != 1 {
        return Err(ServerError::Internal("lease row changed while restoring".into()).into());
    }
    Ok("restored")
}

/// Repair the lease row of a lease whose saved request verified: set its
/// client_request_id and request_nullifier from that request, moving the
/// reviews recorded under its former id with it. Refuses when another lease
/// row holds either value: that row, not this one, may be the request's
/// lease.
fn rebind_lease_row(conn: &Connection, lease: &OpenRouterLeaseRecord) -> Result<(), ReopenRefusal> {
    let failed =
        |error: rusqlite::Error| ServerError::Database(format!("lease row rebind failed: {error}"));
    let request = &lease.api_request;
    let nullifier = request.public_inputs.request_nullifier.to_hex();
    let elsewhere: Option<String> = conn
        .query_row(
            "SELECT client_request_id FROM openrouter_leases
             WHERE (client_request_id = ?1 OR request_nullifier = ?2) AND client_request_id != ?3
             LIMIT 1",
            params![
                request.client_request_id,
                nullifier,
                lease.client_request_id
            ],
            |row| row.get(0),
        )
        .optional()
        .map_err(failed)?;
    if let Some(other) = elsewhere {
        return Err(ReopenRefusal::LeaseElsewhere(other));
    }
    let rows = conn
        .execute(
            "UPDATE openrouter_leases SET client_request_id = ?1, request_nullifier = ?2
             WHERE client_request_id = ?3",
            params![
                request.client_request_id,
                nullifier,
                lease.client_request_id
            ],
        )
        .map_err(failed)?;
    if rows != 1 {
        return Err(ServerError::Internal("lease row changed while rebinding".into()).into());
    }
    conn.execute(
        "UPDATE settlement_reviews SET client_request_id = ?1 WHERE client_request_id = ?2",
        params![request.client_request_id, lease.client_request_id],
    )
    .map_err(failed)?;
    Ok(())
}

/// The repairs of a reopening, for its review's detail.
fn repair_note(
    saved_request: &str,
    lease_row: &str,
    former_id: &str,
    id: &str,
    reservation: &str,
) -> String {
    let mut note = String::new();
    if saved_request == "restored" {
        note.push_str("; its saved request was restored from the supplied request");
    }
    if lease_row == "rewritten" {
        note.push_str("; its lease row was rewritten from the verified request");
        if former_id != id {
            note.push_str(&format!(" (its client_request_id was {former_id})"));
        }
    }
    match reservation {
        "rewritten" => note.push_str("; its reservation was rewritten from the verified request"),
        "recreated" => {
            note.push_str("; its missing reservation was recreated from the verified request")
        }
        _ => {}
    }
    note
}

/// Repair the reservation of a lease whose saved request verified: rewrite a
/// Reserved row's authenticators from that request, or re-create a missing
/// row. Refuses a signed (Finalized) row, and a row of this request kept
/// under another nullifier: that row is mis-keyed, not missing, and may hold
/// a signed transcript.
fn rebind_reservation(
    conn: &Connection,
    lease: &OpenRouterLeaseRecord,
    record: Option<&TranscriptRecord>,
    now: u64,
) -> Result<&'static str, ReopenRefusal> {
    let failed = |error: rusqlite::Error| {
        ServerError::Database(format!("reservation rebind failed: {error}"))
    };
    let request = &lease.api_request;
    let binding = api_request_binding(request)?;
    let nullifier = lease.request_nullifier.to_hex();
    let reserved = status_to_str(NullifierStatus::Reserved);
    match record {
        // A settled reservation's charge is final: its request is the one
        // that settled, and nothing is rewritten.
        Some(record) if record.settled_charge.is_some() => Err(ReopenRefusal::RebindSettled),
        Some(record) if record.status == NullifierStatus::Reserved => {
            let rows = conn
                .execute(
                    "UPDATE nullifiers SET reservation_kind = 'openrouter_lease',
                        client_request_id = ?1, payload_hash = ?2, api_request_binding = ?3
                     WHERE nullifier = ?4 AND status = ?5",
                    params![
                        request.client_request_id,
                        request.payload_hash.to_hex(),
                        binding,
                        nullifier,
                        reserved
                    ],
                )
                .map_err(failed)?;
            if rows != 1 {
                return Err(
                    ServerError::Internal("reservation changed while rebinding".into()).into(),
                );
            }
            // The verified request becomes evidence too (append-only).
            insert_evidence(conn, request, "rebind", now)?;
            Ok("rewritten")
        }
        Some(_) => Err(ReopenRefusal::RebindSigned),
        None => {
            let elsewhere: Option<(String, String)> = conn
                .query_row(
                    "SELECT nullifier, status FROM nullifiers WHERE client_request_id = ?1 LIMIT 1",
                    params![request.client_request_id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(failed)?;
            if let Some((nullifier, status)) = elsewhere {
                return Err(ReopenRefusal::ReservationElsewhere { nullifier, status });
            }
            conn.execute(
                "INSERT INTO nullifiers (
                    nullifier, status, reservation_kind, client_request_id, payload_hash,
                    api_request_binding, created_at
                 ) VALUES (?1, ?2, 'openrouter_lease', ?3, ?4, ?5, ?6)",
                params![
                    nullifier,
                    reserved,
                    request.client_request_id,
                    request.payload_hash.to_hex(),
                    binding,
                    sql_time(now)
                ],
            )
            .map_err(failed)?;
            insert_evidence(conn, request, "rebind", now)?;
            Ok("recreated")
        }
    }
}

/// A stopped server's database, opened by an offline operator command. The
/// server writer lock is held for the whole session: opening refuses while a
/// server runs, and no server starts until this is dropped.
pub struct OfflineStore {
    store: NullifierStore,
    _writer_lock: crate::writer_lock::ServerWriterLock,
}

impl OfflineStore {
    /// Open an existing server database; never creates one.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, ServerError> {
        let path = path.as_ref();
        if !path.is_file() {
            return Err(ServerError::Database(format!(
                "no server database at {}",
                path.display()
            )));
        }
        let writer_lock = crate::writer_lock::ServerWriterLock::acquire(path)?;
        let store = NullifierStore::new(path)?;
        Ok(Self {
            store,
            _writer_lock: writer_lock,
        })
    }

    /// See `NullifierStore::reopen_cancelled_lease`. The saved request, and a
    /// request supplied to restore it, are verified with `verifier`, the
    /// request verifier of the server's proof setup, as admission verified it.
    pub fn reopen_cancelled_lease(
        &self,
        client_request_id: &str,
        options: ReopenOptions<'_>,
        verifier: &RequestVerifier,
    ) -> Result<ReopenedLease, ReopenRefusal> {
        self.store.reopen_cancelled_lease(
            client_request_id,
            options,
            &|request| saved_request_mismatch(verifier, request),
            current_timestamp(),
        )
    }
}

fn insert_review(
    conn: &Connection,
    review: &SettlementReview,
    now: i64,
) -> Result<(), ServerError> {
    debug_assert!(SETTLEMENT_REVIEW_REASONS.contains(&review.reason.as_str()));
    // A log: one row per event. Each event is recorded once, by the
    // transition that caused it; a reopened lease can be reviewed again.
    conn.execute(
        "INSERT INTO settlement_reviews (
            client_request_id, request_nullifier, key_source, reason, charge_basis, detail,
            reported_usage_micro_usd, charge_applied, solvency_bound, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            review.client_request_id,
            review.request_nullifier.to_hex(),
            review.key_source,
            review.reason,
            review.charge_basis,
            truncate_detail(&review.detail),
            review
                .reported_usage_micro_usd
                .map(|value| value.to_string()),
            review
                .charge_applied
                .map(|value| value.min(i64::MAX as u128) as i64),
            review.solvency_bound.to_string(),
            now,
        ],
    )
    .map_err(|error| ServerError::Database(format!("review insert failed: {error}")))?;
    Ok(())
}

fn insert_key_cleanup(
    conn: &Connection,
    client_request_id: &str,
    cleanup: &KeyCleanup<'_>,
    now: i64,
) -> Result<(), ServerError> {
    conn.execute(
        "INSERT OR IGNORE INTO provider_key_cleanup (
            client_request_id, key_source, key_hash, key_name, next_attempt_at, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        params![
            client_request_id,
            cleanup.key_source,
            cleanup.key_hash,
            cleanup.key_name,
            now
        ],
    )
    .map_err(|error| ServerError::Database(format!("key cleanup insert failed: {error}")))?;
    Ok(())
}

fn truncate_detail(detail: &str) -> String {
    detail.chars().take(500).collect()
}

/// UNIX seconds as a SQLite integer; far-future values saturate.
fn sql_time(value: u64) -> i64 {
    value.min(i64::MAX as u64) as i64
}

/// A charge in gwei as a SQLite integer. Charges never exceed a request's
/// solvency bound, which admission keeps below 2^53.
fn sql_charge(value: u128) -> Result<i64, ServerError> {
    i64::try_from(value).map_err(|_| ServerError::Internal("charge exceeds i64".into()))
}

/// Insert a new lease row (`NullifierStore::create_openrouter_lease_bound`).
fn insert_lease_row(conn: &Connection, lease: &NewOpenRouterLease<'_>) -> Result<(), ServerError> {
    let request = lease.request;
    let request_json = serde_json::to_string(request)
        .map_err(|error| ServerError::Database(format!("lease serialization failed: {error}")))?;
    conn.execute(
            "INSERT INTO openrouter_leases (
                client_request_id, request_nullifier, api_request_json, key_source, status,
                issued_at, expires_at, settle_after, spending_limit_usd, updated_at, oa_client_request_id,
                oa_provisioning_outcome, ttl_seconds, settlement_deadline_at, delivered
             ) VALUES (?1, ?2, ?3, ?4, 'provisioning', ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14)",
            params![
                request.client_request_id,
                request.public_inputs.request_nullifier.to_hex(),
                request_json,
                lease.key_source,
                lease.issued_at as i64,
                lease.expires_at as i64,
                lease.settle_after as i64,
                lease.spending_limit_usd,
                current_timestamp() as i64,
                lease.oa_client_request_id,
                if lease.key_source == "oa_org" { "not_started" } else { "may_have_issued" },
                lease.ttl_seconds.map(sql_time),
                lease.settlement_deadline_at.map(sql_time),
                lease.delivered,
            ],
        )
        .map_err(|error| ServerError::Database(format!("lease insert failed: {error}")))?;
    Ok(())
}

fn insert_reservation(
    conn: &Connection,
    nullifier: &Felt252,
    client_request_id: &str,
    payload_hash: &Felt252,
    reservation_kind: &str,
    api_request_binding: Option<&str>,
    now: u64,
) -> Result<(), ServerError> {
    conn.execute(
        "INSERT INTO nullifiers (
            nullifier, status, reservation_kind, client_request_id, payload_hash,
            api_request_binding, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            nullifier.to_hex(),
            status_to_str(NullifierStatus::Reserved),
            reservation_kind,
            client_request_id,
            payload_hash.to_hex(),
            api_request_binding,
            sql_time(now),
        ],
    )
    .map_err(|e| {
        if let rusqlite::Error::SqliteFailure(ref err, _) = e {
            if err.code == rusqlite::ErrorCode::ConstraintViolation {
                return ServerError::Replay;
            }
        }
        ServerError::Database(format!("insert failed: {}", e))
    })?;
    Ok(())
}

/// Add a column a decoder reads by name unless it already exists. Failure is
/// an error, unless a concurrent opener added the column first.
fn ensure_column(
    conn: &Connection,
    table: &str,
    column: &str,
    definition: &str,
) -> Result<(), ServerError> {
    let present = |conn: &Connection| -> Result<bool, ServerError> {
        conn.prepare(&format!("PRAGMA table_info({table})"))
            .and_then(|mut statement| {
                statement
                    .query_map([], |row| row.get::<_, String>(1))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map(|columns| columns.iter().any(|name| name == column))
            .map_err(|error| {
                ServerError::Database(format!("{table}.{column} migration read failed: {error}"))
            })
    };
    if present(conn)? {
        return Ok(());
    }
    if let Err(error) = conn.execute(
        &format!("ALTER TABLE {table} ADD COLUMN {column} {definition}"),
        [],
    ) {
        if !present(conn)? {
            return Err(ServerError::Database(format!(
                "{table}.{column} migration failed: {error}"
            )));
        }
    }
    Ok(())
}

fn migrate_oa_provisioning_outcome(conn: &Connection) -> Result<(), ServerError> {
    let columns = conn
        .prepare("PRAGMA table_info(openrouter_leases)")
        .and_then(|mut statement| {
            statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<Result<Vec<_>, _>>()
        })
        .map_err(|error| {
            ServerError::Database(format!("OA outcome migration read failed: {error}"))
        })?;
    if !columns.iter().any(|name| name == "oa_provisioning_outcome") {
        conn.execute(
            "ALTER TABLE openrouter_leases ADD COLUMN oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued'",
            [],
        )
        .map_err(|error| ServerError::Database(format!("OA outcome migration failed: {error}")))?;
    }
    Ok(())
}

/// Settlement reviews were keyed by lease, one per lease. A reopened lease is
/// reviewed again, so they are kept as a log: rebuild such a table once,
/// keeping every row. Earlier writers keep working against the log.
fn migrate_settlement_review_log(conn: &Connection) -> Result<(), ServerError> {
    let failed = |error: rusqlite::Error| {
        ServerError::Database(format!("settlement review migration failed: {error}"))
    };
    let migrated = |conn: &Connection| -> Result<bool, ServerError> {
        conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM pragma_table_info('settlement_reviews')
                            WHERE name = 'review_id')",
            [],
            |row| row.get(0),
        )
        .map_err(failed)
    };
    if migrated(conn)? {
        return Ok(());
    }
    let transaction = rusqlite::Transaction::new_unchecked(conn, TransactionBehavior::Immediate)
        .map_err(failed)?;
    // Checked again inside the write transaction: a concurrent opener may
    // have migrated first.
    if migrated(&transaction)? {
        return Ok(());
    }
    transaction
        .execute_batch(
            "ALTER TABLE settlement_reviews RENAME TO settlement_reviews_by_lease;
             CREATE TABLE settlement_reviews (
                review_id INTEGER PRIMARY KEY,
                client_request_id TEXT NOT NULL,
                request_nullifier TEXT NOT NULL,
                key_source TEXT NOT NULL,
                reason TEXT NOT NULL,
                charge_basis TEXT,
                detail TEXT NOT NULL,
                reported_usage_micro_usd TEXT,
                charge_applied INTEGER,
                solvency_bound TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                acknowledged_at INTEGER
             );
             INSERT INTO settlement_reviews (
                client_request_id, request_nullifier, key_source, reason, charge_basis, detail,
                reported_usage_micro_usd, charge_applied, solvency_bound, created_at,
                acknowledged_at
             )
             SELECT client_request_id, request_nullifier, key_source, reason, charge_basis, detail,
                reported_usage_micro_usd, charge_applied, solvency_bound, created_at,
                acknowledged_at
             FROM settlement_reviews_by_lease ORDER BY created_at, client_request_id;
             DROP TABLE settlement_reviews_by_lease;",
        )
        .map_err(failed)?;
    transaction.commit().map_err(failed)
}

/// Older lease rows already contain the complete original request. Use that
/// durable copy to migrate their nullifier reservation safely; proxy
/// reservations have no equivalent source and intentionally remain unbound so
/// retries fail closed.
fn backfill_openrouter_request_bindings(conn: &Connection) -> Result<(), ServerError> {
    let rows = {
        let mut statement = conn
            .prepare(
                "SELECT client_request_id, request_nullifier, api_request_json
                 FROM openrouter_leases",
            )
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration query failed: {error}"))
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|error| {
                ServerError::Database(format!("lease binding migration read failed: {error}"))
            })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|error| {
            ServerError::Database(format!("lease binding migration row failed: {error}"))
        })?
    };

    for (client_request_id, request_nullifier, request_json) in rows {
        let Ok(request) = serde_json::from_str::<ApiRequestV2>(&request_json) else {
            // A malformed durable lease cannot be resumed safely. Leave the
            // reservation unbound so validate_and_reserve rejects it.
            continue;
        };
        if request.client_request_id != client_request_id
            || request.public_inputs.request_nullifier.to_hex() != request_nullifier
        {
            continue;
        }
        let binding = api_request_binding(&request)?;
        conn.execute(
            "UPDATE nullifiers SET api_request_binding = ?1
             WHERE nullifier = ?2
               AND client_request_id = ?3
               AND payload_hash = ?4
               AND reservation_kind = 'openrouter_lease'
               AND api_request_binding IS NULL",
            params![
                binding,
                request_nullifier,
                client_request_id,
                request.payload_hash.to_hex(),
            ],
        )
        .map_err(|error| {
            ServerError::Database(format!("lease binding migration update failed: {error}"))
        })?;
    }
    Ok(())
}

/// Convert a NullifierStatus to its string representation for storage.
fn status_to_str(status: NullifierStatus) -> &'static str {
    match status {
        NullifierStatus::Reserved => "Reserved",
        NullifierStatus::Finalized => "Finalized",
        NullifierStatus::ClearanceReserved => "ClearanceReserved",
        NullifierStatus::ExitedUnsigned => "ExitedUnsigned",
    }
}

/// Parse a status string from the database.
fn str_to_status(s: &str) -> NullifierStatus {
    match s {
        "Reserved" => NullifierStatus::Reserved,
        "Finalized" => NullifierStatus::Finalized,
        "ClearanceReserved" => NullifierStatus::ClearanceReserved,
        "ExitedUnsigned" => NullifierStatus::ExitedUnsigned,
        _ => NullifierStatus::Reserved, // fallback
    }
}

/// Parse an optional hex string into a Felt252.
fn parse_opt_felt(s: Option<String>) -> Option<Felt252> {
    s.and_then(|h| Felt252::from_hex(&h).ok())
}

/// The append-only evidence table: every request proof the server accepted,
/// written in the transaction that reserves its nullifier (`source`
/// "reserve"), or appended when `zkapi settlement reopen --rebind` re-creates a
/// reservation from a verified request ("rebind"). Kept until the deployment
/// is retired; the triggers refuse every update and delete.
pub(crate) const REQUEST_EVIDENCE_SCHEMA: &str = "
    CREATE TABLE IF NOT EXISTS request_evidence (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nullifier TEXT NOT NULL, client_request_id TEXT NOT NULL,
        solvency_bound TEXT NOT NULL,
        request_inputs_json TEXT NOT NULL,
        proof_blob BLOB NOT NULL CHECK (length(proof_blob) = 256),
        source TEXT NOT NULL CHECK (source IN ('reserve','rebind')),
        created_at INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS request_evidence_nullifier ON request_evidence(nullifier);
    CREATE TRIGGER IF NOT EXISTS request_evidence_no_update BEFORE UPDATE ON request_evidence
        BEGIN SELECT RAISE(ABORT,'append-only'); END;
    CREATE TRIGGER IF NOT EXISTS request_evidence_no_delete BEFORE DELETE ON request_evidence
        BEGIN SELECT RAISE(ABORT,'append-only'); END;";

/// Every `request_evidence` column `row_to_evidence` reads.
pub(crate) const REQUEST_EVIDENCE_COLUMNS: &[&str] = &[
    "id",
    "nullifier",
    "client_request_id",
    "solvency_bound",
    "request_inputs_json",
    "proof_blob",
    "source",
    "created_at",
];

/// The triggers that keep `request_evidence` append-only.
pub(crate) const REQUEST_EVIDENCE_TRIGGERS: &[&str] =
    &["request_evidence_no_update", "request_evidence_no_delete"];

/// Every `deployment_binding` column `read_deployment_binding` reads.
pub(crate) const DEPLOYMENT_BINDING_COLUMNS: &[&str] = &[
    "id",
    "chain_id",
    "contract_address",
    "state_key_x",
    "state_key_y",
    "clearance_key_x",
    "clearance_key_y",
    "challenge_period_seconds",
    "verified_at",
    "verified_block",
    "circuit_id",
    "setup_id",
    "request_vk_keccak256",
    "withdrawal_vk_keccak256",
    "source",
];

/// The refusal of a reader (zkapi-challenged) opening a database without the
/// schema it reads.
pub const READER_SCHEMA_REFUSAL: &str =
    "server database schema is older than this reader: run `zkapi db init` first \
     (or start the upgraded API server once)";

/// A reader requires every table and column its decoders read, and the
/// triggers that keep the evidence it relies on append-only.
fn check_reader_schema(conn: &Connection) -> Result<(), ServerError> {
    for (table, required) in [
        ("nullifiers", TRANSCRIPT_RECORD_COLUMNS),
        ("openrouter_leases", OPENROUTER_LEASE_RECORD_COLUMNS),
        ("request_evidence", REQUEST_EVIDENCE_COLUMNS),
        ("deployment_binding", DEPLOYMENT_BINDING_COLUMNS),
    ] {
        let present = conn
            .prepare("SELECT name FROM pragma_table_info(?1)")
            .and_then(|mut statement| {
                statement
                    .query_map([table], |row| row.get::<_, String>(0))?
                    .collect::<Result<Vec<_>, _>>()
            })
            .map_err(|e| ServerError::Database(format!("schema check failed: {e}")))?;
        if required
            .iter()
            .any(|column| !present.iter().any(|name| name == column))
        {
            return Err(ServerError::Database(READER_SCHEMA_REFUSAL.to_string()));
        }
    }
    for trigger in REQUEST_EVIDENCE_TRIGGERS {
        let present: bool = conn
            .query_row(
                "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?1)",
                [trigger],
                |row| row.get(0),
            )
            .map_err(|e| ServerError::Database(format!("schema check failed: {e}")))?;
        if !present {
            return Err(ServerError::Database(READER_SCHEMA_REFUSAL.to_string()));
        }
    }
    Ok(())
}

/// Every `nullifiers` column `row_to_record` reads; `open_read_only` refuses a
/// schema without them. Whoever makes `row_to_record` read a column MUST add it.
pub(crate) const TRANSCRIPT_RECORD_COLUMNS: &[&str] = &[
    "nullifier",
    "status",
    "reservation_kind",
    "client_request_id",
    "payload_hash",
    "charge_applied",
    "response_code",
    "response_payload",
    "response_hash",
    "next_commitment_x",
    "next_commitment_y",
    "next_anchor",
    "blind_delta_srv",
    "next_state_sig_json",
    "policy_reason_code",
    "policy_evidence_hash",
    "proof_blob",
    "request_inputs_json",
    "api_request_binding",
    "created_at",
    "finalized_at",
    "settled_charge",
    "settled_basis",
    "settled_at",
    "exit_deferred_since",
];

/// Convert a database row into a TranscriptRecord.
fn row_to_record(row: &rusqlite::Row<'_>) -> rusqlite::Result<TranscriptRecord> {
    let nullifier_hex: String = row.get("nullifier")?;
    let status_str: String = row.get("status")?;
    let reservation_kind: String = row.get("reservation_kind")?;
    let client_request_id: Option<String> = row.get("client_request_id")?;
    let payload_hash: Option<String> = row.get("payload_hash")?;
    let charge_applied: Option<i64> = row.get("charge_applied")?;
    let response_code: Option<i32> = row.get("response_code")?;
    let response_payload: Option<String> = row.get("response_payload")?;
    let response_hash: Option<String> = row.get("response_hash")?;
    let next_commitment_x: Option<String> = row.get("next_commitment_x")?;
    let next_commitment_y: Option<String> = row.get("next_commitment_y")?;
    let next_anchor: Option<String> = row.get("next_anchor")?;
    let blind_delta_srv: Option<String> = row.get("blind_delta_srv")?;
    let next_state_sig_json: Option<String> = row.get("next_state_sig_json")?;
    let policy_reason_code: Option<i32> = row.get("policy_reason_code")?;
    let policy_evidence_hash: Option<String> = row.get("policy_evidence_hash")?;
    let proof_blob: Option<Vec<u8>> = row.get("proof_blob")?;
    let request_inputs_json: Option<String> = row.get("request_inputs_json")?;
    let api_request_binding: Option<String> = row.get("api_request_binding")?;
    let created_at: i64 = row.get("created_at")?;
    let finalized_at: Option<i64> = row.get("finalized_at")?;
    let settled_charge: Option<i64> = row.get("settled_charge")?;
    let settled_basis: Option<String> = row.get("settled_basis")?;
    let settled_at: Option<i64> = row.get("settled_at")?;
    let exit_deferred_since: Option<i64> = row.get("exit_deferred_since")?;

    let next_state_sig =
        next_state_sig_json.and_then(|json| serde_json::from_str::<SchnorrSignature>(&json).ok());

    Ok(TranscriptRecord {
        nullifier: Felt252::from_hex(&nullifier_hex).unwrap_or(Felt252::ZERO),
        status: str_to_status(&status_str),
        reservation_kind,
        client_request_id,
        payload_hash: parse_opt_felt(payload_hash),
        charge_applied: charge_applied.map(|c| c as u128),
        response_code: response_code.map(|c| c as u16),
        response_payload,
        response_hash: parse_opt_felt(response_hash),
        next_commitment_x: parse_opt_felt(next_commitment_x),
        next_commitment_y: parse_opt_felt(next_commitment_y),
        next_anchor: parse_opt_felt(next_anchor),
        blind_delta_srv: parse_opt_felt(blind_delta_srv),
        next_state_sig,
        policy_reason_code: policy_reason_code.map(|c| c as u32),
        policy_evidence_hash: parse_opt_felt(policy_evidence_hash),
        proof_blob,
        request_inputs_json,
        api_request_binding,
        created_at: created_at as u64,
        finalized_at: finalized_at.map(|t| t as u64),
        settled_charge: settled_charge.map(|c| c.max(0) as u128),
        settled_basis,
        settled_at: settled_at.map(|t| t.max(0) as u64),
        exit_deferred_since: exit_deferred_since.map(|t| t.max(0) as u64),
    })
}

fn row_to_evidence(row: &rusqlite::Row<'_>) -> rusqlite::Result<RequestEvidence> {
    let undecodable = |index: usize, error: String| {
        rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, error.into())
    };
    let nullifier: String = row.get("nullifier")?;
    let bound: String = row.get("solvency_bound")?;
    let inputs: String = row.get("request_inputs_json")?;
    Ok(RequestEvidence {
        id: row.get("id")?,
        nullifier: Felt252::from_hex(&nullifier).map_err(|e| undecodable(1, e.to_string()))?,
        client_request_id: row.get("client_request_id")?,
        solvency_bound: bound
            .parse()
            .map_err(|e: std::num::ParseIntError| undecodable(3, e.to_string()))?,
        public_inputs: serde_json::from_str(&inputs).map_err(|e| undecodable(4, e.to_string()))?,
        proof: row.get("proof_blob")?,
        source: row.get("source")?,
        created_at: row.get::<_, i64>("created_at")?.max(0) as u64,
    })
}

/// Append one evidence row inside the caller's transaction. The proof must
/// be the 256-byte Groth16 proof the server verified.
fn insert_evidence(
    conn: &Connection,
    request: &ApiRequestV2,
    source: &str,
    now: u64,
) -> Result<(), ServerError> {
    let proof = request_proof_bytes(request)?;
    let inputs = serde_json::to_string(&request.public_inputs).map_err(|error| {
        ServerError::Internal(format!("failed to encode request evidence: {error}"))
    })?;
    conn.execute(
        "INSERT INTO request_evidence (
            nullifier, client_request_id, solvency_bound, request_inputs_json, proof_blob,
            source, created_at
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            request.public_inputs.request_nullifier.to_hex(),
            request.client_request_id,
            request.public_inputs.solvency_bound.to_string(),
            inputs,
            proof,
            source,
            sql_time(now),
        ],
    )
    .map_err(|error| ServerError::Database(format!("request evidence insert failed: {error}")))?;
    Ok(())
}

/// The 256-byte Groth16 proof of a request (eight 32-byte coordinates).
pub(crate) fn request_proof_bytes(request: &ApiRequestV2) -> Result<Vec<u8>, ServerError> {
    let proof = base64::engine::general_purpose::STANDARD
        .decode(&request.proof.proof)
        .map_err(|error| ServerError::InvalidProof(format!("proof is not base64: {error}")))?;
    if proof.len() != 256 {
        return Err(ServerError::InvalidProof(
            "a Groth16 proof has exactly 256 bytes".into(),
        ));
    }
    Ok(proof)
}

/// Every `openrouter_leases` column `row_to_openrouter_lease` reads; keep in
/// sync exactly like `TRANSCRIPT_RECORD_COLUMNS`.
pub(crate) const OPENROUTER_LEASE_RECORD_COLUMNS: &[&str] = &[
    "client_request_id",
    "request_nullifier",
    "api_request_json",
    "oa_client_request_id",
    "key_hash",
    "key_source",
    "oa_provisioning_outcome",
    "status",
    "issued_at",
    "expires_at",
    "settle_after",
    "spending_limit_usd",
    "usage_usd",
    "charge_applied",
    "last_error",
    "ttl_seconds",
    "settlement_deadline_at",
    "settlement_attempts",
    "first_error_at",
    "charge_basis",
    "delivered",
    "updated_at",
];

fn row_to_openrouter_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<OpenRouterLeaseRecord> {
    let time = |column: &str| -> rusqlite::Result<Option<u64>> {
        Ok(row
            .get::<_, Option<i64>>(column)?
            .map(|value| value.max(0) as u64))
    };
    let request_json: String = row.get("api_request_json")?;
    let api_request = serde_json::from_str(&request_json).map_err(|error| {
        rusqlite::Error::FromSqlConversionFailure(
            request_json.len(),
            rusqlite::types::Type::Text,
            Box::new(error),
        )
    })?;
    let nullifier: String = row.get("request_nullifier")?;
    Ok(OpenRouterLeaseRecord {
        client_request_id: row.get("client_request_id")?,
        request_nullifier: Felt252::from_hex(&nullifier).unwrap_or(Felt252::ZERO),
        api_request,
        oa_client_request_id: row.get("oa_client_request_id")?,
        key_hash: row.get("key_hash")?,
        key_source: row.get("key_source")?,
        oa_provisioning_outcome: OaProvisioningOutcome::from_db(
            &row.get::<_, String>("oa_provisioning_outcome")?,
        ),
        status: row.get("status")?,
        issued_at: row.get::<_, i64>("issued_at")? as u64,
        expires_at: row.get::<_, i64>("expires_at")? as u64,
        settle_after: row.get::<_, i64>("settle_after")? as u64,
        spending_limit_usd: row.get("spending_limit_usd")?,
        usage_usd: row.get("usage_usd")?,
        charge_applied: row
            .get::<_, Option<i64>>("charge_applied")?
            .map(|value| value as u128),
        last_error: row.get("last_error")?,
        ttl_seconds: time("ttl_seconds")?,
        settlement_deadline_at: time("settlement_deadline_at")?,
        settlement_attempts: time("settlement_attempts")?.unwrap_or(0),
        first_error_at: time("first_error_at")?,
        charge_basis: row.get("charge_basis")?,
        delivered: row
            .get::<_, Option<i64>>("delivered")?
            .map(|value| value != 0),
        updated_at: time("updated_at")?.unwrap_or(0),
    })
}

fn row_to_deployment_binding(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeploymentBinding> {
    fn felt(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<Felt252> {
        let value: String = row.get(index)?;
        Felt252::from_hex(&value).map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                index,
                rusqlite::types::Type::Text,
                error.into(),
            )
        })
    }
    Ok(DeploymentBinding {
        chain_id: row.get(0)?,
        contract_address: row.get(1)?,
        state_signing_key: CurvePointWire {
            x: felt(row, 2)?,
            y: felt(row, 3)?,
        },
        clearance_signing_key: CurvePointWire {
            x: felt(row, 4)?,
            y: felt(row, 5)?,
        },
        challenge_period_seconds: row.get(6)?,
        verified_at: row.get(7)?,
        verified_block: row.get(8)?,
        circuit_id: row.get(9)?,
        setup_id: row.get(10)?,
        request_vk_keccak256: row.get(11)?,
        withdrawal_vk_keccak256: row.get(12)?,
        source: row.get(13)?,
    })
}

/// Get the current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    fn lease_request(client_request_id: &str, nullifier: u64) -> ApiRequestV2 {
        use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        ApiRequestV2 {
            client_request_id: client_request_id.to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: Felt252::from_u64(nullifier),
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: crate::test_support::fake_proof(7),
            },
        }
    }

    fn create_oa_lease(store: &NullifierStore, id: &str, nullifier: u64) {
        store
            .create_openrouter_lease_with_oa_id(
                &lease_request(id, nullifier),
                "oa_org",
                10,
                20,
                21,
                6.0,
                Some(&format!("bound-{id}")),
            )
            .unwrap();
    }

    #[test]
    fn oa_issuance_fence_preserves_ambiguity_across_retries() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "ambiguous", 1);
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(store.due_openrouter_leases(20).is_empty());
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert!(store.confirm_oa_unissued("ambiguous").is_err());
        assert!(store.begin_oa_issuance("ambiguous").unwrap());
        assert_eq!(
            store
                .lookup_openrouter_lease("ambiguous")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
        store
            .record_openrouter_lease_error("ambiguous", "response lost")
            .unwrap();
        assert!(!store.begin_oa_issuance("ambiguous").unwrap());
        let lease = store.lookup_openrouter_lease("ambiguous").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.last_error.as_deref(), Some("response lost"));
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn confirmed_unissued_oa_lease_is_due_immediately_and_cannot_resume() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "rejected", 1);
        assert!(store.begin_oa_issuance("rejected").unwrap());
        let before = current_timestamp();
        store.confirm_oa_unissued("rejected").unwrap();
        let lease = store.lookup_openrouter_lease("rejected").unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(lease.settle_after >= before);
        assert_eq!(store.due_openrouter_leases(0).len(), 1);
        assert!(store.begin_oa_issuance("rejected").is_err());
        assert!(store.confirm_oa_unissued("rejected").is_err());
        store
            .record_openrouter_lease_error("rejected", "recovery retry")
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
    }

    #[test]
    fn oa_outcome_changes_require_an_unissued_provisioning_oa_row() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("direct", 1), "openrouter", 10, 20, 21, 6.0)
            .unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("direct")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        for id in ["missing", "direct"] {
            assert!(store.begin_oa_issuance(id).is_err());
            assert!(store.confirm_oa_unissued(id).is_err());
        }
        for (index, status, key_hash) in [
            (2, "active", None),
            (3, "finalized", None),
            (4, "provisioning", Some("provider-key-hash")),
        ] {
            let id = format!("guard-{index}");
            create_oa_lease(&store, &id, index);
            assert!(store.begin_oa_issuance(&id).unwrap());
            store.conn.lock().unwrap().execute(
                "UPDATE openrouter_leases SET status = ?1, key_hash = ?2 WHERE client_request_id = ?3",
                params![status, key_hash, id],
            ).unwrap();
            assert!(store.begin_oa_issuance(&id).is_err());
            assert!(store.confirm_oa_unissued(&id).is_err());
        }
        assert!(store.due_openrouter_leases(0).is_empty());
    }

    #[test]
    fn unknown_oa_outcome_is_ambiguous_and_still_due_for_zero_settlement() {
        let store = NullifierStore::in_memory().unwrap();
        create_oa_lease(&store, "unknown", 1);
        store.conn.lock().unwrap().execute(
            "UPDATE openrouter_leases SET oa_provisioning_outcome = 'future_or_invalid' WHERE client_request_id = 'unknown'",
            [],
        ).unwrap();
        assert_eq!(
            store
                .lookup_openrouter_lease("unknown")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        // Never delivered whatever the issuer did: still settled (at zero),
        // never silently skipped.
        assert!(store.due_openrouter_leases(20).is_empty());
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
        assert!(store.confirm_oa_unissued("unknown").is_err());
        assert!(!store.begin_oa_issuance("unknown").unwrap());
        assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
    }

    #[test]
    fn legacy_oa_leases_migrate_to_ambiguous_and_outcomes_survive_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("leases.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE openrouter_leases (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
                    api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
                    key_source TEXT NOT NULL DEFAULT 'openrouter', status TEXT NOT NULL,
                    issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, settle_after INTEGER NOT NULL,
                    spending_limit_usd REAL NOT NULL, usage_usd REAL, charge_applied INTEGER,
                    last_error TEXT, updated_at INTEGER NOT NULL
                );",
            ).unwrap();
            let request = lease_request("legacy", 1);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier, api_request_json,
                    oa_client_request_id, key_source, status, issued_at, expires_at, settle_after,
                    spending_limit_usd, updated_at)
                 VALUES ('legacy', ?1, ?2, 'legacy-bound-id', 'oa_org', 'provisioning', 10, 20, 21, 6.0, 10)",
                params![request.public_inputs.request_nullifier.to_hex(), serde_json::to_string(&request).unwrap()],
            ).unwrap();
        }
        {
            let store = NullifierStore::new(&path).unwrap();
            assert_eq!(
                store
                    .lookup_openrouter_lease("legacy")
                    .unwrap()
                    .oa_provisioning_outcome,
                OaProvisioningOutcome::MayHaveIssued
            );
            assert_eq!(store.due_openrouter_leases(10_000).len(), 1);
            assert!(!store.begin_oa_issuance("legacy").unwrap());
            create_oa_lease(&store, "never-started", 2);
            create_oa_lease(&store, "attempted", 3);
            assert!(store.begin_oa_issuance("attempted").unwrap());
            create_oa_lease(&store, "rejected", 4);
            assert!(store.begin_oa_issuance("rejected").unwrap());
            store.confirm_oa_unissued("rejected").unwrap();
        }
        let reopened = NullifierStore::new(&path).unwrap();
        assert_eq!(
            reopened
                .lookup_openrouter_lease("never-started")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::NotStarted
        );
        assert!(!reopened.begin_oa_issuance("attempted").unwrap());
        assert_eq!(
            reopened
                .lookup_openrouter_lease("rejected")
                .unwrap()
                .oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert!(reopened.begin_oa_issuance("rejected").is_err());
        let mut due_ids: Vec<_> = reopened
            .due_openrouter_leases(21)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        due_ids.sort();
        assert_eq!(
            due_ids,
            vec!["attempted", "legacy", "never-started", "rejected"]
        );
    }

    #[test]
    fn test_reserve_and_lookup() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "test-req-1";
        let payload_hash = Felt252::from_u64(100);

        store.reserve(&nullifier, client_id, &payload_hash).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.client_request_id.as_deref(), Some(client_id));
    }

    #[test]
    fn test_reserve_duplicate_fails() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();
        let result = store.reserve(&nullifier, "req-2", &Felt252::from_u64(2));
        assert!(result.is_err());
    }

    #[test]
    fn test_lookup_by_client_id() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);
        let client_id = "unique-client-id";

        store
            .reserve(&nullifier, client_id, &Felt252::from_u64(1))
            .unwrap();

        let record = store.lookup_by_client_id(client_id).unwrap();
        assert_eq!(record.nullifier, nullifier);
    }

    #[test]
    fn test_finalize() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();

        let transcript = TranscriptRecord {
            nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "proxy".to_string(),
            client_request_id: Some("req-1".to_string()),
            payload_hash: Some(Felt252::from_u64(1)),
            charge_applied: Some(100),
            response_code: Some(200),
            response_payload: Some("{\"ok\":true}".to_string()),
            response_hash: Some(Felt252::from_u64(999)),
            next_commitment_x: Some(Felt252::from_u64(10)),
            next_commitment_y: Some(Felt252::from_u64(20)),
            next_anchor: Some(Felt252::from_u64(30)),
            blind_delta_srv: Some(Felt252::from_u64(40)),
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: None,
            request_inputs_json: None,
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
            settled_charge: None,
            settled_basis: None,
            settled_at: None,
            exit_deferred_since: None,
        };

        store.finalize(&nullifier, &transcript).unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(100));
        assert_eq!(record.response_payload.as_deref(), Some("{\"ok\":true}"));
    }

    #[test]
    fn test_reserve_clearance() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(42);

        store
            .reserve_clearance(&nullifier, "ownership_proof")
            .unwrap();

        let record = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::ClearanceReserved);
        assert_eq!(
            store.clearance_auth(&nullifier).unwrap().as_deref(),
            Some("ownership_proof")
        );
        assert!(matches!(
            store.reserve_clearance(&nullifier, "legacy"),
            Err(ServerError::NullifierUsed)
        ));
        assert_eq!(store.clearance_auth(&Felt252::from_u64(43)).unwrap(), None);
    }

    #[test]
    fn test_get_reserved_entries() {
        let store = NullifierStore::in_memory().unwrap();

        store
            .reserve(&Felt252::from_u64(1), "r1", &Felt252::from_u64(10))
            .unwrap();
        store
            .reserve(&Felt252::from_u64(2), "r2", &Felt252::from_u64(20))
            .unwrap();

        let reserved = store.get_reserved_entries();
        assert_eq!(reserved.len(), 2);
    }

    #[test]
    fn openrouter_lease_never_persists_plaintext_key() {
        use zkapi_types::wire::{ApiRequestV2, Groth16ProofWire, ProofBackendWire};
        use zkapi_types::RequestPublicInputsV2;

        let store = NullifierStore::in_memory().unwrap();
        let nullifier = Felt252::from_u64(77);
        let request = ApiRequestV2 {
            client_request_id: "lease-1".to_string(),
            payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".to_string(),
            payload_hash: Felt252::from_u64(88),
            public_inputs: RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: Felt252::from_u64(2),
                active_root: Felt252::from_u64(3),
                state_signing_key_x: Felt252::from_u64(4),
                state_signing_key_y: Felt252::from_u64(5),
                request_time: 6,
                solvency_bound: 1_000,
                request_nullifier: nullifier,
                authorization_tag: Felt252::from_u64(7),
                anonymous_commitment_x: Felt252::from_u64(8),
                anonymous_commitment_y: Felt252::from_u64(9),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: crate::test_support::fake_proof(7),
            },
        };
        store.reserve_openrouter_lease(&request).unwrap();
        let reservation = store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(
            reservation.api_request_binding.as_deref(),
            Some(api_request_binding(&request).unwrap().as_str())
        );
        store
            .create_openrouter_lease(&request, "openrouter", 10, 20, 21, 0.001)
            .unwrap();
        {
            let conn = store.conn.lock().unwrap();
            conn.execute(
                "UPDATE nullifiers SET api_request_binding = NULL WHERE nullifier = ?1",
                params![nullifier.to_hex()],
            )
            .unwrap();
            backfill_openrouter_request_bindings(&conn).unwrap();
        }
        assert_eq!(
            store
                .lookup_by_nullifier(&nullifier)
                .unwrap()
                .api_request_binding,
            Some(api_request_binding(&request).unwrap())
        );
        store
            .activate_openrouter_lease("lease-1", "safe-key-hash")
            .unwrap();

        let lease = store.lookup_openrouter_lease("lease-1").unwrap();
        assert_eq!(lease.key_hash.as_deref(), Some("safe-key-hash"));
        assert!(!serde_json::to_string(&lease.api_request)
            .unwrap()
            .contains("sk-or-"));
        assert_eq!(store.due_openrouter_leases(20).len(), 0);
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
    }

    fn deployment_binding() -> DeploymentBinding {
        let signer = crate::signer::ServerSigner::new(&Felt252::from_u64(7), &Felt252::from_u64(8));
        DeploymentBinding {
            chain_id: 11_155_111,
            contract_address: "0x00000000000000000000000000000000000000aa".into(),
            state_signing_key: signer.state_public_key(),
            clearance_signing_key: signer.clearance_public_key(),
            challenge_period_seconds: 86_400,
            verified_at: 1_700_000_000,
            verified_block: None,
            circuit_id: Some(zkapi_proof::compact::CIRCUIT_ID.into()),
            setup_id: Some("dev".into()),
            request_vk_keccak256: Some(format!("0x{}", "11".repeat(32))),
            withdrawal_vk_keccak256: Some(format!("0x{}", "22".repeat(32))),
            source: BINDING_SOURCE_VAULT.into(),
        }
    }

    fn finalized(nullifier: Felt252) -> TranscriptRecord {
        TranscriptRecord {
            nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "proxy".to_string(),
            client_request_id: Some("req-1".to_string()),
            payload_hash: Some(Felt252::from_u64(1)),
            charge_applied: Some(100),
            response_code: Some(200),
            response_payload: Some("{}".to_string()),
            response_hash: Some(Felt252::from_u64(999)),
            next_commitment_x: None,
            next_commitment_y: None,
            next_anchor: Some(Felt252::from_u64(30)),
            blind_delta_srv: None,
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(vec![7; 256]),
            request_inputs_json: Some("{}".to_string()),
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
            settled_charge: None,
            settled_basis: None,
            settled_at: None,
            exit_deferred_since: None,
        }
    }

    #[test]
    fn read_only_store_sees_server_writes_but_cannot_write() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        let nullifier = Felt252::from_u64(42);
        assert!(reader
            .try_lookup_by_nullifier(&nullifier)
            .unwrap()
            .is_none());
        assert_eq!(reader.read_deployment_binding().unwrap(), None);
        server
            .reserve(&nullifier, "req-1", &Felt252::from_u64(1))
            .unwrap();
        server.finalize(&nullifier, &finalized(nullifier)).unwrap();
        server
            .create_openrouter_lease(&lease_request("lease", 9), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        server
            .write_deployment_binding(&deployment_binding())
            .unwrap();

        let record = reader.try_lookup_by_nullifier(&nullifier).unwrap().unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.proof_blob.as_deref(), Some(&[7; 256][..]));
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("lease")
                .unwrap()
                .unwrap()
                .status,
            "provisioning"
        );
        assert_eq!(
            reader.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );

        // Every write fails on the reader and leaves the database unchanged.
        assert!(reader
            .reserve_clearance(&Felt252::from_u64(43), "ownership_proof")
            .is_err());
        assert!(reader
            .reserve(&Felt252::from_u64(44), "req-2", &Felt252::from_u64(2))
            .is_err());
        assert!(reader
            .write_deployment_binding(&DeploymentBinding {
                chain_id: 1,
                ..deployment_binding()
            })
            .is_err());
        assert!(reader
            .record_openrouter_lease_error("lease", "reader write")
            .is_err());
        assert!(server.lookup_by_nullifier(&Felt252::from_u64(43)).is_none());
        assert!(server.lookup_by_nullifier(&Felt252::from_u64(44)).is_none());
        assert_eq!(
            server.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );
        assert!(server
            .lookup_openrouter_lease("lease")
            .unwrap()
            .last_error
            .is_none());

        // A read-only open never creates a database.
        let missing = directory.path().join("missing.db");
        assert!(NullifierStore::open_read_only(&missing).is_err());
        assert!(!missing.exists());
    }

    #[test]
    fn read_only_store_rejects_outdated_schema() {
        let directory = tempfile::tempdir().unwrap();
        let unrelated = directory.path().join("unrelated.db");
        Connection::open(&unrelated)
            .unwrap()
            .execute_batch("CREATE TABLE unrelated (value TEXT);")
            .unwrap();
        // A server database from before api_request_binding was read.
        let legacy = directory.path().join("legacy.db");
        let legacy_columns = TRANSCRIPT_RECORD_COLUMNS
            .iter()
            .filter(|column| **column != "api_request_binding")
            .copied()
            .collect::<Vec<_>>();
        Connection::open(&legacy)
            .unwrap()
            .execute_batch(&format!(
                "CREATE TABLE nullifiers ({}); CREATE TABLE openrouter_leases ({});",
                legacy_columns.join(", "),
                OPENROUTER_LEASE_RECORD_COLUMNS.join(", ")
            ))
            .unwrap();
        for path in [&unrelated, &legacy] {
            let error = NullifierStore::open_read_only(path)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("schema is older"), "{error}");
        }
        // The read-only open did not migrate the file; the server's open does.
        let column_count = |path: &std::path::Path| -> i64 {
            Connection::open(path)
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM pragma_table_info('nullifiers')
                     WHERE name = 'api_request_binding'",
                    [],
                    |row| row.get(0),
                )
                .unwrap()
        };
        assert_eq!(column_count(&legacy), 0);
        NullifierStore::new(&legacy).unwrap();
        assert_eq!(column_count(&legacy), 1);
        assert!(NullifierStore::open_read_only(&legacy).is_ok());
    }

    /// A reader refuses a database missing any column it reads, in any of
    /// the four tables, even with every table and trigger present.
    #[test]
    fn read_only_store_requires_every_column_of_every_table_it_reads() {
        let directory = tempfile::tempdir().unwrap();
        for (table, columns) in [
            ("nullifiers", TRANSCRIPT_RECORD_COLUMNS),
            ("openrouter_leases", OPENROUTER_LEASE_RECORD_COLUMNS),
            ("request_evidence", REQUEST_EVIDENCE_COLUMNS),
            ("deployment_binding", DEPLOYMENT_BINDING_COLUMNS),
        ] {
            let mut dropped = 0;
            for column in columns {
                let path = directory.path().join(format!("{table}-{column}.db"));
                drop(NullifierStore::new(&path).unwrap());
                assert!(NullifierStore::open_read_only(&path).is_ok());
                // Key and indexed columns cannot be dropped; the others can.
                if Connection::open(&path)
                    .unwrap()
                    .execute_batch(&format!("ALTER TABLE {table} DROP COLUMN {column}"))
                    .is_err()
                {
                    continue;
                }
                dropped += 1;
                let error = NullifierStore::open_read_only(&path)
                    .err()
                    .map(|error| error.to_string());
                assert!(
                    error
                        .as_deref()
                        .is_some_and(|error| error.contains("run `zkapi db init` first")),
                    "{table}.{column}: {error:?}"
                );
            }
            assert!(dropped > 0, "no column of {table} could be dropped");
        }
    }

    #[test]
    fn the_recorded_binding_is_read_from_a_database_of_any_release_without_writing() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let read = || NullifierStore::read_recorded_deployment_binding(&path);
        // A database older than the binding table, then the pre-change
        // schema with no binding row: unbound.
        Connection::open(&path)
            .unwrap()
            .execute_batch("CREATE TABLE nullifiers (nullifier TEXT PRIMARY KEY)")
            .unwrap();
        assert_eq!(read().unwrap(), None);
        std::fs::remove_file(&path).unwrap();
        Connection::open(&path)
            .unwrap()
            .execute_batch(SCHEMA_4F21B66)
            .unwrap();
        assert_eq!(read().unwrap(), None);
        // Its binding: no statement recorded, verified against the vault.
        let legacy = deployment_binding();
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO deployment_binding (id, chain_id, contract_address, state_key_x,
                    state_key_y, clearance_key_x, clearance_key_y, challenge_period_seconds,
                    verified_at, verified_block)
                 VALUES (1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 9)",
                params![
                    legacy.chain_id,
                    legacy.contract_address,
                    legacy.state_signing_key.x.to_hex(),
                    legacy.state_signing_key.y.to_hex(),
                    legacy.clearance_signing_key.x.to_hex(),
                    legacy.clearance_signing_key.y.to_hex(),
                    legacy.challenge_period_seconds,
                    legacy.verified_at
                ],
            )
            .unwrap();
        let before = std::fs::read(&path).unwrap();
        assert_eq!(
            read().unwrap(),
            Some(DeploymentBinding {
                verified_block: Some(9),
                circuit_id: None,
                setup_id: None,
                request_vk_keccak256: None,
                withdrawal_vk_keccak256: None,
                source: BINDING_SOURCE_VAULT.into(),
                ..legacy
            })
        );
        assert!(
            std::fs::read(&path).unwrap() == before,
            "nothing is written"
        );
        assert!(NullifierStore::open_read_only(&path).is_err());
        // Migrated, it reads as `read_deployment_binding` reads it.
        let store = NullifierStore::new(&path).unwrap();
        store
            .write_deployment_binding(&deployment_binding())
            .unwrap();
        drop(store);
        assert_eq!(read().unwrap(), Some(deployment_binding()));
        // A binding table without a column every release recorded is an
        // error, never "unbound".
        let damaged = directory.path().join("damaged.db");
        Connection::open(&damaged)
            .unwrap()
            .execute_batch(
                "CREATE TABLE deployment_binding (id INTEGER PRIMARY KEY, chain_id INTEGER);
                 INSERT INTO deployment_binding VALUES (1, 1);",
            )
            .unwrap();
        assert!(NullifierStore::read_recorded_deployment_binding(&damaged).is_err());
    }

    #[test]
    fn deployment_binding_round_trips_and_is_absent_from_older_databases() {
        let store = NullifierStore::in_memory().unwrap();
        assert_eq!(store.read_deployment_binding().unwrap(), None);
        store
            .write_deployment_binding(&deployment_binding())
            .unwrap();
        assert_eq!(
            store.read_deployment_binding().unwrap(),
            Some(deployment_binding())
        );
        let reverified = DeploymentBinding {
            verified_at: 1_700_000_100,
            verified_block: Some(123),
            ..deployment_binding()
        };
        store.write_deployment_binding(&reverified).unwrap();
        assert_eq!(store.read_deployment_binding().unwrap(), Some(reverified));
        {
            // One row, felts as Felt252::to_hex prints them.
            let conn = store.conn.lock().unwrap();
            let (rows, address, state_x, clearance_y): (i64, String, String, String) = conn
                .query_row(
                    "SELECT COUNT(*), contract_address, state_key_x, clearance_key_y
                     FROM deployment_binding",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .unwrap();
            assert_eq!(rows, 1);
            assert_eq!(address, deployment_binding().contract_address);
            assert_eq!(state_x, deployment_binding().state_signing_key.x.to_hex());
            assert_eq!(
                clearance_y,
                deployment_binding().clearance_signing_key.y.to_hex()
            );
        }
        assert!(store
            .write_deployment_binding(&DeploymentBinding {
                chain_id: u64::MAX,
                ..deployment_binding()
            })
            .is_err());

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        NullifierStore::new(&path).unwrap();
        assert_eq!(
            NullifierStore::open_read_only(&path)
                .unwrap()
                .read_deployment_binding()
                .unwrap(),
            None
        );
        // A reader requires the binding table (with its statement columns):
        // `zkapi db init` creates it.
        Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE deployment_binding;")
            .unwrap();
        let error = NullifierStore::open_read_only(&path).err().unwrap();
        assert!(error.to_string().contains("zkapi db init"), "{error}");
    }

    #[test]
    fn required_column_lists_cover_every_column_the_row_decoders_read() {
        // Tables holding only the listed columns: a decoder that reads any
        // other column fails here until its list is updated.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("minimal.db");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(&format!(
                "CREATE TABLE nullifiers ({}); CREATE TABLE openrouter_leases ({});
                 CREATE TABLE request_evidence ({}); CREATE TABLE deployment_binding ({});
                 CREATE TRIGGER request_evidence_no_update BEFORE UPDATE ON request_evidence
                    BEGIN SELECT RAISE(ABORT,'append-only'); END;
                 CREATE TRIGGER request_evidence_no_delete BEFORE DELETE ON request_evidence
                    BEGIN SELECT RAISE(ABORT,'append-only'); END;",
                TRANSCRIPT_RECORD_COLUMNS.join(", "),
                OPENROUTER_LEASE_RECORD_COLUMNS.join(", "),
                REQUEST_EVIDENCE_COLUMNS.join(", "),
                DEPLOYMENT_BINDING_COLUMNS.join(", ")
            ))
            .unwrap();
            conn.execute(
                "INSERT INTO nullifiers (nullifier, status, reservation_kind, created_at)
                 VALUES (?1, 'Reserved', 'openrouter_lease', 1)",
                params![Felt252::from_u64(5).to_hex()],
            )
            .unwrap();
            let request = lease_request("minimal", 5);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier,
                    api_request_json, key_source, oa_provisioning_outcome, status, issued_at,
                    expires_at, settle_after, spending_limit_usd)
                 VALUES ('minimal', ?1, ?2, 'openrouter', 'may_have_issued', 'active', 1, 2, 3, 1.5)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request).unwrap()
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO request_evidence (id, nullifier, client_request_id, solvency_bound,
                    request_inputs_json, proof_blob, source, created_at)
                 VALUES (1, ?1, 'minimal', '1000', ?2, ?3, 'reserve', 4)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request.public_inputs).unwrap(),
                    vec![7u8; 256]
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO deployment_binding (id, chain_id, contract_address, state_key_x,
                    state_key_y, clearance_key_x, clearance_key_y, challenge_period_seconds,
                    verified_at, source)
                 VALUES (1, 1, '0xaa', '0x1', '0x2', '0x3', '0x4', 86400, 7, 'manifest')",
                [],
            )
            .unwrap();
        }
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert_eq!(
            reader
                .try_lookup_by_nullifier(&Felt252::from_u64(5))
                .unwrap()
                .unwrap()
                .reservation_kind,
            "openrouter_lease"
        );
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("minimal")
                .unwrap()
                .unwrap()
                .status,
            "active"
        );
        let evidence = reader
            .earliest_reserve_evidence(&Felt252::from_u64(5))
            .unwrap()
            .unwrap();
        assert_eq!(evidence.solvency_bound, 1_000);
        assert_eq!(evidence.proof, vec![7u8; 256]);
        assert_eq!(
            reader.read_deployment_binding().unwrap().unwrap().source,
            BINDING_SOURCE_MANIFEST
        );
    }

    /// O2: a reservation and its evidence are written in one transaction.
    /// An evidence insert that fails (here injected with a trigger) leaves no
    /// reservation, a reservation that fails (a replay) leaves no evidence,
    /// and a proof that is not 256 bytes reserves nothing.
    #[test]
    fn evidence_is_written_atomically_with_the_reservation() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("atomic", 31);
        store.execute_for_test(
            "CREATE TRIGGER inject_evidence_failure BEFORE INSERT ON request_evidence
             BEGIN SELECT RAISE(ABORT, 'injected evidence failure'); END",
            [],
        );
        let error = store.reserve_openrouter_lease(&request).unwrap_err();
        assert!(
            error.to_string().contains("injected evidence failure"),
            "{error}"
        );
        assert!(store
            .try_lookup_by_nullifier(&Felt252::from_u64(31))
            .unwrap()
            .is_none());
        store.execute_for_test("DROP TRIGGER inject_evidence_failure", []);
        store.reserve_openrouter_lease(&request).unwrap();
        let evidence = store.request_evidence(&Felt252::from_u64(31)).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].source, "reserve");
        assert_eq!(evidence[0].client_request_id, "atomic");
        assert_eq!(evidence[0].solvency_bound, 1_000);
        assert_eq!(evidence[0].public_inputs, request.public_inputs);
        assert_eq!(evidence[0].proof, vec![7u8; 256]);
        // A replay of the nullifier reserves nothing and adds no evidence.
        let mut replay = lease_request("replay", 31);
        replay.proof.proof = crate::test_support::fake_proof(8);
        assert!(matches!(
            store.reserve_openrouter_lease(&replay),
            Err(ServerError::Replay)
        ));
        assert_eq!(
            store
                .request_evidence(&Felt252::from_u64(31))
                .unwrap()
                .len(),
            1
        );
        // A proof of the wrong size reserves nothing.
        let mut short = lease_request("short", 32);
        short.proof.proof = "AA==".into();
        assert!(matches!(
            store.reserve_openrouter_lease(&short),
            Err(ServerError::InvalidProof(_))
        ));
        assert!(store.lookup_by_nullifier(&Felt252::from_u64(32)).is_none());
        assert!(store
            .request_evidence(&Felt252::from_u64(32))
            .unwrap()
            .is_empty());
    }

    /// The evidence table is append-only: updates and deletes abort, also on
    /// a raw connection, and the triggers are recreated on every open.
    #[test]
    fn request_evidence_is_append_only() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let store = NullifierStore::new(&path).unwrap();
        store
            .reserve_openrouter_lease(&lease_request("kept", 41))
            .unwrap();
        drop(store);
        let conn = Connection::open(&path).unwrap();
        for sql in [
            "UPDATE request_evidence SET solvency_bound = '1'",
            "UPDATE request_evidence SET proof_blob = zeroblob(256)",
            "DELETE FROM request_evidence",
        ] {
            let error = conn.execute(sql, []).unwrap_err().to_string();
            assert!(error.contains("append-only"), "{sql}: {error}");
        }
        // Rows of another size or source never enter.
        for sql in [
            "INSERT INTO request_evidence (nullifier, client_request_id, solvency_bound,
                request_inputs_json, proof_blob, source, created_at)
             VALUES ('0x1', 'x', '1', '{}', zeroblob(255), 'reserve', 1)",
            "INSERT INTO request_evidence (nullifier, client_request_id, solvency_bound,
                request_inputs_json, proof_blob, source, created_at)
             VALUES ('0x1', 'x', '1', '{}', zeroblob(256), 'forged', 1)",
        ] {
            assert!(conn.execute(sql, []).is_err(), "{sql}");
        }
        // Dropping a trigger does not survive the next open.
        conn.execute_batch("DROP TRIGGER request_evidence_no_delete;")
            .unwrap();
        drop(conn);
        let error = NullifierStore::open_read_only(&path).err().unwrap();
        assert!(error.to_string().contains("zkapi db init"), "{error}");
        NullifierStore::new(&path).unwrap();
        let conn = Connection::open(&path).unwrap();
        assert!(conn.execute("DELETE FROM request_evidence", []).is_err());
        assert_eq!(
            NullifierStore::open_read_only(&path)
                .unwrap()
                .request_evidence(&Felt252::from_u64(41))
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn try_lookups_report_database_errors_instead_of_absence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server
            .create_openrouter_lease(&lease_request("corrupt", 6), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        server
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET api_request_json = 'not json'",
                [],
            )
            .unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert!(reader.try_lookup_openrouter_lease("corrupt").is_err());
        assert!(reader.lookup_openrouter_lease("corrupt").is_none());
        server
            .conn
            .lock()
            .unwrap()
            .execute_batch("DROP TABLE nullifiers; DROP TABLE openrouter_leases;")
            .unwrap();
        assert!(reader
            .try_lookup_by_nullifier(&Felt252::from_u64(1))
            .is_err());
        assert!(reader.lookup_by_nullifier(&Felt252::from_u64(1)).is_none());
        assert!(reader.try_lookup_openrouter_lease("corrupt").is_err());
    }

    fn review(id: &str, reason: &str) -> SettlementReview {
        SettlementReview {
            client_request_id: id.to_string(),
            request_nullifier: Felt252::from_u64(9),
            key_source: "openrouter".into(),
            reason: reason.into(),
            charge_basis: Some("worst_case".into()),
            detail: "x".repeat(800),
            reported_usage_micro_usd: Some(u128::MAX),
            charge_applied: Some(1_000),
            solvency_bound: 1_000,
        }
    }

    #[test]
    fn settlement_review_and_cancel_are_atomic_and_listed() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("worst", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(&lease_request("corrupt", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("worst", "hash-1").unwrap();
        let worst = review("worst", "deadline_worst_case");
        assert!(store
            .finalize_openrouter_lease_with(
                "worst",
                &LeaseFinalization {
                    usage_usd: 0.0,
                    charge_applied: 1_000,
                    charge_basis: "worst_case",
                    review: Some(&worst),
                    key_cleanup: Some(KeyCleanup {
                        key_source: "openrouter",
                        key_hash: Some("hash-1"),
                        key_name: "zkapi-worst",
                    }),
                    guard: FinalizeGuard::NotCancelled,
                },
            )
            .unwrap());
        let lease = store.lookup_openrouter_lease("worst").unwrap();
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_applied, Some(1_000));
        assert_eq!(lease.charge_basis.as_deref(), Some("worst_case"));
        store
            .cancel_openrouter_lease("corrupt", &review("corrupt", "binding_corrupt"))
            .unwrap();
        let cancelled = store.lookup_openrouter_lease("corrupt").unwrap();
        assert_eq!(cancelled.status, "cancelled");
        assert_eq!(cancelled.last_error.as_ref().unwrap().len(), 500);
        // A cancelled row is terminal: neither finalized nor settled later.
        assert!(!store
            .finalize_openrouter_lease_with(
                "corrupt",
                &LeaseFinalization {
                    usage_usd: 0.0,
                    charge_applied: 0,
                    charge_basis: "measured",
                    review: None,
                    key_cleanup: None,
                    guard: FinalizeGuard::NotCancelled,
                },
            )
            .unwrap());
        assert!(store.due_openrouter_leases(u64::MAX / 4).is_empty());
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 2);
        let stored = reviews
            .iter()
            .find(|stored| stored.review.client_request_id == "worst")
            .unwrap();
        assert_eq!(stored.review.detail.len(), 500);
        assert_eq!(stored.review.reported_usage_micro_usd, Some(u128::MAX));
        assert_eq!(stored.review.charge_applied, Some(1_000));
        assert_eq!(stored.acknowledged_at, None);
        // A terminal lease is neither cancelled nor reviewed again.
        store
            .cancel_openrouter_lease("worst", &review("worst", "binding_corrupt"))
            .unwrap();
        assert_eq!(
            store.lookup_openrouter_lease("worst").unwrap().status,
            "finalized"
        );
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 2);
        let counts = store.settlement_counts(0).unwrap();
        assert_eq!(
            (counts.pending, counts.cancelled, counts.open_reviews),
            (0, 1, 2)
        );
        assert_eq!(counts.pending_key_cleanups, 1);
        let queued = store.due_key_cleanups(u64::MAX / 4, 10).unwrap();
        assert_eq!(queued.len(), 1);
        assert_eq!(queued[0].key_hash.as_deref(), Some("hash-1"));
        store
            .defer_key_cleanup("worst", "provider unavailable", u64::MAX / 8)
            .unwrap();
        assert!(store
            .due_key_cleanups(u64::MAX / 16, 10)
            .unwrap()
            .is_empty());
        assert_eq!(
            store.due_key_cleanups(u64::MAX / 4, 10).unwrap()[0].attempts,
            1
        );
        store.complete_key_cleanup("worst").unwrap();
        assert!(store.due_key_cleanups(u64::MAX / 4, 10).unwrap().is_empty());
    }

    #[test]
    fn unissued_finalization_is_conditional_on_an_unissued_row() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("raced", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("raced", "issued").unwrap();
        let zero = LeaseFinalization {
            usage_usd: 0.0,
            charge_applied: 0,
            charge_basis: "unissued",
            review: None,
            key_cleanup: None,
            guard: FinalizeGuard::Unissued,
        };
        // An activation without delivery provenance may have been delivered.
        assert!(!store.fence_unissued_settlement("raced").unwrap());
        assert!(!store
            .finalize_openrouter_lease_with("raced", &zero)
            .unwrap());
        assert_eq!(
            store.lookup_openrouter_lease("raced").unwrap().status,
            "active"
        );
        store
            .create_openrouter_lease(&lease_request("unissued", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        // Only a row fenced before signing finalizes at zero.
        assert!(!store
            .finalize_openrouter_lease_with("unissued", &zero)
            .unwrap());
        assert!(store.fence_unissued_settlement("unissued").unwrap());
        assert!(store
            .finalize_openrouter_lease_with("unissued", &zero)
            .unwrap());
        assert_eq!(
            store.lookup_openrouter_lease("unissued").unwrap().status,
            "finalized"
        );
    }

    fn create_bound_lease(store: &NullifierStore, id: &str, nullifier: u64, delivered: bool) {
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &lease_request(id, nullifier),
                key_source: "oa_org",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: Some("bound"),
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(1_000),
                delivered: Some(delivered),
            })
            .unwrap();
    }

    /// Review regression (unsettleable lease #1), at the store: a zero
    /// settlement fences its lease before signing, after which the key can be
    /// neither activated nor marked delivered; a delivered key can no longer
    /// be fenced or finalized at zero.
    #[test]
    fn zero_settlement_fence_excludes_key_delivery() {
        let store = NullifierStore::in_memory().unwrap();
        let zero = LeaseFinalization {
            usage_usd: 0.0,
            charge_applied: 0,
            charge_basis: "unissued",
            review: None,
            key_cleanup: None,
            guard: FinalizeGuard::Unissued,
        };
        // Settlement first: issuance's later mark is refused.
        create_bound_lease(&store, "fenced", 1, false);
        store.activate_openrouter_lease("fenced", "hash-1").unwrap();
        assert!(store.fence_unissued_settlement("fenced").unwrap());
        assert!(store.fence_unissued_settlement("fenced").unwrap());
        assert!(store.mark_openrouter_lease_delivered("fenced").is_err());
        assert!(store
            .finalize_openrouter_lease_with("fenced", &zero)
            .unwrap());
        let fenced = store.lookup_openrouter_lease("fenced").unwrap();
        assert_eq!(fenced.status, "finalized");
        assert_eq!(fenced.delivered, Some(false));
        assert_eq!(fenced.charge_basis.as_deref(), Some("unissued"));
        // Delivery first: no fence, and no zero finalization.
        create_bound_lease(&store, "delivered", 2, false);
        store
            .activate_openrouter_lease("delivered", "hash-2")
            .unwrap();
        store.mark_openrouter_lease_delivered("delivered").unwrap();
        assert!(!store.fence_unissued_settlement("delivered").unwrap());
        assert!(!store
            .finalize_openrouter_lease_with("delivered", &zero)
            .unwrap());
        let delivered = store.lookup_openrouter_lease("delivered").unwrap();
        assert_eq!(delivered.status, "active");
        assert_eq!(delivered.delivered, Some(true));
        assert_eq!(delivered.charge_basis, None);
        // A fenced provisioning row never activates a key.
        create_bound_lease(&store, "provisioning", 3, false);
        assert!(store.fence_unissued_settlement("provisioning").unwrap());
        assert!(store
            .activate_openrouter_lease("provisioning", "hash-3")
            .is_err());
        let provisioning = store.lookup_openrouter_lease("provisioning").unwrap();
        assert_eq!(provisioning.status, "provisioning");
        assert_eq!(provisioning.key_hash, None);
        // Neither does a lease conceded by the operator; it is due at once.
        create_bound_lease(&store, "conceded", 4, false);
        store
            .activate_openrouter_lease("conceded", "hash-4")
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET charge_basis = 'operator_conceded'
                 WHERE client_request_id = 'conceded'",
                [],
            )
            .unwrap();
        assert!(store.mark_openrouter_lease_delivered("conceded").is_err());
        assert!(!store.fence_unissued_settlement("conceded").unwrap());
        let mut due: Vec<_> = store
            .due_openrouter_leases(0)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        due.sort();
        assert_eq!(due, ["conceded", "provisioning"]);
    }

    #[test]
    fn record_error_counts_attempts_and_first_error_survives_transitions() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("errors", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("errors", "hash").unwrap();
        let fresh = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!((fresh.settlement_attempts, fresh.first_error_at), (0, None));
        store
            .record_openrouter_lease_error("errors", "first")
            .unwrap();
        let first = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!(first.settlement_attempts, 1);
        let first_error_at = first.first_error_at.unwrap();
        for (from, to) in [
            ("active", "retiring"),
            ("retiring", "disabled"),
            ("disabled", "retiring"),
        ] {
            store
                .advance_openrouter_retirement("errors", from, to, 0, None)
                .unwrap();
            store
                .record_openrouter_lease_error("errors", "again")
                .unwrap();
        }
        let lease = store.lookup_openrouter_lease("errors").unwrap();
        assert_eq!(lease.settlement_attempts, 4);
        assert_eq!(lease.first_error_at, Some(first_error_at));
        assert_eq!(lease.last_error.as_deref(), Some("again"));
    }

    #[test]
    fn settlement_deadline_is_write_once() {
        let store = NullifierStore::in_memory().unwrap();
        let request = lease_request("deadline", 1);
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "oa_org",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: Some("bound"),
                ttl_seconds: Some(600),
                settlement_deadline_at: Some(1_000),
                delivered: Some(false),
            })
            .unwrap();
        let lease = store.lookup_openrouter_lease("deadline").unwrap();
        assert_eq!(lease.ttl_seconds, Some(600));
        assert_eq!(lease.settlement_deadline_at, Some(1_000));
        assert_eq!(lease.delivered, Some(false));
        assert_eq!(
            store.assign_settlement_deadline("deadline", 5).unwrap(),
            1_000
        );
        store
            .update_openrouter_lease_timing("deadline", 900, 950)
            .unwrap();
        store.activate_openrouter_lease("deadline", "hash").unwrap();
        store.mark_openrouter_lease_delivered("deadline").unwrap();
        let lease = store.lookup_openrouter_lease("deadline").unwrap();
        assert_eq!(lease.settlement_deadline_at, Some(1_000));
        assert_eq!(lease.delivered, Some(true));
        // Due at the deadline even when settle_after is later.
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET settle_after = 5000 WHERE client_request_id = 'deadline'",
                [],
            )
            .unwrap();
        assert!(store.due_openrouter_leases(999).is_empty());
        assert_eq!(store.due_openrouter_leases(1_000).len(), 1);
        // Rows recorded without a deadline are assigned once, then keep it.
        store
            .create_openrouter_lease(&lease_request("legacy", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        assert_eq!(
            store.leases_without_settlement_deadline().unwrap(),
            vec![("legacy".to_string(), 20)]
        );
        assert_eq!(
            store.assign_settlement_deadline("legacy", 7_000).unwrap(),
            7_000
        );
        assert_eq!(
            store.assign_settlement_deadline("legacy", 9_000).unwrap(),
            7_000
        );
        assert!(store
            .leases_without_settlement_deadline()
            .unwrap()
            .is_empty());
        assert!(store.mark_openrouter_lease_delivered("legacy").is_err());
    }

    #[test]
    fn due_includes_direct_provisioning_after_settle_after() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("direct", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(
                &lease_request("unknown", 2),
                "future_source",
                10,
                20,
                21,
                1.0,
            )
            .unwrap();
        assert!(store.due_openrouter_leases(20).is_empty());
        let due = store.due_openrouter_leases(21);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].client_request_id, "direct");
        // Least recently attempted first.
        store
            .create_openrouter_lease(&lease_request("second", 3), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .record_openrouter_lease_error("direct", "retry later")
            .unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET updated_at = 1 WHERE client_request_id = 'second'",
                [],
            )
            .unwrap();
        let order: Vec<_> = store
            .due_openrouter_leases(21)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        assert_eq!(order, ["second", "direct"]);
    }

    #[test]
    fn settlement_counts_include_unreadable_rows() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("ok", 1), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .create_openrouter_lease(&lease_request("broken", 2), "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store.assign_settlement_deadline("ok", 500).unwrap();
        store.record_openrouter_lease_error("ok", "failed").unwrap();
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET api_request_json = 'not json' WHERE client_request_id = 'broken'",
                [],
            )
            .unwrap();
        // The scan cannot decode the broken row...
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert_eq!(store.pending_openrouter_leases(10).unwrap().len(), 1);
        // ...but the operator counts include it.
        let counts = store.settlement_counts(100).unwrap();
        assert_eq!(counts.pending, 2);
        assert_eq!(counts.provisioning, 2);
        assert_eq!(counts.retrying, 1);
        assert_eq!(counts.next_deadline_in_seconds, Some(400));
        store
            .conn
            .lock()
            .unwrap()
            .execute(
                "UPDATE openrouter_leases SET status = 'mystery' WHERE client_request_id = 'broken'",
                [],
            )
            .unwrap();
        assert_eq!(store.settlement_counts(100).unwrap().unknown_status, 1);
    }

    #[test]
    fn legacy_db_migrates_settlement_columns_reviews_and_clearance_auth() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("legacy.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE nullifiers (
                    nullifier TEXT PRIMARY KEY, status TEXT NOT NULL,
                    reservation_kind TEXT NOT NULL DEFAULT 'proxy', client_request_id TEXT,
                    payload_hash TEXT, charge_applied INTEGER, response_code INTEGER,
                    response_payload TEXT, response_hash TEXT, next_commitment_x TEXT,
                    next_commitment_y TEXT, next_anchor TEXT, blind_delta_srv TEXT,
                    next_state_sig_epoch INTEGER, next_state_sig_root TEXT, next_state_sig_json TEXT,
                    policy_reason_code INTEGER, policy_evidence_hash TEXT, proof_blob BLOB,
                    request_inputs_json TEXT, api_request_binding TEXT, created_at INTEGER NOT NULL,
                    finalized_at INTEGER
                );
                CREATE TABLE openrouter_leases (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
                    api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
                    key_source TEXT NOT NULL DEFAULT 'openrouter',
                    oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
                    status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
                    settle_after INTEGER NOT NULL, spending_limit_usd REAL NOT NULL, usage_usd REAL,
                    charge_applied INTEGER, last_error TEXT, updated_at INTEGER NOT NULL
                );
                INSERT INTO nullifiers (nullifier, status, created_at)
                    VALUES ('0x2a', 'ClearanceReserved', 1);",
            )
            .unwrap();
            let request = lease_request("legacy", 1);
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier, api_request_json,
                    key_source, key_hash, status, issued_at, expires_at, settle_after, spending_limit_usd,
                    usage_usd, updated_at)
                 VALUES ('legacy', ?1, ?2, 'openrouter', 'hash', 'revoking', 10, 20, 21, 6.0, 0.5, 10)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request).unwrap()
                ],
            )
            .unwrap();
        }
        let store = NullifierStore::new(&path).unwrap();
        let lease = store.lookup_openrouter_lease("legacy").unwrap();
        assert_eq!(lease.ttl_seconds, None);
        assert_eq!(lease.settlement_deadline_at, None);
        assert_eq!(lease.settlement_attempts, 0);
        assert_eq!(lease.first_error_at, None);
        assert_eq!(lease.charge_basis, None);
        assert_eq!(lease.delivered, None);
        assert_eq!(lease.updated_at, 10);
        assert_eq!(store.due_openrouter_leases(21).len(), 1);
        assert_eq!(store.clearance_auth(&Felt252::from_u64(42)).unwrap(), None);
        assert!(store.settlement_reviews(10).unwrap().is_empty());
        assert_eq!(store.settlement_counts(0).unwrap().pending, 1);
        drop(store);
        // Reopening is idempotent, and a read-only reader accepts the schema.
        NullifierStore::new(&path).unwrap();
        let reader = NullifierStore::open_read_only(&path).unwrap();
        assert_eq!(
            reader
                .try_lookup_openrouter_lease("legacy")
                .unwrap()
                .unwrap()
                .usage_usd,
            Some(0.5)
        );
    }

    /// The `openrouter_leases` and `nullifiers` tables as written by 045b444
    /// and by f7c99837 (before the pending-deferral column).
    const SCHEMA_045B444: &str = "CREATE TABLE nullifiers (
            nullifier TEXT PRIMARY KEY, status TEXT NOT NULL,
            reservation_kind TEXT NOT NULL DEFAULT 'proxy', client_request_id TEXT,
            payload_hash TEXT, charge_applied INTEGER, response_code INTEGER,
            response_payload TEXT, response_hash TEXT, next_commitment_x TEXT,
            next_commitment_y TEXT, next_anchor TEXT, blind_delta_srv TEXT,
            next_state_sig_epoch INTEGER, next_state_sig_root TEXT, next_state_sig_json TEXT,
            policy_reason_code INTEGER, policy_evidence_hash TEXT, proof_blob BLOB,
            request_inputs_json TEXT, api_request_binding TEXT, created_at INTEGER NOT NULL,
            finalized_at INTEGER
        );
        CREATE TABLE openrouter_leases (
            client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
            api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
            key_source TEXT NOT NULL DEFAULT 'openrouter',
            oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
            status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            settle_after INTEGER NOT NULL, spending_limit_usd REAL NOT NULL, usage_usd REAL,
            charge_applied INTEGER, last_error TEXT, updated_at INTEGER NOT NULL
        );";
    const SCHEMA_F7C99837: &str = "CREATE TABLE nullifiers (
            nullifier TEXT PRIMARY KEY, status TEXT NOT NULL,
            reservation_kind TEXT NOT NULL DEFAULT 'proxy', client_request_id TEXT,
            payload_hash TEXT, charge_applied INTEGER, response_code INTEGER,
            response_payload TEXT, response_hash TEXT, next_commitment_x TEXT,
            next_commitment_y TEXT, next_anchor TEXT, blind_delta_srv TEXT,
            next_state_sig_epoch INTEGER, next_state_sig_root TEXT, next_state_sig_json TEXT,
            policy_reason_code INTEGER, policy_evidence_hash TEXT, proof_blob BLOB,
            request_inputs_json TEXT, api_request_binding TEXT, clearance_auth TEXT,
            created_at INTEGER NOT NULL, finalized_at INTEGER
        );
        CREATE TABLE openrouter_leases (
            client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
            api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
            key_source TEXT NOT NULL DEFAULT 'openrouter',
            oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
            status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            settle_after INTEGER NOT NULL, spending_limit_usd REAL NOT NULL, usage_usd REAL,
            charge_applied INTEGER, last_error TEXT, updated_at INTEGER NOT NULL,
            ttl_seconds INTEGER, settlement_deadline_at INTEGER,
            settlement_attempts INTEGER NOT NULL DEFAULT 0, first_error_at INTEGER,
            charge_basis TEXT, delivered INTEGER
        );
        CREATE TABLE deployment_binding (
            id INTEGER PRIMARY KEY CHECK (id = 1), chain_id INTEGER NOT NULL,
            contract_address TEXT NOT NULL, state_key_x TEXT NOT NULL, state_key_y TEXT NOT NULL,
            clearance_key_x TEXT NOT NULL, clearance_key_y TEXT NOT NULL,
            challenge_period_seconds INTEGER NOT NULL, verified_at INTEGER NOT NULL,
            verified_block INTEGER
        );
        CREATE TABLE settlement_reviews (
            review_id INTEGER PRIMARY KEY, client_request_id TEXT NOT NULL,
            request_nullifier TEXT NOT NULL, key_source TEXT NOT NULL, reason TEXT NOT NULL,
            charge_basis TEXT, detail TEXT NOT NULL, reported_usage_micro_usd TEXT,
            charge_applied INTEGER, solvency_bound TEXT NOT NULL, created_at INTEGER NOT NULL,
            acknowledged_at INTEGER
        );
        CREATE TABLE provider_key_cleanup (
            client_request_id TEXT PRIMARY KEY, key_source TEXT NOT NULL, key_hash TEXT,
            key_name TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL, last_error TEXT, created_at INTEGER NOT NULL
        );
        CREATE INDEX openrouter_leases_status ON openrouter_leases(status, settle_after);
        CREATE INDEX openrouter_leases_deadline ON openrouter_leases(settlement_deadline_at);
        CREATE INDEX settlement_reviews_open ON settlement_reviews(acknowledged_at, created_at);
        CREATE INDEX settlement_reviews_lease ON settlement_reviews(client_request_id);";

    /// The schema `NullifierStore::new` created before the concession exit
    /// (circuit zkapi-v2-note-bound-v1, release ac9be63).
    pub(crate) const SCHEMA_4F21B66: &str = "CREATE TABLE nullifiers (
            nullifier TEXT PRIMARY KEY, status TEXT NOT NULL,
            reservation_kind TEXT NOT NULL DEFAULT 'proxy', client_request_id TEXT,
            payload_hash TEXT, charge_applied INTEGER, response_code INTEGER,
            response_payload TEXT, response_hash TEXT, next_commitment_x TEXT,
            next_commitment_y TEXT, next_anchor TEXT, blind_delta_srv TEXT,
            next_state_sig_epoch INTEGER, next_state_sig_root TEXT, next_state_sig_json TEXT,
            policy_reason_code INTEGER, policy_evidence_hash TEXT, proof_blob BLOB,
            request_inputs_json TEXT, api_request_binding TEXT, clearance_auth TEXT,
            created_at INTEGER NOT NULL, finalized_at INTEGER
        );
        CREATE TABLE openrouter_leases (
            client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL UNIQUE,
            api_request_json TEXT NOT NULL, oa_client_request_id TEXT, key_hash TEXT UNIQUE,
            key_source TEXT NOT NULL DEFAULT 'openrouter',
            oa_provisioning_outcome TEXT NOT NULL DEFAULT 'may_have_issued',
            status TEXT NOT NULL, issued_at INTEGER NOT NULL, expires_at INTEGER NOT NULL,
            settle_after INTEGER NOT NULL, spending_limit_usd REAL NOT NULL, usage_usd REAL,
            charge_applied INTEGER, last_error TEXT, updated_at INTEGER NOT NULL,
            ttl_seconds INTEGER, settlement_deadline_at INTEGER,
            settlement_attempts INTEGER NOT NULL DEFAULT 0, first_error_at INTEGER,
            charge_basis TEXT, delivered INTEGER, next_attempt_at INTEGER,
            key_source_identity TEXT
        );
        CREATE TABLE deployment_binding (
            id INTEGER PRIMARY KEY CHECK (id = 1), chain_id INTEGER NOT NULL,
            contract_address TEXT NOT NULL, state_key_x TEXT NOT NULL, state_key_y TEXT NOT NULL,
            clearance_key_x TEXT NOT NULL, clearance_key_y TEXT NOT NULL,
            challenge_period_seconds INTEGER NOT NULL, verified_at INTEGER NOT NULL,
            verified_block INTEGER
        );
        CREATE TABLE settlement_reviews (
            review_id INTEGER PRIMARY KEY, client_request_id TEXT NOT NULL,
            request_nullifier TEXT NOT NULL, key_source TEXT NOT NULL, reason TEXT NOT NULL,
            charge_basis TEXT, detail TEXT NOT NULL, reported_usage_micro_usd TEXT,
            charge_applied INTEGER, solvency_bound TEXT NOT NULL, created_at INTEGER NOT NULL,
            acknowledged_at INTEGER
        );
        CREATE TABLE provider_key_cleanup (
            client_request_id TEXT PRIMARY KEY, key_source TEXT NOT NULL, key_hash TEXT,
            key_name TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
            next_attempt_at INTEGER NOT NULL, last_error TEXT, created_at INTEGER NOT NULL
        );
        CREATE INDEX openrouter_leases_status ON openrouter_leases(status, settle_after);
        CREATE INDEX openrouter_leases_deadline ON openrouter_leases(settlement_deadline_at);
        CREATE INDEX settlement_reviews_open ON settlement_reviews(acknowledged_at, created_at);
        CREATE INDEX settlement_reviews_lease ON settlement_reviews(client_request_id);";

    /// §11: a database of the pre-change server migrates in place: the
    /// settle/sign columns, the append-only evidence table and its triggers,
    /// and the binding's statement columns appear; its rows stay readable;
    /// its binding reads as bound before circuit identifiers were recorded,
    /// which every daemon of this release refuses; and a reader opens it only
    /// after the migration.
    #[test]
    fn the_pre_change_database_migrates_in_place() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let request = lease_request("legacy-pending", 1);
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(SCHEMA_4F21B66).unwrap();
            conn.execute(
                "INSERT INTO nullifiers (nullifier, status, reservation_kind, client_request_id,
                    payload_hash, created_at)
                 VALUES (?1, 'Reserved', 'openrouter_lease', 'legacy-pending', ?2, 5)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    request.payload_hash.to_hex()
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO openrouter_leases (client_request_id, request_nullifier,
                    api_request_json, key_source, key_hash, status, issued_at, expires_at,
                    settle_after, spending_limit_usd, updated_at)
                 VALUES ('legacy-pending', ?1, ?2, 'oa_org', 'hash', 'active', 10, 20, 21, 6.0, 10)",
                params![
                    request.public_inputs.request_nullifier.to_hex(),
                    serde_json::to_string(&request).unwrap()
                ],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO deployment_binding (id, chain_id, contract_address, state_key_x,
                    state_key_y, clearance_key_x, clearance_key_y, challenge_period_seconds,
                    verified_at)
                 VALUES (1, 1, '0x00000000000000000000000000000000000000aa', '0x1', '0x2', '0x3',
                    '0x4', 86400, 7)",
                [],
            )
            .unwrap();
        }
        let error = NullifierStore::open_read_only(&path).err().unwrap();
        assert!(error.to_string().contains("zkapi db init"), "{error}");
        let store = NullifierStore::new(&path).unwrap();
        let record = store
            .try_lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap()
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.settled_charge, None);
        assert_eq!(record.exit_deferred_since, None);
        assert_eq!(
            store
                .lookup_openrouter_lease("legacy-pending")
                .unwrap()
                .status,
            "active"
        );
        let binding = store.read_deployment_binding().unwrap().unwrap();
        assert_eq!(binding.circuit_id, None);
        assert_eq!(binding.source, BINDING_SOURCE_VAULT);
        let identity = StatementIdentity {
            circuit_id: zkapi_proof::compact::CIRCUIT_ID.into(),
            setup_id: "dev".into(),
            request_vk_keccak256: "0x1".into(),
            withdrawal_vk_keccak256: "0x2".into(),
        };
        assert!(identity
            .mismatch(&binding)
            .unwrap()
            .contains("zkapi-v2-note-bound-v1"));
        // The evidence table works, append-only, after the migration.
        let new = lease_request("new", 2);
        store.reserve_openrouter_lease(&new).unwrap();
        assert_eq!(
            store.request_evidence(&Felt252::from_u64(2)).unwrap().len(),
            1
        );
        assert!(store
            .conn
            .lock()
            .unwrap()
            .execute("DELETE FROM request_evidence", [])
            .is_err());
        drop(store);
        // Idempotent; a reader now opens it.
        NullifierStore::new(&path).unwrap();
        NullifierStore::open_read_only(&path).unwrap();
    }

    #[test]
    fn databases_from_earlier_releases_gain_the_pending_deferral() {
        for (release, schema) in [("045b444", SCHEMA_045B444), ("f7c99837", SCHEMA_F7C99837)] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            {
                let conn = Connection::open(&path).unwrap();
                conn.execute_batch(schema).unwrap();
                let request = lease_request("pending", 1);
                conn.execute(
                    "INSERT INTO openrouter_leases (client_request_id, request_nullifier,
                        api_request_json, key_source, key_hash, status, issued_at, expires_at,
                        settle_after, spending_limit_usd, updated_at)
                     VALUES ('pending', ?1, ?2, 'oa_org', 'hash', 'active', 10, 20, 21, 6.0, 10)",
                    params![
                        request.public_inputs.request_nullifier.to_hex(),
                        serde_json::to_string(&request).unwrap()
                    ],
                )
                .unwrap();
            }
            // A reader refuses the database until it is migrated (by
            // `zkapi db init` or the API server): it lacks the evidence table.
            let error = NullifierStore::open_read_only(&path).err().unwrap();
            assert!(error.to_string().contains("zkapi db init"), "{error}");
            let store = NullifierStore::new(&path).unwrap();
            store.assign_settlement_deadline("pending", 1_000).unwrap();
            assert_eq!(store.due_openrouter_leases(21).len(), 1, "{release}");
            store
                .defer_openrouter_lease_settlement("pending", 500, 21)
                .unwrap();
            let lease = store.lookup_openrouter_lease("pending").unwrap();
            assert_eq!(lease.updated_at, 21, "{release}");
            assert_eq!(lease.settlement_attempts, 0, "{release}");
            assert!(store.due_openrouter_leases(499).is_empty(), "{release}");
            assert_eq!(store.due_openrouter_leases(500).len(), 1, "{release}");
            drop(store);
            // Idempotent, and the deferral survives a restart.
            let store = NullifierStore::new(&path).unwrap();
            assert!(store.due_openrouter_leases(499).is_empty(), "{release}");
            // The deadline makes a deferred lease due whatever the deferral.
            store
                .defer_openrouter_lease_settlement("pending", 5_000, 21)
                .unwrap();
            assert_eq!(store.due_openrouter_leases(1_000).len(), 1, "{release}");
            drop(store);
            NullifierStore::open_read_only(&path).unwrap();
        }
    }

    #[test]
    fn deferral_applies_only_to_leases_awaiting_provider_usage() {
        let store = NullifierStore::in_memory().unwrap();
        store
            .create_openrouter_lease(&lease_request("done", 1), "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store.activate_openrouter_lease("done", "hash").unwrap();
        store.finalize_openrouter_lease("done", 0.0, 0).unwrap();
        let finalized = store.lookup_openrouter_lease("done").unwrap();
        assert_eq!(finalized.status, "finalized");
        store
            .defer_openrouter_lease_settlement("done", 500, finalized.updated_at + 30)
            .unwrap();
        assert_eq!(
            store.lookup_openrouter_lease("done").unwrap().updated_at,
            finalized.updated_at
        );
        assert_eq!(
            store.query_i64_for_test(
                "SELECT COUNT(*) FROM openrouter_leases WHERE next_attempt_at IS NOT NULL",
                []
            ),
            0
        );
        // A failure, or a new retirement phase, ends the deferral of an
        // earlier pending result.
        for (id, nullifier) in [("failed", 2), ("advanced", 3)] {
            store
                .create_openrouter_lease(
                    &lease_request(id, nullifier),
                    "openrouter",
                    10,
                    20,
                    21,
                    1.0,
                )
                .unwrap();
            store.activate_openrouter_lease(id, id).unwrap();
            store
                .defer_openrouter_lease_settlement(id, 500, 30)
                .unwrap();
            assert!(store.due_openrouter_leases(100).is_empty());
        }
        store
            .record_openrouter_lease_error("failed", "503")
            .unwrap();
        store
            .advance_openrouter_retirement("advanced", "active", "retiring", 21, None)
            .unwrap();
        let due: Vec<_> = store
            .due_openrouter_leases(100)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        assert_eq!(due.len(), 2, "{due:?}");
    }

    #[test]
    fn settlement_reviews_keyed_by_lease_migrate_to_a_log() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reviews.sqlite");
        {
            let conn = Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE settlement_reviews (
                    client_request_id TEXT PRIMARY KEY, request_nullifier TEXT NOT NULL,
                    key_source TEXT NOT NULL, reason TEXT NOT NULL, charge_basis TEXT,
                    detail TEXT NOT NULL, reported_usage_micro_usd TEXT, charge_applied INTEGER,
                    solvency_bound TEXT NOT NULL, created_at INTEGER NOT NULL, acknowledged_at INTEGER
                );
                CREATE INDEX settlement_reviews_open ON settlement_reviews(acknowledged_at, created_at);
                INSERT INTO settlement_reviews (client_request_id, request_nullifier, key_source,
                    reason, detail, solvency_bound, created_at, acknowledged_at)
                VALUES ('old', '0x9', 'oa_org', 'binding_corrupt', 'corrupt', '1000', 5, 7);",
            )
            .unwrap();
        }
        let store = NullifierStore::new(&path).unwrap();
        let old = store.settlement_reviews(10).unwrap();
        assert_eq!(old.len(), 1);
        assert_eq!(old[0].review.reason, "binding_corrupt");
        assert_eq!((old[0].created_at, old[0].acknowledged_at), (5, Some(7)));
        // A lease now gets one row per review event.
        store
            .create_openrouter_lease(&lease_request("old", 9), "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store
            .cancel_openrouter_lease("old", &review("old", "binding_corrupt"))
            .unwrap();
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 2);
        assert_eq!(reviews[0].acknowledged_at, None);
        drop(store);
        // Idempotent, and the open-review index exists on the new table.
        let store = NullifierStore::new(&path).unwrap();
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 2);
        assert_eq!(store.settlement_counts(0).unwrap().open_reviews, 1);
        let indexes: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM pragma_index_list('settlement_reviews')
                 WHERE name IN ('settlement_reviews_open', 'settlement_reviews_lease')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(indexes, 2);
    }

    /// Reopen without verifying the saved request: these fixtures carry no
    /// proofs (the processor tests verify real ones).
    fn reopen(
        store: &NullifierStore,
        client_request_id: &str,
        zero_charge: bool,
        now: u64,
    ) -> Result<ReopenedLease, ReopenRefusal> {
        store.reopen_cancelled_lease(
            client_request_id,
            ReopenOptions {
                zero_charge,
                rebind: false,
                saved_request: None,
            },
            &|_| None,
            now,
        )
    }

    /// A lease request whose payload hash matches its payload.
    fn consistent_request(id: &str, nullifier: u64) -> ApiRequestV2 {
        let mut request = lease_request(id, nullifier);
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request
    }

    /// A reserved OA lease (activated with `key_hash`), cancelled for a
    /// corrupt binding as the settler cancels one.
    fn cancelled_lease(
        store: &NullifierStore,
        id: &str,
        nullifier: u64,
        key_hash: Option<&str>,
        delivered: Option<bool>,
    ) -> ApiRequestV2 {
        let request = consistent_request(id, nullifier);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "oa_org",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: Some("bound"),
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(1_000),
                delivered,
            })
            .unwrap();
        if let Some(hash) = key_hash {
            store.activate_openrouter_lease(id, hash).unwrap();
        }
        store
            .cancel_openrouter_lease(id, &review(id, "binding_corrupt"))
            .unwrap();
        request
    }

    /// Review regression (cancelled-lease remediation): reopening refuses,
    /// changing nothing, while the binding is still corrupt (naming the field
    /// to repair) and for a clearance-reserved nullifier; once repaired, the
    /// lease resumes settlement.
    #[test]
    fn reopen_refuses_until_the_cancelled_binding_is_repaired() {
        let store = NullifierStore::in_memory().unwrap();
        assert!(matches!(
            reopen(&store, "missing", false, 500),
            Err(ReopenRefusal::UnknownLease(_))
        ));
        let request = cancelled_lease(&store, "corrupt", 1, Some("hash-1"), Some(true));
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let binding = api_request_binding(&request).unwrap();
        let request_json = serde_json::to_string(&request).unwrap();
        let payload_hash = request.payload_hash.to_hex();
        let set = |sql: &str, value: &str| {
            store
                .conn
                .lock()
                .unwrap()
                .execute(sql, params![value])
                .unwrap()
        };
        for (field, sql, corrupt, repaired) in [
            (
                "nullifiers.payload_hash",
                "UPDATE nullifiers SET payload_hash = ?1",
                "0x1",
                payload_hash.as_str(),
            ),
            (
                "nullifiers.api_request_binding",
                "UPDATE nullifiers SET api_request_binding = ?1",
                "stale",
                binding.as_str(),
            ),
            (
                "nullifiers.client_request_id",
                "UPDATE nullifiers SET client_request_id = ?1",
                "other",
                "corrupt",
            ),
            (
                "nullifiers.reservation_kind",
                "UPDATE nullifiers SET reservation_kind = ?1",
                "proxy",
                "openrouter_lease",
            ),
            (
                "openrouter_leases.api_request_json",
                "UPDATE openrouter_leases SET api_request_json = ?1",
                "not json",
                request_json.as_str(),
            ),
            (
                "nullifiers.nullifier",
                "UPDATE nullifiers SET nullifier = ?1",
                "0x5eed",
                nullifier.as_str(),
            ),
        ] {
            set(sql, corrupt);
            match reopen(&store, "corrupt", false, 500) {
                Err(ReopenRefusal::BindingCorrupt(mismatch)) => {
                    assert_eq!(mismatch.field, field);
                    let message = ReopenRefusal::BindingCorrupt(mismatch).to_string();
                    assert!(message.contains(field), "{message}");
                }
                other => panic!("{field}: expected a binding refusal, got {other:?}"),
            }
            set(sql, repaired);
        }
        // The owner holds a clearance for that state: mutual close is its exit.
        set("UPDATE nullifiers SET status = ?1", "ClearanceReserved");
        let refusal = reopen(&store, "corrupt", true, 500).unwrap_err();
        assert!(matches!(refusal, ReopenRefusal::ClearanceReserved));
        assert!(refusal.to_string().contains("mutual close"), "{refusal}");
        set("UPDATE nullifiers SET status = ?1", "Reserved");
        // Nothing changed while it refused.
        let lease = store.lookup_openrouter_lease("corrupt").unwrap();
        assert_eq!(lease.status, "cancelled");
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 1);

        let reopened = reopen(&store, "corrupt", false, 500).unwrap();
        assert_eq!(
            reopened,
            ReopenedLease {
                client_request_id: "corrupt".into(),
                key_source: "oa_org".into(),
                status: "active".into(),
                delivered: Some(true),
                settlement_deadline_at: Some(1_000),
                settles: "measured_until_deadline",
                key_cleanup_withdrawn: false,
                reservation: "unchanged",
                lease_row: "unchanged",
                saved_request: "unchanged",
                warning: None,
                restored_pending: false,
            }
        );
        let lease = store.lookup_openrouter_lease("corrupt").unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.settlement_deadline_at, Some(1_000));
        assert_eq!((lease.charge_basis, lease.last_error), (None, None));
        // The cancellation's review is handled; the reopening is reviewed.
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 2);
        let by_reason = |reason: &str| {
            reviews
                .iter()
                .find(|stored| stored.review.reason == reason)
                .unwrap()
                .clone()
        };
        assert_eq!(by_reason("binding_corrupt").acknowledged_at, Some(500));
        let reopen_review = by_reason("binding_reopened");
        assert_eq!(reopen_review.acknowledged_at, None);
        assert_eq!(reopen_review.review.charge_basis, None);
        assert!(reopen_review
            .review
            .detail
            .contains("measured_until_deadline"));
        assert!(matches!(
            reopen(&store, "corrupt", false, 600),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
    }

    #[test]
    fn reopen_resumes_settlement_where_the_cancelled_lease_left_it() {
        let store = NullifierStore::in_memory().unwrap();
        // Never activated: provisioning again, committed to its zero
        // settlement, so that no retry can issue its key.
        cancelled_lease(&store, "keyless", 1, None, Some(false));
        let reopened = reopen(&store, "keyless", false, 500).unwrap();
        assert_eq!(reopened.status, "provisioning");
        assert_eq!(reopened.settles, "zero_never_delivered");
        let keyless = store.lookup_openrouter_lease("keyless").unwrap();
        assert_eq!(keyless.charge_basis.as_deref(), Some("unissued"));
        assert_eq!(keyless.settlement_deadline_at, Some(1_000));
        assert!(store
            .activate_openrouter_lease("keyless", "hash-1")
            .is_err());
        // Activated but never returned: active, settling at zero.
        cancelled_lease(&store, "unreturned", 2, Some("hash-2"), Some(false));
        let reopened = reopen(&store, "unreturned", false, 500).unwrap();
        assert_eq!(
            (reopened.status.as_str(), reopened.settles),
            ("active", "zero_never_delivered")
        );
        assert!(store.mark_openrouter_lease_delivered("unreturned").is_err());
        // Both are due at once, whatever their drain time.
        let mut due: Vec<_> = store
            .due_openrouter_leases(0)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        due.sort();
        assert_eq!(due, ["keyless", "unreturned"]);
        // Possibly delivered, past its unchanged deadline: the fallback.
        cancelled_lease(&store, "late", 3, Some("hash-3"), None);
        let reopened = reopen(&store, "late", false, 1_000).unwrap();
        assert_eq!(
            (reopened.status.as_str(), reopened.settles),
            ("active", "deadline_fallback")
        );
        // Conceded: committed to zero, whatever was delivered.
        cancelled_lease(&store, "conceded", 4, Some("hash-4"), Some(true));
        let reopened = reopen(&store, "conceded", true, 500).unwrap();
        assert_eq!(reopened.settles, "operator_conceded");
        let lease = store.lookup_openrouter_lease("conceded").unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.charge_basis.as_deref(), Some("operator_conceded"));
        let reopen_review = store
            .settlement_reviews(100)
            .unwrap()
            .into_iter()
            .find(|stored| {
                stored.review.client_request_id == "conceded"
                    && stored.review.reason == "binding_reopened"
            })
            .unwrap()
            .review;
        assert_eq!(
            reopen_review.charge_basis.as_deref(),
            Some("operator_conceded")
        );
        assert!(store.mark_openrouter_lease_delivered("conceded").is_err());

        // A direct key whose usage was captured resumes revoking, and its
        // queued deletion is withdrawn so that settlement owns the key again.
        let request = consistent_request("revoking", 5);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease("revoking", "hash-5")
            .unwrap();
        for (from, to, usage) in [
            ("active", "retiring", None),
            ("retiring", "disabled", None),
            ("disabled", "revoking", Some(0.25)),
        ] {
            store
                .advance_openrouter_retirement("revoking", from, to, 0, usage)
                .unwrap();
        }
        store
            .cancel_openrouter_lease("revoking", &review("revoking", "binding_corrupt"))
            .unwrap();
        store
            .enqueue_key_cleanup(
                "revoking",
                &KeyCleanup {
                    key_source: "openrouter",
                    key_hash: Some("hash-5"),
                    key_name: "zkapi-revoking",
                },
            )
            .unwrap();
        let reopened = reopen(&store, "revoking", false, 500).unwrap();
        assert_eq!(reopened.status, "revoking");
        assert!(reopened.key_cleanup_withdrawn);
        assert_eq!(
            store.settlement_counts(500).unwrap().pending_key_cleanups,
            0
        );
        assert_eq!(
            store.lookup_openrouter_lease("revoking").unwrap().usage_usd,
            Some(0.25)
        );

        // A successor already signed settles from its transcript; it cannot
        // be conceded.
        let signed = cancelled_lease(&store, "signed", 6, Some("hash-6"), Some(true));
        let mut transcript = finalized(signed.public_inputs.request_nullifier);
        transcript.reservation_kind = "openrouter_lease".into();
        store
            .finalize(&signed.public_inputs.request_nullifier, &transcript)
            .unwrap();
        assert!(matches!(
            reopen(&store, "signed", true, 500),
            Err(ReopenRefusal::AlreadySigned)
        ));
        assert_eq!(
            reopen(&store, "signed", false, 500).unwrap().settles,
            "signed_transcript"
        );

        // Only a cancellation for a corrupt binding is reopened.
        let other = consistent_request("other", 7);
        store.reserve_openrouter_lease(&other).unwrap();
        store
            .create_openrouter_lease(&other, "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store
            .cancel_openrouter_lease("other", &review("other", "usage_clamped"))
            .unwrap();
        assert!(matches!(
            reopen(&store, "other", false, 500),
            Err(ReopenRefusal::NotBindingCorrupt)
        ));
    }

    /// A possibly delivered direct lease with key `hash-<nullifier>`,
    /// cancelled for a corrupt binding with its key cleanup queued, as the
    /// settler cancels one whose usage was never captured.
    fn cancelled_direct_lease(store: &NullifierStore, id: &str, nullifier: u64) -> ApiRequestV2 {
        let request = consistent_request(id, nullifier);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "openrouter",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(1_000),
                delivered: Some(true),
            })
            .unwrap();
        let hash = format!("hash-{nullifier}");
        store.activate_openrouter_lease(id, &hash).unwrap();
        let key_name = format!("zkapi-{id}");
        store
            .cancel_corrupt_openrouter_lease(
                id,
                &review(id, "binding_corrupt"),
                Some(KeyCleanup {
                    key_source: "openrouter",
                    key_hash: Some(&hash),
                    key_name: &key_name,
                }),
            )
            .unwrap();
        request
    }

    /// Review regression (reopening a delivered direct lease): the
    /// cancellation queues its key's deletion in its own transaction, so a
    /// reopening knows whether the key still exists. Deleted before its usage
    /// was captured, it cannot be measured: the reopening reports the
    /// solvency-bound fallback and warns, instead of promising a measurement.
    /// Still queued, its deletion is withdrawn and the key is measured.
    #[test]
    fn reopen_reports_the_bound_for_a_direct_key_deleted_unmeasured() {
        let store = NullifierStore::in_memory().unwrap();
        cancelled_direct_lease(&store, "deleted", 1);
        cancelled_direct_lease(&store, "queued", 2);
        assert_eq!(
            store.settlement_counts(500).unwrap().pending_key_cleanups,
            2
        );
        // The background cleanup deleted the first key.
        store.complete_key_cleanup("deleted").unwrap();
        let reopened = reopen(&store, "deleted", false, 500).unwrap();
        assert_eq!(
            (reopened.status.as_str(), reopened.settles),
            ("active", "deadline_fallback")
        );
        assert!(!reopened.key_cleanup_withdrawn);
        assert!(
            reopened.warning.unwrap().contains("--zero-charge"),
            "{reopened:?}"
        );
        let detail = store
            .settlement_reviews(10)
            .unwrap()
            .into_iter()
            .find(|stored| {
                stored.review.client_request_id == "deleted"
                    && stored.review.reason == "binding_reopened"
            })
            .unwrap()
            .review
            .detail;
        assert!(detail.contains("deadline_fallback"), "{detail}");
        let reopened = reopen(&store, "queued", false, 500).unwrap();
        assert_eq!(
            (reopened.status.as_str(), reopened.settles, reopened.warning),
            ("active", "measured_until_deadline", None)
        );
        assert!(reopened.key_cleanup_withdrawn);
        assert_eq!(
            store.settlement_counts(500).unwrap().pending_key_cleanups,
            0
        );
    }

    /// Review regression (reopen authenticity): once the saved request
    /// verifies, a refusal names the corrupt side and its repair: a
    /// reservation field or a lease column is rebound (--rebind), and an
    /// unreadable request is restored (--saved-request). --rebind never
    /// rewrites a signed reservation, and a concession needs a lease reopened
    /// earlier.
    #[test]
    fn rebind_repairs_only_an_unsigned_reservation() {
        let store = NullifierStore::in_memory().unwrap();
        let rebind = |id: &str| {
            store.reopen_cancelled_lease(
                id,
                ReopenOptions {
                    zero_charge: false,
                    rebind: true,
                    saved_request: None,
                },
                &|_| None,
                500,
            )
        };
        // A reservation field: --rebind suggested, and it repairs it.
        let request = cancelled_lease(&store, "stale", 1, Some("hash-1"), Some(true));
        store.execute_for_test(
            "UPDATE nullifiers SET payload_hash = '0x1', client_request_id = 'other',
                reservation_kind = 'proxy'
             WHERE client_request_id = 'stale'",
            [],
        );
        let refusal = reopen(&store, "stale", false, 500).unwrap_err();
        assert!(refusal.to_string().contains("--rebind"), "{refusal}");
        let reopened = rebind("stale").unwrap();
        assert_eq!(reopened.reservation, "rewritten");
        let record = store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.payload_hash, Some(request.payload_hash));
        assert_eq!(record.client_request_id.as_deref(), Some("stale"));
        assert_eq!(record.reservation_kind, "openrouter_lease");
        // Without a disagreement, --rebind changes nothing.
        cancelled_lease(&store, "intact", 2, Some("hash-2"), Some(true));
        assert_eq!(rebind("intact").unwrap().reservation, "unchanged");
        // A lease column: the lease row is the corrupt side, rebound too.
        let lease_side = cancelled_lease(&store, "lease-side", 3, Some("hash-3"), Some(true));
        store.execute_for_test(
            "UPDATE openrouter_leases SET request_nullifier = '0x77'
             WHERE client_request_id = 'lease-side'",
            [],
        );
        let refusal = reopen(&store, "lease-side", false, 500).unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                if mismatch.field == "openrouter_leases.request_nullifier"),
            "{refusal}"
        );
        assert!(
            refusal
                .to_string()
                .contains("the lease row is the corrupt side")
                && refusal.to_string().contains("--rebind"),
            "{refusal}"
        );
        let reopened = rebind("lease-side").unwrap();
        assert_eq!(
            (reopened.lease_row, reopened.reservation),
            ("rewritten", "unchanged")
        );
        assert_eq!(
            store
                .lookup_openrouter_lease("lease-side")
                .unwrap()
                .request_nullifier,
            lease_side.public_inputs.request_nullifier
        );
        cancelled_lease(&store, "unreadable", 4, Some("hash-4"), Some(true));
        store.execute_for_test(
            "UPDATE openrouter_leases SET api_request_json = 'not json'
             WHERE client_request_id = 'unreadable'",
            [],
        );
        let refusal = rebind("unreadable").unwrap_err();
        assert!(
            refusal.to_string().contains("--saved-request")
                && refusal.to_string().contains("from a backup"),
            "{refusal}"
        );
        // A signed reservation is never rewritten.
        let signed = cancelled_lease(&store, "signed", 5, Some("hash-5"), Some(true));
        let mut transcript = finalized(signed.public_inputs.request_nullifier);
        transcript.reservation_kind = "openrouter_lease".into();
        store
            .finalize(&signed.public_inputs.request_nullifier, &transcript)
            .unwrap();
        store.execute_for_test(
            "UPDATE nullifiers SET client_request_id = 'someone-else'
             WHERE client_request_id = 'signed'",
            [],
        );
        let refusal = rebind("signed").unwrap_err();
        assert!(matches!(refusal, ReopenRefusal::RebindSigned), "{refusal}");
        assert_eq!(
            store.lookup_openrouter_lease("signed").unwrap().status,
            "cancelled"
        );
        // A concession of a pending lease needs a reopening first.
        let pending = consistent_request("never-cancelled", 6);
        store.reserve_openrouter_lease(&pending).unwrap();
        store
            .create_openrouter_lease(&pending, "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease("never-cancelled", "hash-6")
            .unwrap();
        assert!(matches!(
            reopen(&store, "never-cancelled", true, 500),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
        assert_eq!(
            store
                .lookup_openrouter_lease("never-cancelled")
                .unwrap()
                .charge_basis,
            None
        );
    }

    /// Review regression (lease-row repair): a lease row whose
    /// client_request_id, its primary key, was corrupt was cancelled with its
    /// review and queued key cleanup under the faulted id. --rebind rewrites
    /// the row from the verified request in one transaction: its reviews move
    /// with it, and its queued cleanup is withdrawn. It refuses, changing
    /// nothing, while another lease row holds the request's id. A row renamed
    /// by hand still finds its review by its nullifier, and adopts it.
    #[test]
    fn rebind_moves_a_corrupt_lease_id_with_its_reviews() {
        let store = NullifierStore::in_memory().unwrap();
        let rebind = |id: &str| {
            store.reopen_cancelled_lease(
                id,
                ReopenOptions {
                    rebind: true,
                    ..ReopenOptions::default()
                },
                &|_| None,
                500,
            )
        };
        let found = |request: &ApiRequestV2, id: &str| SettlementReview {
            request_nullifier: request.public_inputs.request_nullifier,
            ..review(id, "binding_corrupt")
        };
        // A direct lease whose id was faulted before its cancellation.
        let request = consistent_request("lease-a", 1);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "openrouter",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(1_000),
                delivered: Some(true),
            })
            .unwrap();
        store
            .activate_openrouter_lease("lease-a", "hash-1")
            .unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET client_request_id = 'lease-a-x'
             WHERE client_request_id = 'lease-a'",
            [],
        );
        store
            .cancel_corrupt_openrouter_lease(
                "lease-a-x",
                &found(&request, "lease-a-x"),
                Some(KeyCleanup {
                    key_source: "openrouter",
                    key_hash: Some("hash-1"),
                    key_name: "zkapi-lease-a-x",
                }),
            )
            .unwrap();
        let refusal = reopen(&store, "lease-a-x", false, 500).unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                if mismatch.field == "openrouter_leases.client_request_id"),
            "{refusal}"
        );
        assert!(refusal.to_string().contains("--rebind"), "{refusal}");
        // Another row holding the request's id: neither row is rewritten.
        store
            .create_openrouter_lease(&consistent_request("lease-a", 2), "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        let refusal = rebind("lease-a-x").unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::LeaseElsewhere(other) if other == "lease-a"),
            "{refusal}"
        );
        assert_eq!(
            store.lookup_openrouter_lease("lease-a-x").unwrap().status,
            "cancelled"
        );
        store.remove_failed_openrouter_lease("lease-a").unwrap();
        let reopened = rebind("lease-a-x").unwrap();
        assert_eq!(
            (
                reopened.client_request_id.as_str(),
                reopened.lease_row,
                reopened.status.as_str(),
                reopened.settles
            ),
            ("lease-a", "rewritten", "active", "measured_until_deadline")
        );
        assert!(reopened.key_cleanup_withdrawn);
        assert!(store.lookup_openrouter_lease("lease-a-x").is_none());
        assert_eq!(
            store.settlement_counts(500).unwrap().pending_key_cleanups,
            0
        );
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 2);
        assert!(reviews
            .iter()
            .all(|stored| stored.review.client_request_id == "lease-a"));
        assert!(reviews
            .iter()
            .any(|stored| stored.review.reason == "binding_corrupt"
                && stored.acknowledged_at == Some(500)));
        let reopening = reviews
            .iter()
            .find(|stored| stored.review.reason == "binding_reopened")
            .unwrap();
        assert!(
            reopening
                .review
                .detail
                .contains("its client_request_id was lease-a-x"),
            "{}",
            reopening.review.detail
        );

        // Renamed by hand instead: the review left under the faulted id is
        // found by the row's nullifier, and joins the row.
        let other = consistent_request("lease-b", 3);
        store.reserve_openrouter_lease(&other).unwrap();
        store
            .create_openrouter_lease(&other, "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease("lease-b", "hash-3")
            .unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET client_request_id = 'lease-b-x'
             WHERE client_request_id = 'lease-b'",
            [],
        );
        store
            .cancel_openrouter_lease("lease-b-x", &found(&other, "lease-b-x"))
            .unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET client_request_id = 'lease-b'
             WHERE client_request_id = 'lease-b-x'",
            [],
        );
        let reopened = reopen(&store, "lease-b", false, 500).unwrap();
        assert_eq!(
            (reopened.lease_row, reopened.status.as_str()),
            ("unchanged", "active")
        );
        let reviews: Vec<_> = store
            .settlement_reviews(10)
            .unwrap()
            .into_iter()
            .filter(|stored| {
                stored.review.request_nullifier == other.public_inputs.request_nullifier
            })
            .collect();
        assert_eq!(reviews.len(), 2);
        assert!(reviews.iter().all(|stored| {
            stored.review.client_request_id == "lease-b"
                && (stored.review.reason == "binding_reopened" || stored.acknowledged_at.is_some())
        }));
    }

    /// Review regression (lease-row repair, direct key): a direct lease
    /// cancelled under a faulted client_request_id queued its key's deletion
    /// under that id. Renamed by hand and reopened by its corrected id, it
    /// withdraws that deletion too, so the restarted server measures the key
    /// instead of deleting it. Another lease's queued deletion stays.
    #[test]
    fn hand_renamed_direct_lease_withdraws_its_queued_key_deletion() {
        let store = NullifierStore::in_memory().unwrap();
        let request = consistent_request("lease-a", 1);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "openrouter",
                issued_at: 10,
                expires_at: 20,
                settle_after: 21,
                spending_limit_usd: 1.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(1_000),
                delivered: Some(true),
            })
            .unwrap();
        store
            .activate_openrouter_lease("lease-a", "hash-1")
            .unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET client_request_id = 'lease-a-x'
             WHERE client_request_id = 'lease-a'",
            [],
        );
        store
            .cancel_corrupt_openrouter_lease(
                "lease-a-x",
                &SettlementReview {
                    request_nullifier: request.public_inputs.request_nullifier,
                    ..review("lease-a-x", "binding_corrupt")
                },
                Some(KeyCleanup {
                    key_source: "openrouter",
                    key_hash: Some("hash-1"),
                    key_name: "zkapi-lease-a-x",
                }),
            )
            .unwrap();
        cancelled_direct_lease(&store, "other", 2);
        store.execute_for_test(
            "UPDATE openrouter_leases SET client_request_id = 'lease-a'
             WHERE client_request_id = 'lease-a-x'",
            [],
        );
        let reopened = reopen(&store, "lease-a", false, 500).unwrap();
        assert_eq!(
            (
                reopened.lease_row,
                reopened.status.as_str(),
                reopened.settles,
                reopened.warning
            ),
            ("unchanged", "active", "measured_until_deadline", None)
        );
        assert!(reopened.key_cleanup_withdrawn);
        let queued: Vec<_> = store
            .due_key_cleanups(u64::MAX, 10)
            .unwrap()
            .into_iter()
            .map(|cleanup| cleanup.client_request_id)
            .collect();
        assert_eq!(queued, ["other"]);
        assert!(store
            .settlement_reviews(10)
            .unwrap()
            .iter()
            .filter(
                |stored| stored.review.request_nullifier == request.public_inputs.request_nullifier
            )
            .all(|stored| stored.review.client_request_id == "lease-a"));
    }

    /// Review regression (concession of a reopened lease): a lease reopened
    /// earlier and still pending can be found corrupt again before its
    /// concession. The refusal names --rebind, and --rebind repairs it there
    /// as well, from the same verified request: the lease row, or the
    /// reservation, is rewritten and the lease is conceded. The concession
    /// acknowledges the server's new binding_corrupt review, as a reopening
    /// does.
    #[test]
    fn concession_of_a_reopened_lease_honours_rebind() {
        let store = NullifierStore::in_memory().unwrap();
        let concede = |id: &str, rebind: bool| {
            store.reopen_cancelled_lease(
                id,
                ReopenOptions {
                    zero_charge: true,
                    rebind,
                    saved_request: None,
                },
                &|_| None,
                600,
            )
        };
        let open_corrupt_reviews = |id: &str| {
            store
                .settlement_reviews(20)
                .unwrap()
                .into_iter()
                .filter(|stored| {
                    stored.review.client_request_id == id
                        && stored.review.reason == "binding_corrupt"
                        && stored.acknowledged_at.is_none()
                })
                .count()
        };
        // A lease-row field.
        let row_side = cancelled_lease(&store, "row-side", 1, Some("hash-1"), Some(true));
        reopen(&store, "row-side", false, 500).unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET request_nullifier = '0x77'
             WHERE client_request_id = 'row-side'",
            [],
        );
        // The server finds it corrupt again and reviews it.
        assert!(store
            .review_corrupt_binding(&review("row-side", "binding_corrupt"))
            .unwrap());
        assert_eq!(open_corrupt_reviews("row-side"), 1);
        let refusal = concede("row-side", false).unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                if mismatch.field == "openrouter_leases.request_nullifier"),
            "{refusal}"
        );
        assert!(refusal.to_string().contains("--rebind"), "{refusal}");
        assert_eq!(open_corrupt_reviews("row-side"), 1);
        let conceded = concede("row-side", true).unwrap();
        assert_eq!(
            (
                conceded.lease_row,
                conceded.status.as_str(),
                conceded.settles
            ),
            ("rewritten", "active", "operator_conceded")
        );
        let lease = store.lookup_openrouter_lease("row-side").unwrap();
        assert_eq!(
            lease.request_nullifier,
            row_side.public_inputs.request_nullifier
        );
        assert_eq!(lease.charge_basis.as_deref(), Some("operator_conceded"));
        assert_eq!(open_corrupt_reviews("row-side"), 0);
        // A reservation field.
        cancelled_lease(&store, "reservation-side", 2, Some("hash-2"), Some(true));
        reopen(&store, "reservation-side", false, 500).unwrap();
        store.execute_for_test(
            "UPDATE nullifiers SET api_request_binding = 'stale'
             WHERE client_request_id = 'reservation-side'",
            [],
        );
        assert!(matches!(
            concede("reservation-side", false),
            Err(ReopenRefusal::BindingCorrupt(mismatch))
                if mismatch.field == "nullifiers.api_request_binding"
        ));
        let conceded = concede("reservation-side", true).unwrap();
        assert_eq!(
            (conceded.reservation, conceded.settles),
            ("rewritten", "operator_conceded")
        );
        // Without --zero-charge, a pending lease is still not reopened.
        assert!(matches!(
            store.reopen_cancelled_lease(
                "reservation-side",
                ReopenOptions {
                    rebind: true,
                    ..ReopenOptions::default()
                },
                &|_| None,
                700,
            ),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
    }

    /// Review regression (corrupt saved request): --saved-request restores a
    /// corrupt or unreadable saved request only from a copy that verifies,
    /// whose binding is its reservation's, and that shares the lease row's id
    /// or nullifier. Another request its owner authorized for the same note
    /// state, another lease's request, a clearance-reserved nullifier and a
    /// missing reservation are refused, changing nothing.
    #[test]
    fn saved_request_is_restored_only_from_the_reserved_request() {
        let store = NullifierStore::in_memory().unwrap();
        let request = cancelled_lease(&store, "bitrot", 1, Some("hash-1"), Some(true));
        let other_lease = cancelled_lease(&store, "other", 2, Some("hash-2"), Some(true));
        let mut same_state = request.clone();
        same_state.public_inputs.request_time += 1;
        let mut faulted = request.clone();
        faulted.public_inputs.request_time += 7;
        // Proof verification as these fixtures allow it: only requests their
        // owners authorized verify.
        let authorized: Vec<String> = [&request, &same_state, &other_lease]
            .into_iter()
            .map(|authorized| api_request_binding(authorized).unwrap())
            .collect();
        let verify = |candidate: &ApiRequestV2| {
            (!authorized.contains(&api_request_binding(candidate).unwrap())).then_some(
                BindingMismatch {
                    field: SAVED_REQUEST_FIELD,
                    detail: GROTH16_UNVERIFIED,
                },
            )
        };
        let restore = |saved: &ApiRequestV2| {
            store.reopen_cancelled_lease(
                "bitrot",
                ReopenOptions {
                    saved_request: Some(saved),
                    ..ReopenOptions::default()
                },
                &verify,
                500,
            )
        };
        let set = |sql: &str| store.execute_for_test(sql, []);
        let faulted_json = serde_json::to_string(&faulted).unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET api_request_json = ?1 WHERE client_request_id = 'bitrot'",
            params![faulted_json],
        );
        let refusal = store
            .reopen_cancelled_lease("bitrot", ReopenOptions::default(), &verify, 500)
            .unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                if mismatch.field == SAVED_REQUEST_FIELD),
            "{refusal}"
        );
        assert!(refusal.to_string().contains("--saved-request"), "{refusal}");
        assert!(matches!(
            restore(&faulted),
            Err(ReopenRefusal::SuppliedRequestUnverified(detail)) if detail == GROTH16_UNVERIFIED
        ));
        assert!(matches!(
            restore(&same_state),
            Err(ReopenRefusal::SuppliedRequestNotReserved(detail))
                if detail.contains("api_request_binding")
        ));
        assert!(matches!(
            restore(&other_lease),
            Err(ReopenRefusal::SuppliedRequestForAnotherLease)
        ));
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        set(&format!(
            "UPDATE nullifiers SET status = 'ClearanceReserved' WHERE nullifier = '{nullifier}'"
        ));
        assert!(matches!(
            restore(&request),
            Err(ReopenRefusal::ClearanceReserved)
        ));
        set(&format!(
            "UPDATE nullifiers SET status = 'Reserved', nullifier = '0x5eed'
             WHERE nullifier = '{nullifier}'"
        ));
        assert!(matches!(
            restore(&request),
            Err(ReopenRefusal::SuppliedRequestNotReserved(detail))
                if detail.contains("no nullifiers row")
        ));
        set(&format!(
            "UPDATE nullifiers SET nullifier = '{nullifier}' WHERE nullifier = '0x5eed'"
        ));
        // Nothing changed while it refused.
        let lease = store.lookup_openrouter_lease("bitrot").unwrap();
        assert_eq!(lease.status, "cancelled");
        assert_eq!(
            serde_json::to_string(&lease.api_request).unwrap(),
            faulted_json
        );
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 2);
        // The reserved request restores it, also over an unreadable one.
        set("UPDATE openrouter_leases SET api_request_json = 'not json'
             WHERE client_request_id = 'bitrot'");
        let reopened = restore(&request).unwrap();
        assert_eq!(
            (reopened.saved_request, reopened.status.as_str()),
            ("restored", "active")
        );
        assert_eq!(
            api_request_binding(&store.lookup_openrouter_lease("bitrot").unwrap().api_request)
                .unwrap(),
            api_request_binding(&request).unwrap()
        );
        let reopening = store
            .settlement_reviews(10)
            .unwrap()
            .into_iter()
            .find(|stored| stored.review.reason == "binding_reopened")
            .unwrap();
        assert!(
            reopening
                .review
                .detail
                .contains("saved request was restored"),
            "{}",
            reopening.review.detail
        );
        // A copy of an intact saved request changes nothing: the
        // reservation's stale binding is then named, for --rebind.
        store.execute_for_test(
            "UPDATE nullifiers SET api_request_binding = 'stale' WHERE client_request_id = 'other'",
            [],
        );
        let supplied = |rebind: bool| {
            store.reopen_cancelled_lease(
                "other",
                ReopenOptions {
                    rebind,
                    saved_request: Some(&other_lease),
                    ..ReopenOptions::default()
                },
                &verify,
                500,
            )
        };
        assert!(matches!(
            supplied(false),
            Err(ReopenRefusal::BindingCorrupt(mismatch))
                if mismatch.field == "nullifiers.api_request_binding"
        ));
        let reopened = supplied(true).unwrap();
        assert_eq!(
            (reopened.saved_request, reopened.reservation),
            ("unchanged", "rewritten")
        );
    }

    /// Final review, round 2: a pending lease whose saved request cannot be
    /// decoded is skipped by every settlement scan, so its deadline never
    /// applies, and the reopen command refused it (not cancelled), leaving
    /// its nullifier reserved for good. --saved-request now restores that
    /// request after the same checks, keeping the lease's status and
    /// deadline, so that the scan settles it again; the repair is reviewed,
    /// and its charge can be conceded (in the same run or a later one).
    #[test]
    fn saved_request_restores_an_unreadable_pending_lease() {
        let store = NullifierStore::in_memory().unwrap();
        let pending_lease = |id: &str, nullifier: u64| {
            let request = consistent_request(id, nullifier);
            store.reserve_openrouter_lease(&request).unwrap();
            store
                .create_openrouter_lease_bound(&NewOpenRouterLease {
                    request: &request,
                    key_source: "oa_org",
                    issued_at: 10,
                    expires_at: 20,
                    settle_after: 21,
                    spending_limit_usd: 1.0,
                    oa_client_request_id: Some("bound"),
                    ttl_seconds: Some(300),
                    settlement_deadline_at: Some(1_000),
                    delivered: Some(true),
                })
                .unwrap();
            store
                .activate_openrouter_lease(id, &format!("hash-{nullifier}"))
                .unwrap();
            store.execute_for_test(
                "UPDATE openrouter_leases SET api_request_json = '{\"client_request_id\":\"ro'
                 WHERE client_request_id = ?1",
                params![id],
            );
            request
        };
        let request = pending_lease("rotten", 1);
        let late = pending_lease("late", 2);
        let conceded_now = pending_lease("conceded-now", 3);
        let mut forged = request.clone();
        forged.public_inputs.request_time += 1;
        let authorized: Vec<String> = [&request, &late, &conceded_now]
            .into_iter()
            .map(|authorized| api_request_binding(authorized).unwrap())
            .collect();
        let verify = |candidate: &ApiRequestV2| {
            (!authorized.contains(&api_request_binding(candidate).unwrap())).then_some(
                BindingMismatch {
                    field: SAVED_REQUEST_FIELD,
                    detail: GROTH16_UNVERIFIED,
                },
            )
        };
        let run = |id: &str, saved: Option<&ApiRequestV2>, zero_charge: bool, now: u64| {
            store.reopen_cancelled_lease(
                id,
                ReopenOptions {
                    zero_charge,
                    rebind: false,
                    saved_request: saved,
                },
                &verify,
                now,
            )
        };
        // The scan cannot read any of them, not even past their deadline.
        assert!(store.due_openrouter_leases(500).is_empty());
        assert!(store.due_openrouter_leases(1_500).is_empty());
        assert!(matches!(
            run("rotten", None, false, 500),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
        assert!(matches!(
            run("rotten", Some(&forged), false, 500),
            Err(ReopenRefusal::SuppliedRequestUnverified(detail)) if detail == GROTH16_UNVERIFIED
        ));
        assert!(matches!(
            run("rotten", Some(&late), false, 500),
            Err(ReopenRefusal::SuppliedRequestForAnotherLease)
        ));
        // Nothing changed while it refused.
        assert!(matches!(
            store.try_lookup_openrouter_lease("rotten"),
            Err(ServerError::LeaseRecordUnreadable)
        ));
        assert!(store.settlement_reviews(10).unwrap().is_empty());

        let restored = run("rotten", Some(&request), false, 500).unwrap();
        assert_eq!(
            restored,
            ReopenedLease {
                client_request_id: "rotten".into(),
                key_source: "oa_org".into(),
                status: "active".into(),
                delivered: Some(true),
                settlement_deadline_at: Some(1_000),
                settles: "measured_until_deadline",
                key_cleanup_withdrawn: false,
                reservation: "unchanged",
                lease_row: "unchanged",
                saved_request: "restored",
                warning: None,
                restored_pending: true,
            }
        );
        let lease = store.lookup_openrouter_lease("rotten").unwrap();
        assert_eq!(
            api_request_binding(&lease.api_request).unwrap(),
            api_request_binding(&request).unwrap()
        );
        assert_eq!(
            (
                lease.status.as_str(),
                lease.charge_basis,
                lease.settlement_deadline_at
            ),
            ("active", None, Some(1_000))
        );
        let due: Vec<String> = store
            .due_openrouter_leases(500)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        assert_eq!(due, ["rotten"]);
        // Reviewed, and the server verifies the restored request again.
        assert!(store.lease_reopened("rotten").unwrap());
        let reviews = store.settlement_reviews(10).unwrap();
        assert_eq!(reviews.len(), 1);
        assert_eq!(reviews[0].review.reason, "binding_reopened");
        assert_eq!(reviews[0].review.charge_basis, None);
        assert!(
            reviews[0].review.detail.contains("kept active")
                && reviews[0]
                    .review
                    .detail
                    .contains("saved request was restored"),
            "{}",
            reviews[0].review.detail
        );
        // A readable pending lease is still not reopened.
        assert!(matches!(
            run("rotten", Some(&request), false, 600),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));

        // Past its deadline, restored, it is charged its solvency bound at
        // once: the output warns, and a later run concedes its charge.
        let restored = run("late", Some(&late), false, 1_500).unwrap();
        assert_eq!(
            (restored.settles, restored.warning),
            ("deadline_fallback", Some(DEADLINE_FALLBACK_WARNING))
        );
        let conceded = run("late", None, true, 1_500).unwrap();
        assert_eq!(
            (
                conceded.status.as_str(),
                conceded.settles,
                conceded.restored_pending
            ),
            ("active", "operator_conceded", false)
        );
        // Or both in one run.
        let conceded = run("conceded-now", Some(&conceded_now), true, 1_500).unwrap();
        assert_eq!(
            (
                conceded.saved_request,
                conceded.settles,
                conceded.restored_pending
            ),
            ("restored", "operator_conceded", true)
        );
        for id in ["late", "conceded-now"] {
            let lease = store.lookup_openrouter_lease(id).unwrap();
            assert_eq!(
                (lease.status.as_str(), lease.charge_basis.as_deref()),
                ("active", Some("operator_conceded"))
            );
        }
        let due: Vec<String> = store
            .due_openrouter_leases(1_500)
            .into_iter()
            .map(|lease| lease.client_request_id)
            .collect();
        assert_eq!(due.len(), 3, "{due:?}");
    }

    /// Final round (server-fixup2#4): a pending row whose saved request can
    /// be read, but whose other column cannot be decoded, is skipped by every
    /// scan just the same. The reopen command names that column instead of
    /// saying the server settles the lease itself, with or without
    /// --saved-request, and changes nothing.
    #[test]
    fn reopen_names_another_undecodable_column_of_a_pending_lease() {
        let store = NullifierStore::in_memory().unwrap();
        let request = consistent_request("garbled", 1);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 10, 20, 21, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease("garbled", "hash-1")
            .unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET expires_at = 'soon', settlement_deadline_at = 1000
             WHERE client_request_id = ?1",
            params!["garbled"],
        );
        assert!(store.due_openrouter_leases(1_500).is_empty());
        let verify = |_: &ApiRequestV2| None;
        for saved_request in [None, Some(&request)] {
            let refusal = store
                .reopen_cancelled_lease(
                    "garbled",
                    ReopenOptions {
                        zero_charge: false,
                        rebind: false,
                        saved_request,
                    },
                    &verify,
                    500,
                )
                .unwrap_err();
            assert!(
                matches!(
                    &refusal,
                    ReopenRefusal::RowUndecodable { status, detail }
                        if status == "active" && detail.contains("expires_at")
                ),
                "{refusal}"
            );
            let message = refusal.to_string();
            assert!(
                message.contains("repaired by hand from a backup")
                    && message.contains("--saved-request cannot repair it"),
                "{message}"
            );
        }
        assert!(matches!(
            store.try_lookup_openrouter_lease("garbled"),
            Err(ServerError::LeaseRecordUnreadable)
        ));
        assert!(store.settlement_reviews(10).unwrap().is_empty());
        // Repaired by hand, the lease is readable, and the command again
        // leaves it to the server.
        store.execute_for_test(
            "UPDATE openrouter_leases SET expires_at = 20 WHERE client_request_id = ?1",
            params!["garbled"],
        );
        assert!(matches!(
            store.reopen_cancelled_lease(
                "garbled",
                ReopenOptions {
                    zero_charge: false,
                    rebind: false,
                    saved_request: None,
                },
                &verify,
                500,
            ),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
    }

    /// Review regression (usage capture of a corrupt direct lease): a corrupt
    /// binding found while its key's usage is still being captured is
    /// reviewed once, however often the capture is retried, and again after
    /// a reopening. The lease cannot be reopened, nor conceded, until it is
    /// cancelled; its cancellation records its own review.
    #[test]
    fn corrupt_binding_is_reviewed_once_while_its_capture_is_retried() {
        let store = NullifierStore::in_memory().unwrap();
        let request = consistent_request("capturing", 1);
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "openrouter", 10, 20, 21, 1.0)
            .unwrap();
        store
            .activate_openrouter_lease("capturing", "hash-1")
            .unwrap();
        store
            .advance_openrouter_retirement("capturing", "active", "retiring", 0, None)
            .unwrap();
        let found = review("capturing", "binding_corrupt");
        assert!(store.review_corrupt_binding(&found).unwrap());
        assert!(!store.review_corrupt_binding(&found).unwrap());
        for zero_charge in [false, true] {
            assert!(matches!(
                reopen(&store, "capturing", zero_charge, 500),
                Err(ReopenRefusal::CapturePending(status)) if status == "retiring"
            ));
        }
        store.cancel_openrouter_lease("capturing", &found).unwrap();
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 2);
        assert_eq!(
            reopen(&store, "capturing", false, 500).unwrap().status,
            "active"
        );
        // Found corrupt again after the reopening: reviewed again.
        assert!(store.review_corrupt_binding(&found).unwrap());
        assert!(!store.review_corrupt_binding(&found).unwrap());
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 4);
    }
}
