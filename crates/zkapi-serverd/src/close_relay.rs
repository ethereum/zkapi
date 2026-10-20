//! The operator's close relay: cooperative closes submitted through the
//! permissionless `ZkApiExitBatcher` (`mutualCloseBatch`), paid for by one
//! metered request.
//!
//! # Fee
//!
//! A client that wants its close relayed first makes one fee request
//! (`POST /v2/withdraw/relay/fee`) at its current state `k`: an ordinary
//! request proof whose payload ([`CloseRelayFeeAuthorization`]) names the fee
//! and the hash of a fresh ticket secret. The server admits it like any
//! request (fresh root, keys, time, authorization tag, Groth16 proof), with
//! solvency bound at least the fee, and settles it at once at exactly the fee
//! (`settled_basis = 'relay_fee'`): reservation, evidence, charge and ticket
//! in one transaction. The successor `k+1` is then signed (O7, only while
//! `N_k` is unspent) with the fee deducted. The client asks for clearance at
//! `N_{k+1}` and proves its close there, so `deposit - finalBalance`, the
//! treasury share of the close, already contains the fee: no circuit change.
//!
//! The operator is safe because the fee request is an ordinary metered
//! request: its evidence is in `request_evidence` and its charge is final
//! before anything is signed, so the challenger enforces it like every
//! other (an escape from state `k` is raised by the fee, one from an earlier
//! state defeated with the request at its successor). The user is safe
//! because the payout is bound by the close's proof (destination and final
//! balance): the relay can submit the close or not, never redirect it, and
//! the batcher holds no ETH. A close the relay does not land in time is
//! submitted by the client itself; it keeps its proof.
//!
//! # Submission
//!
//! `POST /v2/withdraw/relay` takes the kind-1 statement and proof exactly as
//! `mutualClose` does, and the ticket secret. It is checked cheaply first
//! (this deployment, kind 1, no successor or concession, a destination,
//! `valid_until` at least [`CloseRelayConfig::min_validity_seconds`] ahead),
//! then the proof is verified off chain and the nullifier read unused on
//! chain; the server must hold the clearance it signed at that nullifier and
//! the ticket must be paid and unredeemed. The close is queued and the ticket
//! redeemed in one transaction (the fee row is then keyed by `N_{k+1}`). The
//! same close submitted again returns its status; another close at the same
//! nullifier is refused.
//!
//! # Batches
//!
//! [`RelayWorker::tick`] flushes the queue through the batcher once
//! [`CloseRelayConfig::batch_target`] closes are queued, once the oldest has
//! waited [`CloseRelayConfig::flush_age_seconds`], or at once when one comes
//! within [`CloseRelayConfig::urgent_margin_seconds`] of its `valid_until`.
//! It `eth_call`s the exact batch first and bisects a batch that reverts
//! (all proofs are verified up front, so one bad proof reverts the whole
//! batch); a lone close goes to `vault.mutualClose` directly, which is
//! cheaper than a batch of one. The gas limit is `batcher.gasBound(kinds)`
//! plus the intrinsic and calldata gas, never below `eth_estimateGas`.
//!
//! A close the batch would skip is classified from the vault's refusal: a
//! note already closed (the client submitted it itself, or someone did) is
//! done (`closed`); a payout push that failed or burned its gas cap
//! (`NativeTransferFailed`, an empty revert) is `failed` and never relayed
//! again; a paused vault leaves it queued. One transaction is in flight at a
//! time, on one nonce, with its calldata, nonce and every hash persisted
//! before and after each send, so a restart resumes it: its receipt decides
//! (`MutualClose` and `ItemSkipped` logs, after
//! [`CloseRelayConfig::confirmations`] blocks); a nonce consumed by a
//! transaction whose receipt is gone is resolved from each note's on-chain
//! status, never by sending again; a nonce never used releases the closes
//! back to the queue. A stuck transaction is replaced at the same nonce with
//! fees raised by 25%, within [`CloseRelayConfig::max_fee_per_gas`].
//!
//! The relayer is a dedicated account behind an operator-controlled signing
//! RPC (`eth_sendTransaction`), as for the challenger; this module never
//! holds a key.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{ensure, Context};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_types::wire::CloseRelayTermsResponse;
pub use zkapi_types::wire::{CloseRelayFeeAuthorization, CloseRelayStatusResponse};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2C};

use crate::error::ServerError;
use crate::nullifier_store::{
    CloseRelayRecord, CloseRelayStatus, NewRelayBatch, NullifierStore, RelayBatchRecord,
    RelayItemOutcome,
};

/// `ZkApiExitBatcher.MAX_ITEMS()`.
pub const MAX_BATCH_ITEMS: usize = 64;
/// The batcher's kind of a cooperative close.
pub const KIND_CLOSE: u8 = 0;

pub const MUTUAL_CLOSE_BATCH_SIGNATURE: &str = "mutualCloseBatch((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)[],bytes)";
pub const GAS_BOUND_SIGNATURE: &str = "gasBound(uint8[])";
pub const BATCHER_VAULT_SIGNATURE: &str = "vault()";
pub const BATCHER_ADAPTER_SIGNATURE: &str = "adapter()";
pub const BATCHER_MAX_ITEMS_SIGNATURE: &str = "MAX_ITEMS()";
pub const NOTES_SIGNATURE: &str = "notes(uint32)";
pub const ITEM_SKIPPED_EVENT: &str = "ItemSkipped(uint256,uint8,uint32,bytes)";
pub const MUTUAL_CLOSE_EVENT: &str = "MutualClose(uint32,uint256,uint128,address)";
/// `Types.NoteStatus.Closed`.
pub const NOTE_STATUS_CLOSED: u64 = 3;

/// Defaults of the relay's flags (`zkapi serverd --relay-*`).
pub const DEFAULT_BATCH_TARGET: usize = 16;
pub const DEFAULT_MAX_BATCH: usize = 32;
pub const DEFAULT_FLUSH_AGE_SECONDS: u64 = 900;
pub const DEFAULT_URGENT_MARGIN_SECONDS: u64 = 1_800;
pub const DEFAULT_CUTOFF_SECONDS: u64 = 300;
pub const DEFAULT_MIN_VALIDITY_SECONDS: u64 = 3_600;
pub const DEFAULT_POLL_SECONDS: u64 = 5;
pub const DEFAULT_CONFIRMATIONS: u64 = 2;
pub const DEFAULT_BUMP_AFTER_SECONDS: u64 = 120;
pub const DEFAULT_MAX_GAS: u64 = 12_000_000;
pub const DEFAULT_MAX_ATTEMPTS: u32 = 3;
pub const DEFAULT_PRIORITY_FEE_PER_GAS: u128 = 1_000_000_000;
/// Gas limit of a single `mutualClose` above its estimate: 20%.
const SINGLE_GAS_HEADROOM_PERCENT: u64 = 20;
/// How long a consumed nonce waits for the receipt of a hash the relay sent
/// before the batch is resolved from the notes' on-chain status instead.
const LOST_RECEIPT_GRACE_SECONDS: u64 = 300;
/// How long a batch whose nonce the node does not hold waits before its
/// closes return to the queue (a send the node never accepted, or a
/// transaction dropped from its pool).
const DROPPED_GRACE_SECONDS: u64 = 60;
/// Queued closes one flush considers.
const QUEUE_SCAN: usize = 1_000;
const RPC_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_DETAIL_CHARS: usize = 300;

/// The relay's configuration (`zkapi serverd --relay-*`). The relay is off
/// unless this is configured.
#[derive(Clone)]
pub struct CloseRelayConfig {
    /// The fee of one relayed close, in the vault's native units (gwei).
    pub fee_units: u128,
    /// The `ZkApiExitBatcher` bound to this server's vault.
    pub batcher_address: String,
    /// The relayer's signing RPC: `eth_sendTransaction` for `sender` (the
    /// signer sidecar in its close-relay role, or a node holding the key),
    /// and the sender's nonce. It may embed a key: never logged.
    pub rpc_url: String,
    /// The RPC of every other read: `eth_call` simulations (whose revert data
    /// a signer sidecar does not pass on), estimates, blocks and receipts.
    /// None: run_server uses the native billing RPC; a library embedding
    /// without it reads through `rpc_url`.
    pub read_rpc_url: Option<String>,
    /// The dedicated relayer account.
    pub sender: String,
    pub batch_target: usize,
    pub max_batch: usize,
    pub flush_age_seconds: u64,
    pub urgent_margin_seconds: u64,
    pub cutoff_seconds: u64,
    pub min_validity_seconds: u64,
    pub poll_seconds: u64,
    pub confirmations: u64,
    pub bump_after_seconds: u64,
    /// The highest `maxFeePerGas` the relay pays (wei). It is also the gas
    /// price the fee is priced against (docs/native-eth-billing.md).
    pub max_fee_per_gas: u128,
    pub priority_fee_per_gas: u128,
    /// The highest gas limit of one relay transaction.
    pub max_gas: u64,
    /// Whole-batch reverts a close may take part in before it fails.
    pub max_attempts: u32,
}

impl std::fmt::Debug for CloseRelayConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CloseRelayConfig")
            .field("fee_units", &self.fee_units)
            .field("batcher_address", &self.batcher_address)
            .field("rpc_url", &"[redacted]")
            .field(
                "read_rpc_url",
                &self.read_rpc_url.as_ref().map(|_| "[redacted]"),
            )
            .field("sender", &self.sender)
            .field("batch_target", &self.batch_target)
            .field("max_batch", &self.max_batch)
            .field("flush_age_seconds", &self.flush_age_seconds)
            .field("urgent_margin_seconds", &self.urgent_margin_seconds)
            .field("cutoff_seconds", &self.cutoff_seconds)
            .field("min_validity_seconds", &self.min_validity_seconds)
            .field("poll_seconds", &self.poll_seconds)
            .field("confirmations", &self.confirmations)
            .field("bump_after_seconds", &self.bump_after_seconds)
            .field("max_fee_per_gas", &self.max_fee_per_gas)
            .field("priority_fee_per_gas", &self.priority_fee_per_gas)
            .field("max_gas", &self.max_gas)
            .field("max_attempts", &self.max_attempts)
            .finish()
    }
}

impl CloseRelayConfig {
    /// A configuration with the default policy.
    pub fn new(
        fee_units: u128,
        batcher_address: String,
        rpc_url: String,
        sender: String,
        max_fee_per_gas: u128,
    ) -> Self {
        Self {
            fee_units,
            batcher_address,
            rpc_url,
            read_rpc_url: None,
            sender,
            batch_target: DEFAULT_BATCH_TARGET,
            max_batch: DEFAULT_MAX_BATCH,
            flush_age_seconds: DEFAULT_FLUSH_AGE_SECONDS,
            urgent_margin_seconds: DEFAULT_URGENT_MARGIN_SECONDS,
            cutoff_seconds: DEFAULT_CUTOFF_SECONDS,
            min_validity_seconds: DEFAULT_MIN_VALIDITY_SECONDS,
            poll_seconds: DEFAULT_POLL_SECONDS,
            confirmations: DEFAULT_CONFIRMATIONS,
            bump_after_seconds: DEFAULT_BUMP_AFTER_SECONDS,
            max_fee_per_gas,
            priority_fee_per_gas: DEFAULT_PRIORITY_FEE_PER_GAS,
            max_gas: DEFAULT_MAX_GAS,
            max_attempts: DEFAULT_MAX_ATTEMPTS,
        }
    }

    /// Refuse an inconsistent policy before anything starts. Addresses are
    /// normalized to lowercase.
    pub fn validate(&mut self) -> anyhow::Result<()> {
        // Empty until run_server takes it from the deployment manifest.
        if !self.batcher_address.is_empty() {
            self.batcher_address = address(&self.batcher_address).context("--relay-batcher")?;
        }
        self.sender = address(&self.sender).context("--relay-sender")?;
        ensure!(!self.rpc_url.is_empty(), "--relay-rpc-url is required");
        ensure!(
            self.fee_units > 0 && self.fee_units <= crate::native_billing::MAX_SAFE_UNITS,
            "--relay-fee-units must be positive and browser-safe"
        );
        ensure!(
            (1..=MAX_BATCH_ITEMS).contains(&self.max_batch),
            "--relay-max-batch must be between 1 and {MAX_BATCH_ITEMS}"
        );
        ensure!(
            (1..=self.max_batch).contains(&self.batch_target),
            "--relay-batch-target must be between 1 and --relay-max-batch"
        );
        ensure!(
            self.flush_age_seconds > 0,
            "--relay-flush-age-seconds must be positive"
        );
        ensure!(
            self.cutoff_seconds > 0 && self.cutoff_seconds < self.urgent_margin_seconds,
            "--relay-cutoff-seconds must be positive and below --relay-urgent-margin-seconds"
        );
        // A close accepted at the minimum validity is flushed urgently at
        // once at the latest and still has the urgent margin to land.
        ensure!(
            self.urgent_margin_seconds < self.min_validity_seconds,
            "--relay-urgent-margin-seconds must be below --relay-min-validity-seconds"
        );
        ensure!(
            self.poll_seconds > 0 && self.poll_seconds < self.cutoff_seconds,
            "--relay-poll-seconds must be positive and below --relay-cutoff-seconds"
        );
        ensure!(
            self.confirmations >= 1,
            "--relay-confirmations must be at least 1"
        );
        ensure!(
            self.bump_after_seconds >= self.poll_seconds,
            "--relay-bump-after-seconds must be at least --relay-poll-seconds"
        );
        ensure!(
            self.priority_fee_per_gas > 0 && self.priority_fee_per_gas <= self.max_fee_per_gas,
            "--relay-priority-fee-per-gas must be positive and at most --relay-max-fee-per-gas"
        );
        ensure!(
            self.max_fee_per_gas <= u128::MAX / u128::from(u64::MAX),
            "--relay-max-fee-per-gas is implausibly large"
        );
        ensure!(
            self.max_gas >= 500_000,
            "--relay-max-gas must allow at least one close"
        );
        ensure!(
            self.max_attempts >= 1,
            "--relay-max-attempts must be at least 1"
        );
        Ok(())
    }

    /// The public terms (`GET /v2/withdraw/relay/terms`).
    pub fn terms(&self) -> CloseRelayTermsResponse {
        CloseRelayTermsResponse {
            enabled: true,
            fee_units: Some(self.fee_units.to_string()),
            min_validity_seconds: Some(self.min_validity_seconds),
            batch_target: Some(self.batch_target as u64),
            flush_age_seconds: Some(self.flush_age_seconds),
            urgent_margin_seconds: Some(self.urgent_margin_seconds),
            cutoff_seconds: Some(self.cutoff_seconds),
            exit_batcher: Some(self.batcher_address.clone()),
        }
    }
}

/// The terms of a server without a relay.
pub fn disabled_terms() -> CloseRelayTermsResponse {
    CloseRelayTermsResponse {
        enabled: false,
        fee_units: None,
        min_validity_seconds: None,
        batch_target: None,
        flush_age_seconds: None,
        urgent_margin_seconds: None,
        cutoff_seconds: None,
        exit_batcher: None,
    }
}

pub(crate) fn relay_refusal(code: &'static str, message: impl Into<String>) -> ServerError {
    ServerError::CloseRelay {
        code,
        message: message.into(),
    }
}

/// 0x and 40 lowercase hex digits, nonzero.
fn address(value: &str) -> anyhow::Result<String> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .context("an address is 0x-prefixed")?;
    ensure!(
        body.len() == 40 && body.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "an address is 20 hex bytes"
    );
    ensure!(
        body.bytes().any(|byte| byte != b'0'),
        "the zero address is not allowed"
    );
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

/// The 32-byte ticket secret of a submission (`0x` and 64 hex digits).
pub fn parse_ticket_secret(value: &str) -> Result<[u8; 32], ServerError> {
    let invalid = || {
        relay_refusal(
            "relay_ticket_invalid",
            "ticket_secret must be 0x followed by 64 hex digits",
        )
    };
    let body = value.strip_prefix("0x").ok_or_else(invalid)?;
    if body.len() != 64 {
        return Err(invalid());
    }
    let bytes = hex::decode(body).map_err(|_| invalid())?;
    bytes.try_into().map_err(|_| invalid())
}

/// The ticket hash a fee payload names: `0x` and 64 lowercase hex digits.
pub fn ticket_hash_hex(secret: &[u8; 32]) -> String {
    format!(
        "0x{}",
        hex::encode(zkapi_types::wire::close_relay_ticket_hash(secret))
    )
}

/// Parse a fee request's payload strictly and check its shape.
pub fn parse_fee_authorization(payload: &str) -> Result<CloseRelayFeeAuthorization, ServerError> {
    let authorization: CloseRelayFeeAuthorization = serde_json::from_str(payload)
        .map_err(|_| ServerError::InvalidRequest("invalid close relay fee payload".into()))?;
    if authorization.mode != zkapi_types::wire::CLOSE_RELAY_FEE_MODE
        || authorization.version != zkapi_types::wire::CLOSE_RELAY_FEE_VERSION
    {
        return Err(ServerError::InvalidRequest(
            "unsupported close relay fee payload".into(),
        ));
    }
    let hash = authorization.ticket_hash.strip_prefix("0x");
    if !hash.is_some_and(|hash| {
        hash.len() == 64
            && hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        return Err(ServerError::InvalidRequest(
            "ticket_hash must be 0x followed by 64 lowercase hex digits".into(),
        ));
    }
    if authorization.fee_units.is_empty()
        || authorization.fee_units.starts_with('0')
        || !authorization
            .fee_units
            .bytes()
            .all(|byte| byte.is_ascii_digit())
    {
        return Err(ServerError::InvalidRequest(
            "fee_units must be a positive decimal integer".into(),
        ));
    }
    Ok(authorization)
}

/// The identity of a submitted close: its statement and proof.
pub fn submission_digest(inputs: &WithdrawalPublicInputsV2C, proof: &[u8]) -> String {
    let mut digest = Keccak256::new();
    digest.update(b"zkapi:v2c:close-relay-submission\0");
    for word in inputs.to_field_elements() {
        digest.update(word.as_bytes());
    }
    digest.update(proof);
    format!("0x{}", hex::encode(digest.finalize()))
}

/// The client-facing status of a relayed close.
pub fn status_response(
    record: &CloseRelayRecord,
    in_flight_hash: Option<String>,
) -> CloseRelayStatusResponse {
    let status = match record.status {
        CloseRelayStatus::Queued => "queued",
        CloseRelayStatus::InFlight => "submitted",
        CloseRelayStatus::Landed => "landed",
        CloseRelayStatus::Closed => "closed",
        CloseRelayStatus::Failed => "failed",
        CloseRelayStatus::Expired => "expired",
    };
    CloseRelayStatusResponse {
        status: status.to_string(),
        withdrawal_nullifier: record.withdrawal_nullifier,
        note_id: record.note_id,
        valid_until: record.valid_until,
        queued_at: record.queued_at,
        updated_at: record.updated_at,
        transaction_hash: record.transaction_hash.clone().or(in_flight_hash),
        block_number: record.block_number,
        detail: record.detail.clone(),
        self_submit: matches!(
            record.status,
            CloseRelayStatus::Failed | CloseRelayStatus::Expired
        ),
    }
}

// --------------------------------------------------------------------------
// ABI
// --------------------------------------------------------------------------

pub fn selector(signature: &str) -> [u8; 4] {
    let digest = Keccak256::digest(signature.as_bytes());
    [digest[0], digest[1], digest[2], digest[3]]
}

fn topic(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}

fn word_u64(value: u64) -> [u8; 32] {
    *Felt252::from_u64(value).as_bytes()
}

/// `mutualCloseBatch(inputs[], proofs)` calldata: the selector, the two
/// offsets, the array of static 16-word tuples and the concatenated proofs.
pub fn batch_calldata(items: &[&CloseRelayRecord]) -> Vec<u8> {
    let count = items.len() as u64;
    let inputs_offset = 64u64;
    let proofs_offset = inputs_offset + 32 + count * 16 * 32;
    let mut data = Vec::with_capacity(4 + 64 + 32 + items.len() * (16 * 32 + 256) + 32);
    data.extend_from_slice(&selector(MUTUAL_CLOSE_BATCH_SIGNATURE));
    data.extend_from_slice(&word_u64(inputs_offset));
    data.extend_from_slice(&word_u64(proofs_offset));
    data.extend_from_slice(&word_u64(count));
    for item in items {
        for word in item.public_inputs.to_field_elements() {
            data.extend_from_slice(word.as_bytes());
        }
    }
    data.extend_from_slice(&word_u64(count * 256));
    for item in items {
        data.extend_from_slice(&item.proof);
    }
    data
}

/// `vault.mutualClose(inputs, proof)` calldata for one close.
pub fn single_calldata(item: &CloseRelayRecord) -> Result<Vec<u8>, String> {
    crate::watcher::withdrawal_calldata(&item.public_inputs, &item.proof)
}

/// `gasBound(kinds)` calldata for `count` closes.
pub fn gas_bound_calldata(count: usize) -> Vec<u8> {
    let mut data = Vec::with_capacity(4 + 64 + count * 32);
    data.extend_from_slice(&selector(GAS_BOUND_SIGNATURE));
    data.extend_from_slice(&word_u64(32));
    data.extend_from_slice(&word_u64(count as u64));
    for _ in 0..count {
        data.extend_from_slice(&word_u64(u64::from(KIND_CLOSE)));
    }
    data
}

fn notes_calldata(note_id: u32) -> Vec<u8> {
    let mut data = selector(NOTES_SIGNATURE).to_vec();
    data.extend_from_slice(&word_u64(u64::from(note_id)));
    data
}

/// Calldata gas of a transaction: the standard cost (16 per nonzero byte,
/// 4 per zero byte) and the EIP-7623 floor (10 per token, a nonzero byte
/// counting 4 tokens).
pub fn calldata_gas(data: &[u8]) -> (u64, u64) {
    let zero = data.iter().filter(|byte| **byte == 0).count() as u64;
    let nonzero = data.len() as u64 - zero;
    (16 * nonzero + 4 * zero, 10 * (zero + 4 * nonzero))
}

/// The gas limit of a transaction whose execution needs at most `execution`
/// gas: 21,000 plus calldata plus execution, or the EIP-7623 floor if higher.
pub fn transaction_gas(data: &[u8], execution: u64) -> u64 {
    let (standard, floor) = calldata_gas(data);
    21_000 + standard.saturating_add(execution).max(floor)
}

fn decode_word_u128(bytes: &[u8], index: usize) -> Option<u128> {
    let word = bytes.get(index * 32..index * 32 + 32)?;
    if word[..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(u128::from_be_bytes(word[16..].try_into().ok()?))
}

/// Why the vault (or the batcher) refused a close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// `NoteNotActive` or `ReplayedNullifier`: the note was closed (or is
    /// escaping) by another transaction; its on-chain status decides.
    NoteNotActive,
    /// `Paused`: exits are closed for now; the close stays queued.
    Paused,
    /// `ProofExpired`.
    Expired,
    /// The payout push failed (`NativeTransferFailed`), or the item's call
    /// ran out of its gas cap (an empty revert): never relayed again.
    PayoutFailed(&'static str),
    /// Any other refusal, named.
    Other(String),
}

/// Classify a vault revert (or an `ItemSkipped` reason).
pub fn classify_refusal(data: &[u8]) -> Refusal {
    if data.is_empty() {
        return Refusal::PayoutFailed(
            "the close ran out of gas (a destination that burns the payout's gas)",
        );
    }
    let Some(head) = data.get(..4) else {
        return Refusal::Other(format!("revert 0x{}", hex::encode(data)));
    };
    for (name, refusal) in [
        ("NoteNotActive()", Refusal::NoteNotActive),
        ("ReplayedNullifier()", Refusal::NoteNotActive),
        ("Paused()", Refusal::Paused),
        ("ProofExpired()", Refusal::Expired),
        (
            "NativeTransferFailed()",
            Refusal::PayoutFailed("the destination refused the payout (NativeTransferFailed)"),
        ),
    ] {
        if head == selector(name) {
            return refusal;
        }
    }
    for name in [
        "InvalidProof()",
        "UnknownRoot()",
        "InvalidBalance()",
        "InvalidDestination()",
        "InvalidDeploymentBinding()",
        "WrongWithdrawalKind()",
        "InvalidFelt()",
    ] {
        if head == selector(name) {
            return Refusal::Other(format!("the vault refused the close ({name})"));
        }
    }
    Refusal::Other(format!(
        "the vault refused the close (0x{})",
        hex::encode(head)
    ))
}

// --------------------------------------------------------------------------
// Chain access
// --------------------------------------------------------------------------

/// A failed chain read or send. The message never contains the RPC URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainError(pub String);

impl std::fmt::Display for ChainError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// The result of an `eth_call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallOutcome {
    Success(Vec<u8>),
    Revert(Vec<u8>),
}

/// One log of a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiptLog {
    pub address: String,
    pub topics: Vec<String>,
    pub data: Vec<u8>,
}

/// A mined transaction's receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub transaction_hash: String,
    pub block_number: u64,
    pub success: bool,
    pub logs: Vec<ReceiptLog>,
}

/// An EIP-1559 relay transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTransaction {
    pub to: String,
    pub data: Vec<u8>,
    pub gas: u64,
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
}

/// The chain as the relay worker sees it: the relayer's signing RPC.
pub trait RelayChain: Send + Sync {
    /// `eth_call` from the relayer at latest.
    fn call(
        &self,
        to: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<CallOutcome, ChainError>> + Send;
    /// `eth_estimateGas` from the relayer; a revert is an error.
    fn estimate_gas(
        &self,
        to: &str,
        data: &[u8],
    ) -> impl Future<Output = Result<u64, ChainError>> + Send;
    /// The relayer's transaction count at latest (`pending` false) or
    /// pending.
    fn nonce(&self, pending: bool) -> impl Future<Output = Result<u64, ChainError>> + Send;
    /// The latest block's number and base fee.
    fn head(&self) -> impl Future<Output = Result<(u64, u128), ChainError>> + Send;
    /// `eth_sendTransaction` from the relayer: the hash, or an error (the
    /// transaction may still have been broadcast).
    fn send(
        &self,
        transaction: &RelayTransaction,
    ) -> impl Future<Output = Result<String, ChainError>> + Send;
    /// The receipt of `hash`, if mined.
    fn receipt(
        &self,
        hash: &str,
    ) -> impl Future<Output = Result<Option<Receipt>, ChainError>> + Send;
}

/// [`RelayChain`] over JSON-RPC.
pub struct RpcRelayChain {
    client: reqwest::Client,
    /// Reads, simulations and receipts.
    read_url: String,
    /// `eth_sendTransaction` and the sender's nonces (the node the
    /// transactions are broadcast to).
    send_url: String,
    sender: String,
    chain_id: u64,
}

impl std::fmt::Debug for RpcRelayChain {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RpcRelayChain")
            .field("url", &"[redacted]")
            .field("sender", &self.sender)
            .field("chain_id", &self.chain_id)
            .finish()
    }
}

impl RpcRelayChain {
    pub fn new(config: &CloseRelayConfig, chain_id: u64) -> anyhow::Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(RPC_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            read_url: config
                .read_rpc_url
                .clone()
                .unwrap_or_else(|| config.rpc_url.clone()),
            send_url: config.rpc_url.clone(),
            sender: config.sender.clone(),
            chain_id,
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Result<Value, Value>, ChainError> {
        self.rpc_at(&self.read_url, method, params).await
    }

    async fn rpc_at(
        &self,
        url: &str,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, Value>, ChainError> {
        let response: Value = self
            .client
            .post(url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| ChainError(format!("{method}: {}", error.without_url())))?
            .json()
            .await
            .map_err(|error| ChainError(format!("{method}: {}", error.without_url())))?;
        if let Some(error) = response.get("error") {
            return Ok(Err(error.clone()));
        }
        response
            .get("result")
            .cloned()
            .map(Ok)
            .ok_or_else(|| ChainError(format!("{method}: missing RPC result")))
    }

    async fn result(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        self.rpc(method, params)
            .await?
            .map_err(|error| ChainError(format!("{method}: {}", bounded(&error.to_string()))))
    }

    async fn send_result(&self, method: &str, params: Value) -> Result<Value, ChainError> {
        self.rpc_at(&self.send_url, method, params)
            .await?
            .map_err(|error| ChainError(format!("{method}: {}", bounded(&error.to_string()))))
    }

    /// The chain ids the read and the signing RPC serve, for the startup
    /// check.
    pub async fn chain_ids(&self) -> Result<(u64, u64), ChainError> {
        Ok((
            quantity(&self.result("eth_chainId", json!([])).await?)?,
            quantity(&self.send_result("eth_chainId", json!([])).await?)?,
        ))
    }

    /// Whether `address` holds code.
    pub async fn has_code(&self, address: &str) -> Result<bool, ChainError> {
        let code = self
            .result("eth_getCode", json!([address, "latest"]))
            .await?;
        let code = code
            .as_str()
            .ok_or_else(|| ChainError("eth_getCode: expected bytes".into()))?;
        Ok(code.trim_start_matches("0x").chars().any(|c| c != '0'))
    }
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_DETAIL_CHARS).collect()
}

fn quantity(value: &Value) -> Result<u64, ChainError> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| ChainError("expected a hex quantity".into()))?;
    if digits.is_empty() {
        return Err(ChainError("expected a hex quantity".into()));
    }
    u64::from_str_radix(digits, 16).map_err(|_| ChainError("quantity exceeds uint64".into()))
}

fn quantity_u128(value: &Value) -> Result<u128, ChainError> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| ChainError("expected a hex quantity".into()))?;
    u128::from_str_radix(digits, 16).map_err(|_| ChainError("quantity exceeds uint128".into()))
}

fn hex_bytes(value: &Value) -> Result<Vec<u8>, ChainError> {
    let digits = value
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(|| ChainError("expected hex bytes".into()))?;
    hex::decode(digits).map_err(|_| ChainError("malformed hex bytes".into()))
}

/// The revert data of a JSON-RPC error, if it reports a revert: `data` as hex
/// (geth, reth, anvil), possibly nested, or an "execution reverted" message
/// without data (an empty revert).
fn revert_data(error: &Value) -> Option<Vec<u8>> {
    let data = error.get("data");
    let hex = data.and_then(Value::as_str).or_else(|| {
        data.and_then(|data| data.get("data"))
            .and_then(Value::as_str)
    });
    if let Some(hex) = hex.and_then(|hex| hex.strip_prefix("0x")) {
        return hex::decode(hex).ok();
    }
    let message = error.get("message").and_then(Value::as_str).unwrap_or("");
    message
        .to_ascii_lowercase()
        .contains("revert")
        .then(Vec::new)
}

impl RelayChain for RpcRelayChain {
    async fn call(&self, to: &str, data: &[u8]) -> Result<CallOutcome, ChainError> {
        let call =
            json!({ "from": self.sender, "to": to, "data": format!("0x{}", hex::encode(data)) });
        match self.rpc("eth_call", json!([call, "latest"])).await? {
            Ok(result) => hex_bytes(&result).map(CallOutcome::Success),
            Err(error) => revert_data(&error)
                .map(CallOutcome::Revert)
                .ok_or_else(|| ChainError(format!("eth_call: {}", bounded(&error.to_string())))),
        }
    }

    async fn estimate_gas(&self, to: &str, data: &[u8]) -> Result<u64, ChainError> {
        let call =
            json!({ "from": self.sender, "to": to, "data": format!("0x{}", hex::encode(data)) });
        quantity(&self.result("eth_estimateGas", json!([call])).await?)
    }

    async fn nonce(&self, pending: bool) -> Result<u64, ChainError> {
        let tag = if pending { "pending" } else { "latest" };
        quantity(
            &self
                .send_result("eth_getTransactionCount", json!([self.sender, tag]))
                .await?,
        )
    }

    async fn head(&self) -> Result<(u64, u128), ChainError> {
        let block = self
            .result("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let number = quantity(&block["number"])?;
        let base_fee = quantity_u128(&block["baseFeePerGas"])?;
        Ok((number, base_fee))
    }

    async fn send(&self, transaction: &RelayTransaction) -> Result<String, ChainError> {
        let request = json!({
            "from": self.sender,
            "to": transaction.to,
            "data": format!("0x{}", hex::encode(&transaction.data)),
            "gas": format!("0x{:x}", transaction.gas),
            "nonce": format!("0x{:x}", transaction.nonce),
            "value": "0x0",
            "chainId": format!("0x{:x}", self.chain_id),
            "maxFeePerGas": format!("0x{:x}", transaction.max_fee_per_gas),
            "maxPriorityFeePerGas": format!("0x{:x}", transaction.max_priority_fee_per_gas),
        });
        let hash = self
            .send_result("eth_sendTransaction", json!([request]))
            .await?;
        let hash = hash
            .as_str()
            .filter(|hash| {
                hash.strip_prefix("0x")
                    .is_some_and(|body| body.len() == 64 && hex::decode(body).is_ok())
            })
            .ok_or_else(|| ChainError("eth_sendTransaction: malformed hash".into()))?;
        Ok(hash.to_ascii_lowercase())
    }

    async fn receipt(&self, hash: &str) -> Result<Option<Receipt>, ChainError> {
        let receipt = self
            .result("eth_getTransactionReceipt", json!([hash]))
            .await?;
        if receipt.is_null() {
            return Ok(None);
        }
        let logs = receipt["logs"]
            .as_array()
            .ok_or_else(|| ChainError("receipt without logs".into()))?
            .iter()
            .map(|log| {
                Ok(ReceiptLog {
                    address: log["address"]
                        .as_str()
                        .unwrap_or_default()
                        .to_ascii_lowercase(),
                    topics: log["topics"]
                        .as_array()
                        .map(|topics| {
                            topics
                                .iter()
                                .filter_map(Value::as_str)
                                .map(str::to_ascii_lowercase)
                                .collect()
                        })
                        .unwrap_or_default(),
                    data: hex_bytes(&log["data"])?,
                })
            })
            .collect::<Result<_, ChainError>>()?;
        Ok(Some(Receipt {
            transaction_hash: hash.to_ascii_lowercase(),
            block_number: quantity(&receipt["blockNumber"])?,
            success: quantity(&receipt["status"])? == 1,
            logs,
        }))
    }
}

/// Startup check of the batcher: the relayer's RPC serves `chain_id`, the
/// batcher has code, is bound to this server's vault (and to `adapter`, the
/// manifest's proof adapter, when given), and takes `max_batch` items.
pub async fn verify_batcher(
    chain: &RpcRelayChain,
    config: &CloseRelayConfig,
    chain_id: u64,
    vault: &str,
    adapter: Option<&str>,
) -> anyhow::Result<()> {
    let (read, send) = chain.chain_ids().await.map_err(anyhow::Error::msg)?;
    ensure!(
        read == chain_id,
        "the relay's read RPC serves chain {read}, not {chain_id}"
    );
    ensure!(
        send == chain_id,
        "--relay-rpc-url serves chain {send}, not {chain_id}"
    );
    ensure!(
        chain
            .has_code(&config.batcher_address)
            .await
            .map_err(anyhow::Error::msg)?,
        "the relay batcher {} has no code",
        config.batcher_address
    );
    let address_of = |outcome: CallOutcome, what: &str| -> anyhow::Result<String> {
        match outcome {
            CallOutcome::Success(bytes) if bytes.len() == 32 && bytes[..12] == [0; 12] => {
                Ok(format!("0x{}", hex::encode(&bytes[12..])))
            }
            _ => anyhow::bail!("the relay batcher's {what}() did not return an address"),
        }
    };
    let bound = address_of(
        chain
            .call(&config.batcher_address, &selector(BATCHER_VAULT_SIGNATURE))
            .await
            .map_err(anyhow::Error::msg)?,
        "vault",
    )?;
    ensure!(
        bound == vault.to_ascii_lowercase(),
        "the relay batcher is bound to vault {bound}, not this server's {vault}"
    );
    if let Some(adapter) = adapter {
        let bound = address_of(
            chain
                .call(
                    &config.batcher_address,
                    &selector(BATCHER_ADAPTER_SIGNATURE),
                )
                .await
                .map_err(anyhow::Error::msg)?,
            "adapter",
        )?;
        ensure!(
            bound == adapter.to_ascii_lowercase(),
            "the relay batcher uses adapter {bound}, not the manifest's {adapter}"
        );
    }
    match chain
        .call(
            &config.batcher_address,
            &selector(BATCHER_MAX_ITEMS_SIGNATURE),
        )
        .await
        .map_err(anyhow::Error::msg)?
    {
        CallOutcome::Success(bytes) => {
            let max = decode_word_u128(&bytes, 0).context("MAX_ITEMS() is not a uint")?;
            ensure!(
                max >= config.max_batch as u128,
                "the relay batcher takes at most {max} items; lower --relay-max-batch"
            );
        }
        CallOutcome::Revert(_) => anyhow::bail!("the relay batcher's MAX_ITEMS() reverted"),
    }
    Ok(())
}

// --------------------------------------------------------------------------
// The worker
// --------------------------------------------------------------------------

/// The relay worker: one tick per poll.
pub struct RelayWorker<C> {
    store: Arc<NullifierStore>,
    config: CloseRelayConfig,
    chain: C,
    vault: String,
}

/// What one flush found for its candidates.
#[derive(Default)]
struct Simulation {
    /// Closes the batch applies, in candidate order.
    applied: Vec<CloseRelayRecord>,
    /// Closes resolved without sending.
    settled: Vec<(Felt252, RelayItemOutcome)>,
}

impl<C: RelayChain> RelayWorker<C> {
    pub fn new(
        store: Arc<NullifierStore>,
        config: CloseRelayConfig,
        chain: C,
        vault: String,
    ) -> Self {
        Self {
            store,
            config,
            chain,
            vault: vault.to_ascii_lowercase(),
        }
    }

    pub fn chain(&self) -> &C {
        &self.chain
    }

    /// Follow the pending transaction, or flush the queue when it is due.
    pub async fn tick(&self, now: u64) -> anyhow::Result<()> {
        if let Some(batch) = self.store.pending_relay_batch()? {
            return self.follow(batch, now).await;
        }
        self.flush(now).await
    }

    // -- the pending transaction ------------------------------------------

    async fn follow(&self, batch: RelayBatchRecord, now: u64) -> anyhow::Result<()> {
        for hash in &batch.tx_hashes {
            let Some(receipt) = self.chain.receipt(hash).await.map_err(anyhow::Error::msg)? else {
                continue;
            };
            let (head, _) = self.chain.head().await.map_err(anyhow::Error::msg)?;
            if head.saturating_add(1)
                < receipt
                    .block_number
                    .saturating_add(self.config.confirmations)
            {
                // Mined, not yet confirmed: wait.
                return Ok(());
            }
            return self.resolve_from_receipt(&batch, &receipt, now).await;
        }
        let latest = self.chain.nonce(false).await.map_err(anyhow::Error::msg)?;
        if latest > batch.nonce {
            // The nonce is consumed, by one of this batch's transactions
            // (the relayer is dedicated), but no receipt of a hash it holds
            // has shown up: a hash lost to a crash before it was recorded,
            // or an RPC behind. After a grace period, each close is resolved
            // from its note's status, and never sent again.
            let quiet_since = batch.last_sent_at.unwrap_or(batch.created_at);
            if !batch.tx_hashes.is_empty()
                && now < quiet_since.saturating_add(LOST_RECEIPT_GRACE_SECONDS)
            {
                return Ok(());
            }
            let mut outcomes = Vec::with_capacity(batch.items.len());
            for nullifier in &batch.items {
                let Some(record) = self.store.close_relay(nullifier)? else {
                    continue;
                };
                let outcome = if self.note_closed(record.note_id).await? {
                    terminal(
                        CloseRelayStatus::Closed,
                        None,
                        None,
                        "the note is closed; the relay transaction that may have closed it has no receipt",
                    )
                } else {
                    terminal(
                        CloseRelayStatus::Failed,
                        None,
                        None,
                        "the relay transaction carrying this close was mined without a receipt the relay holds; it is not relayed again",
                    )
                };
                outcomes.push((*nullifier, outcome));
            }
            self.store.resolve_relay_batch(
                batch.batch_id,
                &outcomes,
                "nonce consumed without a known receipt",
                now,
            )?;
            return Ok(());
        }
        let pending = self.chain.nonce(true).await.map_err(anyhow::Error::msg)?;
        if pending <= batch.nonce {
            // The node holds nothing at this nonce: the send never reached
            // it, or its transaction left the pool. The closes go back to
            // the queue (the next flush simulates them again).
            let quiet_since = batch.last_sent_at.unwrap_or(batch.created_at);
            if batch.tx_hashes.is_empty()
                || now >= quiet_since.saturating_add(DROPPED_GRACE_SECONDS)
            {
                tracing::warn!(
                    nonce = batch.nonce,
                    "close relay: the node holds no transaction at the batch's nonce; its closes return to the queue"
                );
                self.store.resolve_relay_batch(
                    batch.batch_id,
                    &[],
                    "dropped: the node held no transaction at its nonce",
                    now,
                )?;
            }
            return Ok(());
        }
        // In the pool: replace it with higher fees once it is stale.
        let last = batch.last_sent_at.unwrap_or(batch.created_at);
        if batch.tx_hashes.is_empty() || now >= last.saturating_add(self.config.bump_after_seconds)
        {
            self.bump(&batch, now).await?;
        }
        Ok(())
    }

    /// Send the pending batch again at its nonce, with fees raised by 25%
    /// (and at least by one wei), within the fee cap.
    async fn bump(&self, batch: &RelayBatchRecord, now: u64) -> anyhow::Result<()> {
        let cap = self.config.max_fee_per_gas;
        let (tip, max_fee) = if batch.tx_hashes.is_empty() {
            (batch.max_priority_fee_per_gas, batch.max_fee_per_gas)
        } else {
            let raise =
                |value: u128| (value.saturating_mul(125) / 100).max(value.saturating_add(1));
            (
                raise(batch.max_priority_fee_per_gas),
                raise(batch.max_fee_per_gas).min(cap),
            )
        };
        if !batch.tx_hashes.is_empty() && max_fee <= batch.max_fee_per_gas {
            tracing::warn!(
                nonce = batch.nonce,
                "close relay: the pending transaction is at --relay-max-fee-per-gas and cannot be replaced; waiting"
            );
            return Ok(());
        }
        let transaction = RelayTransaction {
            to: batch.target.clone(),
            data: batch.calldata.clone(),
            gas: batch.gas_limit,
            nonce: batch.nonce,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip.min(max_fee),
        };
        match self.chain.send(&transaction).await {
            Ok(hash) => {
                tracing::info!(nonce = batch.nonce, %hash, "close relay: transaction sent");
                self.store.record_relay_send(
                    batch.batch_id,
                    &hash,
                    transaction.max_fee_per_gas,
                    transaction.max_priority_fee_per_gas,
                    now,
                )?;
            }
            Err(error) => {
                tracing::warn!(nonce = batch.nonce, error = %error, "close relay: send failed; the batch is followed by its nonce");
            }
        }
        Ok(())
    }

    async fn resolve_from_receipt(
        &self,
        batch: &RelayBatchRecord,
        receipt: &Receipt,
        now: u64,
    ) -> anyhow::Result<()> {
        let hash = Some(receipt.transaction_hash.clone());
        let block = Some(receipt.block_number);
        let mut outcomes = Vec::with_capacity(batch.items.len());
        let single = batch.target != self.config.batcher_address;
        if !receipt.success && !single {
            // The whole batch reverted (BatchOutOfGas, or a state no
            // simulation saw): every close goes back to the queue, counted.
            tracing::warn!(nonce = batch.nonce, hash = %receipt.transaction_hash, "close relay: the batch transaction reverted; its closes return to the queue");
            for nullifier in &batch.items {
                outcomes.push((
                    *nullifier,
                    RelayItemOutcome::Requeue {
                        attempt: true,
                        detail: Some("a relay batch carrying this close reverted".into()),
                    },
                ));
            }
            self.store
                .resolve_relay_batch(batch.batch_id, &outcomes, "batch reverted", now)?;
            return Ok(());
        }
        let closes = self.mutual_closes(receipt);
        let skipped = self.skipped_items(receipt);
        for (index, nullifier) in batch.items.iter().enumerate() {
            let Some(record) = self.store.close_relay(nullifier)? else {
                continue;
            };
            let outcome = if closes.contains(nullifier) {
                RelayItemOutcome::Terminal {
                    status: CloseRelayStatus::Landed,
                    transaction_hash: hash.clone(),
                    block_number: block,
                    detail: None,
                }
            } else if let Some(reason) = skipped.get(&(index as u64)) {
                self.refusal_outcome(&record, classify_refusal(reason), hash.clone(), block)
                    .await?
            } else if single && !receipt.success {
                // A lone close that reverted: the receipt holds no reason.
                if self.note_closed(record.note_id).await? {
                    terminal(
                        CloseRelayStatus::Closed,
                        hash.clone(),
                        block,
                        "the note was closed by another transaction",
                    )
                } else {
                    terminal(
                        CloseRelayStatus::Failed,
                        hash.clone(),
                        block,
                        "the relay's mutualClose reverted (for example the destination refused the payout); it is not relayed again",
                    )
                }
            } else if self.note_closed(record.note_id).await? {
                terminal(
                    CloseRelayStatus::Closed,
                    hash.clone(),
                    block,
                    "the note is closed, without a MutualClose of this close in the relay's transaction",
                )
            } else {
                terminal(
                    CloseRelayStatus::Failed,
                    hash.clone(),
                    block,
                    "the relay's transaction neither closed nor skipped this close; it is not relayed again",
                )
            };
            outcomes.push((*nullifier, outcome));
        }
        let landed = outcomes
            .iter()
            .filter(|(_, outcome)| {
                matches!(
                    outcome,
                    RelayItemOutcome::Terminal {
                        status: CloseRelayStatus::Landed,
                        ..
                    }
                )
            })
            .count();
        tracing::info!(
            hash = %receipt.transaction_hash,
            block = receipt.block_number,
            closes = batch.items.len(),
            landed,
            "close relay: transaction confirmed"
        );
        self.store.resolve_relay_batch(
            batch.batch_id,
            &outcomes,
            &format!("{landed} of {} landed", batch.items.len()),
            now,
        )?;
        Ok(())
    }

    /// The withdrawal nullifiers of the vault's MutualClose logs.
    fn mutual_closes(&self, receipt: &Receipt) -> std::collections::HashSet<Felt252> {
        let topic0 = topic(MUTUAL_CLOSE_EVENT);
        receipt
            .logs
            .iter()
            .filter(|log| log.address == self.vault && log.topics.first() == Some(&topic0))
            .filter_map(|log| log.data.get(..32))
            .filter_map(|word| Felt252::try_from_bytes_be(word.try_into().ok()?).ok())
            .collect()
    }

    /// The batcher's ItemSkipped logs: item index to the vault's refusal.
    fn skipped_items(&self, receipt: &Receipt) -> std::collections::BTreeMap<u64, Vec<u8>> {
        let topic0 = topic(ITEM_SKIPPED_EVENT);
        let mut skipped = std::collections::BTreeMap::new();
        for log in &receipt.logs {
            if log.address != self.config.batcher_address || log.topics.first() != Some(&topic0) {
                continue;
            }
            let Some(index) = log
                .topics
                .get(1)
                .and_then(|topic| topic.strip_prefix("0x"))
                .and_then(|digits| {
                    u64::from_str_radix(digits.trim_start_matches('0'), 16)
                        .ok()
                        .or_else(|| digits.chars().all(|c| c == '0').then_some(0))
                })
            else {
                continue;
            };
            // data: offset, length, reason bytes.
            let reason = decode_word_u128(&log.data, 1)
                .and_then(|length| log.data.get(64..64 + length as usize))
                .map(<[u8]>::to_vec)
                .unwrap_or_default();
            skipped.insert(index, reason);
        }
        skipped
    }

    async fn note_closed(&self, note_id: u32) -> anyhow::Result<bool> {
        match self
            .chain
            .call(&self.vault, &notes_calldata(note_id))
            .await
            .map_err(anyhow::Error::msg)?
        {
            CallOutcome::Success(bytes) => Ok(decode_word_u128(&bytes, 3)
                .context("notes() returned no status word")?
                == u128::from(NOTE_STATUS_CLOSED)),
            CallOutcome::Revert(_) => anyhow::bail!("notes() reverted"),
        }
    }

    async fn refusal_outcome(
        &self,
        record: &CloseRelayRecord,
        refusal: Refusal,
        hash: Option<String>,
        block: Option<u64>,
    ) -> anyhow::Result<RelayItemOutcome> {
        Ok(match refusal {
            Refusal::NoteNotActive => {
                if self.note_closed(record.note_id).await? {
                    terminal(
                        CloseRelayStatus::Closed,
                        hash,
                        block,
                        "the note was closed by another transaction",
                    )
                } else {
                    terminal(
                        CloseRelayStatus::Failed,
                        hash,
                        block,
                        "the note is not active (an escape is pending)",
                    )
                }
            }
            Refusal::Paused => RelayItemOutcome::Requeue {
                attempt: false,
                detail: Some("the vault is paused".into()),
            },
            Refusal::Expired => terminal(
                CloseRelayStatus::Expired,
                hash,
                block,
                "the close's proof expired",
            ),
            Refusal::PayoutFailed(detail) => {
                terminal(CloseRelayStatus::Failed, hash, block, detail)
            }
            Refusal::Other(detail) => terminal(CloseRelayStatus::Failed, hash, block, &detail),
        })
    }

    // -- flushing ----------------------------------------------------------

    async fn flush(&self, now: u64) -> anyhow::Result<()> {
        let queued = self.store.queued_close_relays(QUEUE_SCAN)?;
        if queued.is_empty() {
            return Ok(());
        }
        // Closes past the cutoff, or out of attempts, are given back to
        // their clients first.
        let mut given_back = Vec::new();
        let mut live = Vec::with_capacity(queued.len());
        for record in queued {
            if record.valid_until <= now.saturating_add(self.config.cutoff_seconds) {
                given_back.push((
                    record.withdrawal_nullifier,
                    terminal(
                        CloseRelayStatus::Expired,
                        None,
                        None,
                        "too near its valid_until for the relay to send it",
                    ),
                ));
            } else if record.attempts >= self.config.max_attempts {
                given_back.push((
                    record.withdrawal_nullifier,
                    terminal(
                        CloseRelayStatus::Failed,
                        None,
                        None,
                        "relay batches carrying this close kept reverting",
                    ),
                ));
            } else {
                live.push(record);
            }
        }
        if !given_back.is_empty() {
            self.store.settle_queued_relays(&given_back, now)?;
        }
        if !self.due(&live, now) {
            return Ok(());
        }
        // The most urgent first, then the oldest.
        live.sort_by_key(|record| {
            let urgent =
                record.valid_until <= now.saturating_add(self.config.urgent_margin_seconds);
            (
                !urgent,
                if urgent { record.valid_until } else { 0 },
                record.queued_at,
            )
        });
        live.truncate(self.config.max_batch);
        let simulation = self.simulate(live).await?;
        if !simulation.settled.is_empty() {
            self.store.settle_queued_relays(&simulation.settled, now)?;
        }
        if simulation.applied.is_empty() {
            return Ok(());
        }
        self.send_new(simulation.applied, now).await
    }

    /// Whether the queue is due for a batch.
    pub fn due(&self, live: &[CloseRelayRecord], now: u64) -> bool {
        live.len() >= self.config.batch_target
            || live.iter().any(|record| {
                record
                    .queued_at
                    .saturating_add(self.config.flush_age_seconds)
                    <= now
                    || record.valid_until <= now.saturating_add(self.config.urgent_margin_seconds)
            })
    }

    /// `eth_call` the batch; bisect one that reverts; classify each close
    /// it would skip by calling `mutualClose` for it alone.
    async fn simulate(&self, candidates: Vec<CloseRelayRecord>) -> anyhow::Result<Simulation> {
        let mut simulation = Simulation::default();
        let mut stack = vec![candidates];
        // Depth-first, keeping candidate order: halves are pushed reversed.
        while let Some(group) = stack.pop() {
            if group.len() == 1 {
                let record = group.into_iter().next().expect("one close");
                self.simulate_single(record, &mut simulation, None).await?;
                continue;
            }
            let refs: Vec<&CloseRelayRecord> = group.iter().collect();
            match self
                .chain
                .call(&self.config.batcher_address, &batch_calldata(&refs))
                .await
                .map_err(anyhow::Error::msg)?
            {
                CallOutcome::Success(bytes) => {
                    let bitmap = bytes
                        .get(..32)
                        .context("mutualCloseBatch returned no bitmap")?;
                    for (index, record) in group.into_iter().enumerate() {
                        let byte = bitmap[31 - index / 8];
                        if byte & (1 << (index % 8)) != 0 {
                            simulation.applied.push(record);
                        } else {
                            self.simulate_single(record, &mut simulation, Some(()))
                                .await?;
                        }
                    }
                }
                CallOutcome::Revert(_) => {
                    let mut group = group;
                    let second = group.split_off(group.len() / 2);
                    stack.push(second);
                    stack.push(group);
                }
            }
        }
        Ok(simulation)
    }

    /// A close alone: `mutualClose` from the relayer. `skipped_in_batch`
    /// marks a close the batch skipped although it would succeed alone: its
    /// payout needs more gas than the batcher's item cap.
    async fn simulate_single(
        &self,
        record: CloseRelayRecord,
        simulation: &mut Simulation,
        skipped_in_batch: Option<()>,
    ) -> anyhow::Result<()> {
        let calldata = match single_calldata(&record) {
            Ok(calldata) => calldata,
            Err(error) => {
                simulation.settled.push((
                    record.withdrawal_nullifier,
                    terminal(CloseRelayStatus::Failed, None, None, &error),
                ));
                return Ok(());
            }
        };
        match self
            .chain
            .call(&self.vault, &calldata)
            .await
            .map_err(anyhow::Error::msg)?
        {
            CallOutcome::Success(_) if skipped_in_batch.is_some() => simulation.settled.push((
                record.withdrawal_nullifier,
                terminal(
                    CloseRelayStatus::Failed,
                    None,
                    None,
                    "the payout needs more gas than the batcher's per-close cap; submit the close yourself",
                ),
            )),
            CallOutcome::Success(_) => simulation.applied.push(record),
            CallOutcome::Revert(data) => {
                let outcome = self
                    .refusal_outcome(&record, classify_refusal(&data), None, None)
                    .await?;
                // A refusal no transaction carried: a transient one stays
                // queued without counting an attempt.
                simulation.settled.push((record.withdrawal_nullifier, outcome));
            }
        }
        Ok(())
    }

    /// Open a batch for `closes` at the relayer's next nonce and send it.
    async fn send_new(&self, mut closes: Vec<CloseRelayRecord>, now: u64) -> anyhow::Result<()> {
        let (_, base_fee) = self.chain.head().await.map_err(anyhow::Error::msg)?;
        let tip = self.config.priority_fee_per_gas;
        if base_fee.saturating_add(tip) > self.config.max_fee_per_gas {
            tracing::warn!(
                base_fee,
                cap = self.config.max_fee_per_gas,
                "close relay: the base fee is above --relay-max-fee-per-gas; the queue waits"
            );
            return Ok(());
        }
        let max_fee = base_fee
            .saturating_mul(2)
            .saturating_add(tip)
            .min(self.config.max_fee_per_gas);
        let (target, calldata, gas) = loop {
            let (target, calldata, gas) = self.plan_transaction(&closes).await?;
            if gas <= self.config.max_gas || closes.len() == 1 {
                break (target, calldata, gas);
            }
            closes.truncate(closes.len() / 2);
        };
        if gas > self.config.max_gas {
            anyhow::bail!("a single close needs {gas} gas, above --relay-max-gas");
        }
        let nonce = self.chain.nonce(true).await.map_err(anyhow::Error::msg)?;
        let items: Vec<Felt252> = closes
            .iter()
            .map(|close| close.withdrawal_nullifier)
            .collect();
        let batch_id = self.store.open_relay_batch(&NewRelayBatch {
            nonce,
            target: &target,
            calldata: &calldata,
            items: &items,
            gas_limit: gas,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            now,
        })?;
        let batch = self
            .store
            .pending_relay_batch()?
            .filter(|batch| batch.batch_id == batch_id)
            .context("the relay batch just opened is not pending")?;
        self.bump(&batch, now).await
    }

    /// The transaction for `closes`: a lone close to the vault (a batch of
    /// one costs more), otherwise `mutualCloseBatch` to the batcher. Its gas
    /// limit is the batcher's bound plus intrinsic and calldata gas (for a
    /// single close, the estimate plus 20%), never below `eth_estimateGas`.
    async fn plan_transaction(
        &self,
        closes: &[CloseRelayRecord],
    ) -> anyhow::Result<(String, Vec<u8>, u64)> {
        if let [close] = closes {
            let calldata = single_calldata(close).map_err(anyhow::Error::msg)?;
            let estimate = self
                .chain
                .estimate_gas(&self.vault, &calldata)
                .await
                .map_err(anyhow::Error::msg)?;
            let gas = estimate.saturating_add(estimate * SINGLE_GAS_HEADROOM_PERCENT / 100);
            return Ok((self.vault.clone(), calldata, gas));
        }
        let refs: Vec<&CloseRelayRecord> = closes.iter().collect();
        let calldata = batch_calldata(&refs);
        let bound = match self
            .chain
            .call(
                &self.config.batcher_address,
                &gas_bound_calldata(closes.len()),
            )
            .await
            .map_err(anyhow::Error::msg)?
        {
            CallOutcome::Success(bytes) => decode_word_u128(&bytes, 0)
                .and_then(|bound| u64::try_from(bound).ok())
                .context("gasBound() returned no uint64")?,
            CallOutcome::Revert(_) => anyhow::bail!("gasBound() reverted"),
        };
        let estimate = self
            .chain
            .estimate_gas(&self.config.batcher_address, &calldata)
            .await
            .map_err(anyhow::Error::msg)?;
        let gas = transaction_gas(&calldata, bound).max(estimate);
        Ok((self.config.batcher_address.clone(), calldata, gas))
    }
}

fn terminal(
    status: CloseRelayStatus,
    transaction_hash: Option<String>,
    block_number: Option<u64>,
    detail: &str,
) -> RelayItemOutcome {
    RelayItemOutcome::Terminal {
        status,
        transaction_hash,
        block_number,
        detail: Some(detail.to_string()),
    }
}

/// Run the worker every poll until the process ends.
pub fn spawn_relay_worker<C: RelayChain + 'static>(worker: Arc<RelayWorker<C>>) {
    tokio::spawn(async move {
        let mut ticker =
            tokio::time::interval(Duration::from_secs(worker.config.poll_seconds.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if let Err(error) = worker.tick(now).await {
                tracing::warn!(error = %error, "close relay tick failed; retrying next poll");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nullifier_store::{CloseRelayEnqueued, NewCloseRelay, SettledCharge};
    use std::collections::{HashMap, HashSet};
    use std::sync::Mutex;
    use zkapi_types::wire::{ApiRequestV2, Groth16ProofWire, ProofBackendWire};

    const VAULT: &str = "0x00000000000000000000000000000000000000aa";
    const BATCHER: &str = "0x00000000000000000000000000000000000000bb";
    const SENDER: &str = "0x00000000000000000000000000000000000000cc";
    const NOW: u64 = 1_900_000_000;
    const BOUND_PER_ITEM: u64 = 200_000;

    fn config() -> CloseRelayConfig {
        let mut config = CloseRelayConfig::new(
            250_000,
            BATCHER.into(),
            "http://127.0.0.1:9".into(),
            SENDER.into(),
            100_000_000_000,
        );
        config.batch_target = 4;
        config.max_batch = 8;
        config.validate().unwrap();
        config
    }

    fn selector_of(data: &[u8]) -> [u8; 4] {
        data[..4].try_into().unwrap()
    }

    /// A vault, batcher and relayer account in memory. Closes apply unless
    /// their note is closed, their proof is bad (the whole batch reverts),
    /// or a refusal is set for them; a sent transaction is mined at once
    /// unless `hold` is set.
    #[derive(Default)]
    struct MockState {
        closed: HashSet<u32>,
        refusals: HashMap<u32, Vec<u8>>,
        bad_proof: HashSet<u32>,
        /// Closes the batch skips (out of its gas cap) though alone they pass.
        cap_exceeded: HashSet<u32>,
        paused: bool,
        nonce: u64,
        pending_extra: u64,
        head: u64,
        base_fee: u128,
        hold: bool,
        fail_send: bool,
        sent: Vec<RelayTransaction>,
        receipts: HashMap<String, Receipt>,
        batch_calls: Vec<usize>,
    }

    #[derive(Default)]
    struct MockChain(Mutex<MockState>);

    fn decode_items(data: &[u8]) -> Vec<(u32, Felt252)> {
        let word = |index: usize| &data[4 + index * 32..4 + index * 32 + 32];
        let count = u64::from_be_bytes(word(2)[24..].try_into().unwrap()) as usize;
        (0..count)
            .map(|item| {
                let base = 3 + item * 16;
                let note = u32::from_be_bytes(word(base + 8)[28..].try_into().unwrap());
                (note, Felt252(word(base + 11).try_into().unwrap()))
            })
            .collect()
    }

    fn decode_single(data: &[u8]) -> (u32, Felt252) {
        let word = |index: usize| &data[4 + index * 32..4 + index * 32 + 32];
        (
            u32::from_be_bytes(word(8)[28..].try_into().unwrap()),
            Felt252(word(11).try_into().unwrap()),
        )
    }

    impl MockState {
        /// Why the vault refuses this close now, if it does.
        fn refusal(&self, note: u32) -> Option<Vec<u8>> {
            if self.bad_proof.contains(&note) {
                return Some(selector("InvalidProof()").to_vec());
            }
            if self.paused {
                return Some(selector("Paused()").to_vec());
            }
            if self.closed.contains(&note) {
                return Some(selector("NoteNotActive()").to_vec());
            }
            self.refusals.get(&note).cloned()
        }

        fn batch(&self, data: &[u8]) -> Result<Vec<Option<Vec<u8>>>, Vec<u8>> {
            let items = decode_items(data);
            if items.iter().any(|(note, _)| self.bad_proof.contains(note)) {
                return Err(selector("InvalidProof()").to_vec());
            }
            Ok(items
                .iter()
                .map(|(note, _)| {
                    if self.cap_exceeded.contains(note) {
                        Some(Vec::new())
                    } else {
                        self.refusal(*note)
                    }
                })
                .collect())
        }

        fn mine(&mut self, transaction: &RelayTransaction, hash: &str) {
            let mut logs = Vec::new();
            let mut success = true;
            if transaction.to == VAULT {
                let (note, nullifier) = decode_single(&transaction.data);
                if self.refusal(note).is_some() {
                    success = false;
                } else {
                    self.closed.insert(note);
                    logs.push(close_log(note, &nullifier));
                }
            } else {
                match self.batch(&transaction.data) {
                    Err(_) => success = false,
                    Ok(outcomes) => {
                        for (index, ((note, nullifier), refusal)) in decode_items(&transaction.data)
                            .into_iter()
                            .zip(outcomes)
                            .enumerate()
                        {
                            match refusal {
                                None => {
                                    self.closed.insert(note);
                                    logs.push(close_log(note, &nullifier));
                                }
                                Some(reason) => logs.push(skip_log(index as u64, note, &reason)),
                            }
                        }
                    }
                }
            }
            self.head += 1;
            self.nonce += 1;
            self.receipts.insert(
                hash.to_string(),
                Receipt {
                    transaction_hash: hash.to_string(),
                    block_number: self.head,
                    success,
                    logs,
                },
            );
        }
    }

    fn close_log(note: u32, nullifier: &Felt252) -> ReceiptLog {
        let mut data = nullifier.as_bytes().to_vec();
        data.extend_from_slice(Felt252::from_u64(1).as_bytes());
        data.extend_from_slice(Felt252::from_u64(0x11).as_bytes());
        ReceiptLog {
            address: VAULT.into(),
            topics: vec![
                topic(MUTUAL_CLOSE_EVENT),
                Felt252::from_u64(note.into()).to_hex(),
            ],
            data,
        }
    }

    fn skip_log(index: u64, note: u32, reason: &[u8]) -> ReceiptLog {
        let mut data = word_u64(32).to_vec();
        data.extend_from_slice(&word_u64(reason.len() as u64));
        let mut padded = reason.to_vec();
        padded.resize(reason.len().div_ceil(32) * 32, 0);
        data.extend_from_slice(&padded);
        let full = |value: u64| format!("0x{}", hex::encode(word_u64(value)));
        ReceiptLog {
            address: BATCHER.into(),
            topics: vec![
                topic(ITEM_SKIPPED_EVENT),
                full(index),
                full(u64::from(KIND_CLOSE)),
                full(u64::from(note)),
            ],
            data,
        }
    }

    impl RelayChain for MockChain {
        async fn call(&self, to: &str, data: &[u8]) -> Result<CallOutcome, ChainError> {
            let mut state = self.0.lock().unwrap();
            let head = selector_of(data);
            if head == selector(NOTES_SIGNATURE) {
                let note = u32::from_be_bytes(data[32..36].try_into().unwrap());
                let status = if state.closed.contains(&note) { 3 } else { 1 };
                let mut words = vec![0u8; 96];
                words.extend_from_slice(&word_u64(status));
                return Ok(CallOutcome::Success(words));
            }
            if head == selector(GAS_BOUND_SIGNATURE) {
                let count = u64::from_be_bytes(data[60..68].try_into().unwrap());
                return Ok(CallOutcome::Success(
                    word_u64(1_000_000 + count * BOUND_PER_ITEM).to_vec(),
                ));
            }
            if to == VAULT {
                let (note, _) = decode_single(data);
                return Ok(match state.refusal(note) {
                    Some(reason) => CallOutcome::Revert(reason),
                    None => CallOutcome::Success(Vec::new()),
                });
            }
            assert_eq!(to, BATCHER);
            state.batch_calls.push(decode_items(data).len());
            Ok(match state.batch(data) {
                Err(reason) => CallOutcome::Revert(reason),
                Ok(outcomes) => {
                    let mut bitmap = [0u8; 32];
                    for (index, outcome) in outcomes.iter().enumerate() {
                        if outcome.is_none() {
                            bitmap[31 - index / 8] |= 1 << (index % 8);
                        }
                    }
                    CallOutcome::Success(bitmap.to_vec())
                }
            })
        }

        async fn estimate_gas(&self, _to: &str, _data: &[u8]) -> Result<u64, ChainError> {
            Ok(300_000)
        }

        async fn nonce(&self, pending: bool) -> Result<u64, ChainError> {
            let state = self.0.lock().unwrap();
            Ok(state.nonce + if pending { state.pending_extra } else { 0 })
        }

        async fn head(&self) -> Result<(u64, u128), ChainError> {
            let state = self.0.lock().unwrap();
            Ok((state.head, state.base_fee))
        }

        async fn send(&self, transaction: &RelayTransaction) -> Result<String, ChainError> {
            let mut state = self.0.lock().unwrap();
            state.sent.push(transaction.clone());
            if state.fail_send {
                return Err(ChainError("eth_sendTransaction: connection reset".into()));
            }
            assert_eq!(transaction.nonce, state.nonce, "one nonce lane");
            let hash = format!("0x{:064x}", state.sent.len());
            if state.hold {
                state.pending_extra = 1;
            } else {
                state.mine(transaction, &hash);
                state.pending_extra = 0;
            }
            Ok(hash)
        }

        async fn receipt(&self, hash: &str) -> Result<Option<Receipt>, ChainError> {
            Ok(self.0.lock().unwrap().receipts.get(hash).cloned())
        }
    }

    fn worker(store: Arc<NullifierStore>) -> RelayWorker<MockChain> {
        let chain = MockChain::default();
        chain.0.lock().unwrap().base_fee = 1_000_000_000;
        RelayWorker::new(store, config(), chain, VAULT.into())
    }

    fn state(worker: &RelayWorker<MockChain>) -> std::sync::MutexGuard<'_, MockState> {
        worker.chain().0.lock().unwrap()
    }

    fn proof_wire() -> Groth16ProofWire {
        Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: crate::test_support::fake_proof(7),
        }
    }

    fn inputs(note: u32, valid_until: u64) -> WithdrawalPublicInputsV2C {
        WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_hex(VAULT).unwrap(),
            active_root: Felt252::from_u64(5),
            state_signing_key_x: Felt252::from_u64(6),
            state_signing_key_y: Felt252::from_u64(7),
            clearance_signing_key_x: Felt252::from_u64(8),
            clearance_signing_key_y: Felt252::from_u64(9),
            note_id: note,
            final_balance: 1_000,
            destination: [0x11; 20],
            withdrawal_nullifier: Felt252::from_u64(10_000 + u64::from(note)),
            kind: 1,
            next_nullifier: Felt252::ZERO,
            conceded: 0,
            valid_until,
        }
    }

    /// Pay a fee ticket (as the fee endpoint does), clear the nullifier and
    /// queue the close of `note`.
    fn queue(store: &NullifierStore, note: u32, valid_until: u64, queued_at: u64) -> Felt252 {
        let secret = [note as u8; 32];
        let ticket = ticket_hash_hex(&secret);
        let mut fee_inputs = zkapi_types::RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_hex(VAULT).unwrap(),
            active_root: Felt252::from_u64(5),
            state_signing_key_x: Felt252::from_u64(6),
            state_signing_key_y: Felt252::from_u64(7),
            request_time: queued_at,
            solvency_bound: 250_000,
            request_nullifier: Felt252::from_u64(20_000 + u64::from(note)),
            authorization_tag: Felt252::ONE,
            anonymous_commitment_x: Felt252::ONE,
            anonymous_commitment_y: Felt252::ONE,
        };
        fee_inputs.authorization_tag = Felt252::from_u64(3);
        let payload =
            serde_json::to_string(&CloseRelayFeeAuthorization::new(250_000, &secret)).unwrap();
        let request = ApiRequestV2 {
            client_request_id: format!("fee-{note}"),
            payload_hash: zkapi_types::canonical_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: fee_inputs,
            proof: proof_wire(),
        };
        store
            .reserve_relay_fee(
                &request,
                &ticket,
                &SettledCharge {
                    charge: 250_000,
                    basis: "relay_fee".into(),
                    response_code: 200,
                    response_payload: "{}".into(),
                    settled_at: queued_at,
                },
            )
            .unwrap();
        let inputs = inputs(note, valid_until);
        store
            .reserve_clearance(&inputs.withdrawal_nullifier, "ownership_proof")
            .unwrap();
        let proof = vec![7u8; 256];
        let digest = submission_digest(&inputs, &proof);
        let enqueued = store
            .enqueue_close_relay(&NewCloseRelay {
                public_inputs: &inputs,
                proof: &proof,
                ticket_hash: &ticket,
                submission_digest: &digest,
                now: queued_at,
            })
            .unwrap();
        assert!(matches!(enqueued, CloseRelayEnqueued::New(_)));
        inputs.withdrawal_nullifier
    }

    fn status(store: &NullifierStore, nullifier: &Felt252) -> CloseRelayStatus {
        store.close_relay(nullifier).unwrap().unwrap().status
    }

    /// Confirm whatever is mined (two confirmations) and resolve it.
    async fn confirm(worker: &RelayWorker<MockChain>, now: u64) {
        state(worker).head += 1;
        worker.tick(now).await.unwrap();
    }

    #[test]
    fn calldata_and_selectors_match_the_batcher_abi() {
        // cast sig of the ABI in docs (batcher-abi.md).
        assert_eq!(
            hex::encode(selector(MUTUAL_CLOSE_BATCH_SIGNATURE)),
            "178cd980"
        );
        assert_eq!(hex::encode(selector(GAS_BOUND_SIGNATURE)), "aa012945");
        assert_eq!(
            format!(
                "0x{}",
                hex::encode(selector(crate::watcher::MUTUAL_CLOSE_SIGNATURE))
            ),
            crate::test_support::real_selector("mutualClose")
        );
        assert_eq!(
            format!("0x{}", hex::encode(selector(NOTES_SIGNATURE))),
            crate::test_support::real_selector("notes")
        );
        assert_eq!(
            topic(MUTUAL_CLOSE_EVENT),
            crate::test_support::real_vault_layout()["events"]["MutualClose"]["topic0"]
                .as_str()
                .unwrap()
        );
        let store = NullifierStore::in_memory().unwrap();
        let first = queue(&store, 1, NOW + 7_200, NOW);
        let second = queue(&store, 2, NOW + 7_200, NOW);
        let records: Vec<_> = [first, second]
            .iter()
            .map(|n| store.close_relay(n).unwrap().unwrap())
            .collect();
        let data = batch_calldata(&records.iter().collect::<Vec<_>>());
        // selector, two offsets, the length, 2 x 16 words, the bytes length
        // and 2 x 256 proof bytes.
        assert_eq!(data.len(), 4 + 32 * 3 + 2 * 16 * 32 + 32 + 2 * 256);
        assert_eq!(decode_word_u128(&data[4..], 0), Some(64));
        assert_eq!(decode_word_u128(&data[4..], 1), Some(64 + 32 + 2 * 16 * 32));
        assert_eq!(decode_items(&data), vec![(1, first), (2, second)]);
        assert_eq!(decode_word_u128(&data[4..], 3 + 32), Some(512));
        let (standard, floor) = calldata_gas(&[0, 0, 1]);
        assert_eq!((standard, floor), (24, 60));
        assert_eq!(transaction_gas(&[0, 0, 1], 100), 21_000 + 124);
        assert_eq!(transaction_gas(&[0, 0, 1], 0), 21_000 + 60);
    }

    #[test]
    fn refusals_are_classified_for_relaying_never_again() {
        assert_eq!(
            classify_refusal(&selector("NoteNotActive()")),
            Refusal::NoteNotActive
        );
        assert_eq!(
            classify_refusal(&selector("ReplayedNullifier()")),
            Refusal::NoteNotActive
        );
        assert_eq!(classify_refusal(&selector("Paused()")), Refusal::Paused);
        assert_eq!(
            classify_refusal(&selector("ProofExpired()")),
            Refusal::Expired
        );
        assert!(matches!(
            classify_refusal(&selector("NativeTransferFailed()")),
            Refusal::PayoutFailed(_)
        ));
        assert!(matches!(classify_refusal(&[]), Refusal::PayoutFailed(_)));
        assert!(matches!(
            classify_refusal(&selector("InvalidProof()")),
            Refusal::Other(detail) if detail.contains("InvalidProof")
        ));
    }

    #[test]
    fn configuration_is_validated() {
        let mut bad = config();
        bad.batch_target = 9;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.max_batch = 65;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.cutoff_seconds = bad.urgent_margin_seconds;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.urgent_margin_seconds = bad.min_validity_seconds;
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.sender = "0x0000000000000000000000000000000000000000".into();
        assert!(bad.validate().is_err());
        let mut bad = config();
        bad.fee_units = 0;
        assert!(bad.validate().is_err());
        assert!(!format!("{:?}", config()).contains("127.0.0.1:9"));
    }

    #[test]
    fn fee_payloads_are_strict() {
        let good = serde_json::to_string(&CloseRelayFeeAuthorization::new(5, &[1; 32])).unwrap();
        assert!(parse_fee_authorization(&good).is_ok());
        for bad in [
            good.replace("close_relay_fee", "openrouter_ephemeral_lease"),
            good.replace("\"5\"", "\"05\""),
            good.replace("\"5\"", "\"\""),
            good.replace("0x", "0X"),
            good.replace("}", ",\"prompt\":\"x\"}"),
        ] {
            assert!(parse_fee_authorization(&bad).is_err(), "{bad}");
        }
        assert!(parse_ticket_secret(&format!("0x{}", "ab".repeat(32))).is_ok());
        assert!(parse_ticket_secret(&"ab".repeat(32)).is_err());
        assert!(parse_ticket_secret(&format!("0x{}", "ab".repeat(31))).is_err());
    }

    /// The flush policy: nothing below the target while young; a batch at
    /// the target, at the flush age, or at once for a close near its
    /// valid_until; a lone close goes to the vault itself.
    #[tokio::test]
    async fn the_queue_flushes_at_the_target_the_age_or_a_deadline() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let worker = worker(store.clone());
        let config = config();
        let first = queue(&store, 1, NOW + 7_200, NOW);
        worker.tick(NOW + 10).await.unwrap();
        assert!(state(&worker).sent.is_empty());
        // At the flush age the lone close is sent to the vault directly.
        worker.tick(NOW + config.flush_age_seconds).await.unwrap();
        {
            let state = state(&worker);
            assert_eq!(state.sent.len(), 1);
            assert_eq!(state.sent[0].to, VAULT);
            assert_eq!(state.sent[0].gas, 360_000, "the estimate plus 20%");
        }
        assert_eq!(status(&store, &first), CloseRelayStatus::InFlight);
        confirm(&worker, NOW + config.flush_age_seconds + 5).await;
        let record = store.close_relay(&first).unwrap().unwrap();
        assert_eq!(record.status, CloseRelayStatus::Landed);
        assert_eq!(
            record.transaction_hash.as_deref(),
            Some(&*format!("0x{:064x}", 1))
        );

        // The target (4) sends at once, through the batcher, with the gas
        // bound plus intrinsic and calldata gas.
        let notes: Vec<_> = (10..14)
            .map(|note| queue(&store, note, NOW + 7_200, NOW + 1_000))
            .collect();
        worker.tick(NOW + 1_001).await.unwrap();
        {
            let state = state(&worker);
            let sent = &state.sent[1];
            assert_eq!(sent.to, BATCHER);
            assert_eq!(
                sent.gas,
                transaction_gas(&sent.data, 1_000_000 + 4 * BOUND_PER_ITEM)
            );
            assert_eq!(sent.max_priority_fee_per_gas, DEFAULT_PRIORITY_FEE_PER_GAS);
            assert_eq!(
                sent.max_fee_per_gas,
                2 * 1_000_000_000 + DEFAULT_PRIORITY_FEE_PER_GAS
            );
        }
        confirm(&worker, NOW + 1_010).await;
        for nullifier in &notes {
            assert_eq!(status(&store, nullifier), CloseRelayStatus::Landed);
        }

        // A close near its valid_until goes at once with whatever is queued.
        let young = queue(&store, 20, NOW + 7_200, NOW + 2_000);
        let urgent = queue(
            &store,
            21,
            NOW + 2_000 + config.urgent_margin_seconds,
            NOW + 2_000,
        );
        worker.tick(NOW + 2_001).await.unwrap();
        assert_eq!(state(&worker).sent.len(), 3);
        confirm(&worker, NOW + 2_010).await;
        assert_eq!(status(&store, &young), CloseRelayStatus::Landed);
        assert_eq!(status(&store, &urgent), CloseRelayStatus::Landed);

        // Past the cutoff a close is given back to its client, unsent.
        let late = queue(&store, 30, NOW + 3_000 + config.cutoff_seconds, NOW + 2_900);
        worker.tick(NOW + 3_000).await.unwrap();
        assert_eq!(status(&store, &late), CloseRelayStatus::Expired);
        assert_eq!(state(&worker).sent.len(), 3);
    }

    /// One bad proof reverts a batch: bisection isolates it, and the rest
    /// still go in one batch. Closes the vault would refuse are resolved
    /// without being sent: a closed note is done, a refused payout fails
    /// for good, a paused vault keeps the close queued.
    #[tokio::test]
    async fn simulation_bisects_and_classifies_before_sending() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let worker = worker(store.clone());
        let ok: Vec<_> = (1..=3)
            .map(|note| queue(&store, note, NOW + 7_200, NOW))
            .collect();
        let bad = queue(&store, 4, NOW + 7_200, NOW);
        let closed = queue(&store, 5, NOW + 7_200, NOW);
        let refused = queue(&store, 6, NOW + 7_200, NOW);
        let hungry = queue(&store, 7, NOW + 7_200, NOW);
        {
            let mut state = state(&worker);
            state.bad_proof.insert(4);
            state.closed.insert(5);
            state
                .refusals
                .insert(6, selector("NativeTransferFailed()").to_vec());
            state.cap_exceeded.insert(7);
        }
        worker.tick(NOW + 1).await.unwrap();
        {
            let state = state(&worker);
            // 7 closes, then halves until the bad proof is alone.
            assert_eq!(state.batch_calls[0], 7);
            assert!(state.batch_calls.len() > 1);
            assert_eq!(state.sent.len(), 1);
            assert_eq!(decode_items(&state.sent[0].data).len(), 3);
        }
        assert_eq!(status(&store, &bad), CloseRelayStatus::Failed);
        assert_eq!(status(&store, &closed), CloseRelayStatus::Closed);
        let refused_record = store.close_relay(&refused).unwrap().unwrap();
        assert_eq!(refused_record.status, CloseRelayStatus::Failed);
        assert!(refused_record
            .detail
            .unwrap()
            .contains("NativeTransferFailed"));
        let hungry_record = store.close_relay(&hungry).unwrap().unwrap();
        assert_eq!(hungry_record.status, CloseRelayStatus::Failed);
        assert!(hungry_record.detail.unwrap().contains("per-close cap"));
        confirm(&worker, NOW + 10).await;
        for nullifier in &ok {
            assert_eq!(status(&store, nullifier), CloseRelayStatus::Landed);
        }
        // Failed closes are never relayed again.
        state(&worker).refusals.clear();
        worker.tick(NOW + 5_000).await.unwrap();
        assert_eq!(state(&worker).sent.len(), 1);
        assert_eq!(status(&store, &refused), CloseRelayStatus::Failed);

        // A paused vault keeps the close queued, unsent and uncounted.
        let waiting = queue(&store, 8, NOW + 9_000, NOW);
        state(&worker).paused = true;
        worker.tick(NOW + 5_001).await.unwrap();
        let record = store.close_relay(&waiting).unwrap().unwrap();
        assert_eq!(record.status, CloseRelayStatus::Queued);
        assert_eq!(record.attempts, 0);
        state(&worker).paused = false;
        worker.tick(NOW + 5_002).await.unwrap();
        confirm(&worker, NOW + 5_010).await;
        assert_eq!(status(&store, &waiting), CloseRelayStatus::Landed);
    }

    /// A mined batch's ItemSkipped logs decide: a close another transaction
    /// closed first is done, one whose payout push failed is failed for
    /// good and never sent again; a batch that reverted as a whole puts its
    /// closes back, counted, until they fail. Unconfirmed receipts wait.
    #[tokio::test]
    async fn receipts_decide_landed_closed_failed_and_requeued() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let worker = worker(store.clone());
        let notes: Vec<_> = (1..=4)
            .map(|note| queue(&store, note, NOW + 7_200, NOW))
            .collect();
        state(&worker).hold = true;
        worker.tick(NOW + 1).await.unwrap();
        assert_eq!(state(&worker).sent.len(), 1);
        // While in flight, note 1 is closed by its owner and note 2's
        // destination starts refusing; then the batch is mined.
        let sent = {
            let mut state = state(&worker);
            state.closed.insert(1);
            state
                .refusals
                .insert(2, selector("NativeTransferFailed()").to_vec());
            state.sent[0].clone()
        };
        {
            let mut state = state(&worker);
            let hash = format!("0x{:064x}", 1);
            state.mine(&sent, &hash);
            state.pending_extra = 0;
            state.hold = false;
        }
        // Mined in the head block: one more block is needed.
        worker.tick(NOW + 2).await.unwrap();
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::InFlight);
        confirm(&worker, NOW + 3).await;
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::Closed);
        assert_eq!(status(&store, &notes[1]), CloseRelayStatus::Failed);
        assert_eq!(status(&store, &notes[2]), CloseRelayStatus::Landed);
        assert_eq!(status(&store, &notes[3]), CloseRelayStatus::Landed);
        // Nothing is sent again.
        worker.tick(NOW + 5_000).await.unwrap();
        assert_eq!(state(&worker).sent.len(), 1);

        // A batch that reverts as a whole: back to the queue, counted, and
        // failed after max_attempts.
        let again: Vec<_> = (11..=14)
            .map(|note| queue(&store, note, NOW + 9_000, NOW))
            .collect();
        let max = config().max_attempts;
        for attempt in 0..max {
            let now = NOW + 6_000 + u64::from(attempt) * 100;
            state(&worker).hold = true;
            worker.tick(now).await.unwrap();
            let sent = state(&worker).sent.last().cloned().unwrap();
            {
                let mut state = state(&worker);
                // Mined as a revert (BatchOutOfGas, say).
                state.head += 1;
                state.nonce += 1;
                state.pending_extra = 0;
                let hash = format!("0x{:064x}", state.sent.len());
                let block = state.head;
                state.receipts.insert(
                    hash.clone(),
                    Receipt {
                        transaction_hash: hash,
                        block_number: block,
                        success: false,
                        logs: vec![],
                    },
                );
                state.hold = false;
            }
            assert_eq!(sent.to, BATCHER);
            confirm(&worker, now + 10).await;
            let record = store.close_relay(&again[0]).unwrap().unwrap();
            assert_eq!(record.attempts, attempt + 1);
            assert_eq!(record.status, CloseRelayStatus::Queued);
        }
        worker.tick(NOW + 9_000 - 1_000).await.unwrap();
        for nullifier in &again {
            assert_eq!(status(&store, nullifier), CloseRelayStatus::Failed);
        }
    }

    /// Everything the relay does survives a restart: queued closes, a batch
    /// whose send never reached the node (its closes go back and are sent
    /// again at the same nonce), a stuck transaction (replaced at the same
    /// nonce with higher fees) and a nonce consumed by a transaction whose
    /// hash was lost (resolved from the notes, never sent again).
    #[tokio::test]
    async fn restarts_resume_unsent_stuck_and_lost_transactions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.db");
        let store = Arc::new(NullifierStore::new(&path).unwrap());
        let notes: Vec<_> = (1..=4)
            .map(|note| queue(&store, note, NOW + 7_200, NOW))
            .collect();
        drop(store);

        // The send fails without reaching the node.
        let store = Arc::new(NullifierStore::new(&path).unwrap());
        assert_eq!(store.queued_close_relays(10).unwrap().len(), 4);
        let first = worker(store.clone());
        state(&first).fail_send = true;
        first.tick(NOW + 1).await.unwrap();
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::InFlight);
        let batch = store.pending_relay_batch().unwrap().unwrap();
        assert!(batch.tx_hashes.is_empty());
        drop(first);
        drop(store);

        // Restarted: the node holds nothing at the nonce, so the closes go
        // back to the queue and the next tick sends them again.
        let store = Arc::new(NullifierStore::new(&path).unwrap());
        let second = worker(store.clone());
        second.tick(NOW + 2).await.unwrap();
        assert!(store.pending_relay_batch().unwrap().is_none());
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::Queued);
        state(&second).hold = true;
        second.tick(NOW + 3).await.unwrap();
        let stuck = store.pending_relay_batch().unwrap().unwrap();
        assert_eq!(stuck.tx_hashes.len(), 1);
        // Stuck in the pool: replaced after bump_after_seconds with 25%
        // higher fees, at the same nonce.
        second.tick(NOW + 10).await.unwrap();
        assert_eq!(state(&second).sent.len(), 1);
        second
            .tick(NOW + 3 + config().bump_after_seconds)
            .await
            .unwrap();
        {
            let state = state(&second);
            assert_eq!(state.sent.len(), 2);
            assert_eq!(state.sent[1].nonce, state.sent[0].nonce);
            assert_eq!(state.sent[1].data, state.sent[0].data);
            assert_eq!(
                state.sent[1].max_fee_per_gas,
                state.sent[0].max_fee_per_gas * 125 / 100
            );
        }
        let bumped = store.pending_relay_batch().unwrap().unwrap();
        assert_eq!(bumped.tx_hashes.len(), 2);
        drop(second);
        drop(store);

        // Restarted again: the replacement was mined, but the receipt RPC
        // never returns it (a lost hash); after the grace period the closes
        // are resolved from their notes' status, never sent again.
        let store = Arc::new(NullifierStore::new(&path).unwrap());
        let third = worker(store.clone());
        {
            let mut state = state(&third);
            state.nonce = 1;
            state.closed.extend([1, 2, 3]);
        }
        third.tick(NOW + 200).await.unwrap();
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::InFlight);
        third
            .tick(NOW + 3 + config().bump_after_seconds + LOST_RECEIPT_GRACE_SECONDS)
            .await
            .unwrap();
        assert_eq!(status(&store, &notes[0]), CloseRelayStatus::Closed);
        assert_eq!(status(&store, &notes[3]), CloseRelayStatus::Failed);
        assert!(state(&third).sent.is_empty());
    }

    /// The base fee above the cap holds the queue; nothing is sent.
    #[tokio::test]
    async fn a_base_fee_above_the_cap_holds_the_queue() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let worker = worker(store.clone());
        let nullifier = queue(&store, 1, NOW + 7_200, NOW);
        state(&worker).base_fee = config().max_fee_per_gas;
        worker.tick(NOW + 1_000).await.unwrap();
        assert!(state(&worker).sent.is_empty());
        assert_eq!(status(&store, &nullifier), CloseRelayStatus::Queued);
    }

    /// The store's enqueue: the same close again is the same record; another
    /// close at the nullifier, a ticket redeemed elsewhere, an unpaid ticket
    /// and an uncleared nullifier are refused.
    #[test]
    fn enqueue_is_idempotent_and_refuses_conflicts() {
        let store = NullifierStore::in_memory().unwrap();
        let nullifier = queue(&store, 1, NOW + 7_200, NOW);
        let record = store.close_relay(&nullifier).unwrap().unwrap();
        let same = store
            .enqueue_close_relay(&NewCloseRelay {
                public_inputs: &record.public_inputs,
                proof: &record.proof,
                ticket_hash: &record.ticket_hash,
                submission_digest: &record.submission_digest,
                now: NOW + 5,
            })
            .unwrap();
        assert_eq!(same, CloseRelayEnqueued::Existing(record.clone()));
        let code = |result: Result<CloseRelayEnqueued, ServerError>| {
            result.unwrap_err().error_code().to_string()
        };
        let mut other = record.public_inputs.clone();
        other.valid_until += 1;
        let digest = submission_digest(&other, &record.proof);
        assert_eq!(
            code(store.enqueue_close_relay(&NewCloseRelay {
                public_inputs: &other,
                proof: &record.proof,
                ticket_hash: &record.ticket_hash,
                submission_digest: &digest,
                now: NOW,
            })),
            "relay_conflict"
        );
        // The redeemed ticket for another note's close.
        let foreign = inputs(2, NOW + 7_200);
        store
            .reserve_clearance(&foreign.withdrawal_nullifier, "ownership_proof")
            .unwrap();
        let digest = submission_digest(&foreign, &record.proof);
        assert_eq!(
            code(store.enqueue_close_relay(&NewCloseRelay {
                public_inputs: &foreign,
                proof: &record.proof,
                ticket_hash: &record.ticket_hash,
                submission_digest: &digest,
                now: NOW,
            })),
            "relay_ticket_redeemed"
        );
        assert_eq!(
            code(store.enqueue_close_relay(&NewCloseRelay {
                public_inputs: &foreign,
                proof: &record.proof,
                ticket_hash: &ticket_hash_hex(&[0xee; 32]),
                submission_digest: &digest,
                now: NOW,
            })),
            "relay_ticket_unknown"
        );
        let counts = store.close_relay_counts().unwrap();
        assert_eq!(counts.get("queued"), Some(&1));
    }

    /// The JSON-RPC chain: reverts (with and without data) are told apart
    /// from transport errors, sends carry the relayer, nonce, chain and
    /// fees, and receipts decode.
    #[tokio::test]
    async fn the_rpc_chain_decodes_reverts_sends_and_receipts() {
        use axum::{routing::post, Json, Router};
        let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
        let app = |endpoint: &'static str| {
            let recorded = seen.clone();
            Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let recorded = recorded.clone();
                async move {
                    let mut request = request;
                    request["endpoint"] = endpoint.into();
                    recorded.lock().unwrap().push(request.clone());
                    let data = request["params"][0]["data"].as_str().unwrap_or_default();
                    let body = match request["method"].as_str().unwrap() {
                        "eth_call" if data.starts_with("0xdead") => json!({"jsonrpc":"2.0","id":1,
                            "error":{"code":3,"message":"execution reverted","data":"0x7a19ed05"}}),
                        "eth_call" if data.starts_with("0xbeef") => json!({"jsonrpc":"2.0","id":1,
                            "error":{"code":-32000,"message":"execution reverted"}}),
                        "eth_call" if data.starts_with("0xfeed") => json!({"jsonrpc":"2.0","id":1,
                            "error":{"code":-32603,"message":"header not found"}}),
                        "eth_call" => json!({"jsonrpc":"2.0","id":1,"result":"0x01"}),
                        "eth_sendTransaction" => json!({"jsonrpc":"2.0","id":1,
                            "result":format!("0x{}", "AB".repeat(32))}),
                        "eth_getTransactionReceipt" => json!({"jsonrpc":"2.0","id":1,"result":{
                            "blockNumber":"0x10","status":"0x1","logs":[{"address":VAULT.to_uppercase().replace("0X","0x"),
                            "topics":[topic(MUTUAL_CLOSE_EVENT)],"data":"0x00"}]}}),
                        "eth_getBlockByNumber" => json!({"jsonrpc":"2.0","id":1,
                            "result":{"number":"0x11","baseFeePerGas":"0x3b9aca00"}}),
                        "eth_getTransactionCount" => json!({"jsonrpc":"2.0","id":1,"result":"0x7"}),
                        _ => json!({"jsonrpc":"2.0","id":1,"result":"0x5208"}),
                    };
                    Json(body)
                }
            }),
        )
        };
        let mut urls = Vec::new();
        for endpoint in ["send", "read"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            urls.push(format!("http://{}", listener.local_addr().unwrap()));
            let app = app(endpoint);
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        }
        let mut config = config();
        config.rpc_url = urls[0].clone();
        config.read_rpc_url = Some(urls[1].clone());
        let chain = RpcRelayChain::new(&config, 11_155_111).unwrap();
        assert_eq!(chain.chain_ids().await.unwrap(), (0x5208, 0x5208));
        assert_eq!(
            chain.call(VAULT, &[0xde, 0xad]).await.unwrap(),
            CallOutcome::Revert(vec![0x7a, 0x19, 0xed, 0x05])
        );
        assert_eq!(
            chain.call(VAULT, &[0xbe, 0xef]).await.unwrap(),
            CallOutcome::Revert(vec![])
        );
        assert!(chain.call(VAULT, &[0xfe, 0xed]).await.is_err());
        assert_eq!(
            chain.call(VAULT, &[1]).await.unwrap(),
            CallOutcome::Success(vec![1])
        );
        assert_eq!(chain.nonce(true).await.unwrap(), 7);
        assert_eq!(chain.head().await.unwrap(), (0x11, 1_000_000_000));
        assert_eq!(chain.estimate_gas(VAULT, &[1]).await.unwrap(), 21_000);
        let hash = chain
            .send(&RelayTransaction {
                to: BATCHER.into(),
                data: vec![1, 2],
                gas: 100_000,
                nonce: 7,
                max_fee_per_gas: 3,
                max_priority_fee_per_gas: 2,
            })
            .await
            .unwrap();
        assert_eq!(hash, format!("0x{}", "ab".repeat(32)));
        let sent = seen
            .lock()
            .unwrap()
            .iter()
            .find(|request| request["method"] == "eth_sendTransaction")
            .cloned()
            .unwrap();
        assert_eq!(
            sent["params"][0],
            json!({"from":SENDER,"to":BATCHER,"data":"0x0102","gas":"0x186a0","nonce":"0x7",
                "value":"0x0","chainId":"0xaa36a7","maxFeePerGas":"0x3","maxPriorityFeePerGas":"0x2"})
        );
        // Sends and nonces go to the signing RPC, everything else to the
        // read RPC.
        for request in seen.lock().unwrap().iter() {
            let method = request["method"].as_str().unwrap();
            let expected = if matches!(method, "eth_sendTransaction" | "eth_getTransactionCount") {
                "send"
            } else if method == "eth_chainId" {
                continue;
            } else {
                "read"
            };
            assert_eq!(request["endpoint"], expected, "{method}");
        }
        let receipt = chain.receipt(&hash).await.unwrap().unwrap();
        assert_eq!(receipt.block_number, 16);
        assert!(receipt.success);
        assert_eq!(receipt.logs[0].address, VAULT);
    }
}
