//! Operator status for `zkapi-activated`.
//!
//! The worker publishes a snapshot after every poll. The handlers recompute
//! queue ages, blocked durations and poll staleness at request time, so the
//! status escalates even while polls stall:
//!
//! - `GET /livez`: the poll loop is alive (container healthcheck only);
//! - `GET /health`: 503 for any critical condition (alerting);
//! - `GET /status`: the full JSON snapshot.
//!
//! Bind the listener to loopback or a private network only.

use std::sync::{Arc, RwLock};

use axum::{
    extract::State,
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

use crate::challenge_status::{unix_now, BlockedReason, Severity};

/// v1: proved activation batches of vault revision 4.
pub const STATUS_SCHEMA: &str = "zkapi-activated-status/v1";

pub type ActivationStatusHandle = Arc<RwLock<ActivationStatus>>;

/// What the worker is doing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkerState {
    /// No poll has completed since the worker started.
    Starting,
    /// Every recorded note is activated.
    Idle,
    /// A larger aligned batch is filling; the smaller one is activated at
    /// `next_batch.activate_by` at the latest.
    Waiting,
    /// The insertion proof of the next batch is being computed.
    Proving,
    /// An activation is pending on the worker's nonce.
    Submitted,
    /// The worker's activation mined; its nonce is held until it is
    /// confirmed (a reorganization may undo it).
    Confirming,
    /// The cursor, root or recorded notes moved under a prepared batch
    /// (another activation, a leaf retirement or a reorganization): rebuilt
    /// from fresh state.
    Rebuilding,
    /// The vault is paused: activation reverts until it is unpaused.
    Paused,
    /// `--dry-run`: the batch simulated, nothing was sent.
    DryRun,
    /// Something prevents progress; see `blocked_reason`.
    Blocked,
}

/// Why the worker cannot make progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationBlocked {
    RpcError,
    IndexerUnavailable,
    IndexerInvalidResponse,
    /// The indexer's siblings of the cursor's slot do not hash to the
    /// vault's root (it lags, or serves another fork).
    IndexerPathBehind,
    /// The vault's reads disagree (a recorded note below nextNoteId reads
    /// Uninitialized): a reorganization under the read, retried.
    VaultInconsistent,
    /// The vault's `activator()` is not the worker's sender, so it refuses
    /// the worker's `activateNotes` (`NotActivator()`): nothing is sent until
    /// the owner calls `setActivator` with the sender.
    NotActivator,
    ProvingFailed,
    /// The adapter refused the worker's insertion proof (`InvalidProof()`).
    ProofRejected,
    SimulationReverted,
    SignerRefused,
    SendAmbiguous,
    BaseFeeAboveFeeCap,
    BaseFeeAboveMaxFee,
    FeeCapReached,
    TipCapReached,
    FeeReserveHeld,
    TxFeeCapReached,
    TxFeeAboveCap,
    UpstreamTxFeeCap,
    InsufficientBalance,
    NonceConflict,
}

impl ActivationBlocked {
    /// The worker's reason for a blocked reason of the shared transaction
    /// lane (fee planning and signer refusals).
    pub fn from_lane(reason: BlockedReason) -> Self {
        match reason {
            BlockedReason::SignerRefused => Self::SignerRefused,
            BlockedReason::SendAmbiguous => Self::SendAmbiguous,
            BlockedReason::BaseFeeAboveFeeCap => Self::BaseFeeAboveFeeCap,
            BlockedReason::BaseFeeAboveMaxFee => Self::BaseFeeAboveMaxFee,
            BlockedReason::FeeCapReached => Self::FeeCapReached,
            BlockedReason::TipCapReached => Self::TipCapReached,
            BlockedReason::FeeReserveHeld => Self::FeeReserveHeld,
            BlockedReason::TxFeeCapReached => Self::TxFeeCapReached,
            BlockedReason::TxFeeAboveCap => Self::TxFeeAboveCap,
            BlockedReason::UpstreamTxFeeCap => Self::UpstreamTxFeeCap,
            BlockedReason::InsufficientBalance => Self::InsufficientBalance,
            BlockedReason::NonceConflict => Self::NonceConflict,
            BlockedReason::SimulationReverted => Self::SimulationReverted,
            _ => Self::RpcError,
        }
    }

    /// Conditions that waiting cannot resolve; all others escalate with time.
    pub fn is_immediately_critical(self) -> bool {
        matches!(
            self,
            Self::ProofRejected
                | Self::IndexerInvalidResponse
                | Self::SignerRefused
                | Self::UpstreamTxFeeCap
        )
    }
}

/// Alarm thresholds, in seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActivationAlarmPolicy {
    /// The oldest pending note has waited this long: a warning...
    pub pending_warning_seconds: u64,
    /// ...and this long: critical (the worker is not keeping up; consider
    /// the `activateNotesOnChain` fallback, open to anyone from
    /// `chain.activation_fallback_opens_at`).
    pub pending_critical_seconds: u64,
    pub blocked_warning_seconds: u64,
    pub critical_blocked_seconds: u64,
    pub stale_poll_seconds: u64,
    /// Before the first successful poll, status is a warning for this long.
    pub startup_grace_seconds: u64,
    /// None: the gas of one 16-note activation times the fee cap.
    pub min_sender_balance_wei: Option<u128>,
}

impl Default for ActivationAlarmPolicy {
    fn default() -> Self {
        Self {
            pending_warning_seconds: 600,
            pending_critical_seconds: 3_600,
            blocked_warning_seconds: 120,
            critical_blocked_seconds: 1_800,
            stale_poll_seconds: 300,
            startup_grace_seconds: 300,
            min_sender_balance_wei: None,
        }
    }
}

impl ActivationAlarmPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.pending_critical_seconds < self.pending_warning_seconds {
            return Err("pending critical seconds must be at least pending warning seconds".into());
        }
        if self.critical_blocked_seconds < self.blocked_warning_seconds {
            return Err("critical blocked seconds must be at least blocked warning seconds".into());
        }
        if self.stale_poll_seconds == 0 {
            return Err("stale poll seconds must be positive".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationStatus {
    pub schema: String,
    pub status: Severity,
    /// Human-readable reasons for a warning or critical status.
    pub alarms: Vec<String>,
    pub generated_at: u64,
    pub started_at: u64,
    pub version: String,
    pub state: WorkerState,
    pub detail: Option<String>,
    pub blocked_reason: Option<ActivationBlocked>,
    pub blocked_since: Option<u64>,
    pub chain: ActivationChainStatus,
    pub queue: QueueStatus,
    pub next_batch: Option<NextBatchStatus>,
    pub pending_call: Option<PendingCallStatus>,
    pub last_batch: Option<BatchRecord>,
    pub totals: ActivationTotals,
    pub sender: ActivationSenderStatus,
    pub poll: ActivationPollStatus,
    pub config_warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationChainStatus {
    pub chain_id: u64,
    pub vault: String,
    pub latest_block: Option<u64>,
    pub latest_block_timestamp: Option<u64>,
    pub base_fee_per_gas_wei: Option<String>,
    pub confirmations: u64,
    pub current_root: Option<Felt252>,
    pub paused: Option<bool>,
    /// The vault's `activator()`: the only sender whose `activateNotes` it
    /// accepts.
    pub activator: Option<String>,
    /// The vault's `activationFallbackOpensAt()`: from then on anyone may
    /// activate with `activateNotesOnChain`, until the next proved activation
    /// (an hour after it).
    pub activation_fallback_opens_at: Option<u64>,
}

/// The recorded notes that wait for activation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueStatus {
    pub activation_cursor: Option<u32>,
    pub next_note_id: Option<u32>,
    /// `nextNoteId - activationCursor`.
    pub pending_notes: u64,
    /// When the worker first saw the oldest pending note.
    pub oldest_pending_seen_at: Option<u64>,
    pub oldest_pending_age_seconds: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextBatchStatus {
    pub first_note_id: u32,
    /// The size activated now, or at `activate_by` while a larger aligned
    /// batch fills.
    pub size: usize,
    /// The largest batch aligned at the cursor.
    pub aligned_size: usize,
    pub activate_by: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingCallStatus {
    pub nonce: u64,
    pub first_note_id: u32,
    pub size: u32,
    pub transaction_hash: Option<String>,
    pub attempts: u32,
    pub max_fee_per_gas_wei: Option<String>,
    pub max_priority_fee_per_gas_wei: Option<String>,
    pub gas_limit: Option<u64>,
    pub submitted_block: Option<u64>,
}

/// How the transaction that consumed the worker's nonce ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BatchOutcome {
    /// It activated the batch (`NotesActivated` from the vault).
    Activated,
    /// It mined and reverted (another activation or a retirement landed
    /// first, or its sender was no longer the activator): nothing was
    /// activated by it.
    Reverted,
    /// The nonce was consumed by an attempt whose receipt the worker does
    /// not know (an ambiguous send without a hash).
    Unknown,
}

/// The last activation the worker's nonce consumed at confirmation depth.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchRecord {
    pub first_note_id: u32,
    pub size: u32,
    pub outcome: BatchOutcome,
    pub proving_ms: u64,
    pub gas_used: Option<u64>,
    pub transaction_hash: Option<String>,
    pub block: Option<u64>,
    pub confirmed_at: u64,
}

/// Counters since the checkpoint was created.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationTotals {
    pub batches_activated_total: u64,
    pub notes_activated_total: u64,
    pub batches_1_total: u64,
    pub batches_4_total: u64,
    pub batches_16_total: u64,
    /// The worker's transactions that mined and reverted.
    pub reverted_total: u64,
    /// Prepared batches discarded because the cursor or root moved.
    pub stale_rebuilds_total: u64,
    pub proofs_total: u64,
    pub proving_ms_total: u64,
    pub gas_used_total: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationSenderStatus {
    pub address: String,
    pub balance_wei: Option<String>,
    pub balance_observed_at: Option<u64>,
    pub min_balance_wei: String,
    pub max_fee_per_gas_wei: String,
    pub max_priority_fee_per_gas_wei: String,
    pub tx_fee_cap_wei: String,
    /// The signer's transaction fee cap, from `zkapi_signerStatus` or a
    /// `tx_fee_above_cap` refusal.
    pub signer_tx_fee_cap_wei: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivationPollStatus {
    pub last_started_at: Option<u64>,
    pub last_completed_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
    pub stale: bool,
}

impl ActivationStatus {
    pub fn initial(
        chain: ActivationChainStatus,
        sender: ActivationSenderStatus,
        started_at: u64,
    ) -> Self {
        Self {
            schema: STATUS_SCHEMA.to_string(),
            status: Severity::Warning,
            alarms: Vec::new(),
            generated_at: started_at,
            started_at,
            version: env!("CARGO_PKG_VERSION").to_string(),
            state: WorkerState::Starting,
            detail: None,
            blocked_reason: None,
            blocked_since: None,
            chain,
            queue: QueueStatus::default(),
            next_batch: None,
            pending_call: None,
            last_batch: None,
            totals: ActivationTotals::default(),
            sender,
            poll: ActivationPollStatus::default(),
            config_warnings: Vec::new(),
        }
    }
}

/// The snapshot with ages, staleness and severity as of `now`.
pub fn evaluate(
    snapshot: &ActivationStatus,
    policy: &ActivationAlarmPolicy,
    now: u64,
) -> ActivationStatus {
    let mut status = snapshot.clone();
    status.generated_at = now;
    let mut alarms: Vec<(Severity, String)> = Vec::new();
    let in_grace = now.saturating_sub(status.started_at) < policy.startup_grace_seconds;
    match status.poll.last_success_at {
        None if in_grace => alarms.push((
            Severity::Warning,
            "no successful poll yet (starting)".into(),
        )),
        None => alarms.push((
            Severity::Critical,
            format!(
                "no successful poll in the {} s since startup",
                now.saturating_sub(status.started_at)
            ),
        )),
        Some(at) if now.saturating_sub(at) > policy.stale_poll_seconds => {
            status.poll.stale = true;
            alarms.push((
                Severity::Critical,
                format!("last successful poll {} s ago", now.saturating_sub(at)),
            ));
        }
        Some(_) => status.poll.stale = false,
    }
    if let Some(seen) = status
        .queue
        .oldest_pending_seen_at
        .filter(|_| status.queue.pending_notes > 0)
    {
        let age = now.saturating_sub(seen);
        status.queue.oldest_pending_age_seconds = Some(age);
        if age > policy.pending_critical_seconds {
            alarms.push((
                Severity::Critical,
                format!("the oldest pending note has waited {age} s for activation"),
            ));
        } else if age > policy.pending_warning_seconds {
            alarms.push((
                Severity::Warning,
                format!("the oldest pending note has waited {age} s for activation"),
            ));
        }
    } else {
        status.queue.oldest_pending_age_seconds = None;
    }
    if let (Some(reason), Some(since)) = (status.blocked_reason, status.blocked_since) {
        let blocked = now.saturating_sub(since);
        let label = serde_json::to_value(reason)
            .ok()
            .and_then(|value| value.as_str().map(str::to_string))
            .unwrap_or_default();
        if reason.is_immediately_critical() || blocked > policy.critical_blocked_seconds {
            alarms.push((
                Severity::Critical,
                format!("blocked ({label}) for {blocked} s"),
            ));
        } else if blocked > policy.blocked_warning_seconds {
            alarms.push((
                Severity::Warning,
                format!("blocked ({label}) for {blocked} s"),
            ));
        }
    }
    let below_minimum = match (
        status
            .sender
            .balance_wei
            .as_deref()
            .and_then(|value| value.parse::<u128>().ok()),
        status.sender.min_balance_wei.parse::<u128>().ok(),
    ) {
        (Some(balance), Some(minimum)) => balance < minimum,
        _ => false,
    };
    if below_minimum {
        alarms.push((
            Severity::Warning,
            "sender balance below the minimum for one 16-note activation".into(),
        ));
    }
    status.status = alarms
        .iter()
        .map(|(severity, _)| *severity)
        .max()
        .unwrap_or(Severity::Ok);
    status.alarms = alarms
        .into_iter()
        .map(|(_, message)| message)
        .chain(status.config_warnings.iter().cloned())
        .collect();
    status
}

#[derive(Clone)]
struct StatusState {
    handle: ActivationStatusHandle,
    policy: ActivationAlarmPolicy,
}

pub fn router(handle: ActivationStatusHandle, policy: ActivationAlarmPolicy) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(StatusState { handle, policy })
}

fn snapshot(state: &StatusState) -> ActivationStatus {
    match state.handle.read() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    }
}

fn no_store(code: StatusCode, body: serde_json::Value) -> Response {
    let mut response = (code, Json(body)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

async fn livez(State(state): State<StatusState>) -> Response {
    let now = unix_now();
    let snapshot = snapshot(&state);
    let last = snapshot
        .poll
        .last_completed_at
        .or(snapshot.poll.last_started_at)
        .unwrap_or(snapshot.started_at);
    let alive = now.saturating_sub(last) <= state.policy.stale_poll_seconds;
    no_store(
        if alive {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        serde_json::json!({
            "status": if alive { "alive" } else { "stale" },
            "generated_at": now,
            "last_started_at": snapshot.poll.last_started_at,
            "last_completed_at": snapshot.poll.last_completed_at,
        }),
    )
}

async fn health(State(state): State<StatusState>) -> Response {
    let now = unix_now();
    let current = evaluate(&snapshot(&state), &state.policy, now);
    no_store(
        if current.status == Severity::Critical {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::OK
        },
        serde_json::json!({
            "status": current.status,
            "generated_at": now,
            "state": current.state,
            "pending_notes": current.queue.pending_notes,
            "oldest_pending_age_seconds": current.queue.oldest_pending_age_seconds,
            "alarms": current.alarms,
        }),
    )
}

async fn status(State(state): State<StatusState>) -> Response {
    let current = evaluate(&snapshot(&state), &state.policy, unix_now());
    no_store(
        StatusCode::OK,
        serde_json::to_value(current).unwrap_or_default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn polled(now: u64) -> ActivationStatus {
        let mut status = ActivationStatus::initial(
            ActivationChainStatus::default(),
            ActivationSenderStatus {
                min_balance_wei: "0".into(),
                ..Default::default()
            },
            now - 1_000,
        );
        status.poll.last_success_at = Some(now);
        status
    }

    #[test]
    fn severity_follows_queue_age_blocking_and_staleness() {
        let policy = ActivationAlarmPolicy::default();
        policy.validate().unwrap();
        let now = 2_000_000_000;
        assert_eq!(evaluate(&polled(now), &policy, now).status, Severity::Ok);
        // The oldest pending note's wait escalates.
        let mut waiting = polled(now);
        waiting.queue.pending_notes = 3;
        waiting.queue.oldest_pending_seen_at = Some(now - 601);
        let evaluated = evaluate(&waiting, &policy, now);
        assert_eq!(evaluated.status, Severity::Warning);
        assert_eq!(evaluated.queue.oldest_pending_age_seconds, Some(601));
        waiting.queue.oldest_pending_seen_at = Some(now - 3_601);
        assert_eq!(evaluate(&waiting, &policy, now).status, Severity::Critical);
        // An empty queue has no age, whatever the last observation.
        waiting.queue.pending_notes = 0;
        assert_eq!(evaluate(&waiting, &policy, now).status, Severity::Ok);
        // Blocking escalates with time, a rejected proof at once.
        let mut blocked = polled(now);
        blocked.blocked_reason = Some(ActivationBlocked::IndexerPathBehind);
        blocked.blocked_since = Some(now - 60);
        assert_eq!(evaluate(&blocked, &policy, now).status, Severity::Ok);
        blocked.blocked_since = Some(now - 121);
        assert_eq!(evaluate(&blocked, &policy, now).status, Severity::Warning);
        blocked.blocked_since = Some(now - 1_801);
        assert_eq!(evaluate(&blocked, &policy, now).status, Severity::Critical);
        blocked.blocked_reason = Some(ActivationBlocked::ProofRejected);
        blocked.blocked_since = Some(now);
        let evaluated = evaluate(&blocked, &policy, now);
        assert_eq!(evaluated.status, Severity::Critical);
        assert!(
            evaluated.alarms[0].contains("proof_rejected"),
            "{:?}",
            evaluated.alarms
        );
        // A stale poll loop is critical; a fresh start only warns.
        let stale = polled(now - 301);
        let evaluated = evaluate(&stale, &policy, now);
        assert_eq!(evaluated.status, Severity::Critical);
        assert!(evaluated.poll.stale);
        let starting = ActivationStatus::initial(
            ActivationChainStatus::default(),
            ActivationSenderStatus::default(),
            now - 10,
        );
        assert_eq!(evaluate(&starting, &policy, now).status, Severity::Warning);
        assert_eq!(
            evaluate(&starting, &policy, now + 400).status,
            Severity::Critical
        );
        // A low sender balance warns.
        let mut poor = polled(now);
        poor.sender.balance_wei = Some("5".into());
        poor.sender.min_balance_wei = "6".into();
        assert_eq!(evaluate(&poor, &policy, now).status, Severity::Warning);
    }

    #[test]
    fn lane_reasons_map_to_the_workers() {
        assert_eq!(
            ActivationBlocked::from_lane(BlockedReason::TxFeeCapReached),
            ActivationBlocked::TxFeeCapReached
        );
        assert_eq!(
            ActivationBlocked::from_lane(BlockedReason::SignerRefused),
            ActivationBlocked::SignerRefused
        );
        assert!(ActivationBlocked::SignerRefused.is_immediately_critical());
        assert!(!ActivationBlocked::FeeCapReached.is_immediately_critical());
        // The owner's setActivator resolves it: it escalates with time.
        assert!(!ActivationBlocked::NotActivator.is_immediately_critical());
        assert_eq!(
            serde_json::to_value(ActivationBlocked::NotActivator).unwrap(),
            "not_activator"
        );
        assert!(ActivationAlarmPolicy {
            pending_critical_seconds: 1,
            pending_warning_seconds: 2,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
