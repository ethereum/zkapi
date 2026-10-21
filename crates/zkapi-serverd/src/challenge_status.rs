//! Operator status for `zkapi-challenged`.
//!
//! The daemon publishes a snapshot after every poll. The HTTP handlers
//! recompute remaining times, deadline severities and staleness at request
//! time, so escalation advances even while polls stall:
//!
//! - `GET /livez`: the poll loop is alive (container healthcheck only);
//! - `GET /health`: 503 for any critical condition (alerting);
//! - `GET /status`: the full JSON snapshot.
//!
//! Bind the listener to loopback or a private network only and never route it
//! through the public gateway: the status tells an attacker when challenges
//! are blocked.

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

use crate::watcher::{CallKind, SettlementProgress};

/// v2: concession escapes (defeats, raises and leaf retirements).
pub const STATUS_SCHEMA: &str = "zkapi-challenged-status/v2";
/// Wall time without a new head block before the status warns, then alarms.
pub const HEAD_AGE_WARNING_SECONDS: u64 = 120;
pub const HEAD_AGE_CRITICAL_SECONDS: u64 = 600;
/// Confirmed blocks not yet scanned for escape events.
pub const SCAN_LAG_WARNING_BLOCKS: u64 = 50;
pub const SCAN_LAG_CRITICAL_BLOCKS: u64 = 300;
/// A recorded missed deadline stays a critical alarm this long, also when
/// its escape was paid out and the obligation retired within one poll.
pub const MISSED_ALARM_SECONDS: u64 = 3_600;
const DEFAULT_WARNING_REMAINING_SECONDS: u64 = 43_200;
const DEFAULT_CRITICAL_REMAINING_SECONDS: u64 = 21_600;

pub type StatusHandle = Arc<RwLock<ChallengeStatus>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Ok,
    Warning,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObligationState {
    /// Tracked, but no poll has evaluated it since the daemon started.
    Unevaluated,
    /// Nothing is due: no verified evidence at the successor nullifier, and
    /// the concession covers what is owed at the escaped one. The honest
    /// outcome.
    NothingDue,
    /// What is owed at the escaped nullifier is not final: a request that may
    /// have been delivered has not settled. The raise is decided once it
    /// settles, or at `deadline - raise_lead_seconds` at the latest.
    AwaitingSettlement,
    /// A defeat or a raise is due but not pending.
    Ready,
    /// A defeat, raise or leaf retirement is pending on the obligation's nonce.
    Submitted,
    /// A defeat's nonce was consumed while the escape is still pending.
    MinedUnconfirmed,
    /// The concession covers what is owed (after a raise); the escape is
    /// watched for successor evidence until its deadline.
    Raised,
    /// The escape is gone at the latest block, not yet at confirmation
    /// depth. With evidence it may have been paid out, not defeated.
    ResolvedUnconfirmed,
    /// The deadline passed while a defeat or a raise was due.
    Missed,
    /// The deadline passed and nothing was due.
    ExpiredNothingDue,
    /// After a missed defeat the escape was paid out: the closed note's leaf
    /// is being retired (`retireClosedLeaf`, `--retire-on-miss`).
    RetiringLeaf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    /// A verified request proof at the successor nullifier: a defeat.
    Successor,
    /// The request at the escaped nullifier settled; `owed` is its charge.
    Settled,
    /// It may have been delivered and has not settled; `owed` is its bound
    /// from the raise lead on.
    Unsettled,
    /// Its key was never issued or never delivered: nothing is owed.
    NeverDelivered,
    /// A reservation without a lease row: nothing is owed.
    ReservedWithoutLease,
    /// The escaped nullifier is reserved only for a clearance.
    Clearance,
    /// No request at the escaped nullifier.
    Unknown,
    /// Evidence rows exist that do not verify.
    Corrupt,
    /// The server database could not be read.
    Unavailable,
    /// The note's leaf, being retired after a missed defeat.
    Leaf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockedReason {
    EvidenceInvalid,
    EvidenceDbError,
    IndexerUnavailable,
    IndexerInvalidResponse,
    IndexerPathBehind,
    IndexerDiverged,
    RpcError,
    SimulationReverted,
    SignerRefused,
    SendAmbiguous,
    BaseFeeAboveFeeCap,
    /// The signer saw a base fee above the bid's maxFeePerGas (a stale bid).
    BaseFeeAboveMaxFee,
    FeeCapReached,
    TipCapReached,
    /// A pending challenge spent the replacements allowed before the critical
    /// threshold; the remaining fee headroom is kept for that threshold.
    FeeReserveHeld,
    /// The transaction fee ceiling (gas limit x maxFeePerGas) leaves no
    /// includable bid or valid replacement.
    TxFeeCapReached,
    /// The signer refused a bid above its transaction fee cap.
    TxFeeAboveCap,
    /// The signer's upstream node refused the transaction fee (its RPC fee cap).
    UpstreamTxFeeCap,
    InsufficientBalance,
    NonceConflict,
    NonceBlocked,
}

impl BlockedReason {
    /// Conditions that waiting cannot resolve; all others escalate with time.
    pub fn is_immediately_critical(self) -> bool {
        matches!(
            self,
            Self::EvidenceInvalid
                | Self::EvidenceDbError
                | Self::IndexerInvalidResponse
                | Self::IndexerDiverged
                | Self::SignerRefused
                | Self::UpstreamTxFeeCap
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndexerState {
    Unknown,
    Consistent,
    Lagging,
    Diverged,
    Unavailable,
}

/// Alarm thresholds; every duration is in seconds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AlarmPolicy {
    /// None: challengePeriod/2, or 12 hours while the period is unknown.
    pub warning_remaining_seconds: Option<u64>,
    /// None: challengePeriod/4, or 6 hours while the period is unknown.
    pub critical_remaining_seconds: Option<u64>,
    pub blocked_warning_seconds: u64,
    pub critical_blocked_seconds: u64,
    pub settlement_overdue_seconds: u64,
    pub indexer_divergence_seconds: u64,
    pub indexer_divergence_polls: u32,
    pub indexer_lag_warning_blocks: u64,
    pub stale_poll_seconds: u64,
    /// Before the first successful poll, status is a warning for this long.
    pub startup_grace_seconds: u64,
    /// Sender and indexer observations run at most this often.
    pub observe_interval_seconds: u64,
    /// None: 7.6M gas times the fee cap.
    pub min_sender_balance_wei: Option<u128>,
}

impl Default for AlarmPolicy {
    fn default() -> Self {
        Self {
            warning_remaining_seconds: None,
            critical_remaining_seconds: None,
            blocked_warning_seconds: 120,
            critical_blocked_seconds: 1800,
            settlement_overdue_seconds: 3600,
            indexer_divergence_seconds: 600,
            indexer_divergence_polls: 3,
            indexer_lag_warning_blocks: 64,
            stale_poll_seconds: 300,
            startup_grace_seconds: 300,
            observe_interval_seconds: 15,
            min_sender_balance_wei: None,
        }
    }
}

/// Remaining-time thresholds in effect for the vault's challenge period.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemainingThresholds {
    pub warning_remaining_seconds: u64,
    pub critical_remaining_seconds: u64,
}

impl AlarmPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if let (Some(warning), Some(critical)) = (
            self.warning_remaining_seconds,
            self.critical_remaining_seconds,
        ) {
            if critical >= warning {
                return Err(
                    "critical remaining seconds must be below warning remaining seconds".into(),
                );
            }
        }
        if self.critical_blocked_seconds < self.blocked_warning_seconds {
            return Err("critical blocked seconds must be at least blocked warning seconds".into());
        }
        if self.stale_poll_seconds == 0 || self.indexer_divergence_polls == 0 {
            return Err("stale poll seconds and indexer divergence polls must be positive".into());
        }
        Ok(())
    }

    pub fn remaining_thresholds(&self, challenge_period: Option<u64>) -> RemainingThresholds {
        let warning = self.warning_remaining_seconds.unwrap_or(
            challenge_period.map_or(DEFAULT_WARNING_REMAINING_SECONDS, |period| period / 2),
        );
        let critical = self
            .critical_remaining_seconds
            .unwrap_or(
                challenge_period.map_or(DEFAULT_CRITICAL_REMAINING_SECONDS, |period| period / 4),
            )
            .min(warning);
        RemainingThresholds {
            warning_remaining_seconds: warning,
            critical_remaining_seconds: critical,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChallengeStatus {
    pub schema: String,
    pub status: Severity,
    /// Human-readable reasons for a warning or critical status.
    pub alarms: Vec<String>,
    pub generated_at: u64,
    pub started_at: u64,
    pub version: String,
    pub thresholds: RemainingThresholds,
    pub chain: ChainStatus,
    pub poll: PollStatus,
    pub sender: SenderStatus,
    pub indexer: IndexerStatus,
    pub obligations: Vec<ObligationStatus>,
    pub detached_nonces: Vec<DetachedNonceStatus>,
    /// Missed defeats and missed raises.
    pub missed_total: u64,
    /// Missed defeats (§5.4): verified evidence at the successor nullifier
    /// existed before the deadline and the escape was finalized.
    #[serde(default)]
    pub escapes_finalized_with_successor_evidence_total: u64,
    /// Missed raises: more than the concession was owed at finalization.
    #[serde(default)]
    pub missed_raises_total: u64,
    pub last_missed: Option<MissedRecord>,
    pub config_warnings: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainStatus {
    pub chain_id: u64,
    pub vault: String,
    pub latest_block: Option<u64>,
    pub latest_block_timestamp: Option<u64>,
    /// Wall time at which `latest_block` was first observed.
    pub head_observed_at: Option<u64>,
    /// Wall time since a new head block was last observed.
    pub head_age_seconds: Option<u64>,
    pub base_fee_per_gas_wei: Option<String>,
    pub scan_next_block: u64,
    /// Confirmed blocks not yet scanned for escape events.
    pub scan_lag_blocks: Option<u64>,
    pub confirmations: u64,
    pub challenge_period_seconds: Option<u64>,
    pub vault_root: Option<Felt252>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PollStatus {
    pub last_started_at: Option<u64>,
    pub last_completed_at: Option<u64>,
    pub last_scan_success_at: Option<u64>,
    pub last_success_at: Option<u64>,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
    pub stale: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SenderStatus {
    pub address: String,
    pub balance_wei: Option<String>,
    pub balance_observed_at: Option<u64>,
    pub balance_detail: Option<String>,
    pub min_balance_wei: String,
    /// Outstanding obligations x challenge gas x proposed max fee.
    pub required_balance_wei: Option<String>,
    pub outstanding_obligations: u64,
    pub nonce_latest: Option<u64>,
    pub nonce_pending: Option<u64>,
    pub max_fee_per_gas_wei: String,
    pub max_priority_fee_per_gas_wei: String,
    pub priority_fee_per_gas_wei: String,
    pub proposed_max_fee_per_gas_wei: Option<String>,
    /// This daemon's transaction fee ceiling (gas limit x maxFeePerGas).
    pub tx_fee_cap_wei: String,
    /// The signer's `tx_fee_cap_wei` from `zkapi_signerStatus` or a refusal.
    pub signer_tx_fee_cap_wei: Option<String>,
    pub signer_status_detail: Option<String>,
    /// A ceiling learned from the signer's node: 10/11 of the lowest
    /// transaction fee it refused as above its RPC fee cap
    /// (`upstream_tx_fee_cap`). It stays in force until the daemon restarts.
    pub node_tx_fee_cap_bound_wei: Option<String>,
    /// The ceiling in force: the lowest of the three.
    pub effective_tx_fee_cap_wei: String,
    /// Gas limit of the latest challenge (its estimate plus 20%).
    pub challenge_gas_limit: Option<u64>,
    /// The highest maxFeePerGas the ceiling allows at that gas limit.
    pub tx_fee_cap_max_fee_per_gas_wei: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexerStatus {
    pub state: IndexerState,
    pub root: Option<Felt252>,
    pub block_number: Option<u64>,
    pub block_hash: Option<String>,
    pub lag_blocks: Option<u64>,
    pub mismatch_since: Option<u64>,
    pub consecutive_mismatches: u32,
    pub unavailable_since: Option<u64>,
    pub observed_at: Option<u64>,
    pub detail: Option<String>,
    /// `ok`, `unsupported` (an indexer without /v1/escapes/pending),
    /// `unavailable` or `unknown`.
    pub pending_escapes: String,
    pub pending_escapes_unavailable_since: Option<u64>,
    /// Escapes the event scan had not delivered when the indexer listed them.
    pub escapes_added_from_indexer: u64,
    /// Listed escapes whose nullifier or deadline differs from the vault's
    /// `pendingWithdrawals`, in the latest list (the vault's are tracked),
    /// and listed, untracked notes for which vault reads at least
    /// `blocked_warning_seconds` apart found no escape, once a list served
    /// at a block between two of those reads named them (a list that may
    /// only lag the vault is not reported).
    pub pending_escapes_disagreement: Option<String>,
    pub pending_escapes_disagreement_since: Option<u64>,
}

impl Default for IndexerStatus {
    fn default() -> Self {
        Self {
            state: IndexerState::Unknown,
            root: None,
            block_number: None,
            block_hash: None,
            lag_blocks: None,
            mismatch_since: None,
            consecutive_mismatches: 0,
            unavailable_since: None,
            observed_at: None,
            detail: None,
            pending_escapes: "unknown".into(),
            pending_escapes_unavailable_since: None,
            escapes_added_from_indexer: 0,
            pending_escapes_disagreement: None,
            pending_escapes_disagreement_since: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObligationStatus {
    pub note_id: u32,
    /// The escaped nullifier `N`.
    pub nullifier: Felt252,
    /// `N⁺`: only a request proof at it defeats the escape.
    #[serde(default)]
    pub next_nullifier: Option<Felt252>,
    /// `B`, the escaped state's balance, and `c`, the current concession.
    #[serde(default)]
    pub state_balance: Option<u128>,
    #[serde(default)]
    pub conceded: Option<u128>,
    /// `Ω`, once known: final once settled, else the bound from the raise lead.
    #[serde(default)]
    pub owed: Option<u128>,
    /// `deadline - raise_lead_seconds`: the raise is decided by then.
    #[serde(default)]
    pub raise_due_at: Option<u64>,
    /// The vault call on the obligation's nonce.
    #[serde(default)]
    pub action: Option<CallKind>,
    pub state: ObligationState,
    pub severity: Severity,
    pub challenge_deadline: Option<u64>,
    pub seconds_remaining: Option<u64>,
    pub evidence: Option<EvidenceKind>,
    pub blocked_reason: Option<BlockedReason>,
    pub detail: Option<String>,
    pub blocked_since: Option<u64>,
    pub consecutive_failures: u32,
    pub settlement: Option<SettlementProgress>,
    pub nonce: Option<u64>,
    pub transaction_hash: Option<String>,
    pub superseded_hashes: Vec<String>,
    pub max_fee_per_gas_wei: Option<String>,
    pub max_priority_fee_per_gas_wei: Option<String>,
    pub attempts: u32,
    pub submitted_block: Option<u64>,
    pub first_seen_at: Option<u64>,
    pub evaluated_at: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetachedNonceStatus {
    pub nonce: u64,
    pub note_id: u32,
    pub nullifier: Felt252,
    pub transaction_hash: Option<String>,
    pub superseded_hashes: Vec<String>,
    /// Fees and gas limit of the latest attempt on the nonce, when recorded.
    /// A gas limit x `maxFeePerGas` above the node's RPC fee cap was refused
    /// before any pool, even if a signer reported it as possibly broadcast.
    pub max_fee_per_gas_wei: Option<String>,
    pub max_priority_fee_per_gas_wei: Option<String>,
    pub gas_limit: Option<u64>,
    /// Consumed at the latest block (retained until confirmation depth).
    pub mined: bool,
}

/// The most recent missed challenge deadline, kept in the checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MissedRecord {
    pub note_id: u32,
    pub nullifier: Felt252,
    pub challenge_deadline: u64,
    pub reason: String,
    pub recorded_at: u64,
    /// `defeat` or `raise`; absent in records of an earlier release.
    #[serde(default)]
    pub kind: Option<CallKind>,
}

impl ChallengeStatus {
    /// The snapshot before any poll: a warning until the startup grace ends.
    pub fn initial(chain: ChainStatus, sender: SenderStatus, started_at: u64) -> Self {
        Self {
            schema: STATUS_SCHEMA.into(),
            status: Severity::Warning,
            alarms: vec!["warning: no poll completed".into()],
            generated_at: started_at,
            started_at,
            version: env!("CARGO_PKG_VERSION").into(),
            thresholds: AlarmPolicy::default().remaining_thresholds(None),
            chain,
            poll: PollStatus::default(),
            sender,
            indexer: IndexerStatus::default(),
            obligations: Vec::new(),
            detached_nonces: Vec::new(),
            missed_total: 0,
            escapes_finalized_with_successor_evidence_total: 0,
            missed_raises_total: 0,
            last_missed: None,
            config_warnings: Vec::new(),
        }
    }
}

/// The chain time now, extrapolated with wall-clock time from when the latest
/// head was first observed. Only wall-clock deltas are used, so absolute clock
/// skew does not matter, and a frozen RPC head does not stop the clock.
pub fn chain_now(chain: &ChainStatus, wall_now: u64) -> Option<u64> {
    chain
        .latest_block_timestamp
        .zip(chain.head_observed_at)
        .map(|(timestamp, seen)| timestamp.saturating_add(wall_now.saturating_sub(seen)))
}

pub fn deadline_severity(seconds_remaining: Option<u64>, t: RemainingThresholds) -> Severity {
    match seconds_remaining {
        Some(remaining) if remaining <= t.critical_remaining_seconds => Severity::Critical,
        Some(remaining) if remaining <= t.warning_remaining_seconds => Severity::Warning,
        _ => Severity::Ok,
    }
}

/// Severity of one obligation; `o.seconds_remaining` must be current.
pub fn obligation_severity(
    o: &ObligationStatus,
    wall_now: u64,
    t: RemainingThresholds,
    policy: &AlarmPolicy,
) -> Severity {
    let deadline = deadline_severity(o.seconds_remaining, t);
    let blocked = match o.blocked_reason {
        None => Severity::Ok,
        Some(reason) if reason.is_immediately_critical() => Severity::Critical,
        Some(_) => {
            let elapsed = o
                .blocked_since
                .map_or(0, |since| wall_now.saturating_sub(since));
            if elapsed >= policy.critical_blocked_seconds {
                Severity::Critical
            } else if elapsed >= policy.blocked_warning_seconds {
                Severity::Warning
            } else {
                Severity::Ok
            }
        }
    };
    match o.state {
        ObligationState::Missed => Severity::Critical,
        // Until confirmation depth tells a defeat from a payout.
        ObligationState::ResolvedUnconfirmed if o.evidence.is_some() => deadline.max(blocked),
        ObligationState::NothingDue
        | ObligationState::Raised
        | ObligationState::ExpiredNothingDue
        | ObligationState::ResolvedUnconfirmed => blocked,
        // The nonce is consumed but the escape remains: it reverted.
        ObligationState::MinedUnconfirmed | ObligationState::Unevaluated => deadline,
        // Nothing is sent before the raise lead, whatever the deadline: only
        // an overdue settlement or a blocked read is reported.
        ObligationState::AwaitingSettlement => {
            let overdue = o
                .settlement
                .as_ref()
                .and_then(|settlement| settlement.settle_after)
                .is_some_and(|settle_after| {
                    wall_now > settle_after.saturating_add(policy.settlement_overdue_seconds)
                });
            if overdue {
                blocked.max(Severity::Warning)
            } else {
                blocked
            }
        }
        // A missed defeat was paid out; its alarm is the missed record.
        ObligationState::RetiringLeaf => blocked.max(Severity::Warning),
        ObligationState::Ready | ObligationState::Submitted => deadline.max(blocked),
    }
}

/// Recompute every time-dependent field of a snapshot at `wall_now`.
pub fn evaluate(
    snapshot: &ChallengeStatus,
    policy: &AlarmPolicy,
    wall_now: u64,
) -> ChallengeStatus {
    let mut s = snapshot.clone();
    s.generated_at = wall_now;
    let t = policy.remaining_thresholds(s.chain.challenge_period_seconds);
    s.thresholds = t;
    let now = chain_now(&s.chain, wall_now);
    s.chain.head_age_seconds = s
        .chain
        .head_observed_at
        .map(|seen| wall_now.saturating_sub(seen));
    for o in &mut s.obligations {
        o.seconds_remaining = o
            .challenge_deadline
            .zip(now)
            .map(|(deadline, now)| deadline.saturating_sub(now));
        o.severity = obligation_severity(o, wall_now, t, policy);
    }
    s.poll.stale = s
        .poll
        .last_scan_success_at
        .is_none_or(|at| wall_now.saturating_sub(at) > policy.stale_poll_seconds);

    let mut alarms = Vec::new();
    let mut status = Severity::Ok;
    let mut raise = |severity: Severity, message: String| {
        if severity > Severity::Ok {
            let label = if severity == Severity::Critical {
                "critical"
            } else {
                "warning"
            };
            alarms.push(format!("{label}: {message}"));
            status = status.max(severity);
        }
    };
    for o in &s.obligations {
        raise(
            o.severity,
            format!(
                "note {} {}{}",
                o.note_id,
                wire_name(o.state),
                o.blocked_reason
                    .map(|reason| format!(" ({})", wire_name(reason)))
                    .unwrap_or_default()
            ),
        );
    }
    if let Some(missed) = s
        .last_missed
        .as_ref()
        .filter(|missed| wall_now.saturating_sub(missed.recorded_at) < MISSED_ALARM_SECONDS)
    {
        raise(
            Severity::Critical,
            format!(
                "missed challenge deadline of note {} ({})",
                missed.note_id, missed.reason
            ),
        );
    }
    for detached in s.detached_nonces.iter().filter(|d| !d.mined) {
        raise(
            Severity::Critical,
            format!(
                "unmined nonce {} of a completed or replaced note {} requires signer intervention",
                detached.nonce, detached.note_id
            ),
        );
    }
    let since = |at: Option<u64>| at.map(|at| wall_now.saturating_sub(at));
    match s.indexer.state {
        IndexerState::Diverged => raise(
            Severity::Critical,
            "indexer mirror diverged from vault currentRoot".into(),
        ),
        IndexerState::Unavailable
            if since(s.indexer.unavailable_since)
                .is_some_and(|elapsed| elapsed >= policy.blocked_warning_seconds) =>
        {
            raise(Severity::Warning, "indexer unavailable".into())
        }
        IndexerState::Lagging
            if s.indexer
                .lag_blocks
                .is_some_and(|lag| lag >= policy.indexer_lag_warning_blocks) =>
        {
            raise(Severity::Warning, "indexer lagging".into())
        }
        _ => {}
    }
    if s.indexer.pending_escapes == "unsupported" {
        raise(
            Severity::Warning,
            "indexer lacks /v1/escapes/pending; escape completeness is unchecked".into(),
        );
    } else if since(s.indexer.pending_escapes_unavailable_since)
        .is_some_and(|elapsed| elapsed >= policy.blocked_warning_seconds)
    {
        raise(
            Severity::Warning,
            "indexer pending-escapes list unavailable".into(),
        );
    }
    if let Some(detail) = s.indexer.pending_escapes_disagreement.as_ref().filter(|_| {
        since(s.indexer.pending_escapes_disagreement_since)
            .is_some_and(|elapsed| elapsed >= policy.blocked_warning_seconds)
    }) {
        raise(
            Severity::Warning,
            format!("indexer pending-escapes list disagrees with the vault ({detail}); resync the indexer"),
        );
    }
    if s.obligations
        .iter()
        .any(|o| o.blocked_reason == Some(BlockedReason::TxFeeCapReached))
    {
        let known = |value: &Option<String>| value.as_deref().unwrap_or("unknown").to_owned();
        raise(
            Severity::Warning,
            format!(
                "transaction fee ceiling {} wei allows a maxFeePerGas of at most {} wei at {} gas; base fee {} wei",
                s.sender.effective_tx_fee_cap_wei,
                known(&s.sender.tx_fee_cap_max_fee_per_gas_wei),
                known(&s.sender.challenge_gas_limit.map(|gas| gas.to_string())),
                known(&s.chain.base_fee_per_gas_wei),
            ),
        );
    }
    match s.poll.last_scan_success_at {
        None if wall_now.saturating_sub(s.started_at) <= policy.startup_grace_seconds => {
            raise(Severity::Warning, "no poll completed".into())
        }
        None => raise(Severity::Critical, "no successful poll since start".into()),
        Some(_) if s.poll.stale => raise(Severity::Critical, "polls are stale".into()),
        Some(_) => {}
    }
    match s.chain.head_age_seconds {
        Some(age) if age >= HEAD_AGE_CRITICAL_SECONDS => {
            raise(Severity::Critical, format!("no new head block for {age}s"))
        }
        Some(age) if age >= HEAD_AGE_WARNING_SECONDS => {
            raise(Severity::Warning, format!("no new head block for {age}s"))
        }
        _ => {}
    }
    match s.chain.scan_lag_blocks {
        Some(lag) if lag >= SCAN_LAG_CRITICAL_BLOCKS => raise(
            Severity::Critical,
            format!("event scan {lag} blocks behind"),
        ),
        Some(lag) if lag >= SCAN_LAG_WARNING_BLOCKS => {
            raise(Severity::Warning, format!("event scan {lag} blocks behind"))
        }
        _ => {}
    }
    let wei = |value: &Option<String>| value.as_deref().and_then(|v| v.parse::<u128>().ok());
    if let Some(balance) = wei(&s.sender.balance_wei) {
        if s.sender
            .min_balance_wei
            .parse::<u128>()
            .is_ok_and(|minimum| balance < minimum)
        {
            raise(Severity::Warning, "sender balance below the minimum".into());
        }
        if wei(&s.sender.required_balance_wei).is_some_and(|required| balance < required) {
            raise(
                Severity::Warning,
                "sender balance cannot fund every outstanding challenge".into(),
            );
        }
    }
    for warning in &s.config_warnings {
        raise(Severity::Warning, warning.clone());
    }
    s.status = status;
    s.alarms = alarms;
    s
}

/// Liveness only: the poll loop started or finished an iteration recently.
pub fn is_alive(snapshot: &ChallengeStatus, policy: &AlarmPolicy, wall_now: u64) -> bool {
    match snapshot
        .poll
        .last_completed_at
        .max(snapshot.poll.last_started_at)
    {
        Some(at) => wall_now.saturating_sub(at) <= policy.stale_poll_seconds,
        None => wall_now.saturating_sub(snapshot.started_at) <= policy.startup_grace_seconds,
    }
}

#[derive(Clone)]
struct StatusState {
    handle: StatusHandle,
    policy: AlarmPolicy,
}

pub fn router(handle: StatusHandle, policy: AlarmPolicy) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(StatusState { handle, policy })
}

fn snapshot(state: &StatusState) -> ChallengeStatus {
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
    let alive = is_alive(&snapshot, &state.policy, now);
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
            "poll_age_seconds": current
                .poll
                .last_scan_success_at
                .map(|at| now.saturating_sub(at)),
            "obligations": current.obligations.len(),
            "critical_obligations": current
                .obligations
                .iter()
                .filter(|o| o.severity == Severity::Critical)
                .count(),
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

/// The snake_case name a status enum has in the JSON.
pub fn wire_name(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_default()
}

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use tower::ServiceExt;

    const NOW: u64 = 1_800_000_000;

    fn thresholds() -> RemainingThresholds {
        RemainingThresholds {
            warning_remaining_seconds: 50,
            critical_remaining_seconds: 10,
        }
    }

    fn obligation(state: ObligationState, remaining: u64) -> ObligationStatus {
        ObligationStatus {
            note_id: 0,
            nullifier: Felt252::from_u64(9),
            next_nullifier: Some(Felt252::from_u64(10)),
            state_balance: Some(100),
            conceded: Some(0),
            owed: None,
            raise_due_at: None,
            action: None,
            state,
            severity: Severity::Ok,
            challenge_deadline: Some(NOW + remaining),
            seconds_remaining: Some(remaining),
            evidence: Some(EvidenceKind::Successor),
            blocked_reason: None,
            detail: None,
            blocked_since: None,
            consecutive_failures: 0,
            settlement: None,
            nonce: None,
            transaction_hash: None,
            superseded_hashes: Vec::new(),
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            attempts: 0,
            submitted_block: None,
            first_seen_at: None,
            evaluated_at: Some(NOW),
        }
    }

    fn healthy_snapshot() -> ChallengeStatus {
        let mut s = ChallengeStatus::initial(
            ChainStatus {
                chain_id: 1,
                latest_block: Some(5),
                latest_block_timestamp: Some(NOW),
                head_observed_at: Some(NOW),
                scan_lag_blocks: Some(0),
                challenge_period_seconds: Some(86_400),
                ..Default::default()
            },
            SenderStatus {
                min_balance_wei: "0".into(),
                ..Default::default()
            },
            NOW - 1_000,
        );
        s.poll.last_scan_success_at = Some(NOW);
        s.poll.last_completed_at = Some(NOW);
        s.indexer.state = IndexerState::Consistent;
        s.indexer.pending_escapes = "ok".into();
        s
    }

    fn policy() -> AlarmPolicy {
        AlarmPolicy {
            warning_remaining_seconds: Some(50),
            critical_remaining_seconds: Some(10),
            ..Default::default()
        }
    }

    #[test]
    fn obligation_severity_table() {
        let policy = policy();
        let t = thresholds();
        let severity = |o: &ObligationStatus| obligation_severity(o, NOW, t, &policy);
        use ObligationState::*;
        for (state, remaining, expected) in [
            (Ready, 100, Severity::Ok),
            (Ready, 50, Severity::Warning),
            (Ready, 10, Severity::Critical),
            (Submitted, 100, Severity::Ok),
            (Submitted, 30, Severity::Warning),
            (Submitted, 0, Severity::Critical),
            (MinedUnconfirmed, 100, Severity::Ok),
            (MinedUnconfirmed, 5, Severity::Critical),
            (Unevaluated, 5, Severity::Critical),
            (AwaitingSettlement, 100, Severity::Ok),
            (AwaitingSettlement, 5, Severity::Ok),
            (NothingDue, 0, Severity::Ok),
            (Raised, 0, Severity::Ok),
            (ExpiredNothingDue, 0, Severity::Ok),
            // With evidence it may have been paid out: its deadline counts.
            (ResolvedUnconfirmed, 100, Severity::Ok),
            (ResolvedUnconfirmed, 0, Severity::Critical),
            (Missed, 0, Severity::Critical),
        ] {
            assert_eq!(
                severity(&obligation(state, remaining)),
                expected,
                "{state:?} at {remaining}s"
            );
        }
        let mut resolved = obligation(ResolvedUnconfirmed, 0);
        resolved.evidence = None;
        assert_eq!(severity(&resolved), Severity::Ok, "no evidence, no miss");
        // Blocked reasons: some are critical at once, the rest escalate.
        for reason in [
            BlockedReason::EvidenceInvalid,
            BlockedReason::EvidenceDbError,
            BlockedReason::IndexerInvalidResponse,
            BlockedReason::IndexerDiverged,
            BlockedReason::SignerRefused,
            BlockedReason::UpstreamTxFeeCap,
        ] {
            let mut o = obligation(Ready, 1_000);
            o.blocked_reason = Some(reason);
            o.blocked_since = Some(NOW);
            assert_eq!(severity(&o), Severity::Critical, "{reason:?}");
        }
        for reason in [
            BlockedReason::IndexerUnavailable,
            BlockedReason::IndexerPathBehind,
            BlockedReason::RpcError,
            BlockedReason::SimulationReverted,
            BlockedReason::SendAmbiguous,
            BlockedReason::BaseFeeAboveFeeCap,
            BlockedReason::BaseFeeAboveMaxFee,
            BlockedReason::FeeCapReached,
            BlockedReason::TipCapReached,
            BlockedReason::FeeReserveHeld,
            BlockedReason::TxFeeCapReached,
            BlockedReason::TxFeeAboveCap,
            BlockedReason::InsufficientBalance,
            BlockedReason::NonceConflict,
            BlockedReason::NonceBlocked,
        ] {
            let mut o = obligation(Submitted, 1_000);
            o.blocked_reason = Some(reason);
            for (age, expected) in [
                (0, Severity::Ok),
                (policy.blocked_warning_seconds, Severity::Warning),
                (policy.critical_blocked_seconds, Severity::Critical),
            ] {
                o.blocked_since = Some(NOW - age);
                assert_eq!(severity(&o), expected, "{reason:?} after {age}s");
            }
            // The deadline still dominates a recently blocked obligation.
            o.blocked_since = Some(NOW);
            o.seconds_remaining = Some(5);
            assert_eq!(severity(&o), Severity::Critical);
        }
        // Awaiting settlement sends nothing before the raise lead: its
        // deadline does not escalate it, an overdue settlement warns and an
        // unreadable lease row is critical.
        let mut awaiting = obligation(AwaitingSettlement, 5);
        awaiting.evidence = Some(EvidenceKind::Unsettled);
        awaiting.settlement = Some(SettlementProgress {
            lease_status: Some("active".into()),
            key_issued: true,
            possibly_delivered: true,
            settle_after: Some(NOW + 100),
            ..Default::default()
        });
        assert_eq!(severity(&awaiting), Severity::Ok);
        awaiting.settlement.as_mut().unwrap().settle_after =
            Some(NOW - policy.settlement_overdue_seconds - 1);
        assert_eq!(severity(&awaiting), Severity::Warning, "overdue");
        let mut unreadable = obligation(AwaitingSettlement, 1_000);
        unreadable.evidence = Some(EvidenceKind::Unavailable);
        unreadable.blocked_reason = Some(BlockedReason::EvidenceDbError);
        assert_eq!(severity(&unreadable), Severity::Critical);
        // A raised escape is watched quietly; corrupt successor evidence is
        // critical whatever the state.
        assert_eq!(severity(&obligation(Raised, 5)), Severity::Ok);
        let mut corrupt = obligation(NothingDue, 1_000);
        corrupt.evidence = Some(EvidenceKind::Corrupt);
        corrupt.blocked_reason = Some(BlockedReason::EvidenceInvalid);
        corrupt.blocked_since = Some(NOW);
        assert_eq!(severity(&corrupt), Severity::Critical);
        // A leaf retirement after a missed defeat warns.
        assert_eq!(severity(&obligation(RetiringLeaf, 0)), Severity::Warning);
    }

    #[test]
    fn evaluate_recomputes_time_and_overall_status() {
        let policy = policy();
        let mut s = healthy_snapshot();
        s.obligations.push(obligation(ObligationState::Ready, 100));
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);
        // Escalation advances with wall time, even without new polls.
        let later = evaluate(&s, &policy, NOW + 60);
        assert_eq!(later.obligations[0].seconds_remaining, Some(40));
        assert_eq!(later.obligations[0].severity, Severity::Warning);
        assert_eq!(later.status, Severity::Warning);
        let critical = evaluate(&s, &policy, NOW + 95);
        assert_eq!(critical.obligations[0].severity, Severity::Critical);
        assert_eq!(critical.status, Severity::Critical);
        // ... where staleness also turns critical.
        let stale = evaluate(&s, &policy, NOW + policy.stale_poll_seconds + 1);
        assert!(stale.poll.stale);
        assert!(stale.alarms.iter().any(|alarm| alarm.contains("stale")));

        let mut s = healthy_snapshot();
        s.indexer.state = IndexerState::Diverged;
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Critical);
        s.indexer.state = IndexerState::Lagging;
        s.indexer.lag_blocks = Some(policy.indexer_lag_warning_blocks - 1);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);
        s.indexer.lag_blocks = Some(policy.indexer_lag_warning_blocks);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Warning);

        let mut s = healthy_snapshot();
        s.detached_nonces.push(DetachedNonceStatus {
            nonce: 3,
            note_id: 1,
            nullifier: Felt252::from_u64(1),
            transaction_hash: None,
            superseded_hashes: Vec::new(),
            max_fee_per_gas_wei: None,
            max_priority_fee_per_gas_wei: None,
            gas_limit: None,
            mined: false,
        });
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Critical);
        s.detached_nonces[0].mined = true;
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);

        let mut s = healthy_snapshot();
        s.sender.balance_wei = Some("10".into());
        s.sender.required_balance_wei = Some("11".into());
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Warning);
        s.sender.required_balance_wei = Some("10".into());
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);
        s.config_warnings
            .push("fee cap below typical Mainnet base-fee peaks".into());
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Warning);

        let mut s = healthy_snapshot();
        s.chain.head_observed_at = Some(NOW - HEAD_AGE_WARNING_SECONDS);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Warning);
        s.chain.head_observed_at = Some(NOW - HEAD_AGE_CRITICAL_SECONDS);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Critical);
        let mut s = healthy_snapshot();
        s.chain.scan_lag_blocks = Some(SCAN_LAG_CRITICAL_BLOCKS);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Critical);

        // A recorded miss stays critical for a while after it is recorded.
        let mut s = healthy_snapshot();
        s.missed_total = 1;
        s.last_missed = Some(MissedRecord {
            note_id: 4,
            nullifier: Felt252::from_u64(9),
            challenge_deadline: NOW - 30,
            reason: "challenge not mined before the deadline".into(),
            recorded_at: NOW - 10,
            kind: Some(CallKind::Defeat),
        });
        let current = evaluate(&s, &policy, NOW);
        assert_eq!(current.status, Severity::Critical);
        assert_eq!(
            current.alarms,
            ["critical: missed challenge deadline of note 4 (challenge not mined before the deadline)"]
        );
        s.last_missed.as_mut().unwrap().recorded_at = NOW - MISSED_ALARM_SECONDS;
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);
        let mut s = healthy_snapshot();
        s.indexer.pending_escapes = "unsupported".into();
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Warning);

        // A listing that disagrees with the vault warns once it persists.
        let mut s = healthy_snapshot();
        s.indexer.pending_escapes_disagreement = Some("note 0".into());
        s.indexer.pending_escapes_disagreement_since = Some(NOW);
        assert_eq!(evaluate(&s, &policy, NOW).status, Severity::Ok);
        let later = evaluate(&s, &policy, NOW + policy.blocked_warning_seconds);
        assert_eq!(later.status, Severity::Warning);
        assert!(later
            .alarms
            .iter()
            .any(|alarm| alarm.contains("disagrees with the vault (note 0)")));

        // An obligation stopped by the transaction fee ceiling shows the
        // ceiling and the base fee at once.
        let mut s = healthy_snapshot();
        s.chain.base_fee_per_gas_wei = Some("140000000000".into());
        s.sender.effective_tx_fee_cap_wei = "1000000000000000000".into();
        s.sender.challenge_gas_limit = Some(7_534_341);
        s.sender.tx_fee_cap_max_fee_per_gas_wei = Some("132725950546".into());
        let mut capped = obligation(ObligationState::Ready, 1_000);
        capped.blocked_reason = Some(BlockedReason::TxFeeCapReached);
        capped.blocked_since = Some(NOW);
        s.obligations.push(capped);
        let current = evaluate(&s, &policy, NOW);
        assert_eq!(current.status, Severity::Warning);
        assert!(current.alarms.iter().any(|alarm| alarm
            == "warning: transaction fee ceiling 1000000000000000000 wei allows a maxFeePerGas of at most 132725950546 wei at 7534341 gas; base fee 140000000000 wei"));
    }

    #[test]
    fn startup_grace_and_liveness_are_explicit() {
        let policy = policy();
        let mut s = healthy_snapshot();
        s.started_at = NOW;
        s.poll = PollStatus::default();
        let early = evaluate(&s, &policy, NOW + policy.startup_grace_seconds);
        assert_eq!(early.status, Severity::Warning);
        assert!(is_alive(&s, &policy, NOW + policy.startup_grace_seconds));
        let late = evaluate(&s, &policy, NOW + policy.startup_grace_seconds + 1);
        assert_eq!(late.status, Severity::Critical);
        assert!(!is_alive(
            &s,
            &policy,
            NOW + policy.startup_grace_seconds + 1
        ));
        // A started poll keeps the loop alive; a hung one eventually does not.
        s.poll.last_started_at = Some(NOW + 400);
        assert!(is_alive(&s, &policy, NOW + 500));
        assert!(!is_alive(
            &s,
            &policy,
            NOW + 401 + policy.stale_poll_seconds
        ));
    }

    async fn get(router: Router, path: &str) -> (StatusCode, serde_json::Value, Option<String>) {
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let code = response.status();
        let cache = response
            .headers()
            .get(header::CACHE_CONTROL)
            .map(|value| value.to_str().unwrap().to_owned());
        let body = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .unwrap();
        (code, serde_json::from_slice(&body).unwrap(), cache)
    }

    #[tokio::test]
    async fn health_codes_follow_severity_and_poll_staleness() {
        let now = unix_now();
        let policy = policy();
        let mut s = healthy_snapshot();
        s.started_at = now - 1_000;
        s.chain.latest_block_timestamp = Some(now);
        s.chain.head_observed_at = Some(now);
        s.poll.last_scan_success_at = Some(now);
        s.poll.last_completed_at = Some(now);
        let mut ok = obligation(ObligationState::Ready, 0);
        ok.challenge_deadline = Some(now + 1_000);
        s.obligations.push(ok);
        let handle: StatusHandle = Arc::new(RwLock::new(s.clone()));
        let app = || router(handle.clone(), policy.clone());

        let (code, body, cache) = get(app(), "/health").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["status"], "ok");
        assert_eq!(body["obligations"], 1);
        assert_eq!(cache.as_deref(), Some("no-store"));
        let (code, body, _) = get(app(), "/status").await;
        assert_eq!(code, StatusCode::OK);
        assert_eq!(body["schema"], STATUS_SCHEMA);
        // Recomputed from the absolute deadline at request time.
        let remaining = body["obligations"][0]["seconds_remaining"]
            .as_u64()
            .unwrap();
        assert!((998..=1_000).contains(&remaining), "{remaining}");

        // Warning stays 200; a critical obligation is 503 on /health only.
        handle.write().unwrap().obligations[0].challenge_deadline = Some(now + 30);
        assert_eq!(get(app(), "/health").await.0, StatusCode::OK);
        handle.write().unwrap().obligations[0].challenge_deadline = Some(now + 5);
        let (code, body, _) = get(app(), "/health").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["critical_obligations"], 1);
        let (code, body, _) = get(app(), "/livez").await;
        assert_eq!(code, StatusCode::OK, "alarms never fail liveness");
        assert_eq!(body["status"], "alive");

        // Stale polls fail /health; a stuck loop also fails /livez.
        {
            let mut s = handle.write().unwrap();
            s.obligations.clear();
            s.poll.last_scan_success_at = Some(now - policy.stale_poll_seconds - 10);
        }
        assert_eq!(
            get(app(), "/health").await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(get(app(), "/livez").await.0, StatusCode::OK);
        {
            let mut s = handle.write().unwrap();
            s.poll.last_completed_at = Some(now - policy.stale_poll_seconds - 10);
            s.poll.last_started_at = Some(now - policy.stale_poll_seconds - 10);
        }
        let (code, body, cache) = get(app(), "/livez").await;
        assert_eq!(code, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(body["status"], "stale");
        assert_eq!(cache.as_deref(), Some("no-store"));
    }

    #[test]
    fn status_never_includes_a_client_request_id() {
        let mut s = healthy_snapshot();
        let mut o = obligation(ObligationState::AwaitingSettlement, 100);
        o.settlement = Some(SettlementProgress {
            reservation_kind: "openrouter_lease".into(),
            lease_status: Some("active".into()),
            ..Default::default()
        });
        s.obligations.push(o);
        let json = serde_json::to_string(&s).unwrap();
        assert!(!json.contains("client_request_id"), "{json}");
        let round_trip: ChallengeStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, s);
    }

    #[test]
    fn alarm_policy_derives_and_validates_thresholds() {
        let policy = AlarmPolicy::default();
        assert_eq!(
            policy.remaining_thresholds(Some(86_400)),
            RemainingThresholds {
                warning_remaining_seconds: 43_200,
                critical_remaining_seconds: 21_600
            }
        );
        assert_eq!(
            policy.remaining_thresholds(Some(400)),
            RemainingThresholds {
                warning_remaining_seconds: 200,
                critical_remaining_seconds: 100
            }
        );
        let explicit = AlarmPolicy {
            warning_remaining_seconds: Some(50),
            ..Default::default()
        };
        // A derived critical threshold never exceeds an explicit warning.
        assert_eq!(
            explicit
                .remaining_thresholds(Some(86_400))
                .critical_remaining_seconds,
            50
        );
        assert!(policy.validate().is_ok());
        assert!(AlarmPolicy {
            warning_remaining_seconds: Some(10),
            critical_remaining_seconds: Some(10),
            ..Default::default()
        }
        .validate()
        .is_err());
        assert!(AlarmPolicy {
            critical_blocked_seconds: 1,
            ..Default::default()
        }
        .validate()
        .is_err());
    }
}
