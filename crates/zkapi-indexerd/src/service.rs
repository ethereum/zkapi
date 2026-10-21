//! Indexer service state: the verified head view and its health.

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

use crate::tree_mirror::{EscapeClose, PendingEscape, TreeMirror};

/// Indexer status as reported on `/health` and `/metrics`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncStatus {
    /// A verified head view is being served.
    Ok,
    /// Replaying or catching up; nothing verified has been published yet.
    Syncing,
    /// No verified poll within `stale_after`, or the RPC head stopped advancing.
    Stale,
    /// The mirror does not match the vault state.
    Diverged,
    /// Replaying from the deployment block after a detected inconsistency.
    Rebuilding,
}

impl SyncStatus {
    pub const ALL: [SyncStatus; 5] = [
        SyncStatus::Ok,
        SyncStatus::Syncing,
        SyncStatus::Stale,
        SyncStatus::Diverged,
        SyncStatus::Rebuilding,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            SyncStatus::Ok => "ok",
            SyncStatus::Syncing => "syncing",
            SyncStatus::Stale => "stale",
            SyncStatus::Diverged => "diverged",
            SyncStatus::Rebuilding => "rebuilding",
        }
    }
}

/// A mirror state the vault had at a recorded block hash, as verified by
/// `currentRoot()` and `nextNoteId()` read at that block. That check covers
/// the tree (deposits and retirements); note statuses, open escapes and
/// published nullifiers come from the same logs but are not covered by it
/// (see `PendingEscape`).
#[derive(Clone)]
pub struct TreeView {
    pub mirror: Arc<TreeMirror>,
    pub block_number: u64,
    pub block_hash: String,
    pub root: Felt252,
    pub next_note_id: u32,
    pub verified_at_ms: u64,
}

impl TreeView {
    pub fn new(mirror: Arc<TreeMirror>, block_number: u64, block_hash: String) -> Self {
        Self {
            root: mirror.root(),
            next_note_id: mirror.next_note_id(),
            mirror,
            block_number,
            block_hash,
            verified_at_ms: unix_ms(),
        }
    }
}

/// Static settings reported on `/health` and used to judge staleness.
#[derive(Debug, Clone)]
pub struct ServiceSettings {
    pub contract_address: String,
    pub chain_id: Option<u64>,
    pub confirmations: u64,
    /// Longest time without a verified poll before the view is stale.
    pub stale_after: Duration,
    /// Oldest RPC head timestamp the view may rest on; `None` disables the
    /// check (for chains that mine only on demand, such as anvil).
    pub max_head_age: Option<Duration>,
}

impl Default for ServiceSettings {
    fn default() -> Self {
        Self {
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            chain_id: None,
            confirmations: 12,
            stale_after: Duration::from_secs(120),
            max_head_age: Some(Duration::from_secs(180)),
        }
    }
}

/// Why no tree view can be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unavailable {
    pub status: SyncStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
struct Confirmed {
    block: u64,
    hash: String,
    root: Felt252,
    next_note_id: u32,
}

struct State {
    /// Set phase; `Stale` is derived in `status()` and never stored.
    phase: SyncStatus,
    reason: Option<String>,
    head: Option<Arc<TreeView>>,
    confirmed: Option<Confirmed>,
    chain_id: Option<u64>,
    head_block: Option<u64>,
    head_timestamp: Option<u64>,
    sync_block: Option<u64>,
    last_success: Option<Instant>,
    last_success_unix_ms: Option<u64>,
    last_verified_unix_ms: Option<u64>,
    consecutive_failures: u64,
    last_error: Option<String>,
    divergence_count: u64,
    rebuild_count: u64,
    missed_re_escapes_challenged: u64,
    missed_re_escapes_finalized: u64,
    missed_re_escapes_raised: u64,
    stale_reported: bool,
    head_stale_reported: bool,
}

/// Shared state between the poller and the HTTP handlers.
///
/// The poller publishes verified head views; handlers clone the current
/// `Arc<TreeView>` and compute outside the lock, so every response is drawn
/// from one consistent vault state.
pub struct IndexerService {
    settings: ServiceSettings,
    state: RwLock<State>,
}

impl IndexerService {
    /// Construct an indexer that must verify a head view before serving tree
    /// data.
    pub fn new_syncing(settings: ServiceSettings) -> Self {
        let chain_id = settings.chain_id;
        Self {
            settings,
            state: RwLock::new(State {
                phase: SyncStatus::Syncing,
                reason: None,
                head: None,
                confirmed: None,
                chain_id,
                head_block: None,
                head_timestamp: None,
                sync_block: None,
                last_success: None,
                last_success_unix_ms: None,
                last_verified_unix_ms: None,
                consecutive_failures: 0,
                last_error: None,
                divergence_count: 0,
                rebuild_count: 0,
                missed_re_escapes_challenged: 0,
                missed_re_escapes_finalized: 0,
                missed_re_escapes_raised: 0,
                stale_reported: false,
                head_stale_reported: false,
            }),
        }
    }

    /// Test helper: serve `mirror` as if verified at block 0.
    #[doc(hidden)]
    pub fn new_ready(mirror: TreeMirror) -> Self {
        let service = Self::new_syncing(ServiceSettings {
            max_head_age: None,
            ..ServiceSettings::default()
        });
        service.publish_head(TreeView::new(
            Arc::new(mirror),
            0,
            format!("0x{}", "0".repeat(64)),
        ));
        service.record_success();
        service
    }

    pub fn settings(&self) -> &ServiceSettings {
        &self.settings
    }

    pub fn status(&self) -> SyncStatus {
        let state = self.state.read().unwrap();
        self.status_of(&state)
    }

    pub fn is_ready(&self) -> bool {
        self.status() == SyncStatus::Ok
    }

    /// The verified head view, or why none can be served.
    pub fn view(&self) -> Result<Arc<TreeView>, Unavailable> {
        let state = self.state.read().unwrap();
        let status = self.status_of(&state);
        match (status, &state.head) {
            (SyncStatus::Ok, Some(view)) => Ok(view.clone()),
            _ => Err(Unavailable {
                status,
                reason: self.reason_of(&state, status),
            }),
        }
    }

    pub fn health(&self) -> HealthResponse {
        let state = self.state.read().unwrap();
        let status = self.status_of(&state);
        let view = state.head.as_deref();
        HealthResponse {
            status,
            reason: self.reason_of(&state, status),
            chain_id: state.chain_id,
            contract_address: self.settings.contract_address.clone(),
            confirmations: self.settings.confirmations,
            head_block: state.head_block,
            head_timestamp: state.head_timestamp,
            head_age_seconds: state
                .head_timestamp
                .map(|timestamp| (unix_ms() / 1_000).saturating_sub(timestamp)),
            served_block: view.map(|view| view.block_number),
            served_block_hash: view.map(|view| view.block_hash.clone()),
            root: view.map(|view| view.root),
            next_note_id: view.map(|view| view.next_note_id),
            lag_blocks: match (state.head_block, view) {
                (Some(head), Some(view)) => Some(head.saturating_sub(view.block_number)),
                _ => None,
            },
            confirmed_block: state.confirmed.as_ref().map(|c| c.block),
            confirmed_block_hash: state.confirmed.as_ref().map(|c| c.hash.clone()),
            confirmed_root: state.confirmed.as_ref().map(|c| c.root),
            confirmed_next_note_id: state.confirmed.as_ref().map(|c| c.next_note_id),
            sync_block: state.sync_block,
            last_success_unix_ms: state.last_success_unix_ms,
            last_verified_unix_ms: state.last_verified_unix_ms,
            consecutive_failures: state.consecutive_failures,
            last_error: state.last_error.clone(),
            divergence_count: state.divergence_count,
            rebuild_count: state.rebuild_count,
            missed_re_escape_count: state
                .missed_re_escapes_challenged
                .saturating_add(state.missed_re_escapes_finalized)
                .saturating_add(state.missed_re_escapes_raised),
            missed_re_escape_finalized_count: state.missed_re_escapes_finalized,
            missed_re_escape_raised_count: state.missed_re_escapes_raised,
            known_root_count: view.map(|view| view.mirror.known_root_count() as u64),
            published_nullifier_count: view.map(|view| view.mirror.published_count() as u64),
        }
    }

    fn status_of(&self, state: &State) -> SyncStatus {
        match state.phase {
            SyncStatus::Ok if state.head.is_none() => SyncStatus::Syncing,
            SyncStatus::Ok if self.success_is_stale(state) || self.head_is_old(state) => {
                SyncStatus::Stale
            }
            phase => phase,
        }
    }

    fn reason_of(&self, state: &State, status: SyncStatus) -> Option<String> {
        if status != SyncStatus::Stale {
            return state.reason.clone();
        }
        if self.head_is_old(state) {
            return Some(format!(
                "rpc head block {} is {}s old; the rpc head is not advancing",
                state.head_block.unwrap_or_default(),
                head_age_ms(state).unwrap_or_default() / 1_000
            ));
        }
        Some(format!(
            "no verified poll for {}s",
            state
                .last_success
                .map_or(0, |instant| instant.elapsed().as_secs())
        ))
    }

    fn success_is_stale(&self, state: &State) -> bool {
        state
            .last_success
            .is_none_or(|instant| instant.elapsed() > self.settings.stale_after)
    }

    fn head_is_old(&self, state: &State) -> bool {
        match (self.settings.max_head_age, head_age_ms(state)) {
            (Some(limit), Some(age_ms)) => u128::from(age_ms) > limit.as_millis(),
            _ => false,
        }
    }

    /// Record the RPC's latest block. Returns whether its timestamp is recent
    /// enough for the view to count as current.
    pub(crate) fn observe_head(&self, number: u64, timestamp: u64) -> bool {
        let mut state = self.state.write().unwrap();
        state.head_block = Some(number);
        state.head_timestamp = Some(timestamp);
        let old = self.head_is_old(&state);
        if old && !state.head_stale_reported {
            state.head_stale_reported = true;
            tracing::error!(
                head_block = number,
                head_age_seconds = head_age_ms(&state).unwrap_or_default() / 1_000,
                "indexer RPC head is not advancing; tree endpoints return 503"
            );
        } else if !old && state.head_stale_reported {
            state.head_stale_reported = false;
            tracing::info!(head_block = number, "indexer RPC head is advancing again");
        }
        !old
    }

    pub(crate) fn publish_head(&self, view: TreeView) {
        self.state.write().unwrap().head = Some(Arc::new(view));
    }

    pub(crate) fn set_confirmed(&self, block: u64, hash: String, root: Felt252, next_note_id: u32) {
        self.state.write().unwrap().confirmed = Some(Confirmed {
            block,
            hash,
            root,
            next_note_id,
        });
    }

    pub(crate) fn set_sync_block(&self, block: u64) {
        self.state.write().unwrap().sync_block = Some(block);
    }

    pub(crate) fn set_chain_id(&self, chain_id: u64) {
        self.state.write().unwrap().chain_id = Some(chain_id);
    }

    /// Fail closed with a reason; only a fresh verified publish
    /// (`record_success`) returns the phase to `Ok`.
    pub(crate) fn set_phase(&self, phase: SyncStatus, reason: Option<String>) {
        let mut state = self.state.write().unwrap();
        state.phase = phase;
        state.reason = reason;
    }

    /// A head view was verified and published.
    pub(crate) fn record_success(&self) {
        let mut state = self.state.write().unwrap();
        let now = unix_ms();
        state.phase = SyncStatus::Ok;
        state.reason = None;
        state.last_success = Some(Instant::now());
        state.last_success_unix_ms = Some(now);
        state.last_verified_unix_ms = Some(now);
        state.consecutive_failures = 0;
        state.last_error = None;
    }

    /// The RPC head is unchanged and fresh, so the published view is still
    /// current. Never changes the phase or the verification time.
    pub(crate) fn refresh_success(&self) {
        let mut state = self.state.write().unwrap();
        state.last_success = Some(Instant::now());
        state.last_success_unix_ms = Some(unix_ms());
        state.consecutive_failures = 0;
        state.last_error = None;
    }

    pub(crate) fn record_failure(&self, error: String) {
        let mut state = self.state.write().unwrap();
        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        state.last_error = Some(error);
    }

    pub(crate) fn bump_divergences(&self) {
        let mut state = self.state.write().unwrap();
        state.divergence_count = state.divergence_count.saturating_add(1);
    }

    /// A committed event closed an escape the mirror never saw initiated
    /// (see `MissedReEscape`).
    pub(crate) fn bump_missed_re_escapes(&self, closed_by: EscapeClose) {
        let mut state = self.state.write().unwrap();
        let count = match closed_by {
            EscapeClose::Challenged => &mut state.missed_re_escapes_challenged,
            EscapeClose::Finalized => &mut state.missed_re_escapes_finalized,
            EscapeClose::Raised => &mut state.missed_re_escapes_raised,
        };
        *count = count.saturating_add(1);
    }

    /// Stop serving and report a rebuild from the deployment block.
    pub(crate) fn begin_rebuild(&self, reason: String) {
        let mut state = self.state.write().unwrap();
        state.phase = SyncStatus::Rebuilding;
        state.reason = Some(reason);
        state.head = None;
        state.confirmed = None;
        state.rebuild_count = state.rebuild_count.saturating_add(1);
    }

    /// Seconds since the last success, once per transition into `Stale`.
    pub(crate) fn stale_transition(&self) -> Option<u64> {
        let mut state = self.state.write().unwrap();
        let stale = self.status_of(&state) == SyncStatus::Stale;
        if stale && !state.stale_reported {
            state.stale_reported = true;
            return Some(
                state
                    .last_success
                    .map_or(0, |instant| instant.elapsed().as_secs()),
            );
        }
        if !stale {
            state.stale_reported = false;
        }
        None
    }

    /// Prometheus text exposition of the health fields.
    pub fn metrics(&self) -> String {
        let health = self.health();
        let mut out = String::new();
        gauge(
            &mut out,
            "zkapi_indexer_status",
            "Indexer status; 1 for the current status.",
        );
        for status in SyncStatus::ALL {
            out.push_str(&format!(
                "zkapi_indexer_status{{status=\"{}\"}} {}\n",
                status.as_str(),
                u8::from(status == health.status)
            ));
        }
        let gauges: [(&str, &str, Option<u64>); 9] = [
            (
                "zkapi_indexer_head_block",
                "Latest block reported by the RPC.",
                health.head_block,
            ),
            (
                "zkapi_indexer_head_timestamp_seconds",
                "Timestamp of the latest block reported by the RPC.",
                health.head_timestamp,
            ),
            (
                "zkapi_indexer_head_age_seconds",
                "Age of the latest block reported by the RPC.",
                health.head_age_seconds,
            ),
            (
                "zkapi_indexer_served_block",
                "Block of the verified head view.",
                health.served_block,
            ),
            (
                "zkapi_indexer_confirmed_block",
                "Block of the durable checkpoint.",
                health.confirmed_block,
            ),
            (
                "zkapi_indexer_lag_blocks",
                "Blocks between the RPC head and the verified head view.",
                health.lag_blocks,
            ),
            (
                "zkapi_indexer_consecutive_failures",
                "Consecutive failed polls.",
                Some(health.consecutive_failures),
            ),
            (
                "zkapi_indexer_last_success_timestamp_seconds",
                "Time of the last successful verified poll.",
                health.last_success_unix_ms.map(|ms| ms / 1_000),
            ),
            (
                "zkapi_indexer_sync_block",
                "Next block the indexer will read.",
                health.sync_block,
            ),
        ];
        for (name, help, value) in gauges {
            if let Some(value) = value {
                gauge(&mut out, name, help);
                out.push_str(&format!("{name} {value}\n"));
            }
        }
        for (name, help, value) in [
            (
                "zkapi_indexer_divergences_total",
                "Times the mirror diverged from the vault state.",
                health.divergence_count,
            ),
            (
                "zkapi_indexer_rebuilds_total",
                "Rebuilds from the deployment block.",
                health.rebuild_count,
            ),
        ] {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        let name = "zkapi_indexer_missed_re_escapes_total";
        out.push_str(&format!(
            "# HELP {name} Committed defeats, raises or finalizations of an escape the indexer never saw initiated, once per escape, by event.\n# TYPE {name} counter\n"
        ));
        for closed_by in EscapeClose::ALL {
            let value = match closed_by {
                EscapeClose::Challenged => health
                    .missed_re_escape_count
                    .saturating_sub(health.missed_re_escape_finalized_count)
                    .saturating_sub(health.missed_re_escape_raised_count),
                EscapeClose::Finalized => health.missed_re_escape_finalized_count,
                EscapeClose::Raised => health.missed_re_escape_raised_count,
            };
            out.push_str(&format!(
                "{name}{{event=\"{}\"}} {value}\n",
                closed_by.as_str()
            ));
        }
        out
    }
}

fn gauge(out: &mut String, name: &str, help: &str) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
}

fn head_age_ms(state: &State) -> Option<u64> {
    state
        .head_timestamp
        .map(|timestamp| unix_ms().saturating_sub(timestamp.saturating_mul(1_000)))
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_millis() as u64)
}

/// Internal health report (`/health`). Unknown values are `null`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: SyncStatus,
    pub reason: Option<String>,
    pub chain_id: Option<u64>,
    pub contract_address: String,
    pub confirmations: u64,
    pub head_block: Option<u64>,
    pub head_timestamp: Option<u64>,
    pub head_age_seconds: Option<u64>,
    pub served_block: Option<u64>,
    pub served_block_hash: Option<String>,
    pub root: Option<Felt252>,
    pub next_note_id: Option<u32>,
    pub lag_blocks: Option<u64>,
    pub confirmed_block: Option<u64>,
    pub confirmed_block_hash: Option<String>,
    pub confirmed_root: Option<Felt252>,
    pub confirmed_next_note_id: Option<u32>,
    pub sync_block: Option<u64>,
    pub last_success_unix_ms: Option<u64>,
    pub last_verified_unix_ms: Option<u64>,
    pub consecutive_failures: u64,
    pub last_error: Option<String>,
    pub divergence_count: u64,
    pub rebuild_count: u64,
    /// Committed challenges or finalizations of an escape the indexer never
    /// saw initiated, once per escape and closing event in this process: its
    /// logs missed a challenge and re-escape of the note, or a reorganization
    /// below the checkpoint replaced the note's escape (see `MissedReEscape`).
    #[serde(default)]
    pub missed_re_escape_count: u64,
    /// Of those, finalizations: the vault finalized (paid or credited) an
    /// escape the indexer's pending list never showed.
    #[serde(default)]
    pub missed_re_escape_finalized_count: u64,
    /// Of those, raises of an escape the pending list never showed.
    #[serde(default)]
    pub missed_re_escape_raised_count: u64,
    /// Roots the vault ever set, in the served view (Amendment A1).
    #[serde(default)]
    pub known_root_count: Option<u64>,
    /// Nullifiers vault events made public, in the served view (§5.2).
    #[serde(default)]
    pub published_nullifier_count: Option<u64>,
}

/// Response type for tree endpoints.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeRootResponse {
    pub root: Felt252,
    #[serde(default)]
    pub next_note_id: u32,
    #[serde(default)]
    pub block_number: u64,
    #[serde(default)]
    pub block_hash: String,
}

/// A sibling path. `root` is the view's root: the siblings hash to it with
/// `leaf` (and, for a zero-path, with the empty leaf of an unused slot).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreePathResponse {
    pub note_id: u32,
    pub leaf: Felt252,
    pub siblings: Vec<Felt252>,
    #[serde(default)]
    pub root: Felt252,
    #[serde(default)]
    pub block_number: u64,
    #[serde(default)]
    pub block_hash: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct NextNoteIdResponse {
    pub next_note_id: u32,
    #[serde(default)]
    pub root: Felt252,
    #[serde(default)]
    pub block_number: u64,
    #[serde(default)]
    pub block_hash: String,
}

/// Whole-tree snapshot: clients rebuild the tree and derive any sibling path
/// locally, so the untrusted indexer never learns which note a client queries.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TreeSnapshotResponse {
    pub root: Felt252,
    pub next_note_id: u32,
    pub leaves: Vec<Felt252>,
    #[serde(default)]
    pub block_number: u64,
    #[serde(default)]
    pub block_hash: String,
}

/// Escape withdrawals open in the verified view (internal), with their
/// concession (`next_nullifier`, `state_balance`, `conceded`). Escapes change
/// no leaf, so the view's root check does not cover the list: the challenger
/// uses it as a completeness check for its own event scan, and each entry is
/// the last one applied from the logs, a hint. Consumers read
/// `pendingWithdrawals(note)` and `pendingConcessions(note)` from the vault.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PendingEscapesResponse {
    pub block_number: u64,
    pub block_hash: String,
    pub root: Felt252,
    pub escapes: Vec<PendingEscape>,
}

/// `GET /v1/nullifiers/{N}/published`: whether a vault event made `N`
/// public, as a `withdrawalNullifier` or `nextNullifier` (§5.2). serverd
/// never serves evidence or request data of a published nullifier.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PublishedNullifierResponse {
    pub nullifier: Felt252,
    pub published: bool,
    pub block_number: u64,
    pub block_hash: String,
}

/// `GET /v1/tree/roots/{root}`: whether the vault ever set `root`, so that
/// it accepts proofs made at it (`knownRoots`, Amendment A1).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct KnownRootResponse {
    pub root: Felt252,
    pub known: bool,
    /// The current root of the served view.
    pub current_root: Felt252,
    pub block_number: u64,
    pub block_hash: String,
}
