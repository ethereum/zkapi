//! Ethereum JSON-RPC log poller for the indexer.
//!
//! The poller keeps two tiers of mirrored vault state, both verified against
//! the vault itself:
//!
//! - The committed tier is a durable checkpoint at a block at least
//!   `confirmations` below the head. A batch of logs is committed only after
//!   it applied cleanly and the vault's `currentRoot()` and `nextNoteId()`,
//!   read by `eth_call` pinned to the batch's last block hash (EIP-1898),
//!   equal the staged mirror. Only this tier is persisted.
//! - The served tier is a head view: the committed mirror plus the logs above
//!   it, re-derived whenever the head changes, verified the same way at the
//!   head block hash, and published atomically. It is never persisted.
//!
//! A reorg no deeper than `confirmations` is absorbed by re-deriving the head
//! view. A reorg below the checkpoint re-anchors it when the vault state is
//! unchanged and rebuilds from the deployment block otherwise. A persistent
//! mismatch takes the indexer out of service (503) instead of serving a root
//! the vault never had.

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_types::Felt252;

use crate::events::VaultEvent;
use crate::service::{unix_ms, IndexerService, SyncStatus, TreeView};
use crate::tree_mirror::{EscapeClose, MissedReEscape, TreeMirror, TreeMirrorSnapshot};

/// Version 3: the append-only tree of vault revision 3, with note statuses,
/// known roots and the published-nullifier table. Earlier checkpoints mirror
/// a tree whose exits removed leaves; they are archived and replayed.
const CHECKPOINT_VERSION: u32 = 3;
/// The statement of the vaults this indexer mirrors. A checkpoint records it.
pub const CIRCUIT_ID: &str = "zkapi-v2-concession-v1";
/// `currentRoot()`
const CURRENT_ROOT: &str = "0xfdab463d";
/// `nextNoteId()`
const NEXT_NOTE_ID: &str = "0x7a2043a3";
/// `CONCESSION_ESCAPE_VERSION()`, 1 on a revision-3 vault and absent before.
const CONCESSION_ESCAPE_VERSION: &str = "0x5e00b426";
const RPC_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest parent-hash walk used to confirm that a reorganized checkpoint
/// block is an ancestor of the head. Beyond it two sightings suffice.
const MAX_ANCESTRY_WALK: u64 = 256;
/// Most blocks below the head tried, newest first, when the head overlay
/// does not verify (also bounded by the confirmation depth).
const MAX_HEAD_FALLBACK_BLOCKS: u64 = 16;
const DEFAULT_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(5);
const MAX_RATE_LIMIT_BACKOFF: Duration = Duration::from_secs(60);
const JSON_RPC_INVALID_PARAMS: i64 = -32602;

#[derive(Debug, Clone)]
pub struct PollerConfig {
    pub rpc_url: String,
    pub contract_address: String,
    pub from_block: u64,
    pub cursor_path: Option<String>,
    /// Depth below the head at which logs are committed to the checkpoint.
    pub confirmations: u64,
    /// Expected chain id. When unset, the checkpoint's or the RPC's is used.
    pub chain_id: Option<u64>,
    /// Largest `eth_getLogs` range.
    pub max_block_range: u64,
    /// Consecutive mismatching polls before the indexer reports divergence.
    pub divergence_threshold: u32,
    /// Shortest mismatch streak, in time, before the indexer reports divergence.
    pub divergence_grace: Duration,
    /// Minimum spacing of automatic rebuilds, and how long a divergence must
    /// persist before it triggers one. An operator resync is immediate.
    pub rebuild_after: Duration,
    /// Archive the checkpoint and replay from `from_block`.
    pub resync: bool,
    /// Pause between catch-up chunks, to stay under provider rate limits.
    pub catch_up_interval: Duration,
    /// Polls whose reorganized checkpoint state cannot be read before the
    /// indexer falls back to a rebuild.
    pub anchor_unavailable_limit: u32,
}

impl Default for PollerConfig {
    fn default() -> Self {
        Self {
            rpc_url: "http://127.0.0.1:8545".to_string(),
            contract_address: "0x0000000000000000000000000000000000000000".to_string(),
            from_block: 0,
            cursor_path: Some("zkapi-indexer.cursor".to_string()),
            confirmations: 12,
            chain_id: None,
            max_block_range: 1_000,
            divergence_threshold: 3,
            divergence_grace: Duration::from_secs(30),
            rebuild_after: Duration::from_secs(300),
            resync: false,
            catch_up_interval: Duration::from_millis(100),
            anchor_unavailable_limit: 5,
        }
    }
}

/// A block identified by number and hash (`0x` + 64 lowercase hex).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockRef {
    pub number: u64,
    pub hash: String,
}

/// Whether `poll_once` should be called again right away.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PollOutcome {
    Idle,
    MoreWork,
}

/// Result of comparing a mirror with the vault state at a block.
enum Verdict {
    Match,
    Mismatch(String),
    /// The state could not be read (RPC error, pruned state, unknown or
    /// non-canonical block hash). Never treated as evidence either way.
    Unavailable(anyhow::Error),
}

#[derive(Debug, Clone)]
struct Header {
    number: u64,
    hash: String,
    parent_hash: String,
    timestamp: u64,
}

impl Header {
    fn block_ref(&self) -> BlockRef {
        BlockRef {
            number: self.number,
            hash: self.hash.clone(),
        }
    }
}

#[derive(Clone)]
struct Committed {
    mirror: Arc<TreeMirror>,
    anchor: Option<BlockRef>,
    /// Block of the latest committed lifecycle event (any event but a
    /// deposit or a leaf retirement). Lifecycle events change no root, so a
    /// reorg below the checkpoint near one is rebuilt, never re-anchored.
    last_lifecycle_block: Option<u64>,
}

impl Committed {
    fn genesis() -> Self {
        Self {
            mirror: Arc::new(TreeMirror::new()),
            anchor: None,
            last_lifecycle_block: None,
        }
    }
}

struct AnchorCandidate {
    hash: String,
    sightings: u32,
}

/// Catch-up progress above the anchor whose state could not be verified
/// (pruned history). Never served or persisted.
struct Provisional {
    mirror: Arc<TreeMirror>,
    /// Missed re-escapes in the held chunks, reported only when a later
    /// chunk verifies and commits them.
    missed_re_escapes: Vec<MissedReEscapeAt>,
    last_lifecycle_block: Option<u64>,
}

pub struct JsonRpcLogPoller {
    client: Client,
    rpc_url: String,
    contract_address: String,
    cfg: PollerConfig,
    /// Verified, persisted state at `committed.anchor`.
    committed: Committed,
    provisional: Option<Provisional>,
    /// First block not yet applied to the working (committed or provisional)
    /// mirror.
    next_block: u64,
    chain_id: Option<u64>,
    chain_verified: bool,
    chain_mismatch_reported: bool,
    /// The vault reported `CONCESSION_ESCAPE_VERSION() == 1` in this process.
    vault_verified: bool,
    vault_mismatch_reported: bool,
    published: Option<BlockRef>,
    /// The committed state is a restored checkpoint not yet verified in this
    /// process.
    startup_check_pending: bool,
    anchor_checked_at: Option<BlockRef>,
    anchor_candidate: Option<AnchorCandidate>,
    anchor_unavailable: u32,
    mismatch_streak: u32,
    mismatch_since: Option<Instant>,
    diverged: bool,
    diverged_since: Option<Instant>,
    last_rebuild: Option<Instant>,
    rebuild_started: Option<Instant>,
    pending_rebuild: Option<String>,
    eip1898_reported: bool,
    /// Missed re-escapes already reported, by note id, nullifier and closing
    /// event. A rebuild replays the same history and must not report them
    /// again.
    reported_missed_re_escapes: HashSet<(u32, Felt252, EscapeClose)>,
    cursor_path: Option<PathBuf>,
    _lock: Option<File>,
}

impl JsonRpcLogPoller {
    /// Acquire the checkpoint lock and load (or archive) the checkpoint.
    /// Nothing is served until a head view verifies.
    pub fn new(config: PollerConfig, service: &IndexerService) -> anyhow::Result<Self> {
        let contract_address = normalize_address(&config.contract_address)?;
        anyhow::ensure!(
            config.max_block_range > 0,
            "max block range must be positive"
        );
        let client = Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .context("failed to build rpc client")?;
        let cursor_path = config.cursor_path.as_deref().map(PathBuf::from);
        let mut poller = Self {
            client,
            rpc_url: config.rpc_url.clone(),
            contract_address,
            committed: Committed::genesis(),
            provisional: None,
            next_block: config.from_block,
            chain_id: config.chain_id,
            chain_verified: false,
            chain_mismatch_reported: false,
            vault_verified: false,
            vault_mismatch_reported: false,
            published: None,
            startup_check_pending: false,
            anchor_checked_at: None,
            anchor_candidate: None,
            anchor_unavailable: 0,
            mismatch_streak: 0,
            mismatch_since: None,
            diverged: false,
            diverged_since: None,
            last_rebuild: None,
            rebuild_started: None,
            pending_rebuild: None,
            eip1898_reported: false,
            reported_missed_re_escapes: HashSet::new(),
            cursor_path: cursor_path.clone(),
            _lock: None,
            cfg: config,
        };

        if let Some(path) = cursor_path {
            poller._lock = Some(lock_checkpoint(&path)?);
            let sentinel = sidecar(&path, "resync");
            if poller.cfg.resync || sentinel.exists() {
                let archived = if path.exists() {
                    Some(archive(&path, "resync")?)
                } else {
                    None
                };
                if sentinel.exists() {
                    if let Err(err) = fs::remove_file(&sentinel) {
                        tracing::error!(
                            path = %sentinel.display(),
                            error = %err,
                            "failed to remove the resync sentinel; every restart will resync until it is removed"
                        );
                    }
                }
                tracing::info!(
                    archived = ?archived.as_ref().map(|path| path.display().to_string()),
                    from_block = poller.cfg.from_block,
                    "resync requested; archived checkpoint"
                );
            } else if let Some(checkpoint) =
                load_checkpoint(&path, &poller.contract_address, poller.cfg.chain_id)?
            {
                poller.restore(checkpoint, service);
            }
        }
        service.set_sync_block(poller.next_block);
        Ok(poller)
    }

    fn restore(&mut self, checkpoint: LoadedCheckpoint, service: &IndexerService) {
        let anchor = checkpoint.anchor;
        tracing::info!(
            block = anchor.number,
            root = %checkpoint.mirror.root(),
            next_note_id = checkpoint.mirror.next_note_id(),
            "restored indexer checkpoint; verifying against the vault before serving"
        );
        service.set_confirmed(
            anchor.number,
            anchor.hash.clone(),
            checkpoint.mirror.root(),
            checkpoint.mirror.next_note_id(),
        );
        service.set_chain_id(checkpoint.chain_id);
        self.next_block = anchor.number.saturating_add(1);
        self.committed = Committed {
            mirror: Arc::new(checkpoint.mirror),
            anchor: Some(anchor),
            last_lifecycle_block: checkpoint.last_lifecycle_block,
        };
        self.chain_id = Some(checkpoint.chain_id);
        self.startup_check_pending = true;
    }

    /// First block the next commit batch will read.
    pub fn next_block(&self) -> u64 {
        self.next_block
    }

    /// Poll until idle, pacing catch-up chunks, and record any failure.
    /// Returns the delay a rate-limited RPC asked for, if any.
    pub async fn run_cycle(&mut self, service: &IndexerService) -> Option<Duration> {
        loop {
            match self.poll_once(service).await {
                Ok(PollOutcome::MoreWork) => {
                    if self.cfg.catch_up_interval.is_zero() {
                        tokio::task::yield_now().await;
                    } else {
                        tokio::time::sleep(self.cfg.catch_up_interval).await;
                    }
                }
                Ok(PollOutcome::Idle) => return None,
                Err(err) => {
                    let message = format!("{err:#}");
                    tracing::warn!(error = %message, "indexer rpc poll failed");
                    service.record_failure(message);
                    return retry_delay(&err);
                }
            }
        }
    }

    /// One step of the poller: at most one commit chunk, then (once caught
    /// up) one verified head view.
    pub async fn poll_once(&mut self, service: &IndexerService) -> anyhow::Result<PollOutcome> {
        if let Some(reason) = self.pending_rebuild.clone() {
            if !self.rebuild_allowed() {
                return Ok(PollOutcome::Idle);
            }
            self.start_rebuild(service, &reason);
        }

        // S1. Head discovery.
        let head = self
            .header_by_number("latest")
            .await?
            .ok_or_else(|| anyhow!("rpc returned no latest block"))?;
        let head_ref = head.block_ref();
        let head_fresh = service.observe_head(head.number, head.timestamp);
        if let Some(anchor) = &self.committed.anchor {
            if head.number < anchor.number {
                bail!(
                    "rpc head {} is below the committed checkpoint block {}; waiting for the rpc to catch up",
                    head.number,
                    anchor.number
                );
            }
        }

        // S2. Chain id, after start or rebuild and while it disagrees.
        if !self.chain_verified && !self.verify_chain_id(service).await? {
            return Ok(PollOutcome::Idle);
        }
        // S2b. The vault's revision, once per process: this mirror's rules
        // (an append-only tree, concession events) are revision 3's.
        if !self.vault_verified && !self.verify_vault_revision(service, &head_ref).await? {
            return Ok(PollOutcome::Idle);
        }

        if let Some(published) = &self.published {
            if *published == head_ref {
                // The served view is the head state. A divergence or a head
                // that stopped advancing must not keep it looking fresh.
                if head_fresh && !self.diverged {
                    service.refresh_success();
                }
                return Ok(PollOutcome::Idle);
            }
            if published.number > head.number {
                tracing::debug!(
                    head = head.number,
                    served = published.number,
                    "rpc head is behind the served view; waiting"
                );
                return Ok(PollOutcome::Idle);
            }
        }

        // S3. Checkpoint continuity, once per distinct head.
        if self.committed.anchor.is_some() {
            if let Some(outcome) = self.check_anchor(service, &head).await? {
                return Ok(outcome);
            }
        }

        // S4. Commit tier, one chunk per call.
        let target = head.number.saturating_sub(self.cfg.confirmations);
        if self.next_block <= target {
            if let Some(outcome) = self.commit_chunk(service, &head_ref, target).await? {
                return Ok(outcome);
            }
        }

        // S5. Head overlay.
        if self.provisional.is_some() {
            // Unverified catch-up progress above a head that moved back.
            return Ok(PollOutcome::Idle);
        }
        self.publish_head_view(service, &head).await?;
        Ok(PollOutcome::Idle)
    }

    async fn verify_chain_id(&mut self, service: &IndexerService) -> anyhow::Result<bool> {
        let rpc_chain_id = parse_quantity(&self.rpc("eth_chainId", json!([])).await?)
            .context("invalid eth_chainId result")?;
        if let Some(expected) = self.chain_id {
            if rpc_chain_id != expected {
                let reason = format!(
                    "rpc chain id {rpc_chain_id} does not match expected chain id {expected}"
                );
                if !self.chain_mismatch_reported {
                    self.chain_mismatch_reported = true;
                    tracing::error!(reason = %reason, "indexer RPC serves another chain; tree endpoints return 503");
                }
                service.set_phase(SyncStatus::Diverged, Some(reason.clone()));
                service.record_failure(reason);
                self.published = None;
                return Ok(false);
            }
        }
        self.chain_mismatch_reported = false;
        self.chain_id = Some(rpc_chain_id);
        self.chain_verified = true;
        service.set_chain_id(rpc_chain_id);
        Ok(true)
    }

    /// Fail closed on a vault that is not revision 3 (`CONCESSION_ESCAPE_VERSION()`
    /// is not 1, or the getter does not exist): its exits remove leaves, which
    /// this mirror never does, so every view would be wrong.
    async fn verify_vault_revision(
        &mut self,
        service: &IndexerService,
        head: &BlockRef,
    ) -> anyhow::Result<bool> {
        let version = match self.call_word(CONCESSION_ESCAPE_VERSION, head).await {
            Ok(Some(word)) => Some(word),
            Ok(None) => bail!(
                "vault has no code at head block {} {}; waiting",
                head.number,
                head.hash
            ),
            Err(err) if is_revert(&err) => None,
            Err(err) => return Err(err.context("cannot read CONCESSION_ESCAPE_VERSION()")),
        };
        let one = {
            let mut word = [0u8; 32];
            word[31] = 1;
            word
        };
        if version == Some(one) {
            self.vault_verified = true;
            self.vault_mismatch_reported = false;
            return Ok(true);
        }
        let reason = match version {
            Some(word) => format!(
                "vault CONCESSION_ESCAPE_VERSION() is 0x{}, not 1: not a revision-3 vault ({CIRCUIT_ID})",
                hex::encode(word)
            ),
            None => format!(
                "vault has no CONCESSION_ESCAPE_VERSION(): a vault before revision 3, which this indexer ({CIRCUIT_ID}) cannot mirror"
            ),
        };
        if !self.vault_mismatch_reported {
            self.vault_mismatch_reported = true;
            tracing::error!(reason = %reason, "indexer refuses the vault; tree endpoints return 503");
        }
        service.set_phase(SyncStatus::Diverged, Some(reason.clone()));
        service.record_failure(reason);
        self.published = None;
        Ok(false)
    }

    async fn check_anchor(
        &mut self,
        service: &IndexerService,
        head: &Header,
    ) -> anyhow::Result<Option<PollOutcome>> {
        let anchor = self.committed.anchor.clone().expect("checked by caller");
        let head_ref = head.block_ref();
        if self.anchor_checked_at.as_ref() != Some(&head_ref) {
            let canonical = self.header_by_number(&hex_quantity(anchor.number)).await?;
            let canonical = canonical.ok_or_else(|| {
                anyhow!(
                    "rpc has no block {} for the committed checkpoint",
                    anchor.number
                )
            })?;
            if canonical.hash != anchor.hash {
                return self
                    .handle_reorged_anchor(service, head, &anchor, canonical)
                    .await;
            }
            self.anchor_candidate = None;
            self.anchor_unavailable = 0;
            self.anchor_checked_at = Some(head_ref);
        }

        if self.startup_check_pending {
            let mirror = self.committed.mirror.clone();
            match self.verify_state(&mirror, &anchor, false).await {
                Verdict::Mismatch(detail) => {
                    self.startup_check_pending = false;
                    tracing::error!(
                        detail = %detail,
                        "indexer checkpoint does not match the vault state; archiving it"
                    );
                    if let Some(path) = &self.cursor_path {
                        if let Err(err) = archive(path, "corrupt") {
                            tracing::error!(error = %err, "failed to archive the corrupt checkpoint");
                        }
                    }
                    return Ok(Some(self.request_rebuild(
                        service,
                        format!("checkpoint does not match vault state: {detail}"),
                    )));
                }
                Verdict::Match => self.startup_check_pending = false,
                // Retried on the next poll. Until it passes, the restored
                // state is published only through a view verified on its own.
                Verdict::Unavailable(err) => tracing::debug!(
                    error = %format!("{err:#}"),
                    "checkpoint state unavailable at startup; retrying on the next poll"
                ),
            }
        }
        Ok(None)
    }

    async fn handle_reorged_anchor(
        &mut self,
        service: &IndexerService,
        head: &Header,
        anchor: &BlockRef,
        canonical: Header,
    ) -> anyhow::Result<Option<PollOutcome>> {
        let sightings = match &mut self.anchor_candidate {
            Some(candidate) if candidate.hash == canonical.hash => {
                candidate.sightings = candidate.sightings.saturating_add(1);
                candidate.sightings
            }
            _ => {
                tracing::warn!(
                    block = anchor.number,
                    stored_hash = %anchor.hash,
                    canonical_hash = %canonical.hash,
                    "indexer checkpoint block was reorganized"
                );
                self.anchor_candidate = Some(AnchorCandidate {
                    hash: canonical.hash.clone(),
                    sightings: 1,
                });
                1
            }
        };
        // A load-balanced RPC can briefly serve a stale fork; act only on a
        // hash seen on consecutive polls and on the head's own ancestry.
        if sightings < 2 {
            bail!(
                "checkpoint block {} changed hash; confirming on the next poll",
                anchor.number
            );
        }
        if !self.is_ancestor(head, &canonical).await? {
            self.anchor_candidate = None;
            bail!(
                "reorganized checkpoint block {} ({}) is not an ancestor of head {}",
                anchor.number,
                canonical.hash,
                head.number
            );
        }

        let mirror = self.committed.mirror.clone();
        match self
            .verify_state(&mirror, &canonical.block_ref(), false)
            .await
        {
            Verdict::Match
                if self.committed.last_lifecycle_block.is_some_and(|block| {
                    block.saturating_add(MAX_ANCESTRY_WALK) >= anchor.number
                }) =>
            {
                // The tree is unchanged, but exits, defeats and raises change
                // no root: the reorg may have removed one the mirror holds.
                self.anchor_candidate = None;
                Ok(Some(self.request_rebuild(
                    service,
                    format!(
                        "reorg below checkpoint at block {} near a committed exit or defeat (block {}); its replacement cannot be verified by the root",
                        anchor.number,
                        self.committed.last_lifecycle_block.unwrap_or_default()
                    ),
                )))
            }
            Verdict::Match => {
                self.anchor_candidate = None;
                self.anchor_unavailable = 0;
                self.provisional = None;
                self.startup_check_pending = false;
                self.next_block = anchor.number.saturating_add(1);
                self.committed.anchor = Some(canonical.block_ref());
                self.anchor_checked_at = Some(head.block_ref());
                self.persist_committed();
                service.set_confirmed(
                    canonical.number,
                    canonical.hash.clone(),
                    mirror.root(),
                    mirror.next_note_id(),
                );
                tracing::warn!(
                    block = canonical.number,
                    hash = %canonical.hash,
                    "indexer checkpoint re-anchored; vault state unchanged"
                );
                Ok(None)
            }
            Verdict::Mismatch(detail) => {
                self.anchor_candidate = None;
                Ok(Some(self.request_rebuild(
                    service,
                    format!(
                        "reorg below checkpoint at block {}: {detail}",
                        anchor.number
                    ),
                )))
            }
            Verdict::Unavailable(err) => {
                self.anchor_unavailable = self.anchor_unavailable.saturating_add(1);
                if self.anchor_unavailable >= self.cfg.anchor_unavailable_limit {
                    self.anchor_candidate = None;
                    self.anchor_unavailable = 0;
                    return Ok(Some(self.request_rebuild(
                        service,
                        format!(
                            "vault state at reorganized checkpoint block {} is unavailable",
                            anchor.number
                        ),
                    )));
                }
                Err(err.context(format!(
                    "cannot verify reorganized checkpoint block {}",
                    anchor.number
                )))
            }
        }
    }

    /// Whether `block` is on the head's parent-hash chain.
    async fn is_ancestor(&self, head: &Header, block: &Header) -> anyhow::Result<bool> {
        if head.number <= block.number {
            return Ok(head.number == block.number && head.hash == block.hash);
        }
        if head.number - block.number > MAX_ANCESTRY_WALK {
            return Ok(true);
        }
        let mut cursor = head.clone();
        while cursor.number > block.number + 1 {
            let parent = self
                .header_by_hash(&cursor.parent_hash)
                .await?
                .ok_or_else(|| anyhow!("rpc has no block {}", cursor.parent_hash))?;
            if parent.number + 1 != cursor.number {
                bail!(
                    "rpc returned an inconsistent parent for block {}",
                    cursor.number
                );
            }
            cursor = parent;
        }
        Ok(cursor.parent_hash == block.hash)
    }

    async fn commit_chunk(
        &mut self,
        service: &IndexerService,
        head: &BlockRef,
        target: u64,
    ) -> anyhow::Result<Option<PollOutcome>> {
        let from = self.next_block;
        let to = target.min(from.saturating_add(self.cfg.max_block_range - 1));
        let to_header = self
            .header_by_number(&hex_quantity(to))
            .await?
            .ok_or_else(|| anyhow!("rpc has no block {to}"))?;
        let logs = self.fetch_logs(from, to, &to_header.hash).await?;
        let base = self
            .provisional
            .as_ref()
            .map_or_else(|| self.committed.mirror.clone(), |held| held.mirror.clone());
        let (staged, chunk_missed, chunk_lifecycle) = match apply_logs(&base, &logs) {
            Ok(applied) => (
                applied.mirror,
                applied.missed_re_escapes,
                applied.last_lifecycle_block,
            ),
            Err(detail) => {
                self.on_mismatch(service, detail).await;
                return Ok(Some(PollOutcome::Idle));
            }
        };
        let to_ref = to_header.block_ref();
        match self.verify_state(&staged, &to_ref, false).await {
            Verdict::Match => {
                let (mut missed, held_lifecycle) = self.take_provisional();
                missed.extend(chunk_missed);
                let lifecycle = self
                    .committed
                    .last_lifecycle_block
                    .max(held_lifecycle)
                    .max(chunk_lifecycle);
                self.commit(service, staged, to_ref, lifecycle);
                // Read by number under this head and verified as canonical.
                self.anchor_checked_at = Some(head.clone());
                self.report_missed_re_escapes(service, &missed);
            }
            Verdict::Mismatch(detail) => {
                self.on_mismatch(service, detail).await;
                return Ok(Some(PollOutcome::Idle));
            }
            Verdict::Unavailable(err) if to < target => {
                // Historical state is pruned on non-archive nodes. Hold the
                // chunk in memory; the final chunk must verify before
                // anything is persisted, served or reported.
                tracing::debug!(
                    from,
                    to,
                    error = %format!("{err:#}"),
                    "historical vault state unavailable; holding catch-up chunk in memory"
                );
                let (mut missed, held_lifecycle) = self.take_provisional();
                missed.extend(chunk_missed);
                self.provisional = Some(Provisional {
                    mirror: staged,
                    missed_re_escapes: missed,
                    last_lifecycle_block: held_lifecycle.max(chunk_lifecycle),
                });
                self.next_block = to + 1;
            }
            Verdict::Unavailable(err) => {
                return Err(err.context(format!("cannot verify vault state at block {to}")));
            }
        }
        service.set_sync_block(self.next_block);
        Ok((self.next_block <= target).then_some(PollOutcome::MoreWork))
    }

    fn commit(
        &mut self,
        service: &IndexerService,
        mirror: Arc<TreeMirror>,
        at: BlockRef,
        last_lifecycle_block: Option<u64>,
    ) {
        service.set_confirmed(
            at.number,
            at.hash.clone(),
            mirror.root(),
            mirror.next_note_id(),
        );
        self.next_block = at.number.saturating_add(1);
        self.provisional = None;
        self.anchor_candidate = None;
        self.anchor_unavailable = 0;
        self.startup_check_pending = false;
        self.committed = Committed {
            mirror,
            anchor: Some(at),
            last_lifecycle_block,
        };
        self.persist_committed();
    }

    /// Missed re-escapes and the latest lifecycle block of the held catch-up
    /// chunks, if any; the held chunks themselves are dropped.
    fn take_provisional(&mut self) -> (Vec<MissedReEscapeAt>, Option<u64>) {
        self.provisional
            .take()
            .map(|held| (held.missed_re_escapes, held.last_lifecycle_block))
            .unwrap_or_default()
    }

    /// Log and count each missed re-escape a verified commit took, once per
    /// escape and closing event in this process: a rebuild replays the same
    /// history.
    fn report_missed_re_escapes(&mut self, service: &IndexerService, missed: &[MissedReEscapeAt]) {
        for at in missed {
            let event = &at.event;
            if !self.reported_missed_re_escapes.insert((
                event.note_id,
                event.nullifier,
                event.closed_by,
            )) {
                tracing::debug!(detail = %at, "missed re-escape already reported");
                continue;
            }
            match event.closed_by {
                EscapeClose::Challenged => tracing::warn!(
                    detail = %at,
                    "escape challenged that the indexer never saw initiated: the rpc logs missed a challenge and re-escape of the note, or a reorg below the checkpoint replaced its escape; the pending list showed a stale nullifier and deadline until now"
                ),
                EscapeClose::Raised => tracing::warn!(
                    detail = %at,
                    "escape raised that the indexer never saw initiated: the rpc logs missed a challenge and re-escape of the note, or a reorg below the checkpoint replaced its escape; the pending list now shows the raised escape without its successor nullifier"
                ),
                // The vault finalized (paid or credited) an escape the pending
                // list never showed.
                EscapeClose::Finalized => tracing::error!(
                    detail = %at,
                    "escape finalized that the indexer never saw initiated: the rpc logs missed a challenge and re-escape of the note, or a reorg below the checkpoint replaced its escape; the pending list showed a stale nullifier and deadline until now, so check that the challenge service tracked this escape"
                ),
            }
            service.bump_missed_re_escapes(event.closed_by);
        }
    }

    async fn publish_head_view(
        &mut self,
        service: &IndexerService,
        head: &Header,
    ) -> anyhow::Result<()> {
        let head_ref = head.block_ref();
        let span = (head.number + 1).saturating_sub(self.next_block);
        if span > self.cfg.max_block_range {
            bail!(
                "head overlay would span {span} blocks above block {}; more than the max block range",
                self.next_block.saturating_sub(1)
            );
        }
        let logs = if span > 0 {
            self.fetch_logs(self.next_block, head.number, &head.hash)
                .await?
        } else {
            Vec::new()
        };
        let (overlay, last_event_block) = match apply_logs(&self.committed.mirror, &logs) {
            Ok(applied) => {
                // Re-derived on every head; reported once committed.
                for at in &applied.missed_re_escapes {
                    tracing::debug!(
                        detail = %at,
                        "escape closed above the checkpoint that the indexer never saw initiated"
                    );
                }
                (applied.mirror, applied.last_event_block)
            }
            Err(detail) => {
                self.on_mismatch(service, detail).await;
                return Ok(());
            }
        };
        if self.committed.anchor.as_ref() == Some(&head_ref) && !self.startup_check_pending {
            // Committed at the head (zero confirmations) and verified there by
            // this process. A restored checkpoint is verified like any view.
            self.publish(service, overlay, head_ref);
            return Ok(());
        }
        match self.verify_state(&overlay, &head_ref, true).await {
            Verdict::Match => self.publish(service, overlay, head_ref),
            Verdict::Mismatch(detail) => {
                // A log index that lags the head can still serve a slightly
                // older state that the vault verifiably had: any block above
                // the checkpoint at or after the last applied event.
                let lowest = last_event_block.unwrap_or(0).max(self.next_block);
                match self.verify_below_head(&overlay, head, lowest).await? {
                    Some(block) => {
                        tracing::debug!(
                            head = head.number,
                            served = block.number,
                            "rpc logs lag the head; serving the newest verifiable block"
                        );
                        self.publish(service, overlay, block);
                    }
                    None => self.on_mismatch(service, detail).await,
                }
            }
            Verdict::Unavailable(err) => {
                return Err(err.context(format!(
                    "cannot verify vault state at head block {}",
                    head.number
                )));
            }
        }
        Ok(())
    }

    /// Verify `overlay` at blocks from just below the head down to `lowest`,
    /// newest first, bounded by the confirmation depth.
    async fn verify_below_head(
        &mut self,
        overlay: &TreeMirror,
        head: &Header,
        lowest: u64,
    ) -> anyhow::Result<Option<BlockRef>> {
        let mut block = head.number;
        for _ in 0..self.cfg.confirmations.min(MAX_HEAD_FALLBACK_BLOCKS) {
            if block <= lowest {
                break;
            }
            block -= 1;
            let header = self
                .header_by_number(&hex_quantity(block))
                .await?
                .ok_or_else(|| anyhow!("rpc has no block {block}"))?;
            match self.verify_state(overlay, &header.block_ref(), true).await {
                Verdict::Match => return Ok(Some(header.block_ref())),
                Verdict::Mismatch(_) => {}
                Verdict::Unavailable(err) => {
                    return Err(err.context(format!("cannot verify vault state at block {block}")));
                }
            }
        }
        Ok(None)
    }

    fn publish(&mut self, service: &IndexerService, mirror: Arc<TreeMirror>, at: BlockRef) {
        let root = mirror.root();
        service.publish_head(TreeView::new(mirror, at.number, at.hash.clone()));
        if self.diverged {
            tracing::info!(block = at.number, root = %root, "indexer mirror reconciled with vault state");
        }
        if let Some(started) = self.rebuild_started.take() {
            tracing::info!(
                block = at.number,
                root = %root,
                seconds = started.elapsed().as_secs(),
                "indexer rebuild complete"
            );
        }
        self.published = Some(at);
        self.mismatch_streak = 0;
        self.mismatch_since = None;
        self.diverged = false;
        self.diverged_since = None;
        service.record_success();
    }

    async fn on_mismatch(&mut self, service: &IndexerService, detail: String) {
        // Staged state that failed is never kept; provisional catch-up
        // progress is dropped with it.
        self.provisional = None;
        self.next_block = self
            .committed
            .anchor
            .as_ref()
            .map_or(self.cfg.from_block, |anchor| {
                anchor.number.saturating_add(1)
            });
        self.mismatch_streak = self.mismatch_streak.saturating_add(1);
        let since = *self.mismatch_since.get_or_insert_with(Instant::now);
        service.record_failure(format!("vault state mismatch: {detail}"));
        service.set_sync_block(self.next_block);
        if self.mismatch_streak == 1 {
            tracing::warn!(detail = %detail, "indexer staged state does not match the vault; retrying");
        }

        if self.diverged {
            service.set_phase(SyncStatus::Diverged, Some(detail));
            if self
                .diverged_since
                .is_some_and(|since| since.elapsed() >= self.cfg.rebuild_after)
                && self.rebuild_allowed()
            {
                self.start_rebuild(service, "divergence persisted");
            }
            return;
        }
        if self.mismatch_streak >= self.cfg.divergence_threshold
            && since.elapsed() >= self.cfg.divergence_grace
        {
            self.diverged = true;
            self.diverged_since = Some(Instant::now());
            service.set_phase(SyncStatus::Diverged, Some(detail.clone()));
            service.bump_divergences();
            tracing::error!(
                detail = %detail,
                "indexer mirror diverged from vault state; tree endpoints return 503"
            );
            if let Some(anchor) = self.committed.anchor.clone() {
                let mirror = self.committed.mirror.clone();
                if let Verdict::Mismatch(base) = self.verify_state(&mirror, &anchor, false).await {
                    self.request_rebuild(
                        service,
                        format!("committed checkpoint does not match vault state: {base}"),
                    );
                }
            }
        }
    }

    fn rebuild_allowed(&self) -> bool {
        self.last_rebuild
            .is_none_or(|last| last.elapsed() >= self.cfg.rebuild_after)
    }

    /// Rebuild now, or fail closed until the rate limit allows it.
    fn request_rebuild(&mut self, service: &IndexerService, reason: String) -> PollOutcome {
        if self.rebuild_allowed() {
            self.start_rebuild(service, &reason);
            return PollOutcome::MoreWork;
        }
        tracing::error!(
            reason = %reason,
            "indexer rebuild is rate limited; tree endpoints return 503 until it runs"
        );
        service.set_phase(SyncStatus::Diverged, Some(reason.clone()));
        self.published = None;
        self.pending_rebuild = Some(reason);
        PollOutcome::Idle
    }

    /// Replay from the deployment block in memory. Partial state is never
    /// published; the checkpoint on disk is replaced by the first verified
    /// commit.
    fn start_rebuild(&mut self, service: &IndexerService, reason: &str) {
        tracing::error!(
            reason = %reason,
            from_block = self.cfg.from_block,
            "indexer rebuilding mirror from deployment block; tree endpoints return 503 until verified"
        );
        service.begin_rebuild(reason.to_string());
        self.committed = Committed::genesis();
        self.provisional = None;
        self.next_block = self.cfg.from_block;
        self.published = None;
        self.startup_check_pending = false;
        self.anchor_checked_at = None;
        self.anchor_candidate = None;
        self.anchor_unavailable = 0;
        self.mismatch_streak = 0;
        self.mismatch_since = None;
        self.diverged = false;
        self.diverged_since = None;
        self.pending_rebuild = None;
        self.chain_verified = false;
        self.last_rebuild = Some(Instant::now());
        self.rebuild_started = Some(Instant::now());
        service.set_sync_block(self.next_block);
    }

    /// Compare a mirror with `currentRoot()` and `nextNoteId()` read at the
    /// block hash. A lagging or forked replica yields `Unavailable`, never a
    /// false match.
    async fn verify_state(
        &mut self,
        mirror: &TreeMirror,
        at: &BlockRef,
        require_code: bool,
    ) -> Verdict {
        let root = match self.call_word(CURRENT_ROOT, at).await {
            Ok(word) => word,
            Err(err) => return Verdict::Unavailable(err),
        };
        let Some(root) = root else {
            // No vault code at this block, e.g. a range before deployment.
            if !require_code && mirror.is_empty() && mirror.root() == TreeMirror::empty_root() {
                return Verdict::Match;
            }
            if require_code {
                return Verdict::Unavailable(anyhow!(
                    "vault has no code at block {} {}",
                    at.number,
                    at.hash
                ));
            }
            return Verdict::Mismatch(format!(
                "vault has no code at block {} {}",
                at.number, at.hash
            ));
        };
        let root = match Felt252::try_from_bytes_be(root) {
            Ok(root) => root,
            Err(err) => return Verdict::Unavailable(anyhow!("invalid currentRoot word: {err}")),
        };
        let next_note_id = match self.call_word(NEXT_NOTE_ID, at).await {
            Ok(Some(word)) if word[..28].iter().all(|byte| *byte == 0) => {
                u32::from_be_bytes([word[28], word[29], word[30], word[31]])
            }
            Ok(_) => return Verdict::Unavailable(anyhow!("invalid nextNoteId result")),
            Err(err) => return Verdict::Unavailable(err),
        };
        if root == mirror.root() && next_note_id == mirror.next_note_id() {
            return Verdict::Match;
        }
        Verdict::Mismatch(format!(
            "block {} {}: vault root {} nextNoteId {}; mirror root {} next_note_id {}",
            at.number,
            at.hash,
            root,
            next_note_id,
            mirror.root(),
            mirror.next_note_id()
        ))
    }

    /// `eth_call` by EIP-1898 block hash. `None` when the vault has no code.
    async fn call_word(
        &mut self,
        selector: &str,
        at: &BlockRef,
    ) -> anyhow::Result<Option<[u8; 32]>> {
        let params = json!([
            { "to": &self.contract_address, "data": selector },
            { "blockHash": &at.hash, "requireCanonical": true },
        ]);
        let result = match self.rpc("eth_call", params).await {
            Ok(result) => result,
            Err(err) => {
                if rpc_error_code(&err) == Some(JSON_RPC_INVALID_PARAMS) {
                    if !self.eip1898_reported {
                        self.eip1898_reported = true;
                        tracing::error!(
                            "RPC rejected block-hash eth_call (EIP-1898); indexer cannot verify vault state"
                        );
                    }
                    return Err(err.context(
                        "rpc rejected block-hash eth_call (EIP-1898); indexer cannot verify vault state",
                    ));
                }
                return Err(err);
            }
        };
        let raw = result
            .as_str()
            .ok_or_else(|| anyhow!("eth_call result is not a string"))?;
        let raw = strip_hex_prefix(raw);
        if raw.is_empty() {
            return Ok(None);
        }
        if raw.len() != 64 {
            bail!(
                "eth_call returned {} bytes, expected one word",
                raw.len() / 2
            );
        }
        let mut word = [0u8; 32];
        hex::decode_to_slice(raw, &mut word).context("eth_call returned invalid hex")?;
        Ok(Some(word))
    }

    async fn header_by_number(&self, tag: &str) -> anyhow::Result<Option<Header>> {
        let result = self
            .rpc("eth_getBlockByNumber", json!([tag, false]))
            .await?;
        parse_header(result)
    }

    async fn header_by_hash(&self, hash: &str) -> anyhow::Result<Option<Header>> {
        let result = self.rpc("eth_getBlockByHash", json!([hash, false])).await?;
        parse_header(result)
    }

    async fn fetch_logs(&self, from: u64, to: u64, to_hash: &str) -> anyhow::Result<Vec<ChainLog>> {
        let filter = json!([{
            "address": &self.contract_address,
            "fromBlock": hex_quantity(from),
            "toBlock": hex_quantity(to),
        }]);
        let raw: Vec<RpcLog> = serde_json::from_value(self.rpc("eth_getLogs", filter).await?)
            .context("invalid eth_getLogs result")?;
        validate_logs(raw, &self.contract_address, from, to, to_hash)
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method,
            params,
            id: 1,
        };
        let response = self
            .client
            .post(&self.rpc_url)
            .json(&request)
            .send()
            .await
            .map_err(|err| RpcError::Transport(self.describe(err)))?;
        let status = response.status();
        if !status.is_success() {
            let retry_after = response
                .headers()
                .get(reqwest::header::RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            return Err(RpcError::Http {
                method: method.to_string(),
                status: status.as_u16(),
                retry_after,
            }
            .into());
        }
        let body: JsonRpcResponse = response
            .json()
            .await
            .map_err(|err| RpcError::Invalid(self.describe(err)))?;
        if let Some(error) = body.error {
            return Err(RpcError::Rpc {
                method: method.to_string(),
                code: error.code,
                message: error.message,
            }
            .into());
        }
        Ok(body.result.unwrap_or(Value::Null))
    }

    /// A transport error without the RPC URL, which can embed an API key.
    fn describe(&self, err: reqwest::Error) -> String {
        let err = err.without_url();
        let mut message = err.to_string();
        let mut source = std::error::Error::source(&err);
        while let Some(cause) = source {
            message.push_str(": ");
            message.push_str(&cause.to_string());
            source = cause.source();
        }
        message.replace(&self.rpc_url, "<rpc-url>")
    }

    fn persist_committed(&self) {
        let (Some(path), Some(anchor), Some(chain_id)) =
            (&self.cursor_path, &self.committed.anchor, self.chain_id)
        else {
            return;
        };
        let mirror = &self.committed.mirror;
        let checkpoint = IndexerCheckpoint {
            version: CHECKPOINT_VERSION,
            circuit_id: CIRCUIT_ID.to_string(),
            chain_id,
            contract_address: self.contract_address.clone(),
            from_block: self.cfg.from_block,
            last_processed_block: anchor.number,
            last_processed_block_hash: anchor.hash.clone(),
            root: mirror.root(),
            next_note_id: mirror.next_note_id(),
            last_lifecycle_block: self.committed.last_lifecycle_block,
            mirror: mirror.snapshot(),
        };
        if let Err(err) = write_checkpoint(path, &checkpoint) {
            tracing::error!(
                error = %format!("{err:#}"),
                "failed to persist indexer checkpoint; continuing from memory"
            );
        }
    }
}

pub fn spawn_json_rpc_log_poller(
    service: Arc<IndexerService>,
    mut poller: JsonRpcLogPoller,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            ticker.tick().await;
            if let Some(delay) = poller.run_cycle(&service).await {
                tracing::warn!(
                    seconds = delay.as_secs(),
                    "rpc rate limited the indexer; backing off"
                );
                tokio::time::sleep(delay).await;
            }
            if let Some(seconds) = service.stale_transition() {
                tracing::warn!("indexer view is stale; no verified poll for {seconds}s");
            }
        }
    })
}

/// Errors from the JSON-RPC transport. Messages never include the RPC URL.
#[derive(Debug, thiserror::Error)]
enum RpcError {
    #[error("rpc request failed: {0}")]
    Transport(String),
    #[error("rpc {method} returned HTTP {status}")]
    Http {
        method: String,
        status: u16,
        retry_after: Option<Duration>,
    },
    #[error("rpc {method} error {code}: {message}")]
    Rpc {
        method: String,
        code: i64,
        message: String,
    },
    #[error("invalid rpc response: {0}")]
    Invalid(String),
}

fn rpc_error(err: &anyhow::Error) -> Option<&RpcError> {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<RpcError>())
}

/// A JSON-RPC error of a reverted `eth_call` (geth code 3 with revert data,
/// or -32000 "execution reverted").
fn is_revert(err: &anyhow::Error) -> bool {
    matches!(
        rpc_error(err),
        Some(RpcError::Rpc { code, message, .. })
            if *code == 3 || message.to_ascii_lowercase().contains("revert")
    )
}

fn rpc_error_code(err: &anyhow::Error) -> Option<i64> {
    match rpc_error(err)? {
        RpcError::Rpc { code, .. } => Some(*code),
        _ => None,
    }
}

/// Backoff requested by a rate-limited RPC (HTTP 429 with Retry-After, or a
/// JSON-RPC limit error).
fn retry_delay(err: &anyhow::Error) -> Option<Duration> {
    match rpc_error(err)? {
        RpcError::Http {
            status: 429,
            retry_after,
            ..
        } => Some(
            retry_after
                .unwrap_or(DEFAULT_RATE_LIMIT_BACKOFF)
                .min(MAX_RATE_LIMIT_BACKOFF),
        ),
        RpcError::Rpc {
            code: 429 | -32005, ..
        } => Some(DEFAULT_RATE_LIMIT_BACKOFF),
        _ => None,
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct IndexerCheckpoint {
    version: u32,
    /// The statement of the vault mirrored (`CIRCUIT_ID`).
    circuit_id: String,
    chain_id: u64,
    contract_address: String,
    from_block: u64,
    last_processed_block: u64,
    last_processed_block_hash: String,
    root: Felt252,
    next_note_id: u32,
    #[serde(default)]
    last_lifecycle_block: Option<u64>,
    mirror: TreeMirrorSnapshot,
}

#[derive(Deserialize)]
struct CheckpointProbe {
    version: u32,
}

struct LoadedCheckpoint {
    chain_id: u64,
    anchor: BlockRef,
    mirror: TreeMirror,
    last_lifecycle_block: Option<u64>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcLog {
    #[serde(rename = "blockNumber")]
    pub block_number: String,
    #[serde(rename = "blockHash")]
    pub block_hash: String,
    #[serde(rename = "logIndex")]
    pub log_index: String,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub removed: Option<bool>,
    pub data: String,
    pub topics: Vec<String>,
}

/// A validated log with its parsed position.
#[derive(Debug, Clone)]
struct ChainLog {
    block: u64,
    index: u64,
    log: RpcLog,
}

#[derive(Debug, Serialize)]
struct JsonRpcRequest<'a> {
    jsonrpc: &'static str,
    method: &'a str,
    params: Value,
    id: u64,
}

#[derive(Debug, Deserialize)]
struct JsonRpcResponse {
    #[serde(default)]
    result: Option<Value>,
    #[serde(default)]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Deserialize)]
struct JsonRpcError {
    code: i64,
    message: String,
}

#[derive(Debug, Deserialize)]
struct RpcBlock {
    number: String,
    hash: String,
    #[serde(rename = "parentHash")]
    parent_hash: String,
    timestamp: String,
}

fn parse_header(result: Value) -> anyhow::Result<Option<Header>> {
    if result.is_null() {
        return Ok(None);
    }
    let block: RpcBlock = serde_json::from_value(result).context("invalid block header")?;
    Ok(Some(Header {
        number: parse_hex_u64(&block.number)?,
        hash: normalize_hash(&block.hash)?,
        parent_hash: normalize_hash(&block.parent_hash)?,
        timestamp: parse_hex_u64(&block.timestamp)?,
    }))
}

/// Reject a log batch that cannot be a complete, consistent answer for
/// `[from, to]`, then order it. Rejections are transient errors.
fn validate_logs(
    raw: Vec<RpcLog>,
    contract_address: &str,
    from: u64,
    to: u64,
    to_hash: &str,
) -> anyhow::Result<Vec<ChainLog>> {
    let mut block_hashes: HashMap<u64, String> = HashMap::new();
    let mut positions = HashSet::new();
    let mut logs = Vec::with_capacity(raw.len());
    for log in raw {
        if log.removed == Some(true) {
            bail!("rpc returned a removed log");
        }
        if let Some(address) = &log.address {
            if normalize_address(address)? != contract_address {
                bail!("rpc returned a log from another contract");
            }
        }
        let block = parse_hex_u64(&log.block_number)?;
        if block < from || block > to {
            bail!("rpc returned a log from block {block} outside {from}..={to}");
        }
        let hash = normalize_hash(&log.block_hash)?;
        if block == to && hash != to_hash {
            bail!("rpc returned a log for block {to} with hash {hash}, expected {to_hash}");
        }
        match block_hashes.entry(block) {
            Entry::Occupied(entry) if *entry.get() != hash => {
                bail!("rpc returned logs for block {block} with different block hashes");
            }
            Entry::Occupied(_) => {}
            Entry::Vacant(entry) => {
                entry.insert(hash);
            }
        }
        let index = parse_hex_u64(&log.log_index)?;
        if !positions.insert((block, index)) {
            bail!("rpc returned log {index} of block {block} twice");
        }
        logs.push(ChainLog { block, index, log });
    }
    logs.sort_by_key(|log| (log.block, log.index));
    Ok(logs)
}

/// A missed re-escape and the log that revealed it.
#[derive(Debug, Clone)]
struct MissedReEscapeAt {
    block: u64,
    log_index: u64,
    event: MissedReEscape,
}

impl std::fmt::Display for MissedReEscapeAt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "block {} log {}: {}",
            self.block, self.log_index, self.event
        )
    }
}

/// Logs applied to a copy of a mirror.
struct Applied {
    /// The staged mirror; the base itself when no log decodes to a vault event.
    mirror: Arc<TreeMirror>,
    /// Block of the last vault event.
    last_event_block: Option<u64>,
    /// Block of the last lifecycle event (not a deposit or retirement).
    last_lifecycle_block: Option<u64>,
    /// Events that ended or raised an escape the mirror never saw initiated.
    missed_re_escapes: Vec<MissedReEscapeAt>,
}

/// Apply logs to a copy of `base`.
fn apply_logs(base: &Arc<TreeMirror>, logs: &[ChainLog]) -> Result<Applied, String> {
    let mut staged: Option<TreeMirror> = None;
    let mut last_event_block = None;
    let mut last_lifecycle_block = None;
    let mut missed_re_escapes = Vec::new();
    for log in logs {
        let event = decode_log(&log.log)
            .map_err(|err| format!("block {} log {}: {err}", log.block, log.index))?;
        let Some(event) = event else {
            continue;
        };
        let missed = staged
            .get_or_insert_with(|| (**base).clone())
            .apply_event(&event)
            .map_err(|err| format!("block {} log {}: {err}", log.block, log.index))?;
        if let Some(event) = missed {
            missed_re_escapes.push(MissedReEscapeAt {
                block: log.block,
                log_index: log.index,
                event,
            });
        }
        last_event_block = Some(log.block);
        if !matches!(
            event,
            VaultEvent::NoteDeposited { .. } | VaultEvent::ClosedLeafRetired { .. }
        ) {
            last_lifecycle_block = Some(log.block);
        }
    }
    Ok(Applied {
        mirror: staged.map(Arc::new).unwrap_or_else(|| base.clone()),
        last_event_block,
        last_lifecycle_block,
        missed_re_escapes,
    })
}

fn lock_checkpoint(path: &Path) -> anyhow::Result<File> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create cursor dir {}", parent.display()))?;
    }
    let lock_path = sidecar(path, "lock");
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(&lock_path)
        .with_context(|| format!("failed to open {}", lock_path.display()))?;
    fs2::FileExt::try_lock_exclusive(&file).context("another indexer holds this checkpoint")?;
    Ok(file)
}

/// `<cursor>.<suffix>`, next to the checkpoint.
fn sidecar(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path
        .file_name()
        .map(|name| name.to_os_string())
        .unwrap_or_default();
    name.push(".");
    name.push(suffix);
    path.with_file_name(name)
}

/// Move the checkpoint aside as `<cursor>.<tag>-<unix_ms>.bak`, never
/// replacing an earlier archive.
fn archive(path: &Path, tag: &str) -> anyhow::Result<PathBuf> {
    let stamp = unix_ms();
    let mut target = sidecar(path, &format!("{tag}-{stamp}.bak"));
    let mut attempt = 0;
    while target.exists() {
        attempt += 1;
        target = sidecar(path, &format!("{tag}-{stamp}-{attempt}.bak"));
    }
    fs::rename(path, &target).with_context(|| {
        format!(
            "failed to archive checkpoint {} as {}",
            path.display(),
            target.display()
        )
    })?;
    Ok(target)
}

fn write_checkpoint(path: &Path, checkpoint: &IndexerCheckpoint) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent)
        .with_context(|| format!("failed to create cursor dir {}", parent.display()))?;
    let encoded = serde_json::to_vec(checkpoint).context("failed to encode checkpoint")?;
    let temp_path = path.with_extension(format!("tmp-{}", std::process::id()));
    let mut file = File::create(&temp_path)
        .with_context(|| format!("failed to write checkpoint {}", temp_path.display()))?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .with_context(|| format!("failed to write checkpoint {}", temp_path.display()))?;
    fs::rename(&temp_path, path)
        .with_context(|| format!("failed to replace checkpoint {}", path.display()))?;
    File::open(parent)
        .and_then(|dir| dir.sync_all())
        .with_context(|| format!("failed to sync cursor dir {}", parent.display()))
}

fn load_checkpoint(
    path: &Path,
    contract_address: &str,
    chain_id: Option<u64>,
) -> anyhow::Result<Option<LoadedCheckpoint>> {
    if !path.exists() {
        return Ok(None);
    }
    let raw =
        fs::read(path).with_context(|| format!("failed to read cursor file {}", path.display()))?;
    if std::str::from_utf8(&raw)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .is_some()
    {
        tracing::warn!(
            path = %path.display(),
            "legacy cursor has no Merkle snapshot; replaying from deployment block"
        );
        return Ok(None);
    }
    let corrupt = |detail: String| -> anyhow::Result<Option<LoadedCheckpoint>> {
        let archived = archive(path, "corrupt")?;
        tracing::error!(
            detail = %detail,
            archived = %archived.display(),
            "indexer checkpoint is invalid; archived it and replaying from the deployment block"
        );
        Ok(None)
    };
    let version = match serde_json::from_slice::<CheckpointProbe>(&raw) {
        Ok(probe) => probe.version,
        Err(err) => return corrupt(format!("unparseable checkpoint: {err}")),
    };
    match version {
        1 => {
            let archived = archive(path, "v1")?;
            tracing::warn!(
                archived = %archived.display(),
                "v1 indexer checkpoint lacks block hash and deployment binding; archived and replaying from --from-block"
            );
            return Ok(None);
        }
        2 => {
            // Revision-2 mirrors removed leaves on exits and lack note
            // statuses, known roots and published nullifiers.
            let archived = archive(path, "v2")?;
            tracing::warn!(
                archived = %archived.display(),
                "v2 indexer checkpoint mirrors a tree whose exits removed leaves; archived and replaying from --from-block"
            );
            return Ok(None);
        }
        CHECKPOINT_VERSION => {}
        version if version > CHECKPOINT_VERSION => bail!(
            "indexer checkpoint version {version} is newer than this binary supports; refusing to replace it"
        ),
        version => return corrupt(format!("unknown checkpoint version {version}")),
    }

    let checkpoint: IndexerCheckpoint = match serde_json::from_slice(&raw) {
        Ok(checkpoint) => checkpoint,
        Err(err) => return corrupt(format!("invalid v3 checkpoint: {err}")),
    };
    let bound_address = normalize_address(&checkpoint.contract_address).ok();
    if checkpoint.circuit_id != CIRCUIT_ID {
        bail!(
            "indexer checkpoint mirrors a vault of circuit {:?}, not {CIRCUIT_ID}; restart with --resync to discard it",
            checkpoint.circuit_id
        );
    }
    if bound_address.as_deref() != Some(contract_address)
        || chain_id.is_some_and(|chain_id| chain_id != checkpoint.chain_id)
    {
        bail!(
            "indexer checkpoint belongs to vault {} on chain {} (configured {} on chain {}); restart with --resync to discard it",
            checkpoint.contract_address,
            checkpoint.chain_id,
            contract_address,
            chain_id.map_or_else(|| "any".to_string(), |chain_id| chain_id.to_string())
        );
    }
    let hash = match normalize_hash(&checkpoint.last_processed_block_hash) {
        Ok(hash) => hash,
        Err(err) => return corrupt(format!("invalid checkpoint block hash: {err}")),
    };
    let mirror = match TreeMirror::from_snapshot(checkpoint.mirror) {
        Ok(mirror) => mirror,
        Err(err) => return corrupt(format!("invalid checkpoint mirror: {err}")),
    };
    if mirror.root() != checkpoint.root || mirror.next_note_id() != checkpoint.next_note_id {
        return corrupt("checkpoint root or next_note_id does not match its mirror".to_string());
    }
    Ok(Some(LoadedCheckpoint {
        chain_id: checkpoint.chain_id,
        anchor: BlockRef {
            number: checkpoint.last_processed_block,
            hash,
        },
        mirror,
        last_lifecycle_block: checkpoint.last_lifecycle_block,
    }))
}

pub(crate) fn normalize_address(address: &str) -> anyhow::Result<String> {
    let raw = strip_hex_prefix(address.trim());
    if raw.is_empty() || raw.len() > 40 {
        return Err(anyhow!("contract address must be 20-byte hex"));
    }
    let normalized = format!("{raw:0>40}").to_ascii_lowercase();
    hex::decode(&normalized).context("contract address is not valid hex")?;
    Ok(format!("0x{normalized}"))
}

fn normalize_hash(hash: &str) -> anyhow::Result<String> {
    let raw = strip_hex_prefix(hash.trim());
    if raw.len() != 64 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid block hash {hash}");
    }
    Ok(format!("0x{}", raw.to_ascii_lowercase()))
}

fn strip_hex_prefix(value: &str) -> &str {
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value)
}

fn hex_quantity(value: u64) -> String {
    format!("0x{value:x}")
}

/// Event signatures of vault revision 3 (topic0 is their keccak256).
pub(crate) const NOTE_DEPOSITED: &str = "NoteDeposited(uint32,bytes32,uint128,uint64,uint256)";
pub(crate) const MUTUAL_CLOSE: &str = "MutualClose(uint32,uint256,uint128,address)";
pub(crate) const ESCAPE_INITIATED: &str =
    "EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64,uint256)";
pub(crate) const CONCESSION_RECORDED: &str =
    "EscapeConcessionRecorded(uint32,uint256,uint128,uint128)";
pub(crate) const CONCESSION_RAISED: &str = "EscapeConcessionRaised(uint32,uint256,uint128,uint128)";
pub(crate) const ESCAPE_CHALLENGED: &str = "EscapeWithdrawalChallenged(uint32,uint256,uint256)";
pub(crate) const ESCAPE_FINALIZED: &str =
    "EscapeWithdrawalFinalized(uint32,uint256,uint128,address)";
pub(crate) const EXPIRED_CLAIMED: &str = "ExpiredClaimed(uint32,uint128,uint256)";
pub(crate) const CLOSED_LEAF_RETIRED: &str = "ClosedLeafRetired(uint32,uint256)";

struct EventTopics {
    note_deposited: String,
    mutual_close: String,
    escape_initiated: String,
    concession_recorded: String,
    concession_raised: String,
    escape_challenged: String,
    escape_finalized: String,
    expired_claimed: String,
    closed_leaf_retired: String,
}

fn event_topics() -> &'static EventTopics {
    static TOPICS: OnceLock<EventTopics> = OnceLock::new();
    TOPICS.get_or_init(|| EventTopics {
        note_deposited: event_topic(NOTE_DEPOSITED),
        mutual_close: event_topic(MUTUAL_CLOSE),
        escape_initiated: event_topic(ESCAPE_INITIATED),
        concession_recorded: event_topic(CONCESSION_RECORDED),
        concession_raised: event_topic(CONCESSION_RAISED),
        escape_challenged: event_topic(ESCAPE_CHALLENGED),
        escape_finalized: event_topic(ESCAPE_FINALIZED),
        expired_claimed: event_topic(EXPIRED_CLAIMED),
        closed_leaf_retired: event_topic(CLOSED_LEAF_RETIRED),
    })
}

/// The data words and the indexed note id of a vault event log, which must
/// carry exactly `topics` topics and `words` data words.
fn event_words(
    log: &RpcLog,
    name: &str,
    topics: usize,
    words: usize,
) -> anyhow::Result<(u32, Vec<[u8; 32]>)> {
    let data = split_words(&log.data)?;
    if log.topics.len() != topics || data.len() != words {
        bail!(
            "malformed {name} log: {} topics and {} data words, expected {topics} and {words}",
            log.topics.len(),
            data.len()
        );
    }
    Ok((topic_to_u32(&log.topics[1])?, data))
}

/// Decode one of the nine tree and lifecycle events, strictly: exact topic
/// and word counts, canonical uint widths and field elements. Any other
/// topic (treasury, pause, ownership, payout credits and future events) is
/// ignored without parsing its data.
fn decode_log(log: &RpcLog) -> anyhow::Result<Option<VaultEvent>> {
    let Some(topic0) = log.topics.first() else {
        return Ok(None);
    };
    let topics = event_topics();
    let is = |topic: &String| topic0.eq_ignore_ascii_case(topic);

    let event = if is(&topics.note_deposited) {
        let (note_id, words) = event_words(log, "NoteDeposited", 3, 3)?;
        VaultEvent::NoteDeposited {
            note_id,
            commitment: topic_to_felt(&log.topics[2])?,
            amount: word_to_u128(&words[0])?,
            expiry_ts: word_to_u64(&words[1])?,
            new_root: word_to_felt(&words[2])?,
        }
    } else if is(&topics.mutual_close) {
        let (note_id, words) = event_words(log, "MutualClose", 2, 3)?;
        word_to_address(&words[2])?;
        VaultEvent::MutualClose {
            note_id,
            nullifier: word_to_felt(&words[0])?,
            final_balance: word_to_u128(&words[1])?,
        }
    } else if is(&topics.escape_initiated) {
        let (note_id, words) = event_words(log, "EscapeWithdrawalInitiated", 2, 5)?;
        word_to_address(&words[2])?;
        VaultEvent::EscapeWithdrawalInitiated {
            note_id,
            nullifier: word_to_felt(&words[0])?,
            final_balance: word_to_u128(&words[1])?,
            challenge_deadline: word_to_u64(&words[3])?,
            current_root: word_to_felt(&words[4])?,
        }
    } else if is(&topics.concession_recorded) {
        let (note_id, words) = event_words(log, "EscapeConcessionRecorded", 2, 3)?;
        VaultEvent::EscapeConcessionRecorded {
            note_id,
            next_nullifier: word_to_felt(&words[0])?,
            state_balance: word_to_u128(&words[1])?,
            conceded: word_to_u128(&words[2])?,
        }
    } else if is(&topics.concession_raised) {
        let (note_id, words) = event_words(log, "EscapeConcessionRaised", 2, 3)?;
        VaultEvent::EscapeConcessionRaised {
            note_id,
            nullifier: word_to_felt(&words[0])?,
            conceded: word_to_u128(&words[1])?,
            final_balance: word_to_u128(&words[2])?,
        }
    } else if is(&topics.escape_challenged) {
        let (note_id, words) = event_words(log, "EscapeWithdrawalChallenged", 2, 2)?;
        VaultEvent::EscapeWithdrawalChallenged {
            note_id,
            nullifier: word_to_felt(&words[0])?,
            current_root: word_to_felt(&words[1])?,
        }
    } else if is(&topics.escape_finalized) {
        let (note_id, words) = event_words(log, "EscapeWithdrawalFinalized", 2, 3)?;
        word_to_address(&words[2])?;
        VaultEvent::EscapeWithdrawalFinalized {
            note_id,
            nullifier: word_to_felt(&words[0])?,
            final_balance: word_to_u128(&words[1])?,
        }
    } else if is(&topics.expired_claimed) {
        let (note_id, words) = event_words(log, "ExpiredClaimed", 2, 2)?;
        VaultEvent::ExpiredClaimed {
            note_id,
            deposit_amount: word_to_u128(&words[0])?,
            current_root: word_to_felt(&words[1])?,
        }
    } else if is(&topics.closed_leaf_retired) {
        let (note_id, words) = event_words(log, "ClosedLeafRetired", 2, 1)?;
        VaultEvent::ClosedLeafRetired {
            note_id,
            new_root: word_to_felt(&words[0])?,
        }
    } else {
        return Ok(None);
    };
    Ok(Some(event))
}

pub(crate) fn event_topic(signature: &str) -> String {
    let digest = Keccak256::digest(signature.as_bytes());
    format!("0x{}", hex::encode(digest))
}

fn split_words(data: &str) -> anyhow::Result<Vec<[u8; 32]>> {
    let raw = strip_hex_prefix(data.trim());
    if raw.is_empty() {
        return Ok(Vec::new());
    }
    if !raw.len().is_multiple_of(64) {
        return Err(anyhow!("log data is not a whole number of 32-byte words"));
    }
    let mut words = Vec::with_capacity(raw.len() / 64);
    for chunk in raw.as_bytes().chunks(64) {
        let decoded = hex::decode(chunk).context("invalid hex in log data")?;
        let mut word = [0u8; 32];
        word.copy_from_slice(&decoded);
        words.push(word);
    }
    Ok(words)
}

fn parse_hex_u64(value: &str) -> anyhow::Result<u64> {
    let raw = strip_hex_prefix(value.trim());
    u64::from_str_radix(raw, 16).with_context(|| format!("invalid hex u64 {value}"))
}

fn parse_quantity(value: &Value) -> anyhow::Result<u64> {
    parse_hex_u64(
        value
            .as_str()
            .ok_or_else(|| anyhow!("expected a hex quantity"))?,
    )
}

fn topic_to_u32(topic: &str) -> anyhow::Result<u32> {
    let felt =
        Felt252::from_hex(topic).map_err(|err| anyhow!("invalid indexed topic {topic}: {err}"))?;
    let value = felt
        .to_u64()
        .ok_or_else(|| anyhow!("indexed note id does not fit in u64"))?;
    u32::try_from(value).context("indexed note id does not fit in u32")
}

fn topic_to_felt(topic: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(topic).map_err(|err| anyhow!("invalid topic felt {topic}: {err}"))
}

/// An ABI word holding a uint of `bytes` bytes: its high bytes are zero.
fn narrow<const N: usize>(word: &[u8; 32], kind: &str) -> anyhow::Result<[u8; N]> {
    if word[..32 - N].iter().any(|byte| *byte != 0) {
        bail!("log word 0x{} is not a canonical {kind}", hex::encode(word));
    }
    Ok(word[32 - N..].try_into().expect("N bytes"))
}

fn word_to_u64(word: &[u8; 32]) -> anyhow::Result<u64> {
    Ok(u64::from_be_bytes(narrow::<8>(word, "uint64")?))
}

fn word_to_u128(word: &[u8; 32]) -> anyhow::Result<u128> {
    Ok(u128::from_be_bytes(narrow::<16>(word, "uint128")?))
}

fn word_to_address(word: &[u8; 32]) -> anyhow::Result<[u8; 20]> {
    narrow::<20>(word, "address")
}

/// A uint256 the vault emits as a BN254 field element (a nullifier or root).
fn word_to_felt(word: &[u8; 32]) -> anyhow::Result<Felt252> {
    Felt252::try_from_bytes_be(*word)
        .map_err(|err| anyhow!("log word is not a field element: {err}"))
}

#[cfg(test)]
mod reorg_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::ServiceSettings;
    use crate::test_chain::{MockChain, CHAIN_ID, VAULT};

    fn encode_word(value: Felt252) -> String {
        format!("{:0>64}", value.to_hex().trim_start_matches("0x"))
    }

    fn encode_u128(value: u128) -> String {
        format!("{value:064x}")
    }

    fn encode_u64(value: u64) -> String {
        format!("{value:064x}")
    }

    fn service() -> IndexerService {
        IndexerService::new_syncing(ServiceSettings {
            contract_address: VAULT.to_string(),
            chain_id: Some(CHAIN_ID),
            confirmations: 0,
            max_head_age: None,
            ..ServiceSettings::default()
        })
    }

    #[test]
    fn test_normalize_address_left_pads_short_values() {
        assert_eq!(
            normalize_address("0xabc").unwrap(),
            "0x0000000000000000000000000000000000000abc"
        );
    }

    #[test]
    fn test_decode_note_deposited_log() {
        let new_root = Felt252::from_u64(999);
        let log = RpcLog {
            block_number: "0x1".to_string(),
            block_hash: format!("0x{}", "ab".repeat(32)),
            log_index: "0x0".to_string(),
            address: None,
            removed: None,
            topics: vec![
                event_topic("NoteDeposited(uint32,bytes32,uint128,uint64,uint256)"),
                Felt252::from_u64(7).to_hex(),
                Felt252::from_u64(1234).to_hex(),
            ],
            data: format!(
                "0x{}{}{}",
                encode_u128(55),
                encode_u64(1_700_000_000),
                encode_word(new_root),
            ),
        };

        match decode_log(&log).unwrap().unwrap() {
            VaultEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                new_root: event_root,
            } => {
                assert_eq!(note_id, 7);
                assert_eq!(commitment, Felt252::from_u64(1234));
                assert_eq!(amount, 55);
                assert_eq!(expiry_ts, 1_700_000_000);
                assert_eq!(event_root, new_root);
            }
            other => panic!("unexpected event: {other:?}"),
        }
    }

    #[test]
    fn known_event_with_malformed_data_is_rejected_and_unknown_events_are_not_parsed() {
        let log = |topic0: String, data: &str| RpcLog {
            block_number: "0x1".to_string(),
            block_hash: format!("0x{}", "ab".repeat(32)),
            log_index: "0x0".to_string(),
            address: None,
            removed: None,
            topics: vec![topic0, format!("0x{:064x}", 1)],
            data: data.to_string(),
        };
        assert!(decode_log(&log(
            event_topic("ExpiredClaimed(uint32,uint128,uint256)"),
            "0x1234"
        ))
        .is_err());
        assert!(decode_log(&log(event_topic("Paused(address)"), "0x1234"))
            .unwrap()
            .is_none());
        assert!(decode_log(&log(event_topic("TreasurySet(address)"), "0x"))
            .unwrap()
            .is_none());
    }

    #[test]
    fn validate_logs_rejects_inconsistent_batches() {
        let hash = |byte: &str| format!("0x{}", byte.repeat(32));
        let log = |block: u64, index: u64, block_hash: String| RpcLog {
            block_number: format!("0x{block:x}"),
            block_hash,
            log_index: format!("0x{index:x}"),
            address: Some(VAULT.to_string()),
            removed: Some(false),
            data: "0x".to_string(),
            topics: Vec::new(),
        };
        let to_hash = hash("cc");
        let ordered = validate_logs(
            vec![
                log(5, 1, to_hash.clone()),
                log(4, 0, hash("aa")),
                log(5, 0, to_hash.clone()),
            ],
            VAULT,
            3,
            5,
            &to_hash,
        )
        .unwrap();
        assert_eq!(
            ordered
                .iter()
                .map(|log| (log.block, log.index))
                .collect::<Vec<_>>(),
            vec![(4, 0), (5, 0), (5, 1)]
        );

        let mut removed = log(4, 0, hash("aa"));
        removed.removed = Some(true);
        let mut foreign = log(4, 0, hash("aa"));
        foreign.address = Some("0x00000000000000000000000000000000000000bb".to_string());
        for batch in [
            vec![removed],
            vec![foreign],
            vec![log(6, 0, hash("aa"))],
            vec![log(2, 0, hash("aa"))],
            vec![log(5, 0, hash("dd"))],
            vec![log(4, 0, hash("aa")), log(4, 1, hash("bb"))],
            vec![log(4, 0, hash("aa")), log(4, 0, hash("aa"))],
        ] {
            assert!(validate_logs(batch, VAULT, 3, 5, &to_hash).is_err());
        }
    }

    #[test]
    fn legacy_cursor_without_snapshot_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.txt");
        fs::write(&path, "17").unwrap();
        assert!(load_checkpoint(&path, VAULT, None).unwrap().is_none());
        assert!(path.exists());
    }

    pub(super) fn write_v3_checkpoint(
        path: &Path,
        contract_address: &str,
        chain_id: u64,
        anchor: &BlockRef,
        mirror: &TreeMirror,
    ) {
        write_checkpoint(
            path,
            &IndexerCheckpoint {
                version: CHECKPOINT_VERSION,
                circuit_id: CIRCUIT_ID.to_string(),
                chain_id,
                contract_address: contract_address.to_string(),
                from_block: 0,
                last_processed_block: anchor.number,
                last_processed_block_hash: anchor.hash.clone(),
                root: mirror.root(),
                next_note_id: mirror.next_note_id(),
                last_lifecycle_block: None,
                mirror: mirror.snapshot(),
            },
        )
        .unwrap();
    }

    #[test]
    fn checkpoint_round_trip_restores_tree_and_cursor_together() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("checkpoint.json");
        let mut reference = TreeMirror::new();
        let mut deposit = VaultEvent::NoteDeposited {
            note_id: 0,
            commitment: Felt252::from_u64(1234),
            amount: 55,
            expiry_ts: 1_700_000_000,
            new_root: Felt252::ZERO,
        };
        reference.process_event(&deposit);
        if let VaultEvent::NoteDeposited { new_root, .. } = &mut deposit {
            *new_root = reference.root();
        }
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();
        let anchor = BlockRef {
            number: 17,
            hash: format!("0x{}", "17".repeat(32)),
        };
        write_v3_checkpoint(&path, VAULT, CHAIN_ID, &anchor, &mirror);

        let restored = service();
        let poller = JsonRpcLogPoller::new(
            PollerConfig {
                rpc_url: "http://127.0.0.1:1".to_string(),
                contract_address: "0xaa".to_string(),
                from_block: 3,
                cursor_path: Some(path.display().to_string()),
                ..PollerConfig::default()
            },
            &restored,
        )
        .unwrap();
        assert_eq!(poller.next_block(), 18);
        assert_eq!(poller.committed.mirror.root(), mirror.root());
        assert_eq!(poller.committed.anchor, Some(anchor.clone()));
        let health = restored.health();
        assert_eq!(health.confirmed_block, Some(17));
        assert_eq!(health.confirmed_block_hash, Some(anchor.hash));
        assert_eq!(health.confirmed_root, Some(mirror.root()));
        assert_eq!(health.confirmed_next_note_id, Some(1));
        // Intentionally inverted from the v1 behaviour: nothing is served
        // until the restored state verifies against the vault.
        assert_eq!(restored.status(), SyncStatus::Syncing);
        assert!(restored.view().is_err());
    }

    #[tokio::test]
    async fn poller_scans_large_replays_in_bounded_ranges() {
        let chain = MockChain::start().await;
        assert_eq!(chain.mine_empty(2_499), 0x9c4);
        let service = service();
        let mut poller = JsonRpcLogPoller::new(
            PollerConfig {
                rpc_url: chain.url(),
                contract_address: VAULT.to_string(),
                from_block: 1,
                cursor_path: None,
                confirmations: 0,
                chain_id: Some(CHAIN_ID),
                catch_up_interval: Duration::ZERO,
                ..PollerConfig::default()
            },
            &service,
        )
        .unwrap();

        assert_eq!(
            poller.poll_once(&service).await.unwrap(),
            PollOutcome::MoreWork
        );
        assert_eq!(
            poller.poll_once(&service).await.unwrap(),
            PollOutcome::MoreWork
        );
        assert_eq!(poller.poll_once(&service).await.unwrap(), PollOutcome::Idle);

        let ranges: Vec<(String, String)> = chain
            .calls("eth_getLogs")
            .iter()
            .map(|params| {
                (
                    params[0]["fromBlock"].as_str().unwrap().to_string(),
                    params[0]["toBlock"].as_str().unwrap().to_string(),
                )
            })
            .collect();
        assert_eq!(
            ranges,
            vec![
                ("0x1".to_string(), "0x3e8".to_string()),
                ("0x3e9".to_string(), "0x7d0".to_string()),
                ("0x7d1".to_string(), "0x9c4".to_string()),
            ]
        );
        assert_eq!(poller.next_block(), 2_501);
        assert!(service.is_ready());
    }

    #[test]
    fn rate_limits_are_classified_for_backoff() {
        let limited = anyhow::Error::from(RpcError::Http {
            method: "eth_getLogs".to_string(),
            status: 429,
            retry_after: Some(Duration::from_secs(7)),
        })
        .context("cannot verify vault state at block 3");
        assert_eq!(retry_delay(&limited), Some(Duration::from_secs(7)));
        let capped = anyhow::Error::from(RpcError::Http {
            method: "eth_call".to_string(),
            status: 429,
            retry_after: Some(Duration::from_secs(3_600)),
        });
        assert_eq!(retry_delay(&capped), Some(MAX_RATE_LIMIT_BACKOFF));
        let limit_error = anyhow::Error::from(RpcError::Rpc {
            method: "eth_getLogs".to_string(),
            code: -32005,
            message: "limit exceeded".to_string(),
        });
        assert_eq!(retry_delay(&limit_error), Some(DEFAULT_RATE_LIMIT_BACKOFF));
        let unavailable = anyhow::Error::from(RpcError::Http {
            method: "eth_call".to_string(),
            status: 503,
            retry_after: None,
        });
        assert_eq!(retry_delay(&unavailable), None);
    }

    #[tokio::test]
    async fn transport_errors_never_reveal_the_rpc_url() {
        let service = service();
        let mut poller = JsonRpcLogPoller::new(
            PollerConfig {
                rpc_url: "http://127.0.0.1:1/v3/secret-api-key".to_string(),
                contract_address: VAULT.to_string(),
                cursor_path: None,
                ..PollerConfig::default()
            },
            &service,
        )
        .unwrap();
        assert_eq!(poller.run_cycle(&service).await, None);
        let error = service.health().last_error.unwrap();
        assert!(!error.contains("secret-api-key"), "{error}");
        assert!(!error.contains("127.0.0.1:1"), "{error}");
    }

    fn log_of(topics: Vec<String>, words: &[String]) -> RpcLog {
        RpcLog {
            block_number: "0x1".to_string(),
            block_hash: format!("0x{}", "ab".repeat(32)),
            log_index: "0x0".to_string(),
            address: None,
            removed: None,
            topics,
            data: format!("0x{}", words.concat()),
        }
    }

    /// Every decoded event is the real vault's: its topic0, topic count and
    /// data layout, decoded from the log the compiled vault emits
    /// (crates/zkapi-serverd/tests/fixtures/vault_calldata_golden.json, which
    /// check-calldata-golden.sh checks against protocol/contracts).
    #[test]
    fn decoders_read_the_real_vault_events() {
        let layout: serde_json::Value = serde_json::from_str(include_str!(
            "../../zkapi-serverd/tests/fixtures/vault_calldata_golden.json"
        ))
        .unwrap();
        let log = |name: &str| {
            let event = &layout["events"][name];
            let topics = event["topics"]
                .as_str()
                .unwrap()
                .strip_prefix("0x")
                .unwrap();
            let topics: Vec<String> = topics
                .as_bytes()
                .chunks(64)
                .map(|word| format!("0x{}", std::str::from_utf8(word).unwrap()))
                .collect();
            assert_eq!(topics[0], event["topic0"].as_str().unwrap());
            let data = event["data"].as_str().unwrap().strip_prefix("0x").unwrap();
            let words: Vec<String> = data
                .as_bytes()
                .chunks(64)
                .map(|word| std::str::from_utf8(word).unwrap().to_string())
                .collect();
            log_of(topics, &words)
        };
        for (name, signature) in [
            ("NoteDeposited", NOTE_DEPOSITED),
            ("MutualClose", MUTUAL_CLOSE),
            ("EscapeWithdrawalInitiated", ESCAPE_INITIATED),
            ("EscapeConcessionRecorded", CONCESSION_RECORDED),
            ("EscapeConcessionRaised", CONCESSION_RAISED),
            ("EscapeWithdrawalChallenged", ESCAPE_CHALLENGED),
            ("EscapeWithdrawalFinalized", ESCAPE_FINALIZED),
            ("ExpiredClaimed", EXPIRED_CLAIMED),
            ("ClosedLeafRetired", CLOSED_LEAF_RETIRED),
        ] {
            assert_eq!(
                event_topic(signature),
                layout["events"][name]["topic0"].as_str().unwrap(),
                "{name}"
            );
        }
        let n = Felt252::from_u64;
        for (name, expected) in [
            (
                "NoteDeposited",
                VaultEvent::NoteDeposited {
                    note_id: 7,
                    commitment: n(0x0c0c),
                    amount: 1_000_000,
                    expiry_ts: 2_000_000_000,
                    new_root: n(0x0a0a),
                },
            ),
            (
                "MutualClose",
                VaultEvent::MutualClose {
                    note_id: 7,
                    nullifier: n(0x0101),
                    final_balance: 900_000,
                },
            ),
            (
                "EscapeWithdrawalInitiated",
                VaultEvent::EscapeWithdrawalInitiated {
                    note_id: 7,
                    nullifier: n(0x0101),
                    final_balance: 900_000,
                    challenge_deadline: 2_000_086_400,
                    current_root: n(0x0a0a),
                },
            ),
            (
                "EscapeConcessionRecorded",
                VaultEvent::EscapeConcessionRecorded {
                    note_id: 7,
                    next_nullifier: n(0x0202),
                    state_balance: 1_000_000,
                    conceded: 100_000,
                },
            ),
            (
                "EscapeConcessionRaised",
                VaultEvent::EscapeConcessionRaised {
                    note_id: 7,
                    nullifier: n(0x0101),
                    conceded: 150_000,
                    final_balance: 850_000,
                },
            ),
            (
                "EscapeWithdrawalChallenged",
                VaultEvent::EscapeWithdrawalChallenged {
                    note_id: 7,
                    nullifier: n(0x0101),
                    current_root: n(0x0a0a),
                },
            ),
            (
                "EscapeWithdrawalFinalized",
                VaultEvent::EscapeWithdrawalFinalized {
                    note_id: 7,
                    nullifier: n(0x0101),
                    final_balance: 850_000,
                },
            ),
            (
                "ExpiredClaimed",
                VaultEvent::ExpiredClaimed {
                    note_id: 7,
                    deposit_amount: 1_000_000,
                    current_root: n(0x0a0a),
                },
            ),
            (
                "ClosedLeafRetired",
                VaultEvent::ClosedLeafRetired {
                    note_id: 7,
                    new_root: n(0x0b0b),
                },
            ),
        ] {
            assert_eq!(decode_log(&log(name)).unwrap(), Some(expected), "{name}");
        }
        // Payout-credit events are not tree events: ignored, not parsed.
        for name in ["EscapePayoutDeferred", "EscapePayoutClaimed"] {
            assert_eq!(decode_log(&log(name)).unwrap(), None, "{name}");
        }
    }

    #[test]
    fn revision_three_event_topics_are_pinned() {
        // topic0 values pinned in the concession-exit spec (section 4.1).
        assert_eq!(
            event_topic(CONCESSION_RECORDED),
            "0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d"
        );
        assert_eq!(
            event_topic(CONCESSION_RAISED),
            "0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c"
        );
        assert_eq!(
            event_topic(CLOSED_LEAF_RETIRED),
            "0x64572cec8ef079a5baa4f2860f8b65efb52a96f64ee679d315fd2a0541ea28b3"
        );
        assert!(event_topic(ESCAPE_INITIATED).starts_with("0xb0d1eb71"));
        assert!(event_topic(ESCAPE_CHALLENGED).starts_with("0x5cc5343b"));
    }

    #[test]
    fn concession_events_decode_strictly() {
        let note = format!("0x{:064x}", 4);
        let recorded = log_of(
            vec![event_topic(CONCESSION_RECORDED), note.clone()],
            &[
                encode_word(Felt252::from_u64(0x901)),
                encode_u128(15),
                encode_u128(5),
            ],
        );
        assert_eq!(
            decode_log(&recorded).unwrap(),
            Some(VaultEvent::EscapeConcessionRecorded {
                note_id: 4,
                next_nullifier: Felt252::from_u64(0x901),
                state_balance: 15,
                conceded: 5,
            })
        );
        let raised = log_of(
            vec![event_topic(CONCESSION_RAISED), note.clone()],
            &[
                encode_word(Felt252::from_u64(0x900)),
                encode_u128(9),
                encode_u128(6),
            ],
        );
        assert_eq!(
            decode_log(&raised).unwrap(),
            Some(VaultEvent::EscapeConcessionRaised {
                note_id: 4,
                nullifier: Felt252::from_u64(0x900),
                conceded: 9,
                final_balance: 6,
            })
        );
        let retired = log_of(
            vec![event_topic(CLOSED_LEAF_RETIRED), note.clone()],
            &[encode_word(Felt252::from_u64(77))],
        );
        assert_eq!(
            decode_log(&retired).unwrap(),
            Some(VaultEvent::ClosedLeafRetired {
                note_id: 4,
                new_root: Felt252::from_u64(77),
            })
        );

        // A word too many or too few, an extra topic, a uint128 with high
        // bytes, and a nullifier outside the field are refused.
        let mut extra_word = recorded.clone();
        extra_word.data.push_str(&encode_u128(0));
        let mut missing_word = retired.clone();
        missing_word.data = "0x".to_string();
        let mut extra_topic = raised.clone();
        extra_topic.topics.push(note.clone());
        let wide = log_of(
            vec![event_topic(CONCESSION_RAISED), note.clone()],
            &[
                encode_word(Felt252::from_u64(0x900)),
                format!("{}{}", "01", "0".repeat(62)),
                encode_u128(6),
            ],
        );
        let outside_field = log_of(
            vec![event_topic(CONCESSION_RECORDED), note],
            &["f".repeat(64), encode_u128(15), encode_u128(5)],
        );
        for log in [extra_word, missing_word, extra_topic, wide, outside_field] {
            assert!(decode_log(&log).is_err(), "{log:?}");
        }
    }

    #[test]
    fn v2_checkpoint_of_a_leaf_removing_tree_is_archived_and_replayed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.json");
        fs::write(
            &path,
            r#"{"version":2,"chain_id":31337,"contract_address":"0xaa","mirror":{}}"#,
        )
        .unwrap();
        assert!(load_checkpoint(&path, VAULT, None).unwrap().is_none());
        assert!(!path.exists());
        assert_eq!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter(|entry| entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .contains(".v2-"))
                .count(),
            1
        );
    }

    #[test]
    fn checkpoint_of_another_circuit_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.json");
        let anchor = BlockRef {
            number: 3,
            hash: format!("0x{}", "03".repeat(32)),
        };
        write_v3_checkpoint(&path, VAULT, CHAIN_ID, &anchor, &TreeMirror::new());
        let mut raw: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        raw["circuit_id"] = "zkapi-v2-note-bound-v1".into();
        fs::write(&path, raw.to_string()).unwrap();
        let error = load_checkpoint(&path, VAULT, None).err().unwrap();
        assert!(format!("{error:#}").contains("zkapi-v2-note-bound-v1"));
        assert!(path.exists(), "a refused checkpoint is left in place");
    }

    #[tokio::test]
    async fn a_vault_before_revision_three_is_never_served() {
        for version in [None, Some(0), Some(2)] {
            let chain = MockChain::start().await;
            chain.mine(vec![crate::test_chain::Tx::Deposit { commitment: 0xa }]);
            chain.set_escape_version(version);
            let service = service();
            let mut poller = JsonRpcLogPoller::new(
                PollerConfig {
                    rpc_url: chain.url(),
                    contract_address: VAULT.to_string(),
                    cursor_path: None,
                    confirmations: 0,
                    chain_id: Some(CHAIN_ID),
                    catch_up_interval: Duration::ZERO,
                    ..PollerConfig::default()
                },
                &service,
            )
            .unwrap();
            for _ in 0..3 {
                assert_eq!(poller.poll_once(&service).await.unwrap(), PollOutcome::Idle);
                assert_eq!(service.status(), SyncStatus::Diverged, "{version:?}");
                assert!(service.view().is_err());
            }
            assert!(service.health().reason.unwrap().contains("revision"));
            assert!(chain.calls("eth_getLogs").is_empty());

            // Once the vault reports version 1 (a misread corrected), it is
            // mirrored.
            chain.set_escape_version(Some(1));
            assert_eq!(poller.poll_once(&service).await.unwrap(), PollOutcome::Idle);
            assert!(service.is_ready());
        }
    }
}
