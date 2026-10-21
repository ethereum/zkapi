//! Reorg, lagging-replica and fail-closed regression tests against a mock
//! chain (review regressions 1-3 and the persists-across-restart case).

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::*;
use crate::http::create_router;
use crate::service::{IndexerService, ServiceSettings, SyncStatus};
use crate::test_chain::{escape_deadline, MockChain, Tx, CHAIN_ID, VAULT};

fn settings(confirmations: u64) -> ServiceSettings {
    ServiceSettings {
        contract_address: VAULT.to_string(),
        chain_id: Some(CHAIN_ID),
        confirmations,
        stale_after: Duration::from_secs(120),
        max_head_age: None,
    }
}

fn config(chain: &MockChain, confirmations: u64, cursor: Option<&Path>) -> PollerConfig {
    PollerConfig {
        rpc_url: chain.url(),
        contract_address: VAULT.to_string(),
        from_block: 0,
        cursor_path: cursor.map(|path| path.display().to_string()),
        confirmations,
        chain_id: Some(CHAIN_ID),
        max_block_range: 1_000,
        divergence_threshold: 3,
        divergence_grace: Duration::ZERO,
        rebuild_after: Duration::from_secs(300),
        resync: false,
        catch_up_interval: Duration::ZERO,
        anchor_unavailable_limit: 5,
    }
}

struct Indexer {
    service: Arc<IndexerService>,
    poller: JsonRpcLogPoller,
}

impl Indexer {
    fn new(config: PollerConfig) -> Self {
        let settings = settings(config.confirmations);
        Self::with_settings(config, settings)
    }

    fn with_settings(config: PollerConfig, settings: ServiceSettings) -> Self {
        let service = Arc::new(IndexerService::new_syncing(settings));
        let poller = JsonRpcLogPoller::new(config, &service).unwrap();
        Self { service, poller }
    }

    async fn poll(&mut self) -> anyhow::Result<PollOutcome> {
        self.poller.poll_once(&self.service).await
    }

    async fn poll_to_idle(&mut self) {
        for _ in 0..10_000 {
            if self.poll().await.unwrap() == PollOutcome::Idle {
                return;
            }
        }
        panic!("poller never became idle");
    }

    /// One spawn-loop cycle: polls until idle and records any failure.
    async fn cycle(&mut self) {
        self.poller.run_cycle(&self.service).await;
    }

    fn view(&self) -> Arc<TreeView> {
        self.service.view().expect("a verified view is served")
    }
}

fn json_of<T: Serialize>(value: T) -> Value {
    serde_json::to_value(value).unwrap()
}

/// This thread's log lines at debug level and above, while the guard lives.
/// Tokio tests run on one thread, so the poller's lines are all captured.
#[derive(Clone, Default)]
struct CapturedLogs(Arc<std::sync::Mutex<Vec<u8>>>);

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    fn start() -> (Self, tracing::subscriber::DefaultGuard) {
        let logs = Self::default();
        let writer = logs.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .with_ansi(false)
            .with_writer(move || writer.clone())
            .finish();
        (logs, tracing::subscriber::set_default(subscriber))
    }

    fn lines_with(&self, needle: &str) -> Vec<String> {
        String::from_utf8_lossy(&self.0.lock().unwrap())
            .lines()
            .filter(|line| line.contains(needle))
            .map(str::to_string)
            .collect()
    }

    /// Lines reporting a missed re-escape closed by `closed_by`.
    fn reports(&self, closed_by: EscapeClose) -> Vec<String> {
        self.lines_with(&format!(
            "escape {} that the indexer never saw initiated:",
            closed_by.as_str()
        ))
    }
}

/// Every served view must be the state the chain has at a canonical block.
fn assert_canonical(chain: &MockChain, service: &IndexerService) {
    if let Ok(view) = service.view() {
        assert!(
            chain.is_canonical(&view.block_hash),
            "served non-canonical block {}",
            view.block_number
        );
        assert_eq!(view.root, chain.root_at(view.block_number));
        assert_eq!(view.next_note_id, chain.next_note_id_at(view.block_number));
    }
}

fn assert_serves_head(chain: &MockChain, indexer: &Indexer) {
    let view = indexer.view();
    let head = chain.head();
    assert_eq!(view.block_number, head);
    assert_eq!(view.block_hash, chain.hash_at(head));
    assert_eq!(view.root, chain.root_at(head));
    assert_eq!(view.next_note_id, chain.next_note_id_at(head));
    assert_eq!(
        view.mirror.pending_escapes(),
        chain.state_at(head).pending_escapes()
    );
}

async fn serve(service: Arc<IndexerService>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        axum::serve(listener, create_router(service)).await.unwrap();
    });
    base
}

async fn get(base: &str, path: &str) -> (u16, Value) {
    let response = reqwest::get(format!("{base}{path}")).await.unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

const SERVED_ROUTES: [&str; 8] = [
    "/v1/tree/root",
    "/v1/tree/next-note-id",
    "/v1/tree/snapshot",
    "/v1/tree/notes/0/path",
    "/v1/tree/notes/0/zero-path",
    "/v1/tree/roots/0x1",
    "/v1/nullifiers/0x1/published",
    "/v1/escapes/pending",
];

/// The pending-escapes entry of the mock vault's escape at `nullifier`
/// (successor `nullifier + 1`, state balance 15, conceded 5).
fn escape_entry(note_id: u32, nullifier: u64) -> Value {
    json!({
        "note_id": note_id,
        "withdrawal_nullifier": format!("0x{nullifier:x}"),
        "challenge_deadline": escape_deadline(nullifier),
        "final_balance": 10,
        "next_nullifier": format!("0x{:x}", nullifier + 1),
        "state_balance": 15,
        "conceded": 5,
    })
}

/// `/health` reports `phase`; every tree route fails closed with the
/// constant public body.
async fn assert_unavailable(base: &str, phase: &str) {
    let (status, health) = get(base, "/health").await;
    assert_eq!(status, 503);
    assert_eq!(health["status"], phase);
    for route in SERVED_ROUTES {
        let (status, body) = get(base, route).await;
        assert_eq!(status, 503, "{route}");
        assert_eq!(body["status"], "unavailable", "{route}");
        assert_eq!(body["error_code"], "indexer_unavailable", "{route}");
    }
}

fn read_checkpoint(path: &Path) -> Option<IndexerCheckpoint> {
    std::fs::read(path)
        .ok()
        .map(|raw| serde_json::from_slice(&raw).unwrap())
}

fn archives(dir: &Path, tag: &str) -> Vec<PathBuf> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            name.contains(&format!(".{tag}-")) && name.ends_with(".bak")
        })
        .collect()
}

/// Deposits spread over the chain; returns their block numbers.
fn mine_spread_deposits(chain: &MockChain, deposits: u64, gap: u64) -> Vec<u64> {
    (0..deposits)
        .map(|index| {
            let block = chain.mine(vec![Tx::Deposit {
                commitment: 0x100 + index,
            }]);
            chain.mine_empty(gap);
            block
        })
        .collect()
}

#[tokio::test]
async fn reorg_dropping_unconfirmed_deposit_is_never_served() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 3, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);

    // An unrelated deposit at the head is served once verified...
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().next_note_id, 2);

    // ...and a depth-2 reorg that drops it is followed on the next poll.
    chain.reorg(2, vec![vec![], vec![]]);
    indexer.poll_to_idle().await;
    assert_canonical(&chain, &indexer.service);
    assert_serves_head(&chain, &indexer);

    let base = serve(indexer.service.clone()).await;
    let head = chain.head();
    let (status, root) = get(&base, "/v1/tree/root").await;
    assert_eq!(status, 200);
    assert_eq!(root["root"], json_of(chain.root_at(head)));
    assert_eq!(root["block_number"], head);
    assert_eq!(root["block_hash"], chain.hash_at(head));
    let (status, next) = get(&base, "/v1/tree/next-note-id").await;
    assert_eq!(status, 200);
    assert_eq!(next["next_note_id"], 1);
    assert_eq!(indexer.service.health().rebuild_count, 0);
}

#[tokio::test]
async fn reorg_below_checkpoint_with_changed_state_rebuilds_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    chain.mine_empty(2);
    let mut indexer = Indexer::new(config(&chain, 1, Some(&cursor)));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(read_checkpoint(&cursor).unwrap().next_note_id, 2);

    // Both committed deposits are dropped by a reorg below the checkpoint.
    chain.reorg(
        4,
        vec![
            vec![Tx::Deposit { commitment: 0xc }],
            vec![],
            vec![],
            vec![],
        ],
    );
    let base = serve(indexer.service.clone()).await;
    // The new checkpoint-block hash must be seen on two polls before acting.
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_unavailable(&base, "rebuilding").await;

    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let (status, health) = get(&base, "/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["rebuild_count"], 1);
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(
        checkpoint.last_processed_block_hash,
        chain.hash_at(checkpoint.last_processed_block)
    );
    assert_eq!(checkpoint.next_note_id, 1);
}

#[tokio::test]
async fn reorg_below_checkpoint_without_vault_change_reanchors() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 1, Some(&cursor)));
    indexer.poll_to_idle().await;
    let before = indexer.view();
    let stored = read_checkpoint(&cursor).unwrap();
    assert_eq!(stored.last_processed_block, 5);

    // Empty blocks, including the checkpoint block, are replaced.
    chain.reorg(3, vec![vec![], vec![], vec![]]);
    assert_ne!(chain.hash_at(5), stored.last_processed_block_hash);
    assert!(indexer.poll().await.is_err());
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().root, before.root);
    assert_eq!(indexer.service.health().rebuild_count, 0);
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(checkpoint.last_processed_block, 5);
    assert_eq!(checkpoint.last_processed_block_hash, chain.hash_at(5));
}

async fn lagging_get_logs_replica_case(confirmations: u64) {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine_empty(15);
    let mut config = config(&chain, confirmations, Some(&cursor));
    config.divergence_threshold = 10;
    let mut indexer = Indexer::new(config);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);

    // eth_getLogs answers from a replica one block behind its own head.
    chain.set_logs_lag(1);
    let deposit_block = chain.mine(vec![Tx::Deposit { commitment: 0xd }]);
    for _ in 0..5 {
        indexer.cycle().await;
        assert_canonical(&chain, &indexer.service);
        let view = indexer.view();
        assert!(
            view.block_number < deposit_block,
            "served block {} without its deposit",
            view.block_number
        );
        if confirmations > 0 {
            // Below the confirmation depth the lag is absorbed: the newest
            // block the lagging logs can verify is served and nothing counts
            // as a mismatch.
            assert_eq!(view.block_number, deposit_block - 1);
            assert_eq!(indexer.poller.mismatch_streak, 0);
        } else {
            // At zero depth the commit itself cannot verify and is retried.
            assert!(indexer.poller.mismatch_streak > 0);
        }
        if let Some(checkpoint) = read_checkpoint(&cursor) {
            assert_eq!(
                checkpoint.next_note_id,
                chain.next_note_id_at(checkpoint.last_processed_block)
            );
        }
    }
    let health = indexer.service.health();
    assert_eq!(health.divergence_count, 0);
    assert_eq!(health.status, SyncStatus::Ok);

    chain.set_logs_lag(0);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().next_note_id, 1);
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(
        checkpoint.next_note_id,
        chain.next_note_id_at(checkpoint.last_processed_block)
    );
}

#[tokio::test]
async fn lagging_get_logs_replica_never_serves_or_commits_missing_deposit() {
    lagging_get_logs_replica_case(0).await;
}

#[tokio::test]
async fn lagging_get_logs_replica_is_absorbed_below_the_confirmation_depth() {
    lagging_get_logs_replica_case(12).await;
}

#[tokio::test]
async fn reorged_mutual_close_reopens_the_note_and_unpublishes_its_nullifier() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 3, None));
    indexer.poll_to_idle().await;
    let original = indexer.view().mirror.get_leaf(0);
    let root = indexer.view().root;
    assert!(!original.is_zero());
    let base = serve(indexer.service.clone()).await;
    let close_nullifier = "/v1/nullifiers/0x1b58/published";

    chain.mine(vec![Tx::Close { note_id: 0 }]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    // A close does no Merkle work: the leaf and the root stay.
    assert_eq!(indexer.view().mirror.get_leaf(0), original);
    assert_eq!(indexer.view().root, root);
    assert_eq!(
        indexer.view().mirror.note_status(0),
        Some(crate::tree_mirror::NoteStatus::Closed)
    );
    assert_eq!(get(&base, close_nullifier).await.1["published"], true);

    chain.reorg(1, vec![vec![]]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(
        indexer.view().mirror.note_status(0),
        Some(crate::tree_mirror::NoteStatus::Active)
    );
    assert_eq!(get(&base, close_nullifier).await.1["published"], false);
    let (status, path) = get(&base, "/v1/tree/notes/0/path").await;
    assert_eq!(status, 200);
    assert_eq!(path["leaf"], json_of(original));
    assert_eq!(path["root"], json_of(chain.root_at(chain.head())));
    assert_eq!(indexer.service.health().rebuild_count, 0);
}

#[tokio::test]
async fn reorged_escape_initiation_clears_the_pending_list_and_publications() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 3, None));
    indexer.poll_to_idle().await;
    let base = serve(indexer.service.clone()).await;
    let leaf = indexer.view().mirror.get_leaf(0);

    let escape_block = chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    indexer.poll_to_idle().await;
    let (status, pending) = get(&base, "/v1/escapes/pending").await;
    assert_eq!(status, 200);
    assert_eq!(pending["block_number"], escape_block);
    assert_eq!(pending["block_hash"], chain.hash_at(escape_block));
    assert_eq!(pending["root"], json_of(chain.root_at(escape_block)));
    assert_eq!(pending["escapes"], json!([escape_entry(0, 900)]));
    // Both nullifiers of the escape are published; the leaf stays.
    for nullifier in ["0x384", "0x385"] {
        let (_, body) = get(&base, &format!("/v1/nullifiers/{nullifier}/published")).await;
        assert_eq!(body["published"], true, "{nullifier}");
    }
    assert_eq!(indexer.view().mirror.get_leaf(0), leaf);

    // A reorg removes the initiation: the pending list and the table revert.
    chain.reorg(1, vec![vec![]]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let (_, pending) = get(&base, "/v1/escapes/pending").await;
    assert_eq!(pending["escapes"], json!([]));
    for nullifier in ["0x384", "0x385"] {
        let (_, body) = get(&base, &format!("/v1/nullifiers/{nullifier}/published")).await;
        assert_eq!(body["published"], false, "{nullifier}");
    }
    let (_, path) = get(&base, "/v1/tree/notes/0/path").await;
    assert_eq!(path["leaf"], json_of(leaf));
}

/// A reorg below the checkpoint that removes a committed `tx`.
async fn deep_reorg_of_committed(tx: Tx) {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![tx]);
    chain.mine_empty(2);
    let mut indexer = Indexer::new(config(&chain, 1, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let root = indexer.view().root;
    assert_ne!(
        indexer.view().mirror.note_status(0),
        Some(crate::tree_mirror::NoteStatus::Active)
    );

    // The replacement chain has the same deposit and no exit: the vault's
    // root and next note id at the reorganized checkpoint block are
    // unchanged, but the committed exit is gone. Exits change no root, so
    // re-anchoring would keep it; the indexer rebuilds instead.
    chain.reorg(
        4,
        vec![
            vec![Tx::Deposit { commitment: 0xa }],
            vec![],
            vec![],
            vec![],
        ],
    );
    assert_eq!(chain.root_at(chain.head()), root);
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_eq!(indexer.service.status(), SyncStatus::Rebuilding);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(
        indexer.view().mirror.note_status(0),
        Some(crate::tree_mirror::NoteStatus::Active)
    );
    assert!(indexer.view().mirror.pending_escapes().is_empty());
    assert_eq!(indexer.view().mirror.published_count(), 0);
    assert_eq!(indexer.service.health().rebuild_count, 1);
}

#[tokio::test]
async fn reorged_committed_escape_rebuilds() {
    deep_reorg_of_committed(Tx::Escape {
        note_id: 0,
        nullifier: 900,
    })
    .await;
}

#[tokio::test]
async fn reorged_committed_mutual_close_rebuilds() {
    deep_reorg_of_committed(Tx::Close { note_id: 0 }).await;
}

#[tokio::test]
async fn reorged_challenge_and_expired_claim_are_undone() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 3, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);

    use crate::tree_mirror::NoteStatus;
    chain.mine(vec![Tx::Challenge { note_id: 0 }]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert!(indexer.view().mirror.pending_escapes().is_empty());
    assert_eq!(
        indexer.view().mirror.note_status(0),
        Some(NoteStatus::Active)
    );

    // The challenge is reorged out: the escape is pending again.
    chain.reorg(1, vec![vec![]]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().mirror.pending_escapes().len(), 1);
    assert_eq!(
        indexer.view().mirror.note_status(0),
        Some(NoteStatus::PendingWithdrawal)
    );

    chain.mine(vec![Tx::Claim { note_id: 1 }]);
    indexer.poll_to_idle().await;
    assert_eq!(
        indexer.view().mirror.note_status(1),
        Some(NoteStatus::Closed)
    );
    assert!(!indexer.view().mirror.get_leaf(1).is_zero());

    // The expiry claim is reorged out: the note is active again.
    chain.reorg(1, vec![vec![]]);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(
        indexer.view().mirror.note_status(1),
        Some(NoteStatus::Active)
    );
    assert_eq!(indexer.service.health().rebuild_count, 0);
}

/// Serve a deposit and its mutual close, then persistently lose the
/// ClosedLeafRetired log once it is below the confirmation depth, and poll
/// until the indexer diverges.
async fn diverge_on_dropped_retirement() -> (MockChain, Indexer, String, u64) {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Close { note_id: 0 }]);
    chain.mine_empty(3);
    let mut indexer = Indexer::new(config(&chain, 2, None));
    indexer.poll_to_idle().await;
    let served = indexer.view().block_number;
    let retire_block = chain.mine(vec![Tx::Retire { note_id: 0 }]);
    chain.drop_log(retire_block, 0);
    chain.mine_empty(3);
    let base = serve(indexer.service.clone()).await;
    for _ in 0..3 {
        indexer.cycle().await;
        assert_canonical(&chain, &indexer.service);
    }
    (chain, indexer, base, served)
}

/// A deposit and the close and leaf retirement of that note all missing from
/// the logs leave the mirror at the vault's root (the note's leaf is zero
/// again) with a stale next_note_id. Only the nextNoteId comparison of the
/// verified-head check catches it, and such a view is never served.
#[tokio::test]
async fn missed_deposit_close_and_retirement_at_the_vaults_root_are_never_served() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(3);
    let mut indexer = Indexer::new(config(&chain, 2, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let deposit = chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    let close = chain.mine(vec![Tx::Close { note_id: 1 }]);
    let retire = chain.mine(vec![Tx::Retire { note_id: 1 }]);
    chain.drop_log(deposit, 0);
    chain.drop_log(close, 0);
    chain.drop_log(retire, 0);
    let head = chain.mine_empty(3);
    assert_eq!(chain.root_at(head), chain.root_at(deposit - 1));
    assert_eq!(chain.next_note_id_at(head), 2);
    let base = serve(indexer.service.clone()).await;
    for _ in 0..3 {
        indexer.cycle().await;
        assert_canonical(&chain, &indexer.service);
    }
    assert_unavailable(&base, "diverged").await;
    let health = indexer.service.health();
    assert!(health.reason.unwrap().contains("nextNoteId 2"));
}

#[tokio::test]
async fn persistent_log_gap_fails_closed_then_recovers() {
    let (chain, mut indexer, base, _) = diverge_on_dropped_retirement().await;
    assert_unavailable(&base, "diverged").await;
    let health = indexer.service.health();
    assert!(health.reason.unwrap().contains("vault root"));
    assert_eq!(health.divergence_count, 1);
    // The committed base still verifies, so no rebuild is started.
    assert_eq!(health.rebuild_count, 0);

    chain.restore_logs();
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
    let (status, health) = get(&base, "/health").await;
    assert_eq!(status, 200);
    assert_eq!(health["status"], "ok");
}

#[tokio::test]
async fn diverged_indexer_stays_unavailable_when_the_rpc_returns_the_old_head() {
    let (chain, mut indexer, base, served) = diverge_on_dropped_retirement().await;
    assert_eq!(indexer.service.status(), SyncStatus::Diverged);
    // A replica lagging back to the last verified head must not revive it.
    chain.set_latest(Some(served));
    for _ in 0..3 {
        indexer.cycle().await;
        assert_unavailable(&base, "diverged").await;
    }
}

#[tokio::test]
async fn restart_resumes_from_verified_checkpoint_without_full_replay() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    chain.mine_empty(4);
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    indexer.poll_to_idle().await;
    let committed = read_checkpoint(&cursor).unwrap().last_processed_block;
    drop(indexer);

    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    chain.mine_empty(3);
    chain.clear_calls();
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    assert_eq!(indexer.service.status(), SyncStatus::Syncing);
    assert!(indexer.service.view().is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::Idle);
    assert_serves_head(&chain, &indexer);
    let first = &chain.calls("eth_getLogs")[0];
    assert_eq!(first[0]["fromBlock"], format!("0x{:x}", committed + 1));
    // The open escape survives the restart through the checkpoint.
    assert_eq!(indexer.view().mirror.pending_escapes().len(), 1);
}

#[tokio::test]
async fn corrupted_checkpoint_is_never_served_and_is_rebuilt() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    chain.mine_empty(3);
    // Self-consistent file at a canonical block whose mirror misses the second
    // deposit, as a SIGKILL-persisted diverged mirror would be.
    let anchor = BlockRef {
        number: 4,
        hash: chain.hash_at(4),
    };
    super::tests::write_v3_checkpoint(&cursor, VAULT, CHAIN_ID, &anchor, &chain.state_at(2));

    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    let base = serve(indexer.service.clone()).await;
    assert_unavailable(&base, "syncing").await;
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_unavailable(&base, "rebuilding").await;
    assert_eq!(archives(dir.path(), "corrupt").len(), 1);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().next_note_id, 2);
    assert_eq!(read_checkpoint(&cursor).unwrap().next_note_id, 2);
}

/// Restart with zero confirmations onto a checkpoint at the head block.
fn restart_at_head_checkpoint(chain: &MockChain, cursor: &Path, mirror: &TreeMirror) -> Indexer {
    let head = chain.head();
    let anchor = BlockRef {
        number: head,
        hash: chain.hash_at(head),
    };
    super::tests::write_v3_checkpoint(cursor, VAULT, CHAIN_ID, &anchor, mirror);
    Indexer::new(config(chain, 0, Some(cursor)))
}

#[tokio::test]
async fn restored_checkpoint_at_the_head_is_published_only_after_it_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    let mut indexer = restart_at_head_checkpoint(&chain, &cursor, &chain.state_at(chain.head()));
    let base = serve(indexer.service.clone()).await;
    // The vault's revision was probed earlier in this process.
    indexer.poller.vault_verified = true;

    // Neither the startup check nor the head view can read the vault.
    chain.fail_next("eth_call", 2);
    indexer.cycle().await;
    assert_unavailable(&base, "syncing").await;

    // The retried startup check matches; only then is the checkpoint served.
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn diverged_checkpoint_at_the_head_is_never_served_when_startup_check_fails() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    // Self-consistent, at the canonical head block, but missing the second
    // deposit, as a SIGKILL-persisted diverged mirror would be.
    let mut indexer =
        restart_at_head_checkpoint(&chain, &cursor, &chain.state_at(chain.head() - 1));
    let base = serve(indexer.service.clone()).await;

    // Only the startup check's first read fails.
    chain.fail_next("eth_call", 1);
    indexer.cycle().await;
    assert_unavailable(&base, "syncing").await;

    // The retried startup check finds the mismatch: archived and rebuilt.
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(archives(dir.path(), "corrupt").len(), 1);
    assert_eq!(indexer.service.health().rebuild_count, 1);
}

fn offline_config(cursor: &Path) -> PollerConfig {
    PollerConfig {
        rpc_url: "http://127.0.0.1:1".to_string(),
        contract_address: VAULT.to_string(),
        from_block: 3,
        cursor_path: Some(cursor.display().to_string()),
        chain_id: Some(CHAIN_ID),
        ..PollerConfig::default()
    }
}

#[test]
fn v1_checkpoint_is_archived_and_replayed() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    std::fs::write(
        &cursor,
        r#"{"version":1,"last_processed_block":17,"mirror":{"next_note_id":0,"current_leaves":[],"original_leaves":[]}}"#,
    )
    .unwrap();
    let service = IndexerService::new_syncing(settings(12));
    let poller = JsonRpcLogPoller::new(offline_config(&cursor), &service).unwrap();
    assert_eq!(poller.next_block(), 3);
    assert!(!cursor.exists());
    assert_eq!(archives(dir.path(), "v1").len(), 1);
}

#[test]
fn checkpoint_for_another_vault_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let anchor = BlockRef {
        number: 9,
        hash: format!("0x{}", "09".repeat(32)),
    };
    let service = IndexerService::new_syncing(settings(12));

    let other_vault = "0x00000000000000000000000000000000000000bb";
    super::tests::write_v3_checkpoint(&cursor, other_vault, CHAIN_ID, &anchor, &TreeMirror::new());
    let Err(error) = JsonRpcLogPoller::new(offline_config(&cursor), &service) else {
        panic!("a checkpoint for another vault must be refused");
    };
    assert!(format!("{error:#}").contains("--resync"));

    super::tests::write_v3_checkpoint(&cursor, VAULT, 1, &anchor, &TreeMirror::new());
    let Err(error) = JsonRpcLogPoller::new(offline_config(&cursor), &service) else {
        panic!("a checkpoint for another chain must be refused");
    };
    assert!(format!("{error:#}").contains("--resync"));
    // The refused checkpoint is left in place for the operator.
    assert!(cursor.exists());

    // A newer binary's checkpoint is never replaced.
    std::fs::write(&cursor, r#"{"version":4}"#).unwrap();
    assert!(JsonRpcLogPoller::new(offline_config(&cursor), &service).is_err());
    assert!(cursor.exists());
}

#[test]
fn second_indexer_on_the_same_checkpoint_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let service = IndexerService::new_syncing(settings(12));
    let _first = JsonRpcLogPoller::new(offline_config(&cursor), &service).unwrap();
    let Err(error) = JsonRpcLogPoller::new(offline_config(&cursor), &service) else {
        panic!("the checkpoint lock must be exclusive");
    };
    assert!(format!("{error:#}").contains("another indexer holds this checkpoint"));
}

#[test]
fn resync_flag_and_sentinel_archive_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let anchor = BlockRef {
        number: 9,
        hash: format!("0x{}", "09".repeat(32)),
    };
    let service = IndexerService::new_syncing(settings(12));

    super::tests::write_v3_checkpoint(&cursor, VAULT, CHAIN_ID, &anchor, &TreeMirror::new());
    let mut config = offline_config(&cursor);
    config.resync = true;
    let poller = JsonRpcLogPoller::new(config.clone(), &service).unwrap();
    assert_eq!(poller.next_block(), 3);
    assert!(!cursor.exists());
    assert_eq!(archives(dir.path(), "resync").len(), 1);
    drop(poller);

    super::tests::write_v3_checkpoint(&cursor, VAULT, CHAIN_ID, &anchor, &TreeMirror::new());
    let sentinel = dir.path().join("indexer.cursor.resync");
    std::fs::write(&sentinel, b"").unwrap();
    config.resync = false;
    let poller = JsonRpcLogPoller::new(config, &service).unwrap();
    assert_eq!(poller.next_block(), 3);
    assert!(!cursor.exists());
    assert!(!sentinel.exists());
    assert_eq!(archives(dir.path(), "resync").len(), 2);
}

#[tokio::test]
async fn historical_catch_up_without_archive_state_verifies_at_recent_block() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    mine_spread_deposits(&chain, 6, 6);
    // A non-archive node: state older than four blocks is pruned.
    chain.set_state_window(Some(4));
    let mut config = config(&chain, 2, Some(&cursor));
    config.max_block_range = 8;
    let mut indexer = Indexer::new(config);

    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert!(
        !cursor.exists(),
        "unverified catch-up progress must not be persisted"
    );
    assert!(indexer.service.view().is_err());
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(checkpoint.last_processed_block, chain.head() - 2);
    assert_eq!(
        checkpoint.next_note_id,
        chain.next_note_id_at(checkpoint.last_processed_block)
    );
}

#[tokio::test]
async fn historical_catch_up_with_missing_log_never_becomes_ready() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    let deposits = mine_spread_deposits(&chain, 6, 6);
    chain.set_state_window(Some(4));
    chain.drop_log(deposits[1], 0);
    let mut config = config(&chain, 2, Some(&cursor));
    config.max_block_range = 8;
    let mut indexer = Indexer::new(config);
    for _ in 0..10 {
        indexer.cycle().await;
        assert!(indexer.service.view().is_err());
        assert!(!cursor.exists());
    }
    assert_ne!(indexer.service.status(), SyncStatus::Ok);
}

#[tokio::test]
async fn unknown_vault_events_are_ignored() {
    // topic0 values of the hardened vault's new events.
    assert_eq!(
        event_topic("Paused(address)"),
        "0x62e78cea01bee320cd4e420270b5ea74000d11b0c9f74754ebdbfc544b05a258"
    );
    assert_eq!(
        event_topic("TreasuryChangeScheduled(address,uint64)"),
        "0xc6c2218a88093c850424bc0b3f475912876098dcc3cb7f14a52c580293569750"
    );
    let payout_deferred = event_topic("EscapePayoutDeferred(uint32,address,uint128)");
    assert_eq!(
        payout_deferred,
        "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942"
    );
    let payout_claimed = event_topic("EscapePayoutClaimed(address,uint128)");
    assert_eq!(
        payout_claimed,
        "0x6bf75371d42e9753c0913bf8fcecb651e8db173d99d7da0e4d836e91512bbe27"
    );
    let owner = format!("0x{:064x}", 0x0e);
    let raw = |signature: &str, data: &str| Tx::Raw {
        topics: vec![event_topic(signature), owner.clone()],
        data: data.to_string(),
    };
    // The mock vault's escape destination and final balance.
    let destination = format!("0x{:064x}", 0xd0d0);
    let amount = format!("0x{:064x}", 10);
    let chain = MockChain::start().await;
    chain.mine(vec![
        raw("Paused(address)", "0x"),
        Tx::Deposit { commitment: 0xa },
        Tx::Deposit { commitment: 0xb },
        raw("Unpaused(address)", "0x1234"),
        raw(
            "TreasuryChangeScheduled(address,uint64)",
            &format!("0x{:064x}", 99),
        ),
        raw("TreasuryChangeCancelled(address)", "0x"),
        raw(
            "TreasuryPaymentDeferred(address,uint128)",
            &format!("0x{:064x}", 5),
        ),
        raw(
            "TreasuryArrearsPaid(address,uint128)",
            &format!("0x{:064x}", 5),
        ),
        raw("TreasurySet(address)", "0x"),
        raw("OwnershipTransferStarted(address,address)", "0x"),
        raw("OwnershipTransferred(address,address)", "0x"),
        Tx::Raw {
            topics: Vec::new(),
            data: "0xdeadbeef".to_string(),
        },
    ]);
    chain.mine(vec![
        raw("Paused(address)", "0x"),
        Tx::Close { note_id: 0 },
        Tx::Escape {
            note_id: 1,
            nullifier: 0x51,
        },
    ]);
    // A finalization whose push to the destination failed: the hardened vault
    // credits the payout and emits a three-topic `EscapePayoutDeferred` just
    // before `EscapeWithdrawalFinalized`, in the same transaction.
    chain.mine(vec![
        Tx::Raw {
            topics: vec![
                payout_deferred.clone(),
                format!("0x{:064x}", 1),
                destination.clone(),
            ],
            data: amount.clone(),
        },
        Tx::Finalize { note_id: 1 },
    ]);
    // Anyone later delivers the credit.
    chain.mine(vec![Tx::Raw {
        topics: vec![payout_claimed.clone(), destination.clone()],
        data: amount.clone(),
    }]);
    chain.mine_empty(2);
    let mut indexer = Indexer::new(config(&chain, 1, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    // The credited finalization still closed the escape, and the mirror stays
    // verified against the vault's state.
    let view = indexer.view();
    assert_eq!(view.mirror.pending_escapes(), Vec::new());
    assert_eq!(view.next_note_id, 2);
    let health = indexer.service.health();
    assert_eq!(health.status, SyncStatus::Ok);
    assert_eq!(health.consecutive_failures, 0);
    assert_eq!(health.divergence_count, 0);
    assert_eq!(health.rebuild_count, 0);
    assert_eq!(health.missed_re_escape_count, 0);
    assert_eq!(health.last_error, None);
}

#[tokio::test]
async fn chain_id_mismatch_fails_closed() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.set_chain_id(1);
    let mut indexer = Indexer::new(config(&chain, 0, None));
    let base = serve(indexer.service.clone()).await;
    indexer.cycle().await;
    assert_unavailable(&base, "diverged").await;
    assert!(indexer
        .service
        .health()
        .reason
        .unwrap()
        .contains("rpc chain id 1"));

    chain.set_chain_id(CHAIN_ID);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn rpc_without_block_hash_calls_never_becomes_ready() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(3);
    chain.reject_block_hash(true);
    let mut indexer = Indexer::new(config(&chain, 2, None));
    for _ in 0..3 {
        indexer.cycle().await;
    }
    let health = indexer.service.health();
    assert_eq!(health.status, SyncStatus::Syncing);
    assert!(health.last_error.unwrap().contains("EIP-1898"));
    assert!(indexer.service.view().is_err());
}

#[tokio::test]
async fn frozen_rpc_head_turns_stale_after_max_head_age() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    let mut settings = settings(0);
    settings.max_head_age = Some(Duration::from_secs(2));
    let mut indexer = Indexer::with_settings(config(&chain, 0, None), settings);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);

    // The RPC keeps answering the same head, so every poll "succeeds".
    tokio::time::sleep(Duration::from_millis(2_500)).await;
    let base = serve(indexer.service.clone()).await;
    for _ in 0..2 {
        indexer.cycle().await;
        assert_unavailable(&base, "stale").await;
    }
    let health = indexer.service.health();
    assert!(health.head_age_seconds.unwrap() >= 2);
    assert!(health.reason.unwrap().contains("not advancing"));
    let metrics = indexer.service.metrics();
    assert!(metrics.contains("zkapi_indexer_status{status=\"stale\"} 1"));
    assert!(metrics.contains("zkapi_indexer_head_age_seconds"));

    chain.mine_empty(1);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn rpc_head_older_than_max_head_age_is_never_served() {
    let chain = MockChain::start().await;
    chain.set_timestamp(Some(crate::service::unix_ms() / 1_000 - 3_600));
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    let mut settings = settings(0);
    settings.max_head_age = Some(Duration::from_secs(180));
    let mut indexer = Indexer::with_settings(config(&chain, 0, None), settings);
    indexer.cycle().await;
    assert_eq!(indexer.service.status(), SyncStatus::Stale);
    assert!(indexer.service.view().is_err());

    chain.set_timestamp(None);
    chain.mine_empty(1);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn rpc_head_below_checkpoint_is_lagging_not_a_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(2);
    chain.mine(vec![Tx::Deposit { commitment: 0xb }]);
    chain.mine_empty(3);
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    indexer.poll_to_idle().await;
    drop(indexer);
    assert_eq!(read_checkpoint(&cursor).unwrap().next_note_id, 2);

    // Restarted against a replica far behind the checkpoint, whose vault
    // state (one deposit) differs from the checkpoint's (two).
    chain.set_latest(Some(3));
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    for _ in 0..5 {
        let error = indexer.poll().await.unwrap_err();
        assert!(format!("{error:#}").contains("below the committed checkpoint"));
    }
    assert_eq!(indexer.poller.mismatch_streak, 0);
    assert_eq!(indexer.service.status(), SyncStatus::Syncing);
    assert_eq!(indexer.service.health().rebuild_count, 0);
    assert!(read_checkpoint(&cursor).is_some());

    chain.set_latest(None);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn stale_fork_header_never_moves_the_checkpoint() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(3);
    let mut indexer = Indexer::new(config(&chain, 1, Some(&cursor)));
    indexer.poll_to_idle().await;
    let stored = read_checkpoint(&cursor).unwrap();

    // A load-balancer backend on a stale fork keeps answering the checkpoint
    // block by number with a hash that is not on the head's ancestry.
    chain.set_stale_header(
        stored.last_processed_block,
        Some(format!("0x{}", "5e".repeat(32))),
    );
    for _ in 0..8 {
        chain.mine_empty(1);
        assert!(indexer.poll().await.is_err());
    }
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(checkpoint.last_processed_block, stored.last_processed_block);
    assert_eq!(
        checkpoint.last_processed_block_hash,
        stored.last_processed_block_hash
    );
    assert_eq!(indexer.service.health().rebuild_count, 0);

    chain.set_stale_header(stored.last_processed_block, None);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.service.health().rebuild_count, 0);
}

#[tokio::test]
async fn transient_transport_error_mid_catch_up_keeps_progress() {
    let chain = MockChain::start().await;
    mine_spread_deposits(&chain, 6, 9);
    chain.set_state_window(Some(4));
    let mut config = config(&chain, 2, None);
    config.max_block_range = 10;
    let mut indexer = Indexer::new(config);
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_eq!(indexer.poller.next_block(), 20);
    assert!(indexer.poller.provisional.is_some());

    chain.fail_next("eth_getLogs", 1);
    indexer.cycle().await;
    assert_eq!(indexer.poller.next_block(), 20);
    assert!(indexer.poller.provisional.is_some());
    assert_eq!(indexer.service.health().consecutive_failures, 1);

    chain.clear_calls();
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let calls = chain.calls("eth_getLogs");
    assert_eq!(calls[0][0]["fromBlock"], "0x14");
    assert!(calls.iter().all(|params| params[0]["fromBlock"] != "0x0"));
}

#[tokio::test]
async fn rate_limited_rpc_asks_for_backoff() {
    let chain = MockChain::start().await;
    let mut indexer = Indexer::new(config(&chain, 0, None));
    chain.rate_limit_next("eth_getBlockByNumber", 1);
    assert_eq!(
        indexer.poller.run_cycle(&indexer.service).await,
        Some(Duration::from_secs(1))
    );
    assert!(indexer
        .service
        .health()
        .last_error
        .unwrap()
        .contains("HTTP 429"));
    assert_eq!(indexer.poller.run_cycle(&indexer.service).await, None);
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn automatic_rebuilds_are_rate_limited() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(3);
    let mut config = config(&chain, 1, None);
    config.rebuild_after = Duration::from_millis(400);
    let mut indexer = Indexer::new(config);
    indexer.poll_to_idle().await;

    let deep_reorg = |commitment: u64| {
        chain.reorg(
            4,
            vec![vec![Tx::Deposit { commitment }], vec![], vec![], vec![]],
        )
    };
    deep_reorg(0xb);
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);

    // A second deep reorg right away waits for the rebuild rate limit,
    // failing closed meanwhile.
    deep_reorg(0xc);
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::Idle);
    assert_eq!(indexer.service.status(), SyncStatus::Diverged);
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::Idle);
    assert!(indexer.service.view().is_err());
    assert_eq!(indexer.service.health().rebuild_count, 1);

    tokio::time::sleep(Duration::from_millis(450)).await;
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.service.health().rebuild_count, 2);
}

#[tokio::test]
async fn reorged_checkpoint_with_pruned_state_falls_back_to_rebuild() {
    let chain = MockChain::start().await;
    chain.mine(vec![Tx::Deposit { commitment: 0xa }]);
    chain.mine_empty(3);
    let mut config = config(&chain, 1, None);
    config.anchor_unavailable_limit = 2;
    let mut indexer = Indexer::new(config);
    indexer.poll_to_idle().await;

    // The checkpoint block is replaced and its state is already pruned.
    chain.reorg(3, vec![vec![], vec![], vec![]]);
    chain.mine_empty(10);
    chain.set_state_window(Some(4));
    assert!(indexer.poll().await.is_err());
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    assert_eq!(indexer.service.status(), SyncStatus::Rebuilding);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
}

#[tokio::test]
async fn pending_escapes_follow_initiate_challenge_and_finalize() {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![
        Tx::Deposit { commitment: 0xa },
        Tx::Deposit { commitment: 0xb },
    ]);
    chain.mine_empty(2);
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    indexer.poll_to_idle().await;
    let base = serve(indexer.service.clone()).await;
    let entry = escape_entry;
    let pending = |base: String| async move {
        let (status, body) = get(&base, "/v1/escapes/pending").await;
        assert_eq!(status, 200);
        body
    };

    assert_eq!(pending(base.clone()).await["escapes"], json!([]));
    let block = chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    indexer.poll_to_idle().await;
    let body = pending(base.clone()).await;
    assert_eq!(body["escapes"], json!([entry(0, 900)]));
    assert_eq!(body["block_number"], block);
    assert_eq!(body["block_hash"], chain.hash_at(block));
    assert_eq!(body["root"], json_of(chain.root_at(block)));

    chain.mine(vec![Tx::Challenge { note_id: 0 }]);
    indexer.poll_to_idle().await;
    assert_eq!(pending(base.clone()).await["escapes"], json!([]));

    // G2: the note escapes again under a new nullifier, alongside another
    // escape, which a raise then concedes more of.
    chain.mine(vec![
        Tx::Escape {
            note_id: 0,
            nullifier: 905,
        },
        Tx::Escape {
            note_id: 1,
            nullifier: 910,
        },
    ]);
    chain.mine(vec![Tx::Raise {
        note_id: 1,
        conceded: 12,
    }]);
    indexer.poll_to_idle().await;
    let mut raised = entry(1, 910);
    raised["conceded"] = json!(12);
    raised["final_balance"] = json!(3);
    assert_eq!(
        pending(base.clone()).await["escapes"],
        json!([entry(0, 905), raised.clone()])
    );

    chain.mine(vec![Tx::Finalize { note_id: 0 }]);
    chain.mine_empty(3);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(pending(base.clone()).await["escapes"], json!([raised]));
    // Complete logs never imply a missed re-escape.
    assert_eq!(indexer.service.health().missed_re_escape_count, 0);

    // The committed list survives a restart through the checkpoint.
    drop(indexer);
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.view().mirror.pending_escapes()[0].note_id, 1);
}

/// An indexer whose checkpoint passed a root-neutral pair of vault events
/// its getLogs replica never returned.
struct HiddenPair {
    _dir: tempfile::TempDir,
    cursor: PathBuf,
    chain: MockChain,
    indexer: Indexer,
    base: String,
}

/// Deposits 0 and 1 and escape 900 of note 0, synced at two confirmations.
/// Then a getLogs replica lagging more than `--confirmations` hides `pair`,
/// mined in one block, until the checkpoint has passed it. A pair that
/// leaves the root unchanged is committed without its events, as documented.
async fn hide_pair_below_checkpoint(pair: Vec<Tx>) -> HiddenPair {
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    chain.mine(vec![
        Tx::Deposit { commitment: 0xa },
        Tx::Deposit { commitment: 0xb },
    ]);
    chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    chain.mine_empty(2);
    let mut indexer = Indexer::new(config(&chain, 2, Some(&cursor)));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let base = serve(indexer.service.clone()).await;

    chain.set_logs_lag(4);
    let pair_block = chain.mine(pair);
    for _ in 0..3 {
        chain.mine_empty(1);
        indexer.cycle().await;
    }
    chain.set_logs_lag(0);
    chain.mine_empty(2);
    indexer.cycle().await;
    assert!(read_checkpoint(&cursor).unwrap().last_processed_block > pair_block);
    HiddenPair {
        _dir: dir,
        cursor,
        chain,
        indexer,
        base,
    }
}

/// The listing of escape 900 of note 0, from before the hidden pair.
fn listed_escape_900() -> Value {
    json!([escape_entry(0, 900)])
}

/// The hidden pair is a challenge of escape 900 and a re-escape 901 of the
/// same note: the checkpoint commits the stale listing, as documented, since
/// the nullifier and deadline are hints. `follow_up`, the vault's next event
/// for the note, closes 901 (`follow_up_kind`).
async fn missed_re_escape_case(follow_up: Tx, follow_up_kind: EscapeClose) {
    let (logs, _capture) = CapturedLogs::start();
    let HiddenPair {
        _dir,
        cursor,
        chain,
        mut indexer,
        base,
    } = hide_pair_below_checkpoint(vec![
        Tx::Challenge { note_id: 0 },
        Tx::Escape {
            note_id: 0,
            nullifier: 905,
        },
    ])
    .await;

    let stale = listed_escape_900();
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert_eq!(json_of(&checkpoint.mirror.pending_escapes), stale);
    let head = chain.head();
    let (status, pending) = get(&base, "/v1/escapes/pending").await;
    assert_eq!(status, 200);
    assert_eq!(pending["block_number"], head);
    assert_eq!(pending["root"], json_of(chain.root_at(head)));
    assert_eq!(pending["escapes"], stale);
    let vault = chain.state_at(head).pending_escapes();
    assert_eq!(vault[0].withdrawal_nullifier, Felt252::from_u64(905));
    assert_eq!(vault[0].challenge_deadline, escape_deadline(905));

    // The mirror never saw 901 initiated. The head view applies the event
    // closing it and still verifies.
    let follow_up_block = chain.mine(vec![follow_up]);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.service.health().missed_re_escape_count, 0);
    assert!(logs.reports(follow_up_kind).is_empty());

    // The commit tier takes it at the confirmation depth and counts it once.
    for _ in 0..3 {
        chain.mine_empty(1);
        indexer.cycle().await;
        assert_serves_head(&chain, &indexer);
    }
    let checkpoint = read_checkpoint(&cursor).unwrap();
    assert!(checkpoint.last_processed_block > follow_up_block);
    assert!(checkpoint.mirror.pending_escapes.is_empty());
    let (_, pending) = get(&base, "/v1/escapes/pending").await;
    assert_eq!(pending["escapes"], json!([]));
    let health = indexer.service.health();
    assert_eq!(health.status, SyncStatus::Ok);
    assert_eq!(health.missed_re_escape_count, 1);
    let finalized = u64::from(matches!(follow_up_kind, EscapeClose::Finalized));
    assert_eq!(health.missed_re_escape_finalized_count, finalized);
    assert_eq!(health.divergence_count, 0);
    assert_eq!(health.rebuild_count, 0);
    let metrics = indexer.service.metrics();
    for (event, value) in [
        ("challenged", 1 - finalized),
        ("finalized", finalized),
        ("raised", 0),
    ] {
        let line = format!("zkapi_indexer_missed_re_escapes_total{{event=\"{event}\"}} {value}");
        assert!(metrics.lines().any(|candidate| candidate == line), "{line}");
    }
    // Logged once; at error level when the vault finalized the escape (paid
    // or credited).
    let reports = logs.reports(follow_up_kind);
    assert_eq!(reports.len(), 1, "{reports:?}");
    let level = match follow_up_kind {
        EscapeClose::Challenged | EscapeClose::Raised => " WARN ",
        EscapeClose::Finalized => "ERROR ",
    };
    assert!(reports[0].contains(level), "{}", reports[0]);
    assert!(
        reports[0].contains(&format!(
            "log 0: note 0 escape 0x389 was {} while escape 0x384 was listed",
            follow_up_kind.as_str()
        )),
        "{}",
        reports[0]
    );
}

#[tokio::test]
async fn challenge_after_missed_challenge_and_re_escape_applies() {
    missed_re_escape_case(Tx::Challenge { note_id: 0 }, EscapeClose::Challenged).await;
}

#[tokio::test]
async fn finalization_after_missed_challenge_and_re_escape_applies() {
    missed_re_escape_case(Tx::Finalize { note_id: 0 }, EscapeClose::Finalized).await;
}

/// A challenge followed by a mutual close or an expiry claim of the same
/// note leaves the root unchanged too. If the logs miss both, the note stays
/// listed although the vault holds no escape for it, as documented; no later
/// event can close the entry, only a resync. (The leaf stays either way.)
#[tokio::test]
async fn missed_challenge_and_close_leave_the_note_listed() {
    for closing in [Tx::Close { note_id: 0 }, Tx::Claim { note_id: 0 }] {
        let hidden = hide_pair_below_checkpoint(vec![Tx::Challenge { note_id: 0 }, closing]).await;
        let head = hidden.chain.head();
        let (status, pending) = get(&hidden.base, "/v1/escapes/pending").await;
        assert_eq!(status, 200);
        assert_eq!(pending["root"], json_of(hidden.chain.root_at(head)));
        assert_eq!(pending["escapes"], listed_escape_900());
        let vault = hidden.chain.state_at(head);
        assert!(vault.pending_escapes().is_empty());
        assert_eq!(
            vault.note_status(0),
            Some(crate::tree_mirror::NoteStatus::Closed)
        );
        let health = hidden.indexer.service.health();
        assert_eq!(health.status, SyncStatus::Ok);
        assert_eq!(health.missed_re_escape_count, 0);
    }
}

/// The provider's log history permanently lacks a challenge of escape 900
/// and a re-escape 905 of note 0 (block 4); the vault then challenges 905
/// (block 5).
fn mine_permanent_missed_re_escape(chain: &MockChain) {
    chain.mine(vec![
        Tx::Deposit { commitment: 0xa },
        Tx::Deposit { commitment: 0xb },
    ]);
    chain.mine(vec![Tx::Escape {
        note_id: 0,
        nullifier: 900,
    }]);
    let pair = chain.mine(vec![
        Tx::Challenge { note_id: 0 },
        Tx::Escape {
            note_id: 0,
            nullifier: 905,
        },
    ]);
    // The challenge, the initiation and its concession record.
    for index in 0..3 {
        chain.drop_log(pair, index);
    }
    chain.mine(vec![Tx::Challenge { note_id: 0 }]);
}

#[tokio::test]
async fn missed_re_escape_in_held_catch_up_chunks_is_reported_once_they_verify() {
    let (logs, _capture) = CapturedLogs::start();
    let dir = tempfile::tempdir().unwrap();
    let cursor = dir.path().join("indexer.cursor");
    let chain = MockChain::start().await;
    mine_permanent_missed_re_escape(&chain);
    chain.mine_empty(20);
    chain.mine(vec![Tx::Deposit { commitment: 0xc }]);
    chain.mine_empty(3);
    // A non-archive node, so catch-up chunks are held unverified until the
    // last one verifies. Its getLogs index lags more than --confirmations, so
    // the last chunk misses the newest deposit and every catch-up mismatches
    // and starts over.
    chain.set_state_window(Some(4));
    chain.set_logs_lag(5);
    let mut config = config(&chain, 2, Some(&cursor));
    config.max_block_range = 8;
    let mut indexer = Indexer::new(config);
    for _ in 0..4 {
        indexer.cycle().await;
        assert!(indexer.service.view().is_err());
        assert!(!cursor.exists());
        // Nothing was committed, so nothing is reported.
        assert_eq!(indexer.service.health().missed_re_escape_count, 0);
        assert!(logs.reports(EscapeClose::Challenged).is_empty());
    }

    chain.set_logs_lag(0);
    indexer.cycle().await;
    assert_serves_head(&chain, &indexer);
    assert!(read_checkpoint(&cursor)
        .unwrap()
        .mirror
        .pending_escapes
        .is_empty());
    // Reported once, by the commit that verified the held chunks.
    assert_eq!(indexer.service.health().missed_re_escape_count, 1);
    let reports = logs.reports(EscapeClose::Challenged);
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert!(reports[0].contains("block 5 log 0: note 0 escape 0x389 was challenged"));
}

#[tokio::test]
async fn rebuild_replay_does_not_report_a_missed_re_escape_again() {
    let (logs, _capture) = CapturedLogs::start();
    let chain = MockChain::start().await;
    mine_permanent_missed_re_escape(&chain);
    chain.mine_empty(3);
    let mut indexer = Indexer::new(config(&chain, 1, None));
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    assert_eq!(indexer.service.health().missed_re_escape_count, 1);

    // A reorg below the checkpoint adds a deposit and forces a rebuild, whose
    // replay closes the same escape again.
    chain.reorg(
        3,
        vec![
            vec![Tx::Deposit { commitment: 0xc }],
            vec![],
            vec![],
            vec![],
        ],
    );
    assert!(indexer.poll().await.is_err());
    assert_eq!(indexer.poll().await.unwrap(), PollOutcome::MoreWork);
    indexer.poll_to_idle().await;
    assert_serves_head(&chain, &indexer);
    let health = indexer.service.health();
    assert_eq!(health.rebuild_count, 1);
    assert_eq!(health.missed_re_escape_count, 1);
    assert_eq!(logs.reports(EscapeClose::Challenged).len(), 1);
    assert_eq!(
        logs.lines_with("missed re-escape already reported").len(),
        1
    );
}
