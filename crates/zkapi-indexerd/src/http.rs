//! Axum HTTP server for the tree indexer.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use zkapi_types::Felt252;

use crate::poller::{normalize_address, spawn_json_rpc_log_poller, JsonRpcLogPoller, PollerConfig};
use crate::service::{
    IndexerService, NextNoteIdResponse, PendingEscapesResponse, PublishedNullifierResponse,
    ServiceSettings, SyncStatus, TreePathResponse, TreeRootResponse, TreeView,
};
use crate::tree_mirror::NoteRecord;

/// Seconds a client should wait before retrying an unavailable indexer.
const RETRY_AFTER_SECONDS: u64 = 5;

/// Runtime configuration for the indexer HTTP server.
#[derive(Debug, Clone)]
pub struct IndexerConfig {
    pub listen_addr: String,
    pub rpc_url: String,
    pub contract_address: String,
    pub from_block: u64,
    pub poll_interval_ms: u64,
    pub cursor_path: Option<String>,
    /// Blocks a vault event must be buried before it is committed.
    pub confirmations: u64,
    /// Expected chain id; the RPC and checkpoint must match it.
    pub chain_id: Option<u64>,
    /// Archive the checkpoint and replay from `from_block`.
    pub resync: bool,
    /// Seconds without a verified poll before the view is stale.
    pub stale_after_secs: u64,
    /// Largest `eth_getLogs` range.
    pub max_block_range: u64,
    /// Oldest RPC head timestamp, in seconds, the view may rest on; 0
    /// disables the check (anvil mines only on demand).
    pub max_head_age_secs: u64,
}

impl Default for IndexerConfig {
    fn default() -> Self {
        let poller = PollerConfig::default();
        Self {
            listen_addr: "0.0.0.0:3001".to_string(),
            rpc_url: poller.rpc_url,
            contract_address: poller.contract_address,
            from_block: poller.from_block,
            poll_interval_ms: 1_000,
            cursor_path: poller.cursor_path,
            confirmations: poller.confirmations,
            chain_id: poller.chain_id,
            resync: poller.resync,
            stale_after_secs: 120,
            max_block_range: poller.max_block_range,
            max_head_age_secs: 180,
        }
    }
}

type AppState = Arc<IndexerService>;

pub async fn run_indexer(config: IndexerConfig) -> anyhow::Result<()> {
    anyhow::ensure!(!config.rpc_url.trim().is_empty(), "--rpc-url is required");
    anyhow::ensure!(
        !config.contract_address.trim().is_empty(),
        "--contract-address is required"
    );
    let contract_address = normalize_address(&config.contract_address)?;
    anyhow::ensure!(
        contract_address != format!("0x{}", "0".repeat(40)),
        "--contract-address must not be the zero address"
    );
    anyhow::ensure!(
        config.max_block_range > 0,
        "--max-block-range must be positive"
    );
    anyhow::ensure!(
        config.confirmations < config.max_block_range,
        "--confirmations must be below --max-block-range"
    );
    anyhow::ensure!(
        config.stale_after_secs > 0,
        "--stale-after-secs must be positive"
    );
    anyhow::ensure!(
        config.poll_interval_ms > 0,
        "--poll-interval-ms must be positive"
    );
    if config.confirmations == 0 {
        tracing::warn!(
            "--confirmations 0 commits unconfirmed blocks to the checkpoint; a reorg then forces a rebuild"
        );
    }
    if config.resync && config.cursor_path.is_none() {
        tracing::warn!("--resync has no effect without --cursor-path");
    }

    let poller_config = PollerConfig {
        rpc_url: config.rpc_url,
        contract_address: config.contract_address,
        from_block: config.from_block,
        cursor_path: config.cursor_path,
        confirmations: config.confirmations,
        chain_id: config.chain_id,
        max_block_range: config.max_block_range,
        resync: config.resync,
        ..PollerConfig::default()
    };
    let service = Arc::new(IndexerService::new_syncing(ServiceSettings {
        contract_address,
        chain_id: config.chain_id,
        confirmations: config.confirmations,
        stale_after: Duration::from_secs(config.stale_after_secs),
        max_head_age: (config.max_head_age_secs > 0)
            .then(|| Duration::from_secs(config.max_head_age_secs)),
    }));
    // Build the poller before binding so lock, checkpoint-binding and
    // version errors exit non-zero instead of serving 503 forever.
    let poller = JsonRpcLogPoller::new(poller_config, &service)?;
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    spawn_json_rpc_log_poller(
        service.clone(),
        poller,
        Duration::from_millis(config.poll_interval_ms),
    );

    let router = create_router(service);
    tracing::info!("Indexer listening on {}", config.listen_addr);
    axum::serve(listener, router).await?;
    Ok(())
}

pub fn create_router(service: Arc<IndexerService>) -> Router {
    Router::new()
        .route("/health", get(handle_health))
        .route("/metrics", get(handle_metrics))
        .route("/v1/tree/root", get(handle_root))
        .route("/v1/tree/next-note-id", get(handle_next_note_id))
        .route("/v1/tree/snapshot", get(handle_snapshot))
        .route("/v1/tree/notes/{note_id}/path", get(handle_note_path))
        .route(
            "/v1/nullifiers/{nullifier}/published",
            get(handle_published_nullifier),
        )
        .route("/v1/escapes/pending", get(handle_pending_escapes))
        .with_state(service)
}

/// Internal: 200 only while a verified head view is served.
async fn handle_health(State(service): State<AppState>) -> Response {
    let health = service.health();
    let status = if health.status == SyncStatus::Ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(health)).into_response()
}

/// Internal Prometheus metrics.
async fn handle_metrics(State(service): State<AppState>) -> Response {
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        service.metrics(),
    )
        .into_response()
}

/// 503 for every tree route without a verified view. The body is public
/// through the gateway, so it never reveals the indexer phase or RPC detail.
pub struct IndexerUnavailable;

impl IntoResponse for IndexerUnavailable {
    fn into_response(self) -> Response {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, RETRY_AFTER_SECONDS.to_string())],
            Json(serde_json::json!({
                "status": "unavailable",
                "error_code": "indexer_unavailable",
                "error_message": "the indexer has no verified view of the vault state; retry later",
                "retriable": true,
                "retry_after_seconds": RETRY_AFTER_SECONDS,
            })),
        )
            .into_response()
    }
}

fn served_view(service: &IndexerService) -> Result<Arc<TreeView>, IndexerUnavailable> {
    service.view().map_err(|_| IndexerUnavailable)
}

async fn handle_root(
    State(service): State<AppState>,
) -> Result<Json<TreeRootResponse>, IndexerUnavailable> {
    let view = served_view(&service)?;
    Ok(Json(TreeRootResponse {
        root: view.root,
        next_note_id: view.next_note_id,
        activation_cursor: view.activation_cursor,
        block_number: view.block_number,
        block_hash: view.block_hash.clone(),
    }))
}

/// What `GET /v1/tree/snapshot` serves, from its `parts` query parameter.
/// A part depends only on the view, never on which note a client cares about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotParts {
    /// No `parts`: the header, `leaves`, `note_leaves` and `notes`.
    All,
    /// `parts=tree`: the header and `leaves`, from which a prover derives
    /// its path.
    Tree,
    /// `parts=records`: the header, `note_leaves` and `notes`, with which a
    /// client corroborates a deposit.
    Records,
}

impl SnapshotParts {
    /// `None` unless `parts` is absent or is exactly one `tree` or
    /// `records`. Other parameters are ignored.
    fn parse(query: &[(String, String)]) -> Option<Self> {
        let mut values = query
            .iter()
            .filter(|(key, _)| key == "parts")
            .map(|(_, value)| value.as_str());
        match (values.next(), values.next()) {
            (None, _) => Some(Self::All),
            (Some("tree"), None) => Some(Self::Tree),
            (Some("records"), None) => Some(Self::Records),
            _ => None,
        }
    }

    fn leaves(self) -> bool {
        self != Self::Records
    }

    fn records(self) -> bool {
        self != Self::Tree
    }
}

/// The snapshot body, borrowed from the view. Its fields and their order are
/// those of [`TreeSnapshotResponse`](crate::service::TreeSnapshotResponse),
/// so the full payload serializes exactly as that type does; a part omits
/// the fields it does not carry.
#[derive(serde::Serialize)]
struct SnapshotBody<'a> {
    root: Felt252,
    next_note_id: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    leaves: Option<Vec<Felt252>>,
    block_number: u64,
    block_hash: &'a str,
    activation_cursor: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    note_leaves: Option<&'a [Felt252]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<&'a [NoteRecord]>,
}

/// Privacy-safe whole-tree snapshot. The same payload is returned regardless of
/// which note the caller cares about, so the untrusted indexer never learns it.
/// `parts=tree` keeps the header and `leaves` (the request path's need),
/// `parts=records` the header, `note_leaves` and `notes`; without `parts`,
/// everything. Each response is cut from one verified view, so the header of
/// every part describes the same block.
async fn handle_snapshot(
    State(service): State<AppState>,
    query: Result<Query<Vec<(String, String)>>, QueryRejection>,
) -> Response {
    let Some(parts) = query
        .ok()
        .and_then(|Query(query)| SnapshotParts::parse(&query))
    else {
        return invalid_request("parts must be tree or records".to_string());
    };
    let view = match served_view(&service) {
        Ok(view) => view,
        Err(unavailable) => return unavailable.into_response(),
    };
    let records = parts.records();
    Json(SnapshotBody {
        root: view.root,
        next_note_id: view.next_note_id,
        leaves: parts.leaves().then(|| view.mirror.current_leaves()),
        block_number: view.block_number,
        block_hash: &view.block_hash,
        activation_cursor: view.activation_cursor,
        note_leaves: records.then(|| view.mirror.note_leaves()),
        notes: records.then(|| view.mirror.notes()),
    })
    .into_response()
}

async fn handle_next_note_id(
    State(service): State<AppState>,
) -> Result<Json<NextNoteIdResponse>, IndexerUnavailable> {
    let view = served_view(&service)?;
    Ok(Json(NextNoteIdResponse {
        next_note_id: view.next_note_id,
        root: view.root,
        block_number: view.block_number,
        block_hash: view.block_hash.clone(),
    }))
}

async fn handle_note_path(
    State(service): State<AppState>,
    Path(note_id): Path<u32>,
) -> Result<Json<TreePathResponse>, IndexerUnavailable> {
    let view = served_view(&service)?;
    Ok(Json(TreePathResponse {
        note_id,
        leaf: view.mirror.get_leaf(note_id),
        siblings: view.mirror.get_path(note_id).to_vec(),
        root: view.root,
        block_number: view.block_number,
        block_hash: view.block_hash.clone(),
        activated: view.mirror.is_activated(note_id),
        activation_cursor: view.activation_cursor,
    }))
}

/// 400 in the indexer's error shape.
fn invalid_request(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({
            "status": "error",
            "error_code": "invalid_request",
            "error_message": message,
            "retriable": false,
        })),
    )
        .into_response()
}

/// 400 for a path parameter that is not a canonical field element.
fn invalid_felt(name: &str) -> Response {
    invalid_request(format!("{name} must be a hex BN254 field element"))
}

/// The published-nullifier table (§5.2): whether a vault event in the
/// verified view names `nullifier` as a `withdrawalNullifier` or
/// `nextNullifier`. 503 without a verified view, which serverd treats as
/// unreadable publication and refuses to serve evidence.
async fn handle_published_nullifier(
    State(service): State<AppState>,
    Path(nullifier): Path<String>,
) -> Response {
    let Ok(nullifier) = Felt252::from_hex(&nullifier) else {
        return invalid_felt("nullifier");
    };
    let view = match served_view(&service) {
        Ok(view) => view,
        Err(unavailable) => return unavailable.into_response(),
    };
    Json(PublishedNullifierResponse {
        nullifier,
        published: view.mirror.is_published(&nullifier),
        block_number: view.block_number,
        block_hash: view.block_hash.clone(),
    })
    .into_response()
}

/// Internal: escape withdrawals open in the verified view, with their
/// concession. Escapes change no leaf, so the root check does not cover the
/// list: the challenger reconciles its own escape-event scan against the note
/// ids, and each entry is a hint. Consumers read `pendingWithdrawals(note)`
/// and `pendingConcessions(note)` from the vault.
async fn handle_pending_escapes(
    State(service): State<AppState>,
) -> Result<Json<PendingEscapesResponse>, IndexerUnavailable> {
    let view = served_view(&service)?;
    Ok(Json(PendingEscapesResponse {
        block_number: view.block_number,
        block_hash: view.block_hash.clone(),
        root: view.root,
        escapes: view.mirror.pending_escapes(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use zkapi_core::merkle::{compute_root, MerkleTree};
    use zkapi_types::MERKLE_DEPTH;

    use crate::events::VaultEvent;
    use crate::service::TreeSnapshotResponse;
    use crate::tree_mirror::tests::{apply_all, Reference};
    use crate::tree_mirror::{EscapeClose, TreeMirror};

    /// `recorded` deposits, the first `activated` of them activated one by
    /// one, with event roots checked.
    fn mirror_with_notes(recorded: u32, activated: u32) -> TreeMirror {
        let mut reference = Reference::new();
        let mut events: Vec<VaultEvent> = (0..recorded)
            .map(|note_id| reference.deposit(100 + u64::from(note_id)))
            .collect();
        events.extend((0..activated).map(|_| reference.activate(1)));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        mirror
    }

    fn mirror_with_deposits(count: u32) -> TreeMirror {
        mirror_with_notes(count, count)
    }

    fn block_hash(byte: &str) -> String {
        format!("0x{}", byte.repeat(32))
    }

    async fn serve(service: Arc<IndexerService>) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = create_router(service);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    const SERVED_ROUTES: [&str; 6] = [
        "/v1/tree/root",
        "/v1/tree/next-note-id",
        "/v1/tree/snapshot",
        "/v1/tree/notes/0/path",
        "/v1/nullifiers/0x1/published",
        "/v1/escapes/pending",
    ];

    async fn assert_public_unavailable(base: &str, secret: &str) {
        for route in SERVED_ROUTES {
            let response = reqwest::get(format!("{base}{route}")).await.unwrap();
            assert_eq!(
                response.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "{route}"
            );
            assert_eq!(
                response.headers()[header::RETRY_AFTER],
                "5",
                "{route} must carry Retry-After"
            );
            let body = response.text().await.unwrap();
            assert!(!body.contains(secret), "{route} leaked indexer detail");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(
                body,
                serde_json::json!({
                    "status": "unavailable",
                    "error_code": "indexer_unavailable",
                    "error_message": "the indexer has no verified view of the vault state; retry later",
                    "retriable": true,
                    "retry_after_seconds": 5,
                }),
                "{route}"
            );
        }
    }

    #[tokio::test]
    async fn the_zero_path_and_known_root_routes_are_gone() {
        // Deposits take no path and the vault keeps no root history.
        let service = Arc::new(IndexerService::new_ready(mirror_with_deposits(1)));
        let base = serve(service).await;
        for route in ["/v1/tree/notes/0/zero-path", "/v1/tree/roots/0x1"] {
            let response = reqwest::get(format!("{base}{route}")).await.unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{route}");
        }
    }

    /// Two deposits, an escape of note 0 (N = 0x900, N+ = 0x901) and a
    /// mutual close of note 1 (N = 0x7001), with event roots checked.
    fn mirror_with_exits() -> TreeMirror {
        let mut reference = Reference::new();
        let mut events = vec![reference.deposit(100), reference.deposit(101)];
        events.extend(reference.escape(0, 0x900));
        events.push(reference.close(1));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        mirror
    }

    #[tokio::test]
    async fn published_nullifiers_are_served_from_the_verified_view() {
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        service.publish_head(TreeView::new(
            Arc::new(mirror_with_exits()),
            12,
            block_hash("12"),
        ));
        service.record_success();
        let base = serve(service.clone()).await;
        let published = |nullifier: &'static str| {
            let base = base.clone();
            async move {
                let response = reqwest::get(format!("{base}/v1/nullifiers/{nullifier}/published"))
                    .await
                    .unwrap();
                (
                    response.status(),
                    response.json::<serde_json::Value>().await.unwrap(),
                )
            }
        };
        // The escaped nullifier, its successor and a closed nullifier, in
        // the short hex serverd sends and in full 32-byte hex.
        for nullifier in [
            "0x900",
            "0x901",
            "0x1b59",
            "0x0000000000000000000000000000000000000000000000000000000000000901",
        ] {
            let (status, body) = published(nullifier).await;
            assert_eq!(status, StatusCode::OK, "{nullifier}");
            assert_eq!(body["published"], true, "{nullifier}");
            assert_eq!(body["block_number"], 12);
            assert_eq!(body["block_hash"], block_hash("12"));
        }
        let (status, body) = published("0x902").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["published"], false);
        assert_eq!(body["nullifier"], "0x902");
        // Not a field element, or not hex: refused, never "not published".
        for invalid in [
            "zz",
            "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",
        ] {
            let (status, body) = published(invalid).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{invalid}");
            assert_eq!(body["error_code"], "invalid_request");
        }
        // Without a verified view the table is unreadable: 503, which serverd
        // turns into chain_read_unavailable rather than serving evidence.
        service.set_phase(SyncStatus::Diverged, Some("test".into()));
        let (status, _) = published("0x900").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// Six recorded notes, four activated, note 1 closed and retired.
    fn mirror_with_retired_note() -> TreeMirror {
        let mut reference = Reference::new();
        let mut events: Vec<VaultEvent> = (0..6).map(|n| reference.deposit(100 + n)).collect();
        events.push(reference.activate(4));
        events.push(reference.close(1));
        events.push(reference.retire(1));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        mirror
    }

    async fn get_snapshot(base: &str, query: &str) -> (StatusCode, String) {
        let response = reqwest::get(format!("{base}/v1/tree/snapshot{query}"))
            .await
            .unwrap();
        (response.status(), response.text().await.unwrap())
    }

    #[tokio::test]
    async fn snapshot_lets_a_client_rebuild_paths_locally() {
        let service = Arc::new(IndexerService::new_ready(mirror_with_retired_note()));
        let base = serve(service.clone()).await;

        let snapshot = reqwest::get(format!("{base}/v1/tree/snapshot"))
            .await
            .unwrap()
            .error_for_status()
            .unwrap()
            .json::<TreeSnapshotResponse>()
            .await
            .unwrap();

        assert_eq!(snapshot.leaves.len() as u32, snapshot.next_note_id);
        assert_eq!(snapshot.next_note_id, 6);
        assert_eq!(snapshot.activation_cursor, 4);
        let view = service.view().unwrap();
        assert_eq!(snapshot.block_number, view.block_number);
        assert_eq!(snapshot.block_hash, view.block_hash);
        // The tree leaves are zero for the retired note and the two notes
        // not yet activated; the recorded leaves and records cover all six.
        let zero: Vec<bool> = snapshot.leaves.iter().map(Felt252::is_zero).collect();
        assert_eq!(zero, [false, true, false, false, true, true]);
        assert_eq!(snapshot.note_leaves, view.mirror.note_leaves());
        assert_eq!(snapshot.notes.len(), 6);
        for (note_id, note) in snapshot.notes.iter().enumerate() {
            assert_eq!(
                *note,
                NoteRecord {
                    note_id: note_id as u32,
                    commitment: Felt252::from_u64(100 + note_id as u64),
                    amount: 1_000,
                    expiry_ts: 1_700_000_000,
                }
            );
            assert_eq!(note.leaf(), snapshot.note_leaves[note_id]);
        }
        let body: serde_json::Value = reqwest::get(format!("{base}/v1/tree/snapshot"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            body["notes"][2],
            serde_json::json!({
                "note_id": 2,
                "commitment": "0x66",
                "amount": 1_000,
                "expiry_ts": 1_700_000_000u64,
            })
        );

        // A client rebuilds the whole tree from the snapshot alone — no per-slot
        // request — and recovers the root plus any sibling path locally.
        let mut local = MerkleTree::new();
        for leaf in &snapshot.leaves {
            local.insert(*leaf);
        }
        assert_eq!(local.root(), snapshot.root);
        for slot in [0, 2, 4] {
            assert_eq!(
                local.get_siblings(slot).to_vec(),
                view.mirror.get_path(slot).to_vec(),
                "locally derived path must match the indexer's per-slot path"
            );
        }
    }

    #[tokio::test]
    async fn snapshot_parts_are_cut_from_one_view() {
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        service.publish_head(TreeView::new(
            Arc::new(mirror_with_retired_note()),
            42,
            block_hash("42"),
        ));
        service.record_success();
        let base = serve(service.clone()).await;
        let view = service.view().unwrap();

        // Without `parts`, the body is byte for byte the full snapshot.
        let (status, full) = get_snapshot(&base, "").await;
        assert_eq!(status, StatusCode::OK);
        let expected = serde_json::to_string(&TreeSnapshotResponse {
            root: view.root,
            next_note_id: view.next_note_id,
            leaves: view.mirror.current_leaves(),
            block_number: view.block_number,
            block_hash: view.block_hash.clone(),
            activation_cursor: view.activation_cursor,
            note_leaves: view.mirror.note_leaves().to_vec(),
            notes: view.mirror.notes().to_vec(),
        })
        .unwrap();
        assert_eq!(full, expected);
        let full: serde_json::Value = serde_json::from_str(&full).unwrap();

        // Each part is the full body less the other part's fields, so its
        // header is the same view's.
        for (query, dropped) in [
            ("?parts=tree", &["note_leaves", "notes"][..]),
            ("?parts=records", &["leaves"][..]),
            // Other parameters, such as a cache buster, are ignored.
            ("?_=1&parts=tree", &["note_leaves", "notes"][..]),
        ] {
            let (status, body) = get_snapshot(&base, query).await;
            assert_eq!(status, StatusCode::OK, "{query}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            let mut expected = full.clone();
            for field in dropped {
                assert!(expected.as_object_mut().unwrap().remove(*field).is_some());
            }
            assert_eq!(body, expected, "{query}");
        }

        // The tree part alone rebuilds the root, and parses as the full type.
        let (_, tree) = get_snapshot(&base, "?parts=tree").await;
        let tree: TreeSnapshotResponse = serde_json::from_str(&tree).unwrap();
        let mut local = MerkleTree::new();
        for leaf in &tree.leaves {
            local.insert(*leaf);
        }
        assert_eq!(local.root(), view.root);
        assert_eq!(tree.activation_cursor, 4);
        assert!(tree.note_leaves.is_empty() && tree.notes.is_empty());
    }

    #[tokio::test]
    async fn snapshot_refuses_unknown_parts() {
        let service = Arc::new(IndexerService::new_ready(mirror_with_deposits(2)));
        let base = serve(service.clone()).await;
        let refused = serde_json::json!({
            "status": "error",
            "error_code": "invalid_request",
            "error_message": "parts must be tree or records",
            "retriable": false,
        });
        for query in [
            "?parts=",
            "?parts",
            "?parts=all",
            "?parts=Tree",
            "?parts=leaves",
            "?parts=tree,records",
            "?parts=tree&parts=records",
            "?parts=tree&parts=tree",
        ] {
            let (status, body) = get_snapshot(&base, query).await;
            assert_eq!(status, StatusCode::BAD_REQUEST, "{query}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body, refused, "{query}");
        }

        // Without a verified view every part is unavailable; a malformed
        // request is still refused as malformed.
        service.set_phase(SyncStatus::Diverged, Some("test".into()));
        for query in ["?parts=tree", "?parts=records"] {
            let (status, body) = get_snapshot(&base, query).await;
            assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{query}");
            let body: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert_eq!(body["error_code"], "indexer_unavailable", "{query}");
        }
        let (status, _) = get_snapshot(&base, "?parts=all").await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn syncing_indexer_does_not_serve_partial_tree_data() {
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        let base = serve(service.clone()).await;

        let health = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let health: serde_json::Value = health.json().await.unwrap();
        assert_eq!(health["status"], "syncing");
        assert_public_unavailable(&base, "syncing").await;

        service.publish_head(TreeView::new(
            Arc::new(mirror_with_deposits(1)),
            7,
            block_hash("07"),
        ));
        service.record_success();
        let root = reqwest::get(format!("{base}/v1/tree/root")).await.unwrap();
        assert_eq!(root.status(), StatusCode::OK);
        let health = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn diverged_and_rebuilding_return_503_with_json_reason() {
        let service = Arc::new(IndexerService::new_ready(mirror_with_deposits(2)));
        let base = serve(service.clone()).await;
        for route in SERVED_ROUTES {
            let response = reqwest::get(format!("{base}{route}")).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{route}");
        }

        let detail = "block 7 0xabc: vault root 0x1 nextNoteId 2; mirror root 0x2 next_note_id 2";
        service.set_phase(SyncStatus::Diverged, Some(detail.to_string()));
        let health = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let health: serde_json::Value = health.json().await.unwrap();
        assert_eq!(health["status"], "diverged");
        assert_eq!(health["reason"], detail);
        // Public bodies are constant: no phase, no mismatch detail.
        assert_public_unavailable(&base, "vault root").await;
        assert_public_unavailable(&base, "diverged").await;

        service.begin_rebuild("reorg below checkpoint at block 7".to_string());
        let health = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let health: serde_json::Value = health.json().await.unwrap();
        assert_eq!(health["status"], "rebuilding");
        assert_eq!(health["rebuild_count"], 1);
        assert_eq!(health["served_block"], serde_json::Value::Null);
        assert_public_unavailable(&base, "rebuilding").await;
    }

    #[tokio::test]
    async fn stale_view_fails_closed_after_stale_after() {
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings {
            stale_after: Duration::from_millis(200),
            max_head_age: None,
            ..ServiceSettings::default()
        }));
        service.publish_head(TreeView::new(
            Arc::new(mirror_with_deposits(1)),
            5,
            block_hash("05"),
        ));
        service.record_success();
        let base = serve(service.clone()).await;
        assert!(service.is_ready());
        assert_eq!(service.stale_transition(), None);

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(service.status(), SyncStatus::Stale);
        assert!(service.stale_transition().is_some());
        assert_eq!(service.stale_transition(), None, "reported once");
        let health = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        let health: serde_json::Value = health.json().await.unwrap();
        assert_eq!(health["status"], "stale");
        assert!(health["reason"]
            .as_str()
            .unwrap()
            .contains("no verified poll"));
        assert_public_unavailable(&base, "stale").await;

        service.refresh_success();
        assert!(service.is_ready());
    }

    #[tokio::test]
    async fn health_reports_served_and_confirmed_blocks() {
        let contract = "0x00000000000000000000000000000000000000aa".to_string();
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings {
            contract_address: contract.clone(),
            chain_id: Some(11_155_111),
            confirmations: 12,
            stale_after: Duration::from_secs(120),
            max_head_age: Some(Duration::from_secs(180)),
        }));
        let mirror = Arc::new(mirror_with_notes(3, 2));
        let now = crate::service::unix_ms() / 1_000;
        assert!(service.observe_head(100, now));
        service.set_confirmed(88, block_hash("88"), &mirror);
        service.set_sync_block(89);
        service.publish_head(TreeView::new(mirror.clone(), 99, block_hash("99")));
        service.record_success();
        let base = serve(service.clone()).await;

        let response = reqwest::get(format!("{base}/health")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let health: serde_json::Value = response.json().await.unwrap();
        assert_eq!(health["status"], "ok");
        assert_eq!(health["reason"], serde_json::Value::Null);
        assert_eq!(health["chain_id"], 11_155_111);
        assert_eq!(health["contract_address"], contract);
        assert_eq!(health["confirmations"], 12);
        assert_eq!(health["head_block"], 100);
        assert_eq!(health["head_timestamp"], now);
        assert!(health["head_age_seconds"].as_u64().unwrap() <= 1);
        assert_eq!(health["served_block"], 99);
        assert_eq!(health["served_block_hash"], block_hash("99"));
        assert_eq!(health["root"], serde_json::to_value(mirror.root()).unwrap());
        assert_eq!(health["next_note_id"], 3);
        assert_eq!(health["activation_cursor"], 2);
        assert_eq!(health["lag_blocks"], 1);
        assert_eq!(health["confirmed_block"], 88);
        assert_eq!(health["confirmed_block_hash"], block_hash("88"));
        assert_eq!(
            health["confirmed_root"],
            serde_json::to_value(mirror.root()).unwrap()
        );
        assert_eq!(health["confirmed_next_note_id"], 3);
        assert_eq!(health["confirmed_activation_cursor"], 2);
        assert_eq!(health["sync_block"], 89);
        assert!(health["last_success_unix_ms"].as_u64().is_some());
        assert!(health["last_verified_unix_ms"].as_u64().is_some());
        assert_eq!(health["consecutive_failures"], 0);
        assert_eq!(health["last_error"], serde_json::Value::Null);
        assert_eq!(health["divergence_count"], 0);
        assert_eq!(health["rebuild_count"], 0);
        assert_eq!(health["missed_re_escape_count"], 0);
        assert_eq!(health["missed_re_escape_finalized_count"], 0);
        assert!(health.get("known_root_count").is_none());
        assert_eq!(health["published_nullifier_count"], 0);
        assert!(serde_json::from_value::<crate::service::HealthResponse>(health).is_ok());

        // A head older than max_head_age makes the view stale.
        assert!(!service.observe_head(101, now - 600));
        let health = service.health();
        assert_eq!(health.status, SyncStatus::Stale);
        assert!(health.head_age_seconds.unwrap() >= 600);
    }

    #[tokio::test]
    async fn tree_responses_include_root_and_block() {
        let mirror = mirror_with_notes(4, 3);
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        service.publish_head(TreeView::new(Arc::new(mirror), 42, block_hash("42")));
        service.record_success();
        let base = serve(service.clone()).await;
        let view = service.view().unwrap();

        let path = reqwest::get(format!("{base}/v1/tree/notes/1/path"))
            .await
            .unwrap()
            .json::<TreePathResponse>()
            .await
            .unwrap();
        let siblings: [Felt252; MERKLE_DEPTH] = path.siblings.clone().try_into().unwrap();
        assert_eq!(compute_root(1, &path.leaf, &siblings), path.root);
        assert_eq!(path.leaf, view.mirror.note_leaves()[1]);
        assert_eq!(path.root, view.root);
        assert_eq!(path.block_number, 42);
        assert_eq!(path.block_hash, block_hash("42"));
        assert!(path.activated);
        assert_eq!(path.activation_cursor, 3);

        // Note 3 is recorded but not activated: its slot is empty, and its
        // siblings are the path above the next batch.
        let pending = reqwest::get(format!("{base}/v1/tree/notes/3/path"))
            .await
            .unwrap()
            .json::<TreePathResponse>()
            .await
            .unwrap();
        let siblings: [Felt252; MERKLE_DEPTH] = pending.siblings.clone().try_into().unwrap();
        assert_eq!(pending.leaf, Felt252::ZERO);
        assert_eq!(compute_root(3, &Felt252::ZERO, &siblings), pending.root);
        assert!(!pending.activated);
        assert_eq!(pending.activation_cursor, 3);
        assert_eq!(pending.block_number, 42);

        let root = reqwest::get(format!("{base}/v1/tree/root"))
            .await
            .unwrap()
            .json::<TreeRootResponse>()
            .await
            .unwrap();
        assert_eq!(root.root, view.root);
        assert_eq!(root.next_note_id, 4);
        assert_eq!(root.activation_cursor, 3);
        assert_eq!(root.block_number, 42);
        assert_eq!(root.block_hash, block_hash("42"));

        let next = reqwest::get(format!("{base}/v1/tree/next-note-id"))
            .await
            .unwrap()
            .json::<NextNoteIdResponse>()
            .await
            .unwrap();
        assert_eq!(next.next_note_id, 4);
        assert_eq!(next.root, view.root);
        assert_eq!(next.block_number, 42);

        // The root response has exactly these fields; consumers that only
        // know the root still parse it.
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        #[allow(dead_code)]
        struct RootFields {
            root: Felt252,
            next_note_id: u32,
            activation_cursor: u32,
            block_number: u64,
            block_hash: String,
        }
        #[derive(serde::Deserialize)]
        struct MinimalRoot {
            root: Felt252,
        }
        let body = reqwest::get(format!("{base}/v1/tree/root"))
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(serde_json::from_str::<RootFields>(&body).is_ok());
        assert_eq!(
            serde_json::from_str::<MinimalRoot>(&body).unwrap().root,
            view.root
        );
        let old_snapshot: TreeSnapshotResponse =
            serde_json::from_str(r#"{"root":"0x1","next_note_id":0,"leaves":[]}"#).unwrap();
        assert_eq!(old_snapshot.block_number, 0);
        assert!(old_snapshot.notes.is_empty());
    }

    #[tokio::test]
    async fn pending_escapes_endpoint_reports_the_served_view() {
        let mut mirror = mirror_with_deposits(2);
        mirror.process_event(&VaultEvent::EscapeWithdrawalInitiated {
            note_id: 1,
            nullifier: Felt252::from_u64(0xabc),
            final_balance: 10,
            challenge_deadline: 1_700_086_400,
            current_root: Felt252::ZERO,
        });
        mirror.process_event(&VaultEvent::EscapeConcessionRecorded {
            note_id: 1,
            next_nullifier: Felt252::from_u64(0xabd),
            state_balance: 15,
            conceded: 5,
        });
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        service.publish_head(TreeView::new(Arc::new(mirror), 9, block_hash("09")));
        service.record_success();
        let base = serve(service.clone()).await;

        let body: serde_json::Value = reqwest::get(format!("{base}/v1/escapes/pending"))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            body,
            serde_json::json!({
                "block_number": 9,
                "block_hash": block_hash("09"),
                "root": service.view().unwrap().root,
                "escapes": [{
                    "note_id": 1,
                    "withdrawal_nullifier": "0xabc",
                    "challenge_deadline": 1_700_086_400u64,
                    "final_balance": 10,
                    "next_nullifier": "0xabd",
                    "state_balance": 15,
                    "conceded": 5,
                }],
            })
        );
    }

    #[tokio::test]
    async fn metrics_endpoint_renders_gauges() {
        let service = Arc::new(IndexerService::new_syncing(ServiceSettings::default()));
        let now = crate::service::unix_ms() / 1_000;
        service.observe_head(100, now);
        let mirror = mirror_with_notes(5, 4);
        service.set_confirmed(88, block_hash("88"), &mirror);
        service.publish_head(TreeView::new(Arc::new(mirror), 99, block_hash("99")));
        service.record_success();
        service.bump_divergences();
        service.bump_missed_re_escapes(EscapeClose::Challenged);
        service.bump_missed_re_escapes(EscapeClose::Finalized);
        service.bump_missed_re_escapes(EscapeClose::Challenged);
        service.bump_missed_re_escapes(EscapeClose::Raised);
        let health = service.health();
        assert_eq!(health.missed_re_escape_count, 4);
        assert_eq!(health.missed_re_escape_finalized_count, 1);
        assert_eq!(health.missed_re_escape_raised_count, 1);
        let base = serve(service).await;

        let response = reqwest::get(format!("{base}/metrics")).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "text/plain; version=0.0.4"
        );
        let text = response.text().await.unwrap();
        for line in [
            "zkapi_indexer_status{status=\"ok\"} 1",
            "zkapi_indexer_status{status=\"syncing\"} 0",
            "zkapi_indexer_status{status=\"stale\"} 0",
            "zkapi_indexer_status{status=\"diverged\"} 0",
            "zkapi_indexer_status{status=\"rebuilding\"} 0",
            "zkapi_indexer_head_block 100",
            &format!("zkapi_indexer_head_timestamp_seconds {now}"),
            "zkapi_indexer_served_block 99",
            "zkapi_indexer_confirmed_block 88",
            "zkapi_indexer_lag_blocks 1",
            "zkapi_indexer_activation_cursor 4",
            "zkapi_indexer_pending_activations 1",
            "zkapi_indexer_consecutive_failures 0",
            "zkapi_indexer_divergences_total 1",
            "zkapi_indexer_rebuilds_total 0",
            "zkapi_indexer_missed_re_escapes_total{event=\"challenged\"} 2",
            "zkapi_indexer_missed_re_escapes_total{event=\"finalized\"} 1",
            "zkapi_indexer_missed_re_escapes_total{event=\"raised\"} 1",
            "# TYPE zkapi_indexer_rebuilds_total counter",
            "# TYPE zkapi_indexer_missed_re_escapes_total counter",
            "# TYPE zkapi_indexer_served_block gauge",
        ] {
            assert!(
                text.lines().any(|candidate| candidate == line),
                "missing {line:?} in\n{text}"
            );
        }
        // One HELP and TYPE pair, and only labelled samples.
        assert_eq!(
            text.matches("# TYPE zkapi_indexer_missed_re_escapes_total ")
                .count(),
            1
        );
        assert!(!text
            .lines()
            .any(|line| line.starts_with("zkapi_indexer_missed_re_escapes_total ")));
        assert!(text.contains("zkapi_indexer_head_age_seconds "));
        assert!(text.contains("zkapi_indexer_last_success_timestamp_seconds "));
    }
}
