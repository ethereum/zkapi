//! Deterministic JSON-RPC chain for poller tests.
//!
//! Blocks carry hashes derived from (fork id, number) with parent links. Vault
//! logs and the vault state after each block come from a reference mirror
//! (note statuses and escapes) and the vault's own tree model
//! (`zkapi_core::merkle::Frontier`), which answers `currentRoot()`,
//! `nextNoteId()` and `noteLeaves(start, count)` as revision 4 computes them.
//! Controls cover the failure modes the indexer must survive: reorgs, a
//! `eth_getLogs` replica that silently lags the head, dropped logs, pruned
//! historical state, RPCs without EIP-1898 support, `noteLeaves` pages served
//! from another block, a wrong chain, a frozen or stale head, transport errors
//! and rate limits. Every call is recorded for assertions.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::State;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_core::leaf::compute_note_leaf;
use zkapi_core::merkle::Frontier;
use zkapi_types::Felt252;

use crate::events::VaultEvent;
use crate::poller::{
    event_topic, CLOSED_LEAF_RETIRED, CONCESSION_RAISED, CONCESSION_RECORDED, ESCAPE_CHALLENGED,
    ESCAPE_FINALIZED, ESCAPE_INITIATED, EXPIRED_CLAIMED, MUTUAL_CLOSE, NOTE_DEPOSITED,
};
use crate::tree_mirror::TreeMirror;

pub(crate) const VAULT: &str = "0x00000000000000000000000000000000000000aa";
pub(crate) const CHAIN_ID: u64 = 31_337;
/// Block 0 has no vault code; the vault is deployed in block 1.
pub(crate) const DEPLOY_BLOCK: u64 = 1;
pub(crate) const DEPOSIT_AMOUNT: u128 = 1_000;
pub(crate) const EXPIRY_TS: u64 = 1_900_000_000;

/// A vault call mined into a block.
#[derive(Debug, Clone)]
pub(crate) enum Tx {
    Deposit {
        commitment: u64,
    },
    Close {
        note_id: u32,
    },
    /// An escape at `nullifier`; its successor nullifier is `nullifier + 1`.
    /// Emits EscapeWithdrawalInitiated and EscapeConcessionRecorded.
    Escape {
        note_id: u32,
        nullifier: u64,
    },
    /// Raise the pending escape's concession to `conceded` (at most 15).
    Raise {
        note_id: u32,
        conceded: u128,
    },
    /// A defeat of the pending escape.
    Challenge {
        note_id: u32,
    },
    /// `retireClosedLeaf` of a closed note.
    Retire {
        note_id: u32,
    },
    Finalize {
        note_id: u32,
    },
    Claim {
        note_id: u32,
    },
    /// Any other vault log (unknown topic0, arbitrary data).
    Raw {
        topics: Vec<String>,
        data: String,
    },
}

/// Challenge deadline the mock vault assigns to an escape.
pub(crate) fn escape_deadline(nullifier: u64) -> u64 {
    2_000_000_000 + nullifier
}

#[derive(Clone)]
struct MockLog {
    topics: Vec<String>,
    data: String,
}

/// The vault's state: note statuses and escapes (a reference mirror) and
/// the tree as the vault keeps it.
#[derive(Clone)]
struct VaultState {
    mirror: TreeMirror,
    tree: Frontier,
}

#[derive(Clone)]
struct Block {
    number: u64,
    hash: String,
    parent_hash: String,
    timestamp: u64,
    logs: Vec<MockLog>,
    /// Vault state after the block; `None` before deployment.
    state: Option<Arc<VaultState>>,
}

#[derive(Default)]
struct Faults {
    logs_lag: u64,
    dropped: HashSet<(u64, usize)>,
    state_window: Option<u64>,
    reject_block_hash: bool,
    latest: Option<u64>,
    /// Header-by-number answers from a stale fork (a load-balancer backend).
    stale_headers: HashMap<u64, String>,
    /// The vault answers CONCESSION_ESCAPE_VERSION() with this value; `None`
    /// reverts, as a vault before revision 3 does.
    escape_version: Option<u64>,
    /// The vault answers LEAF_BOUND_EXIT_VERSION() with this value; `None`
    /// reverts, as a vault before revision 4 does.
    leaf_bound_version: Option<u64>,
    /// `noteLeaves` answers from this block's state whatever block hash it
    /// is asked for.
    leaf_pages_at: Option<u64>,
    fail: HashMap<String, u32>,
    rate_limit: HashMap<String, u32>,
}

struct Chain {
    chain_id: u64,
    fork: u64,
    blocks: Vec<Block>,
    hashes: HashMap<String, u64>,
    faults: Faults,
    calls: Vec<(String, Value)>,
    timestamp: Option<u64>,
}

impl Chain {
    fn head(&self) -> u64 {
        self.blocks.len() as u64 - 1
    }

    fn mine(&mut self, txs: Vec<Tx>) -> u64 {
        let number = self.blocks.len() as u64;
        let parent = self
            .blocks
            .last()
            .map(|block| (block.hash.clone(), block.state.clone()));
        let (parent_hash, parent_state) =
            parent.unwrap_or_else(|| (format!("0x{}", "0".repeat(64)), None));
        let mut state = parent_state.or_else(|| {
            (number >= DEPLOY_BLOCK).then(|| {
                Arc::new(VaultState {
                    mirror: TreeMirror::new(),
                    tree: Frontier::new(),
                })
            })
        });
        let mut logs = Vec::new();
        for tx in txs {
            let vault = Arc::make_mut(state.as_mut().expect("vault is deployed"));
            logs.extend(apply(vault, tx));
        }
        let hash = block_hash(self.fork, number);
        self.hashes.insert(hash.clone(), number);
        self.blocks.push(Block {
            number,
            hash,
            parent_hash,
            timestamp: self.timestamp.unwrap_or_else(now_secs),
            logs,
            state,
        });
        number
    }

    fn block_json(&self, number: u64) -> Value {
        let Some(block) = self.blocks.get(number as usize) else {
            return Value::Null;
        };
        json!({
            "number": hex(block.number),
            "hash": block.hash,
            "parentHash": block.parent_hash,
            "timestamp": hex(block.timestamp),
            "transactions": [],
        })
    }

    fn get_logs(&self, filter: &Value) -> Result<Value, (i64, String)> {
        let address = filter["address"].as_str().unwrap_or_default();
        if !address.eq_ignore_ascii_case(VAULT) {
            return Ok(json!([]));
        }
        let from = parse_hex(&filter["fromBlock"])?;
        let to = parse_hex(&filter["toBlock"])?;
        // Like anvil: a range above the (lagging) head is clamped silently.
        let to = to.min(self.head().saturating_sub(self.faults.logs_lag));
        let mut logs = Vec::new();
        for number in from..=to {
            let Some(block) = self.blocks.get(number as usize) else {
                break;
            };
            for (index, log) in block.logs.iter().enumerate() {
                if self.faults.dropped.contains(&(number, index)) {
                    continue;
                }
                logs.push(json!({
                    "address": VAULT,
                    "topics": log.topics,
                    "data": log.data,
                    "blockNumber": hex(number),
                    "blockHash": block.hash,
                    "logIndex": hex(index as u64),
                    "transactionHash": block_hash(u64::MAX, number * 1_000 + index as u64),
                    "removed": false,
                }));
            }
        }
        Ok(Value::Array(logs))
    }

    fn call(&self, params: &Value) -> Result<Value, (i64, String)> {
        if self.faults.reject_block_hash {
            return Err((
                -32602,
                "invalid argument 1: hex string without 0x prefix".to_string(),
            ));
        }
        let hash = params[1]["blockHash"]
            .as_str()
            .ok_or((-32602, "missing block hash".to_string()))?;
        let number = *self
            .hashes
            .get(&hash.to_ascii_lowercase())
            .ok_or((-32001, "header not found".to_string()))?;
        if let Some(window) = self.faults.state_window {
            if number + window < self.head() {
                return Err((-32000, "missing trie node".to_string()));
            }
        }
        let block = &self.blocks[number as usize];
        let to = params[0]["to"].as_str().unwrap_or_default();
        let Some(state) = block
            .state
            .as_ref()
            .filter(|_| to.eq_ignore_ascii_case(VAULT))
        else {
            return Ok(json!("0x"));
        };
        let revert = || Err((-32000, "execution reverted".to_string()));
        let version = |version: Option<u64>| match version {
            Some(version) => Ok(json!(format!("0x{version:064x}"))),
            None => revert(),
        };
        let data = params[0]["data"].as_str().unwrap_or_default();
        if let Some(args) = data.strip_prefix("0x31749c58") {
            // noteLeaves(uint32 start, uint32 count)
            let word = |index: usize| {
                args.get(index * 64..(index + 1) * 64)
                    .and_then(|word| u64::from_str_radix(word, 16).ok())
            };
            let (Some(start), Some(count)) = (word(0), word(1)) else {
                return revert();
            };
            if start + count > u64::from(state.tree.next_index()) {
                // InvalidNoteRange
                return Err((3, "execution reverted: 0x9fe6fd7a".to_string()));
            }
            let source = match self.faults.leaf_pages_at {
                Some(at) => self.blocks[at as usize].state.clone().expect("deployed"),
                None => state.clone(),
            };
            let mut out = format!("0x{:064x}{count:064x}", 32);
            for index in start..start + count {
                out.push_str(&felt_hex(source.tree.leaf(index as u32)));
            }
            return Ok(json!(out));
        }
        match data {
            "0xfdab463d" => Ok(json!(felt_word(state.tree.root()))),
            "0x7a2043a3" => Ok(json!(format!("0x{:064x}", state.tree.next_index()))),
            "0x5e00b426" => version(self.faults.escape_version),
            "0xc0baafb1" => version(self.faults.leaf_bound_version),
            _ => revert(),
        }
    }
}

/// Apply a vault call to the vault state and return the logs it emits.
fn apply(vault: &mut VaultState, tx: Tx) -> Vec<MockLog> {
    let mirror = &mut vault.mirror;
    let destination = format!("0x{:064x}", 0xd0d0_u64);
    let note_topic = |note_id: u32| format!("0x{note_id:064x}");
    match tx {
        Tx::Deposit { commitment } => {
            let note_id = mirror.next_note_id();
            let commitment_felt = Felt252::from_u64(commitment);
            mirror.process_event(&VaultEvent::NoteDeposited {
                note_id,
                commitment: commitment_felt,
                amount: DEPOSIT_AMOUNT,
                expiry_ts: EXPIRY_TS,
            });
            let leaf = compute_note_leaf(note_id, &commitment_felt, DEPOSIT_AMOUNT, EXPIRY_TS);
            assert_eq!(vault.tree.append(leaf), Ok(note_id));
            vec![MockLog {
                topics: vec![
                    event_topic(NOTE_DEPOSITED),
                    note_topic(note_id),
                    format!("0x{commitment:064x}"),
                ],
                data: words(&[
                    format!("{DEPOSIT_AMOUNT:064x}"),
                    format!("{EXPIRY_TS:064x}"),
                ]),
            }]
        }
        Tx::Close { note_id } => {
            let nullifier = Felt252::from_u64(7_000 + u64::from(note_id));
            mirror.process_event(&VaultEvent::MutualClose {
                note_id,
                nullifier,
                final_balance: 10,
            });
            vec![MockLog {
                topics: vec![event_topic(MUTUAL_CLOSE), note_topic(note_id)],
                data: words(&[
                    felt_hex(nullifier),
                    format!("{:064x}", 10),
                    strip(&destination),
                ]),
            }]
        }
        Tx::Escape { note_id, nullifier } => {
            let deadline = escape_deadline(nullifier);
            let next = nullifier + 1;
            for event in [
                VaultEvent::EscapeWithdrawalInitiated {
                    note_id,
                    nullifier: Felt252::from_u64(nullifier),
                    final_balance: 10,
                    challenge_deadline: deadline,
                },
                VaultEvent::EscapeConcessionRecorded {
                    note_id,
                    next_nullifier: Felt252::from_u64(next),
                    state_balance: 15,
                    conceded: 5,
                },
            ] {
                mirror.process_event(&event);
            }
            vec![
                MockLog {
                    topics: vec![event_topic(ESCAPE_INITIATED), note_topic(note_id)],
                    data: words(&[
                        format!("{nullifier:064x}"),
                        format!("{:064x}", 10),
                        strip(&destination),
                        format!("{deadline:064x}"),
                    ]),
                },
                MockLog {
                    topics: vec![event_topic(CONCESSION_RECORDED), note_topic(note_id)],
                    data: words(&[
                        format!("{next:064x}"),
                        format!("{:064x}", 15),
                        format!("{:064x}", 5),
                    ]),
                },
            ]
        }
        Tx::Raise { note_id, conceded } => {
            let nullifier = pending_nullifier(mirror, note_id);
            mirror.process_event(&VaultEvent::EscapeConcessionRaised {
                note_id,
                nullifier,
                conceded,
                final_balance: 15 - conceded,
            });
            vec![MockLog {
                topics: vec![event_topic(CONCESSION_RAISED), note_topic(note_id)],
                data: words(&[
                    felt_hex(nullifier),
                    format!("{conceded:064x}"),
                    format!("{:064x}", 15 - conceded),
                ]),
            }]
        }
        Tx::Challenge { note_id } => {
            let nullifier = pending_nullifier(mirror, note_id);
            mirror.process_event(&VaultEvent::EscapeWithdrawalChallenged { note_id, nullifier });
            vec![MockLog {
                topics: vec![event_topic(ESCAPE_CHALLENGED), note_topic(note_id)],
                data: words(&[felt_hex(nullifier)]),
            }]
        }
        Tx::Finalize { note_id } => {
            let nullifier = pending_nullifier(mirror, note_id);
            mirror.process_event(&VaultEvent::EscapeWithdrawalFinalized {
                note_id,
                nullifier,
                final_balance: 10,
            });
            vec![MockLog {
                topics: vec![event_topic(ESCAPE_FINALIZED), note_topic(note_id)],
                data: words(&[
                    felt_hex(nullifier),
                    format!("{:064x}", 10),
                    strip(&destination),
                ]),
            }]
        }
        Tx::Claim { note_id } => {
            mirror.process_event(&VaultEvent::ExpiredClaimed {
                note_id,
                deposit_amount: DEPOSIT_AMOUNT,
            });
            vec![MockLog {
                topics: vec![event_topic(EXPIRED_CLAIMED), note_topic(note_id)],
                data: words(&[format!("{DEPOSIT_AMOUNT:064x}")]),
            }]
        }
        Tx::Retire { note_id } => {
            // The vault reads only the retirement level's siblings.
            vault
                .tree
                .retire(note_id, &mirror.get_path(note_id))
                .expect("mock vault: retirement reverts");
            mirror.process_event(&VaultEvent::ClosedLeafRetired { note_id });
            vec![MockLog {
                topics: vec![event_topic(CLOSED_LEAF_RETIRED), note_topic(note_id)],
                data: "0x".to_string(),
            }]
        }
        Tx::Raw { topics, data } => vec![MockLog { topics, data }],
    }
}

fn pending_nullifier(mirror: &TreeMirror, note_id: u32) -> Felt252 {
    mirror
        .pending_escapes()
        .into_iter()
        .find(|escape| escape.note_id == note_id)
        .expect("mock vault: note has no pending escape")
        .withdrawal_nullifier
}

/// Handle to a mock chain served over HTTP JSON-RPC.
pub(crate) struct MockChain {
    chain: Arc<Mutex<Chain>>,
    url: String,
    server: tokio::task::JoinHandle<()>,
}

impl Drop for MockChain {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl MockChain {
    /// Genesis (block 0, no vault code) plus the deployment block.
    pub(crate) async fn start() -> Self {
        let mut chain = Chain {
            chain_id: CHAIN_ID,
            fork: 0,
            blocks: Vec::new(),
            hashes: HashMap::new(),
            faults: Faults {
                escape_version: Some(1),
                leaf_bound_version: Some(1),
                ..Faults::default()
            },
            calls: Vec::new(),
            timestamp: None,
        };
        chain.mine(Vec::new());
        chain.mine(Vec::new());
        let chain = Arc::new(Mutex::new(chain));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/", post(rpc))
            .with_state(chain.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { chain, url, server }
    }

    pub(crate) fn url(&self) -> String {
        self.url.clone()
    }

    fn with<T>(&self, f: impl FnOnce(&mut Chain) -> T) -> T {
        f(&mut self.chain.lock().unwrap())
    }

    /// Mine one block with these vault calls; returns its number.
    pub(crate) fn mine(&self, txs: Vec<Tx>) -> u64 {
        self.with(|chain| chain.mine(txs))
    }

    /// Mine `count` empty blocks; returns the new head.
    pub(crate) fn mine_empty(&self, count: u64) -> u64 {
        self.with(|chain| {
            for _ in 0..count {
                chain.mine(Vec::new());
            }
            chain.head()
        })
    }

    /// Replace the last `depth` blocks with `replacement` (one entry per new
    /// block). Replaced hashes are no longer known to the node.
    pub(crate) fn reorg(&self, depth: u64, replacement: Vec<Vec<Tx>>) {
        self.with(|chain| {
            let keep = chain.head() - depth;
            for block in chain.blocks.split_off(keep as usize + 1) {
                chain.hashes.remove(&block.hash);
            }
            chain.fork += 1;
            for txs in replacement {
                chain.mine(txs);
            }
        });
    }

    pub(crate) fn head(&self) -> u64 {
        self.with(|chain| chain.head())
    }

    pub(crate) fn hash_at(&self, number: u64) -> String {
        self.with(|chain| chain.blocks[number as usize].hash.clone())
    }

    /// The vault's note statuses and escapes after block `number`, as a
    /// mirror built from complete logs.
    pub(crate) fn state_at(&self, number: u64) -> Arc<TreeMirror> {
        self.with(|chain| {
            Arc::new(
                chain.blocks[number as usize]
                    .state
                    .as_ref()
                    .map_or_else(TreeMirror::new, |state| state.mirror.clone()),
            )
        })
    }

    fn tree_at(&self, number: u64) -> Frontier {
        self.with(|chain| {
            chain.blocks[number as usize]
                .state
                .as_ref()
                .map_or_else(Frontier::new, |state| state.tree.clone())
        })
    }

    /// The vault's `currentRoot()` after block `number` (computed from its
    /// frontier, as revision 4 does).
    pub(crate) fn root_at(&self, number: u64) -> Felt252 {
        self.tree_at(number).root()
    }

    pub(crate) fn next_note_id_at(&self, number: u64) -> u32 {
        self.tree_at(number).next_index()
    }

    /// The vault's `noteLeaves(0, nextNoteId())` after block `number`.
    pub(crate) fn leaves_at(&self, number: u64) -> Vec<Felt252> {
        let tree = self.tree_at(number);
        (0..tree.next_index())
            .map(|index| tree.leaf(index))
            .collect()
    }

    pub(crate) fn is_canonical(&self, hash: &str) -> bool {
        self.with(|chain| chain.hashes.contains_key(hash))
    }

    /// `eth_getLogs` answers as if the node were `lag` blocks behind.
    pub(crate) fn set_logs_lag(&self, lag: u64) {
        self.with(|chain| chain.faults.logs_lag = lag);
    }

    /// Persistently omit log `index` of `block` from `eth_getLogs`.
    pub(crate) fn drop_log(&self, block: u64, index: usize) {
        self.with(|chain| chain.faults.dropped.insert((block, index)));
    }

    pub(crate) fn restore_logs(&self) {
        self.with(|chain| chain.faults.dropped.clear());
    }

    /// `eth_call` older than `head - window` fails with "missing trie node".
    pub(crate) fn set_state_window(&self, window: Option<u64>) {
        self.with(|chain| chain.faults.state_window = window);
    }

    /// Reject EIP-1898 block-hash parameters with -32602.
    pub(crate) fn reject_block_hash(&self, reject: bool) {
        self.with(|chain| chain.faults.reject_block_hash = reject);
    }

    pub(crate) fn set_chain_id(&self, chain_id: u64) {
        self.with(|chain| chain.chain_id = chain_id);
    }

    /// Answer `eth_getBlockByNumber("latest")` with this block instead of
    /// the head (a frozen or lagging node).
    pub(crate) fn set_latest(&self, latest: Option<u64>) {
        self.with(|chain| chain.faults.latest = latest);
    }

    /// Answer `eth_getBlockByNumber(number)` with a block hash from a stale
    /// fork that no other method knows (`None` restores the canonical one).
    pub(crate) fn set_stale_header(&self, number: u64, hash: Option<String>) {
        self.with(|chain| match hash {
            Some(hash) => chain.faults.stale_headers.insert(number, hash),
            None => chain.faults.stale_headers.remove(&number),
        });
    }

    /// The vault's CONCESSION_ESCAPE_VERSION() (`None`: the getter reverts).
    pub(crate) fn set_escape_version(&self, version: Option<u64>) {
        self.with(|chain| chain.faults.escape_version = version);
    }

    /// The vault's LEAF_BOUND_EXIT_VERSION() (`None`: the getter reverts,
    /// as on a revision-3 vault).
    pub(crate) fn set_leaf_bound_version(&self, version: Option<u64>) {
        self.with(|chain| chain.faults.leaf_bound_version = version);
    }

    /// Answer `noteLeaves` from block `at`'s state, ignoring the block hash
    /// asked for (`None` restores pinned answers).
    pub(crate) fn serve_leaf_pages_at(&self, at: Option<u64>) {
        self.with(|chain| chain.faults.leaf_pages_at = at);
    }

    /// Timestamp for blocks mined from now on (`None`: wall clock).
    pub(crate) fn set_timestamp(&self, timestamp: Option<u64>) {
        self.with(|chain| chain.timestamp = timestamp);
    }

    /// Fail the next `count` calls of `method` with HTTP 503.
    pub(crate) fn fail_next(&self, method: &str, count: u32) {
        self.with(|chain| chain.faults.fail.insert(method.to_string(), count));
    }

    /// Answer the next `count` calls of `method` with HTTP 429 and
    /// `Retry-After: 1`.
    pub(crate) fn rate_limit_next(&self, method: &str, count: u32) {
        self.with(|chain| chain.faults.rate_limit.insert(method.to_string(), count));
    }

    /// Params of every recorded call of `method`, oldest first.
    pub(crate) fn calls(&self, method: &str) -> Vec<Value> {
        self.with(|chain| {
            chain
                .calls
                .iter()
                .filter(|(name, _)| name == method)
                .map(|(_, params)| params.clone())
                .collect()
        })
    }

    pub(crate) fn clear_calls(&self) {
        self.with(|chain| chain.calls.clear());
    }
}

async fn rpc(State(chain): State<Arc<Mutex<Chain>>>, Json(body): Json<Value>) -> Response {
    let method = body["method"].as_str().unwrap_or_default().to_string();
    let params = body["params"].clone();
    let id = body["id"].clone();
    let mut chain = chain.lock().unwrap();
    chain.calls.push((method.clone(), params.clone()));
    if let Some(remaining) = chain.faults.fail.get_mut(&method).filter(|n| **n > 0) {
        *remaining -= 1;
        return (StatusCode::SERVICE_UNAVAILABLE, "upstream unavailable").into_response();
    }
    if let Some(remaining) = chain.faults.rate_limit.get_mut(&method).filter(|n| **n > 0) {
        *remaining -= 1;
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, "1")],
            "rate limited",
        )
            .into_response();
    }
    let result = match method.as_str() {
        "eth_chainId" => Ok(json!(hex(chain.chain_id))),
        "eth_blockNumber" => Ok(json!(hex(chain.head()))),
        "eth_getBlockByNumber" => match params[0].as_str() {
            Some("latest") => Ok(chain.block_json(chain.faults.latest.unwrap_or(chain.head()))),
            _ => parse_hex(&params[0]).map(|number| {
                let mut block = chain.block_json(number);
                if let Some(hash) = chain.faults.stale_headers.get(&number) {
                    block["hash"] = json!(hash);
                }
                block
            }),
        },
        "eth_getBlockByHash" => {
            let hash = params[0].as_str().unwrap_or_default().to_ascii_lowercase();
            Ok(chain
                .hashes
                .get(&hash)
                .map_or(Value::Null, |number| chain.block_json(*number)))
        }
        "eth_getLogs" => chain.get_logs(&params[0]),
        "eth_call" => chain.call(&params),
        _ => Err((-32601, format!("method {method} not found"))),
    };
    let body = match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err((code, message)) => {
            json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
        }
    };
    Json(body).into_response()
}

fn block_hash(fork: u64, number: u64) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(fork.to_be_bytes());
    hasher.update(number.to_be_bytes());
    format!("0x{}", hex::encode(hasher.finalize()))
}

fn hex(value: u64) -> String {
    format!("0x{value:x}")
}

fn parse_hex(value: &Value) -> Result<u64, (i64, String)> {
    value
        .as_str()
        .and_then(|raw| u64::from_str_radix(raw.trim_start_matches("0x"), 16).ok())
        .ok_or((-32602, format!("invalid block number {value}")))
}

fn felt_hex(value: Felt252) -> String {
    hex::encode(value.0)
}

fn felt_word(value: Felt252) -> String {
    format!("0x{}", felt_hex(value))
}

fn strip(word: &str) -> String {
    word.trim_start_matches("0x").to_string()
}

fn words(parts: &[String]) -> String {
    format!("0x{}", parts.concat())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
