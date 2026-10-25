//! End-to-end tests of the companion's exits against an in-process operator
//! (protocol server and indexer) and a simulated vault behind JSON-RPC: the
//! escape routes, the mutual close's decision, E0's bounds on a hanging
//! operator, the stale-device pre-check, exits without any path (vault
//! revision 4), E5 after a raise and E6.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::{Path as AxumPath, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{json, Value};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{CompactSigner, WithdrawalVerifier};
use zkapi_types::{Felt252, WithdrawalPublicInputsV2C, MERKLE_DEPTH};

use super::*;
use crate::service::{AuthService, ConfirmDepositRequest, WithdrawalMode};

const SETUP_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/setup/v2-concession-dev"
);
const VAULT: [u8; 20] = [0x5a; 20];
const NOTE_ID: u32 = 3;
const DEPOSIT: u128 = 1_500_000;
const DESTINATION: &str = "0x2222222222222222222222222222222222222222";

/// The simulated vault and operator.
#[derive(Default)]
struct World {
    // Operator.
    nullifiers: HashMap<String, Value>,
    requests: HashMap<String, Value>,
    evidence: HashMap<String, Value>,
    clearance: Option<(u16, Value)>,
    clearance_calls: usize,
    hang: bool,
    operator_calls: usize,
    /// `/v2/requests/{id}` answers 404 to this many calls first.
    requests_unknown_for: usize,
    request_calls: usize,
    // Indexer.
    indexer_root: Felt252,
    indexer_leaves: Vec<Felt252>,
    indexer_hang: bool,
    // RPCs: the pinned one (`/rpc`) and the owner's exit RPC (`/exit-rpc`).
    pinned_down: bool,
    /// The pinned RPC reports the note Active with no pending exit, its
    /// nullifiers challenged, and a finalized block far in the future.
    pinned_lies: bool,
    /// Calls the pinned RPC answered.
    pinned_calls: usize,
    /// The exit RPC refuses every call.
    exit_down: bool,
    /// The exit RPC is on this chain instead of the vault's (chain 1).
    exit_chain: Option<u64>,
    /// The finalized block trails the latest by this many blocks.
    finalized_lag: u64,
    /// Every RPC fails `eth_getLogs` (a node that dropped or rate-limits
    /// log queries).
    logs_down: bool,
    // Chain.
    /// The leaf the vault stored for the note (`noteRecord`).
    note_leaf: Felt252,
    /// `currentRoot()`.
    vault_root: Felt252,
    /// The vault's leaves by note id (`noteLeaves`, `nextNoteId()`).
    leaves: Vec<Felt252>,
    /// `nextNoteId()` and `noteLeaves` fail (a node that caps `eth_call`).
    state_reads_down: bool,
    /// `LEAF_BOUND_EXIT_VERSION()`; `None`: it reverts (vault revision 3).
    leaf_bound_version: Option<u64>,
    /// `minDeposit()`.
    min_deposit: u128,
    /// The block parameter of every `eth_call` answered.
    call_blocks: Vec<Value>,
    note_status: u8,
    pending: Option<chain::PendingEscape>,
    challenged: HashSet<Felt252>,
    logs: Vec<Value>,
    receipts: HashMap<String, Value>,
    block: u64,
    now: u64,
}

type Shared = Arc<Mutex<World>>;

fn word(value: impl Into<u128>) -> String {
    format!("{:064x}", value.into())
}

fn felt_word(value: &Felt252) -> String {
    hex::encode(value.0)
}

fn rpc_result(result: Value) -> Response {
    Json(json!({"jsonrpc": "2.0", "id": 1, "result": result})).into_response()
}

/// The pinned RPC: down, lying, or the chain as it is.
async fn pinned_rpc(State(world): State<Shared>, Json(body): Json<Value>) -> Response {
    let (down, lies) = {
        let mut world = world.lock().unwrap();
        world.pinned_calls += 1;
        (world.pinned_down, world.pinned_lies)
    };
    if down {
        return (StatusCode::SERVICE_UNAVAILABLE, "down").into_response();
    }
    answer(&world, &body, lies)
}

/// The owner's exit RPC: the chain as it is, or down.
async fn exit_rpc(State(world): State<Shared>, Json(body): Json<Value>) -> Response {
    if world.lock().unwrap().exit_down {
        return (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response();
    }
    if let Some(chain) = world.lock().unwrap().exit_chain {
        if body["method"] == "eth_chainId" {
            return rpc_result(json!(format!("0x{chain:x}")));
        }
    }
    answer(&world, &body, false)
}

fn answer(world: &Shared, body: &Value, lies: bool) -> Response {
    let mut world = world.lock().unwrap();
    let params = &body["params"];
    match body["method"].as_str().unwrap_or("") {
        "eth_chainId" => rpc_result(json!("0x1")),
        "eth_getBlockByNumber" => {
            let tag = params[0].as_str().unwrap_or("latest");
            let (number, timestamp) = match tag {
                "finalized" if lies => (world.block, world.now + 10_000_000),
                "finalized" => (world.block.saturating_sub(world.finalized_lag), world.now),
                _ => (world.block, world.now),
            };
            rpc_result(json!({
                "number": format!("0x{number:x}"),
                "timestamp": format!("0x{timestamp:x}"),
                "hash": format!("0x{}", "33".repeat(32)),
            }))
        }
        "eth_getTransactionReceipt" => rpc_result(
            world
                .receipts
                .get(params[0].as_str().unwrap_or(""))
                .cloned()
                .unwrap_or(Value::Null),
        ),
        "eth_getLogs" if world.logs_down => Json(json!({
            "jsonrpc": "2.0", "id": 1,
            "error": {"code": -32000, "message": "header not found"},
        }))
        .into_response(),
        "eth_getLogs" => {
            let filter = &params[0];
            let topic0: Vec<String> = match &filter["topics"][0] {
                Value::String(topic) => vec![topic.to_lowercase()],
                Value::Array(topics) => topics
                    .iter()
                    .filter_map(|topic| topic.as_str().map(str::to_lowercase))
                    .collect(),
                _ => Vec::new(),
            };
            let topic1 = filter["topics"][1].as_str().map(str::to_lowercase);
            let from = chain::quantity(&filter["fromBlock"]).unwrap_or(0);
            let to = chain::quantity(&filter["toBlock"]).unwrap_or(u64::MAX);
            let logs: Vec<Value> = world
                .logs
                .iter()
                .filter(|log| {
                    let block = chain::quantity(&log["blockNumber"]).unwrap();
                    let topics = log["topics"].as_array().unwrap();
                    block >= from
                        && block <= to
                        && (topic0.is_empty()
                            || topic0.contains(&topics[0].as_str().unwrap().to_lowercase()))
                        && topic1.as_ref().is_none_or(|expected| {
                            topics
                                .get(1)
                                .and_then(Value::as_str)
                                .is_some_and(|topic| topic.eq_ignore_ascii_case(expected))
                        })
                })
                .cloned()
                .collect();
            rpc_result(json!(logs))
        }
        "eth_call" => {
            let data = params[0]["data"].as_str().unwrap_or("");
            let selector = &data[2..10];
            let argument = &data[10..];
            world.call_blocks.push(params[1].clone());
            let result = match selector {
                chain::NOTE_RECORD => format!(
                    "0x{}{}",
                    felt_word(&world.note_leaf),
                    word(if lies { 1 } else { world.note_status })
                ),
                chain::LEAF_BOUND_EXIT_VERSION => match world.leaf_bound_version {
                    Some(version) => format!("0x{}", word(version)),
                    None => {
                        return Json(json!({"jsonrpc": "2.0", "id": 1,
                            "error": {"code": 3, "message": "execution reverted", "data": "0x"}}))
                        .into_response()
                    }
                },
                chain::CURRENT_ROOT => format!("0x{}", felt_word(&world.vault_root)),
                chain::MIN_DEPOSIT => format!("0x{}", word(world.min_deposit)),
                zkapi_client::tree::NEXT_NOTE_ID_SELECTOR
                | zkapi_client::tree::NOTE_LEAVES_SELECTOR
                    if world.state_reads_down =>
                {
                    return Json(json!({"jsonrpc": "2.0", "id": 1,
                        "error": {"code": -32000, "message": "gas limit exceeded"}}))
                    .into_response()
                }
                zkapi_client::tree::NEXT_NOTE_ID_SELECTOR => {
                    format!("0x{}", word(world.leaves.len() as u64))
                }
                zkapi_client::tree::NOTE_LEAVES_SELECTOR => {
                    let start = usize::from_str_radix(&argument[..64], 16).unwrap();
                    let count = usize::from_str_radix(&argument[64..128], 16).unwrap();
                    let leaves: String = world.leaves[start..start + count]
                        .iter()
                        .map(felt_word)
                        .collect();
                    format!("0x{}{}{leaves}", word(32u8), word(count as u64))
                }
                chain::PENDING_WITHDRAWALS if lies => format!("0x{}", "0".repeat(64 * 6)),
                chain::PENDING_WITHDRAWALS => match world.pending {
                    Some(pending) => format!(
                        "0x{}{}{}{}{}{}{}",
                        word(1u8),
                        word(0u8),
                        felt_word(&pending.nullifier),
                        word(pending.final_balance),
                        "0".repeat(24),
                        hex::encode(pending.destination),
                        word(pending.deadline)
                    ),
                    None => format!("0x{}", "0".repeat(64 * 6)),
                },
                chain::PENDING_CONCESSIONS => match world.pending {
                    Some(pending) => format!(
                        "0x{}{}{}",
                        felt_word(&pending.next_nullifier),
                        word(pending.state_balance),
                        word(pending.conceded)
                    ),
                    None => format!("0x{}", "0".repeat(64 * 3)),
                },
                chain::CHALLENGED_NULLIFIERS if lies => format!("0x{}", word(1u8)),
                chain::CHALLENGED_NULLIFIERS => {
                    let nullifier = Felt252::from_hex(&format!("0x{argument}")).unwrap();
                    format!(
                        "0x{}",
                        word(u8::from(world.challenged.contains(&nullifier)))
                    )
                }
                chain::EFFECTIVE_EXPIRY => format!("0x{}", word(4_000_000_000u64)),
                _ => return (StatusCode::BAD_REQUEST, "unknown selector").into_response(),
            };
            rpc_result(json!(result))
        }
        _ => (StatusCode::BAD_REQUEST, "unknown method").into_response(),
    }
}

/// How long a hanging operator holds each call: far beyond any bound E0 sets,
/// and far beyond any proving time, so a test that bounds an exit by half of
/// it fails only when the exit waited on the operator.
const OPERATOR_HANG: Duration = Duration::from_secs(3_600);

async fn indexer_pause(world: &Shared) {
    let hang = world.lock().unwrap().indexer_hang;
    if hang {
        tokio::time::sleep(OPERATOR_HANG).await;
    }
}

async fn operator_pause(world: &Shared) -> bool {
    let hang = {
        let mut world = world.lock().unwrap();
        world.operator_calls += 1;
        world.hang
    };
    if hang {
        tokio::time::sleep(OPERATOR_HANG).await;
    }
    hang
}

async fn nullifier_route(
    State(world): State<Shared>,
    AxumPath(nullifier): AxumPath<String>,
) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    Json(
        world
            .nullifiers
            .get(&nullifier)
            .cloned()
            .unwrap_or(json!({"status": "not_found", "nullifier_status": "unknown"})),
    )
    .into_response()
}

async fn evidence_route(
    State(world): State<Shared>,
    AxumPath(nullifier): AxumPath<String>,
) -> Response {
    operator_pause(&world).await;
    let world = world.lock().unwrap();
    match world.evidence.get(&nullifier) {
        Some(body) => Json(body.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn request_route(State(world): State<Shared>, AxumPath(id): AxumPath<String>) -> Response {
    operator_pause(&world).await;
    let mut world = world.lock().unwrap();
    world.request_calls += 1;
    if world.request_calls <= world.requests_unknown_for {
        return StatusCode::NOT_FOUND.into_response();
    }
    match world.requests.get(&id) {
        Some(body) => Json(body.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn clearance_route(State(world): State<Shared>) -> Response {
    operator_pause(&world).await;
    let mut world = world.lock().unwrap();
    world.clearance_calls += 1;
    match &world.clearance {
        Some((status, body)) => {
            (StatusCode::from_u16(*status).unwrap(), Json(body.clone())).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(
                json!({"status": "error", "client_request_id": "", "error_code": "maintenance",
                "error_message": "down", "retriable": true}),
            ),
        )
            .into_response(),
    }
}

struct Harness {
    _directory: tempfile::TempDir,
    config: AuthConfig,
    service: Arc<AuthService>,
    world: Shared,
    server: tokio::task::JoinHandle<()>,
    secret: Felt252,
    leaf: Felt252,
    deposit_root: Felt252,
    deposit_siblings: Vec<Felt252>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Harness {
    /// A note deposited next to two others. Its exits need nothing from the
    /// deposit but the note itself (vault revision 4).
    async fn new() -> Self {
        Self::build_expiring(4_000_000_000).await
    }

    /// The harness with the note's expiry at `expiry`.
    async fn build_expiring(expiry: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let world: Shared = Arc::new(Mutex::new(World {
            note_status: 1,
            leaf_bound_version: Some(1),
            min_deposit: 1_000_000,
            block: 100,
            now: now_seconds(),
            ..Default::default()
        }));
        let router = Router::new()
            .route("/rpc", post(pinned_rpc))
            .route("/exit-rpc", post(exit_rpc))
            .route("/v2/nullifiers/{nullifier}", get(nullifier_route))
            .route("/v2/nullifiers/{nullifier}/evidence", get(evidence_route))
            .route("/v2/requests/{id}", get(request_route))
            .route("/v2/withdraw/clearance", post(clearance_route))
            .route(
                "/v1/tree/snapshot",
                get(|State(world): State<Shared>| async move {
                    indexer_pause(&world).await;
                    let world = world.lock().unwrap();
                    Json(json!({
                        "root": world.indexer_root,
                        "next_note_id": world.indexer_leaves.len(),
                        "leaves": world.indexer_leaves,
                        "block_number": world.block,
                        "block_hash": format!("0x{}", "33".repeat(32)),
                    }))
                }),
            )
            .with_state(world.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            contract_address: zkapi_types::serialization::address_to_felt(&VAULT),
            protocol_server_url: url.clone(),
            indexer_url: url.clone(),
            demo_rpc_url: Some(format!("{url}/rpc")),
            proof_setup_dir: SETUP_DIR.into(),
            state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
            clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
            deploy_block: 1,
            ..Default::default()
        };
        // Notes 1 and 2 were deposited first; the tree is append-only.
        let secret = Felt252::from_u64(4242);
        let leaf = core::note_leaf(
            NOTE_ID,
            &core::registration_commitment(&secret),
            DEPOSIT,
            expiry,
        );
        let mut tree = zkapi_client::tree::SparseTree::new();
        let mut logs = Vec::new();
        for (index, (note, owner)) in [(1u32, 7u64), (2, 8), (NOTE_ID, 0)].into_iter().enumerate() {
            let commitment = if note == NOTE_ID {
                core::registration_commitment(&secret)
            } else {
                core::registration_commitment(&Felt252::from_u64(owner))
            };
            tree.set_leaf(note, core::note_leaf(note, &commitment, DEPOSIT, expiry));
            logs.push(json!({
                "address": format!("0x{}", hex::encode(VAULT)),
                "blockNumber": format!("0x{:x}", 10 + index),
                "logIndex": "0x0",
                "removed": false,
                "topics": [zkapi_client::tree::NOTE_DEPOSITED_TOPIC, format!("0x{}", word(note)),
                    format!("0x{}", felt_word(&commitment))],
                "data": format!("0x{}{}", word(DEPOSIT), word(expiry)),
            }));
        }
        let deposit_root = tree.root();
        let deposit_siblings = tree.siblings(NOTE_ID).to_vec();
        {
            let mut world = world.lock().unwrap();
            world.logs = logs;
            world.note_leaf = leaf;
            world.vault_root = deposit_root;
            world.leaves = (0..=NOTE_ID).map(|note| tree.leaf(note)).collect();
            world.indexer_root = deposit_root;
            world.indexer_leaves = (0..=NOTE_ID).map(|id| tree.leaf(id)).collect();
        }
        let service = AuthService::new(config.clone()).unwrap();
        service
            .confirm_deposit(ConfirmDepositRequest {
                secret,
                note_id: NOTE_ID,
                amount: DEPOSIT,
                expiry_ts: expiry,
            })
            .await
            .unwrap();
        Self {
            _directory: directory,
            config,
            service,
            world,
            server,
            secret,
            leaf,
            deposit_root,
            deposit_siblings,
        }
    }

    fn wallet(&self) -> zkapi_client::wallet::Wallet {
        super::super::load_wallet(&self.config).unwrap()
    }

    /// The same wallet behind a service whose owner configured an exit RPC.
    fn with_exit_rpc(mut self) -> Self {
        self.config.exit_rpc_url = Some(format!("{}/exit-rpc", self.config.protocol_server_url));
        self.service = AuthService::new(self.config.clone()).unwrap();
        self
    }

    /// A clearance the operator grants for the current state.
    fn grant_clearance(&self) {
        let nullifier = self.nullifier();
        let message = core::clearance_message(2, 1, &self.config.contract_address, &nullifier);
        let signature = CompactSigner::from_seed(&Felt252::from_u64(12)).sign(&message);
        self.world.lock().unwrap().clearance = Some((
            200,
            json!({"status": "ok", "withdrawal_nullifier": nullifier, "signature": signature}),
        ));
    }

    /// A real request proof at the current state, made by a copy of the
    /// wallet in `copy` (another device), and that copy.
    fn request_from_a_copy(
        &self,
        copy: &std::path::Path,
    ) -> (
        zkapi_client::wallet::Wallet,
        zkapi_types::wire::ApiRequestV2,
    ) {
        std::fs::copy(
            self.config.state_dir.join("note_state.json"),
            copy.join("note_state.json"),
        )
        .unwrap();
        let mut config = self.config.clone();
        config.state_dir = copy.to_path_buf();
        let mut other = super::super::load_wallet(&config).unwrap();
        let request = other
            .prepare_request_with_bound(
                "{}",
                zkapi_types::canonical_payload_hash(b"{}"),
                self.deposit_root,
                self.deposit_siblings.clone(),
                1_000,
            )
            .unwrap();
        (other, request)
    }

    /// The operator's signed successor for `request` charging `charge`.
    fn successor(
        &self,
        request: &zkapi_types::wire::ApiRequestV2,
        charge: u128,
    ) -> zkapi_types::wire::RequestResponseV2 {
        let signer = CompactSigner::from_seed(&Felt252::from_u64(11));
        let anonymous = zkapi_types::wire::CurvePointWire {
            x: request.public_inputs.anonymous_commitment_x,
            y: request.public_inputs.anonymous_commitment_y,
        };
        let delta = zkapi_proof::compact::random_scalar();
        let next = zkapi_proof::compact::server_update(&anonymous, charge, &delta).unwrap();
        let anchor = core::next_anchor(&request.public_inputs.request_nullifier);
        let body = "{}".to_string();
        zkapi_types::wire::RequestResponseV2 {
            status: "ok".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(body.as_bytes()),
            response_payload: body,
            charge_applied: charge,
            next_commitment: next.clone(),
            next_anchor: anchor,
            blind_delta_srv: delta,
            next_state_signature: signer.sign(&core::state_message(
                2,
                1,
                &self.config.contract_address,
                &next.x,
                &next.y,
                &anchor,
            )),
            policy_reason_code: None,
            policy_evidence_hash: None,
        }
    }

    fn nullifier(&self) -> Felt252 {
        self.wallet().current_nullifier().unwrap()
    }

    /// A request at the current state with `bound`, sent `age` seconds ago;
    /// its journal stays pending.
    fn release_request(&self, bound: u128, age: u64) {
        let path = self.config.state_dir.join("note_state.json");
        let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
        state.bound_at_state = bound;
        state.save(&path).unwrap();
        zkapi_client::journal::PendingRequestJournal::write(
            &self.config.state_dir.join("pending_journal.json"),
            &zkapi_client::journal::PendingRequestJournal {
                exists: true,
                client_request_id: "withheld".into(),
                nullifier: self.nullifier(),
                payload_hash: Felt252::ONE,
                user_rerandomization: Felt252::ONE,
                created_at_ms: now_seconds().saturating_sub(age) * 1_000,
                prepared_request: None,
            },
        )
        .unwrap();
    }

    fn set_reading(&self, status: &str) {
        let nullifier = self.nullifier();
        self.world.lock().unwrap().nullifiers.insert(
            nullifier.to_string(),
            json!({"status": "ok", "nullifier_status": status}),
        );
    }

    async fn prepare(
        &self,
        conceded: Option<&str>,
        early: Option<EarlyExit>,
    ) -> Result<Value, AuthError> {
        self.service
            .oa_escape_prepare(EscapePrepareRequest {
                destination: DESTINATION.into(),
                conceded: conceded.map(str::to_string),
                early_exit: early,
            })
            .await
    }

    /// What the vault does with `plan`'s calldata: verify it like the
    /// adapter, then record the pending escape.
    fn initiate(&self, plan: &Value) {
        let inputs: WithdrawalPublicInputsV2C =
            serde_json::from_value(plan["public_inputs"].clone()).unwrap();
        let proof: zkapi_types::wire::Groth16ProofWire =
            serde_json::from_value(plan["proof"].clone()).unwrap();
        let calldata = plan["calldata"].as_str().unwrap();
        assert_eq!(calldata.len(), 2 + 836 * 2);
        assert_eq!(
            calldata,
            chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &inputs, &proof).unwrap()
        );
        assert_eq!(inputs.kind, 0);
        assert!(inputs.valid_until >= now_seconds());
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&inputs, &proof)
            .unwrap());
        let mut world = self.world.lock().unwrap();
        // The vault compares the proof's leaf and fields with its record.
        assert_eq!(inputs.note_leaf, world.note_leaf);
        assert_eq!((inputs.note_id, inputs.deposit_amount), (NOTE_ID, DEPOSIT));
        assert_eq!(
            &calldata[2 + 8 + 3 * 64..2 + 8 + 4 * 64],
            felt_word(&world.note_leaf)
        );
        world.note_status = 2;
        world.pending = Some(chain::PendingEscape {
            nullifier: inputs.withdrawal_nullifier,
            final_balance: inputs.final_balance,
            destination: inputs.destination,
            deadline: now_seconds() - 1,
            next_nullifier: inputs.next_nullifier,
            state_balance: inputs.final_balance + inputs.conceded,
            conceded: inputs.conceded,
        });
        world.block += 1;
    }

    /// `raiseEscapeConcession` to `conceded`.
    fn raise(&self, conceded: u128) {
        let mut world = self.world.lock().unwrap();
        let mut pending = world.pending.unwrap();
        pending.conceded = conceded;
        pending.final_balance = pending.state_balance - conceded;
        world.pending = Some(pending);
        world.block += 1;
        let block = world.block;
        world.logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": "0x0",
            "removed": false,
            "topics": [chain::escape_concession_raised_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}{}{}", felt_word(&pending.nullifier), word(conceded), word(pending.final_balance)),
        }));
    }

    /// `challengeEscapeWithdrawal`: the escape at `nullifier` defeated in a
    /// new block, the note Active again.
    fn defeat(&self, nullifier: Felt252) {
        let mut world = self.world.lock().unwrap();
        world.pending = None;
        world.note_status = 1;
        world.challenged.insert(nullifier);
        world.block += 1;
        let block = world.block;
        world.logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": "0x0",
            "removed": false,
            "transactionHash": format!("0x{}", "cd".repeat(32)),
            "topics": [chain::escape_challenged_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}", felt_word(&nullifier)),
        }));
    }

    /// `finalizeEscapeWithdrawal`, paying or (`credited`) crediting.
    fn finalize(&self, credited: bool) -> String {
        let mut world = self.world.lock().unwrap();
        let pending = world.pending.take().unwrap();
        world.note_status = 3;
        world.block += 1;
        let hash = format!("0x{}", "ab".repeat(32));
        let destination = format!("{}{}", "0".repeat(24), hex::encode(pending.destination));
        let mut logs = Vec::new();
        if credited {
            logs.push(json!({
                "address": format!("0x{}", hex::encode(VAULT)), "removed": false,
                "topics": [chain::escape_payout_deferred_topic(), format!("0x{}", word(NOTE_ID)), format!("0x{destination}")],
                "data": format!("0x{}", word(pending.final_balance)),
            }));
        }
        logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)), "removed": false,
            "topics": [chain::escape_finalized_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}{}{}", felt_word(&pending.nullifier), word(pending.final_balance), destination),
        }));
        let block = world.block;
        world.receipts.insert(
            hash.clone(),
            json!({"status": "0x1", "transactionHash": hash, "blockNumber": format!("0x{block:x}"),
                "blockHash": format!("0x{}", "33".repeat(32)), "logs": logs}),
        );
        hash
    }
}

/// E2 step 5 then E4 and E5: the operator refuses the clearance, the mutual
/// close turns into an escape conceding nothing, the owner confirms it, the
/// escape is proved with no path and no indexer (bound to the note's leaf),
/// initiated,
/// raised by the challenger, finalized; the payout matcher follows the raise
/// and the note closes, which releases the exit lock.
#[tokio::test]
async fn a_refused_clearance_escapes_and_a_raised_escape_finalizes() {
    let harness = Harness::new().await;
    let refused = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await;
    let detail = match &refused {
        Err(AuthError::EscapeRequired(detail)) => detail.clone(),
        other => panic!("{other:?}"),
    };
    assert_eq!(detail["reason"], "mutual_refused");
    assert_eq!(detail["conceded"], "0");
    // From now on the indexer serves a root the vault never held: the
    // escape reads no path, so no indexer answer matters.
    harness.world.lock().unwrap().indexer_root = Felt252::from_u64(99);
    // The owner sees the decision before any escape proof exists.
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["status"], "decision");
    assert_eq!(decision["conceded"], "0");
    assert_eq!(decision["payout"], DEPOSIT.to_string());
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert!(lock.released.iter().all(|proof| proof.kind == 2));
    // A concession the rules do not allow is refused.
    assert!(matches!(
        harness.prepare(Some("5"), None).await,
        Err(AuthError::ConcededMismatch(_))
    ));
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert!(plan.get("path_source").is_none());
    assert_eq!(plan["public_inputs"]["note_leaf"], json!(harness.leaf));
    assert!(plan["public_inputs"].get("active_root").is_none());
    // Asking again hands out the same plan, not a second proof.
    let again = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(again["proof"], plan["proof"]);
    assert_eq!(
        harness
            .wallet()
            .exit_lock()
            .unwrap()
            .unwrap()
            .released
            .iter()
            .filter(|proof| proof.kind == 0)
            .count(),
        1
    );
    // No request proof while the escape is under way (C3).
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::ExitLocked)
    ));
    let submitted = harness
        .service
        .oa_escape_submit(format!("0x{}", "cd".repeat(32)))
        .await
        .unwrap();
    assert_eq!(submitted["phase"], "submitted");
    harness.initiate(&plan);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "pending");
    assert_eq!(status["payout"], DEPOSIT.to_string());
    // The challenger raises the concession; the status follows it.
    harness.raise(300);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["payout"], (DEPOSIT - 300).to_string());
    assert_eq!(status["finalizable"], true);
    let hash = harness.finalize(false);
    let done = harness
        .service
        .oa_escape_finalize(hash.clone())
        .await
        .unwrap();
    assert_eq!(done["status"], "complete");
    assert_eq!(done["payout"], (DEPOSIT - 300).to_string());
    assert_eq!(done["conceded_final"], "300");
    // Nothing was released at this state, so any raise exceeds its bound.
    assert_eq!(done["concession_exceeded_bound"], true);
    assert!(harness.wallet().state().is_none());
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    // The reservation the refused mutual close made is complete too.
    assert_eq!(
        harness.service.oa_withdrawal_status().await.unwrap()["phase"],
        "complete"
    );
    // Idempotent.
    harness.service.oa_escape_finalize(hash).await.unwrap();
}

/// E5: a finalized payout that matches neither B − c nor any raise is
/// refused, and nothing is closed; a credited payout is reported.
#[tokio::test]
async fn the_payout_matcher_refuses_unexplained_amounts_and_reports_credits() {
    let harness = Harness::new().await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("unknown");
    let decision = harness.prepare(None, None).await.unwrap();
    // The request is old and the server knows nothing of it: fresh state,
    // an escape the owner asked for concedes nothing.
    assert_eq!(decision["conceded"], "0", "{decision}");
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    // Paid less than B with no raise on record.
    {
        let mut world = harness.world.lock().unwrap();
        let mut pending = world.pending.unwrap();
        pending.final_balance -= 1;
        world.pending = Some(pending);
    }
    let hash = harness.finalize(true);
    let refused = harness.service.oa_escape_finalize(hash.clone()).await;
    assert!(
        matches!(refused, Err(AuthError::InvalidInput(_))),
        "{refused:?}"
    );
    assert!(harness.wallet().state().is_some());
    // The amount the raise explains is accepted, credited or not.
    let harness = Harness::new().await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("unknown");
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    harness.raise(800);
    let hash = harness.finalize(true);
    let done = harness.service.oa_escape_finalize(hash).await.unwrap();
    assert_eq!(done["payout_credited"], true);
    assert_eq!(done["concession_exceeded_bound"], false);
    assert!(done["claim_calldata"]
        .as_str()
        .unwrap()
        .starts_with("0x88c10aee"));
}

/// E3: a request withheld at the state makes the escape wait until T; the
/// owner may exit early conceding nothing or the bound; at T the escape
/// concedes the bound. The mutual close waits too.
#[tokio::test]
async fn a_withheld_request_waits_for_t_then_concedes_the_bound() {
    let harness = Harness::new().await;
    harness.release_request(1_000, 60);
    harness.set_reading("reserved");
    assert!(matches!(
        harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await,
        Err(AuthError::PendingSettlement)
    ));
    let waiting = harness.prepare(None, None).await.unwrap();
    assert_eq!(waiting["status"], "wait");
    let until = waiting["wait_until"].as_u64().unwrap();
    assert!(until > now_seconds() + 21_000 && until <= now_seconds() + 21_905 + 900);
    let early = harness
        .prepare(None, Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(
        (early["status"].as_str(), early["conceded"].as_str()),
        (Some("decision"), Some("0"))
    );
    let early = harness
        .prepare(None, Some(EarlyExit::ConcedeBound))
        .await
        .unwrap();
    assert_eq!(early["conceded"], "1000");
    // A request sent long ago is past T: the bound is conceded.
    let harness = Harness::new().await;
    harness.release_request(1_000, 100_000);
    harness.set_reading("reserved");
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(
        (decision["conceded"].as_str(), decision["reason"].as_str()),
        (Some("1000"), Some("at_deadline"))
    );
    let plan = harness.prepare(Some("1000"), None).await.unwrap();
    assert_eq!(plan["payout"], (DEPOSIT - 1_000).to_string());
    assert_eq!(plan["public_inputs"]["conceded"], 1_000);
}

/// E0: an operator that hangs cannot hold the exit decision: every call is
/// bounded and counted as unreachable, and past must_initiate_by no
/// operator call is made at all.
#[tokio::test]
async fn a_hanging_operator_cannot_delay_the_exit() {
    let harness = Harness::new().await;
    harness.release_request(1_000, 60);
    harness.world.lock().unwrap().hang = true;
    // The decision makes no proof: a bounded recovery pass and reading.
    let started = Instant::now();
    let decision = tokio::time::timeout(
        Duration::from_secs(25),
        harness.prepare(None, Some(EarlyExit::ConcedeNothing)),
    )
    .await
    .unwrap_or_else(|_| panic!("a hanging operator held the decision"))
    .unwrap();
    assert_eq!(decision["conceded"], "0");
    // The plan adds the escape proof, which takes what it takes (minutes in
    // an unoptimized build on a loaded machine), and the bounded pre-check
    // and E1 reruns: far below half a hanging call (30 minutes), which only
    // waiting on the operator could reach.
    let plan = tokio::time::timeout(
        OPERATOR_HANG / 2,
        harness.prepare(Some("0"), Some(EarlyExit::ConcedeNothing)),
    )
    .await
    .unwrap_or_else(|_| {
        panic!(
            "a hanging operator held the escape: {:?}",
            started.elapsed()
        )
    })
    .unwrap();
    assert_eq!(plan["status"], "prepared");

    // Past must_initiate_by: nothing is asked of the operator, neither by
    // E1 (a request is pending, so a pass would ask for its response), nor
    // by the reading, nor by the stale-device pre-check before proving.
    let harness = Harness::build_expiring(now_seconds() + 1_000).await;
    harness.release_request(1_000, 60);
    harness.world.lock().unwrap().hang = true;
    let calls = harness.world.lock().unwrap().operator_calls;
    let decision = harness.prepare(None, None).await.unwrap();
    // T is capped by must_initiate_by, which has passed: the bound.
    assert_eq!(decision["reason"], "at_deadline", "{decision}");
    assert_eq!(decision["conceded"], "1000");
    let plan = harness.prepare(Some("1000"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert_eq!(harness.world.lock().unwrap().operator_calls, calls);
    // Without the pending request the decision is E2's cutoff, also with no
    // operator call.
    let harness = Harness::new().await;
    let path = harness.config.state_dir.join("note_state.json");
    let mut state = zkapi_client::note_state::NoteState::load(&path).unwrap();
    state.expiry_ts = now_seconds() + 1_000;
    state.save(&path).unwrap();
    harness.world.lock().unwrap().hang = true;
    let calls = harness.world.lock().unwrap().operator_calls;
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["reason"], "mutual_cutoff");
    assert_eq!(harness.world.lock().unwrap().operator_calls, calls);
}

/// E4 step 2: a request proof at N+ that verifies under the request key means
/// another device spent this state; an answer that does not verify is
/// ignored.
#[tokio::test]
async fn the_stale_device_pre_check_refuses_only_on_verified_evidence() {
    let harness = Harness::new().await;
    // A real request proof from the successor state, made by "another
    // device": a copy of the wallet that spent this state.
    let copy = tempfile::tempdir().unwrap();
    std::fs::copy(
        harness.config.state_dir.join("note_state.json"),
        copy.path().join("note_state.json"),
    )
    .unwrap();
    let mut other_config = harness.config.clone();
    other_config.state_dir = copy.path().to_path_buf();
    let mut other = super::super::load_wallet(&other_config).unwrap();
    let request = other
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let signer = CompactSigner::from_seed(&Felt252::from_u64(11));
    let anonymous = zkapi_types::wire::CurvePointWire {
        x: request.public_inputs.anonymous_commitment_x,
        y: request.public_inputs.anonymous_commitment_y,
    };
    let delta = zkapi_proof::compact::random_scalar();
    let next = zkapi_proof::compact::server_update(&anonymous, 10, &delta).unwrap();
    let anchor = core::next_anchor(&request.public_inputs.request_nullifier);
    let body = "{}".to_string();
    other
        .complete_pending_response(&zkapi_types::wire::RequestResponseV2 {
            status: "ok".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            response_code: 200,
            response_hash: zkapi_types::canonical_response_hash(body.as_bytes()),
            response_payload: body,
            charge_applied: 10,
            next_commitment: next.clone(),
            next_anchor: anchor,
            blind_delta_srv: delta,
            next_state_signature: signer.sign(&core::state_message(
                2,
                1,
                &harness.config.contract_address,
                &next.x,
                &next.y,
                &anchor,
            )),
            policy_reason_code: None,
            policy_evidence_hash: None,
        })
        .unwrap();
    let spent = other
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let successor = harness.wallet().current_successor_nullifier().unwrap();
    assert_eq!(spent.public_inputs.request_nullifier, successor);
    // A forged answer (a proof that does not verify) is ignored.
    let mut forged = serde_json::to_value(&spent).unwrap();
    forged["public_inputs"]["request_time"] = json!(1);
    harness.world.lock().unwrap().evidence.insert(
        successor.to_string(),
        json!({"public_inputs": forged["public_inputs"], "proof": forged["proof"]}),
    );
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    // Verified evidence refuses a new escape (here: after the first expired).
    let harness = Harness::new().await;
    harness.world.lock().unwrap().evidence.insert(
        successor.to_string(),
        json!({"public_inputs": spent.public_inputs, "proof": spent.proof}),
    );
    let refused = harness.prepare(Some("0"), None).await;
    assert!(
        matches!(refused, Err(AuthError::DeviceNotNewest)),
        "{refused:?}"
    );
    // Nothing was released, so no lock is left behind.
    assert!(harness.wallet().exit_lock().unwrap().is_none());
}

/// Vault revision 4: an escape needs no Merkle path, root, indexer or log
/// scan. With the indexer down and every RPC refusing `eth_getLogs`, the
/// escape is still proved, bound to the note's leaf and fields, and its
/// calldata carries the leaf in word 3 and the packed fields in word 8.
#[tokio::test]
async fn an_escape_needs_no_path_indexer_or_logs() {
    let harness = Harness::new().await;
    {
        let mut world = harness.world.lock().unwrap();
        world.indexer_hang = true;
        world.logs_down = true;
        world.indexer_root = Felt252::from_u64(6);
    }
    let started = Instant::now();
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert!(started.elapsed() < OPERATOR_HANG / 2);
    let inputs: WithdrawalPublicInputsV2C =
        serde_json::from_value(plan["public_inputs"].clone()).unwrap();
    assert_eq!(inputs.note_leaf, harness.leaf);
    assert_eq!(
        (inputs.note_id, inputs.deposit_amount, inputs.expiry_ts),
        (NOTE_ID, DEPOSIT, 4_000_000_000)
    );
    let calldata = plan["calldata"].as_str().unwrap();
    let word_at = |index: usize| &calldata[10 + index * 64..10 + (index + 1) * 64];
    assert_eq!(word_at(3), felt_word(&harness.leaf));
    assert_eq!(
        word_at(8),
        felt_word(&zkapi_types::pack_note_fields(
            NOTE_ID,
            DEPOSIT,
            4_000_000_000
        ))
    );
    harness.initiate(&plan);
    assert_eq!(harness.leaf, harness.wallet().current_note_leaf().unwrap());
    let _ = harness.secret;
}

/// E6: an escape that never landed keeps the lock until its proof is dead at
/// a finalized block; then the lock is released and chats may resume.
#[tokio::test]
async fn an_escape_that_never_landed_releases_the_lock_once_dead() {
    let harness = Harness::new().await;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let valid_until = plan["valid_until"].as_u64().unwrap();
    let status = harness.service.oa_escape_status().await.unwrap();
    assert!(status["exit_lock"].is_object());
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::ExitLocked)
    ));
    harness.world.lock().unwrap().now = valid_until + 901;
    // The chain's finalized block is past the proof's life, but this
    // device's clock is not: the proof could still land, so nothing is
    // released (whoever answered the reading).
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_ne!(status["phase"], "expired", "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_some());
    let status = harness
        .service
        .escape_status_at(Some(valid_until + 901))
        .await
        .unwrap();
    assert_eq!(status["phase"], "expired");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    harness.wallet().check_request_allowed().unwrap();
    // A defeat (another device spent the successor) is reported as such,
    // only from the defeat's log in a finalized block: the flag alone, or a
    // log in a block not yet final, reports nothing.
    let harness = Harness::new().await;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let nullifier: Felt252 = serde_json::from_value(plan["withdrawal_nullifier"].clone()).unwrap();
    harness.world.lock().unwrap().challenged.insert(nullifier);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_ne!(status["phase"], "defeated", "{status}");
    harness.defeat(nullifier);
    harness.world.lock().unwrap().finalized_lag = 1;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_ne!(status["phase"], "defeated", "{status}");
    harness.world.lock().unwrap().finalized_lag = 0;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "defeated");
    assert_eq!(status["error"], "device_not_newest");
    assert_eq!(
        status["defeat_transaction"],
        format!("0x{}", "cd".repeat(32))
    );
    // Read through the pinned RPC: shown, but marked untrusted.
    assert_eq!(
        (status["chain_rpc"].as_str(), status["trusted"].as_bool()),
        (Some("pinned"), Some(false))
    );
}

/// E6 without an exit RPC (the finding of review round 8): the pinned RPC,
/// which the operator may run, reports a finalized block far past a
/// released escape's life, the note Active and every nullifier challenged.
/// It neither releases the lock (this device's clock says the proof can
/// still land) nor installs the successor that arrived late, nor reports a
/// defeat: chats stay stopped until the proof is dead on this clock too.
#[tokio::test]
async fn a_lying_pinned_rpc_neither_releases_a_live_lock_nor_reports_a_defeat() {
    let harness = Harness::new().await;
    // A real request at the current state, journaled in the wallet itself.
    let request = harness
        .wallet()
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let plan = harness
        .prepare(Some("0"), Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(plan["status"], "prepared", "{plan}");
    let valid_until = plan["valid_until"].as_u64().unwrap();
    // The operator's successor arrives after the escape proof left.
    let late = harness.successor(&request, 40);
    let mut wallet = harness.wallet();
    assert!(matches!(
        wallet.complete_pending_response(&late),
        Err(zkapi_client::error::ClientError::LateSuccessor)
    ));
    let balance = wallet.state().unwrap().current_balance;
    harness.world.lock().unwrap().pinned_lies = true;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(
        (status["chain_rpc"].as_str(), status["trusted"].as_bool()),
        (Some("pinned"), Some(false))
    );
    assert_ne!(status["phase"], "defeated", "{status}");
    assert_ne!(status["phase"], "expired", "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_some());
    assert_eq!(harness.wallet().state().unwrap().current_balance, balance);
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::ExitLocked)
    ));
    // Once this device's clock passes valid_until + 900 too, the proof is
    // dead: the lock is released and the late successor installs.
    let status = harness
        .service
        .escape_status_at(Some(valid_until + 901))
        .await
        .unwrap();
    assert_eq!(status["phase"], "expired", "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    assert_eq!(
        harness.wallet().state().unwrap().current_balance,
        balance - 40
    );
}

/// E6 with failing defeat logs: once the escape proof is dead on this
/// device's clock too, a reading whose `eth_getLogs` fails (here through the
/// owner's exit RPC) still releases the lock, but settles nothing about the
/// escape. It is reported `unknown` and untrusted, never `expired`, and a
/// saved defeat or expiry is kept as it is. Once the logs load, they decide.
#[tokio::test]
async fn failing_defeat_logs_settle_nothing_once_the_proof_is_dead() {
    let phase = |harness: &Harness| load_record(&harness.config).unwrap().unwrap().phase;
    let trust = |status: &Value| {
        (
            status["trusted"].as_bool(),
            status["defeat_checked"].as_bool(),
        )
    };
    let unread = |status: &Value| {
        assert_eq!(status["phase"], "unknown", "{status}");
        assert_eq!(
            (
                status["trusted"].as_bool(),
                status["defeat_checked"].as_bool(),
                status["defeat_logs"].as_str()
            ),
            (Some(false), Some(false), Some("unavailable")),
            "{status}"
        );
    };
    // A defeat saved by an earlier reading is never overwritten.
    let harness = Harness::new().await.with_exit_rpc();
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let dead = plan["valid_until"].as_u64().unwrap() + 901;
    let nullifier: Felt252 = serde_json::from_value(plan["withdrawal_nullifier"].clone()).unwrap();
    harness.defeat(nullifier);
    harness.world.lock().unwrap().now = dead;
    let status = harness.service.escape_status_at(Some(dead)).await.unwrap();
    assert_eq!(status["phase"], "defeated", "{status}");
    assert_eq!(trust(&status), (Some(true), Some(true)), "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    assert_eq!(phase(&harness), "defeated");
    harness.world.lock().unwrap().logs_down = true;
    unread(&harness.service.escape_status_at(Some(dead)).await.unwrap());
    assert_eq!(phase(&harness), "defeated");
    harness.world.lock().unwrap().logs_down = false;
    let status = harness.service.escape_status_at(Some(dead)).await.unwrap();
    assert_eq!(status["phase"], "defeated", "{status}");

    // An escape that never landed: the dead lock is released as before, but
    // the escape is reported expired only from logs that loaded.
    let harness = Harness::new().await.with_exit_rpc();
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    let dead = plan["valid_until"].as_u64().unwrap() + 901;
    {
        let mut world = harness.world.lock().unwrap();
        world.now = dead;
        world.logs_down = true;
    }
    let status = harness.service.escape_status_at(Some(dead)).await.unwrap();
    unread(&status);
    assert!(status["exit_lock"].is_null(), "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    harness.wallet().check_request_allowed().unwrap();
    assert_eq!(phase(&harness), "prepared");
    harness.world.lock().unwrap().logs_down = false;
    let status = harness.service.escape_status_at(Some(dead)).await.unwrap();
    assert_eq!(status["phase"], "expired", "{status}");
    assert_eq!(trust(&status), (Some(true), Some(true)), "{status}");
    assert_eq!(phase(&harness), "expired");
    // A saved expiry is not repeated from a reading without the logs.
    harness.world.lock().unwrap().logs_down = true;
    unread(&harness.service.escape_status_at(Some(dead)).await.unwrap());
    assert_eq!(phase(&harness), "expired");
}

/// C1: two services on one state directory (the bridge and, say, the exit
/// kit in one process) share the wallet's lock: an exit decision and a
/// request preparation never interleave, and neither fails with
/// wallet_busy. Either the request was durable before the decision (which
/// then sees it and waits), or the decision ran first and saw no request;
/// a decision that released nothing leaves no exit lock, so the request
/// then proceeds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_exit_decision_and_a_request_preparation_never_interleave() {
    for round in 0..4 {
        let harness = Harness::new().await;
        harness.set_reading("reserved");
        let second = AuthService::new(harness.config.clone()).unwrap();
        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let (exit_barrier, request_barrier) = (barrier.clone(), barrier.clone());
        let service = harness.service.clone();
        let exit = tokio::spawn(async move {
            exit_barrier.wait().await;
            service
                .oa_escape_prepare(EscapePrepareRequest {
                    destination: DESTINATION.into(),
                    conceded: None,
                    early_exit: None,
                })
                .await
        });
        let config = harness.config.clone();
        let request = tokio::spawn(async move {
            request_barrier.wait().await;
            if round % 2 == 1 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
            second.request_through_lock(&config).await
        });
        let (exit, request) = (exit.await.unwrap(), request.await.unwrap());
        let decision = exit.expect("the decision never fails with wallet_busy");
        request.unwrap_or_else(|error| panic!("round {round}: {error:?}"));
        // "wait": the request came first and the decision saw it (E3);
        // "decision": the decision came first and saw a fresh state.
        assert!(
            matches!(decision["status"].as_str(), Some("wait" | "decision")),
            "round {round}: {decision}"
        );
        let wallet = harness.wallet();
        assert!(wallet.exit_lock().unwrap().is_none(), "round {round}");
        assert!(wallet.has_pending_request(), "round {round}");
    }
}

impl AuthService {
    /// A request preparation through the wallet lock, as the lease path
    /// makes one (a real proof, the bound and the journal).
    async fn request_through_lock(&self, config: &AuthConfig) -> Result<(), AuthError> {
        let config = config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let paths = self.paths.clone();
        super::super::spawn_blocking(move || {
            let _guard = wallet_mutex.lock().unwrap();
            let _lockfile = super::super::acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = super::super::load_wallet(&config)?;
            let runtime = super::super::current_thread_runtime()?;
            let state = wallet.state().unwrap().clone();
            let leaf = wallet.current_note_leaf().unwrap();
            let (root, siblings) =
                runtime.block_on(async { paths.path(state.note_id, &leaf).await })?;
            wallet
                .prepare_request_with_bound(
                    "{}",
                    zkapi_types::canonical_payload_hash(b"{}"),
                    root,
                    siblings,
                    1_000,
                )
                .map(|_| ())
                .map_err(Into::into)
        })
        .await
    }
}

/// E6 "no kind-0 or kind-1 proof was released and the user cancels", and
/// the SDK's rule that a decision leaves no lock behind: previewing the
/// escape's terms, an E3 wait on either route, or a refusal before any proof
/// leaves the note usable for requests. A lock that released only an
/// ownership proof is cancelled by the cancel route (C5 still keeps that
/// state request-free); one that released an escape is not.
#[tokio::test]
async fn a_decision_leaves_no_lock_and_the_cancel_route_releases_an_unused_one() {
    let harness = Harness::new().await;
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["status"], "decision");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    harness.wallet().check_request_allowed().unwrap();

    // E3 waits, on the escape route and on the mutual route.
    let harness = Harness::new().await;
    harness.release_request(1_000, 60);
    harness.set_reading("reserved");
    assert_eq!(harness.prepare(None, None).await.unwrap()["status"], "wait");
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    assert!(matches!(
        harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await,
        Err(AuthError::PendingSettlement)
    ));
    assert!(harness.wallet().exit_lock().unwrap().is_none());

    // A refused clearance released an ownership proof: the lock stays (in
    // escape mode) until the owner cancels it.
    let harness = Harness::new().await;
    assert!(matches!(
        harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await,
        Err(AuthError::EscapeRequired(_))
    ));
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert_eq!(
        lock.released
            .iter()
            .map(|proof| proof.kind)
            .collect::<Vec<_>>(),
        [2]
    );
    let cancelled = harness.service.oa_escape_cancel().await.unwrap();
    assert_eq!(cancelled["status"], "cancelled");
    assert_eq!(cancelled["ownership_proof_sent"], true);
    assert!(harness.wallet().exit_lock().unwrap().is_none());
    assert!(matches!(
        harness.wallet().check_request_allowed(),
        Err(zkapi_client::error::ClientError::OwnershipProofSent)
    ));
    // Cancelling with no lock is a no-op.
    harness.service.oa_escape_cancel().await.unwrap();

    // A released escape keeps its lock.
    let harness = Harness::new().await;
    harness.prepare(Some("0"), None).await.unwrap();
    assert!(matches!(
        harness.service.oa_escape_cancel().await,
        Err(AuthError::ExitLockConflict(_))
    ));
    assert!(harness.wallet().exit_lock().unwrap().is_some());
}

/// L6: a close expires (valid_until = now + 10,800). A reservation's close
/// is handed out again only while it stays valid; one nearer its end is
/// proved again from the kept clearance signature, at the same root and
/// path, with no ownership proof or clearance request. A reservation saved
/// before the signature was kept asks for the clearance again, resending
/// the still-live ownership proof.
#[tokio::test]
async fn an_expiring_close_is_proved_again_and_never_handed_out_stale() {
    let harness = Harness::new().await;
    harness.grant_clearance();
    let first = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    assert!(first.public_inputs.valid_until >= now_seconds() + 10_000);
    assert_eq!(harness.world.lock().unwrap().clearance_calls, 1);
    // Still live: the same close.
    let again = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    assert_eq!(again.proof, first.proof);
    let path = harness.config.state_dir.join("oa-withdrawal.json");
    let age = |valid_until: u64, drop_signature: bool| {
        let mut saved: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        saved["plan"]["public_inputs"]["valid_until"] = json!(valid_until);
        if drop_signature {
            saved.as_object_mut().unwrap().remove("clearance_signature");
        }
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
    };
    for valid_until in [now_seconds() - 60, now_seconds() + 1_000] {
        age(valid_until, false);
        let fresh = harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await
            .unwrap();
        assert!(fresh.public_inputs.valid_until >= now_seconds() + 10_000);
        assert_ne!(fresh.proof, first.proof);
        assert_eq!(
            (
                fresh.public_inputs.withdrawal_nullifier,
                fresh.public_inputs.final_balance,
                fresh.public_inputs.note_leaf,
                fresh.public_inputs.kind,
            ),
            (
                first.public_inputs.withdrawal_nullifier,
                first.public_inputs.final_balance,
                first.public_inputs.note_leaf,
                1,
            )
        );
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&fresh.public_inputs, &fresh.proof)
            .unwrap());
    }
    assert_eq!(harness.world.lock().unwrap().clearance_calls, 1);
    // Saved by an earlier build: no signature kept, so the clearance is
    // asked again (the server signs a reserved nullifier again).
    age(now_seconds() - 60, true);
    let renewed = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    assert!(renewed.public_inputs.valid_until >= now_seconds() + 10_000);
    assert_eq!(harness.world.lock().unwrap().clearance_calls, 2);
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert_eq!(
        lock.released.iter().filter(|proof| proof.kind == 2).count(),
        1
    );
    assert_eq!(
        lock.released.iter().filter(|proof| proof.kind == 1).count(),
        4
    );
    // E6 released the lock once every close was dead: the next close takes
    // it again before it is proved.
    std::fs::remove_file(harness.config.state_dir.join("exit_lock.json")).unwrap();
    age(now_seconds() - 60, false);
    let relocked = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    assert!(relocked.public_inputs.valid_until >= now_seconds() + 10_000);
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert_eq!(
        (lock.mode, lock.released.len()),
        (zkapi_client::exit_lock::ExitMode::Mutual, 1)
    );
}

/// E0 before the escape decision: a live key is retired first, and a
/// retirement that hangs (here a chat in flight holds the request lock)
/// delays the decision by one `RECOVERY_BUDGET`, never longer.
#[tokio::test]
async fn a_live_key_whose_retirement_hangs_delays_the_escape_by_one_budget() {
    let harness = Harness::new().await;
    *harness.service.direct_lease.lock().await = Some(super::super::ActiveOpenRouterLease {
        session_id: "oa-single-use".into(),
        client_request_id: "live".into(),
        api_key: "fixture-key".into(),
        openrouter_api_base: "https://openrouter.ai/api/v1".into(),
        expires_at: now_seconds() + 300,
        settle_after: now_seconds() + 360,
        verification: None,
        verified: true,
        verification_detail: None,
        requests_served: 0,
    });
    let _chat = harness.service.direct_request_mutex.read().await;
    let started = Instant::now();
    let decision = tokio::time::timeout(
        RECOVERY_BUDGET + Duration::from_secs(30),
        harness.prepare(None, None),
    )
    .await
    .expect("the escape decision waited on the hanging retirement")
    .unwrap();
    assert_eq!(decision["status"], "decision", "{decision}");
    assert!(started.elapsed() >= RECOVERY_BUDGET);
    // A decision leaves no key behind.
    assert!(harness.service.direct_lease.lock().await.is_none());
}

/// A reservation that keeps its close and the clearance signature for an
/// earlier state of the note (its closes dead, E6 released the lock, a late
/// successor installed: a dishonest operator's O4 then E6) neither hands
/// that close out again nor proves it again: through the route itself, it
/// gives way to the current state's own mutual close, and is archived.
#[tokio::test]
async fn a_close_kept_for_an_earlier_state_gives_way_to_the_current_states_close() {
    let harness = Harness::new().await;
    // A request from this state made elsewhere, whose successor arrives late.
    let copy = tempfile::tempdir().unwrap();
    let (mut other, request) = harness.request_from_a_copy(copy.path());
    harness.grant_clearance();
    let first = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    let reservation = harness.config.state_dir.join("oa-withdrawal.json");
    let mut saved: Value = serde_json::from_slice(&std::fs::read(&reservation).unwrap()).unwrap();
    assert!(!saved["clearance_signature"].is_null());
    // Every close is dead, E6 released the lock, and the successor installs.
    saved["plan"]["public_inputs"]["valid_until"] = json!(now_seconds() - 5_000);
    std::fs::write(&reservation, serde_json::to_vec(&saved).unwrap()).unwrap();
    std::fs::remove_file(harness.config.state_dir.join("exit_lock.json")).unwrap();
    other
        .complete_pending_response(&harness.successor(&request, 40))
        .unwrap();
    std::fs::copy(
        copy.path().join("note_state.json"),
        harness.config.state_dir.join("note_state.json"),
    )
    .unwrap();
    let moved = harness.nullifier();
    assert_ne!(moved, first.public_inputs.withdrawal_nullifier);
    harness.grant_clearance();
    for _ in 0..2 {
        let close = harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await
            .unwrap();
        assert_eq!(
            (
                close.public_inputs.withdrawal_nullifier,
                close.public_inputs.final_balance,
                close.public_inputs.kind,
            ),
            (moved, DEPOSIT - 40, 1)
        );
        assert!(close.public_inputs.valid_until >= now_seconds() + 10_000);
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&close.public_inputs, &close.proof)
            .unwrap());
    }
    // One clearance per state; the earlier reservation is archived.
    assert_eq!(harness.world.lock().unwrap().clearance_calls, 2);
    let reserved = crate::oa_withdrawal::load(&harness.config)
        .unwrap()
        .unwrap();
    assert_eq!(reserved.nullifier, moved);
    let archived = harness.config.state_dir.join("archive").join(format!(
        "oa-withdrawal-{NOTE_ID}-{}-superseded.json",
        first.public_inputs.withdrawal_nullifier.to_hex()
    ));
    assert!(archived.exists(), "{}", archived.display());
}

/// §1.2(6), §6.7: with the owner's exit RPC configured, a pinned RPC that is
/// down blocks nothing: the escape is planned, followed and finalized
/// through the exit RPC. A pinned RPC that lies (the note Active, a
/// finalized block past the proof's life) cannot release the lock while the
/// escape is pending: the exit RPC alone decides E6.
#[tokio::test]
async fn escapes_follow_the_exit_rpc_when_the_pinned_rpc_is_down_or_lies() {
    let harness = Harness::new().await.with_exit_rpc();
    harness.world.lock().unwrap().pinned_down = true;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    harness.initiate(&plan);
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "pending", "{status}");
    assert_eq!(status["chain_rpc"], "exit");
    harness.raise(250);
    let hash = harness.finalize(false);
    let done = harness.service.oa_escape_finalize(hash).await.unwrap();
    assert_eq!(done["status"], "complete");
    assert_eq!(done["payout"], (DEPOSIT - 250).to_string());

    let harness = Harness::new().await.with_exit_rpc();
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    harness.world.lock().unwrap().pinned_lies = true;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "pending", "{status}");
    assert!(harness.wallet().exit_lock().unwrap().is_some());
    // The exit RPC rate-limited or unreachable too: the pinned RPC is not
    // asked in its place (here it would report the escape defeated, which
    // the caller records for good), and nothing is decided.
    for unreachable in [false, true] {
        let service = if unreachable {
            let mut config = harness.config.clone();
            config.exit_rpc_url = Some("http://127.0.0.1:9/unreachable".into());
            AuthService::new(config).unwrap()
        } else {
            harness.world.lock().unwrap().exit_down = true;
            harness.service.clone()
        };
        harness.world.lock().unwrap().pinned_calls = 0;
        let status = service.oa_escape_status().await.unwrap();
        assert_eq!(status["chain"], "unavailable", "{status}");
        assert_ne!(status["phase"], "defeated");
        assert!(status.get("chain_rpc").is_none());
        assert_eq!(harness.world.lock().unwrap().pinned_calls, 0);
        assert!(harness.wallet().exit_lock().unwrap().is_some());
    }
}

/// WP-D's chain check, in the companion: an exit RPC the owner configured
/// for another network (here chain 5, where the same vault address could
/// hold a Closed note) is never read for the escape's state or its lock
/// (E6), and the pinned RPC is not asked in its place. Pointed back at the
/// vault's chain, it decides again. The escape itself reads no root or path
/// (vault revision 4), so it is proved meanwhile.
#[tokio::test]
async fn an_exit_rpc_on_another_chain_decides_nothing() {
    let harness = Harness::new().await.with_exit_rpc();
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    {
        let mut world = harness.world.lock().unwrap();
        world.exit_chain = Some(5);
        world.pinned_calls = 0;
    }
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["chain"], "unavailable", "{status}");
    assert!(status.get("chain_rpc").is_none());
    assert_eq!(harness.world.lock().unwrap().pinned_calls, 0);
    assert!(harness.wallet().exit_lock().unwrap().is_some());
    harness.world.lock().unwrap().exit_chain = None;
    let status = harness.service.oa_escape_status().await.unwrap();
    assert_eq!(status["phase"], "pending", "{status}");
    assert_eq!(status["chain_rpc"], "exit");

    let harness = Harness::new().await.with_exit_rpc();
    harness.world.lock().unwrap().exit_chain = Some(5);
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    // Without a start block from the exit RPC, raises are scanned from the
    // deployment block.
    let record: Value = serde_json::from_slice(
        &std::fs::read(harness.config.state_dir.join(ESCAPE_RECORD_FILE)).unwrap(),
    )
    .unwrap();
    assert_eq!(record["start_block"], harness.config.deploy_block);
}

/// E4 with the owner's exit RPC down: the escape reads no root, path or log
/// (vault revision 4), so it is proved anyway, and the pinned RPC decides
/// nothing about it in the exit RPC's place.
#[tokio::test]
async fn with_its_exit_rpc_down_an_escape_is_still_proved() {
    let harness = Harness::new().await.with_exit_rpc();
    harness.world.lock().unwrap().exit_down = true;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert_eq!(plan["public_inputs"]["note_leaf"], json!(harness.leaf));
    // E_low needs both RPCs: with the exit RPC down it is the note's expiry.
    assert_eq!(
        plan["must_initiate_by"],
        exit_policy::must_initiate_by(4_000_000_000)
    );
}

/// E0: the indexer is the operator's, and since vault revision 4 no exit
/// reads it. One that accepts a connection and never answers holds neither
/// exit route: the mutual close (refused by the unreachable operator here)
/// and the escape decision complete without it. A request preparation waits
/// for it at most one `CALL_TIMEOUT`, then takes its path from the vault's
/// own tree.
#[tokio::test]
async fn a_hanging_indexer_holds_no_exit_route_and_delays_a_request_once() {
    let harness = Arc::new(Harness::new().await);
    harness.world.lock().unwrap().indexer_hang = true;
    let started = Instant::now();
    let decision = tokio::time::timeout(Duration::from_secs(15), harness.prepare(None, None))
        .await
        .expect("a hanging indexer held the escape decision")
        .unwrap();
    assert_eq!(decision["status"], "decision");
    let mutual = tokio::time::timeout(
        Duration::from_secs(15),
        harness.service.oa_prepare_withdrawal([0x22; 20], false),
    )
    .await
    .expect("a hanging indexer held the mutual close");
    assert!(
        matches!(mutual, Err(AuthError::EscapeRequired(_))),
        "{mutual:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(15));

    let harness = Harness::new().await;
    harness.world.lock().unwrap().indexer_hang = true;
    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(15),
        harness.service.request_through_lock(&harness.config),
    )
    .await
    .expect("a hanging indexer held a request preparation")
    .unwrap();
    assert!(started.elapsed() >= crate::indexer::CALL_TIMEOUT);
    let request = harness.wallet().pending_api_request().unwrap().unwrap();
    assert_eq!(request.public_inputs.active_root, harness.deposit_root);
}

/// E4 step 2 binds the evidence to N+: the operator legitimately holds the
/// owner's own request proof at N (this state's request), which verifies
/// under the request key. Served as "evidence at N+", it must not refuse the
/// escape, or an operator could refuse every escape this way.
#[tokio::test]
async fn evidence_at_another_nullifier_does_not_stop_the_escape() {
    let harness = Harness::new().await;
    let copy = tempfile::tempdir().unwrap();
    let (_, own) = harness.request_from_a_copy(copy.path());
    assert_eq!(own.public_inputs.request_nullifier, harness.nullifier());
    let successor = harness.wallet().current_successor_nullifier().unwrap();
    harness.world.lock().unwrap().evidence.insert(
        successor.to_string(),
        json!({"public_inputs": own.public_inputs, "proof": own.proof}),
    );
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
}

/// Request paths (vault revision 4): the indexer's path is used only at a
/// root the vault's `currentRoot()` reports at the indexer's block; one
/// consistent with itself at a root the vault never held is not. The path
/// then comes from the vault's state, every read pinned to one block hash,
/// or from its logs when the state reads fail, at the vault's root.
#[tokio::test]
async fn request_paths_need_the_vaults_root_and_rebuild_from_its_state() {
    use crate::request_path::PathSource;
    let harness = Harness::new().await;
    let paths = &harness.service.paths;
    let (root, siblings, source) = paths
        .path_with_source(NOTE_ID, &harness.leaf)
        .await
        .unwrap();
    assert_eq!(source, PathSource::Indexer);
    assert_eq!(
        (root, siblings),
        (harness.deposit_root, harness.deposit_siblings.clone())
    );
    // The vault's root was read at the indexer's block hash.
    assert!(harness
        .world
        .lock()
        .unwrap()
        .call_blocks
        .iter()
        .any(|block| { block["blockHash"] == format!("0x{}", "33".repeat(32)) }));
    {
        let mut world = harness.world.lock().unwrap();
        // A tree with one more note than the vault ever recorded.
        world.indexer_leaves.push(Felt252::from_u64(31));
        let mut tree = zkapi_core::merkle::MerkleTree::new();
        for (id, leaf) in world.indexer_leaves.iter().enumerate() {
            tree.set_leaf(id as u32, *leaf);
        }
        world.indexer_root = tree.root();
        assert_ne!(world.indexer_root, world.vault_root);
        world.call_blocks.clear();
    }
    let (root, siblings, source) = paths
        .path_with_source(NOTE_ID, &harness.leaf)
        .await
        .unwrap();
    assert_eq!(source, PathSource::Rebuild);
    assert_eq!(
        (root, siblings),
        (harness.deposit_root, harness.deposit_siblings.clone())
    );
    {
        // nextNoteId(), the noteLeaves page and currentRoot(), all pinned to
        // the one block hash of `latest`.
        let world = harness.world.lock().unwrap();
        let pinned: Vec<&Value> = world
            .call_blocks
            .iter()
            .filter(|block| block.is_object())
            .collect();
        assert!(pinned.len() >= 3, "{pinned:?}");
        assert!(pinned.iter().all(|block| *block == pinned[0]));
        assert_eq!(pinned[0]["requireCanonical"], true);
    }
    // The state reads fail: the logs at the same block, at the vault's root.
    harness.world.lock().unwrap().state_reads_down = true;
    let (root, _, source) = paths
        .path_with_source(NOTE_ID, &harness.leaf)
        .await
        .unwrap();
    assert_eq!((root, source), (harness.deposit_root, PathSource::Rebuild));
    // A note whose leaf the vault does not hold gets no path at all.
    let refused = paths
        .path(NOTE_ID, &Felt252::from_u64(77))
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("does not hold note 3's leaf"),
        "{refused}"
    );
    // Nor does a vault whose root the rebuilt tree does not reproduce.
    harness.world.lock().unwrap().vault_root = Felt252::from_u64(8);
    assert!(paths.path(NOTE_ID, &harness.leaf).await.is_err());
}

/// The deployment check before the first request proof: a vault without
/// `LEAF_BOUND_EXIT_VERSION()` (revision 3, the call reverts) or with another
/// version is refused, and nothing is proved; a vault revision 4 passes, once.
#[tokio::test]
async fn a_revision_3_vault_is_refused_before_any_request_proof() {
    for version in [None, Some(2)] {
        let harness = Harness::new().await;
        harness.world.lock().unwrap().leaf_bound_version = version;
        let refused = harness
            .service
            .request_through_lock(&harness.config)
            .await
            .unwrap_err();
        assert!(
            matches!(&refused, AuthError::InvalidInput(message) if message.contains("deployment check failed")),
            "{version:?}: {refused:?}"
        );
        assert!(!harness.wallet().has_pending_request());
        let refused = harness.service.check_vault().await.unwrap_err();
        assert!(
            refused.to_string().contains("LEAF_BOUND_EXIT_VERSION"),
            "{refused}"
        );
    }
    let harness = Harness::new().await;
    harness.service.check_vault().await.unwrap();
    harness
        .service
        .request_through_lock(&harness.config)
        .await
        .unwrap();
    // A deployment that pins another minDeposit() than the vault's is
    // refused, and one that pins the vault's passes. A deposit plan below
    // the minimum is refused (the vault would revert DepositTooSmall).
    for (pinned, passes) in [(Some(5), false), (Some(1_000_000), true), (None, true)] {
        let mut config = harness.config.clone();
        config.min_deposit_units = pinned;
        let service = AuthService::new(config).unwrap();
        let checked = service.check_vault().await;
        assert_eq!(checked.is_ok(), passes, "{pinned:?}: {checked:?}");
        if !passes {
            assert!(checked
                .unwrap_err()
                .to_string()
                .contains("minDeposit() is 1000000"));
        }
    }
    let mut config = harness.config.clone();
    config.min_deposit_units = Some(1_000_000);
    let service = AuthService::new(config).unwrap();
    let refused = service.prepare_deposit(999_999).await.unwrap_err();
    assert!(
        refused.to_string().contains("deposit_too_small"),
        "{refused}"
    );
}

/// The note a deposit confirmation installs must reproduce the leaf the
/// vault stored: with another expiry every exit would revert
/// (`NoteLeafMismatch`), so it is refused. A deposit-time path that callers
/// before vault revision 4 send is read and ignored.
#[tokio::test]
async fn a_deposit_confirmation_must_reproduce_the_stored_leaf() {
    let harness = Harness::new().await;
    let directory = tempfile::tempdir().unwrap();
    let mut config = harness.config.clone();
    config.state_dir = directory.path().to_path_buf();
    let service = AuthService::new(config).unwrap();
    let confirm = |expiry: u64| {
        serde_json::from_value::<ConfirmDepositRequest>(json!({
            "secret": harness.secret, "note_id": NOTE_ID, "amount": DEPOSIT as u64,
            "expiry_ts": expiry,
            "deposit_root": harness.deposit_root, "deposit_siblings": harness.deposit_siblings,
        }))
        .unwrap()
    };
    let refused = service
        .confirm_deposit(confirm(4_000_086_400))
        .await
        .unwrap_err();
    assert!(
        refused.to_string().contains("note_leaf_mismatch"),
        "{refused}"
    );
    assert!(service.status().await.unwrap().note.is_none());
    // An empty record (an RPC that lags the deposit) or one that cannot be
    // read never confirms the note: deposit_pending (503), nothing installed.
    let stored = harness.world.lock().unwrap().note_leaf;
    harness.world.lock().unwrap().note_leaf = Felt252::ZERO;
    let empty = service
        .confirm_deposit(confirm(4_000_000_000))
        .await
        .unwrap_err();
    assert!(matches!(empty, AuthError::DepositPending(_)), "{empty:?}");
    assert_eq!(empty.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(empty.code(), "deposit_pending");
    assert!(service.status().await.unwrap().note.is_none());
    harness.world.lock().unwrap().note_leaf = stored;
    harness.world.lock().unwrap().pinned_down = true;
    let failed = service
        .confirm_deposit(confirm(4_000_000_000))
        .await
        .unwrap_err();
    assert!(matches!(failed, AuthError::DepositPending(_)), "{failed:?}");
    assert!(service.status().await.unwrap().note.is_none());
    harness.world.lock().unwrap().pinned_down = false;
    // Without an RPC the deposit cannot be checked against the vault.
    let mut without = harness.config.clone();
    without.state_dir = directory.path().join("without-rpc");
    without.demo_rpc_url = None;
    let without = AuthService::new(without).unwrap();
    let refused = without
        .confirm_deposit(confirm(4_000_000_000))
        .await
        .unwrap_err();
    assert!(matches!(refused, AuthError::InvalidInput(_)), "{refused:?}");
    assert!(without.status().await.unwrap().note.is_none());
    // The stored leaf confirms it.
    let status = service
        .confirm_deposit(confirm(4_000_000_000))
        .await
        .unwrap();
    assert_eq!(status.note.unwrap().expiry_ts, 4_000_000_000);
}

/// E4 step 3: a successor that becomes installable after the decision and
/// before the proof moves the escape to the new state (nothing was
/// released yet), instead of proving an escape from the old one that the
/// successor's arrival would then defeat.
#[tokio::test]
async fn a_successor_installable_before_proving_moves_the_escape_to_it() {
    let harness = Harness::new().await;
    // A real request at the current state, journaled in the wallet itself.
    let mut wallet = harness.wallet();
    let request = wallet
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            harness.deposit_root,
            harness.deposit_siblings.clone(),
            1_000,
        )
        .unwrap();
    let old_nullifier = harness.nullifier();
    let response = harness.successor(&request, 40);
    {
        let mut world = harness.world.lock().unwrap();
        world.requests.insert(
            request.client_request_id.clone(),
            json!({"status": "finalized", "nullifier_status": "finalized", "request_response": response}),
        );
        // The decision's E1 pass finds nothing; the pass before proving
        // finds the response.
        world.requests_unknown_for = 1;
    }
    let plan = harness
        .prepare(Some("0"), Some(EarlyExit::ConcedeNothing))
        .await
        .unwrap();
    assert_eq!(plan["status"], "prepared", "{plan}");
    let nullifier: Felt252 = serde_json::from_value(plan["withdrawal_nullifier"].clone()).unwrap();
    assert_ne!(nullifier, old_nullifier);
    assert_eq!(Some(nullifier), harness.wallet().current_nullifier());
    assert_eq!(plan["state_balance"], (DEPOSIT - 40).to_string());
}

/// E5: the escape is closed only on a finalize receipt in a finalized block.
#[tokio::test]
async fn finalize_waits_for_a_finalized_block() {
    let harness = Harness::new().await;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    harness.initiate(&plan);
    let hash = harness.finalize(false);
    harness.world.lock().unwrap().finalized_lag = 1;
    assert!(matches!(
        harness.service.oa_escape_finalize(hash.clone()).await,
        Err(AuthError::OaWithdrawalPending)
    ));
    assert!(harness.wallet().state().is_some());
    harness.world.lock().unwrap().finalized_lag = 0;
    let done = harness.service.oa_escape_finalize(hash).await.unwrap();
    assert_eq!(done["status"], "complete");
}

/// E2 step 4 without a record of a release: the server's nullifier_used
/// claim leaves nothing to wait for, so the exit escapes at once conceding
/// the bound (here nothing), on both routes and on every later decision,
/// instead of a wait that moves with each decision.
#[tokio::test]
async fn nullifier_used_with_nothing_released_escapes_at_once() {
    let harness = Harness::new().await;
    harness.world.lock().unwrap().clearance = Some((
        409,
        json!({"status": "error", "client_request_id": "", "error_code": "nullifier_used",
            "error_message": "used", "retriable": false}),
    ));
    let refused = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await;
    let detail = match refused {
        Err(AuthError::EscapeRequired(detail)) => detail,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        (detail["conceded"].as_str(), detail["reason"].as_str()),
        (Some("0"), Some("at_deadline"))
    );
    for _ in 0..2 {
        let decision = harness.prepare(None, None).await.unwrap();
        assert_eq!(decision["status"], "decision", "{decision}");
        assert_eq!(decision["reason"], "at_deadline");
    }
}

/// A clearance outcome belongs to the state it was asked for: a reservation
/// of an earlier state of the note (refused there) does not steer the
/// escape decision of the current state.
#[tokio::test]
async fn a_refusal_recorded_for_an_earlier_state_does_not_steer_this_one() {
    let harness = Harness::new().await;
    let mut earlier = harness.wallet().state().unwrap().clone();
    earlier.current_anchor = Felt252::from_u64(0xe1);
    let mut record = crate::oa_withdrawal::reserve(&harness.config, &earlier, [0x22; 20]).unwrap();
    record.clearance_outcome = Some(zkapi_client::exit_policy::MutualOutcome::RefusedOrUnreachable);
    crate::oa_withdrawal::save(&harness.config, &record).unwrap();
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["reason"], "requested", "{decision}");
    // The same outcome recorded for this state steers it.
    std::fs::remove_file(harness.config.state_dir.join("oa-withdrawal.json")).unwrap();
    let current = harness.wallet().state().unwrap().clone();
    let mut record = crate::oa_withdrawal::reserve(&harness.config, &current, [0x22; 20]).unwrap();
    record.clearance_outcome = Some(zkapi_client::exit_policy::MutualOutcome::RefusedOrUnreachable);
    crate::oa_withdrawal::save(&harness.config, &record).unwrap();
    let decision = harness.prepare(None, None).await.unwrap();
    assert_eq!(decision["reason"], "mutual_refused", "{decision}");
}

#[test]
fn merkle_depth_is_the_vaults() {
    assert_eq!(MERKLE_DEPTH, 32);
    let _ = WithdrawalMode::Escape;
}
