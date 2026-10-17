//! End-to-end tests of the companion's exits against an in-process operator
//! (protocol server and indexer) and a simulated vault behind JSON-RPC: the
//! escape routes, the mutual close's decision, E0's bounds on a hanging
//! operator, the stale-device pre-check, exits with no path (before
//! activation, without the indexer), the note's activation for requests, E5
//! after a raise and E6.

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
use crate::service::{AuthService, ConfirmDepositRequest, WalletStatus, WithdrawalMode};

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
    // Indexer: its view of the tree and of the activation cursor.
    indexer_root: Felt252,
    indexer_path: Vec<Felt252>,
    indexer_leaf: Felt252,
    indexer_cursor: u32,
    indexer_hang: bool,
    // RPCs: the pinned one (`/rpc`) and the owner's exit RPC (`/exit-rpc`).
    pinned_down: bool,
    /// The pinned RPC reports the note Active with no pending exit, its
    /// nullifiers challenged, and a finalized block far in the future.
    pinned_lies: bool,
    /// Calls the pinned RPC answered.
    pinned_calls: usize,
    /// The pinned RPC holds every call (accepted, never answered).
    pinned_hang: bool,
    /// The pinned RPC answers `eth_call` only after this long (a slow relay).
    pinned_delay: Option<Duration>,
    /// The exit RPC refuses every call.
    exit_down: bool,
    /// The exit RPC is on this chain instead of the vault's (chain 1).
    exit_chain: Option<u64>,
    /// The finalized block trails the latest by this many blocks.
    finalized_lag: u64,
    /// Every RPC fails `eth_getLogs` (a node that dropped or rate-limits
    /// log queries).
    logs_down: bool,
    // Chain: the vault's `notes(NOTE_ID)` (its commitment, amount, expiry
    // and status) and `activationCursor()`.
    commitment: Felt252,
    note_amount: u128,
    expiry: u64,
    activation_cursor: u32,
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

/// The pinned RPC: down, lying, hanging, slow, or the chain as it is.
async fn pinned_rpc(State(world): State<Shared>, Json(body): Json<Value>) -> Response {
    let (down, lies, hang, delay) = {
        let mut world = world.lock().unwrap();
        world.pinned_calls += 1;
        (
            world.pinned_down,
            world.pinned_lies,
            world.pinned_hang,
            world.pinned_delay,
        )
    };
    if hang {
        tokio::time::sleep(OPERATOR_HANG).await;
    }
    if let Some(delay) = delay.filter(|_| body["method"] == "eth_call") {
        tokio::time::sleep(delay).await;
    }
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
    let world = world.lock().unwrap();
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
            let result = match selector {
                chain::NOTES => match if lies { 1 } else { world.note_status } {
                    0 => format!("0x{}", "0".repeat(64 * 4)),
                    status => format!(
                        "0x{}{}{}{}",
                        felt_word(&world.commitment),
                        word(world.note_amount),
                        word(world.expiry),
                        word(status)
                    ),
                },
                chain::ACTIVATION_CURSOR => format!("0x{}", word(world.activation_cursor)),
                chain::PENDING_WITHDRAWALS if lies => format!("0x{}", "0".repeat(64 * 5)),
                chain::PENDING_WITHDRAWALS => match world.pending {
                    Some(pending) => format!(
                        "0x{}{}{}{}{}{}",
                        word(1u8),
                        felt_word(&pending.nullifier),
                        word(pending.final_balance),
                        "0".repeat(24),
                        hex::encode(pending.destination),
                        word(pending.deadline)
                    ),
                    None => format!("0x{}", "0".repeat(64 * 5)),
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
    expiry: u64,
    /// The activated note's path in the vault's tree, which requests prove.
    root: Felt252,
    siblings: Vec<Felt252>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.server.abort();
    }
}

impl Harness {
    /// A note deposited and activated after two others, and confirmed.
    async fn new() -> Self {
        Self::build_expiring(4_000_000_000).await
    }

    /// The harness with the note's expiry at `expiry`.
    async fn build_expiring(expiry: u64) -> Self {
        let harness = Self::unconfirmed(expiry).await;
        harness.confirm().await.unwrap();
        harness
    }

    /// The note recorded and activated by the vault, not yet confirmed in
    /// the wallet.
    async fn unconfirmed(expiry: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let world: Shared = Arc::new(Mutex::new(World {
            note_status: 1,
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
                "/v1/tree/root",
                get(|State(world): State<Shared>| async move {
                    indexer_pause(&world).await;
                    let world = world.lock().unwrap();
                    Json(json!({
                        "root": world.indexer_root,
                        "activation_cursor": world.indexer_cursor,
                    }))
                }),
            )
            .route(
                "/v1/tree/notes/{note}/path",
                get(
                    |State(world): State<Shared>, AxumPath(note): AxumPath<u32>| async move {
                        indexer_pause(&world).await;
                        let world = world.lock().unwrap();
                        let activated = note < world.indexer_cursor;
                        Json(json!({
                            "note_id": note,
                            "leaf": if activated { world.indexer_leaf } else { Felt252::ZERO },
                            "siblings": world.indexer_path,
                            "root": world.indexer_root,
                            "activated": activated,
                            "activation_cursor": world.indexer_cursor,
                        }))
                    },
                ),
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
        // Notes 1 and 2 were activated first, then this one.
        let secret = Felt252::from_u64(4242);
        let mut tree = zkapi_client::tree::SparseTree::new();
        for (note, owner) in [(1u32, 7u64), (2, 8), (NOTE_ID, 0)] {
            let commitment = if note == NOTE_ID {
                core::registration_commitment(&secret)
            } else {
                core::registration_commitment(&Felt252::from_u64(owner))
            };
            tree.set_leaf(note, core::note_leaf(note, &commitment, DEPOSIT, expiry));
        }
        let root = tree.root();
        let siblings = tree.siblings(NOTE_ID).to_vec();
        {
            let mut world = world.lock().unwrap();
            world.commitment = core::registration_commitment(&secret);
            world.note_amount = DEPOSIT;
            world.expiry = expiry;
            world.activation_cursor = NOTE_ID + 1;
            world.indexer_cursor = NOTE_ID + 1;
            world.indexer_root = root;
            world.indexer_path = siblings.clone();
            world.indexer_leaf = tree.leaf(NOTE_ID);
        }
        let service = AuthService::new(config.clone()).unwrap();
        Self {
            _directory: directory,
            config,
            service,
            world,
            server,
            secret,
            expiry,
            root,
            siblings,
        }
    }

    /// The deposit's confirmation, as the bridge sends it.
    async fn confirm(&self) -> Result<WalletStatus, AuthError> {
        self.service
            .confirm_deposit(ConfirmDepositRequest {
                secret: self.secret,
                note_id: NOTE_ID,
                amount: DEPOSIT,
                expiry_ts: self.expiry,
            })
            .await
    }

    fn wallet(&self) -> zkapi_client::wallet::Wallet {
        super::super::load_wallet(&self.config).unwrap()
    }

    /// The same wallet behind a fresh service (a restarted companion), which
    /// holds no activation reading yet.
    fn restarted(mut self) -> Self {
        self.service = AuthService::new(self.config.clone()).unwrap();
        self
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
                self.root,
                self.siblings.clone(),
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
        assert_eq!(calldata.len(), 2 + 868 * 2);
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
        // The vault's note binding: C and M as `notes(noteId)` stores them.
        assert_eq!(inputs.registration_commitment, world.commitment);
        assert_eq!(
            (inputs.deposit_amount, inputs.expiry),
            (world.note_amount, world.expiry)
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
        let root = world.indexer_root;
        world.logs.push(json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": "0x0",
            "removed": false,
            "transactionHash": format!("0x{}", "cd".repeat(32)),
            "topics": [chain::escape_challenged_topic(), format!("0x{}", word(NOTE_ID))],
            "data": format!("0x{}{}", felt_word(&nullifier), felt_word(&root)),
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
/// escape is proved from the note alone (no indexer, no path), initiated,
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
    // From now on the indexer hangs: the escape never reads it.
    harness.world.lock().unwrap().indexer_hang = true;
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
    // The 17-input statement names the note as the vault records it.
    assert_eq!(
        plan["public_inputs"]["registration_commitment"],
        json!(core::registration_commitment(&harness.secret))
    );
    assert_eq!(plan["public_inputs"]["deposit_amount"], json!(DEPOSIT));
    assert_eq!(plan["public_inputs"]["expiry"], json!(harness.expiry));
    assert!(plan["public_inputs"].get("active_root").is_none());
    assert_eq!(plan["warnings"], json!([]), "{plan}");
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
            harness.root,
            harness.siblings.clone(),
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
            harness.root,
            harness.siblings.clone(),
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

/// A recorded note exits at once: before its activation, with the indexer
/// hanging, the escape is proved from the note alone. The vault's record of
/// the note is read only as advice: one that differs from the wallet's is
/// reported (the vault would refuse the escape), never a refusal here.
#[tokio::test]
async fn a_note_escapes_before_activation_and_without_the_indexer() {
    let harness = Harness::new().await;
    {
        let mut world = harness.world.lock().unwrap();
        world.activation_cursor = 0;
        world.indexer_cursor = 0;
        world.indexer_hang = true;
    }
    let plan = tokio::time::timeout(OPERATOR_HANG / 2, harness.prepare(Some("0"), None))
        .await
        .expect("the escape waited on the indexer")
        .unwrap();
    assert_eq!(plan["status"], "prepared", "{plan}");
    assert_eq!(plan["warnings"], json!([]), "{plan}");
    harness.initiate(&plan);

    let harness = Harness::new().await;
    harness.world.lock().unwrap().note_amount = DEPOSIT + 1;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared", "{plan}");
    assert!(
        plan["warnings"]
            .to_string()
            .contains("note_binding_mismatch"),
        "{plan}"
    );
    // A vault RPC that has not seen the deposit yet is reported too.
    let harness = Harness::new().await;
    harness.world.lock().unwrap().note_status = 0;
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert!(
        plan["warnings"]
            .to_string()
            .contains("has no record of note 3"),
        "{plan}"
    );
}

/// A request needs the note's leaf at the current root: until the vault's
/// `activationCursor()` passes the note, request preparation is refused
/// with `note_not_activated` (retriable) and no proof is made, while the
/// escape stays available. The indexer's view must hold the activation (a
/// note the vault activated that it does not hold yet is its lag, refused
/// with the retriable `indexer_root_lag`); the vault's cursor tells the two
/// refusals apart, and the indexer's decides when the vault cannot be read.
#[tokio::test]
async fn a_request_waits_for_the_notes_activation() {
    let harness = Harness::new().await;
    let preview = || {
        harness
            .service
            .preview_request(crate::service::CoreRequest::post_json(
                "/v1/chat/completions",
                json!({}),
            ))
    };
    {
        let mut world = harness.world.lock().unwrap();
        world.activation_cursor = 1;
        world.indexer_cursor = 1;
    }
    let refused = preview().await;
    assert!(
        matches!(
            refused,
            Err(AuthError::NoteNotActivated {
                queue_position: 2,
                activation_cursor: Some(1)
            })
        ),
        "{refused:?}"
    );
    let error = refused.unwrap_err();
    assert_eq!(error.code(), "note_not_activated");
    assert_eq!(error.detail().unwrap()["queue_position"], 2);
    assert!(!harness.wallet().has_pending_request());
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(false), Some(1))
    );
    // The vault activated the note; the indexer's view lags.
    harness.world.lock().unwrap().activation_cursor = 4;
    let lagging = preview().await;
    assert!(
        matches!(
            lagging,
            Err(AuthError::IndexerRootLag {
                activation_cursor: 4
            })
        ),
        "{lagging:?}"
    );
    let error = lagging.unwrap_err();
    assert_eq!(error.code(), "indexer_root_lag");
    assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.detail().unwrap()["retriable"], true);
    assert!(!harness.wallet().has_pending_request());
    // Both hold it: the request is prepared at the indexer's path.
    harness.world.lock().unwrap().indexer_cursor = 4;
    let ready = preview().await.unwrap();
    assert_eq!(ready.active_root, harness.root);
    assert_eq!(ready.merkle_siblings, harness.siblings);
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(4))
    );
    let body = serde_json::to_value(&status).unwrap();
    assert_eq!(body["activated"], true);
    assert_eq!(body["activation_cursor"], 4);
    // Without the vault, the indexer's cursor decides.
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_down = true;
        world.indexer_cursor = 3;
    }
    assert!(matches!(
        preview().await,
        Err(AuthError::NoteNotActivated {
            queue_position: 0,
            activation_cursor: Some(3)
        })
    ));
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!(status.activated, Some(false));
    // Neither answers: the last reading is reported, without waiting.
    harness.world.lock().unwrap().indexer_hang = true;
    let status = tokio::time::timeout(
        Duration::from_millis(1_400),
        harness.service.status_with_activation(),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(false), Some(3))
    );
    // ... until it is out of date: with no answer for
    // `ACTIVATION_READING_MAX_AGE`, a reading that leaves the note waiting
    // is no longer reported (the note may be activated since), and the
    // activation is unknown again.
    tokio::time::sleep(super::super::ACTIVATION_READING_MAX_AGE).await;
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!((status.activated, status.activation_cursor), (None, None));
    let body = serde_json::to_value(&status).unwrap();
    assert!(body.get("activated").is_none(), "{body}");
    assert!(body.get("activation_cursor").is_none(), "{body}");
    // The escape is available throughout.
    harness.world.lock().unwrap().pinned_down = false;
    assert_eq!(
        harness.prepare(Some("0"), None).await.unwrap()["status"],
        "prepared"
    );
}

/// A request never waits on the vault's RPC for a note the indexer's view
/// holds activated: it is prepared at that view without asking the vault
/// (activation only moves forward, and the server admits the root). The
/// vault is asked only to tell a note not activated yet from the indexer's
/// lag, for `ACTIVATION_CLASSIFY_WAIT`, far below E0's bound: an RPC that
/// hangs leaves the indexer's cursor to decide.
#[tokio::test]
async fn a_hanging_rpc_cannot_hold_a_request() {
    let harness = Harness::new().await;
    let preview = || {
        harness
            .service
            .preview_request(crate::service::CoreRequest::post_json(
                "/v1/chat/completions",
                json!({}),
            ))
    };
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_hang = true;
        world.pinned_calls = 0;
    }
    for _ in 0..2 {
        let ready = preview().await.unwrap();
        assert_eq!(ready.active_root, harness.root);
        assert_eq!(ready.merkle_siblings, harness.siblings);
    }
    assert_eq!(harness.world.lock().unwrap().pinned_calls, 0);
    // The indexer's view does not hold the activation: the hanging vault is
    // asked, and given up on, once.
    harness.world.lock().unwrap().indexer_cursor = NOTE_ID;
    let started = Instant::now();
    let refused = preview().await;
    let elapsed = started.elapsed();
    assert!(
        matches!(
            refused,
            Err(AuthError::NoteNotActivated {
                queue_position: 0,
                activation_cursor: Some(NOTE_ID)
            })
        ),
        "{refused:?}"
    );
    assert!(
        elapsed >= super::super::ACTIVATION_CLASSIFY_WAIT && elapsed < crate::indexer::CALL_TIMEOUT,
        "{elapsed:?}"
    );
    assert_eq!(harness.world.lock().unwrap().pinned_calls, 1);
    // Once the vault answers, it names the indexer's lag.
    harness.world.lock().unwrap().pinned_hang = false;
    let lagging = preview().await;
    assert!(
        matches!(
            lagging,
            Err(AuthError::IndexerRootLag { activation_cursor }) if activation_cursor == NOTE_ID + 1
        ),
        "{lagging:?}"
    );
}

/// Status reports the note's activation from its last reading and never waits
/// on the chain or the indexer for long: with the pinned RPC and the indexer
/// hanging, it answers within `ACTIVATION_STATUS_WAIT`, the activation
/// unknown (absent) before any reading (a restarted companion) and the last
/// reading after one (one that passes the note however old), and concurrent
/// calls share one refresh instead of each asking the RPC.
#[tokio::test]
async fn status_never_waits_on_a_hanging_rpc_or_indexer() {
    let harness = Harness::new().await.restarted();
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_hang = true;
        world.indexer_hang = true;
        world.pinned_calls = 0;
    }
    // Each reading alone would take E0's `CALL_TIMEOUT` (1.5 s in tests).
    let bound = Duration::from_millis(1_400);
    let started = Instant::now();
    let (first, second, third) = tokio::join!(
        harness.service.status_with_activation(),
        harness.service.status_with_activation(),
        harness.service.status_with_activation(),
    );
    assert!(started.elapsed() < bound, "{:?}", started.elapsed());
    for status in [first, second, third] {
        let status = status.unwrap();
        assert!(status.has_note);
        assert_eq!((status.activated, status.activation_cursor), (None, None));
        let body = serde_json::to_value(&status).unwrap();
        assert!(body.get("activated").is_none(), "{body}");
        assert!(body.get("activation_cursor").is_none(), "{body}");
    }
    assert_eq!(harness.world.lock().unwrap().pinned_calls, 1);
    // The sources answer again: a reading lands once the hanging refresh
    // gives up on the RPC and asks the indexer.
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_hang = false;
        world.indexer_hang = false;
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        let status = harness.service.status_with_activation().await.unwrap();
        if status.activation_cursor.is_some() {
            break status;
        }
        assert!(Instant::now() < deadline, "no reading landed");
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(NOTE_ID + 1))
    );
    // Both hang again: the last reading is reported, as fast.
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_hang = true;
        world.indexer_hang = true;
    }
    let started = Instant::now();
    let status = harness.service.status_with_activation().await.unwrap();
    assert!(started.elapsed() < bound, "{:?}", started.elapsed());
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(NOTE_ID + 1))
    );
    // A reading that passes the note stays true however old (the cursor
    // only grows), so it is still reported with no answer for
    // `ACTIVATION_READING_MAX_AGE`.
    tokio::time::sleep(super::super::ACTIVATION_READING_MAX_AGE).await;
    let started = Instant::now();
    let status = harness.service.status_with_activation().await.unwrap();
    assert!(started.elapsed() < bound, "{:?}", started.elapsed());
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(NOTE_ID + 1))
    );
}

/// A reading slower than status waits for (an RPC behind a slow relay) is
/// not abandoned: it lands in the background, and the next status reports
/// it.
#[tokio::test]
async fn a_slow_activation_reading_lands_for_the_next_status() {
    let harness = Harness::new().await.restarted();
    {
        let mut world = harness.world.lock().unwrap();
        world.pinned_delay = Some(Duration::from_secs(1));
        world.indexer_hang = true;
    }
    let started = Instant::now();
    let status = harness.service.status_with_activation().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
    assert_eq!((status.activated, status.activation_cursor), (None, None));
    tokio::time::sleep(Duration::from_secs(1)).await;
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(NOTE_ID + 1))
    );
}

/// A note's first status, right after its deposit is confirmed, reports its
/// activation even when a refresh is slower than status waits for (clientd
/// asks it at once, over a slow relay): the confirmation read the vault's
/// cursor with the note's record.
#[tokio::test]
async fn a_confirmed_deposit_reports_its_activation_at_once() {
    let harness = Harness::unconfirmed(4_000_000_000).await;
    {
        // Recorded, not activated yet.
        let mut world = harness.world.lock().unwrap();
        world.activation_cursor = NOTE_ID;
        world.indexer_cursor = NOTE_ID;
        world.pinned_delay = Some(Duration::from_secs(1));
        world.indexer_hang = true;
    }
    harness.confirm().await.unwrap();
    let started = Instant::now();
    let status = harness.service.status_with_activation().await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(900),
        "{:?}",
        started.elapsed()
    );
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(false), Some(NOTE_ID))
    );
    // The batch activates it: the refresh that status started lands.
    harness.world.lock().unwrap().activation_cursor = NOTE_ID + 1;
    tokio::time::sleep(Duration::from_millis(1_200)).await;
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!(
        (status.activated, status.activation_cursor),
        (Some(true), Some(NOTE_ID + 1))
    );
    // A cursor the confirmation cannot read leaves the reading to status.
    let harness = Harness::unconfirmed(4_000_000_000).await;
    harness.world.lock().unwrap().pinned_down = true;
    harness.confirm().await.unwrap();
    harness.world.lock().unwrap().indexer_hang = true;
    let status = harness.service.status_with_activation().await.unwrap();
    assert_eq!((status.activated, status.activation_cursor), (None, None));
}

/// The deposit's confirmation checks the vault's record of the note: one it
/// records with another amount (or commitment, or expiry) is refused and
/// nothing is installed; one its RPC has not recorded yet, or cannot read,
/// is confirmed unchecked. Fields an earlier bridge sent with it (the
/// deposit-time root and siblings) are ignored.
#[tokio::test]
async fn a_deposit_the_vault_records_otherwise_is_not_confirmed() {
    let harness = Harness::unconfirmed(4_000_000_000).await;
    harness.world.lock().unwrap().note_amount = DEPOSIT - 1;
    let refused = harness.confirm().await;
    assert!(
        matches!(&refused, Err(AuthError::NoteBindingMismatch(_))),
        "{refused:?}"
    );
    assert_eq!(refused.unwrap_err().code(), "note_binding_mismatch");
    assert!(harness.wallet().state().is_none());
    // Not recorded at the RPC's latest block yet.
    harness.world.lock().unwrap().note_status = 0;
    harness.confirm().await.unwrap();
    assert!(harness.wallet().state().is_some());

    let harness = Harness::unconfirmed(4_000_000_000).await;
    harness.world.lock().unwrap().pinned_down = true;
    let request: ConfirmDepositRequest = serde_json::from_value(json!({
        "secret": harness.secret,
        "note_id": NOTE_ID,
        "amount": DEPOSIT,
        "expiry_ts": harness.expiry,
        "deposit_root": "0x5",
        "deposit_siblings": vec!["0x1"; 32],
    }))
    .unwrap();
    harness.service.confirm_deposit(request).await.unwrap();
    assert_eq!(
        harness
            .wallet()
            .recorded_note()
            .unwrap()
            .registration_commitment,
        core::registration_commitment(&harness.secret)
    );
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
            harness.root,
            harness.siblings.clone(),
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
        let indexer = self.indexer.clone();
        super::super::spawn_blocking(move || {
            let _guard = wallet_mutex.lock().unwrap();
            let _lockfile = super::super::acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = super::super::load_wallet(&config)?;
            let runtime = super::super::current_thread_runtime()?;
            let state = wallet.state().unwrap().clone();
            let path = runtime.block_on(indexer.note_path(state.note_id))?;
            wallet
                .prepare_request_with_bound(
                    "{}",
                    zkapi_types::canonical_payload_hash(b"{}"),
                    path.root,
                    path.siblings,
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
/// proved again from the kept clearance signature, naming the same note,
/// with no ownership proof or clearance request. A reservation saved
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
                fresh.public_inputs.registration_commitment,
                fresh.public_inputs.note_metadata(),
                fresh.public_inputs.kind,
            ),
            (
                first.public_inputs.withdrawal_nullifier,
                first.public_inputs.final_balance,
                first.public_inputs.registration_commitment,
                first.public_inputs.note_metadata(),
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
/// (E6), nor for the escape's start block, and the pinned RPC is not asked
/// in its place. Pointed back at the vault's chain, it decides again.
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

    // The escape needs no chain reading to be proved: its raises are
    // scanned from the deployment block, not from a block the other chain
    // named, and the RPC's failure is reported.
    let harness = Harness::new().await.with_exit_rpc();
    {
        let mut world = harness.world.lock().unwrap();
        world.exit_chain = Some(5);
        world.block = 500;
    }
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared");
    assert!(plan["warnings"].to_string().contains("chain 5"), "{plan}");
    let record = load_record(&harness.config).unwrap().unwrap();
    assert_eq!(record.start_block, harness.config.deploy_block);
}

/// With the owner's exit RPC down, the escape is still proved (it needs no
/// root and no chain reading), and the pinned RPC never names its start
/// block: raises are scanned from the deployment block.
#[tokio::test]
async fn an_escape_is_proved_with_its_exit_rpc_down() {
    let harness = Harness::new().await.with_exit_rpc();
    {
        let mut world = harness.world.lock().unwrap();
        world.exit_down = true;
        world.block = 500;
    }
    let plan = harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(plan["status"], "prepared", "{plan}");
    let record = load_record(&harness.config).unwrap().unwrap();
    assert_eq!(record.start_block, harness.config.deploy_block);
    assert!(plan["warnings"].to_string().contains("429"), "{plan}");
    // Once it answers, it names the start block.
    let harness = Harness::new().await.with_exit_rpc();
    harness.world.lock().unwrap().block = 500;
    harness.prepare(Some("0"), None).await.unwrap();
    assert_eq!(
        load_record(&harness.config).unwrap().unwrap().start_block,
        500
    );
}

/// E0: the indexer is the operator's. One that accepts a connection and
/// never answers holds no exit: neither the mutual close nor the escape
/// reads it (here the mutual close proves ownership and goes on to the
/// operator's clearance, which refuses; the escape decision waits behind
/// that proof, never on the indexer), and a request preparation waiting on
/// it fails within its bound.
#[tokio::test]
async fn a_hanging_indexer_cannot_hold_the_exit_routes() {
    // The exit routes' bound includes the mutual close's ownership proof:
    // 15 s optimized, while unoptimized (debug) builds prove an order of
    // magnitude slower, so there it is the usual `OPERATOR_HANG / 2`. A
    // route that waited on the indexer fails either.
    const PROVING_BOUND: Duration = if cfg!(debug_assertions) {
        Duration::from_secs(OPERATOR_HANG.as_secs() / 2)
    } else {
        Duration::from_secs(15)
    };
    let harness = Arc::new(Harness::new().await);
    harness.world.lock().unwrap().indexer_hang = true;
    let started = Instant::now();
    let mutual = {
        let harness = harness.clone();
        tokio::spawn(async move {
            harness
                .service
                .oa_prepare_withdrawal([0x22; 20], false)
                .await
        })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    let decision = tokio::time::timeout(PROVING_BOUND, harness.prepare(None, None))
        .await
        .expect("a hanging indexer held the escape decision")
        .unwrap();
    assert_eq!(decision["status"], "decision");
    let mutual = tokio::time::timeout(PROVING_BOUND, mutual)
        .await
        .expect("a hanging indexer held the mutual close")
        .unwrap();
    assert!(
        matches!(mutual, Err(AuthError::EscapeRequired(_))),
        "{mutual:?}"
    );
    assert!(started.elapsed() < PROVING_BOUND);
    // Only the ownership proof the clearance request carried was released.
    let lock = harness.wallet().exit_lock().unwrap().unwrap();
    assert!(lock.released.iter().all(|proof| proof.kind == 2));
    // A request preparation (a chat) is bounded the same way.
    let failed = tokio::time::timeout(
        Duration::from_secs(15),
        harness.service.request_through_lock(&harness.config),
    )
    .await
    .expect("a hanging indexer held a request preparation");
    assert!(matches!(failed, Err(AuthError::Indexer(_))), "{failed:?}");
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
            harness.root,
            harness.siblings.clone(),
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

/// The server checks the ownership proof against the vault's
/// `notes(noteId)`. `note_binding_mismatch` and `note_not_active` are
/// refusals (E2 step 5: the exit continues as an escape, and the refusal is
/// reported); `note_not_recorded`, a deposit the operator's RPC has not seen
/// yet, is retried and then reported as retriable, recording no outcome.
#[tokio::test]
async fn clearance_binding_refusals_escape_and_an_unrecorded_note_is_retried() {
    for code in ["note_binding_mismatch", "note_not_active"] {
        let harness = Harness::new().await;
        harness.world.lock().unwrap().clearance = Some((
            409,
            json!({"status": "error", "client_request_id": "", "error_code": code,
                "error_message": "refused", "retriable": false}),
        ));
        let refused = harness
            .service
            .oa_prepare_withdrawal([0x22; 20], false)
            .await;
        let detail = match refused {
            Err(AuthError::EscapeRequired(detail)) => detail,
            other => panic!("{code}: {other:?}"),
        };
        assert_eq!(detail["clearance_refusal"], code);
        assert_eq!(detail["reason"], "mutual_refused", "{code}");
        assert_eq!(
            crate::oa_withdrawal::load(&harness.config)
                .unwrap()
                .unwrap()
                .clearance_outcome,
            Some(zkapi_client::exit_policy::MutualOutcome::RefusedOrUnreachable)
        );
    }
    let harness = Harness::new().await;
    harness.world.lock().unwrap().clearance = Some((
        409,
        json!({"status": "error", "client_request_id": "", "error_code": "note_not_recorded",
            "error_message": "not yet", "retriable": true}),
    ));
    let retried = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await;
    assert!(
        matches!(retried, Err(AuthError::NoteNotRecorded)),
        "{retried:?}"
    );
    assert!(harness.world.lock().unwrap().clearance_calls > 1);
    let reservation = crate::oa_withdrawal::load(&harness.config)
        .unwrap()
        .unwrap();
    assert_eq!(reservation.clearance_outcome, None);
    // Once the operator sees the deposit, the same reservation closes.
    harness.grant_clearance();
    let plan = harness
        .service
        .oa_prepare_withdrawal([0x22; 20], false)
        .await
        .unwrap();
    assert_eq!(plan.public_inputs.kind, 1);
    assert_eq!(
        plan.public_inputs.registration_commitment,
        core::registration_commitment(&harness.secret)
    );
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
