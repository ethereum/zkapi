//! The activation worker against the real vault and generated adapter on
//! Anvil (design C §5), deployed with the worker's sender as its activator:
//! the startup probes, insertion verifying-key pins and the manifest's
//! activator pass against the deployed contracts; proved batches of 1, 4 and
//! 16 notes verify in `assertValidInsertion` and move the vault's root to the
//! tree of the recorded notes; a competing `activateNotesOnChain`, open once
//! no proved activation landed for `ACTIVATION_FALLBACK_DELAY`, landing first
//! makes the worker's transaction revert and the batch is rebuilt; a dropped
//! transaction is re-sent on its nonce; a restart resumes a pending call;
//! after a reorganization (`evm_revert`) undoes a mined activation, its call
//! is re-sent on its nonce, or, when the batch's deposit was replaced, a
//! fresh batch is proved and sent on it; while the owner names another
//! activator, the vault refuses the worker's `activateNotes` and the worker
//! sends nothing (`not_activator`) until the owner names its sender again.
//!
//! Needs `forge` and `anvil` on PATH; without them it reports a skip, and
//! with `ZKAPI_REQUIRE_ANVIL=1` it fails instead.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use axum::{
    extract::{Path as UrlPath, State},
    routing::get,
    Json, Router,
};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_core::MerkleTree;
use zkapi_serverd::activation_service::{
    activate_calldata, ActivationService, ActivationServiceConfig,
};
use zkapi_serverd::activation_status::{
    ActivationAlarmPolicy, ActivationBlocked, BatchOutcome, WorkerState,
};
use zkapi_serverd::challenge_service::{DeploymentCheckError, FeePolicy};
use zkapi_serverd::deployment::DeploymentManifest;
use zkapi_serverd::nullifier_store::StatementIdentity;
use zkapi_types::Felt252;

const SETUP_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/setup/v2-concession-dev"
);
const REPO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../..");
/// Anvil's default accounts: the deployer, owner and depositor, the worker's
/// sender (the vault's activator), and a competitor using the on-chain
/// fallback.
const DEPLOYER_KEY: &str = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
const DEPOSITOR: &str = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
const WORKER: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const COMPETITOR: &str = "0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc";
const GWEI: u128 = 1_000_000_000;

const DEPLOY_SCRIPT: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script, console} from "forge-std/Script.sol";
import {ZkApiVault} from "zkapi/ZkApiVault.sol";
import {Groth16ProofAdapter} from "zkapi/adapters/Groth16ProofAdapter.sol";

contract Deploy is Script {
    function run() external {
        vm.startBroadcast();
        Groth16ProofAdapter adapter = new Groth16ProofAdapter();
        // The activator is WORKER.
        ZkApiVault vault = new ZkApiVault(
            address(0xbeef), 30 days, 1 days, 100_000, address(adapter), 11, 12, 13, 14, msg.sender, 2 days,
            0x70997970C51812dc3A010C7d01b50e0d17dc79C8
        );
        vm.stopBroadcast();
        console.log(string.concat("vault=", vm.toString(address(vault))));
        console.log(string.concat("adapter=", vm.toString(address(adapter))));
    }
}
"#;

struct Anvil(Child);

impl Drop for Anvil {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn tool(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .map(|path| path.join(name))
            .find(|path| path.is_file())
    })
}

#[derive(Clone)]
struct Rpc {
    client: reqwest::Client,
    url: String,
}

impl Rpc {
    /// A JSON-RPC call; a transport failure (Anvil still starting) is an
    /// error too.
    async fn call(&self, method: &str, params: Value) -> Result<Value, Value> {
        let response = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .map_err(|error| json!(error.to_string()))?;
        let response: Value = response
            .json()
            .await
            .map_err(|error| json!(error.to_string()))?;
        match response.get("error") {
            Some(error) => Err(error.clone()),
            None => Ok(response["result"].clone()),
        }
    }

    async fn ok(&self, method: &str, params: Value) -> Value {
        self.call(method, params)
            .await
            .unwrap_or_else(|error| panic!("{method}: {error}"))
    }

    async fn word(&self, to: &str, data: String) -> Vec<u8> {
        let result = self
            .ok("eth_call", json!([{ "to": to, "data": data }, "latest"]))
            .await;
        hex::decode(&result.as_str().unwrap()[2..]).unwrap()
    }

    async fn number(&self, to: &str, signature: &str) -> u64 {
        let bytes = self.word(to, selector(signature)).await;
        u64::from_be_bytes(bytes[24..32].try_into().unwrap())
    }

    async fn send(&self, from: &str, to: &str, data: String, value: u128) -> String {
        self.ok(
            "eth_sendTransaction",
            json!([{ "from": from, "to": to, "data": data, "value": format!("0x{value:x}") }]),
        )
        .await
        .as_str()
        .unwrap()
        .to_string()
    }

    async fn mine(&self) {
        self.ok("evm_mine", json!([])).await;
    }

    /// The receipt of `hash` once mined (automine returns before it mines),
    /// which must be a success.
    async fn receipt(&self, hash: &str) -> Value {
        for _ in 0..100 {
            let receipt = self.ok("eth_getTransactionReceipt", json!([hash])).await;
            if !receipt.is_null() {
                assert_eq!(receipt["status"], "0x1", "{receipt}");
                return receipt;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("{hash} was not mined");
    }

    async fn code_hash(&self, address: &str) -> String {
        let code = self.ok("eth_getCode", json!([address, "latest"])).await;
        let bytes = hex::decode(&code.as_str().unwrap()[2..]).unwrap();
        format!("0x{}", hex::encode(Keccak256::digest(bytes)))
    }
}

fn selector(signature: &str) -> String {
    format!(
        "0x{}",
        hex::encode(&Keccak256::digest(signature.as_bytes())[..4])
    )
}

/// The vault's request tree, from its recorded notes: the leaf of every note
/// below the cursor (nothing is retired here); and the cursor.
async fn vault_tree(rpc: &Rpc, vault: &str) -> (MerkleTree, u32) {
    let cursor = rpc.number(vault, "activationCursor()").await as u32;
    let mut tree = MerkleTree::new();
    for id in 0..cursor {
        let note = rpc
            .word(vault, format!("{}{id:064x}", selector("notes(uint32)")))
            .await;
        let commitment = Felt252(note[..32].try_into().unwrap());
        let amount = u128::from_be_bytes(note[48..64].try_into().unwrap());
        let expiry = u64::from_be_bytes(note[88..96].try_into().unwrap());
        tree.set_leaf(
            id,
            zkapi_core::v2::note_leaf(id, &commitment, amount, expiry),
        );
    }
    (tree, cursor)
}

/// A minimal indexer: the path of any slot in the vault's current tree.
async fn path(State((rpc, vault)): State<(Rpc, String)>, UrlPath(id): UrlPath<u32>) -> Json<Value> {
    let (tree, cursor) = vault_tree(&rpc, &vault).await;
    Json(json!({
        "note_id": id,
        "leaf": tree.get_leaf(id),
        "siblings": tree.get_siblings(id).to_vec(),
        "root": tree.root(),
        "activated": id < cursor,
        "activation_cursor": cursor,
    }))
}

/// `activateNotesOnChain(uint32,uint256,uint256[32])`, as anyone may call it
/// once the fallback is open.
fn activate_on_chain_calldata(first: u32, count: u32, siblings: &[Felt252]) -> String {
    let mut data = selector("activateNotesOnChain(uint32,uint256,uint256[32])");
    data.push_str(&format!("{first:064x}{count:064x}"));
    for sibling in siblings {
        data.push_str(&hex::encode(sibling.as_bytes()));
    }
    data
}

/// The fallback's encoding, and the activator role's selectors this test
/// uses, are the real vault's (vault_calldata_golden.json, from the compiled
/// protocol/contracts sources).
#[test]
fn activate_on_chain_calldata_matches_forge_abi_encode() {
    let golden: Value =
        serde_json::from_str(include_str!("fixtures/vault_calldata_golden.json")).unwrap();
    let siblings: Vec<Felt252> = (1..=32u64)
        .map(|index| Felt252::from_u64(index * 0x0101010101010101))
        .collect();
    assert_eq!(
        activate_on_chain_calldata(16, 16, &siblings),
        golden["activate_on_chain"].as_str().unwrap()
    );
    for (name, signature) in [
        (
            "activateNotesOnChain",
            "activateNotesOnChain(uint32,uint256,uint256[32])",
        ),
        ("setActivator", "setActivator(address)"),
        ("activationFallbackOpensAt", "activationFallbackOpensAt()"),
        ("NotActivator", "NotActivator()"),
        ("ActivationFallbackClosed", "ActivationFallbackClosed()"),
    ] {
        assert_eq!(
            selector(signature),
            golden["selectors"][name].as_str().unwrap(),
            "{name}"
        );
    }
}

struct Harness {
    rpc: Rpc,
    vault: String,
    config: ActivationServiceConfig,
    deposits: u64,
    /// Anvil mines every transaction on its own; else the harness mines.
    automine: bool,
}

impl Harness {
    /// Record `count` notes and wait until every deposit is mined.
    async fn deposit(&mut self, count: u32) {
        let mut hashes = Vec::new();
        for _ in 0..count {
            self.deposits += 1;
            let commitment = Felt252::from_u64(0x5eed_0000 + self.deposits);
            let amount = 1_000 + u128::from(self.deposits);
            let data = format!(
                "{}{}{amount:064x}",
                selector("deposit(bytes32,uint128)"),
                hex::encode(commitment.as_bytes())
            );
            hashes.push(
                self.rpc
                    .send(DEPOSITOR, &self.vault, data, amount * GWEI)
                    .await,
            );
        }
        if !self.automine {
            self.rpc.mine().await;
        }
        for hash in hashes {
            self.rpc.receipt(&hash).await;
        }
    }

    async fn set_automine(&mut self, automine: bool) {
        self.rpc.ok("evm_setAutomine", json!([automine])).await;
        self.automine = automine;
    }

    async fn cursor(&self) -> u32 {
        self.rpc.number(&self.vault, "activationCursor()").await as u32
    }

    /// The latest block's timestamp.
    async fn now(&self) -> u64 {
        let block = self
            .rpc
            .ok("eth_getBlockByNumber", json!(["latest", false]))
            .await;
        u64::from_str_radix(&block["timestamp"].as_str().unwrap()[2..], 16).unwrap()
    }

    /// The owner's `setActivator(activator)`, mined.
    async fn set_activator(&self, activator: &str) {
        let data = format!(
            "{}{:0>64}",
            selector("setActivator(address)"),
            &activator[2..]
        );
        let hash = self.rpc.send(DEPOSITOR, &self.vault, data, 0).await;
        if !self.automine {
            self.rpc.mine().await;
        }
        self.rpc.receipt(&hash).await;
    }

    /// The vault's root is the tree of the recorded notes below its cursor.
    async fn assert_tree(&self) {
        let (tree, _) = vault_tree(&self.rpc, &self.vault).await;
        let root = self.rpc.word(&self.vault, selector("currentRoot()")).await;
        assert_eq!(Felt252(root.try_into().unwrap()), tree.root());
    }

    /// Poll (mining a block after each poll) until the worker confirms the
    /// activation of `expected` (first note, size); its gas used. With
    /// automine a send mines at once, and a poll that confirms one batch
    /// already sends the next.
    async fn activate(&self, service: &mut ActivationService, expected: (u32, u32)) -> u64 {
        for _ in 0..6 {
            service.poll_once().await.unwrap();
            let status = service.status();
            // Automine mines a send after eth_sendTransaction returned, and
            // while it does, Anvil serves reads at the head block's number
            // from the state being mined: the next poll waits for the block.
            if let Some(hash) = status
                .pending_call
                .as_ref()
                .and_then(|call| call.transaction_hash.as_deref())
                .filter(|_| self.automine)
            {
                self.rpc.receipt(hash).await;
            }
            if let Some(last) = status
                .last_batch
                .as_ref()
                .filter(|last| (last.first_note_id, last.size) == expected)
            {
                assert_eq!(last.outcome, BatchOutcome::Activated);
                return last.gas_used.unwrap();
            }
            assert!(
                matches!(
                    status.state,
                    WorkerState::Submitted | WorkerState::Confirming
                ),
                "waiting for {expected:?}: {:?} ({:?}), last batch {:?}",
                status.state,
                status.detail,
                status.last_batch
            );
            self.rpc.mine().await;
        }
        panic!("the activation of {expected:?} was not confirmed");
    }
}

#[tokio::test]
async fn the_worker_activates_recorded_notes_on_the_real_vault() {
    let required = std::env::var("ZKAPI_REQUIRE_ANVIL").as_deref() == Ok("1");
    let (Some(forge), Some(anvil)) = (tool("forge"), tool("anvil")) else {
        assert!(
            !required,
            "ZKAPI_REQUIRE_ANVIL=1 but forge or anvil is not on PATH"
        );
        eprintln!("skipped: forge and anvil are not on PATH");
        return;
    };
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("deploy");
    std::fs::create_dir_all(project.join("script")).unwrap();
    let repo = Path::new(REPO).canonicalize().unwrap();
    let repo = repo.display();
    std::fs::write(
        project.join("foundry.toml"),
        format!(
            r#"[profile.default]
src = "script"
script = "script"
out = "out"
libs = ["{repo}/protocol/contracts/lib"]
allow_paths = ["{repo}/protocol/contracts"]
remappings = ["forge-std/={repo}/protocol/contracts/lib/forge-std/src/", "@openzeppelin/={repo}/protocol/contracts/lib/openzeppelin-contracts/", "zkapi/={repo}/protocol/contracts/src/"]
solc = "0.8.28"
optimizer = true
optimizer_runs = 10000
via_ir = true
"#
        ),
    )
    .unwrap();
    std::fs::write(project.join("script/Deploy.s.sol"), DEPLOY_SCRIPT).unwrap();
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(
        Command::new(anvil)
            .args(["--port", &port.to_string(), "--order", "fees", "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let rpc = Rpc {
        client: reqwest::Client::new(),
        url: url.clone(),
    };
    for _ in 0..100 {
        if rpc.call("eth_chainId", json!([])).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let output = Command::new(forge)
        .current_dir(&project)
        .args([
            "script",
            "script/Deploy.s.sol:Deploy",
            "--rpc-url",
            &url,
            "--private-key",
            DEPLOYER_KEY,
            "--broadcast",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "forge script failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let logged = |key: &str| {
        stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(&format!("{key}=")))
            .unwrap_or_else(|| panic!("forge printed no {key}"))
            .to_ascii_lowercase()
    };
    let (vault, adapter) = (logged("vault"), logged("adapter"));
    let broadcast: Value = serde_json::from_slice(
        &std::fs::read(project.join("broadcast/Deploy.s.sol/31337/run-latest.json")).unwrap(),
    )
    .unwrap();
    let poseidon = broadcast["transactions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|transaction| transaction["contractName"] == "Bn254Poseidon")
        .and_then(|transaction| transaction["contractAddress"].as_str())
        .expect("forge deployed the Poseidon library")
        .to_ascii_lowercase();

    // The indexer the worker takes the cursor slot's siblings from.
    let app = Router::new()
        .route("/v1/tree/notes/{id}/path", get(path))
        .with_state((rpc.clone(), vault.clone()));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let indexer_url = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

    let identity = StatementIdentity::load(SETUP_DIR).unwrap();
    let manifest = DeploymentManifest::parse(
        &json!({
            "chain_id": 31337,
            "contract_address": vault,
            "state_signing_key": { "x": "0xb", "y": "0xc" },
            "clearance_signing_key": { "x": "0xd", "y": "0xe" },
            "challenge_period": 86_400,
            "circuit_id": identity.circuit_id,
            "setup_id": identity.setup_id,
            "request_vk_keccak256": identity.request_vk_keccak256,
            "withdrawal_vk_keccak256": identity.withdrawal_vk_keccak256,
            "vault_runtime_codehash": rpc.code_hash(&vault).await,
            "proof_adapter_address": adapter,
            "adapter_runtime_codehash": rpc.code_hash(&adapter).await,
            "poseidon_library_address": poseidon,
            "poseidon_runtime_codehash": rpc.code_hash(&poseidon).await,
            "exit_concession": 1,
            "vault_revision": 4,
            "activator": WORKER,
        })
        .to_string(),
    )
    .unwrap();
    let config = ActivationServiceConfig {
        rpc_url: url.clone(),
        indexer_url,
        sender: WORKER.into(),
        contract_address: Felt252::from_hex(&vault).unwrap(),
        chain_id: 31_337,
        confirmations: 1,
        checkpoint: directory.path().join("activation.json"),
        proof_setup_dir: PathBuf::from(SETUP_DIR),
        fee: FeePolicy::new(100 * GWEI, 10 * GWEI),
        alarms: ActivationAlarmPolicy::default(),
        max_activation_wait_seconds: 0,
        dry_run: false,
    };
    let mut harness = Harness {
        rpc: rpc.clone(),
        vault: vault.clone(),
        config,
        deposits: 0,
        automine: true,
    };
    let mut service = ActivationService::new(harness.config.clone()).unwrap();
    // The deployed adapter is this build's circuit and setup, its insertion
    // verifying keys are the setup's, the vault is revision 4, and its
    // activator is the manifest's (the worker's sender). A manifest naming
    // another activator is refused.
    service.verify_deployment(&manifest).await.unwrap();
    assert_eq!(service.status().chain.activator.as_deref(), Some(WORKER));
    let mut other = manifest.clone();
    other.activator = Some(COMPETITOR.into());
    let error = service.verify_deployment(&other).await.unwrap_err();
    assert!(
        matches!(&error, DeploymentCheckError::Mismatch(message) if message.contains("activator")),
        "{error}"
    );

    // Low volume: singletons, each proved, verified on chain and confirmed
    // (one deposit at a 16-aligned cursor, then cursors aligned to 1 only).
    let mut gas = std::collections::BTreeMap::<u32, u64>::new();
    harness.deposit(1).await;
    gas.insert(1, harness.activate(&mut service, (0, 1)).await);
    harness.deposit(3).await;
    for first in 1..4 {
        gas.insert(1, harness.activate(&mut service, (first, 1)).await);
    }
    assert_eq!(harness.cursor().await, 4);
    harness.assert_tree().await;
    // A cursor aligned to 4: a full batch of 4 at once; then 4 at a time to
    // 16-alignment and a full batch of 16.
    harness.deposit(4 + 24).await;
    for expected in [(4, 4), (8, 4), (12, 4), (16, 16)] {
        gas.insert(expected.1, harness.activate(&mut service, expected).await);
    }
    service.poll_once().await.unwrap();
    assert_eq!(service.status().state, WorkerState::Idle);
    assert_eq!(harness.cursor().await, 32);
    harness.assert_tree().await;
    eprintln!("activateNotes gas used by batch size: {gas:?}");
    for (size, used) in &gas {
        assert!(*used < 1_000_000, "{size}-note activation used {used} gas");
    }

    // A competing on-chain activation outbids the worker's in the same
    // block: the worker's reverts StaleActivation(), and the next batch is
    // rebuilt from fresh state. The fallback opens only once no proved
    // activation landed for ACTIVATION_FALLBACK_DELAY (the worker's stays
    // pending meanwhile), which the status reports.
    harness.set_automine(false).await;
    harness.deposit(2).await;
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Submitted);
    let opens_at = rpc.number(&vault, "activationFallbackOpensAt()").await;
    assert_eq!(status.chain.activation_fallback_opens_at, Some(opens_at));
    let (tree, _) = vault_tree(&rpc, &vault).await;
    let competing = activate_on_chain_calldata(32, 1, &tree.get_siblings(32));
    let closed = rpc
        .call(
            "eth_call",
            json!([{ "from": COMPETITOR, "to": vault, "data": competing }, "latest"]),
        )
        .await
        .unwrap_err();
    assert!(
        closed
            .to_string()
            .contains(&selector("ActivationFallbackClosed()")[2..]),
        "{closed}"
    );
    let now = harness.now().await;
    rpc.ok("evm_increaseTime", json!([opens_at - now])).await;
    rpc.ok(
        "eth_sendTransaction",
        json!([{
            "from": COMPETITOR, "to": vault, "data": competing, "gas": "0x4c4b40",
            "maxFeePerGas": format!("0x{:x}", 500 * GWEI),
            "maxPriorityFeePerGas": format!("0x{:x}", 200 * GWEI),
        }]),
    )
    .await;
    rpc.mine().await;
    assert_eq!(harness.cursor().await, 33);
    service.poll_once().await.unwrap();
    assert_eq!(service.status().state, WorkerState::Confirming);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.totals.reverted_total, 1);
    assert_eq!(
        status.last_batch.as_ref().unwrap().outcome,
        BatchOutcome::Reverted
    );
    // The same poll built the fresh batch of note 33.
    assert_eq!(status.state, WorkerState::Submitted);
    assert_eq!(status.pending_call.as_ref().unwrap().first_note_id, 33);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(harness.cursor().await, 34);
    harness.assert_tree().await;

    // A dropped transaction is re-sent on its nonce, without proving again.
    harness.deposit(1).await;
    service.poll_once().await.unwrap();
    let pending = service.status().pending_call.unwrap();
    let proofs = service.status().totals.proofs_total;
    rpc.ok(
        "anvil_dropTransaction",
        json!([pending.transaction_hash.unwrap()]),
    )
    .await;
    service.poll_once().await.unwrap();
    let resent = service.status().pending_call.unwrap();
    assert_eq!(resent.nonce, pending.nonce);
    assert_eq!(resent.attempts, 2);
    assert_eq!(service.status().totals.proofs_total, proofs);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(harness.cursor().await, 35);

    // A restart with a pending call follows it to confirmation on its nonce.
    harness.deposit(1).await;
    service.poll_once().await.unwrap();
    let pending = service.status().pending_call.unwrap();
    drop(service);
    let mut service = ActivationService::new(harness.config.clone()).unwrap();
    service.verify_deployment(&manifest).await.unwrap();
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Submitted);
    assert_eq!(status.pending_call.unwrap().nonce, pending.nonce);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(harness.cursor().await, 36);
    harness.assert_tree().await;
    let status = service.status();
    assert_eq!(status.state, WorkerState::Idle);
    assert_eq!(
        (
            status.totals.batches_1_total,
            status.totals.batches_4_total,
            status.totals.batches_16_total,
            status.totals.notes_activated_total
        ),
        (7, 3, 1, 35)
    );
    // Every transaction of the worker's sender is accounted for: 11 batches
    // and the reverted one.
    let nonce = rpc
        .ok("eth_getTransactionCount", json!([WORKER, "latest"]))
        .await;
    assert_eq!(nonce, json!("0xc"));

    // A reorganization undoes the worker's mined activation before it is
    // confirmed (`evm_revert` drops the reverted transactions): the
    // persisted call is re-sent on its nonce, without proving again.
    harness.deposit(1).await;
    let snapshot = rpc.ok("evm_snapshot", json!([])).await;
    service.poll_once().await.unwrap();
    let pending = service.status().pending_call.unwrap();
    let proofs = service.status().totals.proofs_total;
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(service.status().state, WorkerState::Confirming);
    assert_eq!(harness.cursor().await, 37);
    assert_eq!(rpc.ok("evm_revert", json!([snapshot])).await, json!(true));
    assert_eq!(harness.cursor().await, 36);
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Submitted);
    let resent = status.pending_call.unwrap();
    assert_eq!((resent.nonce, resent.attempts), (pending.nonce, 2));
    assert_eq!(status.totals.proofs_total, proofs);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(harness.cursor().await, 37);
    harness.assert_tree().await;

    // This time the reorganization also replaces the batch's deposit by
    // another note at the same ID: cursor and root are unchanged, but the
    // vault would refuse the persisted proof (InvalidProof()). A fresh batch
    // is proved and sent on the nonce instead.
    let snapshot = rpc.ok("evm_snapshot", json!([])).await;
    harness.deposit(1).await;
    service.poll_once().await.unwrap();
    let pending = service.status().pending_call.unwrap();
    let proofs = service.status().totals.proofs_total;
    rpc.mine().await;
    service.poll_once().await.unwrap();
    assert_eq!(service.status().state, WorkerState::Confirming);
    assert_eq!(rpc.ok("evm_revert", json!([snapshot])).await, json!(true));
    harness.deposit(1).await;
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Submitted);
    let rebuilt = status.pending_call.unwrap();
    assert_eq!(
        (rebuilt.nonce, rebuilt.first_note_id, rebuilt.size),
        (pending.nonce, 37, 1)
    );
    assert_eq!(status.totals.proofs_total, proofs + 1);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Idle);
    assert_eq!(status.totals.reverted_total, 1);
    assert_eq!(harness.cursor().await, 38);
    harness.assert_tree().await;
    let nonce = rpc
        .ok("eth_getTransactionCount", json!([WORKER, "latest"]))
        .await;
    assert_eq!(nonce, json!("0xe"));

    // The owner names another activator: the vault refuses the worker's
    // activateNotes (NotActivator(), before anything else), and the worker
    // proves and sends nothing, reporting not_activator, until the owner
    // names its sender again.
    harness.set_activator(COMPETITOR).await;
    harness.deposit(1).await;
    let proofs = service.status().totals.proofs_total;
    service.poll_once().await.unwrap();
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Blocked);
    assert_eq!(status.blocked_reason, Some(ActivationBlocked::NotActivator));
    assert_eq!(status.chain.activator.as_deref(), Some(COMPETITOR));
    assert!(status.pending_call.is_none());
    assert_eq!(status.totals.proofs_total, proofs);
    for tag in ["latest", "pending"] {
        let nonce = rpc
            .ok("eth_getTransactionCount", json!([WORKER, tag]))
            .await;
        assert_eq!(nonce, json!("0xe"), "{tag}");
    }
    let root = Felt252(
        rpc.word(&vault, selector("currentRoot()"))
            .await
            .try_into()
            .unwrap(),
    );
    let refused = activate_calldata(38, 1, &root, &root, &[0; 256]).unwrap();
    let refused = rpc
        .call(
            "eth_call",
            json!([{ "from": WORKER, "to": vault, "data": format!("0x{}", hex::encode(refused)) }, "latest"]),
        )
        .await
        .unwrap_err();
    assert!(
        refused
            .to_string()
            .contains(&selector("NotActivator()")[2..]),
        "{refused}"
    );
    harness.set_activator(WORKER).await;
    service.poll_once().await.unwrap();
    assert_eq!(service.status().state, WorkerState::Submitted);
    rpc.mine().await;
    service.poll_once().await.unwrap();
    rpc.mine().await;
    service.poll_once().await.unwrap();
    let status = service.status();
    assert_eq!(status.state, WorkerState::Idle);
    assert_eq!(status.chain.activator.as_deref(), Some(WORKER));
    assert_eq!(harness.cursor().await, 39);
    harness.assert_tree().await;
    let nonce = rpc
        .ok("eth_getTransactionCount", json!([WORKER, "latest"]))
        .await;
    assert_eq!(nonce, json!("0xf"));
}
