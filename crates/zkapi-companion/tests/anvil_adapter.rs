//! Companion proofs against this repository's verifying keys and the
//! generated adapter on Anvil (design §11 WP-E): an escape (kind 0), a
//! mutual close (kind 1) and an ownership proof (kind 2) made by the
//! companion's wallet verify in `assertValidWithdrawal` with the calldata
//! the companion builds, a changed public input does not, and the exit kit's
//! EIP-1559 signer gets a transaction mined.
//!
//! Needs `forge` and `anvil` on PATH; without them it reports a skip, and
//! with `ZKAPI_REQUIRE_ANVIL=1` (set by test-companion.sh when Foundry is
//! installed) it fails instead.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use serde_json::{json, Value};
use zkapi_client::config::{ClientConfig, ClientProofMode};
use zkapi_client::exit_lock::ExitMode;
use zkapi_client::wallet::Wallet;
use zkapi_companion::chain::{self, Rpc};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    withdrawal_public_inputs, CompactSigner, WithdrawalProver, WithdrawalStatementParams,
    WithdrawalWitnessData,
};
use zkapi_types::{Felt252, WithdrawalKind, MERKLE_DEPTH};

const SETUP_DIR: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../protocol/setup/v2-concession-dev"
);
/// Anvil's first default account.
const ANVIL_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
/// `assertValidWithdrawal(<the 16-field tuple>,bytes)`.
const ASSERT_VALID_WITHDRAWAL: &str = "9ea31c77";

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

fn build_adapter(directory: &Path) -> String {
    let project = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/anvil");
    for relative in [
        "foundry.toml",
        "src/libraries/Types.sol",
        "src/libraries/Errors.sol",
        "src/interfaces/IZkApiProofAdapter.sol",
    ] {
        let target = directory.join(relative);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        std::fs::copy(project.join(relative), target).unwrap();
    }
    std::fs::create_dir_all(directory.join("src/adapters")).unwrap();
    std::fs::copy(
        Path::new(SETUP_DIR).join("Groth16ProofAdapter.sol"),
        directory.join("src/adapters/Groth16ProofAdapter.sol"),
    )
    .unwrap();
    directory.to_string_lossy().into_owned()
}

fn wallet_config(state_dir: &Path, contract: Felt252) -> ClientConfig {
    ClientConfig {
        protocol_version: 2,
        chain_id: 31_337,
        contract_address: contract,
        request_charge_cap: 1_000,
        policy_charge_cap: 1_000,
        policy_enabled: false,
        server_url: "http://127.0.0.1:1".into(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        proof_mode: ClientProofMode::Groth16 {
            setup_dir: SETUP_DIR.into(),
        },
        state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
        clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
        settlement_window_seconds: 1_800,
    }
}

#[tokio::test]
async fn companion_proofs_verify_in_the_generated_adapter_on_anvil() {
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
    let root = build_adapter(&directory.path().join("adapter"));
    let port = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let url = format!("http://127.0.0.1:{port}");
    let _anvil = Anvil(
        Command::new(anvil)
            .args(["--port", &port.to_string(), "--silent"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let rpc = Rpc::new(&url).unwrap();
    for _ in 0..100 {
        if rpc.request("eth_chainId", json!([])).await.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let output = Command::new(forge)
        .args([
            "create",
            "--root",
            &root,
            "src/adapters/Groth16ProofAdapter.sol:Groth16ProofAdapter",
            "--rpc-url",
            &url,
            "--private-key",
            &format!("0x{ANVIL_KEY}"),
            "--broadcast",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "forge create failed: {stdout}{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let adapter_hex = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("Deployed to: "))
        .expect("forge create prints the address")
        .trim()
        .to_string();
    let adapter: [u8; 20] = hex::decode(adapter_hex.trim_start_matches("0x"))
        .unwrap()
        .try_into()
        .unwrap();

    // The adapter is this setup's: circuit and withdrawal VK hash.
    let manifest: Value =
        serde_json::from_slice(&std::fs::read(Path::new(SETUP_DIR).join("manifest.json")).unwrap())
            .unwrap();
    let circuit = rpc.call(&adapter, "0xda0e8385", "latest").await.unwrap();
    assert_eq!(
        circuit,
        "0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687"
    );
    let withdrawal_vk = rpc.call(&adapter, "0x7fcd0926", "latest").await.unwrap();
    assert_eq!(
        withdrawal_vk.trim_start_matches("0x"),
        manifest["vk_keccak256"]["withdrawal"]
            .as_str()
            .unwrap()
            .trim_start_matches("0x")
    );

    // Proofs from the companion's wallet for a note in a non-trivial tree.
    let vault = [0x42u8; 20];
    let contract = zkapi_types::serialization::address_to_felt(&vault);
    let secret = Felt252::from_u64(777);
    let leaf = core::note_leaf(
        6,
        &core::registration_commitment(&secret),
        3_000_000,
        4_000_000_000,
    );
    let mut tree = zkapi_client::tree::SparseTree::new();
    tree.set_leaf(5, Felt252::from_u64(55));
    tree.set_leaf(6, leaf);
    let (root_felt, siblings) = (tree.root(), tree.siblings(6).to_vec());
    let escape_dir = directory.path().join("escape");
    let mut wallet = Wallet::new(wallet_config(&escape_dir, contract)).unwrap();
    wallet
        .confirm_deposit(secret, 6, 3_000_000, 4_000_000_000)
        .unwrap();
    wallet
        .prepare_request_with_bound(
            "{}",
            zkapi_types::canonical_payload_hash(b"{}"),
            root_felt,
            siblings.clone(),
            1_000,
        )
        .unwrap();
    wallet.set_exit_lock(ExitMode::Escape).unwrap();
    let (escape, escape_proof) = wallet
        .withdrawal_escape_hatch([0x99; 20], 1_000, root_felt, siblings.clone())
        .unwrap();
    let mutual_dir = directory.path().join("mutual");
    let mut mutual = Wallet::new(wallet_config(&mutual_dir, contract)).unwrap();
    mutual
        .confirm_deposit(secret, 6, 3_000_000, 4_000_000_000)
        .unwrap();
    mutual.set_exit_lock(ExitMode::Mutual).unwrap();
    let ownership = mutual.ownership_proof(root_felt, siblings.clone()).unwrap();
    // A close (kind 1) under a clearance signature, proved directly.
    let state = mutual.state().unwrap().clone();
    let nullifier = core::nullifier(&secret, 6, &state.current_anchor);
    let clearance = CompactSigner::from_seed(&Felt252::from_u64(12))
        .sign(&core::clearance_message(2, 31_337, &contract, &nullifier));
    let params = WithdrawalStatementParams {
        protocol_version: 2,
        chain_id: 31_337,
        contract_address: contract,
        active_root: root_felt,
        state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
        clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
        note_id: 6,
        destination: [0x98; 20],
    };
    let witness = WithdrawalWitnessData {
        secret,
        deposit_amount: 3_000_000,
        expiry: 4_000_000_000,
        merkle_siblings: <[Felt252; MERKLE_DEPTH]>::try_from(siblings.clone()).unwrap(),
        state_balance: 3_000_000,
        state_blinding: Felt252::from_hex(&state.balance_blinding).unwrap(),
        current_anchor: state.current_anchor,
        kind: WithdrawalKind::MutualClose,
        conceded: 0,
        valid_until: 4_000_000_000,
        state_signature: None,
        clearance_signature: Some(clearance),
    };
    let close = withdrawal_public_inputs(&params, &witness).unwrap();
    let close_proof = WithdrawalProver::load(SETUP_DIR)
        .unwrap()
        .prove(&close, witness)
        .unwrap();

    let as_assert = |data: String| format!("0x{ASSERT_VALID_WITHDRAWAL}{}", &data[10..]);
    for (label, inputs, proof) in [
        ("escape", &escape, &escape_proof),
        ("close", &close, &close_proof),
        ("ownership", &ownership.public_inputs, &ownership.proof),
    ] {
        let data = chain::withdrawal_calldata(chain::INITIATE_ESCAPE, inputs, proof).unwrap();
        assert_eq!(data.len(), 2 + 836 * 2, "{label}");
        let result = rpc.call(&adapter, &as_assert(data.clone()), "latest").await;
        assert_eq!(result.unwrap(), "0x", "{label} verifies");
        // Any changed public input fails.
        let mut changed = inputs.clone();
        changed.valid_until += 1;
        let data = chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &changed, proof).unwrap();
        assert!(
            rpc.call(&adapter, &as_assert(data), "latest")
                .await
                .is_err(),
            "{label}: a changed valid_until must not verify"
        );
    }

    // The exit kit's signer: a mined EIP-1559 transaction.
    let data = as_assert(
        chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &escape, &escape_proof).unwrap(),
    );
    let key: [u8; 32] = hex::decode(ANVIL_KEY).unwrap().try_into().unwrap();
    let hash = zkapi_companion::exit_kit::sign_and_send(&rpc, &key, 31_337, &adapter, &data)
        .await
        .unwrap();
    let mut receipt = Value::Null;
    for _ in 0..50 {
        if let Some(found) = rpc.receipt(&hash).await.unwrap() {
            receipt = found;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(receipt["status"], "0x1", "{receipt}");
}
