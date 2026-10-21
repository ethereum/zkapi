//! `zkapi-challenged` refuses a server database without the append-only
//! request evidence (§5.5, §11 WP-C), before it touches its checkpoint or
//! makes any RPC call: every escape would otherwise read as nothing due.

use std::path::Path;
use std::process::Command;

use zkapi_serverd::nullifier_store::NullifierStore;

/// A deployment manifest the daemon parses; nothing is read from the chain
/// before the database check.
fn write_manifest(path: &Path) {
    let hash = |byte: &str| format!("0x{}", byte.repeat(32));
    let manifest = serde_json::json!({
        "chain_id": 1,
        "contract_address": "0x000000000000000000000000000000000000dead",
        "state_signing_key": { "x": "0x1", "y": "0x2" },
        "clearance_signing_key": { "x": "0x3", "y": "0x4" },
        "challenge_period": 172_800,
        "circuit_id": "zkapi-v2-concession-v1",
        "setup_id": "dev",
        "request_vk_keccak256": hash("11"),
        "withdrawal_vk_keccak256": hash("22"),
        "vault_runtime_codehash": hash("33"),
        "proof_adapter_address": "0x00000000000000000000000000000000000a11a5",
        "adapter_runtime_codehash": hash("44"),
        "poseidon_library_address": "0x0000000000000000000000000000000000000bee",
        "poseidon_runtime_codehash": hash("55"),
        "settlement_window_seconds": 21_905,
        "exit_concession": 1,
    });
    std::fs::write(path, manifest.to_string()).unwrap();
}

fn run_challenged(directory: &Path, db: &Path) -> std::process::Output {
    let setup =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/setup/v2-concession-dev");
    Command::new(env!("CARGO_BIN_EXE_zkapi-challenged"))
        .args([
            "--rpc-url",
            "http://127.0.0.1:1",
            "--indexer-url",
            "http://127.0.0.1:1",
            "--sender",
            "0x0000000000000000000000000000000000000001",
            "--from-block",
            "0",
            "--max-fee-per-gas-wei",
            "100000000000",
            "--max-priority-fee-per-gas-wei",
            "10000000000",
            "--status-listen",
            "127.0.0.1:0",
        ])
        .arg("--deployment")
        .arg(directory.join("deployment.json"))
        .arg("--db-path")
        .arg(db)
        .arg("--checkpoint")
        .arg(directory.join("checkpoint/challenges.json"))
        .arg("--proof-setup-dir")
        .arg(setup)
        .output()
        .unwrap()
}

#[test]
fn challenged_refuses_a_database_without_request_evidence() {
    let directory = tempfile::tempdir().unwrap();
    write_manifest(&directory.path().join("deployment.json"));
    let db = directory.path().join("server.db");

    // No database at all.
    let output = run_challenged(directory.path(), &db);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("run `zkapi db init` first"), "{stderr}");

    // A server database of the schema before the concession exit: no
    // append-only request evidence.
    drop(NullifierStore::new(&db).unwrap());
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch(
            "DROP TRIGGER request_evidence_no_update;
             DROP TRIGGER request_evidence_no_delete;
             DROP TABLE request_evidence;",
        )
        .unwrap();
    let output = run_challenged(directory.path(), &db);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("run `zkapi db init` first"), "{stderr}");
    // Refused before the checkpoint or its lock is created.
    assert!(!directory.path().join("checkpoint").exists());

    // The evidence table without its append-only triggers is refused too.
    std::fs::remove_file(&db).unwrap();
    drop(NullifierStore::new(&db).unwrap());
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute_batch("DROP TRIGGER request_evidence_no_delete;")
        .unwrap();
    let output = run_challenged(directory.path(), &db);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("run `zkapi db init` first"));
}
