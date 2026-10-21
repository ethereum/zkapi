//! Prove with the shipped JS/WASM/key bundle and verify natively against the
//! development setup (`protocol/setup/v2-concession-dev`).
//!
//! Usage: wasm_roundtrip /absolute/path/to/prove-browser-fixture.mjs /absolute/sdk
//!
//! The fixture asks the bundle for a genesis request and an escape (kind 0,
//! `conceded = 0`, `valid_until`) to the destination below; both proofs and
//! the escape's canonical fields are checked here. It needs a bundle built
//! for circuit `zkapi-v2-concession-v1` with the development setup.
use anyhow::{Context, Result};
use serde_json::json;
use std::{
    io::Write,
    process::{Command, Stdio},
};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{CompactSigner, RequestVerifier, WithdrawalVerifier, CIRCUIT_ID};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalPublicInputsV2C, MERKLE_DEPTH};

const VALID_UNTIL: u64 = 2_000_010_800;

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    anyhow::ensure!(
        args.len() == 3,
        "usage: wasm_roundtrip PROVER_SCRIPT SDK_DIRECTORY"
    );
    let secret = Felt252::from_u64(42);
    let expiry = 4_000_000_000u64;
    let siblings = &core::zero_hashes()[..MERKLE_DEPTH];
    let leaf = core::note_leaf(
        0,
        &core::registration_commitment(&secret),
        1_000_000,
        expiry,
    );
    let root = core::merkle_root(0, &leaf, siblings.try_into().unwrap());
    let fixture = json!({
        "circuit_id": CIRCUIT_ID,
        "config": { "protocol_version": 2, "chain_id": 31337, "contract_address": "0x1234",
            "request_charge_cap": 500000, "policy_charge_cap": 500000, "policy_enabled": false,
            "state_signing_key": CompactSigner::from_seed(&Felt252::ONE).public_key(),
            "clearance_signing_key": CompactSigner::from_seed(&Felt252::from_u64(2)).public_key() },
        "deposit": { "secret": secret, "note_id": 0, "amount": 1000000, "expiry_ts": expiry },
        "request": { "payload": "browser artifact test", "active_root": root, "merkle_siblings": siblings,
            "client_request_id": "wasm-roundtrip", "request_time": 2000000000u64, "created_at_ms": 2000000000000u64 },
        "withdrawal": { "mode": "escape", "destination": "0x1111111111111111111111111111111111111111",
            "conceded": 0, "valid_until": VALID_UNTIL, "active_root": root, "merkle_siblings": siblings }
    });
    let mut child = Command::new("node")
        .args(&args[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    child
        .stdin
        .take()
        .context("child stdin")?
        .write_all(serde_json::to_string(&fixture)?.as_bytes())?;
    let output = child.wait_with_output()?;
    anyhow::ensure!(output.status.success(), "WASM prover failed");
    let proofs: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let setup =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2-concession-dev");
    let request: RequestPublicInputsV2 =
        serde_json::from_value(proofs["request"]["public_inputs"].clone())?;
    anyhow::ensure!(
        RequestVerifier::load(&setup)?.verify(
            &request,
            &serde_json::from_value(proofs["request"]["proof"].clone())?
        )?,
        "WASM request proof invalid"
    );
    anyhow::ensure!(
        request.request_nullifier == core::nullifier(&secret, 0, &core::GENESIS_ANCHOR),
        "WASM request nullifier is not the note-bound genesis nullifier"
    );
    let withdrawal: WithdrawalPublicInputsV2C =
        serde_json::from_value(proofs["withdrawal"]["public_inputs"].clone())?;
    anyhow::ensure!(
        WithdrawalVerifier::load(&setup)?.verify(
            &withdrawal,
            &serde_json::from_value(proofs["withdrawal"]["proof"].clone())?
        )?,
        "WASM withdrawal proof invalid"
    );
    anyhow::ensure!(
        withdrawal.kind == 0
            && withdrawal.conceded == 0
            && withdrawal.valid_until == VALID_UNTIL
            && withdrawal.next_nullifier
                == core::successor_nullifier(&secret, 0, &core::GENESIS_ANCHOR),
        "WASM escape statement is not canonical"
    );
    println!("Shipped WASM request and escape withdrawal proofs verified natively.");
    Ok(())
}
