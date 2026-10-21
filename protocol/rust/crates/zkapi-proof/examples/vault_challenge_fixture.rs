//! Real-proof vault fixtures for circuit `zkapi-v2-concession-v1`:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example vault_challenge_fixture -- \
//!   ../setup/v2-concession-dev > ../contracts/test/fixtures/vault-challenge.json
//! ```
//!
//! Deployment: chain 31337, the vault CREATEd by `0xf00d` at nonce 0, the
//! development keys, deposits of 1,000,000 gwei at `timestamp` with a 30-day
//! TTL (so `expiry` is the vault's bucketed expiry).
//!
//! Note A (id 0) has the honest chain `a0 -R0-> a1 -R1-> a2 -R2-> a3`, each
//! successor signed at `next_anchor(N)`. Note B (id 1) shares A's secret and
//! stays at genesis. Every proof is at root `ab` (A and B deposited) unless
//! named otherwise, and is valid until `valid_until`.
//!
//! * Withholding: the user at `a2` sent R2 (`request_a2`, `sb = 100,000`) and
//!   the operator withheld `a3`. `escape_a2_concede` concedes `sb`
//!   (payout `B2 - sb2`); `escape_a2` concedes 0 and `request_a2` is the
//!   operator's raise evidence (state evidence at `N2`).
//! * Defeat: `request_a3` (from the successor `a3`) is at
//!   `escape_a2.next_nullifier`; `request_a2` is not successor evidence.
//! * Re-escapes after that defeat: `escape_a2` again (ChallengedNullifier),
//!   `escape_a1` (SupersededState: its next nullifier `N2` was flagged),
//!   `escape_a0` (verified, then defeated by `request_a1`).
//! * `escape_a2_at_root_a` is at the root before B's deposit; `escape_a2_expired`
//!   has `valid_until = timestamp - 1`; `ownership_a2` is kind 2 (rejected by
//!   the vault); `escape_b0_genesis_concede`, `close_b0` and `request_b0` use
//!   note B (same secret, disjoint nullifiers).
use anyhow::{Context, Result};
use base64::Engine;
use serde::Serialize;
use serde_json::{json, Value};
use zkapi_core::MerkleTree;
use zkapi_proof::compact::{
    RequestProver, RequestVerifier, WithdrawalProver, WithdrawalVerifier, CIRCUIT_ID,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, WithdrawalKind};

const TIMESTAMP: u64 = 2_000_000_000;
const NOTE_TTL: u64 = 30 * 86_400;
const DEPOSIT: u128 = 1_000_000;
const VALID_UNTIL: u64 = TIMESTAMP + 7 * 86_400;
// CREATE from address(0xf00d), nonce 0. The Forge test deploys normally there.
const VAULT: &str = "0xFb1b848e938aE6474F890bfb28f6a793a515BAcb";
const DESTINATION: [u8; 20] = [0x11; 20];

#[derive(Serialize)]
struct Fixture {
    public_inputs: Value,
    inputs_abi: String,
    proof_hex: String,
}

struct Generator {
    requests: RequestProver,
    request_verifier: RequestVerifier,
    withdrawals: WithdrawalProver,
    withdrawal_verifier: WithdrawalVerifier,
    deployment: DevDeployment,
}

impl Generator {
    fn request(
        &self,
        state: &DevState,
        tree: &MerkleTree,
        request: &DevRequest,
    ) -> Result<Fixture> {
        let (public, witness) = state.request(&self.deployment, tree, request)?;
        let proof = self.requests.prove(&public, witness)?;
        anyhow::ensure!(
            self.request_verifier.verify(&public, &proof)?,
            "request proof failed"
        );
        fixture(
            serde_json::to_value(&public)?,
            &public.to_field_elements(),
            &proof,
        )
    }

    fn withdrawal(
        &self,
        state: &DevState,
        tree: &MerkleTree,
        kind: WithdrawalKind,
        destination: [u8; 20],
        conceded: u128,
        valid_until: u64,
    ) -> Result<Fixture> {
        let (public, witness) = state.withdrawal(
            &self.deployment,
            tree,
            &DevWithdrawal {
                kind,
                destination,
                conceded,
                valid_until,
            },
        )?;
        let proof = self.withdrawals.prove(&public, witness)?;
        anyhow::ensure!(
            self.withdrawal_verifier.verify(&public, &proof)?,
            "withdrawal proof failed"
        );
        fixture(
            serde_json::to_value(&public)?,
            &public.to_field_elements(),
            &proof,
        )
    }
}

fn fixture(public_inputs: Value, inputs: &[Felt252], proof: &Groth16ProofWire) -> Result<Fixture> {
    // Both Solidity public-input structs are static ABI tuples in this order.
    let inputs = inputs
        .iter()
        .flat_map(|field| field.as_bytes().iter().copied())
        .collect::<Vec<_>>();
    let proof = base64::engine::general_purpose::STANDARD.decode(&proof.proof)?;
    Ok(Fixture {
        public_inputs,
        inputs_abi: format!("0x{}", hex::encode(inputs)),
        proof_hex: format!("0x{}", hex::encode(proof)),
    })
}

fn state_summary(state: &DevState) -> Value {
    json!({
        "note_id": state.note.note_id,
        "balance": state.balance,
        "anchor": state.anchor,
        "nullifier": state.nullifier(),
        "successor_nullifier": state.successor_nullifier(),
    })
}

fn request(solvency_bound: u128, context: u64, rerandomization: u64) -> DevRequest {
    DevRequest {
        request_time: TIMESTAMP,
        solvency_bound,
        request_context: Felt252::from_u64(context),
        rerandomization: Felt252::from_u64(rerandomization),
    }
}

fn main() -> Result<()> {
    let setup = std::env::args()
        .nth(1)
        .context("usage: vault_challenge_fixture SETUP_DIRECTORY")?;
    let generator = Generator {
        requests: RequestProver::load(&setup)?,
        request_verifier: RequestVerifier::load(&setup)?,
        withdrawals: WithdrawalProver::load(&setup)?,
        withdrawal_verifier: WithdrawalVerifier::load(&setup)?,
        deployment: DevDeployment::new(
            31_337,
            Felt252::from_hex(VAULT).map_err(anyhow::Error::msg)?,
        ),
    };
    let deployment = &generator.deployment;
    let expiry = (TIMESTAMP + NOTE_TTL).div_ceil(86_400) * 86_400;
    let a = DevNote {
        secret: Felt252::from_u64(42),
        note_id: 0,
        deposit_amount: DEPOSIT,
        expiry,
    };
    let b = DevNote {
        note_id: 1,
        ..a.clone()
    };
    let tree_a = tree_with(&[&a]);
    let tree_ab = tree_with(&[&a, &b]);

    let (r0, r1, r2, r3) = (
        request(100_000, 99, 9),
        request(200_000, 100, 11),
        request(100_000, 101, 13),
        request(100_000, 102, 15),
    );
    let a0 = a.genesis(Felt252::from_u64(7));
    let a1 = a0.successor(deployment, &r0, 60_000, &Felt252::from_u64(17))?;
    let a2 = a1.successor(deployment, &r1, 150_000, &Felt252::from_u64(19))?;
    let a3 = a2.successor(deployment, &r2, 40_000, &Felt252::from_u64(21))?;
    let b0 = b.genesis(Felt252::from_u64(8));

    let w = |state: &DevState, kind, destination, conceded| {
        generator.withdrawal(state, &tree_ab, kind, destination, conceded, VALID_UNTIL)
    };
    let mut fixtures = serde_json::Map::new();
    let mut put = |name: &str, fixture: Fixture| -> Result<()> {
        fixtures.insert(name.to_string(), serde_json::to_value(fixture)?);
        Ok(())
    };
    put("request_a0", generator.request(&a0, &tree_ab, &r0)?)?;
    put("request_a1", generator.request(&a1, &tree_ab, &r1)?)?;
    put("request_a2", generator.request(&a2, &tree_ab, &r2)?)?;
    put("request_a3", generator.request(&a3, &tree_ab, &r3)?)?;
    put("request_b0", generator.request(&b0, &tree_ab, &r0)?)?;
    put("escape_a0", w(&a0, WithdrawalKind::Escape, DESTINATION, 0)?)?;
    put("escape_a1", w(&a1, WithdrawalKind::Escape, DESTINATION, 0)?)?;
    put("escape_a2", w(&a2, WithdrawalKind::Escape, DESTINATION, 0)?)?;
    put(
        "escape_a2_concede",
        w(&a2, WithdrawalKind::Escape, DESTINATION, r2.solvency_bound)?,
    )?;
    put(
        "escape_a2_other_destination",
        w(&a2, WithdrawalKind::Escape, [0x22; 20], 0)?,
    )?;
    put(
        "escape_a2_at_root_a",
        generator.withdrawal(
            &a2,
            &tree_a,
            WithdrawalKind::Escape,
            DESTINATION,
            0,
            VALID_UNTIL,
        )?,
    )?;
    put(
        "escape_a2_expired",
        generator.withdrawal(
            &a2,
            &tree_ab,
            WithdrawalKind::Escape,
            DESTINATION,
            0,
            TIMESTAMP - 1,
        )?,
    )?;
    put(
        "escape_b0_genesis_concede",
        w(&b0, WithdrawalKind::Escape, DESTINATION, 250_000)?,
    )?;
    put(
        "close_a2",
        w(&a2, WithdrawalKind::MutualClose, DESTINATION, 0)?,
    )?;
    put(
        "close_b0",
        w(&b0, WithdrawalKind::MutualClose, DESTINATION, 0)?,
    )?;
    put(
        "ownership_a2",
        w(&a2, WithdrawalKind::Ownership, [0; 20], 0)?,
    )?;

    let mut out = json!({
        "circuit_id": CIRCUIT_ID,
        "setup_id": generator.requests.setup_id(),
        "chain_id": deployment.chain_id,
        "vault": VAULT,
        "timestamp": TIMESTAMP,
        "note_ttl": NOTE_TTL,
        "expiry": expiry,
        "deposit": DEPOSIT,
        "valid_until": VALID_UNTIL,
        "destination": format!("0x{}", hex::encode(DESTINATION)),
        "state_signing_key": deployment.state_key(),
        "clearance_signing_key": deployment.clearance_key(),
        "note_a_registration": a.registration(),
        "note_b_registration": b.registration(),
        "note_a_leaf": a.leaf(),
        "note_b_leaf": b.leaf(),
        "root_a": tree_a.root(),
        "root_ab": tree_ab.root(),
        "states": {
            "a0": state_summary(&a0),
            "a1": state_summary(&a1),
            "a2": state_summary(&a2),
            "a3": state_summary(&a3),
            "b0": state_summary(&b0),
        },
        "charges": { "r0": 60_000, "r1": 150_000, "r2": 40_000 },
        "solvency_bounds": {
            "r0": r0.solvency_bound, "r1": r1.solvency_bound,
            "r2": r2.solvency_bound, "r3": r3.solvency_bound,
        },
    });
    let object = out.as_object_mut().context("fixture object")?;
    object.extend(fixtures);
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
