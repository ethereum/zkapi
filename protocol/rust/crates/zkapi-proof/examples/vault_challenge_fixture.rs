//! Real-proof vault fixtures for circuit `zkapi-v2-concession-v2`:
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
//! stays at genesis. `notes` lists the 16 notes the fixtures deposit, in id
//! order: A, B, then notes 2 to 15 of other secrets (`notes[i]` holds what
//! the vault stores for note `i`, its packed `metadata` and its leaf).
//!
//! Activation (`support/activation.rs` format):
//! * `activate_a` then `activate_b`: one proved K = 1 batch each, from the
//!   empty tree (`empty_root`) to `root_a` and then `root_ab`, the root every
//!   request proof is at. `activate_c` and `activate_d` continue with notes 2
//!   and 3 to `root_abcd`.
//! * `activate_batch4`: notes 0 to 3 in one K = 4 batch from the empty tree,
//!   also to `root_abcd`; `activate_batch16`: notes 0 to 15 in one K = 16
//!   batch, to `root_16`.
//!
//! Withdrawals are bound to the stored note (input 3 is the registration
//! commitment, input 16 the packed amount and expiry), so every withdrawal
//! proof is valid whether or not its note is activated, and at any root.
//! Each is valid until `valid_until`.
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
//! * `escape_a2_expired` has `valid_until = timestamp - 1`; `ownership_a2` is
//!   kind 2 (rejected by the vault); `escape_b0_genesis_concede`, `close_b0`
//!   and `request_b0` use note B (same secret, disjoint nullifiers).
//! * Note binding: `escape_b0_foreign_commitment` (note 1 with another
//!   secret's commitment), `escape_b0_other_amount` (note 1 as if it held
//!   2,000,000 gwei: a genesis escape paying that out) and
//!   `escape_b0_other_expiry` (a day later) are valid proofs of statements
//!   whose commitment or packed values differ from what the vault stores for
//!   note 1, so the vault must refuse them (NoteBindingMismatch) before the
//!   adapter, which accepts them.
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

#[path = "support/activation.rs"]
mod activation;
use activation::{word, Activator, StoredNote};

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
        kind: WithdrawalKind,
        destination: [u8; 20],
        conceded: u128,
        valid_until: u64,
    ) -> Result<Fixture> {
        let (public, witness) = state.withdrawal(
            &self.deployment,
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
    let activator = Activator::load(&setup)?;
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
    let mut notes = vec![a.clone(), b.clone()];
    notes.extend((2..16u32).map(|note_id| DevNote {
        secret: Felt252::from_u64(1_000 + u64::from(note_id)),
        note_id,
        ..a.clone()
    }));
    let tree_ab = tree_with(&[&a, &b]);

    // Activations: A then B, then C and D; and the same notes in batches.
    let mut tree = MerkleTree::new();
    let empty_root = tree.root();
    let activate_a = activator.activate(&mut tree, &notes[0..1])?;
    let root_a = tree.root();
    let activate_b = activator.activate(&mut tree, &notes[1..2])?;
    anyhow::ensure!(tree.root() == tree_ab.root(), "A and B activate to root_ab");
    let activate_c = activator.activate(&mut tree, &notes[2..3])?;
    let activate_d = activator.activate(&mut tree, &notes[3..4])?;
    let root_abcd = tree.root();
    let mut batch_tree = MerkleTree::new();
    let activate_batch4 = activator.activate(&mut batch_tree, &notes[0..4])?;
    anyhow::ensure!(
        batch_tree.root() == root_abcd,
        "one K = 4 batch is four singletons"
    );
    let mut batch_tree = MerkleTree::new();
    let activate_batch16 = activator.activate(&mut batch_tree, &notes)?;
    let root_16 = batch_tree.root();

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
    // Note 1 as the vault does not store it: another secret's commitment, or
    // B's commitment with another amount or expiry. Genesis states need no
    // signature, so anyone can prove them.
    let unstored = |note: DevNote| note.genesis(Felt252::from_u64(8));
    let b0_foreign = unstored(DevNote {
        secret: Felt252::from_u64(43),
        ..b.clone()
    });
    let b0_other_amount = unstored(DevNote {
        deposit_amount: 2 * DEPOSIT,
        ..b.clone()
    });
    let b0_other_expiry = unstored(DevNote {
        expiry: expiry + 86_400,
        ..b.clone()
    });

    let w = |state: &DevState, kind, destination, conceded| {
        generator.withdrawal(state, kind, destination, conceded, VALID_UNTIL)
    };
    let mut fixtures = serde_json::Map::new();
    let mut put = |name: &str, fixture: Value| {
        fixtures.insert(name.to_string(), fixture);
    };
    let value = |fixture: Fixture| serde_json::to_value(fixture);
    put("activate_a", serde_json::to_value(activate_a)?);
    put("activate_b", serde_json::to_value(activate_b)?);
    put("activate_c", serde_json::to_value(activate_c)?);
    put("activate_d", serde_json::to_value(activate_d)?);
    put("activate_batch4", serde_json::to_value(activate_batch4)?);
    put("activate_batch16", serde_json::to_value(activate_batch16)?);
    put("request_a0", value(generator.request(&a0, &tree_ab, &r0)?)?);
    put("request_a1", value(generator.request(&a1, &tree_ab, &r1)?)?);
    put("request_a2", value(generator.request(&a2, &tree_ab, &r2)?)?);
    put("request_a3", value(generator.request(&a3, &tree_ab, &r3)?)?);
    put("request_b0", value(generator.request(&b0, &tree_ab, &r0)?)?);
    put(
        "escape_a0",
        value(w(&a0, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "escape_a1",
        value(w(&a1, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "escape_a2",
        value(w(&a2, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "escape_a2_concede",
        value(w(
            &a2,
            WithdrawalKind::Escape,
            DESTINATION,
            r2.solvency_bound,
        )?)?,
    );
    put(
        "escape_a2_other_destination",
        value(w(&a2, WithdrawalKind::Escape, [0x22; 20], 0)?)?,
    );
    put(
        "escape_a2_expired",
        value(generator.withdrawal(&a2, WithdrawalKind::Escape, DESTINATION, 0, TIMESTAMP - 1)?)?,
    );
    put(
        "escape_b0_genesis_concede",
        value(w(&b0, WithdrawalKind::Escape, DESTINATION, 250_000)?)?,
    );
    put(
        "escape_b0_foreign_commitment",
        value(w(&b0_foreign, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "escape_b0_other_amount",
        value(w(&b0_other_amount, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "escape_b0_other_expiry",
        value(w(&b0_other_expiry, WithdrawalKind::Escape, DESTINATION, 0)?)?,
    );
    put(
        "close_a2",
        value(w(&a2, WithdrawalKind::MutualClose, DESTINATION, 0)?)?,
    );
    put(
        "close_b0",
        value(w(&b0, WithdrawalKind::MutualClose, DESTINATION, 0)?)?,
    );
    put(
        "ownership_a2",
        value(w(&a2, WithdrawalKind::Ownership, [0; 20], 0)?)?,
    );

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
        "note_a_registration": word(&a.registration()),
        "note_b_registration": word(&b.registration()),
        "note_a_leaf": word(&a.leaf()),
        "note_b_leaf": word(&b.leaf()),
        "note_metadata": word(&zkapi_types::inputs::note_metadata(DEPOSIT, expiry)),
        "notes": notes.iter().map(StoredNote::of).collect::<Vec<_>>(),
        "empty_root": word(&empty_root),
        "root_a": word(&root_a),
        "root_ab": word(&tree_ab.root()),
        "root_abcd": word(&root_abcd),
        "root_16": word(&root_16),
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
