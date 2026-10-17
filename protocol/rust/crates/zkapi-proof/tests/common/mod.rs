//! Shared statement fixtures: an honest state chain, note activations, the
//! positive cases and every negative case of the WP-A test plan, at the
//! circuit level.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisMode};
use zkapi_core::v2 as core;
use zkapi_core::MerkleTree;
use zkapi_proof::compact::{
    request_circuit, withdrawal_circuit, KeyKind, RequestWitnessData, WithdrawalWitnessData,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_proof::groth16::{synthesize, RequestCircuit, WithdrawalCircuit};
use zkapi_proof::insertion::{
    insertion_roots, InsertedNote, InsertionCircuit, InsertionPublic, InsertionWitness,
    INSERTION_SIZES,
};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalKind, WithdrawalPublicInputsV2C};

pub const CHAIN_ID: u64 = 31_337;
pub const DEPOSIT: u128 = 1_000_000;
pub const EXPIRY: u64 = 4_000_000_000;
pub const REQUEST_TIME: u64 = 2_000_000_000;
pub const VALID_UNTIL: u64 = REQUEST_TIME + 10_800;
pub const DESTINATION: [u8; 20] = [0x11; 20];

/// The committed development setup.
pub fn dev_setup_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2-concession-dev")
}

/// The setup under test: `ZKAPI_SETUP_DIR` if set (absolute, or relative to
/// `protocol/rust`, where the setup READMEs run their commands), otherwise
/// the development setup. G-SETUP step 7 runs `tests/proofs.rs` on the
/// imported ceremony keys this way:
/// `ZKAPI_SETUP_DIR=../setup/v2-concession cargo test --release -p zkapi-proof --test proofs`.
pub fn setup_dir() -> std::path::PathBuf {
    match std::env::var_os("ZKAPI_SETUP_DIR") {
        Some(dir) if !dir.is_empty() => {
            let dir = std::path::PathBuf::from(dir);
            if dir.is_absolute() {
                dir
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../..")
                    .join(dir)
            }
        }
        _ => dev_setup_dir(),
    }
}

/// Note A's honest chain `S0 -R0-> S1 -R1-> S2`, plus note B with A's secret.
pub struct Chain {
    pub deployment: DevDeployment,
    pub note: DevNote,
    pub same_secret_note: DevNote,
    pub tree: MerkleTree,
    pub s0: DevState,
    pub r0: DevRequest,
    pub s1: DevState,
    pub r1: DevRequest,
    pub s2: DevState,
    pub r2: DevRequest,
}

pub fn request(solvency_bound: u128, context: u64, rerandomization: u64) -> DevRequest {
    DevRequest {
        request_time: REQUEST_TIME,
        solvency_bound,
        request_context: Felt252::from_u64(context),
        rerandomization: Felt252::from_u64(rerandomization),
    }
}

pub fn chain() -> Chain {
    let deployment = DevDeployment::new(CHAIN_ID, Felt252::from_u64(0x1234));
    let note = DevNote {
        secret: Felt252::from_u64(42),
        note_id: 0,
        deposit_amount: DEPOSIT,
        expiry: EXPIRY,
    };
    let same_secret_note = DevNote {
        note_id: 1,
        ..note.clone()
    };
    let tree = tree_with(&[&note, &same_secret_note]);
    let s0 = note.genesis(Felt252::from_u64(7));
    let r0 = request(100_000, 99, 9);
    let s1 = s0
        .successor(&deployment, &r0, 60_000, &Felt252::from_u64(17))
        .unwrap();
    let r1 = request(200_000, 100, 11);
    let s2 = s1
        .successor(&deployment, &r1, 150_000, &Felt252::from_u64(19))
        .unwrap();
    let r2 = request(100_000, 101, 13);
    Chain {
        deployment,
        note,
        same_secret_note,
        tree,
        s0,
        r0,
        s1,
        r1,
        s2,
        r2,
    }
}

pub fn withdrawal(kind: WithdrawalKind, destination: [u8; 20], conceded: u128) -> DevWithdrawal {
    DevWithdrawal {
        kind,
        destination,
        conceded,
        valid_until: VALID_UNTIL,
    }
}

impl Chain {
    pub fn request_of(
        &self,
        state: &DevState,
        request: &DevRequest,
    ) -> (RequestPublicInputsV2, RequestWitnessData) {
        state
            .request(&self.deployment, &self.tree, request)
            .unwrap()
    }

    pub fn withdrawal_of(
        &self,
        state: &DevState,
        withdrawal: &DevWithdrawal,
    ) -> (WithdrawalPublicInputsV2C, WithdrawalWitnessData) {
        state.withdrawal(&self.deployment, withdrawal).unwrap()
    }

    /// The canonical withdrawal statement for `state` without the builder's
    /// rule checks (for states the honest builder refuses).
    pub fn withdrawal_unchecked(
        &self,
        state: &DevState,
        withdrawal: &DevWithdrawal,
    ) -> (WithdrawalPublicInputsV2C, WithdrawalWitnessData) {
        let state_key = self.deployment.state_key();
        let clearance_key = self.deployment.clearance_key();
        let escape = withdrawal.kind == WithdrawalKind::Escape;
        let public = WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: CHAIN_ID,
            contract_address: self.deployment.contract_address,
            registration_commitment: state.note.registration(),
            state_signing_key_x: state_key.x,
            state_signing_key_y: state_key.y,
            clearance_signing_key_x: clearance_key.x,
            clearance_signing_key_y: clearance_key.y,
            note_id: state.note.note_id,
            final_balance: state.balance - withdrawal.conceded,
            destination: withdrawal.destination,
            withdrawal_nullifier: state.nullifier(),
            kind: withdrawal.kind.as_u8(),
            next_nullifier: if escape {
                state.successor_nullifier()
            } else {
                Felt252::ZERO
            },
            conceded: withdrawal.conceded,
            valid_until: withdrawal.valid_until,
            deposit_amount: state.note.deposit_amount,
            expiry: state.note.expiry,
        };
        let witness = WithdrawalWitnessData {
            secret: state.note.secret,
            deposit_amount: state.note.deposit_amount,
            expiry: state.note.expiry,
            state_balance: state.balance,
            state_blinding: state.blinding,
            current_anchor: state.anchor,
            kind: withdrawal.kind,
            conceded: withdrawal.conceded,
            valid_until: withdrawal.valid_until,
            state_signature: state.signature,
            clearance_signature: (withdrawal.kind == WithdrawalKind::MutualClose)
                .then(|| self.deployment.sign_clearance(&state.nullifier())),
        };
        (public, witness)
    }

    /// A withdrawal statement built without the builder's rule checks.
    #[allow(clippy::too_many_arguments)]
    pub fn raw_withdrawal(
        &self,
        state: &DevState,
        kind: u8,
        destination: [u8; 20],
        conceded: u128,
        final_balance: u128,
        next_nullifier: Felt252,
        clearance: bool,
    ) -> (WithdrawalPublicInputsV2C, WithdrawalWitnessData) {
        let (mut public, mut witness) =
            self.withdrawal_unchecked(state, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
        public.kind = kind;
        public.destination = destination;
        public.conceded = conceded;
        public.final_balance = final_balance;
        public.next_nullifier = next_nullifier;
        witness.conceded = conceded;
        witness.clearance_signature =
            clearance.then(|| self.deployment.sign_clearance(&state.nullifier()));
        (public, witness)
    }
}

/// `count` notes from id `first`, with distinct secrets, amounts and expiries.
pub fn batch_notes(first: u32, count: usize) -> Vec<DevNote> {
    (first..first + count as u32)
        .map(|note_id| DevNote {
            secret: Felt252::from_u64(1_000 + u64::from(note_id)),
            note_id,
            deposit_amount: DEPOSIT + 1_000 * u128::from(note_id),
            expiry: EXPIRY + 86_400 * u64::from(note_id),
        })
        .collect()
}

/// What the vault stores for `note`, as the insertion statement carries it.
pub fn stored(note: &DevNote) -> InsertedNote {
    InsertedNote {
        registration_commitment: core::felt_to_field(&note.registration()),
        deposit_amount: note.deposit_amount,
        expiry: note.expiry,
    }
}

/// The honest activation of `notes` (consecutive ids from the first) in
/// `tree`, with the path of the first slot read from the tree.
pub fn activation(tree: &MerkleTree, notes: &[DevNote]) -> InsertionCircuit {
    let first_note_id = notes[0].note_id;
    let notes: Vec<InsertedNote> = notes.iter().map(stored).collect();
    let siblings = tree
        .get_siblings(first_note_id)
        .map(|value| core::felt_to_field(&value));
    let (old_root, new_root) = insertion_roots(first_note_id, &notes, &siblings);
    InsertionCircuit {
        public: InsertionPublic {
            old_root,
            new_root,
            first_note_id,
            notes,
        },
        witness: InsertionWitness { siblings },
    }
}

/// The activation of the `size` notes at cursor `size`, after the first
/// `size` notes were activated (so the path above the subtree is not empty).
pub fn second_batch(size: usize) -> InsertionCircuit {
    let first = batch_notes(0, size);
    let tree = tree_with(&first.iter().collect::<Vec<_>>());
    activation(&tree, &batch_notes(size as u32, size))
}

/// A circuit, plus optional overrides of instance values after synthesis (for
/// statements whose typed fields cannot hold the value, such as
/// `valid_until >= 2^64`). Instance index 0 is the constant one.
pub enum CaseCircuit {
    Request(Box<RequestCircuit>),
    Withdrawal(Box<WithdrawalCircuit>),
    Insertion(Box<InsertionCircuit>),
}

pub struct Case {
    pub name: &'static str,
    pub circuit: CaseCircuit,
    pub instance_overrides: Vec<(usize, Fr)>,
}

impl Case {
    fn request(
        name: &'static str,
        public: &RequestPublicInputsV2,
        witness: &RequestWitnessData,
    ) -> Self {
        Self {
            name,
            circuit: CaseCircuit::Request(Box::new(request_circuit(public, witness).unwrap())),
            instance_overrides: vec![],
        }
    }

    fn withdrawal(
        name: &'static str,
        public: &WithdrawalPublicInputsV2C,
        witness: &WithdrawalWitnessData,
    ) -> Self {
        Self {
            name,
            circuit: CaseCircuit::Withdrawal(Box::new(
                withdrawal_circuit(public, witness).unwrap(),
            )),
            instance_overrides: vec![],
        }
    }

    fn insertion(name: &'static str, circuit: InsertionCircuit) -> Self {
        Self {
            name,
            circuit: CaseCircuit::Insertion(Box::new(circuit)),
            instance_overrides: vec![],
        }
    }

    /// Synthesize as the prover does and apply the instance overrides.
    pub fn synthesize(self) -> ConstraintSystemRef<Fr> {
        let mode = SynthesisMode::Prove {
            construct_matrices: true,
        };
        let cs = match self.circuit {
            CaseCircuit::Request(circuit) => synthesize(*circuit, mode),
            CaseCircuit::Withdrawal(circuit) => synthesize(*circuit, mode),
            CaseCircuit::Insertion(circuit) => synthesize(*circuit, mode),
        }
        .unwrap();
        for (index, value) in self.instance_overrides {
            cs.borrow_mut().unwrap().instance_assignment[index] = value;
        }
        cs
    }

    /// The circuit (and key kind) of the case.
    pub fn kind(&self) -> KeyKind {
        match &self.circuit {
            CaseCircuit::Request(_) => KeyKind::Request,
            CaseCircuit::Withdrawal(_) => KeyKind::Withdrawal,
            CaseCircuit::Insertion(circuit) => {
                KeyKind::insertion(circuit.public.size()).expect("an insertion size")
            }
        }
    }
}

pub fn positive_cases() -> Vec<Case> {
    let c = chain();
    let mut cases = Vec::new();
    let (p, w) = c.request_of(&c.s0, &c.r0);
    cases.push(Case::request("request_genesis", &p, &w));
    let (p, w) = c.request_of(&c.s1, &c.r1);
    cases.push(Case::request("request_signed", &p, &w));
    let (p, w) = c.request_of(&c.s2, &c.r2);
    cases.push(Case::request("request_second_signed", &p, &w));
    let (p, w) = c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    cases.push(Case::withdrawal("escape_c0", &p, &w));
    let (p, w) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, c.r1.solvency_bound),
    );
    cases.push(Case::withdrawal("escape_c_sb", &p, &w));
    let (p, w) = c.withdrawal_of(
        &c.s0,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, 100_000),
    );
    cases.push(Case::withdrawal("escape_genesis_concession", &p, &w));
    let (p, w) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::MutualClose, DESTINATION, 0),
    );
    cases.push(Case::withdrawal("close", &p, &w));
    let (p, w) = c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Ownership, [0; 20], 0));
    cases.push(Case::withdrawal("ownership", &p, &w));
    let (p, w) = c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Escape, [0xff; 20], 0));
    cases.push(Case::withdrawal("escape_full_160_bit_destination", &p, &w));
    let (p, w) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, c.s1.balance),
    );
    cases.push(Case::withdrawal("escape_concede_everything", &p, &w));
    // Exits never need tau_prev: a signed state at a non-derived anchor (a
    // server bug) is unspendable in requests but exits at its signed balance.
    let stray = DevState::signed(
        &c.note,
        &c.deployment,
        800_000,
        Felt252::from_u64(23),
        Felt252::from_u64(0xabcdef),
        None,
    );
    let (p, w) = c.withdrawal_of(&stray, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    cases.push(Case::withdrawal("escape_from_non_derived_anchor", &p, &w));
    let (p, w) = c.request_of(&c.same_secret_note.genesis(Felt252::from_u64(5)), &c.r0);
    cases.push(Case::request("request_same_secret_other_note", &p, &w));
    // Withdrawals take no tree: note B closes at genesis whether or not it
    // is activated.
    let (p, w) = c.withdrawal_of(
        &c.same_secret_note.genesis(Felt252::from_u64(5)),
        &withdrawal(WithdrawalKind::MutualClose, DESTINATION, 0),
    );
    cases.push(Case::withdrawal("close_same_secret_other_note", &p, &w));

    // Activations: A into the empty tree, then B next to it (the tree of the
    // request cases), and full batches at the first two aligned cursors.
    let empty = MerkleTree::new();
    cases.push(Case::insertion(
        "activate_a",
        activation(&empty, std::slice::from_ref(&c.note)),
    ));
    cases.push(Case::insertion(
        "activate_b",
        activation(
            &tree_with(&[&c.note]),
            std::slice::from_ref(&c.same_secret_note),
        ),
    ));
    for size in INSERTION_SIZES {
        let name = match size {
            1 => ["insertion1_first_batch", "insertion1_second_batch"],
            4 => ["insertion4_first_batch", "insertion4_second_batch"],
            _ => ["insertion16_first_batch", "insertion16_second_batch"],
        };
        cases.push(Case::insertion(
            name[0],
            activation(&empty, &batch_notes(0, size)),
        ));
        cases.push(Case::insertion(name[1], second_batch(size)));
    }
    cases
}

fn two_pow(bits: u64) -> Fr {
    Fr::from(2u64).pow([bits])
}

pub fn negative_cases() -> Vec<Case> {
    let c = chain();
    let dep = &c.deployment;
    let mut cases = Vec::new();

    // Q4: a (mis)signed state above the deposit, at a correctly derived anchor.
    let over = DevState::signed(
        &c.note,
        dep,
        DEPOSIT + 1,
        Felt252::from_u64(23),
        c.s1.anchor,
        Some(c.s0.anchor),
    );
    let (mut p, w) = c.request_of(&c.s1, &request(100_000, 5, 6));
    let (p_over, w_over) = c.request_of(&over, &request(100_000, 5, 6));
    cases.push(Case::request(
        "request_balance_above_deposit",
        &p_over,
        &w_over,
    ));

    // Q6 / W6: a signed state at tau = 1 with B < D (born spent).
    let born_spent = DevState::signed(
        &c.note,
        dep,
        DEPOSIT - 60_000,
        Felt252::from_u64(29),
        core::GENESIS_ANCHOR,
        None,
    );
    let (bp, bw) = c.request_of(&born_spent, &request(100_000, 5, 6));
    cases.push(Case::request(
        "request_signed_state_at_anchor_one",
        &bp,
        &bw,
    ));
    let (bp, bw) = c.withdrawal_unchecked(
        &born_spent,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, 0),
    );
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_at_anchor_one",
        &bp,
        &bw,
    ));

    // A "genesis" state at tau != 1 with no signature.
    let unsigned = DevState {
        anchor: Felt252::from_u64(77),
        prev_anchor: Some(Felt252::ZERO),
        ..c.s0.clone()
    };
    let (up, uw) = c.request_of(&unsigned, &request(100_000, 5, 6));
    cases.push(Case::request(
        "request_unsigned_state_off_genesis",
        &up,
        &uw,
    ));
    let (up, uw) = c.withdrawal_unchecked(
        &unsigned,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, 0),
    );
    cases.push(Case::withdrawal(
        "withdrawal_unsigned_state_off_genesis",
        &up,
        &uw,
    ));

    // Q6a: signed states at anchors that are not succ(N(tau_prev)).
    for (name, anchor, prev) in [
        (
            "request_random_anchor",
            Felt252::from_u64(0xabcdef),
            Some(c.s0.anchor),
        ),
        (
            "request_foreign_note_anchor",
            core::next_anchor(&core::nullifier(&c.note.secret, 1, &core::GENESIS_ANCHOR)),
            Some(core::GENESIS_ANCHOR),
        ),
    ] {
        let state = DevState::signed(&c.note, dep, 900_000, Felt252::from_u64(31), anchor, prev);
        let (sp, sw) = c.request_of(&state, &request(100_000, 5, 6));
        cases.push(Case::request(name, &sp, &sw));
    }
    // The genuine S1 with a wrong tau_prev supplied by the prover.
    let mut wrong_prev = c.s1.clone();
    wrong_prev.prev_anchor = Some(Felt252::from_u64(2));
    let (sp, sw) = c.request_of(&wrong_prev, &request(100_000, 5, 6));
    cases.push(Case::request("request_wrong_prev_anchor", &sp, &sw));

    // Q9 / W8: a nullifier computed with the wrong note id.
    p.request_nullifier = core::nullifier(&c.note.secret, 1, &c.s1.anchor);
    p.authorization_tag = core::authorization_tag(&p.request_nullifier, &w.request_context);
    cases.push(Case::request("request_nullifier_wrong_note_id", &p, &w));
    let (mut wp, ww) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::MutualClose, DESTINATION, 0),
    );
    wp.withdrawal_nullifier = core::nullifier(&c.note.secret, 1, &c.s1.anchor);
    cases.push(Case::withdrawal(
        "withdrawal_nullifier_wrong_note_id",
        &wp,
        &ww,
    ));
    // Note binding: A's signed S1 moved to note B (same secret), with every
    // value B's owner controls recomputed; only A's signature is kept.
    let moved = DevState {
        note: c.same_secret_note.clone(),
        anchor: core::next_anchor(&core::nullifier(
            &c.note.secret,
            c.same_secret_note.note_id,
            &c.s0.anchor,
        )),
        ..c.s1.clone()
    };
    let (mp, mw) = c.request_of(&moved, &request(100_000, 5, 6));
    cases.push(Case::request(
        "request_signed_state_moved_to_other_note",
        &mp,
        &mw,
    ));
    let (mp, mw) =
        c.withdrawal_unchecked(&moved, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_moved_to_other_note",
        &mp,
        &mw,
    ));

    let b1 = c.s1.balance;
    let n1 = c.s1.nullifier();
    let next = c.s1.successor_nullifier();
    // W3: f + c != B, and c > B.
    let (p3, w3) = c.raw_withdrawal(&c.s1, 0, DESTINATION, 10_000, b1 - 10_000 + 1, next, false);
    cases.push(Case::withdrawal("f_plus_c_not_b", &p3, &w3));
    let (p3, w3) = c.raw_withdrawal(&c.s1, 0, DESTINATION, b1 + 1, 0, next, false);
    cases.push(Case::withdrawal("conceded_above_balance", &p3, &w3));
    // c > B with a final balance that wraps the field: B - c mod p.
    let (p3, w3) = c.raw_withdrawal(&c.s1, 0, DESTINATION, b1 + 1, 0, next, false);
    let mut wrapped = Case::withdrawal("conceded_above_balance_wrapped_final_balance", &p3, &w3);
    wrapped.instance_overrides = vec![(10, -Fr::ONE)];
    cases.push(wrapped);
    // W4: B > D.
    let (op, ow) =
        c.withdrawal_unchecked(&over, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    cases.push(Case::withdrawal(
        "withdrawal_balance_above_deposit",
        &op,
        &ow,
    ));

    // W9: kind 3 (k1 = k2 = 1) and kind 4.
    let (p9, w9) = c.raw_withdrawal(&c.s1, 3, [0; 20], 0, b1, Felt252::ZERO, true);
    cases.push(Case::withdrawal("kind_3", &p9, &w9));
    let (p9, w9) = c.raw_withdrawal(&c.s1, 4, DESTINATION, 0, b1, next, false);
    cases.push(Case::withdrawal("kind_4", &p9, &w9));

    // W10 / W11: kinds 1 and 2 with a successor nullifier or a concession.
    let (p10, w10) = c.raw_withdrawal(&c.s1, 1, DESTINATION, 0, b1, next, true);
    cases.push(Case::withdrawal("close_with_next_nullifier", &p10, &w10));
    let (p10, w10) = c.raw_withdrawal(&c.s1, 2, [0; 20], 0, b1, next, false);
    cases.push(Case::withdrawal(
        "ownership_with_next_nullifier",
        &p10,
        &w10,
    ));
    let (p11, w11) = c.raw_withdrawal(&c.s1, 1, DESTINATION, 1, b1 - 1, Felt252::ZERO, true);
    cases.push(Case::withdrawal("close_with_concession", &p11, &w11));
    let (p11, w11) = c.raw_withdrawal(&c.s1, 2, [0; 20], 1, b1 - 1, Felt252::ZERO, false);
    cases.push(Case::withdrawal("ownership_with_concession", &p11, &w11));
    // W10: an escape with a wrong successor nullifier.
    for (name, wrong) in [
        ("escape_zero_next_nullifier", Felt252::ZERO),
        ("escape_next_nullifier_is_n", n1),
        ("escape_stale_next_nullifier", c.s0.successor_nullifier()),
        (
            "escape_next_nullifier_other_note",
            core::successor_nullifier(&c.note.secret, 1, &c.s1.anchor),
        ),
    ] {
        let (pw, ww) = c.raw_withdrawal(&c.s1, 0, DESTINATION, 0, b1, wrong, false);
        cases.push(Case::withdrawal(name, &pw, &ww));
    }

    // W12: an ownership proof with a destination.
    let (p12, w12) = c.raw_withdrawal(&c.s1, 2, DESTINATION, 0, b1, Felt252::ZERO, false);
    cases.push(Case::withdrawal("ownership_with_destination", &p12, &w12));
    // W13: a close without a clearance signature, and with one on another nullifier.
    let (p13, w13) = c.raw_withdrawal(&c.s1, 1, DESTINATION, 0, b1, Felt252::ZERO, false);
    cases.push(Case::withdrawal("close_without_clearance", &p13, &w13));
    let (p13, mut w13) = c.raw_withdrawal(&c.s1, 1, DESTINATION, 0, b1, Felt252::ZERO, false);
    w13.clearance_signature = Some(dep.sign_clearance(&c.s0.nullifier()));
    cases.push(Case::withdrawal(
        "close_with_clearance_for_other_nullifier",
        &p13,
        &w13,
    ));

    // W12 / W14 ranges: destination >= 2^160 and valid_until >= 2^64.
    let (pr, wr) = c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    let mut circuit = withdrawal_circuit(&pr, &wr).unwrap();
    circuit.public.destination += two_pow(160);
    cases.push(Case {
        name: "destination_at_least_2_160",
        circuit: CaseCircuit::Withdrawal(Box::new(circuit)),
        instance_overrides: vec![],
    });
    let mut range = Case::withdrawal("valid_until_at_least_2_64", &pr, &wr);
    range.instance_overrides = vec![(16, Fr::from(VALID_UNTIL) + two_pow(64))];
    cases.push(range);
    let mut range = Case::withdrawal("note_id_at_least_2_32", &pr, &wr);
    range.instance_overrides = vec![(9, Fr::from(c.note.note_id) + two_pow(32))];
    cases.push(range);
    let mut range = Case::withdrawal("conceded_at_least_2_128", &pr, &wr);
    range.instance_overrides = vec![(15, two_pow(128))];
    cases.push(range);

    // Note binding (inputs 3 and 16), which the vault checks against what it
    // stores for note_id. A commitment the secret does not open, also at
    // genesis, where no signature binds the leaf: without W5's opening, a
    // genesis exit could name a victim's stored note.
    let escape = withdrawal(WithdrawalKind::Escape, DESTINATION, 0);
    let foreign = core::registration_commitment(&Felt252::from_u64(43));
    for (name, state) in [
        ("withdrawal_foreign_registration_commitment", &c.s1),
        ("genesis_withdrawal_foreign_registration_commitment", &c.s0),
    ] {
        let (mut fp, fw) = c.withdrawal_of(state, &escape);
        fp.registration_commitment = foreign;
        cases.push(Case::withdrawal(name, &fp, &fw));
    }
    // Another amount or expiry in input 16: the signed state commits to the
    // stored leaf, and a genesis balance is exactly the stored amount.
    let (mut mp, mw) = c.withdrawal_of(&c.s1, &escape);
    mp.deposit_amount += 1;
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_other_amount",
        &mp,
        &mw,
    ));
    let (mut mp, mw) = c.withdrawal_of(&c.s1, &escape);
    mp.expiry += 1;
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_other_expiry",
        &mp,
        &mw,
    ));
    for (name, amount) in [
        ("genesis_withdrawal_larger_amount", 2 * DEPOSIT),
        ("genesis_withdrawal_smaller_amount", DEPOSIT - 1),
    ] {
        let (mut mp, mw) = c.withdrawal_of(&c.s0, &escape);
        mp.deposit_amount = amount;
        cases.push(Case::withdrawal(name, &mp, &mw));
    }
    // A same-secret note with other stored values (the same C): A's signed
    // state names its M, at A's id or moved to its id.
    let richer = DevNote {
        note_id: 2,
        deposit_amount: 2 * DEPOSIT,
        expiry: EXPIRY + 86_400,
        ..c.note.clone()
    };
    let (mut sp, sw) = c.withdrawal_of(&c.s1, &escape);
    assert_eq!(sp.registration_commitment, richer.registration());
    sp.deposit_amount = richer.deposit_amount;
    sp.expiry = richer.expiry;
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_with_same_secret_note_metadata",
        &sp,
        &sw,
    ));
    let moved = DevState {
        note: richer.clone(),
        anchor: core::next_anchor(&core::nullifier(
            &c.note.secret,
            richer.note_id,
            &c.s0.anchor,
        )),
        ..c.s1.clone()
    };
    let (sp, sw) = c.withdrawal_unchecked(&moved, &escape);
    cases.push(Case::withdrawal(
        "withdrawal_signed_state_moved_to_same_secret_note_with_other_values",
        &sp,
        &sw,
    ));
    // Input 16 outside the packing: an expiry of 2^64 or more, and a value
    // that wraps the field.
    let mut range = Case::withdrawal("note_metadata_expiry_at_least_2_64", &pr, &wr);
    range.instance_overrides = vec![(17, core::felt_to_field(&pr.note_metadata()) + two_pow(192))];
    cases.push(range);
    let mut range = Case::withdrawal("note_metadata_minus_one", &pr, &wr);
    range.instance_overrides = vec![(17, -Fr::ONE)];
    cases.push(range);

    // Q2 / Q3 ranges on the request.
    let (rp, rw) = c.request_of(&c.s1, &c.r1);
    let mut range = Case::request("request_time_at_least_2_64", &rp, &rw);
    range.instance_overrides = vec![(7, Fr::from(REQUEST_TIME) + two_pow(64))];
    cases.push(range);
    let mut range = Case::request("solvency_bound_at_least_2_128", &rp, &rw);
    range.instance_overrides = vec![(8, Fr::from(c.r1.solvency_bound) + two_pow(128))];
    cases.push(range);
    // Q3: a bound above the balance.
    let (bp2, bw2) = c.request_of(&c.s2, &request(c.s2.balance + 1, 5, 6));
    cases.push(Case::request("request_bound_above_balance", &bp2, &bw2));
    // Q2: an expired leaf.
    let (mut ep, ew) = c.request_of(&c.s1, &c.r1);
    ep.request_time = EXPIRY + 1;
    cases.push(Case::request("request_after_expiry", &ep, &ew));

    cases.extend(negative_insertion_cases(&c));
    cases
}

/// Activations that would change the tree other than by appending the stored
/// notes at the cursor. Instance indices: 1 old root, 2 new root, 3 cursor,
/// then `C_j` at `4 + 2j` and `M_j` at `5 + 2j`.
fn negative_insertion_cases(c: &Chain) -> Vec<Case> {
    let mut cases = Vec::new();
    let tree_a = tree_with(&[&c.note]);
    let b = std::slice::from_ref(&c.same_secret_note);

    // I4: a stale old root (the empty tree's, before A's activation) with B's
    // path in the current tree.
    let mut stale = activation(&tree_a, b);
    stale.public.old_root = core::felt_to_field(&MerkleTree::new().root());
    cases.push(Case::insertion("insertion_stale_old_root", stale));
    // I4: the destination already holds a leaf. The old root is the real
    // root, but no empty subtree under the path reproduces it.
    let occupied = tree_with(&[&c.note, &c.same_secret_note]);
    let mut overwrite = activation(&occupied, &batch_notes(1, 1));
    overwrite.public.old_root = core::felt_to_field(&occupied.root());
    cases.push(Case::insertion(
        "insertion_overwrites_an_occupied_slot",
        overwrite,
    ));
    let partly = tree_with(&[&batch_notes(2, 1)[0]]);
    let mut overwrite = activation(&partly, &batch_notes(0, 4));
    overwrite.public.old_root = core::felt_to_field(&partly.root());
    cases.push(Case::insertion(
        "insertion4_overwrites_an_occupied_slot",
        overwrite,
    ));
    // I1: a cursor off the K alignment, with roots consistent for it.
    for (name, first, size) in [
        ("insertion4_misaligned_cursor", 2, 4),
        ("insertion16_misaligned_cursor", 8, 16),
    ] {
        let misaligned = activation(&MerkleTree::new(), &batch_notes(first, size));
        cases.push(Case::insertion(name, misaligned));
    }
    // I2: two stored notes listed in each other's places, and the commitment
    // and metadata of one note in each other's inputs.
    let mut swapped = second_batch(4);
    swapped.public.notes.swap(0, 1);
    cases.push(Case::insertion("insertion4_notes_swapped", swapped));
    let honest = activation(&tree_a, b);
    let (commitment, metadata) = (
        honest.public.notes[0].registration_commitment,
        honest.public.notes[0].metadata(),
    );
    let mut swapped = Case::insertion("insertion1_commitment_and_metadata_swapped", honest);
    swapped.instance_overrides = vec![(4, metadata), (5, commitment)];
    cases.push(swapped);
    // I3 / I4: a new root of other note values than the stored ones.
    let mut other_root = second_batch(4);
    let mut other_notes = other_root.public.notes.clone();
    other_notes[3].expiry += 1;
    other_root.public.new_root = insertion_roots(
        other_root.public.first_note_id,
        &other_notes,
        &other_root.witness.siblings,
    )
    .1;
    cases.push(Case::insertion(
        "insertion4_new_root_of_other_values",
        other_root,
    ));
    let mut other_root = activation(&tree_a, b);
    other_root.public.new_root = core::felt_to_field(&tree_a.root());
    cases.push(Case::insertion("insertion_new_root_unchanged", other_root));
    // Ranges: M_0 with an expiry of 2^64 or more, and a cursor of 2^32 or more.
    let honest = activation(&tree_a, b);
    let metadata = honest.public.notes[0].metadata();
    let mut range = Case::insertion("insertion1_metadata_expiry_at_least_2_64", honest);
    range.instance_overrides = vec![(5, metadata + two_pow(192))];
    cases.push(range);
    let mut range = Case::insertion("insertion1_cursor_at_least_2_32", activation(&tree_a, b));
    range.instance_overrides = vec![(3, Fr::from(1u64) + two_pow(32))];
    cases.push(range);
    cases
}
