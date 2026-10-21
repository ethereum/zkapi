//! Shared statement fixtures: an honest state chain, the positive cases and
//! every negative case of the WP-A test plan, at the circuit level.
#![allow(dead_code)]

use ark_bn254::Fr;
use ark_ff::Field;
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisMode};
use zkapi_core::v2 as core;
use zkapi_core::MerkleTree;
use zkapi_proof::compact::{
    request_circuit, withdrawal_circuit, RequestWitnessData, WithdrawalWitnessData,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_proof::groth16::{synthesize, RequestCircuit, WithdrawalCircuit};
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
        state
            .withdrawal(&self.deployment, &self.tree, withdrawal)
            .unwrap()
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
            active_root: self.tree.root(),
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
        };
        let witness = WithdrawalWitnessData {
            secret: state.note.secret,
            deposit_amount: state.note.deposit_amount,
            expiry: state.note.expiry,
            merkle_siblings: self.tree.get_siblings(state.note.note_id),
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

/// A circuit, plus optional overrides of instance values after synthesis (for
/// statements whose typed fields cannot hold the value, such as
/// `valid_until >= 2^64`). Instance index 0 is the constant one.
pub enum CaseCircuit {
    Request(RequestCircuit),
    Withdrawal(WithdrawalCircuit),
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
            circuit: CaseCircuit::Request(request_circuit(public, witness).unwrap()),
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
            circuit: CaseCircuit::Withdrawal(withdrawal_circuit(public, witness).unwrap()),
            instance_overrides: vec![],
        }
    }

    /// Synthesize as the prover does and apply the instance overrides.
    pub fn synthesize(self) -> ConstraintSystemRef<Fr> {
        let mode = SynthesisMode::Prove {
            construct_matrices: true,
        };
        let cs = match self.circuit {
            CaseCircuit::Request(circuit) => synthesize(circuit, mode),
            CaseCircuit::Withdrawal(circuit) => synthesize(circuit, mode),
        }
        .unwrap();
        for (index, value) in self.instance_overrides {
            cs.borrow_mut().unwrap().instance_assignment[index] = value;
        }
        cs
    }

    pub fn is_withdrawal(&self) -> bool {
        matches!(self.circuit, CaseCircuit::Withdrawal(_))
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
        circuit: CaseCircuit::Withdrawal(circuit),
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
    cases
}
