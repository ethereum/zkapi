//! Constraint-level tests of both circuits: every positive case of the WP-A
//! plan is satisfied, every negative case is unsatisfiable, and the explicit
//! prover-side rules reject the representable invalid statements.

mod common;

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use common::*;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    check_request_rules, check_withdrawal_rules, request_circuit, withdrawal_public_inputs,
    WithdrawalStatementParams,
};
use zkapi_proof::dev::DevState;
use zkapi_proof::groth16::{
    nullifier, REQUEST_PUBLIC_INPUTS, REQUEST_ROW_BUDGET, WITHDRAWAL_PUBLIC_INPUTS,
};
use zkapi_types::{Felt252, WithdrawalKind};

#[test]
fn positive_cases_are_satisfied() {
    for case in positive_cases() {
        let name = case.name;
        let withdrawal = case.is_withdrawal();
        let cs = case.synthesize();
        assert_eq!(
            cs.which_is_unsatisfied().unwrap(),
            None,
            "positive case {name} is unsatisfied"
        );
        let inputs = if withdrawal {
            WITHDRAWAL_PUBLIC_INPUTS
        } else {
            REQUEST_PUBLIC_INPUTS
        };
        assert_eq!(cs.num_instance_variables(), inputs + 1, "{name}");
    }
}

#[test]
fn negative_cases_are_unsatisfiable() {
    let cases = negative_cases();
    assert!(cases.len() >= 35, "{} negative cases", cases.len());
    for case in cases {
        let name = case.name;
        let cs = case.synthesize();
        assert!(
            !cs.is_satisfied().unwrap(),
            "negative case {name} is satisfied"
        );
    }
}

#[test]
fn constraint_budget() {
    let cs = ConstraintSystem::new_ref();
    let c = chain();
    let (public, witness) = c.request_of(&c.s1, &c.r1);
    request_circuit(&public, &witness)
        .unwrap()
        .generate_constraints(cs.clone())
        .unwrap();
    let rows = cs.num_constraints() + cs.num_instance_variables();
    eprintln!(
        "request: {} constraints, {} instance variables, {rows} QAP rows",
        cs.num_constraints(),
        cs.num_instance_variables()
    );
    assert_eq!(cs.num_instance_variables(), 13);
    assert!(rows <= REQUEST_ROW_BUDGET, "{rows} > {REQUEST_ROW_BUDGET}");
}

#[test]
fn explicit_request_rules() {
    let c = chain();
    let (public, witness) = c.request_of(&c.s1, &c.r1);
    check_request_rules(&public, &witness).unwrap();
    let (public0, witness0) = c.request_of(&c.s0, &c.r0);
    check_request_rules(&public0, &witness0).unwrap();

    let mut missing = witness.clone();
    missing.prev_anchor = None;
    let error = check_request_rules(&public, &missing)
        .unwrap_err()
        .to_string();
    assert!(error.contains("prev_anchor_missing"), "{error}");

    let mut wrong = witness.clone();
    wrong.prev_anchor = Some(Felt252::from_u64(2));
    let error = check_request_rules(&public, &wrong)
        .unwrap_err()
        .to_string();
    assert!(error.contains("not derived"), "{error}");

    let mut over = witness.clone();
    over.current_balance = over.deposit_amount + 1;
    assert!(check_request_rules(&public, &over).is_err());

    let mut born_spent = witness;
    born_spent.current_anchor = core::GENESIS_ANCHOR;
    let error = check_request_rules(&public, &born_spent)
        .unwrap_err()
        .to_string();
    assert!(error.contains("genesis anchor"), "{error}");
}

#[test]
fn explicit_withdrawal_rules() {
    let c = chain();
    let b1 = c.s1.balance;
    let next = c.s1.successor_nullifier();
    for (kind, destination, conceded) in [
        (WithdrawalKind::Escape, DESTINATION, 0),
        (WithdrawalKind::Escape, DESTINATION, 5),
        (WithdrawalKind::MutualClose, DESTINATION, 0),
        (WithdrawalKind::Ownership, [0; 20], 0),
    ] {
        let (public, witness) = c.withdrawal_of(&c.s1, &withdrawal(kind, destination, conceded));
        check_withdrawal_rules(&public, &witness).unwrap();
        assert_eq!(public.final_balance + public.conceded, b1);
        assert_eq!(
            public.next_nullifier,
            if kind == WithdrawalKind::Escape {
                next
            } else {
                Felt252::ZERO
            }
        );
    }
    let rejected = [
        // (kind, destination, conceded, final balance, next nullifier, clearance)
        (0u8, DESTINATION, 10, b1 - 9, next, false),
        (0, DESTINATION, b1 + 1, 0, next, false),
        (3, [0; 20], 0, b1, Felt252::ZERO, true),
        (1, DESTINATION, 0, b1, next, true),
        (2, [0; 20], 0, b1, next, false),
        (1, DESTINATION, 1, b1 - 1, Felt252::ZERO, true),
        (2, [0; 20], 1, b1 - 1, Felt252::ZERO, false),
        (0, DESTINATION, 0, b1, Felt252::ZERO, false),
        (2, DESTINATION, 0, b1, Felt252::ZERO, false),
        (1, DESTINATION, 0, b1, Felt252::ZERO, false),
    ];
    for (kind, destination, conceded, final_balance, next_nullifier, clearance) in rejected {
        let (public, mut witness) = c.raw_withdrawal(
            &c.s1,
            kind,
            destination,
            conceded,
            final_balance,
            next_nullifier,
            clearance,
        );
        if let Ok(kind) = WithdrawalKind::try_from(kind) {
            witness.kind = kind;
        }
        assert!(
            check_withdrawal_rules(&public, &witness).is_err(),
            "kind {kind} destination {destination:?} conceded {conceded} accepted"
        );
    }

    // The builder refuses an ownership proof with a destination and an
    // over-concession.
    let (_, witness) = c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Ownership, [0; 20], 0));
    let mut params = WithdrawalStatementParams {
        protocol_version: 2,
        chain_id: CHAIN_ID,
        contract_address: c.deployment.contract_address,
        active_root: c.tree.root(),
        state_signing_key: c.deployment.state_key(),
        clearance_signing_key: c.deployment.clearance_key(),
        note_id: c.note.note_id,
        destination: DESTINATION,
    };
    assert!(withdrawal_public_inputs(&params, &witness).is_err());
    params.destination = [0; 20];
    assert!(withdrawal_public_inputs(&params, &witness).is_ok());
    let (_, mut witness) =
        c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    witness.conceded = b1 + 1;
    params.destination = DESTINATION;
    assert!(withdrawal_public_inputs(&params, &witness).is_err());
}

/// Notes that share a secret have disjoint nullifier chains: neither note's
/// statements name the other's nullifiers.
#[test]
fn note_binding_of_nullifiers() {
    let c = chain();
    let other = c.same_secret_note.genesis(Felt252::from_u64(5));
    assert_ne!(other.nullifier(), c.s0.nullifier());
    assert_ne!(other.successor_nullifier(), c.s0.successor_nullifier());
    assert_ne!(other.successor_anchor(), c.s0.successor_anchor());
    let field = core::felt_to_field;
    assert_eq!(
        core::field_to_felt(&nullifier(
            field(&c.note.secret),
            1,
            field(&core::GENESIS_ANCHOR)
        )),
        other.nullifier()
    );
}

/// The withdrawal circuit never needs tau_prev; the request circuit refuses a
/// state whose anchor is not derived, so a non-derived signed state can only
/// exit, at its signed balance.
#[test]
fn non_derived_states_exit_but_never_spend() {
    let c = chain();
    let stray = DevState::signed(
        &c.note,
        &c.deployment,
        800_000,
        Felt252::from_u64(23),
        Felt252::from_u64(0xabcdef),
        Some(c.s0.anchor),
    );
    let (public, witness) = c.request_of(&stray, &c.r1);
    let cs = ConstraintSystem::new_ref();
    request_circuit(&public, &witness)
        .unwrap()
        .generate_constraints(cs.clone())
        .unwrap();
    assert!(!cs.is_satisfied().unwrap());
    let (public, witness) =
        c.withdrawal_of(&stray, &withdrawal(WithdrawalKind::Escape, DESTINATION, 0));
    check_withdrawal_rules(&public, &witness).unwrap();
    assert_eq!(public.final_balance, 800_000);
}
