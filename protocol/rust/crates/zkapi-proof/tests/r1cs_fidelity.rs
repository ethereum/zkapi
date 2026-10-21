//! R1CS export fidelity (G-SETUP step 2): the exported circom `.r1cs` files
//! parse back (with `ark-circom`'s reader) to exactly the synthesized
//! matrices, every honest assignment satisfies them, and every negative case's
//! full assignment is rejected by an independent evaluator over the file.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use std::io::Cursor;

use ark_bn254::Fr;
use ark_circom::circom::R1CSFile;
use ark_ff::Zero;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef};
use common::*;
use zkapi_proof::compact::KeyKind;
use zkapi_proof::r1cs::{circuit_matrices, r1cs_bytes, write_r1cs};

fn parse(kind: KeyKind) -> R1CSFile<Fr> {
    R1CSFile::<Fr>::new(Cursor::new(r1cs_bytes(kind).unwrap())).unwrap()
}

fn full_assignment(cs: &ConstraintSystemRef<Fr>) -> Vec<Fr> {
    let cs = cs.borrow().unwrap();
    [
        cs.instance_assignment.as_slice(),
        cs.witness_assignment.as_slice(),
    ]
    .concat()
}

/// An evaluator that knows nothing of arkworks constraint systems: it reads
/// only the parsed file. Returns the first violated row.
fn first_violated_row(file: &R1CSFile<Fr>, assignment: &[Fr]) -> Option<usize> {
    assert_eq!(assignment.len(), file.header.n_wires as usize);
    assert_eq!(assignment[0], Fr::from(1u64), "wire 0 is the constant one");
    let evaluate = |terms: &Vec<(usize, Fr)>| {
        terms.iter().fold(Fr::zero(), |sum, (wire, coefficient)| {
            sum + assignment[*wire] * coefficient
        })
    };
    file.constraints
        .iter()
        .position(|(a, b, c)| evaluate(a) * evaluate(b) != evaluate(c))
}

fn assert_file_matches(file: &R1CSFile<Fr>, matrices: &ConstraintMatrices<Fr>, kind: KeyKind) {
    assert_eq!(file.version, 1);
    assert_eq!(file.header.field_size, 32);
    assert_eq!(
        file.header.n_wires as usize,
        matrices.num_instance_variables + matrices.num_witness_variables
    );
    assert_eq!(file.header.n_pub_out, 0);
    assert_eq!(file.header.n_pub_in as usize, kind.public_inputs());
    assert_eq!(
        matrices.num_instance_variables,
        kind.public_inputs() + 1,
        "{kind}"
    );
    assert_eq!(file.header.n_constraints as usize, matrices.num_constraints);
    assert_eq!(file.header.n_labels, u64::from(file.header.n_wires));
    assert_eq!(file.constraints.len(), matrices.num_constraints);
    let to_file = |row: &Vec<(Fr, usize)>| -> Vec<(usize, Fr)> {
        row.iter()
            .map(|(coefficient, wire)| (*wire, *coefficient))
            .collect()
    };
    for (row, (a, b, c)) in file.constraints.iter().enumerate() {
        assert_eq!(a, &to_file(&matrices.a[row]), "{kind} A row {row}");
        assert_eq!(b, &to_file(&matrices.b[row]), "{kind} B row {row}");
        assert_eq!(c, &to_file(&matrices.c[row]), "{kind} C row {row}");
    }
    assert_eq!(
        file.wire_mapping,
        (0..u64::from(file.header.n_wires)).collect::<Vec<_>>()
    );
}

#[test]
fn r1cs_export_roundtrip() {
    for kind in [KeyKind::Request, KeyKind::Withdrawal] {
        let matrices = circuit_matrices(kind).unwrap();
        let file = parse(kind);
        assert_file_matches(&file, &matrices, kind);
        // Writing the parsed matrices again reproduces the bytes.
        let mut again = Vec::new();
        write_r1cs(&matrices, &mut again).unwrap();
        assert_eq!(again, r1cs_bytes(kind).unwrap());
        eprintln!(
            "{kind}: {} constraints, {} wires, {} public inputs, {} bytes",
            file.header.n_constraints,
            file.header.n_wires,
            file.header.n_pub_in,
            again.len()
        );
    }
}

/// Setup (template, setup mode), proving (real witness, prove mode) and the
/// export see identical matrices; every honest assignment satisfies the
/// exported file; wires 1..=k carry the public inputs in statement order.
#[test]
fn honest_assignments_satisfy_the_exported_file() {
    let request_file = parse(KeyKind::Request);
    let withdrawal_file = parse(KeyKind::Withdrawal);
    let request_matrices = circuit_matrices(KeyKind::Request).unwrap();
    let withdrawal_matrices = circuit_matrices(KeyKind::Withdrawal).unwrap();
    let c = chain();
    let (request_public, _) = c.request_of(&c.s1, &c.r1);
    let (withdrawal_public, _) = c.withdrawal_of(
        &c.s1,
        &withdrawal(zkapi_types::WithdrawalKind::Escape, DESTINATION, 0),
    );
    for case in positive_cases() {
        let name = case.name;
        let is_withdrawal = case.is_withdrawal();
        let cs = case.synthesize();
        let (file, matrices) = if is_withdrawal {
            (&withdrawal_file, &withdrawal_matrices)
        } else {
            (&request_file, &request_matrices)
        };
        let prove_matrices = cs.to_matrices().unwrap();
        assert_eq!(prove_matrices.a, matrices.a, "{name}");
        assert_eq!(prove_matrices.b, matrices.b, "{name}");
        assert_eq!(prove_matrices.c, matrices.c, "{name}");
        assert_eq!(
            prove_matrices.num_witness_variables, matrices.num_witness_variables,
            "{name}"
        );
        let assignment = full_assignment(&cs);
        assert_eq!(first_violated_row(file, &assignment), None, "{name}");
        if name == "request_signed" {
            let inputs: Vec<Fr> = request_public
                .to_field_elements()
                .iter()
                .map(zkapi_core::v2::felt_to_field)
                .collect();
            assert_eq!(&assignment[1..13], inputs.as_slice());
        }
        if name == "escape_c0" {
            let inputs: Vec<Fr> = withdrawal_public
                .to_field_elements()
                .iter()
                .map(zkapi_core::v2::felt_to_field)
                .collect();
            assert_eq!(&assignment[1..17], inputs.as_slice());
        }
    }
}

#[test]
fn r1cs_negative_assignments() {
    let request = parse(KeyKind::Request);
    let withdrawal = parse(KeyKind::Withdrawal);
    let cases = negative_cases();
    let count = cases.len();
    for case in cases {
        let name = case.name;
        let file = if case.is_withdrawal() {
            &withdrawal
        } else {
            &request
        };
        let cs = case.synthesize();
        let assignment = full_assignment(&cs);
        let row = first_violated_row(file, &assignment);
        assert!(
            row.is_some(),
            "the exported file accepts negative case {name}"
        );
    }
    eprintln!("{count} negative assignments rejected by the exported R1CS");
}
