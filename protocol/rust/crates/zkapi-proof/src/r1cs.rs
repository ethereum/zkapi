//! Export of the circuits as circom `.r1cs` files (iden3 R1CS binary format,
//! version 1) for the snarkjs phase-2 setup (G-SETUP step 1).
//!
//! The matrices are those of [`crate::groth16::synthesize`]
//! (`OptimizationGoal::Constraints`, then `finalize()`), so the exported
//! file, the arkworks generator and the prover see identical constraints.
//!
//! Wire order is `[one, public inputs in statement order, witnesses]`, which
//! is exactly the arkworks column order: wire `i` is column `i`. Every public
//! input is declared a public *input* (`nPubOut = 0`), so snarkjs's public
//! signals are the statement's inputs in order. Labels are the identity map.
//! Coefficients are canonical 32-byte little-endian field elements.

use std::io::{self, Write};

use anyhow::{anyhow, ensure, Result};
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, Zero};
use ark_relations::r1cs::{ConstraintMatrices, SynthesisMode};

use crate::compact::{request_template, withdrawal_template, KeyKind};
use crate::groth16::synthesize;

/// The file names `examples/export_r1cs.rs` writes.
pub const REQUEST_R1CS_FILE: &str = "request.r1cs";
pub const WITHDRAWAL_R1CS_FILE: &str = "withdrawal.r1cs";

const MAGIC: &[u8; 4] = b"r1cs";
const VERSION: u32 = 1;
const SECTION_HEADER: u32 = 1;
const SECTION_CONSTRAINTS: u32 = 2;
const SECTION_WIRE_TO_LABEL: u32 = 3;
const FIELD_BYTES: u32 = 32;

/// The finalized constraint matrices of a circuit, synthesized from its
/// template in setup mode.
pub fn circuit_matrices(kind: KeyKind) -> Result<ConstraintMatrices<Fr>> {
    let cs = match kind {
        KeyKind::Request => synthesize(request_template(), SynthesisMode::Setup),
        KeyKind::Withdrawal => synthesize(withdrawal_template(), SynthesisMode::Setup),
    }
    .map_err(|error| anyhow!("synthesize {kind} circuit: {error}"))?;
    cs.to_matrices()
        .ok_or_else(|| anyhow!("{kind} constraint matrices unavailable"))
}

/// The `.r1cs` file of a circuit.
pub fn r1cs_bytes(kind: KeyKind) -> Result<Vec<u8>> {
    let matrices = circuit_matrices(kind)?;
    ensure!(
        matrices.num_instance_variables == kind.public_inputs() + 1,
        "{kind} circuit has {} instance variables",
        matrices.num_instance_variables
    );
    let mut bytes = Vec::new();
    write_r1cs(&matrices, &mut bytes)?;
    Ok(bytes)
}

/// Write `matrices` as an R1CS v1 file. Refuses a row that names a wire twice
/// or carries a zero coefficient: readers (snarkjs) keep one coefficient per
/// wire, so such a row would not mean the same constraint.
pub fn write_r1cs<W: Write>(matrices: &ConstraintMatrices<Fr>, mut writer: W) -> Result<()> {
    let num_wires = matrices.num_instance_variables + matrices.num_witness_variables;
    let num_wires_u32 = u32::try_from(num_wires).map_err(|_| anyhow!("too many wires"))?;
    let public_inputs = u32::try_from(matrices.num_instance_variables - 1)
        .map_err(|_| anyhow!("too many public inputs"))?;
    let num_constraints =
        u32::try_from(matrices.num_constraints).map_err(|_| anyhow!("too many constraints"))?;
    ensure!(
        matrices.a.len() == matrices.num_constraints
            && matrices.b.len() == matrices.num_constraints
            && matrices.c.len() == matrices.num_constraints,
        "matrix row counts differ from the constraint count"
    );

    let mut constraints = Vec::new();
    for row in 0..matrices.num_constraints {
        for matrix in [&matrices.a, &matrices.b, &matrices.c] {
            write_linear_combination(&mut constraints, &matrix[row], num_wires)?;
        }
    }

    let mut out = Vec::with_capacity(constraints.len() + num_wires * 8 + 128);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&VERSION.to_le_bytes());
    out.extend_from_slice(&3u32.to_le_bytes());

    // Section 1: header.
    let mut header = Vec::with_capacity(64);
    header.extend_from_slice(&FIELD_BYTES.to_le_bytes());
    header.extend_from_slice(&field_le_bytes(&field_modulus()));
    header.extend_from_slice(&num_wires_u32.to_le_bytes());
    header.extend_from_slice(&0u32.to_le_bytes()); // nPubOut
    header.extend_from_slice(&public_inputs.to_le_bytes()); // nPubIn
    header.extend_from_slice(&0u32.to_le_bytes()); // nPrvIn
    header.extend_from_slice(&(num_wires as u64).to_le_bytes()); // nLabels
    header.extend_from_slice(&num_constraints.to_le_bytes());
    write_section(&mut out, SECTION_HEADER, &header);

    // Section 2: constraints.
    write_section(&mut out, SECTION_CONSTRAINTS, &constraints);

    // Section 3: wire -> label (identity).
    let mut labels = Vec::with_capacity(num_wires * 8);
    for wire in 0..num_wires as u64 {
        labels.extend_from_slice(&wire.to_le_bytes());
    }
    write_section(&mut out, SECTION_WIRE_TO_LABEL, &labels);

    writer.write_all(&out).map_err(io_error)?;
    Ok(())
}

fn write_linear_combination(out: &mut Vec<u8>, terms: &[(Fr, usize)], wires: usize) -> Result<()> {
    let mut seen = std::collections::BTreeSet::new();
    out.extend_from_slice(&(terms.len() as u32).to_le_bytes());
    for (coefficient, wire) in terms {
        ensure!(*wire < wires, "constraint names wire {wire} of {wires}");
        ensure!(seen.insert(*wire), "constraint names wire {wire} twice");
        ensure!(!coefficient.is_zero(), "zero coefficient on wire {wire}");
        out.extend_from_slice(&(*wire as u32).to_le_bytes());
        out.extend_from_slice(&field_le_bytes_of(coefficient));
    }
    Ok(())
}

fn write_section(out: &mut Vec<u8>, section: u32, body: &[u8]) {
    out.extend_from_slice(&section.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
}

/// The scalar-field modulus as little-endian bytes (the header's prime).
fn field_modulus() -> <Fr as PrimeField>::BigInt {
    Fr::MODULUS
}

fn field_le_bytes(value: &<Fr as PrimeField>::BigInt) -> [u8; 32] {
    let raw = value.to_bytes_le();
    let mut bytes = [0u8; 32];
    bytes[..raw.len()].copy_from_slice(&raw);
    bytes
}

fn field_le_bytes_of(value: &Fr) -> [u8; 32] {
    field_le_bytes(&value.into_bigint())
}

fn io_error(error: io::Error) -> anyhow::Error {
    anyhow!("write r1cs: {error}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_matches_the_circom_layout() {
        let bytes = r1cs_bytes(KeyKind::Request).unwrap();
        assert_eq!(&bytes[..4], b"r1cs");
        assert_eq!(u32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3);
        assert_eq!(u32::from_le_bytes(bytes[12..16].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(bytes[16..24].try_into().unwrap()), 64);
        assert_eq!(u32::from_le_bytes(bytes[24..28].try_into().unwrap()), 32);
        // The BN254 scalar modulus, little-endian.
        assert_eq!(
            hex::encode(&bytes[28..60]),
            "010000f093f5e1439170b97948e833285d588181b64550b829a031e1724e6430"
        );
        // nPubOut = 0, nPubIn = 12.
        assert_eq!(u32::from_le_bytes(bytes[64..68].try_into().unwrap()), 0);
        assert_eq!(u32::from_le_bytes(bytes[68..72].try_into().unwrap()), 12);
    }

    #[test]
    fn duplicate_wires_and_zero_coefficients_are_refused() {
        let matrices = |row: Vec<(Fr, usize)>| ConstraintMatrices::<Fr> {
            num_instance_variables: 1,
            num_witness_variables: 1,
            num_constraints: 1,
            a_num_non_zero: row.len(),
            b_num_non_zero: 0,
            c_num_non_zero: 0,
            a: vec![row],
            b: vec![vec![]],
            c: vec![vec![]],
        };
        let mut sink = Vec::new();
        assert!(write_r1cs(&matrices(vec![(Fr::from(1u64), 1)]), &mut sink).is_ok());
        assert!(write_r1cs(
            &matrices(vec![(Fr::from(1u64), 1), (Fr::from(2u64), 1)]),
            &mut sink
        )
        .is_err());
        assert!(write_r1cs(&matrices(vec![(Fr::from(0u64), 1)]), &mut sink).is_err());
        assert!(write_r1cs(&matrices(vec![(Fr::from(1u64), 2)]), &mut sink).is_err());
    }
}
