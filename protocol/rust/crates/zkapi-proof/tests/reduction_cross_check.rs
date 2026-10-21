//! Cross-check of the vendored `reduction::CircomReduction` against the
//! `ark-circom` crate (0.5.0), method by method and end to end, and of
//! `ark-groth16` 0.5's generator honouring `h_query_scalars`.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use ark_bn254::{Bn254, Fr};
use ark_ff::{Field, UniformRand};
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_groth16::{Groth16, ProvingKey};
use ark_poly::GeneralEvaluationDomain;
use ark_relations::lc;
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, SynthesisMode,
};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use common::*;
use zkapi_proof::compact::{decode_compressed, request_circuit, withdrawal_circuit, KeyKind};
use zkapi_proof::groth16::{synthesize, verify_field_elements};
use zkapi_proof::reduction::CircomReduction as Vendored;
use zkapi_types::WithdrawalKind;

type Upstream = ark_circom::CircomReduction;
type D = GeneralEvaluationDomain<Fr>;

fn assignment(cs: &ConstraintSystemRef<Fr>) -> Vec<Fr> {
    let cs = cs.borrow().unwrap();
    [
        cs.instance_assignment.as_slice(),
        cs.witness_assignment.as_slice(),
    ]
    .concat()
}

fn real_systems() -> Vec<ConstraintSystemRef<Fr>> {
    let c = chain();
    let mode = SynthesisMode::Prove {
        construct_matrices: true,
    };
    let (public, witness) = c.request_of(&c.s1, &c.r1);
    let request = synthesize(request_circuit(&public, &witness).unwrap(), mode).unwrap();
    let (public, witness) = c.withdrawal_of(
        &c.s1,
        &withdrawal(WithdrawalKind::Escape, DESTINATION, 1_000),
    );
    let withdrawal = synthesize(withdrawal_circuit(&public, &witness).unwrap(), mode).unwrap();
    vec![request, withdrawal]
}

#[test]
fn witness_map_matches_ark_circom() {
    for cs in real_systems() {
        assert!(cs.is_satisfied().unwrap());
        let matrices = cs.to_matrices().unwrap();
        let full = assignment(&cs);
        let ours = Vendored::witness_map_from_matrices::<Fr, D>(
            &matrices,
            cs.num_instance_variables(),
            cs.num_constraints(),
            &full,
        )
        .unwrap();
        let theirs = Upstream::witness_map_from_matrices::<Fr, D>(
            &matrices,
            cs.num_instance_variables(),
            cs.num_constraints(),
            &full,
        )
        .unwrap();
        assert_eq!(ours, theirs);
        // The trait's default `witness_map` reads the same system.
        assert_eq!(Vendored::witness_map::<Fr, D>(cs.clone()).unwrap(), ours);
        // And an unsatisfying assignment maps identically too.
        let mut bad = full.clone();
        let last = bad.len() - 1;
        bad[last] += Fr::ONE;
        assert_eq!(
            Vendored::witness_map_from_matrices::<Fr, D>(
                &matrices,
                cs.num_instance_variables(),
                cs.num_constraints(),
                &bad
            )
            .unwrap(),
            Upstream::witness_map_from_matrices::<Fr, D>(
                &matrices,
                cs.num_instance_variables(),
                cs.num_constraints(),
                &bad
            )
            .unwrap()
        );
    }
}

#[test]
fn h_query_scalars_match_ark_circom() {
    let mut rng = StdRng::seed_from_u64(1);
    for max_power in [1usize, 2, 7, 8, 1 << 10, (1 << 15) - 1] {
        let t = Fr::rand(&mut rng);
        let zt = Fr::rand(&mut rng);
        let delta_inverse = Fr::rand(&mut rng);
        let ours = Vendored::h_query_scalars::<Fr, D>(max_power, t, zt, delta_inverse).unwrap();
        let theirs = Upstream::h_query_scalars::<Fr, D>(max_power, t, zt, delta_inverse).unwrap();
        assert_eq!(ours, theirs, "max_power {max_power}");
        assert_ne!(
            ours,
            LibsnarkReduction::h_query_scalars::<Fr, D>(max_power, t, zt, delta_inverse).unwrap()
        );
    }
}

#[test]
fn instance_map_matches_ark_circom() {
    let mut rng = StdRng::seed_from_u64(2);
    for cs in real_systems() {
        let t = Fr::rand(&mut rng);
        let ours = Vendored::instance_map_with_evaluation::<Fr, D>(cs.clone(), &t).unwrap();
        let theirs = Upstream::instance_map_with_evaluation::<Fr, D>(cs.clone(), &t).unwrap();
        assert_eq!(ours, theirs);
    }
}

/// Same keys and randomness give byte-identical proofs with both reductions.
#[test]
fn proofs_match_ark_circom_with_the_development_keys() {
    let c = chain();
    let dir = setup_dir();
    let mut rng = StdRng::seed_from_u64(3);
    let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    let (public, witness) = c.request_of(&c.s2, &c.r2);
    let circuit = request_circuit(&public, &witness).unwrap();
    let (pk, _): (ProvingKey<Bn254>, _) = decode_compressed(
        &std::fs::read(dir.join("request.pk")).unwrap(),
        KeyKind::Request,
    )
    .unwrap();
    let ours = Groth16::<Bn254, Vendored>::create_proof_with_reduction(circuit.clone(), &pk, r, s)
        .unwrap();
    let theirs =
        Groth16::<Bn254, Upstream>::create_proof_with_reduction(circuit, &pk, r, s).unwrap();
    assert_eq!(ours, theirs);
    let inputs: Vec<Fr> = public
        .to_field_elements()
        .iter()
        .map(zkapi_core::v2::felt_to_field)
        .collect();
    assert!(verify_field_elements(&pk.vk, &inputs, &ours).unwrap());

    let (public, witness) =
        c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Ownership, [0; 20], 0));
    let circuit = withdrawal_circuit(&public, &witness).unwrap();
    let (pk, _): (ProvingKey<Bn254>, _) = decode_compressed(
        &std::fs::read(dir.join("withdrawal.pk")).unwrap(),
        KeyKind::Withdrawal,
    )
    .unwrap();
    let ours = Groth16::<Bn254, Vendored>::create_proof_with_reduction(circuit.clone(), &pk, r, s)
        .unwrap();
    let theirs =
        Groth16::<Bn254, Upstream>::create_proof_with_reduction(circuit, &pk, r, s).unwrap();
    assert_eq!(ours, theirs);
}

/// `x * y = z` with public z and private x, y, plus three padding rows.
#[derive(Clone)]
struct Toy {
    x: Fr,
    y: Fr,
}

impl ConstraintSynthesizer<Fr> for Toy {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let z = cs.new_input_variable(|| Ok(self.x * self.y))?;
        let x = cs.new_witness_variable(|| Ok(self.x))?;
        let y = cs.new_witness_variable(|| Ok(self.y))?;
        cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)?;
        for _ in 0..3 {
            cs.enforce_constraint(lc!() + x, lc!() + y, lc!() + z)?;
        }
        Ok(())
    }
}

/// The generator calls `QAP::h_query_scalars`: keys generated with one
/// reduction only work with a prover using the same reduction, and the
/// vendored and upstream reductions generate identical keys.
#[test]
fn generator_honours_the_reduction() {
    let toy = Toy {
        x: Fr::from(3u64),
        y: Fr::from(5u64),
    };
    let inputs = [Fr::from(15u64)];
    let setup = |seed| {
        let mut rng = StdRng::seed_from_u64(seed);
        Groth16::<Bn254, Vendored>::circuit_specific_setup(toy.clone(), &mut rng).unwrap()
    };
    let (pk, vk) = setup(4);
    let (pk_again, _) = setup(4);
    let mut rng = StdRng::seed_from_u64(4);
    let (pk_upstream, _) =
        Groth16::<Bn254, Upstream>::circuit_specific_setup(toy.clone(), &mut rng).unwrap();
    assert_eq!(pk, pk_again);
    assert_eq!(pk, pk_upstream);
    let mut rng = StdRng::seed_from_u64(4);
    let (pk_libsnark, vk_libsnark) =
        Groth16::<Bn254, LibsnarkReduction>::circuit_specific_setup(toy.clone(), &mut rng).unwrap();
    // Only the H query differs between the two generators.
    assert_ne!(pk.h_query, pk_libsnark.h_query);
    assert_eq!(pk.a_query, pk_libsnark.a_query);
    assert_eq!(pk.l_query, pk_libsnark.l_query);
    assert_eq!(vk, vk_libsnark);

    let mut rng = StdRng::seed_from_u64(5);
    let circom_proof = Groth16::<Bn254, Vendored>::prove(&pk, toy.clone(), &mut rng).unwrap();
    assert!(verify_field_elements(&vk, &inputs, &circom_proof).unwrap());
    let libsnark_proof =
        Groth16::<Bn254, LibsnarkReduction>::prove(&pk, toy.clone(), &mut rng).unwrap();
    assert!(!verify_field_elements(&vk, &inputs, &libsnark_proof).unwrap());
    let mismatched =
        Groth16::<Bn254, Vendored>::prove(&pk_libsnark, toy.clone(), &mut rng).unwrap();
    assert!(!verify_field_elements(&vk_libsnark, &inputs, &mismatched).unwrap());
    let libsnark_ok =
        Groth16::<Bn254, LibsnarkReduction>::prove(&pk_libsnark, toy, &mut rng).unwrap();
    assert!(verify_field_elements(&vk_libsnark, &inputs, &libsnark_ok).unwrap());
}
