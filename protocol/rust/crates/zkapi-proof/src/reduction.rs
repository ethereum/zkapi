//! The snarkjs (circom) R1CS-to-QAP reduction for arkworks Groth16.
//!
//! Vendored from `ark-circom` 0.5.0 (`src/circom/qap.rs`, MIT OR Apache-2.0)
//! so that the WebAssembly prover does not depend on `ark-circom` and its
//! WebAssembly runtime. A non-WASM test (`tests/reduction_cross_check.rs`)
//! checks every method against the `ark-circom` crate. The one change is
//! how a row is evaluated (`evaluate_row`): the same sum, without a rayon
//! round trip per row, which makes the witness map about 15 times faster.
//!
//! Every zkAPI prover and the development setup use this reduction
//! ([`crate::compact::Prover`]), so proving keys produced by a snarkjs
//! phase-2 ceremony and keys produced by `ark-groth16`'s generator are used
//! by exactly the same prover. Verification does not depend on the reduction.
//!
//! The reduction differs from `ark-groth16`'s default `LibsnarkReduction` in
//! two places, and nowhere else:
//!
//! * [`R1CSToQAP::h_query_scalars`]: instead of the powers
//!   `t^i · Z(t) / δ`, the H query is the Lagrange basis of the domain of size
//!   `2n` evaluated at `t`, taken at the odd points and divided by `δ`. This is
//!   what snarkjs writes into section 9 of a `.zkey`.
//! * [`R1CSToQAP::witness_map_from_matrices`]: instead of the coefficients of
//!   `(A·B − C)/Z`, the prover supplies the evaluations of `A·B − C` on the odd
//!   coset of the `2n` domain (the points `ω_{2n}^{2i+1}`), where `C` is
//!   computed row by row as `a_i · b_i`. Combined with the H query above this
//!   yields the same `h(t)·Z(t)/δ` term in the proof's `C` element.
//!
//! `instance_map_with_evaluation` is `LibsnarkReduction`'s: the A, B, C and IC
//! queries (including the extra rows that bind each instance variable) are the
//! same in both reductions, and they are what snarkjs computes as well.
//!
//! `ark-groth16` 0.5's generator calls `QAP::h_query_scalars`, so
//! `Groth16::<Bn254, CircomReduction>::circuit_specific_setup` produces keys
//! for this prover (checked by the cross-check test, which proves with keys from
//! both generators).

use ark_ff::PrimeField;
use ark_groth16::r1cs_to_qap::{LibsnarkReduction, R1CSToQAP};
use ark_poly::EvaluationDomain;
use ark_relations::r1cs::{ConstraintMatrices, ConstraintSystemRef, SynthesisError};

/// `<row, assignment>`, the same value as `ark_groth16`'s
/// `evaluate_constraint`. That function folds each row with a rayon parallel
/// iterator, which costs a thread-pool round trip per row when it is called
/// outside the pool: ark-circom's sequential row loop spends about 0.4 s of
/// a 0.65 s request proof there. A plain loop takes under a millisecond.
fn evaluate_row<F: PrimeField>(terms: &[(F, usize)], assignment: &[F]) -> F {
    terms.iter().fold(F::zero(), |sum, (coefficient, index)| {
        let value = assignment[*index];
        if coefficient.is_one() {
            sum + value
        } else {
            sum + value * coefficient
        }
    })
}

/// The snarkjs-compatible R1CS-to-QAP reduction. See the module documentation.
#[derive(Clone, Copy, Debug, Default)]
pub struct CircomReduction;

impl R1CSToQAP for CircomReduction {
    #[allow(clippy::type_complexity)]
    fn instance_map_with_evaluation<F: PrimeField, D: EvaluationDomain<F>>(
        cs: ConstraintSystemRef<F>,
        t: &F,
    ) -> Result<(Vec<F>, Vec<F>, Vec<F>, F, usize, usize), SynthesisError> {
        LibsnarkReduction::instance_map_with_evaluation::<F, D>(cs, t)
    }

    fn witness_map_from_matrices<F: PrimeField, D: EvaluationDomain<F>>(
        matrices: &ConstraintMatrices<F>,
        num_inputs: usize,
        num_constraints: usize,
        full_assignment: &[F],
    ) -> Result<Vec<F>, SynthesisError> {
        let zero = F::zero();
        let domain =
            D::new(num_constraints + num_inputs).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        let domain_size = domain.size();

        // Row evaluations of A and B; the instance rows of A carry the inputs.
        let mut a = vec![zero; domain_size];
        let mut b = vec![zero; domain_size];
        for (row, (a_row, b_row)) in matrices
            .a
            .iter()
            .zip(&matrices.b)
            .take(num_constraints)
            .enumerate()
        {
            a[row] = evaluate_row(a_row, full_assignment);
            b[row] = evaluate_row(b_row, full_assignment);
        }
        a[num_constraints..num_constraints + num_inputs]
            .clone_from_slice(&full_assignment[..num_inputs]);

        // C is computed as A·B row by row, as snarkjs does.
        let mut c = vec![zero; domain_size];
        for ((c_row, a_row), b_row) in c[..num_constraints].iter_mut().zip(&a).zip(&b) {
            *c_row = *a_row * b_row;
        }

        // Move A, B and C to the odd coset of the 2n domain.
        domain.ifft_in_place(&mut a);
        domain.ifft_in_place(&mut b);
        let root_of_unity = {
            let domain_double =
                D::new(2 * domain_size).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
            domain_double.element(1)
        };
        D::distribute_powers_and_mul_by_const(&mut a, root_of_unity, F::one());
        D::distribute_powers_and_mul_by_const(&mut b, root_of_unity, F::one());
        domain.fft_in_place(&mut a);
        domain.fft_in_place(&mut b);

        let mut ab = domain.mul_polynomials_in_evaluation_domain(&a, &b);
        drop(a);
        drop(b);

        domain.ifft_in_place(&mut c);
        D::distribute_powers_and_mul_by_const(&mut c, root_of_unity, F::one());
        domain.fft_in_place(&mut c);

        for (ab_i, c_i) in ab.iter_mut().zip(c) {
            *ab_i -= &c_i;
        }
        Ok(ab)
    }

    fn h_query_scalars<F: PrimeField, D: EvaluationDomain<F>>(
        max_power: usize,
        t: F,
        _: F,
        delta_inverse: F,
    ) -> Result<Vec<F>, SynthesisError> {
        // The usual H query has domain − 1 powers and Z has domain powers, so
        // H·Z has 2·domain − 1 powers.
        let mut scalars = Vec::with_capacity(2 * max_power + 1);
        let mut power = delta_inverse;
        for _ in 0..2 * max_power + 1 {
            scalars.push(power);
            power *= t;
        }
        let domain = D::new(scalars.len()).ok_or(SynthesisError::PolynomialDegreeTooLarge)?;
        // Lagrange coefficients of the 2n domain at t; keep the odd points.
        domain.ifft_in_place(&mut scalars);
        Ok(scalars.into_iter().skip(1).step_by(2).collect())
    }
}
