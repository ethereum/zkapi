//! The ceremony import (`examples/import_zkey.rs`, G-SETUP step 6).
//!
//! A toy ceremony with known `τ, α, β, δ` stands in for snarkjs: its powers of
//! tau is written in the snarkjs `.ptau` layout and its keys are computed the
//! way `snarkjs groth16 setup` derives them (then rescaled by `δ` like a
//! contribution) and written as `.zkey` files. The import must accept those
//! keys, write a loadable setup directory, and refuse every key that is not
//! the circuit's: in particular keys set up from an R1CS whose C matrix
//! differs, which pass every gate but the binding one.
//!
//! The development keys (whose toxic waste is discarded, so no powers of tau
//! matches them) are checked through the zkey reader and the directory writer.
#![cfg(not(target_arch = "wasm32"))]

mod common;

#[allow(dead_code)]
#[path = "../examples/import_zkey.rs"]
mod import_zkey;

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fq, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineRepr, CurveGroup, PrimeGroup, ScalarMul};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_groth16::{ProvingKey, VerifyingKey};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use ark_serialize::CanonicalSerialize;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use common::*;
use import_zkey::{check_coefficients, check_proving, check_shape, check_zkey, import, ImportArgs};
use zkapi_proof::ceremony::{
    check_key_binding, g1_to_lem, g2_to_lem, LagrangeBases, Ptau, PublicPtau, PUBLIC_PTAU,
};
use zkapi_proof::compact::{
    circuit_shape, decode_compressed, decode_compressed_for, sha256, write_setup_directory,
    KeyKind, RequestProver, RequestVerifier, SetupManifest, SetupProvenance, WithdrawalProver,
    WithdrawalVerifier, CEREMONY_SETUP_ID, DEV_SETUP_ID, REHEARSAL_SETUP_ID,
};
use zkapi_proof::r1cs::{circuit_matrices, r1cs_bytes};
use zkapi_types::WithdrawalKind;

// ---- snarkjs file layouts ----

/// snarkjs stores base-field coordinates in Montgomery form, little-endian.
fn put_fq(out: &mut Vec<u8>, value: &Fq) {
    value.0.serialize_uncompressed(&mut *out).unwrap();
}

fn put_g1(out: &mut Vec<u8>, point: &G1Affine) {
    put_fq(out, &point.x);
    put_fq(out, &point.y);
}

fn put_g2(out: &mut Vec<u8>, point: &G2Affine) {
    put_fq(out, &point.x.c0);
    put_fq(out, &point.x.c1);
    put_fq(out, &point.y.c0);
    put_fq(out, &point.y.c1);
}

/// snarkjs stores coefficients as `value · R²` (Montgomery form of `value · R`).
fn put_coefficient(out: &mut Vec<u8>, value: &Fr) {
    let r = Fr::from(2u64).pow([256]);
    (*value * r).0.serialize_uncompressed(&mut *out).unwrap();
}

fn section(out: &mut Vec<u8>, id: u32, body: Vec<u8>) {
    out.extend_from_slice(&id.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(&body);
}

/// A snarkjs Groth16 zkey for `pk` whose coefficient section (4) lists the A
/// and B coefficients of `matrices`, and, when given, a contributions section
/// (10) recording contributions of these types (0 contribution, 1 beacon).
fn write_zkey(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Fr>,
    contributions: Option<&[u32]>,
) -> Vec<u8> {
    let n_public = matrices.num_instance_variables - 1;
    let n_vars = matrices.num_instance_variables + matrices.num_witness_variables;
    let mut out = b"zkey".to_vec();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(9 + u32::from(contributions.is_some())).to_le_bytes());
    section(&mut out, 1, 1u32.to_le_bytes().to_vec());

    let mut header = Vec::new();
    header.extend_from_slice(&32u32.to_le_bytes());
    Fq::MODULUS.serialize_uncompressed(&mut header).unwrap();
    header.extend_from_slice(&32u32.to_le_bytes());
    Fr::MODULUS.serialize_uncompressed(&mut header).unwrap();
    header.extend_from_slice(&(n_vars as u32).to_le_bytes());
    header.extend_from_slice(&(n_public as u32).to_le_bytes());
    header.extend_from_slice(&(pk.h_query.len() as u32).to_le_bytes());
    put_g1(&mut header, &pk.vk.alpha_g1);
    put_g1(&mut header, &pk.beta_g1);
    put_g2(&mut header, &pk.vk.beta_g2);
    put_g2(&mut header, &pk.vk.gamma_g2);
    put_g1(&mut header, &pk.delta_g1);
    put_g2(&mut header, &pk.vk.delta_g2);
    section(&mut out, 2, header);

    let mut ic = Vec::new();
    pk.vk
        .gamma_abc_g1
        .iter()
        .for_each(|point| put_g1(&mut ic, point));
    section(&mut out, 3, ic);

    let mut entries = Vec::new();
    let mut count = 0u32;
    for (matrix_id, matrix) in [(0u32, &matrices.a), (1u32, &matrices.b)] {
        for (row, terms) in matrix.iter().enumerate() {
            for (value, wire) in terms {
                entries.extend_from_slice(&matrix_id.to_le_bytes());
                entries.extend_from_slice(&(row as u32).to_le_bytes());
                entries.extend_from_slice(&(*wire as u32).to_le_bytes());
                put_coefficient(&mut entries, value);
                count += 1;
            }
        }
    }
    // The rows binding each instance variable, as snarkjs adds them.
    for input in 0..=n_public {
        entries.extend_from_slice(&0u32.to_le_bytes());
        entries.extend_from_slice(&((matrices.num_constraints + input) as u32).to_le_bytes());
        entries.extend_from_slice(&(input as u32).to_le_bytes());
        put_coefficient(&mut entries, &Fr::ONE);
        count += 1;
    }
    let mut coefficients = count.to_le_bytes().to_vec();
    coefficients.extend_from_slice(&entries);
    section(&mut out, 4, coefficients);

    let g1_section = |points: &[G1Affine]| {
        let mut body = Vec::new();
        points.iter().for_each(|point| put_g1(&mut body, point));
        body
    };
    section(&mut out, 5, g1_section(&pk.a_query));
    section(&mut out, 6, g1_section(&pk.b_g1_query));
    let mut b2 = Vec::new();
    pk.b_g2_query
        .iter()
        .for_each(|point| put_g2(&mut b2, point));
    section(&mut out, 7, b2);
    section(&mut out, 8, g1_section(&pk.l_query));
    section(&mut out, 9, g1_section(&pk.h_query));
    if let Some(types) = contributions {
        let mut body = vec![0u8; 64];
        body.extend_from_slice(&(types.len() as u32).to_le_bytes());
        for kind in types {
            body.extend_from_slice(&[0u8; 3 * 64 + 128 + 64]);
            body.extend_from_slice(&kind.to_le_bytes());
            body.extend_from_slice(&0u32.to_le_bytes());
        }
        section(&mut out, 10, body);
    }
    assert_eq!(pk.a_query.len(), n_vars);
    out
}

/// The scalars behind sections 2-6 of a powers of tau of `power`: the file
/// holds `x·G1` (or `x·G2`) for each.
#[derive(Clone)]
struct PtauScalars {
    power: u32,
    /// Section 2: `τ^i`, `i < 2^(power + 1) - 1`.
    tau_g1: Vec<Fr>,
    /// Section 3: `τ^i`, `i < 2^power`.
    tau_g2: Vec<Fr>,
    /// Sections 4 and 5: `α·τ^i` and `β·τ^i`, `i < 2^power`.
    alpha_tau_g1: Vec<Fr>,
    beta_tau_g1: Vec<Fr>,
    /// Section 6: `β`.
    beta_g2: Fr,
    /// What section 12's top block (`2^(power + 1)` points) takes for the
    /// power `τ^(2^(power + 1) - 1)` the file lacks: zero (`snarkjs
    /// powersoftau prepare phase2`) or that power (a file truncated from a
    /// larger prepared one, as Hermez's).
    top: Fr,
}

impl PtauScalars {
    /// As `snarkjs powersoftau new`, `contribute` and `prepare phase2`
    /// produce it.
    fn honest(power: u32, secrets: &Secrets) -> Self {
        let powers = |count: usize, first: Fr| {
            let mut value = first;
            (0..count)
                .map(|_| {
                    let current = value;
                    value *= secrets.tau;
                    current
                })
                .collect::<Vec<_>>()
        };
        let half = 1usize << power;
        Self {
            power,
            tau_g1: powers(2 * half - 1, Fr::ONE),
            tau_g2: powers(half, Fr::ONE),
            alpha_tau_g1: powers(half, secrets.alpha),
            beta_tau_g1: powers(half, secrets.beta),
            beta_g2: secrets.beta,
            top: Fr::zero(),
        }
    }

    /// As Hermez's public files: prepared at a larger power, then truncated
    /// to `power` (section 12's top block keeps the power the file lacks).
    fn truncated(power: u32, secrets: &Secrets) -> Self {
        Self {
            top: secrets.tau.pow([(1u64 << (power + 1)) - 1]),
            ..Self::honest(power, secrets)
        }
    }

    /// The block of `size` points of a Lagrange section computed from
    /// `powers`: their inverse FFT. Only section 12's top block runs past the
    /// powers, by one, which takes `top`.
    fn block(powers: &[Fr], size: usize, top: Fr) -> Vec<Fr> {
        let mut values = powers[..powers.len().min(size)].to_vec();
        if values.len() < size {
            values.push(top);
        }
        assert_eq!(values.len(), size);
        Radix2EvaluationDomain::<Fr>::new(size)
            .unwrap()
            .ifft(&values)
    }

    /// `L_j(τ)` of the domain of `n` points, from section 12.
    fn lagrange(&self, n: usize) -> Vec<Fr> {
        Self::block(&self.tau_g1, n, self.top)
    }

    /// The odd points of section 12's block of `2n`: the H query before `δ`.
    fn h(&self, n: usize) -> Vec<Fr> {
        odd(Self::block(&self.tau_g1, 2 * n, self.top))
    }

    /// What `Ptau::lagrange_bases(n)` reads from a file of these scalars.
    fn bases(&self, n: usize) -> LagrangeBases {
        LagrangeBases {
            tau_g1: g1_batch(&self.lagrange(n)),
            tau_g2: g2_batch(&Self::block(&self.tau_g2, n, self.top)),
            alpha_tau_g1: g1_batch(&Self::block(&self.alpha_tau_g1, n, self.top)),
            beta_tau_g1: g1_batch(&Self::block(&self.beta_tau_g1, n, self.top)),
            h_g1: g1_batch(&self.h(n)),
            alpha_g1: g1_batch(&self.alpha_tau_g1[..1])[0],
            beta_g1: g1_batch(&self.beta_tau_g1[..1])[0],
            beta_g2: g2_batch(&[self.beta_g2])[0],
        }
    }
}

/// A prepared powers of tau (snarkjs `prepare phase2` layout): sections 2-6
/// from `scalars`, and the Lagrange blocks the import reads for each domain
/// size `n` of `domains` computed from `lagrange` (normally the same
/// scalars): the size-`n` blocks of sections 12-15 and section 12's
/// size-`2n` block. Every other Lagrange point is zero.
fn ptau_sections(
    scalars: &PtauScalars,
    lagrange: &PtauScalars,
    domains: &[usize],
) -> Vec<(u32, Vec<u8>)> {
    let power = scalars.power;
    let points = |top: u32| (1usize << (top + 1)) - 1;
    let mut sections = [
        (12u32, &lagrange.tau_g1, vec![0u8; points(power + 1) * 64]),
        (14, &lagrange.alpha_tau_g1, vec![0u8; points(power) * 64]),
        (15, &lagrange.beta_tau_g1, vec![0u8; points(power) * 64]),
    ];
    let mut lagrange_g2 = vec![0u8; points(power) * 128];
    for &n in domains {
        for (id, powers, section) in sections.iter_mut() {
            for size in if *id == 12 { vec![n, 2 * n] } else { vec![n] } {
                let block = g1_batch(&PtauScalars::block(powers, size, lagrange.top));
                for (j, point) in block.iter().enumerate() {
                    let at = (size - 1 + j) * 64;
                    section[at..at + 64].copy_from_slice(&g1_to_lem(point));
                }
            }
        }
        let block = g2_batch(&PtauScalars::block(&lagrange.tau_g2, n, lagrange.top));
        for (j, point) in block.iter().enumerate() {
            let at = (n - 1 + j) * 128;
            lagrange_g2[at..at + 128].copy_from_slice(&g2_to_lem(point));
        }
    }
    let g1_section = |scalars: &[Fr]| {
        let mut body = Vec::new();
        g1_batch(scalars)
            .iter()
            .for_each(|point| body.extend_from_slice(&g1_to_lem(point)));
        body
    };
    let mut tau_powers_g2 = Vec::new();
    g2_batch(&scalars.tau_g2)
        .iter()
        .for_each(|point| tau_powers_g2.extend_from_slice(&g2_to_lem(point)));
    let mut header = 32u32.to_le_bytes().to_vec();
    Fq::MODULUS.serialize_uncompressed(&mut header).unwrap();
    header.extend_from_slice(&power.to_le_bytes());
    header.extend_from_slice(&power.to_le_bytes());
    let [(_, _, tau_g1), (_, _, alpha), (_, _, beta)] = sections;
    vec![
        (1, header),
        (2, g1_section(&scalars.tau_g1)),
        (3, tau_powers_g2),
        (4, g1_section(&scalars.alpha_tau_g1)),
        (5, g1_section(&scalars.beta_tau_g1)),
        (6, g2_to_lem(&g2_batch(&[scalars.beta_g2])[0]).to_vec()),
        (12, tau_g1),
        (13, lagrange_g2),
        (14, alpha),
        (15, beta),
    ]
}

fn binfile(magic: &[u8; 4], sections: Vec<(u32, Vec<u8>)>) -> Vec<u8> {
    let mut out = magic.to_vec();
    out.extend_from_slice(&1u32.to_le_bytes());
    out.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    for (id, body) in sections {
        section(&mut out, id, body);
    }
    out
}

fn write_ptau(scalars: &PtauScalars, domains: &[usize]) -> Vec<u8> {
    binfile(b"ptau", ptau_sections(scalars, scalars, domains))
}

// ---- the toy ceremony ----

struct Secrets {
    tau: Fr,
    alpha: Fr,
    beta: Fr,
    delta: Fr,
}

struct ToyCircuit {
    matrices: ConstraintMatrices<Fr>,
    bases: LagrangeBases,
    /// The honest key: what `snarkjs groth16 setup` plus one contribution
    /// produce for this build's circuit.
    pk: ProvingKey<Bn254>,
}

/// The toy ceremony's powers of tau is shaped like Hermez's smallest public
/// file that fits the circuits (power 15 since one-permutation tree nodes
/// brought both under 2^15 rows, truncated from a larger one): both H
/// queries use section 12's top block, computed with the power the file
/// lacks.
const TOY_POWER: u32 = 15;

struct Toy {
    secrets: Secrets,
    scalars: PtauScalars,
    request: ToyCircuit,
    withdrawal: ToyCircuit,
}

impl Toy {
    fn circuit(&self, kind: KeyKind) -> &ToyCircuit {
        match kind {
            KeyKind::Request => &self.request,
            KeyKind::Withdrawal => &self.withdrawal,
        }
    }
}

fn g1_batch(scalars: &[Fr]) -> Vec<G1Affine> {
    G1Projective::generator().batch_mul(scalars)
}

fn g2_batch(scalars: &[Fr]) -> Vec<G2Affine> {
    G2Projective::generator().batch_mul(scalars)
}

fn scaled(scalars: &[Fr], by: Fr) -> Vec<Fr> {
    scalars.iter().map(|value| *value * by).collect()
}

fn odd(scalars: Vec<Fr>) -> Vec<Fr> {
    scalars.into_iter().skip(1).step_by(2).collect()
}

/// The key `snarkjs groth16 setup` derives for `matrices` (with the
/// instance rows it adds) over the powers of tau of `scalars`, after a
/// contribution that set `δ`.
fn toy_key(
    secrets: &Secrets,
    scalars: &PtauScalars,
    matrices: &ConstraintMatrices<Fr>,
    n: usize,
) -> ProvingKey<Bn254> {
    let l = scalars.lagrange(n);
    let instance = matrices.num_instance_variables;
    let wires = instance + matrices.num_witness_variables;
    let evaluate = |matrix: &[Vec<(Fr, usize)>]| {
        let mut values = vec![Fr::zero(); wires];
        for (row, terms) in matrix.iter().enumerate() {
            for (coefficient, wire) in terms {
                values[*wire] += *coefficient * l[row];
            }
        }
        values
    };
    let mut a = evaluate(&matrices.a);
    for (wire, value) in a.iter_mut().enumerate().take(instance) {
        *value += l[matrices.num_constraints + wire];
    }
    let b = evaluate(&matrices.b);
    let c = evaluate(&matrices.c);
    let k: Vec<Fr> = (0..wires)
        .map(|wire| secrets.beta * a[wire] + secrets.alpha * b[wire] + c[wire])
        .collect();
    let delta_inverse = secrets.delta.inverse().unwrap();
    let g1 = G1Projective::generator();
    let g2 = G2Projective::generator();
    ProvingKey {
        vk: VerifyingKey {
            alpha_g1: (g1 * secrets.alpha).into_affine(),
            beta_g2: (g2 * secrets.beta).into_affine(),
            gamma_g2: G2Affine::generator(),
            delta_g2: (g2 * secrets.delta).into_affine(),
            gamma_abc_g1: g1_batch(&k[..instance]),
        },
        beta_g1: (g1 * secrets.beta).into_affine(),
        delta_g1: (g1 * secrets.delta).into_affine(),
        a_query: g1_batch(&a),
        b_g1_query: g1_batch(&b),
        b_g2_query: g2_batch(&b),
        h_query: g1_batch(&scaled(&scalars.h(n), delta_inverse)),
        l_query: g1_batch(&scaled(&k[instance..], delta_inverse)),
    }
}

fn toy() -> &'static Toy {
    static TOY: OnceLock<Toy> = OnceLock::new();
    TOY.get_or_init(|| {
        let mut rng = StdRng::seed_from_u64(0x7a6b6579);
        let secrets = Secrets {
            tau: Fr::rand(&mut rng),
            alpha: Fr::rand(&mut rng),
            beta: Fr::rand(&mut rng),
            delta: Fr::rand(&mut rng),
        };
        let scalars = PtauScalars::truncated(TOY_POWER, &secrets);
        let circuit = |kind| {
            let matrices = circuit_matrices(kind).unwrap();
            let n = circuit_shape(kind).unwrap().domain_size;
            ToyCircuit {
                bases: scalars.bases(n),
                pk: toy_key(&secrets, &scalars, &matrices, n),
                matrices,
            }
        };
        Toy {
            request: circuit(KeyKind::Request),
            withdrawal: circuit(KeyKind::Withdrawal),
            secrets,
            scalars,
        }
    })
}

/// The red-team's weakening: on up to `limit` rows where A or B is a
/// constant, replace C by the linear form A·B. Honest assignments still
/// satisfy those rows, but they no longer constrain anything (every
/// `enforce_equal` there becomes vacuous).
fn weaken(matrices: &ConstraintMatrices<Fr>, limit: usize) -> (ConstraintMatrices<Fr>, usize) {
    let constant = |terms: &[(Fr, usize)]| match terms {
        [] => Some(Fr::zero()),
        [(value, 0)] => Some(*value),
        _ => None,
    };
    let times = |terms: &[(Fr, usize)], k: Fr| -> Vec<(Fr, usize)> {
        terms
            .iter()
            .map(|(value, wire)| (*value * k, *wire))
            .filter(|(value, _)| !value.is_zero())
            .collect()
    };
    let mut weak = matrices.clone();
    let mut changed = 0;
    for row in 0..matrices.num_constraints {
        if changed == limit {
            break;
        }
        let product = if let Some(k) = constant(&matrices.a[row]) {
            times(&matrices.b[row], k)
        } else if let Some(k) = constant(&matrices.b[row]) {
            times(&matrices.a[row], k)
        } else {
            continue;
        };
        if product != matrices.c[row] {
            weak.c[row] = product;
            changed += 1;
        }
    }
    weak.c_num_non_zero = weak.c.iter().map(Vec::len).sum();
    (weak, changed)
}

fn scratch(name: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("zkey-import-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

const CEREMONY_CONTRIBUTIONS: &[u32] = &[0, 0, 0, 1];

// ---- tests ----

/// The binding gate is the regression for keys set up from an R1CS with the
/// circuit's A and B but another C: such keys pass the coefficient, shape and
/// proving gates (an honest witness satisfies the weakened rows), yet prove
/// false statements. The binding gate refuses them, through `check_zkey`.
#[test]
fn keys_set_up_from_another_c_matrix_are_refused() {
    let toy = toy();
    for (kind, limit) in [(KeyKind::Request, usize::MAX), (KeyKind::Withdrawal, 1)] {
        let honest = toy.circuit(kind);
        let (weak, changed) = weaken(&honest.matrices, limit);
        assert!(changed > 0, "{kind}");
        assert_eq!((&weak.a, &weak.b), (&honest.matrices.a, &honest.matrices.b));
        let n = honest.bases.domain_size();
        let pk = toy_key(&toy.secrets, &toy.scalars, &weak, n);
        // The zkey's coefficient section is the honest one (A and B agree).
        let zkey = write_zkey(&pk, &honest.matrices, Some(CEREMONY_CONTRIBUTIONS));
        let (read, coefficients) = ark_circom::read_zkey(&mut std::io::Cursor::new(&zkey)).unwrap();
        assert_eq!(read, pk);
        // Every other gate passes.
        check_coefficients(&coefficients, &pk, kind, &honest.matrices).unwrap();
        check_shape(&pk, kind).unwrap();
        check_proving(&pk, kind).unwrap();
        // The binding gate does not.
        let error = check_key_binding(&pk, &honest.matrices, &honest.bases)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("does not match the circuit"),
            "{kind}: {error}"
        );
        let error = format!("{:#}", check_zkey(&zkey, kind, &honest.bases).unwrap_err());
        assert!(
            error.contains("is not a key of this build's") && error.contains("does not match"),
            "{kind}: {error}"
        );
        // The honest key over the same bases passes all of them.
        let honest_zkey = write_zkey(&honest.pk, &honest.matrices, None);
        assert_eq!(
            check_zkey(&honest_zkey, kind, &honest.bases).unwrap(),
            honest.pk
        );
    }
}

/// Every point the binding gate covers is checked: changing any one of them
/// is refused with a precise message.
#[test]
fn binding_gate_checks_every_key_point() {
    let toy = toy();
    let circuit = &toy.request;
    let check = |pk: &ProvingKey<Bn254>| {
        check_key_binding(pk, &circuit.matrices, &circuit.bases)
            .err()
            .map(|error| error.to_string())
    };
    assert_eq!(check(&circuit.pk), None);
    fn bump1(point: &G1Affine) -> G1Affine {
        (*point + G1Affine::generator()).into_affine()
    }
    fn times(delta: u64) -> (G1Affine, G2Affine) {
        (
            (G1Affine::generator() * Fr::from(delta)).into_affine(),
            (G2Affine::generator() * Fr::from(delta)).into_affine(),
        )
    }
    type Mutation = fn(&mut ProvingKey<Bn254>);
    let cases: [(&str, Mutation); 11] = [
        ("alpha or beta", |pk| {
            pk.vk.alpha_g1 = bump1(&pk.vk.alpha_g1)
        }),
        ("alpha or beta", |pk| pk.beta_g1 = bump1(&pk.beta_g1)),
        ("gamma", |pk| pk.vk.gamma_g2 = times(2).1),
        ("delta", |pk| pk.delta_g1 = times(5).0),
        ("A query", |pk| pk.a_query[40] = bump1(&pk.a_query[40])),
        ("B query (G1)", |pk| {
            pk.b_g1_query[3] = bump1(&pk.b_g1_query[3])
        }),
        ("B query (G2)", |pk| {
            pk.b_g2_query[3] = (pk.b_g2_query[3] + G2Affine::generator()).into_affine()
        }),
        ("IC", |pk| {
            pk.vk.gamma_abc_g1[12] = bump1(&pk.vk.gamma_abc_g1[12])
        }),
        ("L query", |pk| pk.l_query[1000] = bump1(&pk.l_query[1000])),
        ("H query", |pk| pk.h_query[7] = bump1(&pk.h_query[7])),
        // Re-randomizing δ alone is what a contribution does: the L and H
        // queries must follow it.
        ("L query", |pk| (pk.delta_g1, pk.vk.delta_g2) = times(5)),
    ];
    for (expected, mutate) in cases {
        let mut pk = circuit.pk.clone();
        mutate(&mut pk);
        let error = check(&pk).unwrap_or_else(|| panic!("{expected}: accepted"));
        assert!(error.contains(expected), "{expected}: {error}");
    }
    // A key for one circuit over the other circuit's bases is refused.
    assert!(check_key_binding(&toy.withdrawal.pk, &circuit.matrices, &circuit.bases).is_err());
}

#[test]
fn foreign_or_recoefficiented_zkeys_are_refused() {
    let toy = toy();
    let request = &toy.request;
    // A request key offered as the withdrawal key fails the coefficient gate.
    let zkey = write_zkey(&request.pk, &request.matrices, None);
    let error = format!(
        "{:#}",
        check_zkey(&zkey, KeyKind::Withdrawal, &toy.withdrawal.bases).unwrap_err()
    );
    assert!(error.contains("withdrawal zkey has"), "{error}");
    // One changed A coefficient in section 4 fails it too.
    let mut matrices = request.matrices.clone();
    let row = matrices.a.iter().position(|row| !row.is_empty()).unwrap();
    matrices.a[row][0].0 += Fr::ONE;
    let zkey = write_zkey(&request.pk, &matrices, None);
    let error = format!(
        "{:#}",
        check_zkey(&zkey, KeyKind::Request, &request.bases).unwrap_err()
    );
    assert!(error.contains("A matrix differs"), "{error}");
}

/// The whole import on files: powers of tau, R1CS exports and zkeys.
#[test]
fn toy_ceremony_imports_end_to_end() {
    let toy = toy();
    let dir = scratch("toy");
    let write = |name: &str, bytes: &[u8]| {
        let path = dir.join(name);
        std::fs::write(&path, bytes).unwrap();
        path
    };
    let ptau_bytes = write_ptau(
        &toy.scalars,
        &[
            toy.request.bases.domain_size(),
            toy.withdrawal.bases.domain_size(),
        ],
    );
    let ptau_sha256 = hex::encode(sha256(&ptau_bytes));
    let ptau = write("toy.ptau", &ptau_bytes);
    drop(ptau_bytes);
    // The file reader returns exactly the bases the keys were made from.
    let opened = Ptau::open(&ptau).unwrap();
    assert_eq!(opened.power(), TOY_POWER);
    assert_eq!(hex::encode(opened.sha256()), ptau_sha256);
    assert_eq!(
        opened.lagrange_bases(1 << 15).unwrap(),
        toy.request.bases,
        "request bases"
    );
    // Both H queries come from section 12's top block.
    assert_eq!(
        opened.lagrange_bases(1 << 15).unwrap(),
        toy.withdrawal.bases,
        "withdrawal bases"
    );
    // A toy file is no public transcript.
    assert_eq!(opened.public_transcript(PUBLIC_PTAU), None);
    let toy_transcript = PublicPtau {
        name: "toy.ptau",
        power: TOY_POWER,
        blake2b512: Box::leak(hex::encode(opened.blake2b512()).into_boxed_str()),
    };
    assert_eq!(
        opened.public_transcript(&[toy_transcript]),
        Some(&toy_transcript)
    );
    assert_eq!(
        opened.public_transcript(&[PublicPtau {
            power: 17,
            ..toy_transcript
        }]),
        None,
        "the power must match too"
    );
    let request_r1cs = write("request.r1cs", &r1cs_bytes(KeyKind::Request).unwrap());
    let withdrawal_r1cs = write("withdrawal.r1cs", &r1cs_bytes(KeyKind::Withdrawal).unwrap());
    let zkey = |name: &str, kind: KeyKind, contributions: Option<&[u32]>| {
        let circuit = toy.circuit(kind);
        let bytes = write_zkey(&circuit.pk, &circuit.matrices, contributions);
        let digest = hex::encode(sha256(&bytes));
        (write(name, &bytes), digest)
    };
    let (request_zkey, request_digest) = zkey(
        "request.zkey",
        KeyKind::Request,
        Some(CEREMONY_CONTRIBUTIONS),
    );
    let (withdrawal_zkey, withdrawal_digest) = zkey(
        "withdrawal.zkey",
        KeyKind::Withdrawal,
        Some(CEREMONY_CONTRIBUTIONS),
    );
    let args = ImportArgs {
        setup_id: REHEARSAL_SETUP_ID.to_string(),
        ptau: ptau.clone(),
        expected_ptau_sha256: None,
        public_ptau: PUBLIC_PTAU.to_vec(),
        request_r1cs: request_r1cs.clone(),
        withdrawal_r1cs: withdrawal_r1cs.clone(),
        request_zkey: request_zkey.clone(),
        withdrawal_zkey: withdrawal_zkey.clone(),
        transcript_sha256: None,
        output: dir.join("rehearsal"),
    };
    let manifest = import(&args).unwrap();
    assert_eq!(manifest.setup_id, REHEARSAL_SETUP_ID);
    assert_eq!(manifest.ptau_sha256.as_deref(), Some(ptau_sha256.as_str()));
    let zkeys = manifest.zkey_sha256.clone().unwrap();
    assert_eq!(
        (zkeys.request, zkeys.withdrawal),
        (request_digest, withdrawal_digest)
    );
    for (kind, path) in [
        (KeyKind::Request, &request_r1cs),
        (KeyKind::Withdrawal, &withdrawal_r1cs),
    ] {
        assert_eq!(
            manifest.r1cs_sha256.get(kind),
            hex::encode(sha256(&std::fs::read(path).unwrap()))
        );
    }
    let written: SetupManifest =
        serde_json::from_slice(&std::fs::read(args.output.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(written, manifest);
    // The directory loads (rehearsal keys load in dev-setup builds only) and
    // its keys prove.
    let output = &args.output;
    let (pk, setup_id): (ProvingKey<Bn254>, _) = decode_compressed(
        &std::fs::read(output.join("request.pk")).unwrap(),
        KeyKind::Request,
    )
    .unwrap();
    assert_eq!(
        (pk, setup_id.as_str()),
        (toy.request.pk.clone(), REHEARSAL_SETUP_ID)
    );
    for (file, kind) in [
        ("request.vk", KeyKind::Request),
        ("withdrawal.pk", KeyKind::Withdrawal),
    ] {
        let error = decode_compressed_for::<VerifyingKey<Bn254>>(
            &std::fs::read(output.join(file)).unwrap(),
            kind,
            false,
            None,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("not accepted"), "{error}");
    }
    let c = chain();
    let (public, witness) = c.request_of(&c.s1, &c.r1);
    let proof = RequestProver::load(output)
        .unwrap()
        .prove(&public, witness)
        .unwrap();
    assert!(RequestVerifier::load(output)
        .unwrap()
        .verify(&public, &proof)
        .unwrap());
    let (public, witness) =
        c.withdrawal_of(&c.s1, &withdrawal(WithdrawalKind::Escape, DESTINATION, 1));
    let proof = WithdrawalProver::load(output)
        .unwrap()
        .prove(&public, witness)
        .unwrap();
    assert!(WithdrawalVerifier::load(output)
        .unwrap()
        .verify(&public, &proof)
        .unwrap());

    let refused = |args: &ImportArgs, expected: &str| {
        let error = format!("{:#}", import(args).unwrap_err());
        assert!(error.contains(expected), "{expected}: {error}");
        for file in ["request.pk", "manifest.json"] {
            assert!(
                args.output == dir.join("rehearsal") || !args.output.join(file).exists(),
                "{expected}: wrote {file}"
            );
        }
    };
    // Never overwrite.
    refused(&args, "refusing to overwrite");
    let fresh = |name: &str| ImportArgs {
        output: dir.join(name),
        ..args.clone()
    };
    // The R1CS the ceremony used must be this build's export.
    refused(
        &ImportArgs {
            request_r1cs: withdrawal_r1cs.clone(),
            ..fresh("r1cs")
        },
        "is not this build's request R1CS export",
    );
    // A key set up from a weakened R1CS is refused by the import too.
    let (weak, _) = weaken(&toy.request.matrices, usize::MAX);
    let weak_pk = toy_key(
        &toy.secrets,
        &toy.scalars,
        &weak,
        toy.request.bases.domain_size(),
    );
    let weak_zkey = write(
        "weak.zkey",
        &write_zkey(
            &weak_pk,
            &toy.request.matrices,
            Some(CEREMONY_CONTRIBUTIONS),
        ),
    );
    refused(
        &ImportArgs {
            request_zkey: weak_zkey,
            ..fresh("weak")
        },
        "does not match the circuit",
    );
    // The ceremony setup id needs the pinned powers of tau, which must be a
    // public transcript, the ceremony transcript and zkeys that record the
    // ceremony's contributions.
    let ceremony = |name: &str| ImportArgs {
        setup_id: CEREMONY_SETUP_ID.to_string(),
        expected_ptau_sha256: Some(ptau_sha256.clone()),
        public_ptau: vec![toy_transcript],
        transcript_sha256: Some("ab".repeat(32)),
        ..fresh(name)
    };
    // The toy powers of tau is not on the real list: a file the coordinator
    // made (and pinned) is refused however consistent it is.
    refused(
        &ImportArgs {
            public_ptau: PUBLIC_PTAU.to_vec(),
            ..ceremony("not-public")
        },
        "is not a public phase-1 transcript",
    );
    refused(
        &ImportArgs {
            transcript_sha256: None,
            ..ceremony("no-transcript")
        },
        "--transcript-sha256",
    );
    refused(
        &ImportArgs {
            expected_ptau_sha256: Some("00".repeat(32)),
            ..ceremony("other-ptau")
        },
        "not the pinned",
    );
    let (single, _) = zkey("single.zkey", KeyKind::Request, Some(&[0, 1]));
    refused(
        &ImportArgs {
            request_zkey: single,
            ..ceremony("single")
        },
        "needs at least 3 contributions followed by a beacon",
    );
    let (bare, _) = zkey("bare.zkey", KeyKind::Withdrawal, None);
    refused(
        &ImportArgs {
            withdrawal_zkey: bare,
            ..ceremony("bare")
        },
        "no contributions section",
    );
    let manifest = import(&ceremony("mpc")).unwrap();
    assert_eq!(manifest.setup_id, CEREMONY_SETUP_ID);
    assert_eq!(manifest.transcript_sha256, Some("ab".repeat(32)));
    // Labelled mpc-1 but not pinned: release builds still refuse it.
    let error = decode_compressed_for::<VerifyingKey<Bn254>>(
        &std::fs::read(dir.join("mpc").join("request.vk")).unwrap(),
        KeyKind::Request,
        false,
        None,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("pinned"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn malformed_powers_of_tau_are_refused() {
    let dir = scratch("ptau");
    let open = |bytes: &[u8]| {
        let path = dir.join("bad.ptau");
        std::fs::write(&path, bytes).unwrap();
        Ptau::open(&path).map_err(|error| format!("{error:#}"))
    };
    let scalars = PtauScalars::honest(3, &small_secrets(3));
    let domains = [1, 2, 4, 8];
    let small = write_ptau(&scalars, &domains);
    let ptau = open(&small).unwrap();
    assert_eq!(ptau.power(), 3);
    for size in domains {
        assert_eq!(ptau.lagrange_bases(size).unwrap(), scalars.bases(size));
    }
    for size in [16, 6] {
        assert!(ptau.lagrange_bases(size).is_err(), "{size}");
    }
    // Wrong magic, truncated, another curve.
    let mut wrong = small.clone();
    wrong[0] = b'z';
    assert!(open(&wrong).unwrap_err().contains("not a ptau file"));
    assert!(open(&small[..small.len() - 1]).is_err());
    let mut other_curve = small.clone();
    other_curve[12 + 12 + 4] ^= 1;
    assert!(open(&other_curve).unwrap_err().contains("not a BN254"));
    // A section of the wrong size (another power), or a Lagrange section
    // missing (a powers of tau not prepared for phase 2).
    for (id, size) in [(2, 64 * 14), (3, 128 * 7), (6, 0), (15, 64 * 14)] {
        let mut sections = ptau_sections(&scalars, &scalars, &[]);
        sections
            .iter_mut()
            .find(|(section, _)| *section == id)
            .unwrap()
            .1
            .truncate(size);
        let error = open(&binfile(b"ptau", sections)).unwrap_err();
        assert!(error.contains(&format!("section {id} has")), "{error}");
    }
    let mut sections = ptau_sections(&scalars, &scalars, &[]);
    sections.retain(|(id, _)| *id != 13);
    let error = open(&binfile(b"ptau", sections)).unwrap_err();
    assert!(error.contains("no section 13"), "{error}");
    let _ = std::fs::remove_dir_all(dir);
}

fn small_secrets(seed: u64) -> Secrets {
    let mut rng = StdRng::seed_from_u64(seed);
    Secrets {
        tau: Fr::rand(&mut rng),
        alpha: Fr::rand(&mut rng),
        beta: Fr::rand(&mut rng),
        delta: Fr::rand(&mut rng),
    }
}

/// The binding gate trusts the Lagrange points of the powers of tau, so they
/// must be what `snarkjs powersoftau prepare phase2` computes from the
/// `τ`-power sections, and those must be powers of one `τ` (scaled by `α`
/// and `β`). A file whose Lagrange sections alone were replaced (for
/// example only its H points) is refused; a file one party made from its own
/// `τ` is consistent, so only its hash ([`PUBLIC_PTAU`]) can refuse it.
#[test]
fn powers_of_tau_must_be_one_reference_string() {
    let dir = scratch("srs");
    let bases = |sections: Vec<(u32, Vec<u8>)>, size: usize| {
        let path = dir.join("srs.ptau");
        std::fs::write(&path, binfile(b"ptau", sections)).unwrap();
        Ptau::open(&path)
            .unwrap()
            .lagrange_bases(size)
            .map_err(|error| format!("{error:#}"))
    };
    let honest = PtauScalars::honest(4, &small_secrets(4));
    let other = PtauScalars::honest(4, &small_secrets(5));
    // Every domain, the largest using section 12's top block (32 points from
    // 31 powers), as `prepare phase2` and as `truncate` leave it.
    let domains = [1, 2, 4, 8, 16];
    for scalars in [honest.clone(), PtauScalars::truncated(4, &small_secrets(4))] {
        let sections = ptau_sections(&scalars, &scalars, &domains);
        for size in domains {
            assert_eq!(
                bases(sections.clone(), size).unwrap(),
                scalars.bases(size),
                "{size}"
            );
        }
    }
    // Any other value for the missing power is refused.
    let wrong_top = PtauScalars {
        top: Fr::from(7u64),
        ..honest.clone()
    };
    let error = bases(ptau_sections(&honest, &wrong_top, &[16]), 16).unwrap_err();
    assert!(
        error.contains("size-32 block of section 12 is not the Lagrange basis"),
        "{error}"
    );
    let n = 8;
    assert!(bases(ptau_sections(&other, &other, &[n]), n).is_ok());

    // Lagrange points from another τ than sections 2-5, one block at a time.
    let honest_sections = ptau_sections(&honest, &honest, &[n]);
    let forged_sections = ptau_sections(&honest, &other, &[n]);
    let splice = |id: u32, points: &[usize], width: usize| {
        let mut sections = honest_sections.clone();
        let forged = &forged_sections.iter().find(|(i, _)| *i == id).unwrap().1;
        let body = &mut sections.iter_mut().find(|(i, _)| *i == id).unwrap().1;
        for point in points {
            let range = point * width..(point + 1) * width;
            body[range.clone()].copy_from_slice(&forged[range]);
        }
        sections
    };
    let block = |size: usize| (size - 1..2 * size - 1).collect::<Vec<_>>();
    let h_points: Vec<usize> = block(2 * n).into_iter().skip(1).step_by(2).collect();
    for (what, sections, expected) in [
        (
            "the H points",
            splice(12, &h_points, 64),
            "size-16 block of section 12",
        ),
        (
            "L(τ)·G1",
            splice(12, &block(n), 64),
            "size-8 block of section 12",
        ),
        ("L(τ)·G2", splice(13, &block(n), 128), "section 13"),
        ("α·L(τ)·G1", splice(14, &block(n), 64), "section 14"),
        ("β·L(τ)·G1", splice(15, &block(n), 64), "section 15"),
    ] {
        let error = bases(sections, n).unwrap_err();
        assert!(
            error.contains(expected) && error.contains("is not the Lagrange basis"),
            "{what}: {error}"
        );
    }

    // Power sections that are not powers of one τ, with Lagrange sections
    // computed from them.
    type Tamper = fn(&mut PtauScalars, &PtauScalars);
    let cases: [(&str, Tamper); 7] = [
        ("generators", |s, _| s.tau_g1[0] = Fr::from(2u64)),
        ("section 2 does not hold", |s, _| s.tau_g1[5] += Fr::ONE),
        ("section 3 does not hold", |s, _| s.tau_g2[3] += Fr::ONE),
        ("section 4 does not hold", |s, _| {
            s.alpha_tau_g1[2] += Fr::ONE
        }),
        ("section 5 does not hold", |s, _| {
            s.beta_tau_g1[6] += Fr::ONE
        }),
        ("β·G2 (section 6)", |s, _| s.beta_g2 += Fr::ONE),
        // G2 powers of another τ.
        ("section 2 does not hold", |s, other| {
            s.tau_g2 = other.tau_g2.clone()
        }),
    ];
    for (expected, tamper) in cases {
        let mut scalars = honest.clone();
        tamper(&mut scalars, &other);
        let error = bases(ptau_sections(&scalars, &scalars, &[n]), n).unwrap_err();
        assert!(error.contains(expected), "{expected}: {error}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The development keys survive the snarkjs zkey layout exactly, pass the
/// coefficient and shape gates, and the directory writer reproduces the
/// committed development setup byte for byte from them.
#[test]
fn development_keys_round_trip_through_zkeys() {
    let dir = scratch("dev");
    let mut keys = Vec::new();
    for kind in [KeyKind::Request, KeyKind::Withdrawal] {
        let bytes = std::fs::read(dev_setup_dir().join(kind.proving_key_file())).unwrap();
        let (pk, _): (ProvingKey<Bn254>, _) = decode_compressed(&bytes, kind).unwrap();
        let matrices = circuit_matrices(kind).unwrap();
        let zkey = write_zkey(&pk, &matrices, None);
        let (read, coefficients) = ark_circom::read_zkey(&mut std::io::Cursor::new(&zkey)).unwrap();
        assert_eq!(read, pk, "{kind}");
        check_coefficients(&coefficients, &read, kind, &matrices).unwrap();
        check_shape(&read, kind).unwrap();
        keys.push(read);
    }
    let output = dir.join("setup");
    write_setup_directory(
        &output,
        DEV_SETUP_ID,
        &keys[0],
        &keys[1],
        &SetupProvenance::default(),
    )
    .unwrap();
    for file in [
        "request.pk",
        "request.vk",
        "withdrawal.pk",
        "withdrawal.vk",
        "manifest.json",
        "Groth16ProofAdapter.sol",
        "Bn254Poseidon.sol",
    ] {
        assert!(
            std::fs::read(output.join(file)).unwrap()
                == std::fs::read(dev_setup_dir().join(file)).unwrap(),
            "{file} differs after the zkey round trip"
        );
    }
    let _ = std::fs::remove_dir_all(dir);
}

/// The import gates on real ceremony output, before running the import
/// itself (README step 6):
/// `ZKAPI_PTAU=... ZKAPI_REQUEST_ZKEY=... ZKAPI_WITHDRAWAL_ZKEY=... cargo test
/// --release -p zkapi-proof --test zkey_import ceremony_zkeys_pass_the_import_gates -- --ignored`.
#[test]
#[ignore = "needs ceremony files in ZKAPI_PTAU, ZKAPI_REQUEST_ZKEY and ZKAPI_WITHDRAWAL_ZKEY"]
fn ceremony_zkeys_pass_the_import_gates() {
    let variable = |name: &str| std::env::var(name).unwrap_or_else(|_| panic!("set {name}"));
    let ptau = Ptau::open(variable("ZKAPI_PTAU")).unwrap();
    println!(
        "ptau sha256 {}, blake2b512 {}, public transcript {:?}",
        hex::encode(ptau.sha256()),
        hex::encode(ptau.blake2b512()),
        ptau.public_transcript(PUBLIC_PTAU)
            .map(|public| public.name)
    );
    for (name, kind) in [
        ("ZKAPI_REQUEST_ZKEY", KeyKind::Request),
        ("ZKAPI_WITHDRAWAL_ZKEY", KeyKind::Withdrawal),
    ] {
        let bases = ptau
            .lagrange_bases(circuit_shape(kind).unwrap().domain_size)
            .unwrap();
        import_zkey::read_checked_zkey(Path::new(&variable(name)), kind, &bases)
            .unwrap_or_else(|error| panic!("{kind}: {error:#}"));
        println!("{kind} zkey passes the import gates");
    }
}

/// README steps 3 and 5: the powers of tau is a public transcript of
/// [`PUBLIC_PTAU`] and passes the reference-string checks for both circuits'
/// domains: `ZKAPI_PTAU=powersOfTau28_hez_final_16.ptau cargo test --release
/// -p zkapi-proof --test zkey_import public_powers_of_tau_passes_the_import_checks
/// -- --ignored`.
#[test]
#[ignore = "needs a public powers of tau in ZKAPI_PTAU"]
fn public_powers_of_tau_passes_the_import_checks() {
    let path = std::env::var("ZKAPI_PTAU").expect("set ZKAPI_PTAU");
    let ptau = Ptau::open(&path).unwrap();
    let public = ptau.public_transcript(PUBLIC_PTAU).unwrap_or_else(|| {
        panic!(
            "{path} (blake2b512 {}) is not a transcript of PUBLIC_PTAU",
            hex::encode(ptau.blake2b512())
        )
    });
    println!(
        "{path} is {} (sha256 {})",
        public.name,
        hex::encode(ptau.sha256())
    );
    for kind in [KeyKind::Request, KeyKind::Withdrawal] {
        let n = circuit_shape(kind).unwrap().domain_size;
        ptau.lagrange_bases(n)
            .unwrap_or_else(|error| panic!("{kind}: {error:#}"));
        println!("{kind}: the domain of {n} points passes the reference-string checks");
    }
}
