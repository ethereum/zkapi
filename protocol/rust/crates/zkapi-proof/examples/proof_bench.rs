//! Native proving benchmark for the `zkapi-v2-concession-v1` circuits with
//! the shipping `CircomReduction` prover:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example proof_bench -- \
//!   ../setup/v2-concession-dev withdrawal_state_escape 5 1
//! ```
use std::env;
use std::fs;
use std::hint::black_box;
use std::path::Path;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use base64::Engine;
use serde::Serialize;
use zkapi_proof::compact::{
    request_circuit, withdrawal_circuit, RequestProver, RequestVerifier, RequestWitnessData,
    WithdrawalProver, WithdrawalVerifier, WithdrawalWitnessData,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_proof::groth16::{RequestCircuit, WithdrawalCircuit};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalKind, WithdrawalPublicInputsV2C};

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum BenchCase {
    RequestGenesis,
    RequestState,
    WithdrawalGenesisEscape,
    WithdrawalGenesisMutual,
    WithdrawalStateEscape,
    WithdrawalStateMutual,
    WithdrawalStateOwnership,
}

impl BenchCase {
    fn parse(value: &str) -> Result<Self> {
        match value {
            "request_genesis" => Ok(Self::RequestGenesis),
            "request_state" => Ok(Self::RequestState),
            "withdrawal_genesis_escape" => Ok(Self::WithdrawalGenesisEscape),
            "withdrawal_genesis_mutual" => Ok(Self::WithdrawalGenesisMutual),
            "withdrawal_state_escape" => Ok(Self::WithdrawalStateEscape),
            "withdrawal_state_mutual" => Ok(Self::WithdrawalStateMutual),
            "withdrawal_state_ownership" => Ok(Self::WithdrawalStateOwnership),
            _ => bail!(
                "unknown case {value:?}; expected request_genesis, request_state, \
                 withdrawal_genesis_escape, withdrawal_genesis_mutual, \
                 withdrawal_state_escape, withdrawal_state_mutual, or \
                 withdrawal_state_ownership"
            ),
        }
    }

    fn is_request(self) -> bool {
        matches!(self, Self::RequestGenesis | Self::RequestState)
    }
}

#[derive(Debug, Serialize)]
struct Distribution {
    samples_ms: Vec<f64>,
    min_ms: f64,
    median_ms: f64,
    mean_ms: f64,
    p95_ms: f64,
    max_ms: f64,
}

impl Distribution {
    fn new(samples_ms: Vec<f64>) -> Self {
        let mut sorted = samples_ms.clone();
        sorted.sort_by(f64::total_cmp);
        let len = sorted.len();
        let median_ms = if len.is_multiple_of(2) {
            (sorted[len / 2 - 1] + sorted[len / 2]) / 2.0
        } else {
            sorted[len / 2]
        };
        let p95_index = ((len as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(len - 1);
        Self {
            min_ms: sorted[0],
            median_ms,
            mean_ms: sorted.iter().sum::<f64>() / len as f64,
            p95_ms: sorted[p95_index],
            max_ms: sorted[len - 1],
            samples_ms,
        }
    }
}

#[derive(Debug, Serialize)]
struct BenchResult {
    case: BenchCase,
    iterations: usize,
    load_iterations: usize,
    warmup_iterations: usize,
    rayon_threads: String,
    proving_key_bytes: u64,
    verifying_key_bytes: u64,
    constraints: usize,
    instance_variables: usize,
    witness_variables: usize,
    proof_bytes: usize,
    prover_load: Distribution,
    verifier_load: Distribution,
    prove: Distribution,
    verify: Distribution,
}

#[derive(Clone)]
struct RequestFixture {
    public: RequestPublicInputsV2,
    witness: RequestWitnessData,
    circuit: RequestCircuit,
}

#[derive(Clone)]
struct WithdrawalFixture {
    public: WithdrawalPublicInputsV2C,
    witness: WithdrawalWitnessData,
    circuit: WithdrawalCircuit,
}

fn main() -> Result<()> {
    let args = env::args().collect::<Vec<_>>();
    if !(5..=6).contains(&args.len()) {
        bail!(
            "usage: proof_bench SETUP_DIRECTORY CASE ITERATIONS WARMUP_ITERATIONS \
             [LOAD_ITERATIONS]"
        );
    }
    let setup = Path::new(&args[1]);
    let case = BenchCase::parse(&args[2])?;
    let iterations = parse_positive("ITERATIONS", &args[3])?;
    let warmup_iterations = args[4]
        .parse::<usize>()
        .with_context(|| format!("invalid WARMUP_ITERATIONS {:?}", args[4]))?;
    let load_iterations = args
        .get(5)
        .map(|value| parse_positive("LOAD_ITERATIONS", value))
        .transpose()?
        .unwrap_or(iterations);

    let result = if case.is_request() {
        bench_request(setup, case, iterations, warmup_iterations, load_iterations)?
    } else {
        bench_withdrawal(setup, case, iterations, warmup_iterations, load_iterations)?
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn parse_positive(name: &str, value: &str) -> Result<usize> {
    let parsed = value
        .parse::<usize>()
        .with_context(|| format!("invalid {name} {value:?}"))?;
    if parsed == 0 {
        bail!("{name} must be positive");
    }
    Ok(parsed)
}

fn bench_request(
    setup: &Path,
    case: BenchCase,
    iterations: usize,
    warmup_iterations: usize,
    load_iterations: usize,
) -> Result<BenchResult> {
    let fixture = request_fixture(matches!(case, BenchCase::RequestGenesis))?;
    let (constraints, instance_variables, witness_variables) = constraint_counts(fixture.circuit)?;

    let (prover, prover_load) = timed_load(load_iterations, || RequestProver::load(setup))?;
    let (verifier, verifier_load) = timed_load(load_iterations, || RequestVerifier::load(setup))?;

    for _ in 0..warmup_iterations {
        let proof = prover.prove(&fixture.public, fixture.witness.clone())?;
        if !verifier.verify(&fixture.public, &proof)? {
            bail!("request warmup proof did not verify");
        }
    }

    let mut proofs = Vec::with_capacity(iterations);
    let mut prove_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let proof = prover.prove(
            black_box(&fixture.public),
            black_box(fixture.witness.clone()),
        )?;
        prove_ms.push(elapsed_ms(started));
        proofs.push(proof);
    }
    let proof_bytes = decoded_proof_len(&proofs[0].proof)?;
    let mut verify_ms = Vec::with_capacity(iterations);
    for proof in &proofs {
        let started = Instant::now();
        if !verifier.verify(black_box(&fixture.public), black_box(proof))? {
            bail!("request proof did not verify");
        }
        verify_ms.push(elapsed_ms(started));
    }

    Ok(BenchResult {
        case,
        iterations,
        load_iterations,
        warmup_iterations,
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        proving_key_bytes: fs::metadata(setup.join("request.pk"))?.len(),
        verifying_key_bytes: fs::metadata(setup.join("request.vk"))?.len(),
        constraints,
        instance_variables,
        witness_variables,
        proof_bytes,
        prover_load: Distribution::new(prover_load),
        verifier_load: Distribution::new(verifier_load),
        prove: Distribution::new(prove_ms),
        verify: Distribution::new(verify_ms),
    })
}

fn bench_withdrawal(
    setup: &Path,
    case: BenchCase,
    iterations: usize,
    warmup_iterations: usize,
    load_iterations: usize,
) -> Result<BenchResult> {
    let genesis = matches!(
        case,
        BenchCase::WithdrawalGenesisEscape | BenchCase::WithdrawalGenesisMutual
    );
    let kind = match case {
        BenchCase::WithdrawalGenesisMutual | BenchCase::WithdrawalStateMutual => {
            WithdrawalKind::MutualClose
        }
        BenchCase::WithdrawalStateOwnership => WithdrawalKind::Ownership,
        _ => WithdrawalKind::Escape,
    };
    let fixture = withdrawal_fixture(genesis, kind)?;
    let (constraints, instance_variables, witness_variables) = constraint_counts(fixture.circuit)?;

    let (prover, prover_load) = timed_load(load_iterations, || WithdrawalProver::load(setup))?;
    let (verifier, verifier_load) =
        timed_load(load_iterations, || WithdrawalVerifier::load(setup))?;

    for _ in 0..warmup_iterations {
        let proof = prover.prove(&fixture.public, fixture.witness.clone())?;
        if !verifier.verify(&fixture.public, &proof)? {
            bail!("withdrawal warmup proof did not verify");
        }
    }

    let mut proofs = Vec::with_capacity(iterations);
    let mut prove_ms = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let proof = prover.prove(
            black_box(&fixture.public),
            black_box(fixture.witness.clone()),
        )?;
        prove_ms.push(elapsed_ms(started));
        proofs.push(proof);
    }
    let proof_bytes = decoded_proof_len(&proofs[0].proof)?;
    let mut verify_ms = Vec::with_capacity(iterations);
    for proof in &proofs {
        let started = Instant::now();
        if !verifier.verify(black_box(&fixture.public), black_box(proof))? {
            bail!("withdrawal proof did not verify");
        }
        verify_ms.push(elapsed_ms(started));
    }

    Ok(BenchResult {
        case,
        iterations,
        load_iterations,
        warmup_iterations,
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        proving_key_bytes: fs::metadata(setup.join("withdrawal.pk"))?.len(),
        verifying_key_bytes: fs::metadata(setup.join("withdrawal.vk"))?.len(),
        constraints,
        instance_variables,
        witness_variables,
        proof_bytes,
        prover_load: Distribution::new(prover_load),
        verifier_load: Distribution::new(verifier_load),
        prove: Distribution::new(prove_ms),
        verify: Distribution::new(verify_ms),
    })
}

fn timed_load<T>(iterations: usize, mut load: impl FnMut() -> Result<T>) -> Result<(T, Vec<f64>)> {
    let mut samples = Vec::with_capacity(iterations);
    let mut last = None;
    for _ in 0..iterations {
        let started = Instant::now();
        last = Some(load()?);
        samples.push(elapsed_ms(started));
    }
    Ok((last.context("load loop produced no value")?, samples))
}

fn constraint_counts<C: ConstraintSynthesizer<Fr>>(circuit: C) -> Result<(usize, usize, usize)> {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone())?;
    if !cs.is_satisfied()? {
        bail!("benchmark circuit is not satisfied");
    }
    Ok((
        cs.num_constraints(),
        cs.num_instance_variables(),
        cs.num_witness_variables(),
    ))
}

struct Common {
    deployment: DevDeployment,
    tree: zkapi_core::MerkleTree,
    state: DevState,
    request: DevRequest,
}

/// Genesis, or the signed successor of a genesis request (charge 100,000).
fn common(genesis: bool) -> Result<Common> {
    let deployment = DevDeployment::new(31_337, Felt252::from_u64(0x1234));
    let note = DevNote {
        secret: Felt252::from_u64(42),
        note_id: 0,
        deposit_amount: 1_000_000,
        expiry: 4_000_000_000,
    };
    let tree = tree_with(&[&note]);
    let request = DevRequest {
        request_time: 2_000_000_000,
        solvency_bound: 500_000,
        request_context: Felt252::from_u64(99),
        rerandomization: Felt252::from_u64(9),
    };
    let genesis_state = note.genesis(Felt252::from_u64(7));
    let state = if genesis {
        genesis_state
    } else {
        genesis_state.successor(&deployment, &request, 100_000, &Felt252::from_u64(17))?
    };
    Ok(Common {
        deployment,
        tree,
        state,
        request,
    })
}

fn request_fixture(genesis: bool) -> Result<RequestFixture> {
    let common = common(genesis)?;
    let (public, witness) =
        common
            .state
            .request(&common.deployment, &common.tree, &common.request)?;
    let circuit = request_circuit(&public, &witness)?;
    Ok(RequestFixture {
        public,
        witness,
        circuit,
    })
}

fn withdrawal_fixture(genesis: bool, kind: WithdrawalKind) -> Result<WithdrawalFixture> {
    let common = common(genesis)?;
    let (destination, conceded) = match kind {
        WithdrawalKind::Escape => ([0x11; 20], 50_000),
        WithdrawalKind::MutualClose => ([0x11; 20], 0),
        WithdrawalKind::Ownership => ([0; 20], 0),
    };
    let (public, witness) = common.state.withdrawal(
        &common.deployment,
        &common.tree,
        &DevWithdrawal {
            kind,
            destination,
            conceded,
            valid_until: 2_000_010_800,
        },
    )?;
    let circuit = withdrawal_circuit(&public, &witness)?;
    Ok(WithdrawalFixture {
        public,
        witness,
        circuit,
    })
}

fn decoded_proof_len(encoded: &str) -> Result<usize> {
    Ok(base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode proof")?
        .len())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}
