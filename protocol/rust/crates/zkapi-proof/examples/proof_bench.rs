//! Native proving benchmark for the `zkapi-v2-concession-v2` circuits with
//! the shipping `CircomReduction` prover:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example proof_bench -- \
//!   ../setup/v2-concession-dev withdrawal_state_escape 5 1
//! ```
//!
//! The `insertion1`, `insertion4` and `insertion16` cases time the operator's
//! activation proofs: K notes appended at cursor K, after K activated notes.
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
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    request_circuit, withdrawal_circuit, InsertionProver, InsertionVerifier, KeyKind,
    RequestProver, RequestVerifier, RequestWitnessData, WithdrawalProver, WithdrawalVerifier,
    WithdrawalWitnessData,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_proof::groth16::{RequestCircuit, WithdrawalCircuit};
use zkapi_proof::insertion::{
    insertion_roots, InsertedNote, InsertionCircuit, InsertionPublic, InsertionWitness,
};
use zkapi_types::wire::Groth16ProofWire;
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
    Insertion1,
    Insertion4,
    Insertion16,
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
            "insertion1" => Ok(Self::Insertion1),
            "insertion4" => Ok(Self::Insertion4),
            "insertion16" => Ok(Self::Insertion16),
            _ => bail!(
                "unknown case {value:?}; expected request_genesis, request_state, \
                 withdrawal_genesis_escape, withdrawal_genesis_mutual, \
                 withdrawal_state_escape, withdrawal_state_mutual, \
                 withdrawal_state_ownership, insertion1, insertion4, or insertion16"
            ),
        }
    }

    fn kind(self) -> KeyKind {
        match self {
            Self::RequestGenesis | Self::RequestState => KeyKind::Request,
            Self::Insertion1 => KeyKind::Insertion1,
            Self::Insertion4 => KeyKind::Insertion4,
            Self::Insertion16 => KeyKind::Insertion16,
            _ => KeyKind::Withdrawal,
        }
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

    let runs = Runs {
        iterations,
        warmup_iterations,
        load_iterations,
    };
    let result = match case.kind() {
        KeyKind::Request => bench_request(setup, case, &runs)?,
        KeyKind::Withdrawal => bench_withdrawal(setup, case, &runs)?,
        KeyKind::Insertion1 | KeyKind::Insertion4 | KeyKind::Insertion16 => {
            bench_insertion(setup, case, &runs)?
        }
    };
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

struct Runs {
    iterations: usize,
    warmup_iterations: usize,
    load_iterations: usize,
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

fn bench_request(setup: &Path, case: BenchCase, runs: &Runs) -> Result<BenchResult> {
    let fixture = request_fixture(matches!(case, BenchCase::RequestGenesis))?;
    let counts = constraint_counts(fixture.circuit)?;
    measure(
        setup,
        case,
        runs,
        counts,
        || RequestProver::load(setup),
        || RequestVerifier::load(setup),
        |prover| {
            prover.prove(
                black_box(&fixture.public),
                black_box(fixture.witness.clone()),
            )
        },
        |verifier, proof| verifier.verify(black_box(&fixture.public), proof),
    )
}

fn bench_withdrawal(setup: &Path, case: BenchCase, runs: &Runs) -> Result<BenchResult> {
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
    let counts = constraint_counts(fixture.circuit)?;
    measure(
        setup,
        case,
        runs,
        counts,
        || WithdrawalProver::load(setup),
        || WithdrawalVerifier::load(setup),
        |prover| {
            prover.prove(
                black_box(&fixture.public),
                black_box(fixture.witness.clone()),
            )
        },
        |verifier, proof| verifier.verify(black_box(&fixture.public), proof),
    )
}

fn bench_insertion(setup: &Path, case: BenchCase, runs: &Runs) -> Result<BenchResult> {
    let size = case.kind().insertion_size().context("an insertion case")?;
    let circuit = insertion_fixture(size);
    let counts = constraint_counts(circuit.clone())?;
    measure(
        setup,
        case,
        runs,
        counts,
        || InsertionProver::load(setup, size),
        || InsertionVerifier::load(setup, size),
        |prover| prover.prove(black_box(&circuit.public), black_box(&circuit.witness)),
        |verifier, proof| verifier.verify(black_box(&circuit.public), proof),
    )
}

/// Time loading the keys of `case`, then proving and verifying its fixture.
#[allow(clippy::too_many_arguments)]
fn measure<P, V>(
    setup: &Path,
    case: BenchCase,
    runs: &Runs,
    (constraints, instance_variables, witness_variables): (usize, usize, usize),
    load_prover: impl FnMut() -> Result<P>,
    load_verifier: impl FnMut() -> Result<V>,
    prove: impl Fn(&P) -> Result<Groth16ProofWire>,
    verify: impl Fn(&V, &Groth16ProofWire) -> Result<bool>,
) -> Result<BenchResult> {
    let kind = case.kind();
    let (prover, prover_load) = timed_load(runs.load_iterations, load_prover)?;
    let (verifier, verifier_load) = timed_load(runs.load_iterations, load_verifier)?;

    for _ in 0..runs.warmup_iterations {
        let proof = prove(&prover)?;
        if !verify(&verifier, &proof)? {
            bail!("{kind} warmup proof did not verify");
        }
    }

    let mut proofs = Vec::with_capacity(runs.iterations);
    let mut prove_ms = Vec::with_capacity(runs.iterations);
    for _ in 0..runs.iterations {
        let started = Instant::now();
        let proof = prove(&prover)?;
        prove_ms.push(elapsed_ms(started));
        proofs.push(proof);
    }
    let proof_bytes = decoded_proof_len(&proofs[0].proof)?;
    let mut verify_ms = Vec::with_capacity(runs.iterations);
    for proof in &proofs {
        let started = Instant::now();
        if !verify(&verifier, black_box(proof))? {
            bail!("{kind} proof did not verify");
        }
        verify_ms.push(elapsed_ms(started));
    }

    Ok(BenchResult {
        case,
        iterations: runs.iterations,
        load_iterations: runs.load_iterations,
        warmup_iterations: runs.warmup_iterations,
        rayon_threads: env::var("RAYON_NUM_THREADS").unwrap_or_else(|_| "default".into()),
        proving_key_bytes: fs::metadata(setup.join(kind.proving_key_file()))?.len(),
        verifying_key_bytes: fs::metadata(setup.join(kind.verifying_key_file()))?.len(),
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

/// `size` notes appended at cursor `size`, after `size` activated notes.
fn insertion_fixture(size: usize) -> InsertionCircuit {
    let notes: Vec<DevNote> = (0..2 * size as u32)
        .map(|note_id| DevNote {
            secret: Felt252::from_u64(1_000 + u64::from(note_id)),
            note_id,
            deposit_amount: 1_000_000,
            expiry: 4_000_000_000,
        })
        .collect();
    let (activated, appended) = notes.split_at(size);
    let tree = tree_with(&activated.iter().collect::<Vec<_>>());
    let first_note_id = size as u32;
    let siblings = tree
        .get_siblings(first_note_id)
        .map(|value| core::felt_to_field(&value));
    let notes: Vec<InsertedNote> = appended
        .iter()
        .map(|note| InsertedNote {
            registration_commitment: core::felt_to_field(&note.registration()),
            deposit_amount: note.deposit_amount,
            expiry: note.expiry,
        })
        .collect();
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

fn decoded_proof_len(encoded: &str) -> Result<usize> {
    Ok(base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .context("decode proof")?
        .len())
}

fn elapsed_ms(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}
