//! Import the snarkjs phase-2 keys of the ceremony (G-SETUP step 6):
//!
//! ```text
//! cargo run --release -p zkapi-proof --example import_zkey -- \
//!   --setup-id mpc-1 \
//!   --ptau pot.ptau --ptau-sha256 HEX \
//!   --request-r1cs request.r1cs --withdrawal-r1cs withdrawal.r1cs \
//!   --request request_final.zkey --withdrawal withdrawal_final.zkey \
//!   --transcript-sha256 HEX \
//!   OUTPUT_DIRECTORY
//! ```
//!
//! `--setup-id` is `mpc-1` for the ceremony and `rehearsal` for a dry run
//! (which only `dev-setup` builds load). An `mpc-1` import also needs the
//! pinned `--ptau-sha256`, the `--transcript-sha256`, a powers of tau that is
//! a public phase-1 transcript of `ceremony::PUBLIC_PTAU`, and zkeys that
//! record at least three contributions followed by a beacon.
//!
//! Gates, all before anything is written:
//! 1. the `.r1cs` files the ceremony used are byte for byte this build's
//!    export (`r1cs::r1cs_bytes`), and the powers of tau hashes to
//!    `--ptau-sha256` when given;
//! 2. the powers of tau: for `mpc-1`, its Blake2b-512 is the published hash
//!    of a transcript of `ceremony::PUBLIC_PTAU` (a file the coordinator
//!    made could hold a known `τ`, which forges every proof); and the points
//!    the keys are checked against form one reference string
//!    (`Ptau::lagrange_bases`);
//! 3. for each zkey (read with `ark_circom::read_zkey`):
//!    * coefficients: the A and B coefficient lists of zkey section 4, the
//!      constraint count and the variable counts equal the synthesized
//!      circuit. Our prover never reads section 4 (snarkjs's does), so this
//!      is a consistency check, not the binding;
//!    * shape: 13 / 17 IC points and an H query of the QAP domain size;
//!    * binding (`ceremony::check_key_binding`): every circuit-dependent
//!      point (A and B queries, IC, L and H) is what `snarkjs groth16 setup`
//!      derives from this build's A, B **and C** matrices over the powers of
//!      tau, up to `δ`. A key set up from any other R1CS is refused here;
//!    * proving: a canonical statement proved with the shipping
//!      `CircomReduction` prover verifies under the imported key, and the
//!      same proof with any single public input changed does not.
//!
//! The contribution chain itself (the `δ` updates and their proofs of
//! knowledge) is checked by `snarkjs zkey verify`, which every external
//! reviewer runs on their own export (README step 5).
//!
//! Then it writes the setup directory (keys with
//! `zkapi-v2-concession-v1/<setup_id>/<kind>` headers, `manifest.json` with
//! the SHA-256 of the powers of tau, transcript, R1CS exports and zkeys,
//! `Bn254Poseidon.sol` and the regenerated `Groth16ProofAdapter.sol` with the
//! VK hashes). It refuses to overwrite any of those files.
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::ProvingKey;
use ark_relations::r1cs::ConstraintMatrices;
use zkapi_proof::ceremony::{
    check_key_binding, zkey_contributions, Contribution, LagrangeBases, Ptau, PublicPtau,
    PUBLIC_PTAU,
};
use zkapi_proof::compact::{
    circuit_shape, request_circuit, sha256, withdrawal_circuit, write_setup_directory, KeyKind,
    KindHashes, Prover, SetupManifest, SetupProvenance, CEREMONY_SETUP_ID,
    REQUEST_PROVING_KEY_FILE, REQUEST_VERIFYING_KEY_FILE, SETUP_MANIFEST_FILE,
    SOLIDITY_POSEIDON_FILE, SOLIDITY_VERIFIER_FILE, WITHDRAWAL_PROVING_KEY_FILE,
    WITHDRAWAL_VERIFYING_KEY_FILE,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevWithdrawal};
use zkapi_proof::groth16::verify_field_elements;
use zkapi_proof::r1cs::{circuit_matrices, r1cs_bytes};
use zkapi_types::{Felt252, WithdrawalKind};

/// Contributions an `mpc-1` zkey must record before its beacon.
pub const CEREMONY_MIN_CONTRIBUTIONS: usize = 3;

/// Arguments of one import.
#[derive(Clone, Debug)]
pub struct ImportArgs {
    pub setup_id: String,
    /// The prepared powers of tau `snarkjs groth16 setup` used.
    pub ptau: PathBuf,
    /// The pinned SHA-256 (hex) of `ptau`, required for `mpc-1`.
    pub expected_ptau_sha256: Option<String>,
    /// The public transcripts an `mpc-1` powers of tau must be one of:
    /// [`PUBLIC_PTAU`] (tests substitute their toy file).
    pub public_ptau: Vec<PublicPtau>,
    /// The `.r1cs` files `snarkjs groth16 setup` and `zkey verify` used.
    pub request_r1cs: PathBuf,
    pub withdrawal_r1cs: PathBuf,
    pub request_zkey: PathBuf,
    pub withdrawal_zkey: PathBuf,
    /// SHA-256 (hex) of the published transcript, required for `mpc-1`.
    pub transcript_sha256: Option<String>,
    pub output: PathBuf,
}

/// Run the coefficient, shape, binding and proving gates on zkey bytes.
pub fn check_zkey(zkey: &[u8], kind: KeyKind, bases: &LagrangeBases) -> Result<ProvingKey<Bn254>> {
    let (pk, coefficients) = ark_circom::read_zkey(&mut std::io::Cursor::new(zkey))
        .map_err(|error| anyhow!("read the {kind} zkey: {error}"))?;
    let matrices = circuit_matrices(kind)?;
    check_coefficients(&coefficients, &pk, kind, &matrices)?;
    check_shape(&pk, kind)?;
    check_key_binding(&pk, &matrices, bases).with_context(|| {
        format!(
            "{kind} zkey is not a key of this build's {kind} circuit over this powers of tau \
             (was the ceremony set up from another .r1cs?)"
        )
    })?;
    check_proving(&pk, kind)?;
    Ok(pk)
}

/// [`check_zkey`] on a file.
pub fn read_checked_zkey(
    path: &Path,
    kind: KeyKind,
    bases: &LagrangeBases,
) -> Result<ProvingKey<Bn254>> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    check_zkey(&bytes, kind, bases).with_context(|| format!("import {}", path.display()))
}

fn sorted_rows(rows: &[Vec<(Fr, usize)>]) -> Vec<Vec<(usize, Fr)>> {
    rows.iter()
        .map(|row| {
            let mut row: Vec<(usize, Fr)> =
                row.iter().map(|(value, wire)| (*wire, *value)).collect();
            row.sort_by_key(|(wire, _)| *wire);
            row
        })
        .collect()
}

/// Coefficient gate: zkey section 4 (the A and B coefficients snarkjs's
/// prover reads; `read_zkey` returns no C) and the variable counts equal the
/// synthesized circuit. This keeps snarkjs proving consistent with ours; it
/// does not bind the key, whose points our prover and verifier use instead
/// (that is [`check_key_binding`]'s job).
pub fn check_coefficients(
    zkey: &ConstraintMatrices<Fr>,
    pk: &ProvingKey<Bn254>,
    kind: KeyKind,
    ours: &ConstraintMatrices<Fr>,
) -> Result<()> {
    ensure!(
        zkey.num_instance_variables == ours.num_instance_variables,
        "{kind} zkey has {} instance variables, the circuit {}",
        zkey.num_instance_variables,
        ours.num_instance_variables
    );
    ensure!(
        zkey.num_constraints == ours.num_constraints,
        "{kind} zkey has {} constraints, the circuit {}",
        zkey.num_constraints,
        ours.num_constraints
    );
    let variables = ours.num_instance_variables + ours.num_witness_variables;
    ensure!(
        pk.a_query.len() == variables && pk.b_g2_query.len() == variables,
        "{kind} zkey has {} variables, the circuit {variables}",
        pk.a_query.len()
    );
    ensure!(
        pk.l_query.len() == ours.num_witness_variables,
        "{kind} zkey has {} private variables, the circuit {}",
        pk.l_query.len(),
        ours.num_witness_variables
    );
    ensure!(
        sorted_rows(&zkey.a) == sorted_rows(&ours.a),
        "{kind} zkey A matrix differs from the circuit"
    );
    ensure!(
        sorted_rows(&zkey.b) == sorted_rows(&ours.b),
        "{kind} zkey B matrix differs from the circuit"
    );
    Ok(())
}

/// Shape gate: IC points and the H query size.
pub fn check_shape(pk: &ProvingKey<Bn254>, kind: KeyKind) -> Result<()> {
    let shape = circuit_shape(kind)?;
    ensure!(
        pk.vk.gamma_abc_g1.len() == kind.public_inputs() + 1,
        "{kind} zkey has {} IC points",
        pk.vk.gamma_abc_g1.len()
    );
    ensure!(
        pk.h_query.len() == shape.domain_size,
        "{kind} zkey H query has {} points, expected the domain size {}",
        pk.h_query.len(),
        shape.domain_size
    );
    Ok(())
}

/// Proving gate: the shipping prover's proof of a canonical statement
/// verifies under the imported key, and fails with any one public input
/// changed.
pub fn check_proving(pk: &ProvingKey<Bn254>, kind: KeyKind) -> Result<()> {
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
        solvency_bound: 100_000,
        request_context: Felt252::from_u64(99),
        rerandomization: Felt252::from_u64(9),
    };
    let state = note.genesis(Felt252::from_u64(7)).successor(
        &deployment,
        &request,
        60_000,
        &Felt252::from_u64(17),
    )?;
    let mut rng = rand::rngs::OsRng;
    let (inputs, proof) = match kind {
        KeyKind::Request => {
            let (public, witness) = state.request(&deployment, &tree, &request)?;
            let circuit = request_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (public.to_field_elements().to_vec(), proof)
        }
        KeyKind::Withdrawal => {
            let (public, witness) = state.withdrawal(
                &deployment,
                &tree,
                &DevWithdrawal {
                    kind: WithdrawalKind::Escape,
                    destination: [0xff; 20],
                    conceded: 50_000,
                    valid_until: 2_000_010_800,
                },
            )?;
            let circuit = withdrawal_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (public.to_field_elements().to_vec(), proof)
        }
    };
    let fields: Vec<Fr> = inputs.iter().map(zkapi_core::v2::felt_to_field).collect();
    ensure!(
        verify_field_elements(&pk.vk, &fields, &proof)?,
        "{kind} proving gate: the CircomReduction proof does not verify under the imported key"
    );
    for index in 0..fields.len() {
        let mut mutated = fields.clone();
        mutated[index] += Fr::from(1u64);
        ensure!(
            !verify_field_elements(&pk.vk, &mutated, &proof)?,
            "{kind} proving gate: the statement with input {index} changed verifies"
        );
    }
    Ok(())
}

/// Refuse an `.r1cs` file other than this build's export of `kind`.
pub fn check_r1cs_file(path: &Path, kind: KeyKind) -> Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let ours = r1cs_bytes(kind)?;
    ensure!(
        bytes == ours,
        "{} (sha256 {}) is not this build's {kind} R1CS export (sha256 {}): \
         the ceremony must be set up from `examples/export_r1cs.rs` output",
        path.display(),
        hex::encode(sha256(&bytes)),
        hex::encode(sha256(&ours))
    );
    Ok(())
}

/// Refuse a zkey that does not record [`CEREMONY_MIN_CONTRIBUTIONS`]
/// contributions followed by a beacon (the ceremony's shape; the chain itself
/// is `snarkjs zkey verify`'s to check).
pub fn check_ceremony_contributions(zkey: &[u8], kind: KeyKind) -> Result<()> {
    let contributions = zkey_contributions(zkey).with_context(|| format!("{kind} zkey"))?;
    let (last, before) = contributions
        .split_last()
        .ok_or_else(|| anyhow!("the {kind} zkey records no contribution"))?;
    ensure!(
        *last == Contribution::Beacon
            && before.len() >= CEREMONY_MIN_CONTRIBUTIONS
            && before.iter().all(|c| *c == Contribution::Contribution),
        "the {kind} zkey records {contributions:?}; a {CEREMONY_SETUP_ID} setup needs at least \
         {CEREMONY_MIN_CONTRIBUTIONS} contributions followed by a beacon (import dry runs with \
         --setup-id rehearsal)"
    );
    Ok(())
}

/// Run every gate on both zkeys and write the setup directory. The directory
/// may exist (for example holding only its README) but must hold none of the
/// files the import writes.
pub fn import(args: &ImportArgs) -> Result<SetupManifest> {
    for file in [
        REQUEST_PROVING_KEY_FILE,
        REQUEST_VERIFYING_KEY_FILE,
        WITHDRAWAL_PROVING_KEY_FILE,
        WITHDRAWAL_VERIFYING_KEY_FILE,
        SETUP_MANIFEST_FILE,
        SOLIDITY_POSEIDON_FILE,
        SOLIDITY_VERIFIER_FILE,
    ] {
        ensure!(
            !args.output.join(file).exists(),
            "refusing to overwrite {} in {}",
            file,
            args.output.display()
        );
    }
    let ceremony = args.setup_id == CEREMONY_SETUP_ID;
    if ceremony {
        ensure!(
            args.expected_ptau_sha256.is_some() && args.transcript_sha256.is_some(),
            "a {CEREMONY_SETUP_ID} import needs --ptau-sha256 (the pinned powers of tau) and \
             --transcript-sha256"
        );
    }
    let ptau = Ptau::open(&args.ptau)?;
    let ptau_sha256 = hex::encode(ptau.sha256());
    let ptau_blake2b512 = hex::encode(ptau.blake2b512());
    if let Some(expected) = &args.expected_ptau_sha256 {
        ensure!(
            *expected == ptau_sha256,
            "{} has sha256 {ptau_sha256}, not the pinned {expected}",
            args.ptau.display()
        );
    }
    let public = ptau.public_transcript(&args.public_ptau);
    if ceremony {
        ensure!(
            public.is_some(),
            "{} (power {}, blake2b512 {ptau_blake2b512}) is not a public phase-1 transcript of \
             ceremony::PUBLIC_PTAU: whoever made a powers of tau alone can forge every proof of \
             a {CEREMONY_SETUP_ID} setup built on it. Use a listed file as its publisher \
             published it",
            args.ptau.display(),
            ptau.power()
        );
    }
    println!(
        "powers of tau {}: power {}, sha256 {ptau_sha256}, blake2b512 {ptau_blake2b512}, {}",
        args.ptau.display(),
        ptau.power(),
        public.map_or("not a listed public transcript".to_string(), |public| {
            format!("the public transcript {}", public.name)
        })
    );
    check_r1cs_file(&args.request_r1cs, KeyKind::Request)?;
    check_r1cs_file(&args.withdrawal_r1cs, KeyKind::Withdrawal)?;

    let mut keys = Vec::new();
    let mut zkey_sha256 = Vec::new();
    for (kind, path) in [
        (KeyKind::Request, &args.request_zkey),
        (KeyKind::Withdrawal, &args.withdrawal_zkey),
    ] {
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if ceremony {
            check_ceremony_contributions(&bytes, kind)?;
        }
        let bases = ptau.lagrange_bases(circuit_shape(kind)?.domain_size)?;
        let pk = check_zkey(&bytes, kind, &bases)
            .with_context(|| format!("import {}", path.display()))?;
        keys.push(pk);
        zkey_sha256.push(hex::encode(sha256(&bytes)));
    }
    let provenance = SetupProvenance {
        ptau_sha256: Some(ptau_sha256),
        transcript_sha256: args.transcript_sha256.clone(),
        zkey_sha256: Some(KindHashes {
            request: zkey_sha256[0].clone(),
            withdrawal: zkey_sha256[1].clone(),
        }),
    };
    write_setup_directory(
        &args.output,
        &args.setup_id,
        &keys[0],
        &keys[1],
        &provenance,
    )
}

fn parse_args() -> Result<ImportArgs> {
    let mut setup_id = None;
    let mut ptau = None;
    let mut expected_ptau_sha256 = None;
    let mut request_r1cs = None;
    let mut withdrawal_r1cs = None;
    let mut request = None;
    let mut withdrawal = None;
    let mut transcript_sha256 = None;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value"));
        match arg.as_str() {
            "--setup-id" => setup_id = Some(value()?),
            "--ptau" => ptau = Some(PathBuf::from(value()?)),
            "--ptau-sha256" => expected_ptau_sha256 = Some(hex_digest(&value()?)?),
            "--request-r1cs" => request_r1cs = Some(PathBuf::from(value()?)),
            "--withdrawal-r1cs" => withdrawal_r1cs = Some(PathBuf::from(value()?)),
            "--request" => request = Some(PathBuf::from(value()?)),
            "--withdrawal" => withdrawal = Some(PathBuf::from(value()?)),
            "--transcript-sha256" => transcript_sha256 = Some(hex_digest(&value()?)?),
            flag if flag.starts_with("--") => bail!("unknown option {flag}"),
            path => {
                ensure!(output.is_none(), "one output directory");
                output = Some(PathBuf::from(path));
            }
        }
    }
    Ok(ImportArgs {
        setup_id: setup_id.context("--setup-id (mpc-1 or rehearsal) is required")?,
        ptau: ptau.context("--ptau FILE is required")?,
        expected_ptau_sha256,
        public_ptau: PUBLIC_PTAU.to_vec(),
        request_r1cs: request_r1cs.context("--request-r1cs FILE is required")?,
        withdrawal_r1cs: withdrawal_r1cs.context("--withdrawal-r1cs FILE is required")?,
        request_zkey: request.context("--request ZKEY is required")?,
        withdrawal_zkey: withdrawal.context("--withdrawal ZKEY is required")?,
        transcript_sha256,
        output: output.context("OUTPUT_DIRECTORY is required")?,
    })
}

fn hex_digest(value: &str) -> Result<String> {
    let value = value.trim_start_matches("0x").to_ascii_lowercase();
    ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "a SHA-256 digest is 64 hex characters"
    );
    Ok(value)
}

#[allow(dead_code)]
fn main() -> Result<()> {
    let args = parse_args()?;
    let manifest = import(&args)?;
    println!(
        "imported {} setup {} into {}\nptau sha256 {}\nrequest VK keccak256 {}\nwithdrawal VK keccak256 {}",
        manifest.circuit_id,
        manifest.setup_id,
        args.output.display(),
        manifest.ptau_sha256.as_deref().unwrap_or("-"),
        manifest.vk_keccak256.request,
        manifest.vk_keccak256.withdrawal
    );
    Ok(())
}
