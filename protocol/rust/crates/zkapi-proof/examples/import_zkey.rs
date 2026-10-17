//! Import the snarkjs phase-2 keys of the ceremony (G-SETUP step 6):
//!
//! ```text
//! cargo run --release -p zkapi-proof --example import_zkey -- \
//!   --setup-id mpc-1 \
//!   --ptau pot.ptau --ptau-sha256 HEX \
//!   --request-r1cs request.r1cs --withdrawal-r1cs withdrawal.r1cs \
//!   --insertion1-r1cs insertion1.r1cs --insertion4-r1cs insertion4.r1cs \
//!   --insertion16-r1cs insertion16.r1cs \
//!   --request request_final.zkey --withdrawal withdrawal_final.zkey \
//!   --insertion1 insertion1_final.zkey --insertion4 insertion4_final.zkey \
//!   --insertion16 insertion16_final.zkey \
//!   --transcript-sha256 HEX \
//!   OUTPUT_DIRECTORY
//! ```
//!
//! Every circuit of the setup (`KeyKind::ALL`) takes an `--<kind>-r1cs` and
//! an `--<kind>` zkey; the import refuses to write a setup missing any.
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
//! 3. for each of the five zkeys (read with `ark_circom::read_zkey`):
//!    * coefficients: the A and B coefficient lists of zkey section 4, the
//!      constraint count and the variable counts equal the synthesized
//!      circuit. Our prover never reads section 4 (snarkjs's does), so this
//!      is a consistency check, not the binding;
//!    * shape: one IC point per public input plus one (13 request, 18
//!      withdrawal, 6 / 12 / 36 insertion) and an H query of the QAP domain
//!      size;
//!    * binding (`ceremony::check_key_binding`): every circuit-dependent
//!      point (A and B queries, IC, L and H) is what `snarkjs groth16 setup`
//!      derives from this build's A, B **and C** matrices over the powers of
//!      tau, up to `δ`. A key set up from any other R1CS is refused here;
//!    * proving: a canonical statement proved with the shipping
//!      `CircomReduction` prover verifies under the imported key, and the
//!      same proof with any single public input changed does not (for an
//!      insertion key, a K-note batch appended after K activated notes).
//!
//! The contribution chain itself (the `δ` updates and their proofs of
//! knowledge) is checked by `snarkjs zkey verify`, which every external
//! reviewer runs on their own export (README step 5).
//!
//! Then it writes the setup directory (ten keys with
//! `zkapi-v2-concession-v2/<setup_id>/<kind>` headers, `manifest.json` with
//! the SHA-256 of the powers of tau, transcript, R1CS exports and zkeys,
//! `Bn254Poseidon.sol` and the regenerated `Groth16ProofAdapter.sol` with the
//! VK hashes). It refuses to overwrite any of those files.
use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Proof, ProvingKey};
use ark_relations::r1cs::ConstraintMatrices;
use zkapi_core::v2 as core;
use zkapi_proof::ceremony::{
    check_key_binding, zkey_contributions, Contribution, LagrangeBases, Ptau, PublicPtau,
    PUBLIC_PTAU,
};
use zkapi_proof::compact::{
    circuit_shape, request_circuit, sha256, withdrawal_circuit, write_setup_directory, KeyKind,
    KindHashes, Prover, SetupKeys, SetupManifest, SetupProvenance, CEREMONY_SETUP_ID,
    SETUP_MANIFEST_FILE, SOLIDITY_POSEIDON_FILE, SOLIDITY_VERIFIER_FILE,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevWithdrawal};
use zkapi_proof::groth16::verify_field_elements;
use zkapi_proof::insertion::{
    insertion_roots, InsertedNote, InsertionCircuit, InsertionPublic, InsertionWitness,
};
use zkapi_proof::r1cs::{circuit_matrices, r1cs_bytes};
use zkapi_types::{Felt252, WithdrawalKind};

/// Contributions an `mpc-1` zkey must record before its beacon.
pub const CEREMONY_MIN_CONTRIBUTIONS: usize = 3;

/// One file per circuit of the setup.
#[derive(Clone, Debug)]
pub struct KindPaths {
    pub request: PathBuf,
    pub withdrawal: PathBuf,
    pub insertion1: PathBuf,
    pub insertion4: PathBuf,
    pub insertion16: PathBuf,
}

impl KindPaths {
    /// The paths of every circuit, given by `path`.
    pub fn try_from_fn(mut path: impl FnMut(KeyKind) -> Result<PathBuf>) -> Result<Self> {
        Ok(Self {
            request: path(KeyKind::Request)?,
            withdrawal: path(KeyKind::Withdrawal)?,
            insertion1: path(KeyKind::Insertion1)?,
            insertion4: path(KeyKind::Insertion4)?,
            insertion16: path(KeyKind::Insertion16)?,
        })
    }

    pub fn get(&self, kind: KeyKind) -> &Path {
        match kind {
            KeyKind::Request => &self.request,
            KeyKind::Withdrawal => &self.withdrawal,
            KeyKind::Insertion1 => &self.insertion1,
            KeyKind::Insertion4 => &self.insertion4,
            KeyKind::Insertion16 => &self.insertion16,
        }
    }

    pub fn get_mut(&mut self, kind: KeyKind) -> &mut PathBuf {
        match kind {
            KeyKind::Request => &mut self.request,
            KeyKind::Withdrawal => &mut self.withdrawal,
            KeyKind::Insertion1 => &mut self.insertion1,
            KeyKind::Insertion4 => &mut self.insertion4,
            KeyKind::Insertion16 => &mut self.insertion16,
        }
    }
}

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
    pub r1cs: KindPaths,
    /// The final zkeys of the ceremony.
    pub zkeys: KindPaths,
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
    let felts = |inputs: &[Felt252]| inputs.iter().map(core::felt_to_field).collect::<Vec<_>>();
    let (fields, proof): (Vec<Fr>, Proof<Bn254>) = match kind {
        KeyKind::Request => {
            let (public, witness) = state.request(&deployment, &tree_with(&[&note]), &request)?;
            let circuit = request_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (felts(&public.to_field_elements()), proof)
        }
        KeyKind::Withdrawal => {
            let (public, witness) = state.withdrawal(
                &deployment,
                &DevWithdrawal {
                    kind: WithdrawalKind::Escape,
                    destination: [0xff; 20],
                    conceded: 50_000,
                    valid_until: 2_000_010_800,
                },
            )?;
            let circuit = withdrawal_circuit(&public, &witness)?;
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (felts(&public.to_field_elements()), proof)
        }
        KeyKind::Insertion1 | KeyKind::Insertion4 | KeyKind::Insertion16 => {
            let circuit = canonical_insertion(kind.insertion_size().expect("insertion kind"));
            let fields = circuit.public.to_field_elements();
            let proof = <Prover as ark_snark::SNARK<Fr>>::prove(pk, circuit, &mut rng)?;
            (fields, proof)
        }
    };
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

/// The canonical insertion statement of the proving gate: `size` notes
/// appended at cursor `size`, after `size` activated notes (so the path above
/// the subtree is not empty).
fn canonical_insertion(size: usize) -> InsertionCircuit {
    let notes: Vec<DevNote> = (0..2 * size as u32)
        .map(|note_id| DevNote {
            secret: Felt252::from_u64(100 + u64::from(note_id)),
            note_id,
            deposit_amount: 1_000_000 + u128::from(note_id),
            expiry: 4_000_000_000 + u64::from(note_id),
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

/// Run every gate on the five zkeys and write the setup directory. The
/// directory may exist (for example holding only its README) but must hold
/// none of the files the import writes.
pub fn import(args: &ImportArgs) -> Result<SetupManifest> {
    for file in KeyKind::ALL
        .iter()
        .flat_map(|kind| [kind.proving_key_file(), kind.verifying_key_file()])
        .chain([
            SETUP_MANIFEST_FILE,
            SOLIDITY_POSEIDON_FILE,
            SOLIDITY_VERIFIER_FILE,
        ])
    {
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
    for kind in KeyKind::ALL {
        check_r1cs_file(args.r1cs.get(kind), kind)?;
    }

    // The cheap checks of every zkey before the expensive gates of any.
    let mut zkeys = Vec::new();
    for kind in KeyKind::ALL {
        let path = args.zkeys.get(kind);
        let bytes = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
        if ceremony {
            check_ceremony_contributions(&bytes, kind)?;
        }
        zkeys.push((kind, path, bytes));
    }
    // Read (and check) the bases once per QAP domain size: today every
    // circuit has the domain of 2^15 points.
    let mut bases = BTreeMap::new();
    let mut keys = Vec::new();
    let mut zkey_sha256 = Vec::new();
    for (kind, path, bytes) in zkeys {
        let bases = match bases.entry(circuit_shape(kind)?.domain_size) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let domain_size = *entry.key();
                entry.insert(ptau.lagrange_bases(domain_size)?)
            }
        };
        let pk = check_zkey(&bytes, kind, bases)
            .with_context(|| format!("import {}", path.display()))?;
        keys.push(pk);
        zkey_sha256.push(hex::encode(sha256(&bytes)));
    }
    let position = |kind: KeyKind| KeyKind::ALL.iter().position(|k| *k == kind).unwrap();
    let provenance = SetupProvenance {
        ptau_sha256: Some(ptau_sha256),
        transcript_sha256: args.transcript_sha256.clone(),
        zkey_sha256: Some(KindHashes::try_from_fn(|kind| {
            Ok(zkey_sha256[position(kind)].clone())
        })?),
    };
    write_setup_directory(
        &args.output,
        &args.setup_id,
        &SetupKeys {
            request: &keys[position(KeyKind::Request)],
            withdrawal: &keys[position(KeyKind::Withdrawal)],
            insertion1: &keys[position(KeyKind::Insertion1)],
            insertion4: &keys[position(KeyKind::Insertion4)],
            insertion16: &keys[position(KeyKind::Insertion16)],
        },
        &provenance,
    )
}

/// `--<kind>-r1cs FILE` and `--<kind> ZKEY` for every circuit, plus the
/// options of [`ImportArgs`].
fn parse_args() -> Result<ImportArgs> {
    let mut setup_id = None;
    let mut ptau = None;
    let mut expected_ptau_sha256 = None;
    let mut r1cs: [Option<PathBuf>; KeyKind::ALL.len()] = Default::default();
    let mut zkeys: [Option<PathBuf>; KeyKind::ALL.len()] = Default::default();
    let mut transcript_sha256 = None;
    let mut output = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        // `--<kind>` names a zkey, `--<kind>-r1cs` an R1CS export.
        let kind_flag = arg.strip_prefix("--").and_then(|flag| {
            let (name, slots) = match flag.strip_suffix("-r1cs") {
                Some(name) => (name, &mut r1cs),
                None => (flag, &mut zkeys),
            };
            let index = KeyKind::ALL.iter().position(|kind| kind.as_str() == name)?;
            Some(&mut slots[index])
        });
        let mut value = || args.next().ok_or_else(|| anyhow!("{arg} needs a value"));
        if let Some(slot) = kind_flag {
            *slot = Some(PathBuf::from(value()?));
            continue;
        }
        match arg.as_str() {
            "--setup-id" => setup_id = Some(value()?),
            "--ptau" => ptau = Some(PathBuf::from(value()?)),
            "--ptau-sha256" => expected_ptau_sha256 = Some(hex_digest(&value()?)?),
            "--transcript-sha256" => transcript_sha256 = Some(hex_digest(&value()?)?),
            flag if flag.starts_with("--") => bail!("unknown option {flag}"),
            path => {
                ensure!(output.is_none(), "one output directory");
                output = Some(PathBuf::from(path));
            }
        }
    }
    let index = |kind: KeyKind| KeyKind::ALL.iter().position(|k| *k == kind).unwrap();
    Ok(ImportArgs {
        setup_id: setup_id.context("--setup-id (mpc-1 or rehearsal) is required")?,
        ptau: ptau.context("--ptau FILE is required")?,
        expected_ptau_sha256,
        public_ptau: PUBLIC_PTAU.to_vec(),
        r1cs: KindPaths::try_from_fn(|kind| {
            r1cs[index(kind)]
                .clone()
                .with_context(|| format!("--{kind}-r1cs FILE is required"))
        })?,
        zkeys: KindPaths::try_from_fn(|kind| {
            zkeys[index(kind)]
                .clone()
                .with_context(|| format!("--{kind} ZKEY is required"))
        })?,
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
        "imported {} setup {} into {}\nptau sha256 {}",
        manifest.circuit_id,
        manifest.setup_id,
        args.output.display(),
        manifest.ptau_sha256.as_deref().unwrap_or("-"),
    );
    for kind in KeyKind::ALL {
        println!("{kind} VK keccak256 {}", manifest.vk_keccak256.get(kind));
    }
    Ok(())
}
