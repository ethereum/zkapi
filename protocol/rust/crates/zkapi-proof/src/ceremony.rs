//! Binding of imported phase-2 keys to this build's circuits (G-SETUP step 6).
//!
//! `snarkjs groth16 setup <r1cs> <ptau>` derives every circuit-dependent point
//! of a key from the R1CS matrices A, B, C and the Lagrange bases of a
//! powers-of-tau file. Phase-2 contributions and the beacon only change `δ`:
//! they rescale the L and H queries by `1/δ` and touch nothing else.
//! [`check_key_binding`] recomputes that relation for the matrices this build
//! synthesizes, so a key set up from any other R1CS (for example one with the
//! same A and B but a different C, which a prover never reads) is refused.
//! It is the circuit half of `snarkjs zkey verify`; the contribution chain
//! (who changed `δ`, with proofs of knowledge) is not checked here.
//!
//! The binding is only as good as the powers of tau. Whoever knows its `τ` can
//! forge proofs whatever the phase-2 contributors do, and a powers of tau one
//! party made alone passes every consistency check, `snarkjs powersoftau
//! verify` included. So:
//! * [`Ptau::open`] hashes the file (SHA-256 for the pin, Blake2b-512 as its
//!   publisher lists it), and [`Ptau::public_transcript`] names the public
//!   phase-1 transcript of [`PUBLIC_PTAU`] it is, if any: an `mpc-1` import
//!   refuses any other file;
//! * [`Ptau::lagrange_bases`] checks that the points it returns form one
//!   structured reference string: the Lagrange sections the keys are built
//!   from are the inverse FFT of the `τ`-power sections, and those are powers
//!   of one `τ` scaled by `α` and `β`.
//!
//! Formats (iden3 binary files, snarkjs 0.7): every point is little-endian
//! Montgomery `x ‖ y` (G2: `x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1`), `(0, 0)` for
//! infinity. A prepared powers of tau of power `p` holds, in sections 12-15,
//! the Lagrange bases `L_j(τ)·G1`, `L_j(τ)·G2`, `α·L_j(τ)·G1` and
//! `β·L_j(τ)·G1` for every domain size `2^k`, `k = 0..=p` (section 12 also
//! `k = p + 1`), the block of size `d` starting at point `d - 1`. They are
//! the inverse FFT of sections 2-5 (`τ^i·G1` for `i < 2^(p+1) - 1`, and
//! `τ^i·G2`, `α·τ^i·G1`, `β·τ^i·G1` for `i < 2^p`; section 6 is `β·G2`). The
//! file lacks `τ^(2^(p+1) - 1)·G1`, which section 12's block of size
//! `2^(p+1)` needs: `snarkjs powersoftau prepare phase2` takes it as zero,
//! while a file truncated from a larger prepared one (`snarkjs powersoftau
//! truncate`, as Hermez's `powersOfTau28_hez_final_<p>.ptau`) keeps the
//! block computed with it.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::pairing::Pairing;
use ark_ec::{AffineRepr, VariableBaseMSM};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero};
use ark_groth16::ProvingKey;
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_relations::r1cs::ConstraintMatrices;
use blake2::Blake2b512;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

const G1_BYTES: u64 = 64;
const G2_BYTES: u64 = 128;
/// Two-adicity of the BN254 scalar field: the largest radix-2 domain.
const MAX_POWER: u32 = 28;

const PTAU_HEADER: u32 = 1;
const PTAU_TAU_G1: u32 = 2;
const PTAU_TAU_G2: u32 = 3;
const PTAU_ALPHA_TAU_G1: u32 = 4;
const PTAU_BETA_TAU_G1: u32 = 5;
const PTAU_BETA_G2: u32 = 6;
const PTAU_LAGRANGE_TAU_G1: u32 = 12;
const PTAU_LAGRANGE_TAU_G2: u32 = 13;
const PTAU_LAGRANGE_ALPHA_TAU_G1: u32 = 14;
const PTAU_LAGRANGE_BETA_TAU_G1: u32 = 15;

/// Section 10 of a snarkjs zkey: the phase-2 contributions.
const ZKEY_CONTRIBUTIONS: u32 = 10;

/// Position and length of one section of an iden3 binary file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub offset: u64,
    pub size: u64,
}

/// Read the section table of an iden3 binary file (`ptau`, `zkey`, `r1cs`):
/// a 4-byte magic, version 1, the section count, then `(type: u32, size:
/// u64, body)` records. Refuses duplicated sections and sections that run
/// past the end of the file.
pub fn binfile_sections<R: Read + Seek>(
    reader: &mut R,
    magic: &[u8; 4],
) -> Result<BTreeMap<u32, Section>> {
    let length = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    let mut head = [0u8; 12];
    reader
        .read_exact(&mut head)
        .with_context(|| format!("read the {} header", magic_name(magic)))?;
    ensure!(
        &head[..4] == magic,
        "not a {} file (magic {:?})",
        magic_name(magic),
        String::from_utf8_lossy(&head[..4])
    );
    let version = u32::from_le_bytes(head[4..8].try_into().expect("4 bytes"));
    ensure!(
        version == 1,
        "unsupported {} version {version}",
        magic_name(magic)
    );
    let count = u32::from_le_bytes(head[8..12].try_into().expect("4 bytes"));
    let mut sections = BTreeMap::new();
    let mut position = 12u64;
    for _ in 0..count {
        let mut record = [0u8; 12];
        reader
            .read_exact(&mut record)
            .context("read a section header")?;
        let id = u32::from_le_bytes(record[..4].try_into().expect("4 bytes"));
        let size = u64::from_le_bytes(record[4..].try_into().expect("8 bytes"));
        let offset = position + 12;
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= length)
            .ok_or_else(|| anyhow!("section {id} runs past the end of the file"))?;
        ensure!(
            sections.insert(id, Section { offset, size }).is_none(),
            "section {id} appears twice"
        );
        reader.seek(SeekFrom::Start(end))?;
        position = end;
    }
    Ok(sections)
}

fn magic_name(magic: &[u8; 4]) -> String {
    String::from_utf8_lossy(magic).into_owned()
}

/// A public phase-1 transcript, named by the Blake2b-512 its publisher lists
/// for the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicPtau {
    /// The file name as published.
    pub name: &'static str,
    /// The power in the file's header (`log2` of its largest domain).
    pub power: u32,
    /// The published Blake2b-512 of the file (lowercase hex).
    pub blake2b512: &'static str,
}

/// The powers of tau an `mpc-1` setup may be built on: the Hermez phase-1
/// transcripts prepared for phase 2, `powersOfTau28_hez_final_<p>.ptau` for
/// `p` = 16 (the withdrawal circuit's domain) to 27, with the Blake2b-512 the
/// snarkjs README lists for each ("Prepare phase 2"; the snarkjs 0.7.5 and
/// current READMEs list the same hashes). The power-16 file, downloaded from
/// the listed source, has this hash and passes [`Ptau::lagrange_bases`].
///
/// Adding a transcript is a reviewed change to this list, and only with the
/// hash its publisher lists: an import never trusts a powers of tau because
/// the coordinator pinned it.
pub const PUBLIC_PTAU: &[PublicPtau] = &[
    PublicPtau {
        name: "powersOfTau28_hez_final_16.ptau",
        power: 16,
        blake2b512: "6a6277a2f74e1073601b4f9fed6e1e55226917efb0f0db8a07d98ab01df1ccf43eb0e8c3159432acd4960e2f29fe84a4198501fa54c8dad9e43297453efec125",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_17.ptau",
        power: 17,
        blake2b512: "6247a3433948b35fbfae414fa5a9355bfb45f56efa7ab4929e669264a0258976741dfbe3288bfb49828e5df02c2e633df38d2245e30162ae7e3bcca5b8b49345",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_18.ptau",
        power: 18,
        blake2b512: "7e6a9c2e5f05179ddfc923f38f917c9e6831d16922a902b0b4758b8e79c2ab8a81bb5f29952e16ee6c5067ed044d7857b5de120a90704c1d3b637fd94b95b13e",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_19.ptau",
        power: 19,
        blake2b512: "bca9d8b04242f175189872c42ceaa21e2951e0f0f272a0cc54fc37193ff6648600eaf1c555c70cdedfaf9fb74927de7aa1d33dc1e2a7f1a50619484989da0887",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_20.ptau",
        power: 20,
        blake2b512: "89a66eb5590a1c94e3f1ee0e72acf49b1669e050bb5f93c73b066b564dca4e0c7556a52b323178269d64af325d8fdddb33da3a27c34409b821de82aa2bf1a27b",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_21.ptau",
        power: 21,
        blake2b512: "9aef0573cef4ded9c4a75f148709056bf989f80dad96876aadeb6f1c6d062391f07a394a9e756d16f7eb233198d5b69407cca44594c763ab4a5b67ae73254678",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_22.ptau",
        power: 22,
        blake2b512: "0d64f63dba1a6f11139df765cb690da69d9b2f469a1ddd0de5e4aa628abb28f787f04c6a5fb84a235ec5ea7f41d0548746653ecab0559add658a83502d1cb21b",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_23.ptau",
        power: 23,
        blake2b512: "3063a0bd81d68711197c8820a92466d51aeac93e915f5136d74f63c394ee6d88c5e8016231ea6580bec02e25d491f319d92e77f5c7f46a9caa8f3b53c0ea544f",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_24.ptau",
        power: 24,
        blake2b512: "fa404d140d5819d39984833ca5ec3632cd4995f81e82db402371a4de7c2eae8687c62bc632a95b0c6aadba3fb02680a94e09174b7233ccd26d78baca2647c733",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_25.ptau",
        power: 25,
        blake2b512: "0377d860cdb09a8a31ea1b0b8c04335614c8206357181573bf294c25d5ca7dff72387224fbd868897e6769f7805b3dab02854aec6d69d7492883b5e4e5f35eeb",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_26.ptau",
        power: 26,
        blake2b512: "418dee4a74b9592198bd8fd02ad1aea76f9cf3085f206dfd7d594c9e264ae919611b1459a1cc920c2f143417744ba9edd7b8d51e44be9452344a225ff7eead19",
    },
    PublicPtau {
        name: "powersOfTau28_hez_final_27.ptau",
        power: 27,
        blake2b512: "10ffd99837c512ef99752436a54b9810d1ac8878d368fb4b806267bdd664b4abf276c9cd3c4b9039a1fa4315a0c326c0e8e9e8fe0eb588ffd4f9021bf7eae1a1",
    },
];

/// A prepared (phase-2 ready) BN254 powers-of-tau file.
#[derive(Debug)]
pub struct Ptau {
    path: PathBuf,
    sha256: [u8; 32],
    blake2b512: [u8; 64],
    power: u32,
    sections: BTreeMap<u32, Section>,
}

impl Ptau {
    /// Hash the whole file and read its section table and header. Requires
    /// the BN254 base field, a power of at most 28, and sections 2-6 and the
    /// four Lagrange sections of `snarkjs powersoftau prepare phase2`, each of
    /// the exact size its power implies.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let mut file = File::open(&path).with_context(|| format!("open {}", path.display()))?;
        let mut sha256 = Sha256::new();
        let mut blake2b512 = Blake2b512::new();
        let mut buffer = vec![0u8; 1 << 20];
        loop {
            let read = file
                .read(&mut buffer)
                .with_context(|| format!("read {}", path.display()))?;
            if read == 0 {
                break;
            }
            sha256.update(&buffer[..read]);
            blake2b512.update(&buffer[..read]);
        }
        let sha256 = sha256.finalize().into();
        let blake2b512 = blake2b512.finalize().into();
        let mut reader = BufReader::new(file);
        let sections = binfile_sections(&mut reader, b"ptau")
            .with_context(|| format!("read {}", path.display()))?;
        let header = sections
            .get(&PTAU_HEADER)
            .ok_or_else(|| anyhow!("{}: no header section", path.display()))?;
        ensure!(header.size == 44, "{}: malformed header", path.display());
        reader.seek(SeekFrom::Start(header.offset))?;
        let mut bytes = [0u8; 44];
        reader.read_exact(&mut bytes)?;
        ensure!(
            u32::from_le_bytes(bytes[..4].try_into().expect("4 bytes")) == 32
                && bytes[4..36] == le_bytes(&Fq::MODULUS),
            "{}: not a BN254 powers of tau",
            path.display()
        );
        let power = u32::from_le_bytes(bytes[36..40].try_into().expect("4 bytes"));
        ensure!(
            (1..=MAX_POWER).contains(&power),
            "{}: unsupported power {power}",
            path.display()
        );
        let ptau = Self {
            path,
            sha256,
            blake2b512,
            power,
            sections,
        };
        // 2^(top + 1) - 1: all blocks up to size 2^top, or 2^(top + 1) - 1 powers.
        let block_points = |top: u32| (1u64 << (top + 1)) - 1;
        let powers = 1u64 << power;
        for (id, size) in [
            (PTAU_TAU_G1, block_points(power) * G1_BYTES),
            (PTAU_TAU_G2, powers * G2_BYTES),
            (PTAU_ALPHA_TAU_G1, powers * G1_BYTES),
            (PTAU_BETA_TAU_G1, powers * G1_BYTES),
            (PTAU_BETA_G2, G2_BYTES),
            (PTAU_LAGRANGE_TAU_G1, block_points(power + 1) * G1_BYTES),
            (PTAU_LAGRANGE_TAU_G2, block_points(power) * G2_BYTES),
            (PTAU_LAGRANGE_ALPHA_TAU_G1, block_points(power) * G1_BYTES),
            (PTAU_LAGRANGE_BETA_TAU_G1, block_points(power) * G1_BYTES),
        ] {
            let section = ptau.section(id)?;
            ensure!(
                section.size == size,
                "{}: section {id} has {} bytes, expected {size} for power {power} \
                 (run `snarkjs powersoftau prepare phase2`)",
                ptau.path.display(),
                section.size
            );
        }
        Ok(ptau)
    }

    /// SHA-256 of the file (the `ptau_sha256` pin and manifest entry).
    pub fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Blake2b-512 of the file, the hash the snarkjs README lists for the
    /// public transcripts.
    pub fn blake2b512(&self) -> [u8; 64] {
        self.blake2b512
    }

    /// The transcript of `known` (normally [`PUBLIC_PTAU`]) this file is: the
    /// same power and Blake2b-512.
    pub fn public_transcript<'a>(&self, known: &'a [PublicPtau]) -> Option<&'a PublicPtau> {
        let digest = hex::encode(self.blake2b512);
        known
            .iter()
            .find(|entry| entry.power == self.power && entry.blake2b512 == digest)
    }

    /// `log2` of the largest domain the file supports.
    pub fn power(&self) -> u32 {
        self.power
    }

    fn section(&self, id: u32) -> Result<Section> {
        self.sections.get(&id).copied().ok_or_else(|| {
            anyhow!(
                "{}: no section {id} (the powers of tau is not prepared for phase 2)",
                self.path.display()
            )
        })
    }

    fn read(&self, id: u32, offset: u64, length: u64) -> Result<Vec<u8>> {
        let section = self.section(id)?;
        ensure!(
            offset + length <= section.size,
            "{}: read past section {id}",
            self.path.display()
        );
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(section.offset + offset))?;
        let mut bytes = vec![0u8; length as usize];
        file.read_exact(&mut bytes)
            .with_context(|| format!("read {}", self.path.display()))?;
        Ok(bytes)
    }

    /// Points `start..start + count` of a G1 section.
    fn g1_points(&self, id: u32, start: usize, count: usize) -> Result<Vec<G1Affine>> {
        let bytes = self.read(id, start as u64 * G1_BYTES, count as u64 * G1_BYTES)?;
        bytes.as_chunks::<64>().0.iter().map(g1_from_lem).collect()
    }

    /// Points `start..start + count` of a G2 section.
    fn g2_points(&self, id: u32, start: usize, count: usize) -> Result<Vec<G2Affine>> {
        let bytes = self.read(id, start as u64 * G2_BYTES, count as u64 * G2_BYTES)?;
        bytes.as_chunks::<128>().0.iter().map(g2_from_lem).collect()
    }

    /// The bases snarkjs uses for a circuit whose QAP domain has
    /// `domain_size` points: the size-`n` blocks of sections 12-15, the odd
    /// points of section 12's size-`2n` block (the H query), and `α·G1`,
    /// `β·G1`, `β·G2`.
    ///
    /// Before returning them it checks, by random linear combinations, that
    /// they and the `τ`-power points they come from form one structured
    /// reference string ([`check_reference_string`]), so a file whose
    /// Lagrange sections were replaced (for example only the H points) is
    /// refused. A file one party made alone passes: only its hash
    /// ([`Ptau::public_transcript`]) shows where it comes from.
    pub fn lagrange_bases(&self, domain_size: usize) -> Result<LagrangeBases> {
        ensure!(
            domain_size.is_power_of_two()
                && domain_size as u64 <= 1u64 << self.power
                && domain_size < 1 << MAX_POWER,
            "{}: a powers of tau of power {} has no domain of {domain_size} points \
             (the H query needs a radix-2 domain of twice that size)",
            self.path.display(),
            self.power
        );
        let n = domain_size;
        let double = self.g1_points(PTAU_LAGRANGE_TAU_G1, 2 * n - 1, 2 * n)?;
        // The file holds τ^i·G1 for i < 2^(power + 1) - 1, so the top block
        // (2n = 2^(power + 1)) lacks the last power.
        let g1_powers = (2 * n).min((1 << (self.power + 1)) - 1);
        let points = ReferenceString {
            tau_g1: self.g1_points(PTAU_TAU_G1, 0, g1_powers)?,
            tau_g2: self.g2_points(PTAU_TAU_G2, 0, n.max(2))?,
            alpha_tau_g1: self.g1_points(PTAU_ALPHA_TAU_G1, 0, n)?,
            beta_tau_g1: self.g1_points(PTAU_BETA_TAU_G1, 0, n)?,
            beta_g2: self.g2_points(PTAU_BETA_G2, 0, 1)?[0],
            lagrange_tau_g1: self.g1_points(PTAU_LAGRANGE_TAU_G1, n - 1, n)?,
            lagrange_double_tau_g1: double,
            lagrange_tau_g2: self.g2_points(PTAU_LAGRANGE_TAU_G2, n - 1, n)?,
            lagrange_alpha_tau_g1: self.g1_points(PTAU_LAGRANGE_ALPHA_TAU_G1, n - 1, n)?,
            lagrange_beta_tau_g1: self.g1_points(PTAU_LAGRANGE_BETA_TAU_G1, n - 1, n)?,
        };
        check_reference_string(&points)
            .with_context(|| format!("{}: inconsistent powers of tau", self.path.display()))?;
        Ok(LagrangeBases {
            h_g1: points
                .lagrange_double_tau_g1
                .iter()
                .skip(1)
                .step_by(2)
                .copied()
                .collect(),
            alpha_g1: points.alpha_tau_g1[0],
            beta_g1: points.beta_tau_g1[0],
            beta_g2: points.beta_g2,
            tau_g1: points.lagrange_tau_g1,
            tau_g2: points.lagrange_tau_g2,
            alpha_tau_g1: points.lagrange_alpha_tau_g1,
            beta_tau_g1: points.lagrange_beta_tau_g1,
        })
    }
}

/// The points of a prepared powers of tau that one QAP domain of `n` points
/// uses (sections in parentheses).
#[derive(Clone, Debug)]
pub struct ReferenceString {
    /// `τ^i·G1` (2), `i < min(2n, 2^(power + 1) - 1)`.
    pub tau_g1: Vec<G1Affine>,
    /// `τ^i·G2` (3), `i < max(n, 2)`.
    pub tau_g2: Vec<G2Affine>,
    /// `α·τ^i·G1` (4), `i < n`.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// `β·τ^i·G1` (5), `i < n`.
    pub beta_tau_g1: Vec<G1Affine>,
    /// `β·G2` (6).
    pub beta_g2: G2Affine,
    /// The size-`n` block of section 12, `L_j(τ)·G1`.
    pub lagrange_tau_g1: Vec<G1Affine>,
    /// The size-`2n` block of section 12.
    pub lagrange_double_tau_g1: Vec<G1Affine>,
    /// The size-`n` blocks of sections 13, 14 and 15.
    pub lagrange_tau_g2: Vec<G2Affine>,
    pub lagrange_alpha_tau_g1: Vec<G1Affine>,
    pub lagrange_beta_tau_g1: Vec<G1Affine>,
}

/// Check that `points` are one structured reference string, as `snarkjs
/// powersoftau verify` does for a whole file (without its contribution
/// chain), each vector equation as one random linear combination:
/// * `τ^0·G1` and `τ^0·G2` are the generators;
/// * sections 2 and 3 are powers of the same `τ`: `P_(i+1) = τ·P_i`, by
///   pairing with `τ·G1` and `τ·G2`;
/// * sections 4 and 5 are powers of that `τ` too, and `β·G2` matches `β·G1`;
/// * each Lagrange block is the inverse FFT of its power section over its
///   domain: for random coefficients `c`, `Σ c_i·P_i = Σ_j FFT(c)_j·L_j`.
///   Section 12's top block (`2n = 2^(power + 1)`) needs the power
///   `τ^(2n - 1)·G1` the file lacks; it may be computed with zero there
///   (`prepare phase2`) or with that power (`truncate`), and with nothing
///   else (`snarkjs powersoftau verify` leaves it free).
pub fn check_reference_string(points: &ReferenceString) -> Result<()> {
    let n = points.lagrange_tau_g1.len();
    ensure!(
        n.is_power_of_two()
            && n < 1 << MAX_POWER
            && points.lagrange_double_tau_g1.len() == 2 * n
            && points.lagrange_tau_g2.len() == n
            && points.lagrange_alpha_tau_g1.len() == n
            && points.lagrange_beta_tau_g1.len() == n
            && points.alpha_tau_g1.len() == n
            && points.beta_tau_g1.len() == n
            && points.tau_g2.len() == n.max(2)
            && (2..=2 * n).contains(&points.tau_g1.len()),
        "the powers of tau points do not describe a domain of {n} points"
    );
    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    ensure!(
        points.tau_g1[0] == g1 && points.tau_g2[0] == g2,
        "sections 2 and 3 do not start with the generators"
    );
    let tau_g1 = points.tau_g1[1];
    let tau_g2 = points.tau_g2[1];
    let msm1 = |points: &[G1Affine], scalars: &[Fr]| G1Projective::msm_unchecked(points, scalars);
    let msm2 = |points: &[G2Affine], scalars: &[Fr]| G2Projective::msm_unchecked(points, scalars);
    // Σ r_i·P_(i+1) and Σ r_i·P_i for one fresh r.
    let shifted1 = |points: &[G1Affine]| {
        let r = random_scalars(points.len() - 1);
        (
            msm1(&points[1..], &r),
            msm1(&points[..points.len() - 1], &r),
        )
    };
    let (next, previous) = shifted1(&points.tau_g1);
    ensure!(
        Bn254::pairing(next, g2) == Bn254::pairing(previous, tau_g2),
        "section 2 does not hold the powers τ^i·G1 of section 3's τ"
    );
    let r = random_scalars(points.tau_g2.len() - 1);
    let (next, previous) = (
        msm2(&points.tau_g2[1..], &r),
        msm2(&points.tau_g2[..points.tau_g2.len() - 1], &r),
    );
    ensure!(
        Bn254::pairing(g1, next) == Bn254::pairing(tau_g1, previous),
        "section 3 does not hold the powers τ^i·G2 of section 2's τ"
    );
    for (id, section) in [
        (PTAU_ALPHA_TAU_G1, &points.alpha_tau_g1),
        (PTAU_BETA_TAU_G1, &points.beta_tau_g1),
    ] {
        if section.len() > 1 {
            let (next, previous) = shifted1(section);
            ensure!(
                Bn254::pairing(next, g2) == Bn254::pairing(previous, tau_g2),
                "section {id} does not hold a multiple of the powers of τ"
            );
        }
    }
    ensure!(
        Bn254::pairing(points.beta_tau_g1[0], g2) == Bn254::pairing(g1, points.beta_g2),
        "β·G2 (section 6) does not match β·G1 (section 5)"
    );
    // Σ c_i·P_i = Σ_j FFT(c)_j·L_j.
    let lagrange_g1 = |id: u32, block: &[G1Affine], powers: &[G1Affine]| -> Result<()> {
        let size = block.len();
        let (c, evaluations) = random_fft(size);
        let k = powers.len().min(size);
        let rest = msm1(block, &evaluations) - msm1(&powers[..k], &c[..k]);
        let matches = if k == size {
            rest.is_zero()
        } else {
            // The top block, without τ^(size - 1)·G1 = τ·P_(k - 1): the rest
            // is c_(size - 1) times zero or that power.
            k == size - 1
                && (rest.is_zero()
                    || Bn254::pairing(rest, g2)
                        == Bn254::pairing(powers[k - 1] * c[size - 1], tau_g2))
        };
        ensure!(
            matches,
            "the size-{size} block of section {id} is not the Lagrange basis of the powers of τ"
        );
        Ok(())
    };
    lagrange_g1(
        PTAU_LAGRANGE_TAU_G1,
        &points.lagrange_tau_g1,
        &points.tau_g1,
    )?;
    lagrange_g1(
        PTAU_LAGRANGE_TAU_G1,
        &points.lagrange_double_tau_g1,
        &points.tau_g1,
    )?;
    lagrange_g1(
        PTAU_LAGRANGE_ALPHA_TAU_G1,
        &points.lagrange_alpha_tau_g1,
        &points.alpha_tau_g1,
    )?;
    lagrange_g1(
        PTAU_LAGRANGE_BETA_TAU_G1,
        &points.lagrange_beta_tau_g1,
        &points.beta_tau_g1,
    )?;
    let (c, evaluations) = random_fft(n);
    ensure!(
        msm2(&points.lagrange_tau_g2, &evaluations) == msm2(&points.tau_g2[..n], &c),
        "the size-{n} block of section {PTAU_LAGRANGE_TAU_G2} is not the Lagrange basis of the \
         powers of τ"
    );
    Ok(())
}

fn random_scalars(count: usize) -> Vec<Fr> {
    let mut rng = OsRng;
    (0..count).map(|_| Fr::rand(&mut rng)).collect()
}

/// Random coefficients `c` of a polynomial of degree below `size` and its
/// evaluations on the radix-2 domain of `size` points (`size` a power of two
/// of at most 2^28).
fn random_fft(size: usize) -> (Vec<Fr>, Vec<Fr>) {
    let c = random_scalars(size);
    let evaluations = Radix2EvaluationDomain::<Fr>::new(size)
        .expect("a radix-2 domain of at most 2^28 points")
        .fft(&c);
    (c, evaluations)
}

/// The powers-of-tau points a key for one QAP domain of `n` points is built
/// from (`L_j` is the Lagrange basis of that domain).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LagrangeBases {
    /// `L_j(τ)·G1`, `j < n`.
    pub tau_g1: Vec<G1Affine>,
    /// `L_j(τ)·G2`.
    pub tau_g2: Vec<G2Affine>,
    /// `α·L_j(τ)·G1`.
    pub alpha_tau_g1: Vec<G1Affine>,
    /// `β·L_j(τ)·G1`.
    pub beta_tau_g1: Vec<G1Affine>,
    /// The odd points `2i + 1` of the size-`2n` block of `L(τ)·G1`: the H
    /// query before division by `δ`.
    pub h_g1: Vec<G1Affine>,
    pub alpha_g1: G1Affine,
    pub beta_g1: G1Affine,
    pub beta_g2: G2Affine,
}

impl LagrangeBases {
    /// `n`, the QAP domain size.
    pub fn domain_size(&self) -> usize {
        self.tau_g1.len()
    }
}

/// Check that `pk` is the phase-2 key `snarkjs groth16 setup` derives from
/// `matrices` and `bases`, with only `δ` changed since:
/// * `α·G1`, `β·G1`, `β·G2` are the powers of tau's; `γ·G2` is the generator
///   (snarkjs sets `γ = 1`); `δ·G1` and `δ·G2` encode the same `δ ≠ 0`;
/// * for every wire `i`: `A_i = Σ_j A_ji·L_j(τ)·G1`, `B_i` likewise in G1 and
///   G2, and with `K_i = Σ_j (β·A_ji + α·B_ji + C_ji)·L_j(τ)·G1`,
///   `IC_i = K_i` for "one" and the public inputs and `L_i = K_i / δ` for the
///   witnesses;
/// * `H_i = h_g1[i] / δ`.
///
/// Like snarkjs, rows `m + s` (`m` constraints, `s` = 0 for "one" and then
/// each public input) carry `A = 1` on wire `s`. Each vector equation is
/// checked as one random linear combination with fresh `OsRng` weights, the
/// `δ`-scaled ones by a pairing, so a key that differs anywhere passes with
/// probability at most about `2^-253` per equation.
pub fn check_key_binding(
    pk: &ProvingKey<Bn254>,
    matrices: &ConstraintMatrices<Fr>,
    bases: &LagrangeBases,
) -> Result<()> {
    let n = bases.domain_size();
    let constraints = matrices.num_constraints;
    let instance = matrices.num_instance_variables;
    let wires = instance + matrices.num_witness_variables;
    ensure!(
        matrices.a.len() == constraints
            && matrices.b.len() == constraints
            && matrices.c.len() == constraints,
        "matrix row counts differ from the constraint count"
    );
    ensure!(
        constraints + instance <= n
            && bases.tau_g2.len() == n
            && bases.alpha_tau_g1.len() == n
            && bases.beta_tau_g1.len() == n
            && bases.h_g1.len() == n,
        "the bases do not describe a domain for {constraints} constraints and {instance} instance variables"
    );
    ensure!(
        pk.a_query.len() == wires
            && pk.b_g1_query.len() == wires
            && pk.b_g2_query.len() == wires
            && pk.vk.gamma_abc_g1.len() == instance
            && pk.l_query.len() == wires - instance
            && pk.h_query.len() == n,
        "the key's query sizes do not match the circuit"
    );

    let g1 = G1Affine::generator();
    let g2 = G2Affine::generator();
    ensure!(
        pk.vk.alpha_g1 == bases.alpha_g1
            && pk.beta_g1 == bases.beta_g1
            && pk.vk.beta_g2 == bases.beta_g2,
        "alpha or beta is not the powers of tau's"
    );
    ensure!(
        pk.vk.gamma_g2 == g2,
        "gamma is not the G2 generator (snarkjs keys have gamma = 1)"
    );
    ensure!(
        !pk.delta_g1.is_zero()
            && !pk.vk.delta_g2.is_zero()
            && Bn254::pairing(pk.delta_g1, g2) == Bn254::pairing(g1, pk.vk.delta_g2),
        "delta in G1 and G2 differ"
    );

    // Row sums Σ_i M_ji·r_i, for public (0) and private (1) wires apart.
    let mut rng = OsRng;
    let weights: Vec<Fr> = (0..wires).map(|_| Fr::rand(&mut rng)).collect();
    let class = |wire: usize| usize::from(wire >= instance);
    let row_sums = |matrix: &[Vec<(Fr, usize)>]| -> Result<[Vec<Fr>; 2]> {
        let mut sums = [vec![Fr::zero(); n], vec![Fr::zero(); n]];
        for (row, terms) in matrix.iter().enumerate() {
            for (coefficient, wire) in terms {
                ensure!(
                    *wire < wires,
                    "constraint {row} names wire {wire} of {wires}"
                );
                sums[class(*wire)][row] += *coefficient * weights[*wire];
            }
        }
        Ok(sums)
    };
    let mut a = row_sums(&matrices.a)?;
    for (wire, weight) in weights.iter().enumerate().take(instance) {
        a[0][constraints + wire] += weight;
    }
    let b = row_sums(&matrices.b)?;
    let c = row_sums(&matrices.c)?;
    let add = |x: &[Fr], y: &[Fr]| x.iter().zip(y).map(|(x, y)| *x + y).collect::<Vec<_>>();
    let a_all = add(&a[0], &a[1]);
    let b_all = add(&b[0], &b[1]);
    let msm_g1 = |points: &[G1Affine], scalars: &[Fr]| G1Projective::msm_unchecked(points, scalars);
    let msm_g2 = |points: &[G2Affine], scalars: &[Fr]| G2Projective::msm_unchecked(points, scalars);

    ensure!(
        msm_g1(&pk.a_query, &weights) == msm_g1(&bases.tau_g1, &a_all),
        "A query does not match the circuit"
    );
    ensure!(
        msm_g1(&pk.b_g1_query, &weights) == msm_g1(&bases.tau_g1, &b_all),
        "B query (G1) does not match the circuit"
    );
    ensure!(
        msm_g2(&pk.b_g2_query, &weights) == msm_g2(&bases.tau_g2, &b_all),
        "B query (G2) does not match the circuit"
    );
    let k = |class: usize| {
        msm_g1(&bases.beta_tau_g1, &a[class])
            + msm_g1(&bases.alpha_tau_g1, &b[class])
            + msm_g1(&bases.tau_g1, &c[class])
    };
    ensure!(
        msm_g1(&pk.vk.gamma_abc_g1, &weights[..instance]) == k(0),
        "IC (the public-input part of the verifying key) does not match the circuit"
    );
    ensure!(
        Bn254::pairing(msm_g1(&pk.l_query, &weights[instance..]), pk.vk.delta_g2)
            == Bn254::pairing(k(1), g2),
        "L query does not match the circuit"
    );
    let h_weights: Vec<Fr> = (0..n).map(|_| Fr::rand(&mut rng)).collect();
    ensure!(
        Bn254::pairing(msm_g1(&pk.h_query, &h_weights), pk.vk.delta_g2)
            == Bn254::pairing(msm_g1(&bases.h_g1, &h_weights), g2),
        "H query does not match the powers of tau"
    );
    Ok(())
}

/// The kind of one snarkjs phase-2 contribution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Contribution {
    /// `snarkjs zkey contribute` (type 0).
    Contribution,
    /// `snarkjs zkey beacon` (type 1).
    Beacon,
}

/// The contributions a snarkjs zkey records in section 10, in order. This is
/// what the zkey claims; `snarkjs zkey verify` checks the chain.
pub fn zkey_contributions(zkey: &[u8]) -> Result<Vec<Contribution>> {
    let mut reader = std::io::Cursor::new(zkey);
    let sections = binfile_sections(&mut reader, b"zkey")?;
    let section = sections
        .get(&ZKEY_CONTRIBUTIONS)
        .ok_or_else(|| anyhow!("the zkey has no contributions section"))?;
    let body = &zkey[section.offset as usize..(section.offset + section.size) as usize];
    let mut at = 64usize; // circuit hash
    let take = |at: &mut usize, length: usize| -> Result<&[u8]> {
        let bytes = body
            .get(*at..*at + length)
            .ok_or_else(|| anyhow!("truncated contributions section"))?;
        *at += length;
        Ok(bytes)
    };
    let count = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
    let mut contributions = Vec::new();
    for _ in 0..count {
        // deltaAfter, g1_s, g1_sx (G1), g2_spx (G2), transcript (64 bytes).
        take(&mut at, 3 * G1_BYTES as usize + G2_BYTES as usize + 64)?;
        let kind = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
        let parameters = u32::from_le_bytes(take(&mut at, 4)?.try_into().expect("4 bytes"));
        take(&mut at, parameters as usize)?;
        contributions.push(match kind {
            0 => Contribution::Contribution,
            1 => Contribution::Beacon,
            other => bail!("unknown contribution type {other}"),
        });
    }
    ensure!(
        at == body.len(),
        "trailing bytes in the contributions section"
    );
    Ok(contributions)
}

fn le_bytes(value: &BigInt<4>) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (chunk, limb) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(value.0) {
        *chunk = limb.to_le_bytes();
    }
    bytes
}

/// A base-field element in snarkjs's little-endian Montgomery form, which is
/// arkworks' internal representation.
fn fq_from_lem(bytes: &[u8; 32]) -> Result<Fq> {
    let mut limbs = [0u64; 4];
    for (limb, chunk) in limbs.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *limb = u64::from_le_bytes(*chunk);
    }
    let value = BigInt::new(limbs);
    ensure!(
        value < Fq::MODULUS,
        "non-canonical base-field element in the powers of tau"
    );
    Ok(Fq::new_unchecked(value))
}

fn g1_from_lem(bytes: &[u8; 64]) -> Result<G1Affine> {
    let [x, y] = bytes.as_chunks::<32>().0 else {
        unreachable!("64 bytes are two coordinates")
    };
    let (x, y) = (fq_from_lem(x)?, fq_from_lem(y)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G1Affine::zero());
    }
    let point = G1Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "invalid G1 point in the powers of tau"
    );
    Ok(point)
}

fn g2_from_lem(bytes: &[u8; 128]) -> Result<G2Affine> {
    let [x0, x1, y0, y1] = bytes.as_chunks::<32>().0 else {
        unreachable!("128 bytes are four coordinates")
    };
    let x = Fq2::new(fq_from_lem(x0)?, fq_from_lem(x1)?);
    let y = Fq2::new(fq_from_lem(y0)?, fq_from_lem(y1)?);
    if x.is_zero() && y.is_zero() {
        return Ok(G2Affine::zero());
    }
    let point = G2Affine::new_unchecked(x, y);
    ensure!(
        point.is_on_curve() && point.is_in_correct_subgroup_assuming_on_curve(),
        "invalid G2 point in the powers of tau"
    );
    Ok(point)
}

/// Encode a point as snarkjs does (for tests and fixtures that write files).
pub fn g1_to_lem(point: &G1Affine) -> [u8; 64] {
    let mut bytes = [0u8; 64];
    if let Some((x, y)) = point.xy() {
        bytes[..32].copy_from_slice(&le_bytes(&x.0));
        bytes[32..].copy_from_slice(&le_bytes(&y.0));
    }
    bytes
}

/// See [`g1_to_lem`].
pub fn g2_to_lem(point: &G2Affine) -> [u8; 128] {
    let mut bytes = [0u8; 128];
    if let Some((x, y)) = point.xy() {
        for (chunk, value) in bytes
            .as_chunks_mut::<32>()
            .0
            .iter_mut()
            .zip([x.c0, x.c1, y.c0, y.c1])
        {
            *chunk = le_bytes(&value.0);
        }
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{CurveGroup, PrimeGroup};

    #[test]
    fn points_round_trip_through_the_snarkjs_encoding() {
        let mut rng = OsRng;
        for point in [
            G1Affine::zero(),
            G1Affine::generator(),
            (G1Projective::generator() * Fr::rand(&mut rng)).into_affine(),
        ] {
            assert_eq!(g1_from_lem(&g1_to_lem(&point)).unwrap(), point);
        }
        for point in [
            G2Affine::zero(),
            G2Affine::generator(),
            (G2Projective::generator() * Fr::rand(&mut rng)).into_affine(),
        ] {
            assert_eq!(g2_from_lem(&g2_to_lem(&point)).unwrap(), point);
        }
        // Off-curve and non-canonical encodings are refused.
        let mut off = g1_to_lem(&G1Affine::generator());
        off[0] ^= 1;
        assert!(g1_from_lem(&off).is_err());
        let mut big = [0xffu8; 64];
        big[32..].copy_from_slice(&g1_to_lem(&G1Affine::generator())[32..]);
        assert!(g1_from_lem(&big).is_err());
    }

    #[test]
    fn public_transcripts_are_listed_by_power_and_published_hash() {
        let mut powers = Vec::new();
        for entry in PUBLIC_PTAU {
            assert_eq!(
                entry.name,
                format!("powersOfTau28_hez_final_{:02}.ptau", entry.power)
            );
            assert!(
                entry.blake2b512.len() == 128
                    && entry
                        .blake2b512
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "{}",
                entry.name
            );
            powers.push(entry.power);
        }
        // Every power from the withdrawal domain (2^16) up, once each.
        assert_eq!(powers, (16..=27).collect::<Vec<_>>());
    }

    #[test]
    fn binfile_section_tables_are_checked() {
        let file = |magic: &[u8; 4], sections: &[(u32, u64, usize)]| {
            let mut bytes = magic.to_vec();
            bytes.extend_from_slice(&1u32.to_le_bytes());
            bytes.extend_from_slice(&(sections.len() as u32).to_le_bytes());
            for (id, declared, actual) in sections {
                bytes.extend_from_slice(&id.to_le_bytes());
                bytes.extend_from_slice(&declared.to_le_bytes());
                bytes.extend(std::iter::repeat_n(7u8, *actual));
            }
            bytes
        };
        let read = |bytes: Vec<u8>, magic: &[u8; 4]| {
            binfile_sections(&mut std::io::Cursor::new(bytes), magic)
        };
        let sections = read(file(b"ptau", &[(1, 3, 3), (12, 5, 5)]), b"ptau").unwrap();
        assert_eq!(
            sections[&1],
            Section {
                offset: 24,
                size: 3
            }
        );
        assert_eq!(
            sections[&12],
            Section {
                offset: 39,
                size: 5
            }
        );
        assert!(read(file(b"zkey", &[(1, 3, 3)]), b"ptau").is_err());
        assert!(read(file(b"ptau", &[(1, 3, 3), (1, 3, 3)]), b"ptau").is_err());
        assert!(read(file(b"ptau", &[(1, 9, 3)]), b"ptau").is_err());
    }
}
