//! The vault's Poseidon: `Bn254PoseidonRuntime.sol`, an assembly-only contract whose permutation
//! is fully unrolled in the scaled sparse form with lazy modular reduction, and its sidecar
//! `poseidon-runtime.json`. [`crate::compact`] writes both into a setup directory.
//!
//! The derivation and the rendering are the ones `protocol/formal` verifies: the scaled
//! constants are `scaled_constants` of poseidon-proto's `gen/params.py` (and of
//! `protocol/formal/scripts/generate.py`), the body is `gen/gen_unrolled.py --form scaled --lazy`
//! and is rendered statement for statement as `ZkapiFormal/Lazy/Render.lean` builds the program:
//!
//! * every lane carries a bound `m` (its value is below `m·p`);
//! * a sum is a plain `add` iff the operands' bounds total at most 5 (`5p < 2^256 < 6p`, so the
//!   `ADD` cannot wrap), and an `addmod` otherwise (bound 1);
//! * round 0 adds its constants with `addmod`, so inputs of any width are reduced, and the last
//!   round's final additions are `addmod`, so outputs are canonical;
//! * a matrix row is `mulmod(x, c0) + mulmod(y, c1) + mulmod(z, c2)` in that order, the S-box is
//!   `{ let q := mulmod(v, v, P)  v := mulmod(mulmod(q, q, P), v, P) }`, a partial round updates
//!   `s0` then `s1`, `s2`, and the last partial round uses the λ-scaled dense matrix.
//!
//! `protocol/formal/scripts/generate.py --yul` re-renders the body in Python and requires the
//! production file to match it byte for byte and the Solidity around it to be the pinned text.

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, One, PrimeField};
use serde::Serialize;
use sha3::{Digest, Keccak256};

/// Lazy sums stay below `5p`, which is below `2^256` (and `6p` is not).
const MAXM: u32 = 5;
const RF_HALF: usize = 4;
const RP: usize = 57;
const ROUNDS: usize = 2 * RF_HALF + RP;

/// The modulus as the generated Yul writes it.
const P_HEX: &str = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// The contract name and the setup-directory files.
pub const CONTRACT_NAME: &str = "Bn254PoseidonRuntime";

/// The four entry points, with the selectors and ABI of the `Bn254Poseidon` library they
/// replace.
pub const ENTRY_POINTS: [&str; 4] = [
    "compress(uint256,uint256,uint256)",
    "hash5(uint256,uint256,uint256,uint256,uint256)",
    "insertPath32(uint256,uint32,uint256,uint256[32])",
    "compressPairPath32(uint256,uint32,uint256,uint256,uint256[32],uint256)",
];

/// keccak256 of the runtime code solc 0.8.28 compiles [`runtime_source`] to with the settings in
/// [`CompilerSettings::pinned`] (Forge 1.5.1 with protocol/contracts/foundry.toml). Not
/// computed here (no compiler): the Forge suite `Bn254PoseidonRuntimeTest` and Deploy.s.sol
/// compare the compiled and the deployed runtime with the value the sidecar carries, so a
/// change to the generator or to the compiler settings must update this pin.
pub const RUNTIME_CODEHASH: &str =
    "0x1068a7efbae3364012debf8d4e08d7c93d102eaf211fc01d942b66cedda4df9a";

/// The scaled sparse schedule: what the unrolled body computes, as field elements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScaledSchedule {
    /// Full-round constants: rounds 0-3, then rounds 61-64 (round 61 carries the constants the
    /// partial rounds moved out of the two rate lanes).
    pub full: [[Fr; 3]; 2 * RF_HALF],
    /// Partial rounds 0-55 (rounds 4-59): `k/λ_j, b/λ_{j+1}, c/λ_{j+1}, w1·λ_j^5, w2·λ_j^5`.
    pub partial: Vec<[Fr; 5]>,
    /// The last partial round (round 60): `k0/λ_56, k1, k2`.
    pub last_k: [Fr; 3],
    /// Its dense matrix, the first column multiplied by `λ_56^5`.
    pub last_m: [[Fr; 3]; 3],
    /// The scaling factors `λ_0 = 1, …, λ_56`, `λ_{j+1} = a_j · λ_j^5`.
    pub lambdas: Vec<Fr>,
    /// The MDS matrix of the full rounds.
    pub mds: [[Fr; 3]; 3],
}

/// The scaled schedule, from the sparse words of [`crate::compact`]'s
/// `optimized_poseidon_constants` (layout: 4 full rounds of 3 constants, 56 partial rounds of
/// `k, a, b, c, w1, w2`, the last partial round's 3 constants and 9 matrix entries, 4 full
/// rounds of 3 constants). In partial round `j` lane 0 is kept as `σ = s0 / λ_j`: then
/// `(s0 + k)^5 = λ_j^5 (σ + k/λ_j)^5`, and with `λ_{j+1} = a_j λ_j^5` the new lane 0 is
/// `y + (b/λ_{j+1}) s1 + (c/λ_{j+1}) s2` and `s1 + (w1 λ_j^5) y` (no multiplication by `a_j`).
pub(crate) fn scaled_schedule(sparse: &[Fr], mds: [[Fr; 3]; 3]) -> ScaledSchedule {
    assert_eq!(sparse.len(), 372);
    let word3 = |at: usize| [sparse[at], sparse[at + 1], sparse[at + 2]];
    let mut full = [[Fr::from(0u64); 3]; 2 * RF_HALF];
    for (r, round) in full.iter_mut().enumerate().take(RF_HALF) {
        *round = word3(3 * r);
    }
    let suffix = 12 + 6 * (RP - 1) + 12;
    for r in 0..RF_HALF {
        full[RF_HALF + r] = word3(suffix + 3 * r);
    }
    let mut lambda = Fr::one();
    let mut lambdas = vec![lambda];
    let mut partial = Vec::with_capacity(RP - 1);
    for j in 0..RP - 1 {
        let at = 12 + 6 * j;
        let (k, a, b, c, w1, w2) = (
            sparse[at],
            sparse[at + 1],
            sparse[at + 2],
            sparse[at + 3],
            sparse[at + 4],
            sparse[at + 5],
        );
        assert!(
            a != Fr::from(0u64),
            "zero leading coefficient in partial round {j}"
        );
        let l5 = lambda.pow([5u64]);
        let next = a * l5;
        let lambda_inv = lambda.inverse().expect("λ is non-zero");
        let next_inv = next.inverse().expect("λ' is non-zero");
        partial.push([k * lambda_inv, b * next_inv, c * next_inv, w1 * l5, w2 * l5]);
        lambda = next;
        lambdas.push(lambda);
    }
    let at = 12 + 6 * (RP - 1);
    let l5 = lambda.pow([5u64]);
    let last_k = [
        sparse[at] * lambda.inverse().expect("λ is non-zero"),
        sparse[at + 1],
        sparse[at + 2],
    ];
    let last_m = std::array::from_fn(|i| {
        [
            sparse[at + 3 + 3 * i] * l5,
            sparse[at + 4 + 3 * i],
            sparse[at + 5 + 3 * i],
        ]
    });
    assert_eq!(lambdas.len(), RP);
    ScaledSchedule {
        full,
        partial,
        last_k,
        last_m,
        lambdas,
        mds,
    }
}

/// The permutation the scaled schedule describes, in field arithmetic (what the Yul computes
/// on the reduced inputs).
#[cfg(test)]
pub(crate) fn scaled_permutation(schedule: &ScaledSchedule, mut s: [Fr; 3]) -> [Fr; 3] {
    let pow5 = |x: Fr| x.square().square() * x;
    let dense = |m: &[[Fr; 3]; 3], v: [Fr; 3]| -> [Fr; 3] {
        std::array::from_fn(|i| m[i][0] * v[0] + m[i][1] * v[1] + m[i][2] * v[2])
    };
    for k in &schedule.full[..RF_HALF] {
        s = dense(&schedule.mds, std::array::from_fn(|i| pow5(s[i] + k[i])));
    }
    for &[k, b, c, w1, w2] in &schedule.partial {
        let y = pow5(s[0] + k);
        s = [y + b * s[1] + c * s[2], s[1] + w1 * y, s[2] + w2 * y];
    }
    let k = schedule.last_k;
    s = dense(
        &schedule.last_m,
        [pow5(s[0] + k[0]), s[1] + k[1], s[2] + k[2]],
    );
    for k in &schedule.full[RF_HALF..] {
        s = dense(&schedule.mds, std::array::from_fn(|i| pow5(s[i] + k[i])));
    }
    s
}

/// `0x` and 64 lowercase hex digits.
pub(crate) fn word_hex(value: &Fr) -> String {
    format!("0x{}", hex::encode(value.into_bigint().to_bytes_be()))
}

/// gen_unrolled.py `Gen` / Render.lean: the straight-line rounds with the lane bounds.
struct Render {
    lines: Vec<String>,
    /// Bounds of `s0, s1, s2` as multiples of p.
    m: [u32; 3],
    /// The bounds after every round.
    bounds: Vec<[u32; 3]>,
}

const LANES: [&str; 3] = ["s0", "s1", "s2"];
const ROUND_VARS: [&str; 3] = ["x", "y", "z"];
/// Indentation of the round blocks: inside `function permute` in the fallback's assembly.
const ROUND_INDENT: usize = 16;

impl Render {
    fn emit(&mut self, text: &str) {
        self.lines
            .push(format!("{}{text}", " ".repeat(ROUND_INDENT)));
    }

    /// Render.lean `lz`.
    fn add(a: &str, ma: u32, b: &str, mb: u32) -> (String, u32) {
        if ma + mb <= MAXM {
            (format!("add({a}, {b})"), ma + mb)
        } else {
            (format!("addmod({a}, {b}, P)"), 1)
        }
    }

    /// Render.lean `row`.
    fn row(c: &[Fr; 3], reduce_out: bool) -> (String, u32) {
        let term = |v: &str, k: &Fr| format!("mulmod({v}, {}, P)", word_hex(k));
        let (e, m) = Self::add(&term("x", &c[0]), 1, &term("y", &c[1]), 1);
        if reduce_out {
            (format!("addmod({e}, {}, P)", term("z", &c[2])), 1)
        } else {
            Self::add(&e, m, &term("z", &c[2]), 1)
        }
    }

    fn sbox(&mut self, v: &str) {
        self.emit("    {");
        self.emit(&format!("        let q := mulmod({v}, {v}, P)"));
        self.emit(&format!("        {v} := mulmod(mulmod(q, q, P), {v}, P)"));
        self.emit("    }");
    }

    /// Render.lean `fullStmts`.
    fn full_round(&mut self, k: &[Fr; 3], mat: &[[Fr; 3]; 3], first: bool, last: bool) {
        self.emit("{");
        for i in 0..3 {
            let e = if first {
                format!("addmod({}, {}, P)", LANES[i], word_hex(&k[i]))
            } else {
                Self::add(LANES[i], self.m[i], &word_hex(&k[i]), 1).0
            };
            self.emit(&format!("    let {} := {e}", ROUND_VARS[i]));
        }
        for v in ROUND_VARS {
            self.sbox(v);
        }
        for i in 0..3 {
            let (e, m) = Self::row(&mat[i], last);
            self.emit(&format!("    {} := {e}", LANES[i]));
            self.m[i] = m;
        }
        self.emit("}");
        self.bounds.push(self.m);
    }

    /// Render.lean `partialStmts`.
    fn partial_round(&mut self, [k, b, c, w1, w2]: &[Fr; 5]) {
        let (x, _) = Self::add("s0", self.m[0], &word_hex(k), 1);
        self.emit("{");
        self.emit(&format!("    let x := {x}"));
        self.sbox("x");
        let (e0, m0) = Self::add("x", 1, &format!("mulmod(s1, {}, P)", word_hex(b)), 1);
        let (e0, m0) = Self::add(&e0, m0, &format!("mulmod(s2, {}, P)", word_hex(c)), 1);
        self.emit(&format!("    s0 := {e0}"));
        for (i, w) in [(1, w1), (2, w2)] {
            let (e, m) = Self::add(
                LANES[i],
                self.m[i],
                &format!("mulmod(x, {}, P)", word_hex(w)),
                1,
            );
            self.emit(&format!("    {} := {e}", LANES[i]));
            self.m[i] = m;
        }
        self.m[0] = m0;
        self.emit("}");
        self.bounds.push(self.m);
    }

    /// Render.lean `lastStmts`.
    fn last_partial_round(&mut self, k: &[Fr; 3], mat: &[[Fr; 3]; 3]) {
        let e: [String; 3] =
            std::array::from_fn(|i| Self::add(LANES[i], self.m[i], &word_hex(&k[i]), 1).0);
        self.emit("{");
        for i in 0..3 {
            self.emit(&format!("    let {} := {}", ROUND_VARS[i], e[i]));
        }
        self.sbox("x");
        for i in 0..3 {
            let (e, m) = Self::row(&mat[i], false);
            self.emit(&format!("    {} := {e}", LANES[i]));
            self.m[i] = m;
        }
        self.emit("}");
        self.bounds.push(self.m);
    }
}

/// The body of `function permute(s0, s1, s2) -> r0, r1, r2` up to its returns: the modulus
/// binding, the never-taken branch, then the 65 round blocks (one line each, LF-terminated);
/// and the lane bounds after every round.
pub(crate) fn permute_body(schedule: &ScaledSchedule) -> (String, Vec<[u32; 3]>) {
    let mut r = Render {
        lines: vec![
            format!("{}let P := {P_HEX}", " ".repeat(ROUND_INDENT)),
            format!(
                "{}// Never taken (calldata is far shorter): keeps the modulus one stack value.",
                " ".repeat(ROUND_INDENT)
            ),
            format!(
                "{}if gt(calldatasize(), 0xffffffffffff) {{ P := 1 }}",
                " ".repeat(ROUND_INDENT)
            ),
        ],
        m: [1, 1, 1],
        bounds: Vec::with_capacity(ROUNDS),
    };
    for (i, k) in schedule.full[..RF_HALF].iter().enumerate() {
        r.full_round(k, &schedule.mds, i == 0, false);
    }
    for round in &schedule.partial {
        r.partial_round(round);
    }
    r.last_partial_round(&schedule.last_k, &schedule.last_m);
    for (i, k) in schedule.full[RF_HALF..].iter().enumerate() {
        r.full_round(k, &schedule.mds, false, i == RF_HALF - 1);
    }
    assert_eq!(r.bounds.len(), ROUNDS);
    let mut body = r.lines.join("\n");
    body.push('\n');
    (body, r.bounds)
}

/// The 4-byte selector of a function signature.
pub(crate) fn selector(signature: &str) -> String {
    let digest = Keccak256::digest(signature.as_bytes());
    format!("0x{}", hex::encode(&digest[..4]))
}

/// The contract's source. Everything outside `permute`'s body is fixed text, which
/// `protocol/formal/scripts/generate.py` pins (`check_glue`).
pub(crate) fn runtime_source(schedule: &ScaledSchedule) -> String {
    let (body, _) = permute_body(schedule);
    let selectors: Vec<String> = ENTRY_POINTS.iter().map(|s| selector(s)).collect();
    assert_eq!(
        selectors,
        ["0x2d0c7694", "0xc98aeff5", "0x21d2c645", "0xf6073d4e"],
        "the entry points keep the library's selectors"
    );
    RUNTIME_TEMPLATE
        .replace("__PERMUTE_BODY__\n", &body)
        .replace("__P__", P_HEX)
}

/// solc's settings for the runtime (protocol/contracts/foundry.toml `compilation_restrictions`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct CompilerSettings {
    pub solc: &'static str,
    pub via_ir: bool,
    pub optimizer: bool,
    pub optimizer_runs: u32,
    pub evm_version: &'static str,
    pub bytecode_hash: &'static str,
    pub cbor_metadata: bool,
}

impl CompilerSettings {
    pub const fn pinned() -> Self {
        Self {
            solc: "0.8.28",
            via_ir: false,
            optimizer: true,
            optimizer_runs: 10_000,
            evm_version: "prague",
            bytecode_hash: "none",
            cbor_metadata: false,
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct EntryPoint {
    pub signature: &'static str,
    pub selector: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LastPartialRound {
    pub constants: [String; 3],
    pub matrix: [[String; 3]; 3],
}

/// The scaled schedule's words, as the body embeds them.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct ScaledConstants {
    /// Rounds 0-3 and 61-64, three constants each.
    pub full_round_constants: Vec<[String; 3]>,
    /// The full rounds' MDS matrix, row-major.
    pub mds: [[String; 3]; 3],
    /// Partial rounds 0-55 (rounds 4-59): `[k/λ_j, b/λ_{j+1}, c/λ_{j+1}, w1·λ_j^5, w2·λ_j^5]`.
    pub partial_rounds: Vec<[String; 5]>,
    /// Round 60: `[k0/λ_56, k1, k2]` and the dense matrix with its first column times `λ_56^5`.
    pub last_partial_round: LastPartialRound,
    /// `λ_0 = 1, …, λ_56`.
    pub lambdas: Vec<String>,
}

/// `poseidon-runtime.json`: what pins the runtime, for diffing and for the deployment checks.
/// The contracts and the formal project never read it as an input.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct RuntimeManifest {
    pub contract: &'static str,
    pub source_file: &'static str,
    /// SHA-256 (lowercase hex) of the source file.
    pub source_sha256: String,
    pub compiler: CompilerSettings,
    /// keccak256 of the deployed runtime code ([`RUNTIME_CODEHASH`]).
    pub runtime_codehash: &'static str,
    pub field_modulus: &'static str,
    pub entry_points: Vec<EntryPoint>,
    pub scaled_constants: ScaledConstants,
    /// The bound of each lane after each of the 65 rounds, as a multiple of p (a lane's value is
    /// below bound · p); every plain `add` adds operands whose bounds total at most 5.
    pub lane_bounds: Vec<[u32; 3]>,
}

pub(crate) fn runtime_manifest(
    schedule: &ScaledSchedule,
    source_file: &'static str,
) -> RuntimeManifest {
    use sha2::Sha256;
    let source = runtime_source(schedule);
    let (_, lane_bounds) = permute_body(schedule);
    let hex3 = |v: &[Fr; 3]| -> [String; 3] { std::array::from_fn(|i| word_hex(&v[i])) };
    RuntimeManifest {
        contract: CONTRACT_NAME,
        source_file,
        source_sha256: hex::encode(Sha256::digest(source.as_bytes())),
        compiler: CompilerSettings::pinned(),
        runtime_codehash: RUNTIME_CODEHASH,
        field_modulus: P_HEX,
        entry_points: ENTRY_POINTS
            .iter()
            .map(|signature| EntryPoint {
                signature,
                selector: selector(signature),
            })
            .collect(),
        scaled_constants: ScaledConstants {
            full_round_constants: schedule.full.iter().map(hex3).collect(),
            mds: std::array::from_fn(|i| hex3(&schedule.mds[i])),
            partial_rounds: schedule
                .partial
                .iter()
                .map(|round| std::array::from_fn(|i| word_hex(&round[i])))
                .collect(),
            last_partial_round: LastPartialRound {
                constants: hex3(&schedule.last_k),
                matrix: std::array::from_fn(|i| hex3(&schedule.last_m[i])),
            },
            lambdas: schedule.lambdas.iter().map(word_hex).collect(),
        },
        lane_bounds,
    }
}

const RUNTIME_TEMPLATE: &str = r#"// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @title Bn254PoseidonRuntime
/// @notice Poseidon over the BN254 scalar field for ZkApiVault, generated by zkapi-proof from
///         zkAPI v2's arkworks parameters: width 3, rate 2, x^5 S-box, 8 full and 57 partial
///         rounds. The functions, selectors and ABI of the Bn254Poseidon library it replaces,
///         with the same results for every input:
///         * compress(uint256 capacity, uint256 left, uint256 right) returns (uint256): one
///           permutation of (capacity, left, right), its lane 1 (zkapi_core::v2::compress_fields,
///           the note tree's node hash);
///         * hash5(uint256, uint256, uint256, uint256, uint256) returns (uint256): the sponge over
///           five inputs (zkapi_core::v2::hash_fields, the note leaf);
///         * insertPath32(uint256 capacity, uint32 index, uint256 leaf, uint256[32] siblings)
///           returns (uint256 root, uint256 completed): the root of the depth-32 tree with leaf at
///           index, and the path's node at the lowest zero bit of index (the root when there is
///           none);
///         * compressPairPath32(uint256 capacity, uint32 index, uint256 oldLeaf, uint256 newLeaf,
///           uint256[32] siblings, uint256 nodeLevel) returns (uint256 oldRoot, uint256 newRoot,
///           uint256 newNode): the roots with oldLeaf and with newLeaf at index, and the new
///           path's node at nodeLevel (the root from 32 on).
/// @dev Generated (zkapi-proof compact.rs, refresh_setup_sources): never edit by hand. Compiled
///      with solc 0.8.28's legacy pipeline (via_ir false, optimizer 10,000 runs, no metadata);
///      the setup's poseidon-runtime.json pins the source hash and the runtime codehash. The
///      vault calls it with STATICCALL, so it can never change the vault's state. The runtime is
///      solc's prologue (free memory pointer, rejection of call value) and one inline-assembly
///      block: the unrolled permutation in the scaled sparse form with lazy reduction, whose body
///      protocol/formal proves equal to zkAPI's Poseidon for all inputs (Zkapi.Yul.yul_permute),
///      and the dispatcher, which decodes calldata as solc's ABI decoder does (the minimum
///      length, index a clean uint32; anything else reverts with no data). Two values are
///      runtime-opaque on purpose: the modulus P, kept one stack value by a never-taken branch
///      (a literal would become a PUSH32 in each of its hundreds of uses), and hash5's zero
///      capacity (a literal would make the optimizer compile a second copy of permute for it).
contract Bn254PoseidonRuntime {
    fallback() external {
        assembly ("memory-safe") {
            function permute(s0, s1, s2) -> r0, r1, r2 {
__PERMUTE_BODY__
                r0 := s0
                r1 := s1
                r2 := s2
            }
            if lt(calldatasize(), 4) { revert(0, 0) }
            switch shr(224, calldataload(0))
            case 0x2d0c7694 {
                // compress(uint256,uint256,uint256)
                if slt(sub(calldatasize(), 4), 96) { revert(0, 0) }
                let c0, c1, c2 := permute(calldataload(4), calldataload(36), calldataload(68))
                mstore(0x80, c1)
                return(0x80, 0x20)
            }
            case 0xc98aeff5 {
                // hash5(uint256,uint256,uint256,uint256,uint256)
                if slt(sub(calldatasize(), 4), 160) { revert(0, 0) }
                // Zero for any calldata shorter than 2^255 bytes.
                let zero := shr(255, calldatasize())
                let h0, h1, h2 := permute(zero, calldataload(4), calldataload(36))
                h0, h1, h2 := permute(h0, addmod(h1, calldataload(68), __P__), addmod(h2, calldataload(100), __P__))
                h0, h1, h2 := permute(h0, addmod(h1, calldataload(132), __P__), h2)
                mstore(0x80, h1)
                return(0x80, 0x20)
            }
            case 0x21d2c645 {
                // insertPath32(uint256,uint32,uint256,uint256[32])
                if slt(sub(calldatasize(), 4), 1120) { revert(0, 0) }
                let index := calldataload(36)
                if iszero(eq(index, and(index, 0xffffffff))) { revert(0, 0) }
                let capacity := calldataload(4)
                let root := calldataload(68)
                let completed := root
                let completing := 1
                for { let level := 0 } lt(level, 32) { level := add(level, 1) } {
                    let sibling := calldataload(add(100, shl(5, level)))
                    switch and(shr(level, index), 1)
                    case 0 {
                        if completing {
                            completed := root
                            completing := 0
                        }
                        let a0, a1, a2 := permute(capacity, root, sibling)
                        root := a1
                    }
                    default {
                        let a0, a1, a2 := permute(capacity, sibling, root)
                        root := a1
                    }
                }
                if completing { completed := root }
                mstore(0x80, root)
                mstore(0xa0, completed)
                return(0x80, 0x40)
            }
            case 0xf6073d4e {
                // compressPairPath32(uint256,uint32,uint256,uint256,uint256[32],uint256)
                if slt(sub(calldatasize(), 4), 1184) { revert(0, 0) }
                let index := calldataload(36)
                if iszero(eq(index, and(index, 0xffffffff))) { revert(0, 0) }
                let capacity := calldataload(4)
                let oldRoot := calldataload(68)
                let newRoot := calldataload(100)
                let newNode := newRoot
                let nodeLevel := calldataload(1156)
                for { let level := 0 } lt(level, 32) { level := add(level, 1) } {
                    if eq(level, nodeLevel) { newNode := newRoot }
                    let sibling := calldataload(add(132, shl(5, level)))
                    switch and(shr(level, index), 1)
                    case 0 {
                        let a0, a1, a2 := permute(capacity, oldRoot, sibling)
                        oldRoot := a1
                        let b0, b1, b2 := permute(capacity, newRoot, sibling)
                        newRoot := b1
                    }
                    default {
                        let a0, a1, a2 := permute(capacity, sibling, oldRoot)
                        oldRoot := a1
                        let b0, b1, b2 := permute(capacity, sibling, newRoot)
                        newRoot := b1
                    }
                }
                if iszero(lt(nodeLevel, 32)) { newNode := newRoot }
                mstore(0x80, oldRoot)
                mstore(0xa0, newRoot)
                mstore(0xc0, newNode)
                return(0x80, 0x60)
            }
            default { revert(0, 0) }
        }
    }
}
"#;
