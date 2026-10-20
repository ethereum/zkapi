# zkAPI Poseidon: a machine-checked proof that the optimized EVM schedule computes zkAPI's Poseidon

This Lean 4 + Mathlib project proves that the gas-optimized, fully unrolled Yul Poseidon zkAPI
deploys, the vault's `Bn254PoseidonRuntime`
([`protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol`](../contracts/src/poseidon/Bn254PoseidonRuntime.sol),
scaled sparse partial rounds and lazy modular reduction), computes exactly zkAPI's Poseidon.
zkAPI's Poseidon is the one `zkapi-core` defines: width 3 over the BN254 scalar field, `x^5` S-box,
8 full and 57 partial rounds, circomlib's constants (arkworks `find_poseidon_ark_and_mds`),
`compress` and the sponge `hash_fields`.

The proof has three layers:

* the **math layer** (the schedule is the permutation);
* the **word layer** (the straight-line program with lazy reduction computes it on 256-bit words);
* the **Yul layer**: the kernel parses the runtime's whole `assembly ("memory-safe") { … }` block
  from the contract's source (the function `permute`, the dispatcher, the ABI checks and the
  Merkle-path loops) and, in a Yul semantics with memory, function calls, `switch` and `for`, the
  block is proved to do, for **every** calldata shorter than `2^48` bytes and any initial memory,
  what `runtimeSpec` states (`Zkapi.Yul.runtime_block`): revert with no data exactly where solc's
  ABI decoder of the replaced library's functions would, and otherwise return the ABI encoding of
  `compress`, `hash5`, `insertPath32` or `compressPairPath32` of the calldata words, which the word
  and math layers equate with zkAPI's Poseidon, sponge and Merkle paths.

What is not covered is the compilation of the source to bytecode (solc, legacy pipeline) and the
Solidity around the block, which is modelled (`fallbackRun`: solc's prologue and the rejection of
call value) and pinned by the generator (`check_glue`). See [Trust boundary](#trust-boundary).

```sh
cd protocol/formal
lake exe cache get                       # Mathlib oleans for the pinned revision
lake build                               # every proof, the vectors and the axiom audit
python3 -I scripts/generate.py --check   # generated data reproduces from the repository's sources
python3 -I scripts/audit_sources.py      # no sorry/admit/native_decide/axiom/unsafe in the sources
lake build ZkapiPoC                      # the earlier proof of concept (poc/, superseded)
```

CI (`.github/workflows/ci.yml`, job `formal`) runs all of these, with `generate.py --check --yul`
on the contracts' and the setup's copies of the runtime.

A clean `lake build` (with Mathlib's oleans from the cache) takes about 2 minutes on 32 cores.
The heaviest modules are `Yul/Vectors` (the kernel parses the runtime and runs it on concrete
calls, about 70 s and 5.5 GB) and `Yul/Permute` (the kernel parses the whole assembly block and
checks it, about 13 s and 5.2 GB). Every other module stays under about 3.2 GB. (A kernel run of
`insertPath32`'s 32 iterations took 16.6 GB, so it is not among the vectors.) The toolchain and
Mathlib revision are the ones msp-formal-curve uses: `leanprover/lean4:v4.35.0-rc3` and Mathlib
`8accc04827c389e678c3ef83e623b402e7480394`, whose cache is available. In the sandbox where this was
built `~/.elan` is read-only, so the toolchain was installed with
`ELAN_HOME=$HOME/.cache/zkapi-formal-elan` and every `lake` call ran under that variable. A normal
elan installation needs none of that.

## What is proved

The permutation, hash and word-program theorems hold for all inputs and take no hypotheses. The
Yul theorems about the runtime take one hypothesis about the call: the calldata is shorter than
`2^48` bytes (for the opaque branch of `permute`; it also gives `hash5`'s opaque zero, which needs
fewer than `2^255`). The per-round lemmas take the lane invariant they need, and canonical
constants, as hypotheses; the whole-program theorem discharges them.

Every theorem's axioms are only `propext`, `Classical.choice` and `Quot.sound`.
`ZkapiFormal/Audit/Axioms.lean` fails the build otherwise. It checks the named results and also
every declaration under `Zkapi` (2604 at the time of writing).

| Result | Statement |
|---|---|
| `Zkapi.Poseidon.Scaled.permute_eq_reference` | `∀ s : Fin 3 → F, Scaled.permute s = Poseidon.permute s`: the scaled sparse schedule (the new implementation) is the reference permutation on **every** state, including any capacity/domain lane. |
| `Scaled.compress_eq_reference`, `Scaled.hash5_eq_reference`, `Scaled.hashFields_eq_reference` | `compress`, `hash5` and the general sponge built on the scaled permutation equal zkAPI's. |
| `Zkapi.Poseidon.Sparse.permute_eq_reference` | The same for the sparse schedule of the library the vault used before the runtime, kept as the tests' reference implementation (`protocol/contracts/test/reference/Bn254PoseidonReference.sol`). This is about its arithmetic and constants, not its looped Yul, which is not modelled. |
| `Sparse.deployed_constants` | That library's `CONSTANTS` blob (372 words) is exactly the sparse schedule's constants. |
| `Zkapi.Vectors.*` | Kernel evaluation of the Lean reference reproduces known answers from four sources: <br>• `Bn254PoseidonRuntime.t.sol`: both `compress` vectors and the `hash5` vector. <br>• `MerkleUpdateLib`: all 33 `ZERO_HASHES` and `EMPTY_ROOT`. <br>• Rust's `poseidon-vectors.json`: 4 `merkle_node`, `hash_fields` over 0 to 7 inputs, 2 non-canonical `hash_felts`, 7 `note_leaf` (one permutation with the capacity domain `zkapi.v2c.leaf`, `noteLeaf`), 3 `registration_commitment` and 3 `merkle_root` vectors. <br>• arkworks' permutation of 5 whole states, all three lanes, including non-zero capacities (`arkworks_permute_*`, `reference/permutation-vectors.json`). |
| `Zkapi.Lazy.full_first_spec`, `full_spec`, `partial_spec`, `last_spec` | One round of each shape, as the exact operation sequence on unreduced words: <br>• every `ADD` adds two values whose exact sum is below `2^256`; <br>• the outputs keep the bounds the generator tracks; <br>• they represent the field round. |
| `Zkapi.Lazy.program_spec`, `wordPermute_eq`, `wordPermute_safe` | The whole 65-round straight-line program: for all input words, no `ADD` overflows. The outputs are the canonical representatives of `Poseidon.permute` of the inputs reduced mod p. |
| `Zkapi.Lazy.program_words_prefix`, `program_words`, `Expr.eval_lt_W` | With word inputs, every variable holds a word after every statement, and every expression value is a word. So the natural-number model is the EVM's word arithmetic. |
| `Zkapi.Lazy.compressWord_eq`, `hash5Word_eq` | `compress` and `hash5` on words, composed as the runtime's dispatcher composes `permute`, equal zkAPI's on the reduced inputs. |
| `Zkapi.Lazy.insertPath32Word_eq`, `compressPairPath32Word_eq`, `insertPath32Word_root`, `pathNodeW_eq` | The Merkle-path loops of the runtime's `insertPath32` and `compressPairPath32`, on words. They return the path roots and the completed node: the node at the lowest zero bit of `index`, or at `nodeLevel`. These equal `Poseidon.pathNode` and `merkleRoot` (zkAPI's `merkle_root`) as canonical words. Only the leaf itself, at height 0, is returned unreduced. |
| `Zkapi.Yul.runtime_block` | **The runtime's assembly block, for all calldata.** For every calldata `cd` shorter than `2^48` bytes, every call value and every initial memory, the block (the kernel's parse of the source, `blockAst`), run in the Yul semantics, halts as `runtimeSpec cd` says: <br>• fewer than 4 bytes, or a selector other than the four: `revert` with no data; <br>• `compress(uint256,uint256,uint256)` (`0x2d0c7694`), `hash5(uint256×5)` (`0xc98aeff5`), `insertPath32(uint256,uint32,uint256,uint256[32])` (`0x21d2c645`), `compressPairPath32(uint256,uint32,uint256,uint256,uint256[32],uint256)` (`0xf6073d4e`): `revert` with no data when the arguments are shorter than the head (96, 160, 1120, 1184 bytes after the selector) or `index` is not a clean `uint32` (`2^32 ≤ index`), as solc's ABI decoder of the replaced library; otherwise `return` of the ABI encoding of `compressWord`, `hash5Word`, `insertPath32Word` or `compressPairPath32Word` of the calldata words, for every word, canonical or not. |
| `Zkapi.Yul.runtime_fallback` | The same with solc's code around the block (`fallbackRun`): a call with value reverts with no data (the fallback is not `payable`). The replaced library, reached by `DELEGATECALL`, did not check the value; the vault's `STATICCALL` carries none, so the difference never shows. |
| `Zkapi.Yul.runtime_compress`, `runtime_hash5`, `runtime_insertPath32`, `runtime_insertPath32_root`, `runtime_compressPairPath32` | The four entry points' results stated with zkAPI's definitions: `Poseidon.compress` and `Poseidon.hashFields` of the argument words reduced mod p; `Poseidon.pathNode` at height 32 (zkAPI's `merkle_root` for `DOMAIN_NODE`) for the roots; the completed node at the lowest zero bit of `index` and the new path's node at `min nodeLevel 32` (`pathNodeW`, canonical above the leaf by `pathNodeW_eq`). |
| `Zkapi.Yul.yul_permute` | **The runtime's `permute` computes the permutation.** The kernel parses the whole block from the token stream, punctuation included (`blockOK_source`), and finds three statements: `function permute(s0, s1, s2) -> r0, r1, r2 { … }`, the short-calldata check and the dispatcher. The function that definition gives `permute`, called with any words `a b c` and any memory, returns `wordPermute a b c` and leaves memory unchanged. The modulus binding `let P := p` and the opaque branch `if gt(calldatasize(), 0xffffffffffff) { P := 1 }` are part of the run. |
| `Zkapi.Yul.exec_compressArm`, `exec_hash5Arm`, `exec_insertArm`, `exec_pairArm` | Each arm of the dispatcher, for any function `F` computing any permutation `P` (`Computes F P`), so the kernel never unfolds `permute` while checking them. The loops use the bounded loop lemma (`loop_count`, `exec_for`) with the invariants of `insertStep` and `pairStep`. |
| `Zkapi.Yul.Frag.execL_flat`, `Zkapi.Yul.execL_unemb` | Generic: for every *well-scoped* program of the straight-line fragment, scoped execution equals the flat execution `Zkapi.Lazy.exec` (`execL_flat`, on the fragment's own small semantics). A program is well scoped (`wsL`, checked by the kernel) when every read or assigned name is visible and no `let` redeclares a visible name. On that fragment the Yul semantics computes what the small one computes and leaves memory alone (`execL_unemb`). |
| `Zkapi.Yul.yul_compress_*`, `yul_hash5`, `yul_unknown_selector`, `yul_insertPath32_dirty_index`, `yul_callvalue`, `yul_permute_branch_taken`, `Zkapi.Lazy.wordPermute_arkworks_*`, `compressWord_*`, `hash5Word_*`, `insertPath32_root_*` | Kernel evaluation of the parsed runtime (on calldata) and of the word program on concrete inputs: the Solidity tests' `compress` and `hash5` vectors, non-canonical words, short calldata, an unknown selector, a dirty `uint32`, a call with value; all three lanes, inputs above `p`, full-width words; and the opaque branch taken, which zeroes the outputs and so shows the hypothesis is needed. |

## The specification (`ZkapiFormal/Poseidon/Defs.lean`)

These definitions are a transcription of `protocol/rust/crates/zkapi-core/src/v2.rs` and the
arkworks sponge. They are what a reader has to trust as "zkAPI's Poseidon":

* `F = ZMod p`, `p` the BN254 scalar field order. A state is `Fin 3 → F`: lane 0 is the capacity,
  lanes 1 and 2 the rate.
* `round r`: add `ark r`; apply `x^5` to every lane if `r < 4 ∨ 61 ≤ r`, else to lane 0; then
  `new[i] = Σ_j mds[i][j] * old[j]` (arkworks `apply_ark`, `apply_s_box`, `apply_mds`).
  `permute` runs rounds 0 to 64.
* `compress c l r = permute ![c, l, r] 1` (`compress_fields`: capacity set, `[l, r]` absorbed
  into the zero rate, squeeze = permute and read lane 1).
* `hashFields xs = permute (absorb 0 xs) 1`, where `absorb` adds two elements to lanes 1 and 2,
  permutes while more than two remain, and adds the last one or two without permuting. That is
  arkworks `absorb` followed by `squeeze_native_field_elements(1)`, with no padding and no length
  prefix. `hash5 a b c d e` is written as the library computes it, and `hash5_eq_hashFields`
  proves it is `hashFields [a, b, c, d, e]`.
* `pathNode` and `merkleRoot`: `merkle_root`'s loop. Bit `l` of the index chooses
  `compress cap sibling node` or `compress cap node sibling`.
* `domainNode = 0x7a6b6170692e76322e6e6f6465`. `domainNode_eq` proves it equals the big-endian
  bytes of `"zkapi.v2.node"` (`Fr::from_be_bytes_mod_order`).

The vectors tie these definitions to the deployed functions and to the Rust code. They come from
arkworks and zkapi-core at run time and from the Solidity library's tests, and the Lean kernel
reproduces them from these definitions.

## Method

**Reference → sparse** (`Poseidon/Sparse.lean`). This uses msp-formal-curve's certificate method
(`Poseidon/Optimized3Equivalence.lean`). It is generalized from `hash2` with capacity 0 to the
permutation on all states, and adapted to zkAPI's layout (`compact.rs`
`optimized_poseidon_constants`). The reference state before round `j + 4` equals `B_j u_j + τ_j`:

* `u_j` is the sparse state;
* `B_j` is the deferred block-diagonal factor `[[1,0,0],[0,l11,l12],[0,l21,l22]]`;
* `τ_j` holds the relocated constants.

The generator computes `B_j` and `τ_j`. The kernel checks the identities the proof uses with
`decide +kernel` over the finite index sets: `M · B_j = B_{j+1} · S_j`, the first row and column of
each `B_j`, and the constant relocation.

**Sparse → scaled** (`Poseidon/Scaled.lean`). This is params.py's construction. In partial round
`j` lane 0 is kept as `σ = u₀/λ_j`, with `λ_0 = 1` and `λ_{j+1} = a_j λ_j^5`, and the invariant is
`u₀ = λ_j σ`. The certificates are multiplicative only: `k = λ k̂`, `b = λ' b̂`, `c = λ' ĉ`,
`ŵ = w λ^5`, `λ' = a λ^5`, and the last round's first column times `λ^5`. So the proof needs no
field inverses and no primality of `p`.

**Lazy reduction** (`Lazy/*.lean`). `Lazy/Straight.lean` is a minimal straight-line language:
`lit`, the variables `s0 s1 s2 x y z q`, `add`, `addmod(·,·,P)` and `mulmod(·,·,P)`. It runs on
one environment, with block braces as no-ops. Its evaluation uses the EVM results for these
operations: `ADD` wraps mod `2^256`, while `ADDMOD` and `MULMOD` use the exact sum or product mod
`p`.

`Lazy/Render.lean` builds the program from the schedule exactly as
`gen_unrolled.py --form scaled --lazy` does:

* Each lane carries a bound `m` (value `< m·p`).
* A sum is emitted as a plain `add` iff the operand bounds total at most 5. Since
  `5p < 2^256 < 6p`, that `add` cannot wrap. Otherwise the sum is an `addmod`.
* The first round adds its constants with `addmod`, so inputs of any width are reduced.
* The last round ends with `addmod`, so outputs are canonical.

`lzW_spec` is the one arithmetic lemma behind every case. The round lemmas need no bound
hypotheses, because the generator's rule is exactly what makes each case go through.

**The Yul source** (`Yul/*.lean`). This layer has these parts:

* *Lexer.* The generator lexes the runtime's assembly block (`lex_yul`). Every character of the
  source is consumed by one alternative of one regular expression. Only whitespace and `//`
  comments are dropped, and the generator checks that the tokens concatenate back to the source
  minus those. `Data/Yul.lean` holds the token stream of the whole block, punctuation included.
* *Parser* (`Yul/Syntax.lean`). A total parser for the fragment's grammar (blocks, function
  definitions, `let` and assignment of one or more variables, `if`, `switch`, `for`, expression
  statements, calls, identifiers, literals below `2^256`), transcribed from the Yul specification.
* *Semantics* (`Yul/Semantics.lean`). A big-step, structurally recursive semantics, the one the
  theorems are stated in:
  * the state is the visible variables (a scope; a block's declarations go out of scope at its
    end) and byte-addressed memory;
  * a `let` of a visible name, or a read or assignment of an undeclared one, fails, as Yul rejects
    them at compile time;
  * a function's meaning is computed at its definition, so calls need no fuel: a call runs the body
    in a fresh scope of its parameters and return variables (the runtime calls `permute` only after
    defining it, and never recursively);
  * `for` runs at most `2^64` iterations and has no result beyond (the EVM bounds loops by gas), so
    a result of the semantics is the code's result;
  * the builtins `add sub addmod mulmod lt gt slt eq iszero and shr shl calldatasize calldataload
    callvalue` have their EVM results, and `mstore`, `return` and `revert` their effects;
  * `fallbackRun` adds solc's code around the block: `mstore(0x40, 0x80)` and the rejection of
    call value.
* *Generic simulation* (`Yul/Fragment.lean`, `Yul/Flat.lean`, `Yul/Embed.lean`). The body of
  `permute` is in a straight-line fragment with its own small semantics; for every well-scoped
  program of it the scoped run equals the flat `Zkapi.Lazy.exec` (`Frag.execL_flat`), and the Yul
  semantics agrees with the small one on it (`execL_unemb`). This makes the block-flattening
  argument a theorem.
* *The parse* (`Yul/Permute.lean`, `Yul/Shape.lean`). The kernel parses the token stream of the
  block and checks (`blockOK_source`):
  * it is `function permute(s0, s1, s2) -> r0, r1, r2 { … }`, then
    `if lt(calldatasize(), 4) { revert(0, 0) }`, then the dispatcher, which must equal
    `Shape.dispatch`, Lean's own statement of the four arms with their ABI checks;
  * `permute`'s body is `let P := p`, then the opaque branch, then 65 blocks that read, statement
    for statement, as `Zkapi.Lazy.program` (every literal, every `add`/`addmod` choice, every
    operand and every target), are well scoped, and end with `r0 := s0  r1 := s1  r2 := s2`.

  `yul_permute` then follows from `execL_flat`, `execL_unemb` and `program_spec`.
* *The entry points* (`Yul/Exec.lean`, `Yul/Entry.lean`). Generic equations of the semantics for
  each kind of statement, and the bounded loop lemma, are instantiated with `rw`; the arms are
  proved for any function computing any permutation, so the kernel never unfolds the semantics on
  `permute`'s code or its large literals (doing so is what makes the kernel run out of stack).
  `runtime_block` composes them. Because the semantics is executable, the kernel also runs the
  parsed block on concrete calldata (`Yul/Vectors.lean`).

## Constants and vectors provenance

1. **Reference constants.** `protocol/setup/v2-concession-dev/manifest.json` (`poseidon.round_constants`,
   `mds`) is the source of `Data/Reference.lean`. `zkapi-proof`'s `poseidon_manifest()` printed
   it from the same `find_poseidon_ark_and_mds(254, 2, 8, 57, 0)` call that `zkapi-core::v2::config()`
   makes at run time.
   * The generator **regenerates both from the Grain LFSR** (a port of arkworks `PoseidonGrainLFSR`)
     and requires equality.
   * With `--msp` it also checks them against msp-formal-curve's circomlib `t = 3` constants. They
     are identical.
   * In Lean, these constants are checked only through the known-answer vectors, which come from
     Rust, arkworks and the Solidity tests. No certificate covers them, since they are the
     specification's data.
2. **Sparse constants.** These are derived as in `compact.rs` (also `params.py`
   `optimized_constants`). The generator requires them to equal `Bn254PoseidonReference.CONSTANTS`
   (the former library's, kept as the tests' reference), and `deployed_constants` re-checks that in
   Lean.
3. **Scaled constants.** These are derived as in `params.py` `scaled_constants`. The Lean
   certificates check every identity the proof uses.
   * The generator renders the body of `permute` as `gen_unrolled.py` does (and as
     `zkapi-proof`'s `poseidon_runtime.rs` does) and requires the runtime's body to be
     byte-identical to it.
   * It also requires everything else in the file to be the pinned text, comments and whitespace
     aside (`check_glue`): the contract with its one nonpayable fallback, `permute`'s signature
     and three returns, the dispatcher (`revert(0, 0)` for calldata shorter than 4 bytes and for
     unknown selectors), and the four entry points with solc's ABI checks
     (`slt(sub(calldatasize(), 4), N)` and the clean-`uint32` test of `index`), hash5's opaque
     zero, and the two Merkle-path loops.
   * The setup's copy (`protocol/setup/v2-concession-dev/Bn254PoseidonRuntime.sol`) must be the
     same file; `--yul PATH` runs both checks on any other copy.
   * Independently of the Python rendering, Lean parses the runtime's tokens and checks them
     against its own rendering of the program and its own statement of the dispatcher
     (`Yul/Shape.lean`), and proves the entry points from the parse.
4. **Known answers.** `reference/permutation-vectors.json` holds whole-state permutations computed
   by arkworks with zkapi-core's configuration (`scripts/arkworks-vectors`, a standalone Cargo
   crate). Its `check` mode recomputes, with the current zkapi-core, every entry of
   `zkapi-clientd/internal/zkapi/testdata/poseidon-vectors.json`: 61 vectors, all matching at the
   time of writing. That file's own generator regenerates only part of it and nothing in CI keeps
   it in sync, so re-run the check when zkapi-core changes:

   ```sh
   cargo run --release --manifest-path protocol/formal/scripts/arkworks-vectors/Cargo.toml -- \
       check zkapi-clientd/internal/zkapi/testdata/poseidon-vectors.json
   ```
5. **Generation is not a proof.** A wrong constant fails a certificate or a vector in the kernel. A
   wrong token fails the parse check (`blockOK_source`). `generate.py --check` guards only against
   stale files. Two things the kernel does not see:
   * The kernel never sees the `.sol` file, so the lexer is trusted (below).
   * The reference constants are checked by vectors, not by a certificate.

## Trust boundary

Trusted:

* the Lean kernel and the Mathlib definitions used (`ZMod`, `Matrix`);
* that `Defs.lean` states zkAPI's Poseidon. This rests on reading it against `v2.rs` and
  arkworks; the vectors corroborate it.
* that `Yul/Semantics.lean` is Yul's semantics for the fragment (with the EVM's builtins, memory
  and `return`/`revert`), and that `Yul/Syntax.lean` is its grammar. They are short, and the
  kernel-run vectors on the parsed source corroborate them. `Yul/Fragment.lean`'s small semantics
  is not trusted: it is related to `Yul/Semantics.lean` by a proof (`execL_unemb`), and so is
  Lean's statement of the dispatcher (`Yul/Shape.lean`, compared with the parse by the kernel).
* that `runtimeSpec` (`Yul/Entry.lean`) states what the replaced library's functions did as
  solc's ABI decoder decodes their arguments: the selectors, the head sizes, the clean-`uint32`
  rule for `index`, the argument offsets and the ABI encoding of the results. It is short and reads
  against the library's signatures; the results are the word functions the word layer equates with
  zkAPI's definitions.
* that `fallbackRun` is what solc's legacy pipeline wraps around the block: `mstore(0x40, 0x80)`,
  `revert(0, 0)` on call value (the fallback is not `payable`), and a stop if the block ends
  without halting (it never does).
* the generator's lexer (`lex_yul` in `scripts/generate.py`, one regular expression, lossless up to
  whitespace and comments). The runtime's SHA-256 is recorded in the generated `Data/Yul.lean`.
  That the deployed code is this file is checked outside Lean: the setup's
  `poseidon-runtime.json` pins the runtime codehash solc produces from it, which
  `Bn254PoseidonRuntimeTest` and `Deploy.s.sol` require.

Not covered:

* compilation of the Solidity and Yul to bytecode (solc 0.8.28, legacy pipeline, optimizer on).
  The Solidity around the block (pragma, contract, the nonpayable `fallback() external`,
  `assembly ("memory-safe")`) is pinned text (`check_glue`), modelled by `fallbackRun`;
* gas: the semantics has none, so the theorems describe runs that do not run out of gas (a call
  with too little gas reverts);
* the calldata-size hypothesis: below `2^48` bytes. A transaction's gas limit keeps calldata far
  below it.

## Proof of concept (`poc/`)

`poc/` is the feasibility study that preceded the proof of the runtime: a generated contract of the
runtime's shape with only `compress` dispatched (`PoseidonFallback.sol`), its own copy of the
larger Yul fragment, and `Zkapi.PoC.poc_compress`. `ZkapiFormal.Yul` now proves the production
runtime itself, all four entry points, in the merged semantics, so `poc/` adds nothing to the
guarantees; it is kept building (`lake build ZkapiPoC`, `poc/gen_fallback.py --check`) because CI
runs it, and can be removed together with those CI steps. See `poc/README.md`.

## Layout

* `ZkapiFormal/Field.lean`: `p`, `F`.
* `ZkapiFormal/Poseidon/`:
  * `Defs`: the specification;
  * `Iterate`: round lemmas;
  * `Sparse`, `Deployed`, `Scaled`, `Sponge`.
* `ZkapiFormal/Vectors.lean`, `VectorsMerkle.lean` (generated): known-answer theorems.
* `ZkapiFormal/Lazy/`:
  * `Words`: bounded word arithmetic;
  * `Straight`: the flat language;
  * `Render`: the program;
  * `Program`: round lemmas;
  * `Permutation`: the whole program, `compress`, `hash5`;
  * `Paths`: the Merkle-path loops;
  * `WordVectors`.
* `ZkapiFormal/Yul/`:
  * `Syntax`: tokens, AST, parser;
  * `Semantics`: the Yul semantics and `fallbackRun`;
  * `Fragment`, `Flat`, `Embed`: the straight-line fragment, the generic simulation, and its
    agreement with the Yul semantics;
  * `Beq`: structural equality of syntax;
  * `Exec`: generic execution lemmas and the bounded loop lemma;
  * `Shape`: Lean's statement of the dispatcher;
  * `Permute`: the kernel's parse of the block and `yul_permute`;
  * `Entry`: the entry points, `runtimeSpec`, `runtime_block` and the reference corollaries;
  * `Vectors`: the parsed runtime run on concrete calldata.
* `ZkapiFormal/Data/` (generated): reference, sparse, scaled and deployed constants,
  certificates, Yul tokens.
* `ZkapiFormal/Audit/`: the axiom-audit command and the audit.
* `poc/`: the earlier proof of concept, superseded by `ZkapiFormal/Yul` (`ZkapiPoC`,
  `PoseidonFallback.sol`, `gen_fallback.py`).
* `scripts/`:
  * `generate.py`;
  * `audit_sources.py`;
  * `arkworks-vectors/`: the Rust vector generator and checker.
* `reference/permutation-vectors.json`: the arkworks whole-state vectors.

Mutation checks run during development. Each mutation listed here fails as stated:

* Changing one scaling factor in `Data/Scaled.lean` makes five certificates fail in the kernel.
* Each of these changes to `Data/Yul.lean` makes `blockOK_source` fail in the kernel:
  * in `permute`'s body: one `add` changed to `addmod`; the operands of a `mulmod` swapped; one
    literal's last hex digit changed; the opaque branch's bound changed; a `let q` changed to `let s1`;
  * in the dispatcher: the short-calldata bound `4` changed to `3`; `compress` returning `c0`
    instead of `c1`; `hash5`'s `shr(255, …)` changed to `254`; the `uint32` mask changed to
    `0x1ffffffff`; a literal `1` in `insertPath32`'s arm changed to `2`; the operands of a
    `permute` call in `compressPairPath32`'s loop swapped.
* Each of these changes to the runtime makes `generate.py --yul` reject the file:
  * swapping two returns of `permute` (`r1 := s2`);
  * returning lane 0 in `compress`;
  * a minimum length one byte short (`slt(sub(calldatasize(), 4), 95)`);
  * dropping the `uint32` check of `index`, or flipping a loop's bit test;
  * a literal `0` for `hash5`'s capacity, or an operand changed in its `addmod`s;
  * a second function, or code after `default { revert(0, 0) }`.
* A deliberate `sorry`, `axiom` or `native_decide` fails the audit command.
* `generate.py --check` reports every hand-edited generated file.

## Attribution

The following are adapted from msp-formal-curve (Apache-2.0, same author):

* the axiom-audit command;
* the `run` iteration lemmas;
* the field definition;
* the certificate method.

The Grain LFSR is a port of arkworks `ark-crypto-primitives` (MIT/Apache-2.0). The sparse, scaled
and unrolled-rendering derivations port `zkapi-proof/src/compact.rs` and
`zkapi-proof/src/poseidon_runtime.rs` (itself a port of the Poseidon prototype's `gen/params.py`
and `gen/gen_unrolled.py`, which are not kept in this repository).
