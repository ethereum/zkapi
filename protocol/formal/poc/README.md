# Proof of concept: an entry point end to end, for all calldata

**Superseded.** `ZkapiFormal.Yul` now proves the production runtime itself
(`protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol`), all four entry points, for all
calldata, in one Yul semantics that merges this directory's fragment with the permutation's
(`Zkapi.Yul.runtime_block`; see `../README.md`). This directory is kept building because CI runs
it (`lake build ZkapiPoC`, `gen_fallback.py --check`); it can be removed with those CI steps.

This directory is a proof of concept for the implementation layer. It shows that the Yul-level
method of `ZkapiFormal.Yul` extends from the permutation body to a whole entry point:
dispatcher, ABI length check, a Yul function call, memory and `return`/`revert`. It is not
deployed anywhere, and it is not part of the default `lake build`.

```sh
cd protocol/formal
python3 -I poc/gen_fallback.py --check   # PoseidonFallback.sol and ZkapiPoC/Data.lean are fresh
lake build ZkapiPoC                      # the proofs, kernel vectors and the PoC's axiom audit
```

The pieces:

* **`PoseidonFallback.sol`** (generated from the production runtime). A contract whose
  runtime is, after solc's `mstore(0x40, 0x80)` prologue, a single inline-assembly block. The
  block defines `function permute(s0, s1, s2) -> r0, r1, r2`, whose body is the production
  runtime's `permute` body verbatim (`protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol`,
  which has the same shape with four entry points). It then rejects calldata shorter than 4 bytes and dispatches
  `compress(uint256,uint256,uint256)` (selector `0x2d0c7694`) with solc's ABI length check. Only
  `compress` is dispatched.
* **`ZkapiPoC/Syntax.lean`, `Semantics.lean`**: a larger Yul fragment. It adds function
  definitions and calls, `switch`, multi-variable `let`, expression statements, byte-level
  memory, `calldataload`/`calldatasize`, `mstore`, `return` and `revert`. The semantics stays
  structurally recursive, so the kernel can run it. A function's meaning is computed at its
  definition, so this PoC supports only functions called after their definition and
  non-recursive ones.
* **`ZkapiPoC/Embed.lean`** (`execL_unemb`): on the fragment of `ZkapiFormal.Yul`, the larger
  semantics computes what `Zkapi.Yul.Frag.execS` (the straight-line fragment's semantics) computes. So `execL_flat` and the program lemmas carry
  over unchanged.
* **`ZkapiPoC/Compress.lean`**:
  * `pocOK_source`: the kernel parses the block's tokens and finds `permute` (checked exactly as
    `Zkapi.Yul.blockOK_source` checks the production `permute`), the length check and the dispatcher.
  * `poc_compress`: for every calldata shorter than `2^48` bytes and any initial memory, the block
    behaves as follows:
    * calldata shorter than 4 bytes: `revert(0, 0)`;
    * the `compress` selector with fewer than 100 bytes: `revert(0, 0)`;
    * the `compress` selector otherwise: `return` of the 32-byte big-endian
      `compressWord w₄ w₃₆ w₆₈`, where `w₄ w₃₆ w₆₈` are the calldata words at offsets 4, 36 and 68,
      zero-padded;
    * any other selector: `revert(0, 0)`.
  * `poc_compress_reference`: that word is `(Poseidon.compress w₄ w₃₆ w₆₈).val`, for every word,
    canonical or not.
  * `poc_vector_*`: three known-answer runs of the parsed block in the kernel.

Compiled with solc 0.8.28 (legacy pipeline, `--optimize --optimize-runs 10000`), the PoC's runtime
is about 15.7 KB. The production runtime, the same shape with all four entry points, is 16,575
bytes; its `compress` frame is 12,842 gas (`GasBaseline.t.sol`).

Trusted here, beyond `ZkapiFormal`:

* the lexer in `gen_fallback.py`;
* that `Semantics.lean` is Yul's semantics for the larger fragment;
* solc's compilation of the block (Yul → EVM) and of the two-instruction prologue.
