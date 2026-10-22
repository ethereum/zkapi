import ZkapiFormal.Field
import ZkapiFormal.Poseidon.Defs
import ZkapiFormal.Poseidon.Iterate
import ZkapiFormal.Poseidon.Sparse
import ZkapiFormal.Poseidon.Deployed
import ZkapiFormal.Poseidon.Scaled
import ZkapiFormal.Poseidon.Sponge
import ZkapiFormal.Vectors
import ZkapiFormal.VectorsMerkle
import ZkapiFormal.Lazy.Words
import ZkapiFormal.Lazy.Straight
import ZkapiFormal.Lazy.Render
import ZkapiFormal.Lazy.Program
import ZkapiFormal.Lazy.Permutation
import ZkapiFormal.Lazy.Paths
import ZkapiFormal.Lazy.WordVectors
import ZkapiFormal.Yul.Syntax
import ZkapiFormal.Yul.Semantics
import ZkapiFormal.Yul.Fragment
import ZkapiFormal.Yul.Flat
import ZkapiFormal.Yul.Embed
import ZkapiFormal.Yul.Beq
import ZkapiFormal.Yul.Exec
import ZkapiFormal.Yul.Shape
import ZkapiFormal.Yul.Permute
import ZkapiFormal.Yul.Entry
import ZkapiFormal.Yul.Vectors
import ZkapiFormal.Audit.Axioms

/-! # zkAPI Poseidon: the gas-optimized EVM schedule computes zkAPI's Poseidon

See `protocol/formal/README.md`. The headline results:

* `Zkapi.Poseidon.Scaled.permute_eq_reference`: the scaled sparse schedule (the arithmetic of the
  new unrolled implementation) equals the reference permutation on every state;
* `Zkapi.Poseidon.Scaled.compress_eq_reference`, `hash5_eq_reference`, `hashFields_eq_reference`;
* `Zkapi.Poseidon.Sparse.permute_eq_reference` and `deployed_constants`: the same for the
  sparse schedule of the former library, the tests' reference implementation (its constants, not
  its looped Yul);
* `Zkapi.Vectors.*`: known-answer vectors from the Solidity tests, `MerkleUpdateLib.ZERO_HASHES`,
  the Rust vector file and arkworks (all three lanes), by kernel evaluation;
* `Zkapi.Lazy.program_spec`, `wordPermute_eq`, `compressWord_eq`, `hash5Word_eq`: the straight-line
  program with lazy reduction never overflows an `ADD` and computes the reference on words;
* `Zkapi.Lazy.insertPath32Word_eq`, `compressPairPath32Word_eq`, `insertPath32Word_root`: the
  Merkle-path loops on words;
* `Zkapi.Yul.yul_permute`: the kernel parses the whole assembly block of the vault's Poseidon
  runtime; the function `permute` it defines computes `wordPermute` for all inputs;
* `Zkapi.Yul.runtime_block`, `runtime_fallback`: for every calldata shorter than `2^48` bytes and
  any initial memory, the runtime reverts exactly where solc's ABI decoder of the replaced library
  would and otherwise returns the ABI encoding of `compress`, `hash5`, `insertPath32` or
  `compressPairPath32` (`runtimeSpec`); `runtime_compress`, `runtime_hash5`,
  `runtime_insertPath32(_root)`, `runtime_compressPairPath32` state the results with zkAPI's
  reference definitions. -/
