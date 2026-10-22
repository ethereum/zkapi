import ZkapiFormal.Lazy.Permutation

/-! # Known answers from the straight-line program itself

Kernel evaluation of the straight-line program (which the runtime's `permute` parses to,
`Zkapi.Yul.blockOK_source`) on concrete words, independently of the proofs: the
`Bn254PoseidonRuntime.t.sol` vectors, all three lanes of arkworks permutations (one with a non-zero
capacity), inputs above `p` (which the first round reduces) and full-width words. For the latter
the same value is also evaluated from the reference definitions. -/

namespace Zkapi.Lazy

set_option maxRecDepth 100000

/-- All three lanes of the permutation of `(11, 22, 33)` (arkworks,
`reference/permutation-vectors.json`). -/
theorem wordPermute_arkworks_0 :
    wordPermute 11 22 33 =
      (0x054e73d0679c6505a59729aa1ee45b139f267bdc2bcb35fd4afd4ccfad310153,
        0x0b8eeb0e8aeddd655afd4e7290932c08f405e737216595ce219b8e8bbe29d839,
        0x16e6b3a5ca5c7a76d8e1a8211da7171547ca2de138e819f0f394710b26bee67b) := by
  decide +kernel

/-- All three lanes of the permutation of `(DOMAIN_NODE, 1, 2)`, given as words above `p`. -/
theorem wordPermute_arkworks_1_reduces :
    wordPermute (0x7a6b6170692e76322e6e6f6465 + p) (1 + p) (2 + 4 * p) =
      (0x2e9317557b776f3ecc0da154b4167ddd863a8606e88f8659871366c4a4130a1a,
        0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1,
        0x1e8bf109f3afa7edd6d0233e0d7d00aac76f3881536d9f6f82adfe6fd96fedff) := by
  decide +kernel

theorem compressWord_solidity_0 :
    compressWord 0x7a6b6170692e76322e6e6f6465 1 2 =
      0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1 := by
  decide +kernel

theorem compressWord_solidity_1 :
    compressWord 0x7a6b6170692e76322e6e6f6465 0 0 =
      0x03b561b48dcefd3f971d0959dc5332965246b6b1c358db6eb3fb00aee48fabe4 := by
  decide +kernel

theorem hash5Word_solidity_0 :
    hash5Word 1 2 3 4 5 = 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457 := by
  decide +kernel

/-- Inputs `DOMAIN_NODE + p`, `1 + p`, `2 + 4p` (all below `2^256`) give `compress(DOMAIN_NODE, 1, 2)`. -/
theorem compressWord_reduces :
    compressWord (0x7a6b6170692e76322e6e6f6465 + p) (1 + p) (2 + 4 * p) =
      0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1 := by
  decide +kernel

theorem compressWord_full_width :
    compressWord (2 ^ 256 - 1) (2 ^ 256 - 1) (2 ^ 256 - 1) =
      0x136af0eb53c88eddacb3242937d26fd4f47648649b69b3c33d77ec6427ac88b9 := by
  decide +kernel

theorem compress_full_width :
    Poseidon.compress ((2 ^ 256 - 1 : ℕ) : F) ((2 ^ 256 - 1 : ℕ) : F) ((2 ^ 256 - 1 : ℕ) : F) =
      0x136af0eb53c88eddacb3242937d26fd4f47648649b69b3c33d77ec6427ac88b9 := by
  decide +kernel

theorem hash5Word_full_width :
    hash5Word (2 ^ 256 - 1) (2 ^ 256 - 2) 0 p 7 =
      0x0b5eace031177d17a4c944e6bea626902b6163d130a308ae82eac608d6b36abf := by
  decide +kernel

theorem hash5_full_width :
    Poseidon.hash5 ((2 ^ 256 - 1 : ℕ) : F) ((2 ^ 256 - 2 : ℕ) : F) 0 (p : F) 7 =
      0x0b5eace031177d17a4c944e6bea626902b6163d130a308ae82eac608d6b36abf := by
  decide +kernel

end Zkapi.Lazy
