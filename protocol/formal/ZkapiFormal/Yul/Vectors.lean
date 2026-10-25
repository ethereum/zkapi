import ZkapiFormal.Yul.Entry

/-! # Known answers from the parsed runtime itself

The kernel runs the parsed assembly block of the runtime (`blockAst`) in the Yul semantics on
concrete calldata, independently of the proofs (they corroborate the semantics and the
specification): the `Bn254PoseidonRuntime.t.sol` `compress` and `hash5` vectors, `compress` on
non-canonical words, short calldata, an unknown selector, a dirty `uint32` index, and a call with
value. `yul_permute_branch_taken` runs `permute`'s rounds with calldata of `2^48` bytes (in the
straight-line fragment's semantics, which reads only the calldata size): the opaque branch sets
`P := 1` and every output is 0, so the calldata-size hypothesis of `yul_permute` is needed. -/

namespace Zkapi.Yul

set_option maxRecDepth 100000

/-- The halt, if any. -/
def haltOf : Option Out → Option Halt
  | some (.inl h) => some h
  | _ => none

/-- A selector's 4 bytes. -/
def sel4 (s : ℕ) : List ℕ := (List.range 4).map fun k => s / 256 ^ (3 - k) % 256

/-- `compress(DOMAIN_NODE, 1, 2)` as calldata. -/
def compressCalldata : List ℕ :=
  sel4 selCompress ++ be32 0x7a6b6170692e76322e6e6f6465 ++ be32 1 ++ be32 2

theorem yul_compress_node :
    haltOf (run ⟨compressCalldata, 0⟩ (fun _ => 0) blockAst) =
      some (.ret (be32 0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1)) := by
  decide +kernel

/-- The same state as non-canonical words (`DOMAIN_NODE + p, 1 + p, 2 + 4p`): the same answer. -/
theorem yul_compress_node_reduces :
    haltOf (run ⟨sel4 selCompress ++ be32 (0x7a6b6170692e76322e6e6f6465 + Zkapi.p) ++
        be32 (1 + Zkapi.p) ++ be32 (2 + 4 * Zkapi.p), 0⟩ (fun _ => 0) blockAst) =
      some (.ret (be32 0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1)) := by
  decide +kernel

theorem yul_hash5 :
    haltOf (run ⟨sel4 selHash5 ++ be32 1 ++ be32 2 ++ be32 3 ++ be32 4 ++ be32 5, 0⟩ (fun _ => 0)
        blockAst) =
      some (.ret (be32 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457)) := by
  decide +kernel

/-- One byte short of `compress`'s head: `revert` with no data. -/
theorem yul_compress_short :
    haltOf (run ⟨compressCalldata.take 99, 0⟩ (fun _ => 0) blockAst) = some (.rev []) := by
  decide +kernel

/-- An unknown selector: `revert` with no data. -/
theorem yul_unknown_selector :
    haltOf (run ⟨sel4 (selCompress + 1) ++ compressCalldata.drop 4, 0⟩ (fun _ => 0) blockAst) =
      some (.rev []) := by
  decide +kernel

/-- `insertPath32` with `index = 2^32` (a dirty `uint32`): `revert` with no data. -/
theorem yul_insertPath32_dirty_index :
    haltOf (run ⟨sel4 selInsertPath32 ++ be32 0x7a6b6170692e76322e6e6f6465 ++ be32 (2 ^ 32) ++
        (List.range 33).flatMap (fun _ => be32 0), 0⟩ (fun _ => 0) blockAst) = some (.rev []) := by
  decide +kernel

/-- A call with value: `revert` with no data (solc's prologue, `fallbackRun`). -/
theorem yul_callvalue :
    fallbackRun ⟨compressCalldata, 1⟩ (fun _ => 0) blockAst = some (.rev []) := by
  decide +kernel

/-- `permute`'s rounds as the straight-line fragment (the statements `blockOK` checks). -/
def permuteRounds : List Frag.Stmt :=
  match blockAst with
  | [.funDef _ _ _ body, _, _] => (unembL (body.take (body.length - 3))).getD []
  | _ => []

/-- With calldata of `2^48` bytes or more the opaque branch sets `P := 1` and every `addmod` and
`mulmod` returns 0: the hypothesis of `yul_permute` is needed. -/
theorem yul_permute_branch_taken :
    Frag.execS ⟨2 ^ 48⟩ [("s0", 0x7a6b6170692e76322e6e6f6465), ("s1", 1), ("s2", 2)]
        (.block permuteRounds) =
      some [("s0", 0), ("s1", 0), ("s2", 0)] := by
  decide +kernel

end Zkapi.Yul
