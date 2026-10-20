import ZkapiFormal.Poseidon.Sparse
import ZkapiFormal.Data.Deployed

/-! # The former library's constants are the sparse schedule's

`Bn254PoseidonReference.CONSTANTS` (the library the vault used before the runtime, kept as the
tests' reference implementation, `protocol/contracts/test/reference/Bn254PoseidonReference.sol`)
lays out 372 words: the first four full rounds (3 each), 56 partial rounds
(`k`, the sparse matrix's first row `a b c`, its first column below the diagonal `w1 w2`), the
last partial round (3 constants, then its dense matrix row-major), the last four full rounds.
The kernel checks that these words are exactly the constants of `Sparse.permute` in that layout,
so `Sparse.permute_eq_reference` is a statement about that library's constants. (The library's
looped Yul itself is not modelled here.) -/

namespace Zkapi.Poseidon.Sparse

/-- The sparse schedule's constants in the `CONSTANTS` layout. -/
def words : List ℕ :=
  ((List.finRange 4).flatMap fun r => (Data.sparseFullData.get ⟨r.val, by omega⟩).toList) ++
    ((List.finRange 56).flatMap fun j => (Data.sparsePartialData.get j).toList) ++
    Data.sparseLastKData.toList ++
    ((List.finRange 3).flatMap fun i => (Data.sparseLastMData.get i).toList) ++
    ((List.finRange 4).flatMap fun r => (Data.sparseFullData.get ⟨r.val + 4, by omega⟩).toList)

set_option maxRecDepth 100000 in
theorem deployed_constants : Data.deployedWords = words := by decide +kernel

end Zkapi.Poseidon.Sparse
