import ZkapiFormal.Lazy.Permutation

/-! # The Merkle-path loops on words

The runtime's `insertPath32` and `compressPairPath32` run 32 compressions up a depth-32 path,
choosing the order of each compression by bit `level` of `index` (`Zkapi.Yul.exec_insertArm` and
`Zkapi.Yul.exec_pairArm` prove that their Yul computes the functions below).
`insertPath32Word` and `compressPairPath32Word` transcribe the two loops on words, with
`compressWord` (the unrolled program, `compressWord_eq`) for each `permute` call. The theorems say what they return:

* `insertPath32Word_eq`: the path's root, and the node it completes (the path node at the level
  of the lowest zero bit of `index`, the leaf when `index` is even, the root when all 32 bits are
  set);
* `compressPairPath32Word_eq`: the roots of the old and new leaf's paths, and the new path's node
  at `nodeLevel` (the root when `nodeLevel ≥ 32`);
* `insertPath32Word_root`, `pathNodeW_eq`: those are `Poseidon.pathNode` / `Poseidon.merkleRoot`
  (zkAPI's `merkle_root`) of the inputs reduced mod p, as canonical words. Only the leaf itself, at
  height 0, is returned unreduced.

The runtime reverts unless `index` is a clean `uint32` (as solc's ABI decoder would), so
`index < 2^32`; the theorems hold for every `index`. -/

namespace Zkapi.Lazy

open Zkapi.Poseidon

/-- `(index >> level) & 1`, the loops' test. -/
def bitW (index level : ℕ) : ℕ := (index >>> level) &&& 1

theorem bitW_eq_zero_iff (index level : ℕ) : bitW index level = 0 ↔ index.testBit level = false := by
  simp [bitW, Nat.testBit, Nat.and_comm]

/-- One level up: the next path node from `node`, with the sibling on the side bit `level` says. -/
def stepW (capacity index : ℕ) (sib : ℕ → ℕ) (level node : ℕ) : ℕ :=
  if bitW index level = 0 then compressWord capacity node (sib level)
  else compressWord capacity (sib level) node

/-- The path node at height `l` on words (`pathNodeW 0` is the leaf as given). -/
def pathNodeW (capacity index leaf : ℕ) (sib : ℕ → ℕ) : ℕ → ℕ
  | 0 => leaf
  | l + 1 => stepW capacity index sib l (pathNodeW capacity index leaf sib l)

/-- **Above the leaf, the word path is the field path** (canonical words). -/
theorem pathNodeW_eq (capacity index leaf : ℕ) (sib : ℕ → ℕ) :
    ∀ l, (pathNodeW capacity index leaf sib l : F) =
        pathNode capacity index leaf (fun i => (sib i : F)) l ∧
      (0 < l → pathNodeW capacity index leaf sib l =
        (pathNode capacity index leaf (fun i => (sib i : F)) l).val)
  | 0 => ⟨rfl, fun h => absurd h (lt_irrefl 0)⟩
  | l + 1 => by
    have ih := (pathNodeW_eq capacity index leaf sib l).1
    have key : pathNodeW capacity index leaf sib (l + 1) =
        (pathNode capacity index leaf (fun i => (sib i : F)) (l + 1)).val := by
      simp only [pathNodeW, stepW, pathNode]
      by_cases hb : index.testBit l
      · have : ¬ bitW index l = 0 := by rw [bitW_eq_zero_iff]; simp [hb]
        simp only [this, ite_false, hb, ite_true, compressWord_eq, ih]
      · have : bitW index l = 0 := by rw [bitW_eq_zero_iff]; simpa using hb
        simp only [this, ite_true, hb, Bool.false_eq_true, ite_false, compressWord_eq, ih]
    exact ⟨by rw [key, ZMod.natCast_zmod_val], fun _ => key⟩

/-! ## `insertPath32` -/

/-- One iteration of `insertPath32`'s loop on `(root, completed, completing)`. -/
def insertStep (capacity index : ℕ) (sib : ℕ → ℕ) (st : ℕ × ℕ × Bool) (level : ℕ) :
    ℕ × ℕ × Bool :=
  let completed := if bitW index level = 0 ∧ st.2.2 = true then st.1 else st.2.1
  let completing := if bitW index level = 0 then false else st.2.2
  (stepW capacity index sib level st.1, completed, completing)

/-- `insertPath32(capacity, index, leaf, siblings)`, as the Solidity loop computes it. -/
def insertPath32Word (capacity index leaf : ℕ) (sib : ℕ → ℕ) : ℕ × ℕ :=
  let r := (List.range 32).foldl (insertStep capacity index sib) (leaf, leaf, true)
  (r.1, if r.2.2 then r.1 else r.2.1)

/-- The lowest level below `k` whose bit of `index` is zero. -/
def lowZero (index k : ℕ) : Option ℕ := (List.range k).find? fun l => bitW index l = 0

theorem lowZero_succ (index k : ℕ) :
    lowZero index (k + 1) = (lowZero index k).or (if bitW index k = 0 then some k else none) := by
  simp only [lowZero, List.range_succ, List.find?_append, List.find?_singleton]
  cases List.find? (fun l => bitW index l = 0) (List.range k) <;> simp [Option.or]

theorem insert_loop (capacity index leaf : ℕ) (sib : ℕ → ℕ) : ∀ k,
    (List.range k).foldl (insertStep capacity index sib) (leaf, leaf, true) =
      (pathNodeW capacity index leaf sib k,
        (match lowZero index k with
          | some l => pathNodeW capacity index leaf sib l
          | none => leaf),
        (lowZero index k).isNone)
  | 0 => rfl
  | k + 1 => by
    rw [List.range_succ, List.foldl_append, insert_loop capacity index leaf sib k, lowZero_succ]
    simp only [List.foldl_cons, List.foldl_nil, insertStep, pathNodeW]
    cases h : lowZero index k <;> by_cases hb : bitW index k = 0 <;> simp [hb, Option.or]

/-- **`insertPath32` returns the root and the completed node.** The root is the path's node at
height 32; the completed node is the path's node at the height of the lowest zero bit of `index`
(the leaf when `index` is even), or the root when the 32 low bits are all set. -/
theorem insertPath32Word_eq (capacity index leaf : ℕ) (sib : ℕ → ℕ) :
    insertPath32Word capacity index leaf sib =
      (pathNodeW capacity index leaf sib 32,
        pathNodeW capacity index leaf sib ((lowZero index 32).getD 32)) := by
  simp only [insertPath32Word, insert_loop]
  cases lowZero index 32 <;> simp

/-- **`insertPath32`'s root is zkAPI's Merkle root** (`merkle_root` for `DOMAIN_NODE`). -/
theorem insertPath32Word_root (index leaf : ℕ) (sib : ℕ → ℕ) :
    (insertPath32Word 0x7a6b6170692e76322e6e6f6465 index leaf sib).1 =
      (merkleRoot index (leaf : F) (fun i => (sib i : F))).val := by
  rw [insertPath32Word_eq]
  exact (pathNodeW_eq _ index leaf sib 32).2 (by decide)

/-! ## `compressPairPath32` -/

/-- One iteration of `compressPairPath32`'s loop on `(oldRoot, newRoot, newNode)`. -/
def pairStep (capacity index nodeLevel : ℕ) (sib : ℕ → ℕ) (st : ℕ × ℕ × ℕ) (level : ℕ) :
    ℕ × ℕ × ℕ :=
  let newNode := if level = nodeLevel then st.2.1 else st.2.2
  (stepW capacity index sib level st.1, stepW capacity index sib level st.2.1, newNode)

/-- `compressPairPath32(capacity, index, oldLeaf, newLeaf, siblings, nodeLevel)`, as the Solidity
loop computes it. -/
def compressPairPath32Word (capacity index oldLeaf newLeaf : ℕ) (sib : ℕ → ℕ) (nodeLevel : ℕ) :
    ℕ × ℕ × ℕ :=
  let r := (List.range 32).foldl (pairStep capacity index nodeLevel sib) (oldLeaf, newLeaf, newLeaf)
  (r.1, r.2.1, if 32 ≤ nodeLevel then r.2.1 else r.2.2)

theorem pair_loop (capacity index oldLeaf newLeaf nodeLevel : ℕ) (sib : ℕ → ℕ) : ∀ k,
    (List.range k).foldl (pairStep capacity index nodeLevel sib) (oldLeaf, newLeaf, newLeaf) =
      (pathNodeW capacity index oldLeaf sib k, pathNodeW capacity index newLeaf sib k,
        if nodeLevel < k then pathNodeW capacity index newLeaf sib nodeLevel else newLeaf)
  | 0 => by simp [pathNodeW]
  | k + 1 => by
    rw [List.range_succ, List.foldl_append, pair_loop capacity index oldLeaf newLeaf nodeLevel sib k]
    simp only [List.foldl_cons, List.foldl_nil, pairStep, pathNodeW]
    by_cases h1 : nodeLevel < k
    · simp [h1, show nodeLevel < k + 1 by omega, show k ≠ nodeLevel by omega]
    · by_cases h2 : k = nodeLevel
      · subst h2; simp
      · simp [h1, h2, show ¬ nodeLevel < k + 1 by omega]

/-- **`compressPairPath32` returns both roots and the new path's node at `nodeLevel`** (the new
root when `nodeLevel ≥ 32`; the new leaf itself when `nodeLevel = 0`). -/
theorem compressPairPath32Word_eq (capacity index oldLeaf newLeaf : ℕ) (sib : ℕ → ℕ)
    (nodeLevel : ℕ) :
    compressPairPath32Word capacity index oldLeaf newLeaf sib nodeLevel =
      (pathNodeW capacity index oldLeaf sib 32, pathNodeW capacity index newLeaf sib 32,
        pathNodeW capacity index newLeaf sib (min nodeLevel 32)) := by
  simp only [compressPairPath32Word, pair_loop]
  by_cases h : 32 ≤ nodeLevel
  · simp [h]
  · simp [h, show nodeLevel < 32 by omega, Nat.min_eq_left (show nodeLevel ≤ 32 by omega)]

end Zkapi.Lazy
