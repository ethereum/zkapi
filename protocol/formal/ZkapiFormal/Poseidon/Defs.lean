import ZkapiFormal.Field
import ZkapiFormal.Data.Reference
import Mathlib.Data.Matrix.Mul
import Mathlib.Data.Fin.VecNotation
import Mathlib.Algebra.BigOperators.Fin

/-! # zkAPI's Poseidon: the reference permutation, `compress` and the sponge

This is the specification side. It transcribes `protocol/rust/crates/zkapi-core/src/v2.rs`:

* `config()`: arkworks `PoseidonConfig` with 8 full and 57 partial rounds, `alpha = 5`, rate 2,
  capacity 1, round constants and MDS matrix from `find_poseidon_ark_and_mds::<Fr>(254, 2, 8, 57,
  0)` (`ZkapiFormal.Data.Reference`, regenerated from the Grain LFSR and cross-checked against
  circomlib's `t = 3` parameters by the generator);
* arkworks `PoseidonSponge::permute`: in round `r` add `ark[r]`, apply `x ↦ x^5` to every lane if
  `r < 4` or `r ≥ 61` and to lane 0 otherwise, then `new[i] = Σ_j mds[i][j] * old[j]`;
* the state is `(capacity, rate₀, rate₁)` = lanes `(0, 1, 2)`; `squeeze` reads lane 1;
* `compress_fields(c, l, r)`: one permutation of `(c, l, r)`, lane 1 (`compress`);
* `hash_fields(xs)`: the sponge from the zero state absorbing `xs` two lanes at a time,
  permuting between chunks and once before the squeeze (`hashFields`); `hash5` is its
  five-input instance, written the way the runtime's `hash5` computes it.

The permutation is defined on every state (`Fin 3 → F`), not only on states with capacity 0. -/

namespace Zkapi.Poseidon

/-- A Poseidon state: lane 0 is the capacity, lanes 1 and 2 are the rate. -/
abbrev State := Fin 3 → F

/-- 3 × 3 matrices over `F`. -/
abbrev Mat := Matrix (Fin 3) (Fin 3) F

/-- `mix m s = m · s`: `new[i] = Σ_j m[i][j] * s[j]`, written out. -/
def mix (m : Mat) (s : State) : State := fun i => m i 0 * s 0 + m i 1 * s 1 + m i 2 * s 2

theorem mix_eq_mulVec (m : Mat) (s : State) : mix m s = m.mulVec s := by
  funext i
  simp [mix, Matrix.mulVec, dotProduct, Fin.sum_univ_three]

/-- The round constants of round `r`. -/
def ark (r : Fin 65) : State := fun i => ((Data.arkData.get r).get i : F)

/-- The MDS matrix. -/
def mds : Mat := fun i j => ((Data.mdsData.get i).get j : F)

/-- The S-box. -/
def sbox (x : F) : F := x ^ 5

/-- Round `r` of the reference permutation. -/
def round (r : Fin 65) (s : State) : State :=
  mix mds (fun i => if r.val < 4 ∨ 61 ≤ r.val ∨ i = 0 then sbox (s i + ark r i) else s i + ark r i)

/-- Apply `step 0`, `step 1`, ..., `step (n - 1)` in order. Irreducible, so that elaboration
never unfolds a 65-round computation by accident; proofs unfold it explicitly. -/
@[irreducible] def iterate {n : ℕ} (step : Fin n → State → State) (s : State) : State :=
  (List.finRange n).foldl (fun s r => step r s) s

/-- The reference Poseidon permutation (65 rounds), on every state. -/
@[irreducible] def permute (s : State) : State := iterate round s

/-! ## zkAPI's conventions -/

/-- `compress_fields(capacity, left, right)`: lane 1 of the permutation of
`(capacity, left, right)`. The note tree's node hash is `compress domainNode`. -/
def compress (capacity left right : F) : F := permute ![capacity, left, right] 1

/-- arkworks `absorb` of a list of field elements into a state in absorbing mode with
`next_absorb_index = 0` (rate 2, capacity 1): add two elements to lanes 1 and 2, permute while
more than two elements remain, and add the last one or two without permuting (the squeeze
permutes). -/
def absorb : State → List F → State
  | s, [] => s
  | s, [a] => s + ![0, a, 0]
  | s, [a, b] => s + ![0, a, b]
  | s, a :: b :: c :: rest => absorb (permute (s + ![0, a, b])) (c :: rest)

/-- `hash_fields(xs)`: a fresh sponge (zero state), absorb `xs`, squeeze one element (permute,
read lane 1). -/
def hashFields (xs : List F) : F := permute (absorb 0 xs) 1

/-- The five-input sponge (the runtime's `hash5`, the note leaf's hash), written as the runtime
computes it: three permutations, every lane carried between them. -/
def hash5 (a b c d e : F) : F :=
  permute (permute (permute ![0, a, b] + ![0, c, d]) + ![0, e, 0]) 1

theorem hash5_eq_hashFields (a b c d e : F) : hash5 a b c d e = hashFields [a, b, c, d, e] := by
  rw [hashFields, absorb, absorb, absorb, zero_add]
  rfl

/-- `Fr::from_be_bytes_mod_order(label)`: a domain label's big-endian bytes, reduced mod p. -/
def domainOf (label : List UInt8) : F := (label.foldl (fun acc b => acc * 256 + b.toNat) 0 : ℕ)

/-- `DOMAIN_NODE = "zkapi.v2.node"` (`MerkleUpdateLib.DOMAIN_NODE`). -/
def domainNode : F := 0x7a6b6170692e76322e6e6f6465

/-- `DOMAIN_LEAF = "zkapi.v2.leaf"`. -/
def domainLeaf : F := 0x7a6b6170692e76322e6c656166

theorem domainNode_eq : domainNode = domainOf "zkapi.v2.node".toUTF8.toList := by decide +kernel

theorem domainLeaf_eq : domainLeaf = domainOf "zkapi.v2.leaf".toUTF8.toList := by decide +kernel

/-- The note tree's node hash (`zkapi_core::v2::merkle_node`, `MerkleUpdateLib.poseidonNodeHash`). -/
def merkleNode (left right : F) : F := compress domainNode left right

/-- The root of an empty subtree of height `n` (`zkapi_core::v2::zero_hashes`). -/
def zeroHash : ℕ → F
  | 0 => 0
  | n + 1 => merkleNode (zeroHash n) (zeroHash n)

/-- The node at height `l` on the path of `leaf` at position `index`, given the siblings bottom
up: bit `l` of `index` says whether the path's node at height `l` is a right child
(`zkapi_core::v2::merkle_root`'s loop, with `compress capacity` as the node hash). -/
def pathNode (capacity : F) (index : ℕ) (leaf : F) (sib : ℕ → F) : ℕ → F
  | 0 => leaf
  | l + 1 =>
    if index.testBit l then compress capacity (sib l) (pathNode capacity index leaf sib l)
    else compress capacity (pathNode capacity index leaf sib l) (sib l)

/-- `zkapi_core::v2::merkle_root(note_id, leaf, siblings)`: the root of the depth-32 note tree. -/
def merkleRoot (index : ℕ) (leaf : F) (sib : ℕ → F) : F := pathNode domainNode index leaf sib 32

end Zkapi.Poseidon
