import ZkapiFormal.Poseidon.Scaled

/-! # zkAPI's hashes built on the scaled permutation

`compress`, `hash5` and the general sponge `hashFields`, with the reference permutation replaced
by the scaled sparse one (the new implementation's arithmetic), equal zkAPI's reference
definitions on every input. -/

namespace Zkapi.Poseidon.Scaled

open Zkapi.Poseidon

/-- `compress` on the scaled permutation (`compress` of the runtime). -/
def compress (capacity left right : F) : F := permute ![capacity, left, right] 1

/-- The sponge's absorption on the scaled permutation. -/
def absorb : State → List F → State
  | s, [] => s
  | s, [a] => s + ![0, a, 0]
  | s, [a, b] => s + ![0, a, b]
  | s, a :: b :: c :: rest => absorb (permute (s + ![0, a, b])) (c :: rest)

/-- `hash_fields` on the scaled permutation. -/
def hashFields (xs : List F) : F := permute (absorb 0 xs) 1

/-- `hash5` on the scaled permutation, as the runtime computes it. -/
def hash5 (a b c d e : F) : F :=
  permute (permute (permute ![0, a, b] + ![0, c, d]) + ![0, e, 0]) 1

theorem compress_eq_reference (capacity left right : F) :
    compress capacity left right = Poseidon.compress capacity left right := by
  rw [compress, Poseidon.compress, permute_eq_reference]

theorem hash5_eq_reference (a b c d e : F) : hash5 a b c d e = Poseidon.hash5 a b c d e := by
  rw [hash5, Poseidon.hash5, permute_eq_reference']

theorem absorb_eq_reference (s : State) (xs : List F) : absorb s xs = Poseidon.absorb s xs := by
  induction s, xs using absorb.induct with
  | case1 s => rw [absorb, Poseidon.absorb]
  | case2 s a => rw [absorb, Poseidon.absorb]
  | case3 s a b => rw [absorb, Poseidon.absorb]
  | case4 s a b c rest ih => rw [absorb, Poseidon.absorb, ih, permute_eq_reference]

theorem hashFields_eq_reference (xs : List F) : hashFields xs = Poseidon.hashFields xs := by
  rw [hashFields, Poseidon.hashFields, absorb_eq_reference, permute_eq_reference]

end Zkapi.Poseidon.Scaled
