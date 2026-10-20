import ZkapiFormal.Field
import Mathlib.Data.ZMod.Basic
import Mathlib.Tactic.Ring
import Mathlib.Tactic.Linarith

/-! # EVM word arithmetic with explicit bounds

The three EVM operations the unrolled permutation uses, on natural numbers (pure arithmetic, no
EVM state):

* `ADD(a, b) = (a + b) mod 2^256` (`evmAdd`), which wraps;
* `ADDMOD(a, b, P) = (a + b) mod P` and `MULMOD(a, b, P) = (a · b) mod P` with the exact sum or
  product (the yellow paper: "not subject to the 2^256 modulo"), here with `P = p`.

`Rep m w f` says the word `w` is below `m · p` and represents `f : F`. The generator
(gen_unrolled.py `Gen.add`) emits a plain `ADD` for a sum of operands bounded by `ma · p` and
`mb · p` only when `ma + mb ≤ 5`, and `ADDMOD` otherwise (`lzW`); since `5p < 2^256`, the plain
`ADD` never wraps (`lzW_spec`). -/

namespace Zkapi.Lazy

/-- `2^256`. -/
def W : ℕ := 2 ^ 256

theorem five_p_lt_W : 5 * p < W := by decide

theorem W_lt_six_p : W < 6 * p := by decide

/-- EVM `ADD`. -/
def evmAdd (a b : ℕ) : ℕ := (a + b) % W

/-- EVM `ADDMOD(a, b, p)`. -/
def evmAddmod (a b : ℕ) : ℕ := (a + b) % p

/-- EVM `MULMOD(a, b, p)`. -/
def evmMulmod (a b : ℕ) : ℕ := (a * b) % p

/-- The word `w` is below `m · p` and represents the field element `f`. -/
def Rep (m w : ℕ) (f : F) : Prop := w < m * p ∧ (w : F) = f

/-- The bound after a lazy addition (gen_unrolled.py `Gen.add`). -/
def lzBound (ma mb : ℕ) : ℕ := if ma + mb ≤ 5 then ma + mb else 1

/-- A lazy addition: `ADD` if `ma + mb ≤ 5`, `ADDMOD` otherwise. -/
def lzW (a ma b mb : ℕ) : ℕ := if ma + mb ≤ 5 then evmAdd a b else evmAddmod a b

theorem p_pos : 0 < p := by decide

theorem evmAdd_of_lt {a b : ℕ} (h : a + b < W) : evmAdd a b = a + b := Nat.mod_eq_of_lt h

theorem cast_evmAddmod (a b : ℕ) : ((evmAddmod a b : ℕ) : F) = (a : F) + (b : F) := by
  simp [evmAddmod, ZMod.natCast_mod]

theorem cast_evmMulmod (a b : ℕ) : ((evmMulmod a b : ℕ) : F) = (a : F) * (b : F) := by
  simp [evmMulmod, ZMod.natCast_mod]

theorem evmAddmod_lt (a b : ℕ) : evmAddmod a b < p := Nat.mod_lt _ p_pos

theorem evmMulmod_lt (a b : ℕ) : evmMulmod a b < p := Nat.mod_lt _ p_pos

/-- **Lazy addition.** If the operands are below `ma · p` and `mb · p`, the result represents
the field sum, is below `lzBound ma mb · p`, and when a plain `ADD` is emitted (`ma + mb ≤ 5`)
the exact sum is below `2^256`, so the `ADD` does not wrap. -/
theorem lzW_spec {a b ma mb : ℕ} {fa fb : F} (ha : Rep ma a fa) (hb : Rep mb b fb) :
    Rep (lzBound ma mb) (lzW a ma b mb) (fa + fb) ∧ (ma + mb ≤ 5 → a + b < W) := by
  obtain ⟨ha1, ha2⟩ := ha
  obtain ⟨hb1, hb2⟩ := hb
  have key : ma + mb ≤ 5 → a + b < W := by
    intro h
    have h1 : a + b < (ma + mb) * p := by rw [Nat.add_mul]; omega
    have h2 : (ma + mb) * p ≤ 5 * p := Nat.mul_le_mul_right _ h
    have := five_p_lt_W
    omega
  refine ⟨?_, key⟩
  unfold lzW lzBound
  split_ifs with h
  · rw [evmAdd_of_lt (key h)]
    refine ⟨by rw [Nat.add_mul]; omega, ?_⟩
    push_cast
    rw [ha2, hb2]
  · exact ⟨by simpa using evmAddmod_lt a b, by rw [cast_evmAddmod, ha2, hb2]⟩

theorem lzBound_le (ma mb : ℕ) : lzBound ma mb ≤ 5 := by
  unfold lzBound
  split_ifs <;> omega

theorem addmod_spec {a b : ℕ} {fa fb : F} (ha : (a : F) = fa) (hb : (b : F) = fb) :
    Rep 1 (evmAddmod a b) (fa + fb) :=
  ⟨by simpa using evmAddmod_lt a b, by rw [cast_evmAddmod, ha, hb]⟩

theorem mulmod_spec {a b : ℕ} {fa fb : F} (ha : (a : F) = fa) (hb : (b : F) = fb) :
    Rep 1 (evmMulmod a b) (fa * fb) :=
  ⟨by simpa using evmMulmod_lt a b, by rw [cast_evmMulmod, ha, hb]⟩

/-- The S-box as the Yul computes it: `q := x·x; x := (q·q)·x`. -/
def sboxW (w : ℕ) : ℕ := evmMulmod (evmMulmod (evmMulmod w w) (evmMulmod w w)) w

theorem sboxW_spec {w : ℕ} {f : F} (h : (w : F) = f) : Rep 1 (sboxW w) (f ^ 5) := by
  refine ⟨by simpa [sboxW] using evmMulmod_lt (evmMulmod (evmMulmod w w) (evmMulmod w w)) w, ?_⟩
  simp only [sboxW, cast_evmMulmod, h]
  ring

theorem Rep.congr {m w : ℕ} {f g : F} (h : Rep m w f) (e : f = g) : Rep m w g := e ▸ h

theorem Rep.lt_W {m w : ℕ} {f : F} (h : Rep m w f) (hm : m ≤ 5) : w < W := by
  have := five_p_lt_W
  have : m * p ≤ 5 * p := Nat.mul_le_mul_right _ hm
  have := h.1
  omega

/-- A word below `p` is the canonical representative. -/
theorem Rep.eq_val {w : ℕ} {f : F} (h : Rep 1 w f) : w = f.val := by
  obtain ⟨h1, h2⟩ := h
  rw [← h2, ZMod.val_natCast, Nat.mod_eq_of_lt (by simpa using h1)]

theorem rep_lit {k : ℕ} (h : k < p) : Rep 1 k (k : F) := ⟨by simpa using h, rfl⟩

end Zkapi.Lazy
