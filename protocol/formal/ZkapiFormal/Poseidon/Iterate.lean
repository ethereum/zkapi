import ZkapiFormal.Poseidon.Defs

/-! # Iteration and round lemmas

`run step s k` applies the first `k` steps; `run_succ` peels one step. Adapted from
msp-formal-curve `Poseidon/Optimized3Reference.lean` (Apache-2.0, same author). The rest of the
file states the algebra of a single round that the equivalence proofs share. -/

namespace Zkapi.Poseidon

/-- The first `k` steps of `iterate`. -/
def run {n : ℕ} (step : Fin n → State → State) (start : State) (k : ℕ) : State :=
  ((List.finRange n).take k).foldl (fun s r => step r s) start

theorem run_zero {n : ℕ} (step : Fin n → State → State) (start : State) :
    run step start 0 = start := rfl

theorem run_succ {n k : ℕ} (step : Fin n → State → State) (start : State) (h : k < n) :
    run step start (k + 1) = step ⟨k, h⟩ (run step start k) := by
  unfold run
  rw [List.take_succ_eq_append_getElem (by simpa using h), List.foldl_append]
  simp

theorem run_full {n : ℕ} (step : Fin n → State → State) (start : State) :
    run step start n = iterate step start := by
  unfold run
  rw [List.take_of_length_le (by simp [List.finRange])]
  unfold iterate
  rfl

/-! ## Linear algebra of `mix` -/

theorem mix_add (m : Mat) (s t : State) : mix m (s + t) = mix m s + mix m t := by
  simp only [mix_eq_mulVec, Matrix.mulVec_add]

theorem mix_sub (m : Mat) (s t : State) : mix m (s - t) = mix m s - mix m t := by
  simp only [mix_eq_mulVec, Matrix.mulVec_sub]

theorem mix_mix (a b : Mat) (s : State) : mix a (mix b s) = mix (a * b) s := by
  simp only [mix_eq_mulVec, Matrix.mulVec_mulVec]

theorem mix_one (s : State) : mix 1 s = s := by
  simp only [mix_eq_mulVec, Matrix.one_mulVec]

theorem mul_apply3 (a b : Mat) (i j : Fin 3) :
    (a * b) i j = a i 0 * b 0 j + a i 1 * b 1 j + a i 2 * b 2 j := by
  simp [Matrix.mul_apply, Fin.sum_univ_three]

/-- Two matrices are equal when their entries are, stated with explicit sums for `decide`. -/
theorem mat_mul_eq {a b c d : Mat}
    (h : ∀ i j : Fin 3, a i 0 * b 0 j + a i 1 * b 1 j + a i 2 * b 2 j =
      c i 0 * d 0 j + c i 1 * d 1 j + c i 2 * d 2 j) : a * b = c * d := by
  ext i j
  rw [mul_apply3, mul_apply3, h]

/-! ## Rounds -/

/-- A full round with round constants `c`: add, S-box on every lane, MDS. -/
def fullRound (c : State) (s : State) : State := mix mds (fun i => sbox (s i + c i))

/-- The S-box on lane 0 only. -/
def psbox (v : State) : State := fun i => if i = 0 then sbox (v 0) else v i

/-- The unit vector of lane 0, scaled. -/
def single0 (k : F) : State := ![k, 0, 0]

theorem round_full (r : Fin 65) (h : r.val < 4 ∨ 61 ≤ r.val) (s : State) :
    round r s = fullRound (ark r) s := by
  unfold round fullRound
  congr 1
  funext i
  have hi : r.val < 4 ∨ 61 ≤ r.val ∨ i = 0 := by omega
  simp only [hi, ↓reduceIte]

theorem round_partial (r : Fin 65) (h : 4 ≤ r.val ∧ r.val < 61) (s : State) :
    round r s = mix mds (psbox (s + ark r)) := by
  unfold round
  congr 1
  funext i
  by_cases hi : i = 0
  · subst hi
    simp [psbox]
  · have h1 : ¬ r.val < 4 := by omega
    have h2 : ¬ 61 ≤ r.val := by omega
    simp [psbox, hi, h1, h2]

/-- A translation of the input of a full round moves into its constants. -/
theorem fullRound_translate (c t s : State) : fullRound c (s + t) = fullRound (t + c) s := by
  unfold fullRound
  congr 1
  funext i
  simp only [Pi.add_apply, add_assoc]

/-- The partial S-box commutes with a matrix whose first row and column are `e₀`, and with
a translation that leaves lane 0 alone. -/
theorem psbox_basis (b : Mat) (v ρ : State)
    (h00 : b 0 0 = 1) (h01 : b 0 1 = 0) (h02 : b 0 2 = 0) (h10 : b 1 0 = 0) (h20 : b 2 0 = 0)
    (hρ : ρ 0 = 0) :
    psbox (mix b v + ρ) = mix b (psbox v) + ρ := by
  funext i
  fin_cases i <;> simp [psbox, mix, h00, h01, h02, h10, h20, hρ]

/-- A matrix whose first column is `e₀` fixes `single0 k`. -/
theorem mix_single0 (b : Mat) (k : F) (h00 : b 0 0 = 1) (h10 : b 1 0 = 0) (h20 : b 2 0 = 0) :
    mix b (single0 k) = single0 k := by
  funext i
  fin_cases i <;> simp [mix, single0, h00, h10, h20]

end Zkapi.Poseidon
