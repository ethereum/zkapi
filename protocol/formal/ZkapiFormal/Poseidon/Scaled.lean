import ZkapiFormal.Poseidon.Sparse
import ZkapiFormal.Data.Scaled

/-! # The scaled sparse schedule equals the reference permutation

The scaled sparse schedule is the form of the new unrolled implementation
(zkapi-proof `poseidon_runtime.rs` `scaled_schedule`, a port of the prototype's `gen/params.py`
`scaled_constants`): the full
rounds are the sparse schedule's, and in partial round `j` the first lane is kept divided by
`λ_j`, with `λ_0 = 1` and `λ_{j+1} = a_j λ_j^5`. Writing `u₀ = λ_j σ`, the S-box input is
`λ_j (σ + k_j/λ_j)`, so `x = λ_j^5 y` with `y = (σ + k̂_j)^5` and the new first lane
`a_j x + b_j u₁ + c_j u₂ = λ_{j+1} (y + b̂_j u₁ + ĉ_j u₂)`: the coefficient of `y` is 1, and a
partial round costs one modular multiplication less. The last partial round takes `σ` with its
constant divided by `λ_56` and its dense matrix's first column multiplied by `λ_56^5`.

`permute_eq_reference` proves the scaled schedule equal to the reference permutation on every
state. The proof only uses multiplicative identities between the constants (no inverses), which
the kernel checks; the generator computes the `λ_j`. -/

namespace Zkapi.Poseidon.Scaled

open Zkapi.Poseidon

/-- Partial round `j`'s coefficients `k̂, b̂, ĉ, ŵ1, ŵ2` (indices 0-4). -/
def coef (j : Fin 56) (n : Fin 5) : F := ((Data.scaledPartialData.get j).get n : F)

/-- The last partial round's constants `k₀/λ_56, k₁, k₂`. -/
def lastK : State := fun i => (Data.scaledLastKData.get i : F)

/-- The last partial round's dense matrix, first column scaled by `λ_56^5`. -/
def lastM : Mat := fun i l => ((Data.scaledLastMData.get i).get l : F)

/-- Certificate: the scaling factors `λ_0, ..., λ_56`. -/
def lam (j : Fin 57) : F := (Data.scaledLambdaData.get j : F)

/-- Scaled partial round `j`, as the unrolled Yul computes it (7 multiplications: 3 for the
S-box, 4 for the sparse matrix). -/
def partialRound (j : Fin 56) (s : State) : State :=
  let x := sbox (s 0 + coef j 0)
  ![x + coef j 1 * s 1 + coef j 2 * s 2, s 1 + coef j 3 * x, s 2 + coef j 4 * x]

/-- The last partial round. -/
def lastRound (s : State) : State :=
  mix lastM ![sbox (s 0 + lastK 0), s 1 + lastK 1, s 2 + lastK 2]

/-- The scaled sparse permutation. -/
@[irreducible] def permute (s : State) : State :=
  iterate Sparse.suffixRound (lastRound (iterate partialRound (iterate Sparse.prefixRound s)))

/-! ## Kernel-checked certificates -/

set_option maxRecDepth 100000

theorem lam_zero : lam 0 = 1 := by decide +kernel

theorem lam_succ : ∀ j : Fin 56,
    lam ⟨j.val + 1, by omega⟩ = Sparse.coef j 1 * lam ⟨j.val, by omega⟩ ^ 5 := by
  decide +kernel

theorem k_scaled : ∀ j : Fin 56, Sparse.coef j 0 = lam ⟨j.val, by omega⟩ * coef j 0 := by
  decide +kernel

theorem b_scaled : ∀ j : Fin 56, Sparse.coef j 2 = lam ⟨j.val + 1, by omega⟩ * coef j 1 := by
  decide +kernel

theorem c_scaled : ∀ j : Fin 56, Sparse.coef j 3 = lam ⟨j.val + 1, by omega⟩ * coef j 2 := by
  decide +kernel

theorem w1_scaled : ∀ j : Fin 56, coef j 3 = Sparse.coef j 4 * lam ⟨j.val, by omega⟩ ^ 5 := by
  decide +kernel

theorem w2_scaled : ∀ j : Fin 56, coef j 4 = Sparse.coef j 5 * lam ⟨j.val, by omega⟩ ^ 5 := by
  decide +kernel

theorem lastK_scaled :
    Sparse.lastK 0 = lam 56 * lastK 0 ∧ Sparse.lastK 1 = lastK 1 ∧ Sparse.lastK 2 = lastK 2 := by
  decide +kernel

theorem lastM_scaled : ∀ i : Fin 3,
    lastM i 0 = Sparse.lastM i 0 * lam 56 ^ 5 ∧ lastM i 1 = Sparse.lastM i 1 ∧
      lastM i 2 = Sparse.lastM i 2 := by
  decide +kernel

/-! ## The equivalence -/

/-- A scaled state: lane 0 multiplied by `l`. -/
def scale (l : F) (v : State) : State := ![l * v 0, v 1, v 2]

theorem scale_one (v : State) : scale 1 v = v := by
  funext i
  fin_cases i <;> simp [scale]

theorem partial_step (j : Fin 56) (v : State) :
    Sparse.partialRound j (scale (lam ⟨j.val, by omega⟩) v) =
      scale (lam ⟨j.val + 1, by omega⟩) (partialRound j v) := by
  funext i
  fin_cases i <;>
    simp only [Sparse.partialRound, partialRound, scale, sbox, Fin.zero_eta, Fin.isValue,
      Matrix.cons_val_zero, Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons,
      Matrix.tail_cons, Fin.reduceFinMk, k_scaled j, b_scaled j, c_scaled j, w1_scaled j,
      w2_scaled j, lam_succ j] <;>
    ring

theorem last_step (v : State) : Sparse.lastRound (scale (lam 56) v) = lastRound v := by
  obtain ⟨h0, h1, h2⟩ := lastK_scaled
  funext i
  obtain ⟨m0, m1, m2⟩ := lastM_scaled i
  simp only [Sparse.lastRound, lastRound, mix, scale, sbox, Matrix.cons_val_zero,
    Matrix.cons_val_one, Matrix.cons_val_two, Matrix.head_cons, Matrix.tail_cons, h0, h1, h2,
    m0, m1, m2]
  ring

theorem partial_eq (u : State) (j : ℕ) (hj : j ≤ 56) :
    run Sparse.partialRound u j = scale (lam ⟨j, by omega⟩) (run partialRound u j) := by
  induction j with
  | zero => rw [run_zero, run_zero, show (⟨0, _⟩ : Fin 57) = 0 from rfl, lam_zero, scale_one]
  | succ j ih =>
    rw [run_succ Sparse.partialRound u (show j < 56 by omega), ih (by omega),
      run_succ partialRound u (show j < 56 by omega)]
    exact partial_step ⟨j, by omega⟩ _

/-- The scaled sparse schedule computes the sparse one. -/
theorem permute_eq_sparse (s : State) : permute s = Sparse.permute s := by
  have h := partial_eq (iterate Sparse.prefixRound s) 56 le_rfl
  rw [run_full, run_full] at h
  unfold permute Sparse.permute
  rw [h, show (⟨56, _⟩ : Fin 57) = 56 from rfl, last_step]

/-- **The scaled sparse schedule (the new implementation's arithmetic) computes the reference
Poseidon permutation, on every state.** -/
theorem permute_eq_reference (s : State) : permute s = Poseidon.permute s := by
  rw [permute_eq_sparse, Sparse.permute_eq_reference]

theorem permute_eq_reference' : permute = Poseidon.permute := funext permute_eq_reference

end Zkapi.Poseidon.Scaled
