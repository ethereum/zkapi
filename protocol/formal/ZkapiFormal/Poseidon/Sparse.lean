import ZkapiFormal.Poseidon.Iterate
import ZkapiFormal.Data.Sparse
import Mathlib.LinearAlgebra.Matrix.Notation
import Mathlib.Tactic.FinCases
import Mathlib.Tactic.Abel
import Mathlib.Tactic.Ring

/-! # The sparse optimized schedule equals the reference permutation

The sparse schedule is the form of the former `Bn254Poseidon` library (now the tests'
`Bn254PoseidonReference`) (zkapi-proof `compact.rs`
`optimized_poseidon_constants`; the generator checks that its constants are the library's
`CONSTANTS` blob word for word): four full rounds; 56 partial rounds that add one constant to
lane 0 and multiply by a sparse matrix `[[a, b, c], [w1, 1, 0], [w2, 0, 1]]`; a last partial round
with its three constants and a dense matrix; four full rounds, the first of which carries the
constants relocated out of the partial rounds.

`permute_eq_reference` proves it equal to the reference permutation on every state. The proof
is msp-formal-curve's method (`Poseidon/Optimized3Equivalence.lean`, Apache-2.0, same author)
for this schedule: the reference state before round `j + 4` is `B_j u_j + τ_j`, where `u_j` is
the sparse state before its partial round `j`, `B_j` is the deferred block-diagonal factor
(first row and column `e₀`) and `τ_j` collects relocated constants. The generator computes
`B_j` and `τ_j`; the kernel checks every identity the proof uses about them (`decide +kernel`
over the finite index sets). -/

namespace Zkapi.Poseidon.Sparse

open Zkapi.Poseidon

/-- Full-round constants: index `r < 4` is round `r`, index `4 + r` is round `61 + r`. -/
def full (r : Fin 8) : State := fun i => ((Data.sparseFullData.get r).get i : F)

/-- Partial round `j`'s coefficients `k, a, b, c, w1, w2` (indices 0-5). -/
def coef (j : Fin 56) (n : Fin 6) : F := ((Data.sparsePartialData.get j).get n : F)

/-- The last partial round's constants. -/
def lastK : State := fun i => (Data.sparseLastKData.get i : F)

/-- The last partial round's dense matrix. -/
def lastM : Mat := fun i l => ((Data.sparseLastMData.get i).get l : F)

/-- Certificate: the deferred factors `B_0, ..., B_56`. -/
def basis (j : Fin 57) : Mat := fun i l => (((Data.sparseBasisData.get j).get i).get l : F)

/-- Certificate: the translations `τ_0, ..., τ_57`. -/
def translation (j : Fin 58) : State := fun i => ((Data.sparseTranslationData.get j).get i : F)

/-- Partial round `j`'s sparse matrix. -/
def sparseMat (j : Fin 56) : Mat :=
  !![coef j 1, coef j 2, coef j 3; coef j 4, 1, 0; coef j 5, 0, 1]

/-- Partial round `j`, as `Bn254Poseidon._partialRounds` computes it. -/
def partialRound (j : Fin 56) (s : State) : State :=
  let x := sbox (s 0 + coef j 0)
  ![coef j 1 * x + coef j 2 * s 1 + coef j 3 * s 2, s 1 + coef j 4 * x, s 2 + coef j 5 * x]

/-- The last partial round (`Bn254Poseidon._lastPartialRound`). -/
def lastRound (s : State) : State :=
  mix lastM ![sbox (s 0 + lastK 0), s 1 + lastK 1, s 2 + lastK 2]

/-- The first four full rounds. -/
def prefixRound (r : Fin 4) : State → State := fullRound (full ⟨r.val, by omega⟩)

/-- The last four full rounds. -/
def suffixRound (r : Fin 4) : State → State := fullRound (full ⟨r.val + 4, by omega⟩)

/-- The sparse optimized permutation. -/
@[irreducible] def permute (s : State) : State :=
  iterate suffixRound (lastRound (iterate partialRound (iterate prefixRound s)))

/-! ## Kernel-checked certificates -/

set_option maxRecDepth 100000

theorem full_prefix : ∀ r : Fin 4, ∀ i : Fin 3,
    full ⟨r.val, by omega⟩ i = ark ⟨r.val, by omega⟩ i := by
  decide +kernel

theorem full_suffix : ∀ r : Fin 3, ∀ i : Fin 3,
    full ⟨r.val + 1 + 4, by omega⟩ i = ark ⟨62 + r.val, by omega⟩ i := by
  decide +kernel

theorem full_relocated : ∀ i : Fin 3, full 4 i = translation 57 i + ark 61 i := by
  decide +kernel

theorem basis_shape : ∀ j : Fin 57,
    basis j 0 0 = 1 ∧ basis j 0 1 = 0 ∧ basis j 0 2 = 0 ∧ basis j 1 0 = 0 ∧ basis j 2 0 = 0 := by
  decide +kernel

theorem translation_zero_entries : ∀ i : Fin 3, translation 0 i = 0 := by
  decide +kernel

theorem factor_entries : ∀ j : Fin 56, ∀ i l : Fin 3,
    mds i 0 * basis ⟨j.val, by omega⟩ 0 l + mds i 1 * basis ⟨j.val, by omega⟩ 1 l +
        mds i 2 * basis ⟨j.val, by omega⟩ 2 l =
      basis ⟨j.val + 1, by omega⟩ i 0 * sparseMat j 0 l +
        basis ⟨j.val + 1, by omega⟩ i 1 * sparseMat j 1 l +
        basis ⟨j.val + 1, by omega⟩ i 2 * sparseMat j 2 l := by
  decide +kernel

theorem partial_constant : ∀ j : Fin 56,
    translation ⟨j.val, by omega⟩ 0 + ark ⟨j.val + 4, by omega⟩ 0 = coef j 0 := by
  decide +kernel

theorem last_constant : translation 56 0 + ark 60 0 = lastK 0 := by
  decide +kernel

theorem translation_step_entries : ∀ j : Fin 56, ∀ i : Fin 3,
    translation ⟨j.val + 1, by omega⟩ i =
      mix mds (translation ⟨j.val, by omega⟩ + ark ⟨j.val + 4, by omega⟩ - single0 (coef j 0)) i := by
  decide +kernel

theorem last_matrix_entries : ∀ i l : Fin 3,
    mds i 0 * basis 56 0 l + mds i 1 * basis 56 1 l + mds i 2 * basis 56 2 l =
      lastM i 0 * (1 : Mat) 0 l + lastM i 1 * (1 : Mat) 1 l + lastM i 2 * (1 : Mat) 2 l := by
  decide +kernel

theorem last_translation_entries : ∀ i : Fin 3,
    translation 57 i =
      (mix mds (translation 56 + ark 60 - single0 (lastK 0)) - mix lastM ![0, lastK 1, lastK 2]) i := by
  decide +kernel

/-! ## The equivalence -/

theorem basis_zero : basis 0 = 1 := by
  ext i l
  fin_cases i <;> fin_cases l <;> decide +kernel

theorem translation_zero : translation 0 = 0 := funext translation_zero_entries

theorem factor (j : Fin 56) :
    mds * basis ⟨j.val, by omega⟩ = basis ⟨j.val + 1, by omega⟩ * sparseMat j :=
  mat_mul_eq (factor_entries j)

theorem last_matrix : mds * basis 56 = lastM := by
  rw [← Matrix.mul_one lastM]
  exact mat_mul_eq last_matrix_entries

theorem partialRound_eq (j : Fin 56) (u : State) :
    partialRound j u = mix (sparseMat j) (psbox (u + single0 (coef j 0))) := by
  funext i
  fin_cases i <;> simp [partialRound, mix, sparseMat, psbox, single0] <;> ring

theorem lastRound_eq (u : State) :
    lastRound u = mix lastM (psbox (u + single0 (lastK 0))) + mix lastM ![0, lastK 1, lastK 2] := by
  rw [← mix_add, lastRound]
  congr 1
  funext i
  fin_cases i <;> simp [psbox, single0, Matrix.vecHead, Matrix.vecTail]

/-- Moving round `j + 4`'s lane-0 constant through `B_j`. -/
theorem split_input (b : Mat) (u τ c : State) (k : F)
    (h00 : b 0 0 = 1) (h10 : b 1 0 = 0) (h20 : b 2 0 = 0) :
    mix b u + τ + c = mix b (u + single0 k) + (τ + c - single0 k) := by
  rw [mix_add, mix_single0 b k h00 h10 h20]
  abel

theorem partial_step (j : Fin 56) (u : State) :
    round ⟨j.val + 4, by omega⟩ (mix (basis ⟨j.val, by omega⟩) u + translation ⟨j.val, by omega⟩) =
      mix (basis ⟨j.val + 1, by omega⟩) (partialRound j u) + translation ⟨j.val + 1, by omega⟩ := by
  obtain ⟨h00, h01, h02, h10, h20⟩ := basis_shape ⟨j.val, by omega⟩
  rw [round_partial _ (by constructor <;> simp; omega),
    split_input _ _ _ _ (coef j 0) h00 h10 h20]
  have hρ : (translation ⟨j.val, by omega⟩ + ark ⟨j.val + 4, by omega⟩ - single0 (coef j 0)) 0 = 0 := by
    have := partial_constant j
    simp only [Pi.add_apply, Pi.sub_apply, single0, Matrix.cons_val_zero]
    rw [this, sub_self]
  rw [psbox_basis _ _ _ h00 h01 h02 h10 h20 hρ, mix_add, mix_mix, factor, ← mix_mix,
    ← partialRound_eq]
  congr 1
  funext i
  exact (translation_step_entries j i).symm

theorem last_step (u : State) :
    round 60 (mix (basis 56) u + translation 56) = lastRound u + translation 57 := by
  obtain ⟨h00, h01, h02, h10, h20⟩ := basis_shape 56
  rw [round_partial _ (by decide), split_input _ _ _ _ (lastK 0) h00 h10 h20]
  have hρ : (translation 56 + ark 60 - single0 (lastK 0)) 0 = 0 := by
    simp only [Pi.add_apply, Pi.sub_apply, single0, Matrix.cons_val_zero]
    rw [last_constant, sub_self]
  rw [psbox_basis _ _ _ h00 h01 h02 h10 h20 hρ, mix_add, mix_mix, last_matrix, lastRound_eq,
    show translation 57 = _ from funext last_translation_entries]
  abel

/-- The reference state before round `k`. -/
def refState (s : State) (k : ℕ) : State := run round s k

theorem refState_succ (s : State) (k : ℕ) (h : k < 65) :
    refState s (k + 1) = round ⟨k, h⟩ (refState s k) :=
  run_succ round s h

theorem prefix_eq (s : State) (k : ℕ) (hk : k ≤ 4) : run prefixRound s k = refState s k := by
  induction k with
  | zero => rfl
  | succ k ih =>
    rw [run_succ prefixRound s (by omega), ih (by omega), refState_succ s k (by omega),
      round_full _ (by left; simp only; omega)]
    unfold prefixRound
    congr 1
    funext i
    exact full_prefix ⟨k, by omega⟩ i

/-- The sparse state before partial round `j`. -/
def partialState (s : State) (j : ℕ) : State := run partialRound (run prefixRound s 4) j

theorem partial_eq (s : State) (j : ℕ) (hj : j ≤ 56) :
    refState s (j + 4) = mix (basis ⟨j, by omega⟩) (partialState s j) + translation ⟨j, by omega⟩ := by
  induction j with
  | zero =>
    rw [partialState, run_zero, prefix_eq s 4 le_rfl, show (⟨0, _⟩ : Fin 57) = 0 from rfl, basis_zero,
      show (⟨0, _⟩ : Fin 58) = 0 from rfl, translation_zero, mix_one, add_zero]
  | succ j ih =>
    have e2 : partialState s (j + 1) = partialRound ⟨j, by omega⟩ (partialState s j) :=
      run_succ partialRound _ (show j < 56 by omega)
    rw [show j + 1 + 4 = j + 4 + 1 by omega, refState_succ s (j + 4) (by omega), ih (by omega), e2]
    exact partial_step ⟨j, by omega⟩ _

theorem last_eq (s : State) : refState s 61 = lastRound (partialState s 56) + translation 57 := by
  show refState s (60 + 1) = _
  rw [refState_succ s 60 (by omega)]
  show round 60 (refState s (56 + 4)) = _
  rw [partial_eq s 56 le_rfl]
  exact last_step _

theorem suffix_eq (s : State) (k : ℕ) (hk : k ≤ 3) :
    refState s (62 + k) = run suffixRound (lastRound (partialState s 56)) (k + 1) := by
  induction k with
  | zero =>
    show refState s (61 + 1) = run suffixRound _ (0 + 1)
    rw [refState_succ s 61 (by omega), run_succ suffixRound _ (show 0 < 4 by omega), run_zero,
      round_full _ (by right; simp only; omega), last_eq, fullRound_translate]
    unfold suffixRound
    congr 1
    funext i
    exact (full_relocated i).symm
  | succ k ih =>
    rw [show 62 + (k + 1) = 62 + k + 1 by omega, refState_succ s (62 + k) (by omega), ih (by omega),
      run_succ suffixRound _ (show k + 1 < 4 by omega), round_full _ (by right; simp only; omega)]
    unfold suffixRound
    congr 1
    funext i
    exact (full_suffix ⟨k, by omega⟩ i).symm

/-- **The sparse optimized schedule computes the reference permutation, on every state.** -/
theorem permute_eq_reference (s : State) : permute s = Poseidon.permute s := by
  have h := suffix_eq s 3 le_rfl
  rw [show 62 + 3 = 65 from rfl, refState, run_full, partialState, run_full, run_full,
    run_full] at h
  unfold permute Poseidon.permute
  exact h.symm

end Zkapi.Poseidon.Sparse
