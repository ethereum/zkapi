import ZkapiFormal.Lazy.Render
import ZkapiFormal.Poseidon.Sponge

/-! # Lazy reduction: what the unrolled program computes

The integer-level facts the Yul relies on, for the exact operation sequence of each round shape
(`fullStmts`, `partialStmts`, `lastStmts`, rendered from the schedule as the generator emits
them), with intermediate values left unreduced:

* `full_first_spec`: the first round (inputs of any size, constants added with `ADDMOD`);
* `full_spec`: a full round on lanes below `mᵢ · p`;
* `partial_spec`: a scaled partial round on lanes below `mᵢ · p`;
* `last_spec`: the last partial round (lanes 1 and 2 enter its matrix unreduced).

Each states that every `ADD` adds two values whose exact sum is below `2^256` (`Safe`), that the
new lanes obey the bounds the generator tracks (at most `5p < 2^256`), and that they represent the
field computation of the corresponding round of `ZkapiFormal.Poseidon.Scaled`. No hypothesis on the
bounds is needed: the generator's rule (`ADD` only when the operand bounds total at most 5) is what
makes every case go through (`lzW_spec`).

`program_spec` composes them over the 65 rounds: for all inputs, no `ADD` overflows and the three
outputs are the canonical representatives of the reference permutation of the inputs reduced
mod p. `compressWord_eq` and `hash5Word_eq` lift this to the runtime's `compress` and `hash5`
as its dispatcher composes the permutation. -/

namespace Zkapi.Lazy

open Zkapi.Poseidon (State Mat mix sbox iterate)

/-- The lanes are below their bounds and represent `σ`. -/
def Inv (bd : Bounds) (env : Env) (σ : State) : Prop :=
  Rep bd.m0 (env .s0) (σ 0) ∧ Rep bd.m1 (env .s1) (σ 1) ∧ Rep bd.m2 (env .s2) (σ 2)

theorem eval_lz (a b : Expr) (ma mb : ℕ) (env : Env) :
    (lz a ma b mb).1.eval env = lzW (a.eval env) ma (b.eval env) mb := by
  unfold lz lzW
  split_ifs <;> rfl

theorem bound_lz (a b : Expr) (ma mb : ℕ) : (lz a ma b mb).2 = lzBound ma mb := by
  unfold lz lzBound
  split_ifs <;> rfl

theorem safe_lz (a b : Expr) (ma mb : ℕ) (env : Env) :
    (lz a ma b mb).1.Safe env ↔
      a.Safe env ∧ b.Safe env ∧ (ma + mb ≤ 5 → a.eval env + b.eval env < W) := by
  unfold lz
  split_ifs with h <;> simp [Expr.Safe, h]

theorem sboxW_fold (w : ℕ) : evmMulmod (evmMulmod (evmMulmod w w) (evmMulmod w w)) w = sboxW w :=
  rfl

/-- The matrix of word entries, over `F`. -/
def matF (mat : Fin 3 → Fin 3 → ℕ) : Mat := fun i j => (mat i j : F)

/-! ## The operation sequences, concretely

What the renderer emits for typical bounds (by `rfl`). After any full round every lane is below
`3p`, so the next full round's nine additions are all plain `add`s and its lanes are again below
`3p`. In the partial rounds lane 0 stays below `3p` while lanes 1 and 2 grow by `p` per round,
until a sum would exceed `5p` and an `addmod` reduces them. -/

theorem fullStmts_from_3p (k0 k1 k2 : ℕ) (mat : Fin 3 → Fin 3 → ℕ) :
    fullStmts k0 k1 k2 mat false false ⟨3, 3, 3⟩ =
      ([.openB, .letv .x (.add (.var .s0) (.lit k0)), .letv .y (.add (.var .s1) (.lit k1)),
          .letv .z (.add (.var .s2) (.lit k2))] ++ sboxBlock .x ++ sboxBlock .y ++ sboxBlock .z ++
        [.assign .s0 (.add (.add (term .x (mat 0 0)) (term .y (mat 0 1))) (term .z (mat 0 2))),
          .assign .s1 (.add (.add (term .x (mat 1 0)) (term .y (mat 1 1))) (term .z (mat 1 2))),
          .assign .s2 (.add (.add (term .x (mat 2 0)) (term .y (mat 2 1))) (term .z (mat 2 2))),
          .closeB], ⟨3, 3, 3⟩) := rfl

theorem partialStmts_from_3p_4p (k b c w1 w2 : ℕ) :
    partialStmts k b c w1 w2 ⟨3, 4, 4⟩ =
      ([.openB, .letv .x (.add (.var .s0) (.lit k))] ++ sboxBlock .x ++
        [.assign .s0 (.add (.add (.var .x) (term .s1 b)) (term .s2 c)),
          .assign .s1 (.add (.var .s1) (term .x w1)), .assign .s2 (.add (.var .s2) (term .x w2)),
          .closeB], ⟨3, 5, 5⟩) := rfl

theorem partialStmts_from_3p_5p (k b c w1 w2 : ℕ) :
    partialStmts k b c w1 w2 ⟨3, 5, 5⟩ =
      ([.openB, .letv .x (.add (.var .s0) (.lit k))] ++ sboxBlock .x ++
        [.assign .s0 (.add (.add (.var .x) (term .s1 b)) (term .s2 c)),
          .assign .s1 (.addmod (.var .s1) (term .x w1)),
          .assign .s2 (.addmod (.var .s2) (term .x w2)), .closeB], ⟨3, 1, 1⟩) := rfl

/-! ## One round of each shape -/

/-- **Scaled partial round.** -/
theorem partial_spec (k b c w1 w2 : ℕ) (hk : k < p) (bd : Bounds) (env : Env) (σ : State)
    (h : Inv bd env σ) :
    Safe (partialStmts k b c w1 w2 bd).1 env ∧
      Inv (partialStmts k b c w1 w2 bd).2 (exec (partialStmts k b c w1 w2 bd).1 env)
        ![sbox (σ 0 + k) + b * σ 1 + c * σ 2, σ 1 + w1 * sbox (σ 0 + k),
          σ 2 + w2 * sbox (σ 0 + k)] := by
  obtain ⟨h0, h1, h2⟩ := h
  simp only [partialStmts, sboxBlock, term, exec, Stmt.exec, Safe, Stmt.Safe, List.cons_append,
    List.nil_append, Expr.eval, Expr.Safe, eval_lz, safe_lz, bound_lz, Function.update_apply,
    reduceCtorEq, ite_true, ite_false, sboxW_fold, Inv, true_and, and_true]
  have hx0 := lzW_spec h0 (rep_lit hk)
  have hX := sboxW_spec hx0.1.2
  have e0 := lzW_spec hX (mulmod_spec h1.2 rfl : Rep 1 (evmMulmod (env .s1) b) (σ 1 * b))
  have e0' := lzW_spec e0.1 (mulmod_spec h2.2 rfl : Rep 1 (evmMulmod (env .s2) c) (σ 2 * c))
  have e1 := lzW_spec h1 (mulmod_spec hX.2 rfl : Rep 1 (evmMulmod (sboxW _) w1) (_ * w1))
  have e2 := lzW_spec h2 (mulmod_spec hX.2 rfl : Rep 1 (evmMulmod (sboxW _) w2) (_ * w2))
  refine ⟨⟨hx0.2, ⟨e0.2, e0'.2⟩, e1.2, e2.2⟩, e0'.1.congr ?_, e1.1.congr ?_, e2.1.congr ?_⟩ <;>
    simp [sbox] <;> ring

/-- **Full round** (not the first): lanes below `mᵢ · p` in; below `3p`, or canonical for the
last round, out. -/
theorem full_spec (k : Fin 3 → ℕ) (hk : ∀ i, k i < p) (mat : Fin 3 → Fin 3 → ℕ) (last : Bool)
    (bd : Bounds) (env : Env) (σ : State) (h : Inv bd env σ) :
    Safe (fullStmts (k 0) (k 1) (k 2) mat false last bd).1 env ∧
      Inv (fullStmts (k 0) (k 1) (k 2) mat false last bd).2
        (exec (fullStmts (k 0) (k 1) (k 2) mat false last bd).1 env)
        (mix (matF mat) (fun i => sbox (σ i + k i))) := by
  obtain ⟨h0, h1, h2⟩ := h
  have hx := lzW_spec h0 (rep_lit (hk 0))
  have hy := lzW_spec h1 (rep_lit (hk 1))
  have hz := lzW_spec h2 (rep_lit (hk 2))
  have sx := sboxW_spec hx.1.2
  have sy := sboxW_spec hy.1.2
  have sz := sboxW_spec hz.1.2
  have t := fun (i : Fin 3) => (⟨mulmod_spec sx.2 rfl, mulmod_spec sy.2 rfl, mulmod_spec sz.2 rfl⟩ :
    Rep 1 (evmMulmod (sboxW (lzW (env .s0) bd.m0 (k 0) 1)) (mat i 0)) (_ * (mat i 0 : F)) ∧
    Rep 1 (evmMulmod (sboxW (lzW (env .s1) bd.m1 (k 1) 1)) (mat i 1)) (_ * (mat i 1 : F)) ∧
    Rep 1 (evmMulmod (sboxW (lzW (env .s2) bd.m2 (k 2) 1)) (mat i 2)) (_ * (mat i 2 : F)))
  have r := fun (i : Fin 3) => lzW_spec (t i).1 (t i).2.1
  have r' := fun (i : Fin 3) => lzW_spec (r i).1 (t i).2.2
  have ra := fun (i : Fin 3) => addmod_spec (r i).1.2 (t i).2.2.2
  cases last <;>
  simp only [fullStmts, row, sboxBlock, term, exec, Stmt.exec, Safe, Stmt.Safe, List.cons_append,
    List.nil_append, Expr.eval, Expr.Safe, eval_lz, safe_lz, bound_lz,
    Function.update_apply, reduceCtorEq, ite_true, ite_false, sboxW_fold, Inv, true_and, and_true,
    Bool.false_eq_true]
  · refine ⟨⟨hx.2, hy.2, hz.2, ⟨(r 0).2, (r' 0).2⟩, ⟨(r 1).2, (r' 1).2⟩, (r 2).2, (r' 2).2⟩,
      (r' 0).1.congr ?_, (r' 1).1.congr ?_, (r' 2).1.congr ?_⟩ <;>
      simp [mix, matF, sbox] <;> ring
  · refine ⟨⟨hx.2, hy.2, hz.2, (r 0).2, (r 1).2, (r 2).2⟩,
      (ra 0).congr ?_, (ra 1).congr ?_, (ra 2).congr ?_⟩ <;>
      simp [mix, matF, sbox] <;> ring

/-- **First full round**: inputs of any size (only their residues matter); constants added with
`ADDMOD`. -/
theorem full_first_spec (k : Fin 3 → ℕ) (mat : Fin 3 → Fin 3 → ℕ) (bd : Bounds) (env : Env)
    (σ : State) (h0 : (env .s0 : F) = σ 0) (h1 : (env .s1 : F) = σ 1) (h2 : (env .s2 : F) = σ 2) :
    Safe (fullStmts (k 0) (k 1) (k 2) mat true false bd).1 env ∧
      Inv (fullStmts (k 0) (k 1) (k 2) mat true false bd).2
        (exec (fullStmts (k 0) (k 1) (k 2) mat true false bd).1 env)
        (mix (matF mat) (fun i => sbox (σ i + k i))) := by
  have hx := addmod_spec h0 (rfl : ((k 0 : ℕ) : F) = k 0)
  have hy := addmod_spec h1 (rfl : ((k 1 : ℕ) : F) = k 1)
  have hz := addmod_spec h2 (rfl : ((k 2 : ℕ) : F) = k 2)
  have sx := sboxW_spec hx.2
  have sy := sboxW_spec hy.2
  have sz := sboxW_spec hz.2
  have t := fun (i : Fin 3) => (⟨mulmod_spec sx.2 rfl, mulmod_spec sy.2 rfl, mulmod_spec sz.2 rfl⟩ :
    Rep 1 (evmMulmod (sboxW (evmAddmod (env .s0) (k 0))) (mat i 0)) (_ * (mat i 0 : F)) ∧
    Rep 1 (evmMulmod (sboxW (evmAddmod (env .s1) (k 1))) (mat i 1)) (_ * (mat i 1 : F)) ∧
    Rep 1 (evmMulmod (sboxW (evmAddmod (env .s2) (k 2))) (mat i 2)) (_ * (mat i 2 : F)))
  have r := fun (i : Fin 3) => lzW_spec (t i).1 (t i).2.1
  have r' := fun (i : Fin 3) => lzW_spec (r i).1 (t i).2.2
  simp only [fullStmts, row, sboxBlock, term, exec, Stmt.exec, Safe, Stmt.Safe, List.cons_append,
    List.nil_append, Expr.eval, Expr.Safe, eval_lz, safe_lz, bound_lz,
    Function.update_apply, reduceCtorEq, ite_true, ite_false, sboxW_fold, Inv, true_and, and_true,
    Bool.false_eq_true]
  refine ⟨⟨⟨(r 0).2, (r' 0).2⟩, ⟨(r 1).2, (r' 1).2⟩, (r 2).2, (r' 2).2⟩,
    (r' 0).1.congr ?_, (r' 1).1.congr ?_, (r' 2).1.congr ?_⟩ <;>
    simp [mix, matF, sbox] <;> ring

/-- **Last partial round**: lanes 1 and 2 enter the dense matrix unreduced. -/
theorem last_spec (k : Fin 3 → ℕ) (hk : ∀ i, k i < p) (mat : Fin 3 → Fin 3 → ℕ) (bd : Bounds)
    (env : Env) (σ : State) (h : Inv bd env σ) :
    Safe (lastStmts k mat bd).1 env ∧
      Inv (lastStmts k mat bd).2 (exec (lastStmts k mat bd).1 env)
        (mix (matF mat) ![sbox (σ 0 + k 0), σ 1 + k 1, σ 2 + k 2]) := by
  obtain ⟨h0, h1, h2⟩ := h
  have hx := lzW_spec h0 (rep_lit (hk 0))
  have hy := lzW_spec h1 (rep_lit (hk 1))
  have hz := lzW_spec h2 (rep_lit (hk 2))
  have sx := sboxW_spec hx.1.2
  have t := fun (i : Fin 3) => (⟨mulmod_spec sx.2 rfl, mulmod_spec hy.1.2 rfl, mulmod_spec hz.1.2 rfl⟩ :
    Rep 1 (evmMulmod (sboxW (lzW (env .s0) bd.m0 (k 0) 1)) (mat i 0)) (_ * (mat i 0 : F)) ∧
    Rep 1 (evmMulmod (lzW (env .s1) bd.m1 (k 1) 1) (mat i 1)) (_ * (mat i 1 : F)) ∧
    Rep 1 (evmMulmod (lzW (env .s2) bd.m2 (k 2) 1) (mat i 2)) (_ * (mat i 2 : F)))
  have r := fun (i : Fin 3) => lzW_spec (t i).1 (t i).2.1
  have r' := fun (i : Fin 3) => lzW_spec (r i).1 (t i).2.2
  simp only [lastStmts, row, sboxBlock, term, exec, Stmt.exec, Safe, Stmt.Safe, List.cons_append,
    List.nil_append, Expr.eval, Expr.Safe, eval_lz, safe_lz, bound_lz,
    Function.update_apply, reduceCtorEq, ite_true, ite_false, sboxW_fold, Inv, true_and, and_true,
    Bool.false_eq_true]
  refine ⟨⟨hx.2, hy.2, hz.2, ⟨(r 0).2, (r' 0).2⟩, ⟨(r 1).2, (r' 1).2⟩, (r 2).2, (r' 2).2⟩,
    (r' 0).1.congr ?_, (r' 1).1.congr ?_, (r' 2).1.congr ?_⟩ <;>
    simp [mix, matF, sbox] <;> ring

end Zkapi.Lazy
