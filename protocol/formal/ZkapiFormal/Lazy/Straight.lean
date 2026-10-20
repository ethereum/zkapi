import ZkapiFormal.Lazy.Words

/-! # Straight-line arithmetic programs

A minimal expression language for the body of the unrolled permutation: literals, the variables
`s0 s1 s2 x y z q`, `add`, `addmod(·, ·, P)` and `mulmod(·, ·, P)`; statements `let v := e`,
`v := e` and block braces. This is not EVM semantics (no stack, memory or gas): `Expr.eval` is
plain arithmetic with the EVM's results for these three operations (`ADD` wraps modulo `2^256`),
and `Expr.Safe` records that every `ADD`'s exact sum stays below `2^256`.

Blocks only scope `let` bindings. `exec` runs the statements in order on one environment and
treats the braces as no-ops; `ZkapiFormal.Yul.Flat` proves that Yul's scoped semantics computes
the same values for every well-scoped program (no read or assignment of a name that is not
visible, no redeclaration), and the kernel checks that the parsed Yul source is well scoped
(`ZkapiFormal.Yul.Permute`). -/

namespace Zkapi.Lazy

inductive Var
  | s0 | s1 | s2 | x | y | z | q
  deriving DecidableEq, Repr

inductive Expr
  | lit (n : ℕ)
  | var (v : Var)
  | add (a b : Expr)
  | addmod (a b : Expr)
  | mulmod (a b : Expr)
  deriving Repr, DecidableEq

inductive Stmt
  | letv (v : Var) (e : Expr)
  | assign (v : Var) (e : Expr)
  | openB
  | closeB
  deriving Repr, DecidableEq

/-- Variable values. -/
abbrev Env := Var → ℕ

/-- Evaluation, with the EVM's `ADD` (wrapping), `ADDMOD` and `MULMOD` (modulus `p`). -/
def Expr.eval (env : Env) : Expr → ℕ
  | .lit n => n
  | .var v => env v
  | .add a b => evmAdd (a.eval env) (b.eval env)
  | .addmod a b => evmAddmod (a.eval env) (b.eval env)
  | .mulmod a b => evmMulmod (a.eval env) (b.eval env)

/-- Every `ADD` in the expression adds two values whose exact sum is below `2^256`. -/
def Expr.Safe (env : Env) : Expr → Prop
  | .lit _ => True
  | .var _ => True
  | .add a b => a.Safe env ∧ b.Safe env ∧ a.eval env + b.eval env < W
  | .addmod a b => a.Safe env ∧ b.Safe env
  | .mulmod a b => a.Safe env ∧ b.Safe env

def Stmt.exec (env : Env) : Stmt → Env
  | .letv v e => Function.update env v (e.eval env)
  | .assign v e => Function.update env v (e.eval env)
  | .openB => env
  | .closeB => env

def Stmt.Safe (env : Env) : Stmt → Prop
  | .letv _ e => e.Safe env
  | .assign _ e => e.Safe env
  | .openB => True
  | .closeB => True

/-- Execute statements in order. -/
def exec : List Stmt → Env → Env
  | [], env => env
  | s :: ss, env => exec ss (s.exec env)

/-- Every statement is `Safe` in the environment it executes in. -/
def Safe : List Stmt → Env → Prop
  | [], _ => True
  | s :: ss, env => s.Safe env ∧ Safe ss (s.exec env)

theorem exec_append (a b : List Stmt) (env : Env) : exec (a ++ b) env = exec b (exec a env) := by
  induction a generalizing env with
  | nil => rfl
  | cons s ss ih => exact ih _

theorem safe_append (a b : List Stmt) (env : Env) :
    Safe (a ++ b) env ↔ Safe a env ∧ Safe b (exec a env) := by
  induction a generalizing env with
  | nil => simp [Safe, exec]
  | cons s ss ih => simp [Safe, exec, ih, and_assoc]

/-! ## Every value is a word

With word-sized inputs and literals, every value the program computes is below `2^256`, so the
natural-number evaluation above is the EVM's word arithmetic. -/

/-- Every literal of the expression is below `b`. -/
def Expr.litsBelow (b : ℕ) : Expr → Bool
  | .lit n => decide (n < b)
  | .var _ => true
  | .add x y => x.litsBelow b && y.litsBelow b
  | .addmod x y => x.litsBelow b && y.litsBelow b
  | .mulmod x y => x.litsBelow b && y.litsBelow b

def Stmt.litsBelow (b : ℕ) : Stmt → Bool
  | .letv _ e => e.litsBelow b
  | .assign _ e => e.litsBelow b
  | .openB => true
  | .closeB => true

theorem Expr.eval_lt_W (env : Env) (h : ∀ v, env v < W) :
    ∀ e : Expr, e.litsBelow W = true → e.eval env < W
  | .lit n, hl => by simpa [Expr.litsBelow, Expr.eval] using hl
  | .var v, _ => h v
  | .add _ _, _ => Nat.mod_lt _ (by decide)
  | .addmod _ _, _ => lt_trans (evmAddmod_lt _ _) (lt_trans (by decide) five_p_lt_W)
  | .mulmod _ _, _ => lt_trans (evmMulmod_lt _ _) (lt_trans (by decide) five_p_lt_W)

theorem exec_lt_W : ∀ (ss : List Stmt) (env : Env), (∀ v, env v < W) →
    (∀ s ∈ ss, s.litsBelow W = true) → ∀ v, exec ss env v < W
  | [], _, h, _ => h
  | s :: ss, env, h, hs => by
    apply exec_lt_W ss (s.exec env) _ (fun t ht => hs t (List.mem_cons_of_mem _ ht))
    have hl := hs s List.mem_cons_self
    cases s with
    | letv v e =>
      intro w
      simp only [Stmt.exec, Function.update_apply]
      split_ifs
      · exact Expr.eval_lt_W env h e hl
      · exact h w
    | assign v e =>
      intro w
      simp only [Stmt.exec, Function.update_apply]
      split_ifs
      · exact Expr.eval_lt_W env h e hl
      · exact h w
    | openB => exact h
    | closeB => exact h

end Zkapi.Lazy
