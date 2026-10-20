import ZkapiFormal.Yul.Semantics

/-! # The straight-line fragment (a proof device)

The body of the runtime's `permute` uses only blocks, single-variable `let`, assignment, `if` and
calls of the builtins `add addmod mulmod gt calldatasize`. This module is that fragment with a
smaller semantics (scopes, no memory, no functions, no halting), on which the generic simulation
`ZkapiFormal.Yul.Flat` (`execL_flat`) is proved. It is **not** part of what a reader has to
trust: `ZkapiFormal.Yul.Embed` (`execL_unemb`) proves that on this fragment the Yul semantics of
`ZkapiFormal.Yul.Semantics` computes what this one computes, and the theorems about the runtime
are stated in that semantics. -/

namespace Zkapi.Yul.Frag

open Zkapi.Lazy (W)

/-- What the fragment reads from the call: the calldata size. -/
structure Ctx where
  calldatasize : ℕ

/-- Expressions of the fragment. -/
inductive Expr
  | lit (n : Nat)
  | var (x : String)
  | call (f : String) (args : List Expr)
  deriving Repr

/-- Statements of the fragment. -/
inductive Stmt
  | block (ss : List Stmt)
  | letv (x : String) (e : Expr)
  | assign (x : String) (e : Expr)
  | ifs (c : Expr) (body : List Stmt)
  deriving Repr

/-- The fragment's builtins, on words (as in `Zkapi.Yul.builtin`). -/
def builtin (ctx : Ctx) : String → List ℕ → Option ℕ
  | "add", [a, b] => some ((a + b) % W)
  | "addmod", [a, b, m] => some (if m = 0 then 0 else (a + b) % m)
  | "mulmod", [a, b, m] => some (if m = 0 then 0 else (a * b) % m)
  | "gt", [a, b] => some (if b < a then 1 else 0)
  | "shr", [s, v] => some (if s < 256 then v / 2 ^ s else 0)
  | "calldatasize", [] => some ctx.calldatasize
  | _, _ => none

mutual
/-- Evaluate an expression. -/
def evalE (ctx : Ctx) (σ : Scope) : Expr → Option ℕ
  | .lit n => some n
  | .var x => Scope.lookup σ x
  | .call f args =>
    match evalArgs ctx σ args with
    | some vs => builtin ctx f vs
    | none => none

/-- Evaluate arguments, right to left. -/
def evalArgs (ctx : Ctx) (σ : Scope) : List Expr → Option (List ℕ)
  | [] => some []
  | e :: es =>
    match evalArgs ctx σ es with
    | some vs =>
      match evalE ctx σ e with
      | some v => some (v :: vs)
      | none => none
    | none => none
end

mutual
/-- Execute a statement. -/
def execS (ctx : Ctx) (σ : Scope) : Stmt → Option Scope
  | .block ss => (execL ctx σ ss).map (exitBlock σ)
  | .letv x e =>
    match evalE ctx σ e with
    | some v => if (Scope.lookup σ x).isSome then none else some ((x, v) :: σ)
    | none => none
  | .assign x e =>
    match evalE ctx σ e with
    | some v => Scope.set σ x v
    | none => none
  | .ifs c body =>
    match evalE ctx σ c with
    | some 0 => some σ
    | some _ => (execL ctx σ body).map (exitBlock σ)
    | none => none

/-- Execute statements in order. -/
def execL (ctx : Ctx) (σ : Scope) : List Stmt → Option Scope
  | [] => some σ
  | s :: ss =>
    match execS ctx σ s with
    | some σ' => execL ctx σ' ss
    | none => none
end

end Zkapi.Yul.Frag
