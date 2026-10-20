import ZkapiPoC.Syntax
import ZkapiFormal.Yul.Fragment

/-! # Proof of concept: semantics of the larger fragment

The state is the visible variables and the memory (bytes). A statement either continues or halts
with `return(p, n)` / `revert(p, n)` and the `n` bytes of memory at `p`. On top of
`ZkapiFormal.Yul.Semantics`:

* builtins that read the call: `calldataload(i)` is the 32 bytes of calldata at `i`, big-endian,
  zero past the end; `calldatasize()`; `mload(p)`; and `sub`, `lt`, `slt`, `eq`, `iszero`, `and`;
* effects as expression statements: `mstore(p, v)` writes the 32 bytes of `v` big-endian at `p`;
  `return` and `revert` halt;
* `switch` runs the first `case` arm whose literal equals the value, else the `default` arm if any;
* functions: `function f(ps) -> rs { body }` binds `f` for the statements after it in its block.
  Its meaning is computed at its definition (`Fn`), so the semantics stays structurally recursive
  and the kernel can run it. A call runs the body in a fresh scope holding only the parameters and
  the return variables (initially 0), with the caller's memory, and returns the return variables'
  final values. The restriction of this PoC: a function is called only after its definition and
  not recursively (Yul allows both).

`Zkapi.PoC.Embed` proves that on the fragment of `ZkapiFormal.Yul` this semantics computes what
`Zkapi.Yul.Frag.execS` computes, so the permutation theorems carry over. -/

namespace Zkapi.PoC

open Zkapi.Yul (Scope exitBlock)
open Zkapi.Lazy (W)

structure Ctx where
  calldata : List ℕ

/-- Byte `i` of the calldata, 0 past its end. -/
def cdByte (cd : List ℕ) (i : ℕ) : ℕ := cd.getD i 0

/-- The 32 bytes at `i`, big-endian. -/
def word32 (f : ℕ → ℕ) (i : ℕ) : ℕ := (List.range 32).foldl (fun acc k => acc * 256 + f (i + k)) 0

/-- Memory, byte by byte. -/
abbrev Mem := ℕ → ℕ

/-- `mstore(p, v)`: the 32 bytes of `v`, big-endian, at `p`. -/
def mstore (m : Mem) (p v : ℕ) : Mem := fun j =>
  if p ≤ j ∧ j < p + 32 then v / 256 ^ (31 - (j - p)) % 256 else m j

/-- The `n` bytes of memory at `p`. -/
def bytesOf (m : Mem) (p n : ℕ) : List ℕ := (List.range n).map fun k => m (p + k)

/-- A word as a two's-complement integer. -/
def toInt (a : ℕ) : ℤ := if a < 2 ^ 255 then a else (a : ℤ) - 2 ^ 256

/-- The pure builtins. -/
def builtin (ctx : Ctx) (m : Mem) : String → List ℕ → Option ℕ
  | "add", [a, b] => some ((a + b) % W)
  | "sub", [a, b] => some ((a + (W - b % W)) % W)
  | "addmod", [a, b, n] => some (if n = 0 then 0 else (a + b) % n)
  | "mulmod", [a, b, n] => some (if n = 0 then 0 else (a * b) % n)
  | "lt", [a, b] => some (if a < b then 1 else 0)
  | "gt", [a, b] => some (if b < a then 1 else 0)
  | "slt", [a, b] => some (if toInt a < toInt b then 1 else 0)
  | "eq", [a, b] => some (if a = b then 1 else 0)
  | "iszero", [a] => some (if a = 0 then 1 else 0)
  | "and", [a, b] => some (a &&& b)
  | "shr", [s, v] => some (if s < 256 then v / 2 ^ s else 0)
  | "calldatasize", [] => some ctx.calldata.length
  | "calldataload", [i] => some (word32 (cdByte ctx.calldata) i)
  | "mload", [p] => some (word32 m p)
  | _, _ => none

inductive Halt
  | ret (data : List ℕ)
  | rev (data : List ℕ)
  deriving DecidableEq, Repr

structure St where
  scope : Scope
  mem : Mem

/-- A function's meaning: arguments and memory to a halt, or to return values and memory. -/
abbrev Fn := List ℕ → Mem → Option (Halt ⊕ (List ℕ × Mem))

/-- The functions in scope, latest first. -/
abbrev Funs := List (String × Fn)

def Funs.find : Funs → String → Option Fn
  | [], _ => none
  | (g, fn) :: fs, f => if f = g then some fn else Funs.find fs f

/-- After a statement: halted, or the state and the functions in scope. -/
abbrev Out := Halt ⊕ (St × Funs)

mutual
def evalE (ctx : Ctx) (m : Mem) (σ : Scope) : Expr → Option ℕ
  | .lit n => some n
  | .var x => Scope.lookup σ x
  | .call f args =>
    match evalArgs ctx m σ args with
    | some vs => builtin ctx m f vs
    | none => none

def evalArgs (ctx : Ctx) (m : Mem) (σ : Scope) : List Expr → Option (List ℕ)
  | [] => some []
  | e :: es =>
    match evalArgs ctx m σ es with
    | some vs =>
      match evalE ctx m σ e with
      | some v => some (v :: vs)
      | none => none
    | none => none
end

/-- The values of a right-hand side: a call of a function in scope, or one pure value. -/
def rhs (ctx : Ctx) (fs : Funs) (st : St) : Expr → Option (Halt ⊕ (List ℕ × Mem))
  | .call f args =>
    match fs.find f with
    | some fn =>
      match evalArgs ctx st.mem st.scope args with
      | some vs => fn vs st.mem
      | none => none
    | none => (evalE ctx st.mem st.scope (.call f args)).map fun v => .inr ([v], st.mem)
  | e => (evalE ctx st.mem st.scope e).map fun v => .inr ([v], st.mem)

/-- Declare names (fails on a visible name, or a count mismatch). -/
def declare (σ : Scope) : List String → List ℕ → Option Scope
  | [], [] => some σ
  | x :: xs, v :: vs => if (Scope.lookup σ x).isSome then none else declare ((x, v) :: σ) xs vs
  | _, _ => none

/-- The fresh scope of a call. -/
def frame (ps rs : List String) (vs : List ℕ) : Option Scope :=
  if ps.length = vs.length then some ((ps.zip vs) ++ rs.map fun r => (r, 0)) else none

/-- Leaving a block: its variables and functions go out of scope. -/
def closeBlock (st : St) (fs : Funs) : Option Out → Option Out
  | some (.inr (st', _)) => some (.inr (⟨exitBlock st.scope st'.scope, st'.mem⟩, fs))
  | o => o

/-- Read the return variables. -/
def results (σ : Scope) : List String → Option (List ℕ)
  | [] => some []
  | r :: rs =>
    match Scope.lookup σ r, results σ rs with
    | some v, some vs => some (v :: vs)
    | _, _ => none

mutual
def execS (ctx : Ctx) (fs : Funs) (st : St) : Stmt → Option Out
  | .block ss => closeBlock st fs (execL ctx fs st ss)
  | .letv xs e =>
    match rhs ctx fs st e with
    | some (.inr (vs, m)) => (declare st.scope xs vs).map fun σ => .inr (⟨σ, m⟩, fs)
    | some (.inl h) => some (.inl h)
    | none => none
  | .assign x e =>
    match rhs ctx fs st e with
    | some (.inr ([v], m)) => (Scope.set st.scope x v).map fun σ => .inr (⟨σ, m⟩, fs)
    | some (.inl h) => some (.inl h)
    | _ => none
  | .ifs c body =>
    match evalE ctx st.mem st.scope c with
    | some 0 => some (.inr (st, fs))
    | some _ => closeBlock st fs (execL ctx fs st body)
    | none => none
  | .switch c arms =>
    match evalE ctx st.mem st.scope c with
    | some v => execArms ctx fs st v arms
    | none => none
  | .arm _ _ => none
  | .exprStmt (.call f args) =>
    match evalArgs ctx st.mem st.scope args with
    | none => none
    | some vs =>
      if f = "mstore" then
        match vs with
        | [p, v] => some (.inr (⟨st.scope, mstore st.mem p v⟩, fs))
        | _ => none
      else if f = "return" then
        match vs with
        | [p, n] => some (.inl (.ret (bytesOf st.mem p n)))
        | _ => none
      else if f = "revert" then
        match vs with
        | [p, n] => some (.inl (.rev (bytesOf st.mem p n)))
        | _ => none
      else
        match fs.find f with
        | some fn =>
          match fn vs st.mem with
          | some (.inr ([], m)) => some (.inr (⟨st.scope, m⟩, fs))
          | some (.inl h) => some (.inl h)
          | _ => none
        | none => none
  | .exprStmt _ => none
  | .funDef f ps rs body =>
    some (.inr (st, (f, fun vs m =>
      match frame ps rs vs with
      | none => none
      | some σ =>
        match execL ctx fs ⟨σ, m⟩ body with
        | some (.inr (st', _)) => (results st'.scope rs).map fun outs => .inr (outs, st'.mem)
        | some (.inl h) => some (.inl h)
        | none => none) :: fs))

def execL (ctx : Ctx) (fs : Funs) (st : St) : List Stmt → Option Out
  | [] => some (.inr (st, fs))
  | s :: ss =>
    match execS ctx fs st s with
    | some (.inr (st', fs')) => execL ctx fs' st' ss
    | o => o

/-- The first arm whose literal is `v`, else the default arm; none: no effect. -/
def execArms (ctx : Ctx) (fs : Funs) (st : St) (v : ℕ) : List Stmt → Option Out
  | [] => some (.inr (st, fs))
  | .arm (some k) body :: arms =>
    if k = v then closeBlock st fs (execL ctx fs st body) else execArms ctx fs st v arms
  | .arm none body :: _ => closeBlock st fs (execL ctx fs st body)
  | _ :: _ => none
end

/-- Run an assembly block's statements from an empty scope. -/
def run (ctx : Ctx) (m : Mem) (ss : List Stmt) : Option Out := execL ctx [] ⟨[], m⟩ ss

end Zkapi.PoC
