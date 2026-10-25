import ZkapiFormal.Yul.Syntax
import ZkapiFormal.Lazy.Words

/-! # Semantics of the Yul fragment

A big-step semantics of `ZkapiFormal.Yul.Syntax`'s fragment, following the Yul specification
(<https://docs.soliditylang.org/en/latest/yul.html#formal-specification>) and the EVM dialect's
builtins. This is the one semantics the theorems about the runtime are stated in.

* The state is the visible variables and the memory. Variables hold words; a scope lists the
  visible ones, innermost first. Memory is byte-addressed (`Mem`), any initial contents.
* `let x₁, …, xₙ := e` evaluates `e` and declares the names; declaring a visible name fails (Yul
  rejects shadowing at compile time), so does reading or assigning an undeclared name.
  `x₁, …, xₙ := e` assigns them.
* A block's declarations go out of scope when it ends (`exitBlock`), and so do the functions it
  defines.
* `if c { … }` runs its block iff `c` is not zero. `switch` runs the first `case` arm whose literal
  equals the value, else the `default` arm if any.
* `for { init } cond { post } { body }` runs `init` in a scope that lasts for the loop, then, while
  `cond` is not zero, the block `body` and then the block `post`; the loop's declarations go out of
  scope at its end. Yul's loop need not terminate: the EVM bounds it by gas. Here it runs at most
  `loopFuel = 2^64` iterations (more than any transaction's gas pays for) and has no result beyond.
  So a result of this semantics is the result of the code; the theorems about the runtime prove
  results, i.e. that the run terminates.
* Expression statements: `mstore(p, v)` writes the 32 bytes of `v` big-endian at `p`;
  `return(p, n)` and `revert(p, n)` halt with the `n` bytes of memory at `p`.
* The pure builtins (`builtin`) compute the EVM results on words: `add`, `sub` and `shl` wrap
  modulo `2^256`; `addmod` and `mulmod` take the exact sum or product modulo the third argument
  (0 if it is 0); `lt`, `gt`, `slt` (two's complement), `eq`, `iszero`, `and`, `shr`;
  `calldatasize`, `calldataload(i)` (the 32 calldata bytes at `i`, big-endian, zero past the end)
  and `callvalue` read the call.
* Functions: `function f(ps) -> rs { body }` binds `f` for the statements after it in its block.
  Its meaning is computed at its definition (`Fn`), so the semantics stays structurally recursive
  and the kernel can run it. A call runs the body in a fresh scope holding only the parameters and
  the return variables (initially 0), with the caller's memory and the functions visible at the
  definition, and returns the return variables' final values. Yul also allows a call before the
  definition and recursion; such a call has no result here (the runtime makes neither). A call of
  a user function is evaluated as the whole right-hand side of a `let` or an assignment, or as an
  expression statement; nested inside another call's arguments it has no result here (the
  runtime nests none).

Yul evaluates a call's arguments right to left; the builtins here have no side effects, so the
order does not change any result. `evalArgs` follows it anyway.

The semantics has no gas: a result is what the code computes when it does not run out of gas. -/

namespace Zkapi.Yul

open Zkapi.Lazy (W)

/-! ## Scopes -/

/-- Visible variables and their values, innermost first. -/
abbrev Scope := List (String × ℕ)

/-- The value of a visible variable. -/
def Scope.lookup : Scope → String → Option ℕ
  | [], _ => none
  | (y, v) :: σ, x => if x = y then some v else Scope.lookup σ x

/-- Assign to a visible variable (the innermost binding of that name). -/
def Scope.set : Scope → String → ℕ → Option Scope
  | [], _, _ => none
  | (y, w) :: σ, x, v =>
    if x = y then some ((y, v) :: σ) else (Scope.set σ x v).map ((y, w) :: ·)

/-- The names in scope, innermost first. -/
def Scope.names (σ : Scope) : List String := σ.map Prod.fst

/-- Leaving a block that started with the scope `σ`: what the block declared is dropped. -/
def exitBlock (σ σ' : Scope) : Scope := σ'.drop (σ'.length - σ.length)

/-! ## The call and memory -/

/-- What the code reads from the call: the calldata (bytes) and the call value. -/
structure Ctx where
  calldata : List ℕ
  callvalue : ℕ := 0

/-- Byte `i` of the calldata, 0 past its end. -/
def cdByte (cd : List ℕ) (i : ℕ) : ℕ := cd.getD i 0

/-- The 32 bytes at `i`, big-endian. -/
def word32 (f : ℕ → ℕ) (i : ℕ) : ℕ := (List.range 32).foldl (fun acc k => acc * 256 + f (i + k)) 0

/-- `calldataload(i)`: the 32 calldata bytes at `i`, big-endian, zero past the end. -/
def cdWord (cd : List ℕ) (i : ℕ) : ℕ := word32 (cdByte cd) i

/-- Memory, byte by byte. -/
abbrev Mem := ℕ → ℕ

/-- `mstore(p, v)`: the 32 bytes of `v`, big-endian, at `p`. -/
def mstore (m : Mem) (p v : ℕ) : Mem := fun j =>
  if p ≤ j ∧ j < p + 32 then v / 256 ^ (31 - (j - p)) % 256 else m j

/-- The `n` bytes of memory at `p`. -/
def bytesOf (m : Mem) (p n : ℕ) : List ℕ := (List.range n).map fun k => m (p + k)

/-- A word as a two's-complement integer. -/
def toInt (a : ℕ) : ℤ := if a < 2 ^ 255 then a else (a : ℤ) - 2 ^ 256

/-- The pure builtins, on words. -/
def builtin (ctx : Ctx) : String → List ℕ → Option ℕ
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
  | "shl", [s, v] => some (if s < 256 then v * 2 ^ s % W else 0)
  | "calldatasize", [] => some ctx.calldata.length
  | "calldataload", [i] => some (cdWord ctx.calldata i)
  | "callvalue", [] => some ctx.callvalue
  | _, _ => none

/-! ## Statements -/

/-- How a run halts: `return` or `revert` with the bytes they pass. -/
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
/-- Evaluate an expression of builtins. -/
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

/-- The values of a right-hand side: a call of a function in scope, or one pure value. -/
def rhs (ctx : Ctx) (fs : Funs) (st : St) : Expr → Option (Halt ⊕ (List ℕ × Mem))
  | .call f args =>
    match fs.find f with
    | some fn =>
      match evalArgs ctx st.scope args with
      | some vs => fn vs st.mem
      | none => none
    | none => (evalE ctx st.scope (.call f args)).map fun v => .inr ([v], st.mem)
  | e => (evalE ctx st.scope e).map fun v => .inr ([v], st.mem)

/-- Declare names (fails on a visible name, or a count mismatch). -/
def declare (σ : Scope) : List String → List ℕ → Option Scope
  | [], [] => some σ
  | x :: xs, v :: vs => if (Scope.lookup σ x).isSome then none else declare ((x, v) :: σ) xs vs
  | _, _ => none

/-- Assign names, in order (fails on an undeclared name, or a count mismatch). -/
def assignAll (σ : Scope) : List String → List ℕ → Option Scope
  | [], [] => some σ
  | x :: xs, v :: vs =>
    match Scope.set σ x v with
    | some σ' => assignAll σ' xs vs
    | none => none
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

/-- The iteration bound of a `for` loop. -/
def loopFuel : ℕ := 2 ^ 64

/-- At most `n` iterations of a loop with condition `cond` and iteration `step` (the body, then
the post block); no result if the bound is reached. -/
def loop (cond : St → Option ℕ) (step : St → Option (Halt ⊕ St)) : ℕ → St → Option (Halt ⊕ St)
  | 0, _ => none
  | n + 1, st =>
    match cond st with
    | some 0 => some (.inr st)
    | some _ =>
      match step st with
      | some (.inr st') => loop cond step n st'
      | some (.inl h) => some (.inl h)
      | none => none
    | none => none

mutual
/-- Execute a statement. -/
def execS (ctx : Ctx) (fs : Funs) (st : St) : Stmt → Option Out
  | .block ss => closeBlock st fs (execL ctx fs st ss)
  | .letv xs e =>
    match rhs ctx fs st e with
    | some (.inr (vs, m)) => (declare st.scope xs vs).map fun σ => .inr (⟨σ, m⟩, fs)
    | some (.inl h) => some (.inl h)
    | none => none
  | .assign xs e =>
    match rhs ctx fs st e with
    | some (.inr (vs, m)) => (assignAll st.scope xs vs).map fun σ => .inr (⟨σ, m⟩, fs)
    | some (.inl h) => some (.inl h)
    | none => none
  | .ifs c body =>
    match evalE ctx st.scope c with
    | some 0 => some (.inr (st, fs))
    | some _ => closeBlock st fs (execL ctx fs st body)
    | none => none
  | .switch c arms =>
    match evalE ctx st.scope c with
    | some v => execArms ctx fs st v arms
    | none => none
  | .arm _ _ => none
  | .forLoop init c post body =>
    match execL ctx fs st init with
    | some (.inr (st₁, fs₁)) =>
      match loop (fun s => evalE ctx s.scope c)
          (fun s =>
            match closeBlock s fs₁ (execL ctx fs₁ s body) with
            | some (.inr (s', _)) =>
              match closeBlock s' fs₁ (execL ctx fs₁ s' post) with
              | some (.inr (s'', _)) => some (.inr s'')
              | some (.inl h) => some (.inl h)
              | none => none
            | some (.inl h) => some (.inl h)
            | none => none)
          loopFuel st₁ with
      | some (.inr st₂) => some (.inr (⟨exitBlock st.scope st₂.scope, st₂.mem⟩, fs))
      | some (.inl h) => some (.inl h)
      | none => none
    | some (.inl h) => some (.inl h)
    | none => none
  | .exprStmt (.call f args) =>
    match evalArgs ctx st.scope args with
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

/-- Execute statements in order. -/
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

/-- Run an assembly block's statements from an empty scope, with memory `m`. -/
def run (ctx : Ctx) (m : Mem) (ss : List Stmt) : Option Out := execL ctx [] ⟨[], m⟩ ss

/-- **A contract whose code is `fallback() external { assembly ("memory-safe") { B } }`**, as
solc compiles it (legacy pipeline): the prologue `mstore(0x40, 0x80)`, the rejection of call value
(`revert(0, 0)`: the fallback is not `payable`), then the block; if the block ends without
halting, the call stops with no return data. This models solc's code around the block; it is
trusted, like the semantics (`protocol/formal/README.md`, Trust boundary). -/
def fallbackRun (ctx : Ctx) (m : Mem) (ss : List Stmt) : Option Halt :=
  if ctx.callvalue ≠ 0 then some (.rev [])
  else
    match run ctx (mstore m 0x40 0x80) ss with
    | some (.inl h) => some h
    | some (.inr _) => some (.ret [])
    | none => none

end Zkapi.Yul
