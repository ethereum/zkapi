import ZkapiFormal.Yul.Semantics

/-! # Generic execution lemmas

Equations of the Yul semantics for each kind of statement, with the values involved as
hypotheses, and the bounded loop lemma (`loop_count`, `exec_for`). The proofs about the runtime
instantiate them with `rw`, so the semantics is never unfolded on the runtime's concrete code (or
its large literals); only these generic statements are. -/

namespace Zkapi.Yul

open Zkapi.Lazy (W)

variable {ctx : Ctx} {fs : Funs} {st : St}

/-! ## Builtins -/

@[simp] theorem builtin_add (a b : ℕ) : builtin ctx "add" [a, b] = some ((a + b) % W) := rfl
@[simp] theorem builtin_sub (a b : ℕ) : builtin ctx "sub" [a, b] = some ((a + (W - b % W)) % W) := rfl
@[simp] theorem builtin_addmod (a b n : ℕ) :
    builtin ctx "addmod" [a, b, n] = some (if n = 0 then 0 else (a + b) % n) := rfl
@[simp] theorem builtin_mulmod (a b n : ℕ) :
    builtin ctx "mulmod" [a, b, n] = some (if n = 0 then 0 else (a * b) % n) := rfl
@[simp] theorem builtin_lt (a b : ℕ) : builtin ctx "lt" [a, b] = some (if a < b then 1 else 0) := rfl
@[simp] theorem builtin_gt (a b : ℕ) : builtin ctx "gt" [a, b] = some (if b < a then 1 else 0) := rfl
@[simp] theorem builtin_slt (a b : ℕ) :
    builtin ctx "slt" [a, b] = some (if toInt a < toInt b then 1 else 0) := rfl
@[simp] theorem builtin_eq (a b : ℕ) : builtin ctx "eq" [a, b] = some (if a = b then 1 else 0) := rfl
@[simp] theorem builtin_iszero (a : ℕ) : builtin ctx "iszero" [a] = some (if a = 0 then 1 else 0) := rfl
@[simp] theorem builtin_and (a b : ℕ) : builtin ctx "and" [a, b] = some (a &&& b) := rfl
@[simp] theorem builtin_shr (s v : ℕ) :
    builtin ctx "shr" [s, v] = some (if s < 256 then v / 2 ^ s else 0) := rfl
@[simp] theorem builtin_shl (s v : ℕ) :
    builtin ctx "shl" [s, v] = some (if s < 256 then v * 2 ^ s % W else 0) := rfl
@[simp] theorem builtin_calldatasize : builtin ctx "calldatasize" [] = some ctx.calldata.length := rfl
@[simp] theorem builtin_calldataload (i : ℕ) :
    builtin ctx "calldataload" [i] = some (cdWord ctx.calldata i) := rfl

/-! ## Expressions -/

@[simp] theorem evalE_lit (σ : Scope) (n : ℕ) : evalE ctx σ (.lit n) = some n := by rw [evalE]
@[simp] theorem evalE_var (σ : Scope) (x : String) : evalE ctx σ (.var x) = Scope.lookup σ x := by
  rw [evalE]
theorem evalE_call (σ : Scope) (f : String) (args : List Expr) :
    evalE ctx σ (.call f args) = (evalArgs ctx σ args).bind (builtin ctx f) := by
  rw [evalE]; cases evalArgs ctx σ args <;> rfl
@[simp] theorem evalArgs_nil (σ : Scope) : evalArgs ctx σ [] = some [] := by rw [evalArgs]
theorem evalArgs_cons (σ : Scope) (e : Expr) (es : List Expr) :
    evalArgs ctx σ (e :: es) =
      (evalArgs ctx σ es).bind fun vs => (evalE ctx σ e).map fun v => v :: vs := by
  rw [evalArgs]
  cases evalArgs ctx σ es <;> cases evalE ctx σ e <;> rfl

/-- One-argument call of a builtin. -/
theorem evalE_call1 {σ : Scope} {f : String} {a : Expr} {va v : ℕ} (ha : evalE ctx σ a = some va)
    (hf : builtin ctx f [va] = some v) : evalE ctx σ (.call f [a]) = some v := by
  simp [evalE_call, evalArgs_cons, ha, hf]

/-- Two-argument call of a builtin. -/
theorem evalE_call2 {σ : Scope} {f : String} {a b : Expr} {va vb v : ℕ}
    (ha : evalE ctx σ a = some va) (hb : evalE ctx σ b = some vb)
    (hf : builtin ctx f [va, vb] = some v) : evalE ctx σ (.call f [a, b]) = some v := by
  simp [evalE_call, evalArgs_cons, ha, hb, hf]

/-- Three-argument call of a builtin. -/
theorem evalE_call3 {σ : Scope} {f : String} {a b c : Expr} {va vb vc v : ℕ}
    (ha : evalE ctx σ a = some va) (hb : evalE ctx σ b = some vb) (hc : evalE ctx σ c = some vc)
    (hf : builtin ctx f [va, vb, vc] = some v) : evalE ctx σ (.call f [a, b, c]) = some v := by
  simp [evalE_call, evalArgs_cons, ha, hb, hc, hf]

/-- `calldatasize()`. -/
theorem evalE_calldatasize (σ : Scope) :
    evalE ctx σ (.call "calldatasize" []) = some ctx.calldata.length := by
  simp [evalE_call]

/-- `calldataload(lit)`. -/
theorem evalE_calldataload_lit (σ : Scope) (i : ℕ) :
    evalE ctx σ (.call "calldataload" [.lit i]) = some (cdWord ctx.calldata i) :=
  evalE_call1 (evalE_lit σ i) (builtin_calldataload i)

/-! ## Statement lists -/

theorem execL_nil : execL ctx fs st [] = some (.inr (st, fs)) := by rw [execL]

theorem execL_cons (s : Stmt) (ss : List Stmt) :
    execL ctx fs st (s :: ss) =
      match execS ctx fs st s with
      | some (.inr (st', fs')) => execL ctx fs' st' ss
      | o => o := by
  rw [execL]; rfl

theorem execL_cons_inr {s : Stmt} {ss : List Stmt} {st' : St} {fs' : Funs}
    (h : execS ctx fs st s = some (.inr (st', fs'))) :
    execL ctx fs st (s :: ss) = execL ctx fs' st' ss := by
  rw [execL_cons, h]

theorem execL_cons_halt {s : Stmt} {ss : List Stmt} {hl : Halt}
    (h : execS ctx fs st s = some (.inl hl)) : execL ctx fs st (s :: ss) = some (.inl hl) := by
  rw [execL_cons, h]

theorem execL_singleton (s : Stmt) : execL ctx fs st [s] = execS ctx fs st s := by
  rw [execL_cons]
  rcases h : execS ctx fs st s with _ | (_ | ⟨st', fs'⟩) <;> simp [execL_nil]

theorem execL_append (xs ys : List Stmt) :
    execL ctx fs st (xs ++ ys) =
      match execL ctx fs st xs with
      | some (.inr (st', fs')) => execL ctx fs' st' ys
      | o => o := by
  induction xs generalizing fs st with
  | nil => simp [execL_nil]
  | cons x xs ih =>
    simp only [List.cons_append, execL_cons]
    cases h : execS ctx fs st x with
    | none => rfl
    | some o =>
      cases o with
      | inl hh => rfl
      | inr p => exact ih

/-! ## Statements -/

theorem rhs_pure {e : Expr} {v : ℕ} (hfind : ∀ f args, e = .call f args → fs.find f = none)
    (h : evalE ctx st.scope e = some v) : rhs ctx fs st e = some (.inr ([v], st.mem)) := by
  cases e with
  | call f args => simp [rhs, hfind f args rfl, h]
  | lit n => simp [rhs, h]
  | var x => simp [rhs, h]

theorem rhs_fn {f : String} {args : List Expr} {fn : Fn} {vs : List ℕ} (hf : fs.find f = some fn)
    (ha : evalArgs ctx st.scope args = some vs) : rhs ctx fs st (.call f args) = fn vs st.mem := by
  simp [rhs, hf, ha]

theorem exec_letv {xs : List String} {e : Expr} {vs : List ℕ} {m : Mem} {σ : Scope}
    (h : rhs ctx fs st e = some (.inr (vs, m))) (hd : declare st.scope xs vs = some σ) :
    execS ctx fs st (.letv xs e) = some (.inr (⟨σ, m⟩, fs)) := by
  rw [execS, h]; simp [hd]

theorem exec_assign {xs : List String} {e : Expr} {vs : List ℕ} {m : Mem} {σ : Scope}
    (h : rhs ctx fs st e = some (.inr (vs, m))) (ha : assignAll st.scope xs vs = some σ) :
    execS ctx fs st (.assign xs e) = some (.inr (⟨σ, m⟩, fs)) := by
  rw [execS, h]; simp [ha]

theorem exec_block (ss : List Stmt) :
    execS ctx fs st (.block ss) = closeBlock st fs (execL ctx fs st ss) := by
  rw [execS]

theorem exec_if_zero {c : Expr} {body : List Stmt} (h : evalE ctx st.scope c = some 0) :
    execS ctx fs st (.ifs c body) = some (.inr (st, fs)) := by
  rw [execS, h]; rfl

theorem exec_if_ne {c : Expr} {body : List Stmt} {v : ℕ} (h : evalE ctx st.scope c = some v)
    (hv : v ≠ 0) : execS ctx fs st (.ifs c body) = closeBlock st fs (execL ctx fs st body) := by
  rw [execS, h]
  obtain ⟨k, rfl⟩ := Nat.exists_eq_succ_of_ne_zero hv
  rfl

theorem exec_switch {c : Expr} {arms : List Stmt} {v : ℕ} (h : evalE ctx st.scope c = some v) :
    execS ctx fs st (.switch c arms) = execArms ctx fs st v arms := by
  rw [execS, h]

theorem execArms_case (v k : ℕ) (body arms : List Stmt) :
    execArms ctx fs st v (.arm (some k) body :: arms) =
      if k = v then closeBlock st fs (execL ctx fs st body) else execArms ctx fs st v arms := by
  rw [execArms]

theorem execArms_default (v : ℕ) (body arms : List Stmt) :
    execArms ctx fs st v (.arm none body :: arms) = closeBlock st fs (execL ctx fs st body) := by
  rw [execArms]

theorem exec_mstore {p e : Expr} {a b : ℕ} (hp : evalE ctx st.scope p = some a)
    (he : evalE ctx st.scope e = some b) :
    execS ctx fs st (.exprStmt (.call "mstore" [p, e])) =
      some (.inr (⟨st.scope, mstore st.mem a b⟩, fs)) := by
  rw [execS]; simp [evalArgs_cons, hp, he]

theorem exec_return {p e : Expr} {a b : ℕ} (hp : evalE ctx st.scope p = some a)
    (he : evalE ctx st.scope e = some b) :
    execS ctx fs st (.exprStmt (.call "return" [p, e])) = some (.inl (.ret (bytesOf st.mem a b))) := by
  rw [execS]; simp [evalArgs_cons, hp, he]

theorem exec_revert {p e : Expr} {a b : ℕ} (hp : evalE ctx st.scope p = some a)
    (he : evalE ctx st.scope e = some b) :
    execS ctx fs st (.exprStmt (.call "revert" [p, e])) = some (.inl (.rev (bytesOf st.mem a b))) := by
  rw [execS]; simp [evalArgs_cons, hp, he]

/-- `revert(0, 0)`. -/
theorem exec_revert00 :
    execS ctx fs st (.exprStmt (.call "revert" [.lit 0, .lit 0])) = some (.inl (.rev [])) := by
  rw [exec_revert (evalE_lit _ 0) (evalE_lit _ 0)]; rfl

theorem closeBlock_halt (st : St) (fs : Funs) (h : Halt) :
    closeBlock st fs (some (.inl h)) = some (.inl h) := rfl

theorem closeBlock_inr (st st' : St) (fs fs' : Funs) :
    closeBlock st fs (some (.inr (st', fs'))) =
      some (.inr (⟨exitBlock st.scope st'.scope, st'.mem⟩, fs)) := rfl

/-! ## Scopes -/

theorem lookup_cons_eq (σ : Scope) (x : String) (v : ℕ) : Scope.lookup ((x, v) :: σ) x = some v := by
  simp [Scope.lookup]

theorem lookup_cons_ne (σ : Scope) {x y : String} (v : ℕ) (h : x ≠ y) :
    Scope.lookup ((y, v) :: σ) x = Scope.lookup σ x := by
  simp [Scope.lookup, h]

theorem exitBlock_append (σ new : Scope) : exitBlock σ (new ++ σ) = σ := by
  simp [exitBlock]

/-! ## Loops -/

/-- **Bounded loop lemma.** If the states `S j, S (j+1), …, S N` are such that the condition holds
(is not zero) at every `S k` with `k < N` and fails (is zero) at `S N`, and one iteration takes
`S k` to `S (k + 1)`, then with more than `N - j` iterations of fuel the loop started at `S j`
ends in `S N`. -/
theorem loop_count (cond : St → Option ℕ) (step : St → Option (Halt ⊕ St)) (S : ℕ → St) (N : ℕ)
    (hc : ∀ k, k < N → ∃ c, cond (S k) = some c ∧ c ≠ 0) (hN : cond (S N) = some 0)
    (hs : ∀ k, k < N → step (S k) = some (.inr (S (k + 1)))) :
    ∀ fuel j, j ≤ N → N - j < fuel → loop cond step fuel (S j) = some (.inr (S N)) := by
  intro fuel
  induction fuel with
  | zero => intro j _ h; omega
  | succ n ih =>
    intro j hj hf
    rw [loop]
    by_cases hjN : j = N
    · subst hjN; rw [hN]; rfl
    · have hlt : j < N := by omega
      obtain ⟨c, hc1, hc2⟩ := hc j hlt
      rw [hc1]
      obtain ⟨c', rfl⟩ := Nat.exists_eq_succ_of_ne_zero hc2
      simp only [hs j hlt]
      exact ih (j + 1) (by omega) (by omega)

/-- One iteration of a `for` loop: the block `body`, then the block `post`, from `s` to `s'`. -/
def Iter (ctx : Ctx) (fs : Funs) (body post : List Stmt) (s s' : St) : Prop :=
  ∃ s₁, closeBlock s fs (execL ctx fs s body) = some (.inr (s₁, fs)) ∧
    closeBlock s₁ fs (execL ctx fs s₁ post) = some (.inr (s', fs))

/-- **A `for` loop that runs `N` iterations.** `init` takes the state to `S 0`; the condition
holds at `S 0, …, S (N - 1)` and fails at `S N`; each iteration takes `S k` to `S (k + 1)`. Then
the loop ends in `S N`, without the loop's own declarations. -/
theorem exec_for {init post body : List Stmt} {c : Expr} {fs₁ : Funs} (S : ℕ → St) (N : ℕ)
    (hinit : execL ctx fs st init = some (.inr (S 0, fs₁)))
    (hc : ∀ k, k < N → ∃ v, evalE ctx (S k).scope c = some v ∧ v ≠ 0)
    (hN : evalE ctx (S N).scope c = some 0)
    (hs : ∀ k, k < N → Iter ctx fs₁ body post (S k) (S (k + 1))) (hfuel : N < loopFuel) :
    execS ctx fs st (.forLoop init c post body) =
      some (.inr (⟨exitBlock st.scope (S N).scope, (S N).mem⟩, fs)) := by
  rw [execS, hinit]
  simp only
  rw [loop_count _ _ S N hc hN ?_ loopFuel 0 (Nat.zero_le _) (by omega)]
  intro k hk
  obtain ⟨s₁, h1, h2⟩ := hs k hk
  simp only [h1, h2]

end Zkapi.Yul
