import ZkapiFormal.Yul.Fragment

/-! # The straight-line fragment runs the same in the Yul semantics

`unembS` reads a statement of the Yul fragment (`ZkapiFormal.Yul.Syntax`) as a statement of the
straight-line fragment (`ZkapiFormal.Yul.Fragment`: single-variable `let`, single assignment,
`if`, blocks, calls of builtins). Where it does, and with no user function in scope, the Yul
semantics computes exactly what `Zkapi.Yul.Frag.execS` computes and leaves memory alone
(`execS_unemb`). So the generic simulation `Zkapi.Yul.Frag.execL_flat` and the program lemmas
apply to the runtime's `permute`, run in the Yul semantics. -/

namespace Zkapi.Yul

mutual
def unembE : Expr → Option Frag.Expr
  | .lit n => some (.lit n)
  | .var x => some (.var x)
  | .call f args => (unembEs args).map (.call f)

def unembEs : List Expr → Option (List Frag.Expr)
  | [] => some []
  | e :: es =>
    match unembE e, unembEs es with
    | some e', some es' => some (e' :: es')
    | _, _ => none
end

mutual
def unembS : Stmt → Option Frag.Stmt
  | .block ss => (unembL ss).map .block
  | .letv [x] e => (unembE e).map (.letv x)
  | .assign [x] e => (unembE e).map (.assign x)
  | .ifs c body =>
    match unembE c, unembL body with
    | some c', some b' => some (.ifs c' b')
    | _, _ => none
  | _ => none

def unembL : List Stmt → Option (List Frag.Stmt)
  | [] => some []
  | s :: ss =>
    match unembS s, unembL ss with
    | some s', some ss' => some (s' :: ss')
    | _, _ => none
end

/-- The fragment's context of a call. -/
def Ctx.frag (ctx : Ctx) : Frag.Ctx := ⟨ctx.calldata.length⟩

theorem builtin_of_frag {ctx : Ctx} {f : String} {vs : List ℕ} {v : ℕ}
    (h : Frag.builtin ctx.frag f vs = some v) : builtin ctx f vs = some v := by
  unfold Frag.builtin at h
  split at h <;> first | (cases h; rfl) | cases h

mutual
theorem evalE_unemb (ctx : Ctx) (σ : Scope) : ∀ (e : Expr) (e' : Frag.Expr) (v : ℕ),
    unembE e = some e' → Frag.evalE ctx.frag σ e' = some v → evalE ctx σ e = some v
  | .lit n, e', v, h, he => by
    simp only [unembE, Option.some.injEq] at h
    subst h
    exact he
  | .var x, e', v, h, he => by
    simp only [unembE, Option.some.injEq] at h
    subst h
    exact he
  | .call f args, e', v, h, he => by
    simp only [unembE, Option.map_eq_some_iff] at h
    obtain ⟨args', ha, rfl⟩ := h
    simp only [Frag.evalE] at he
    split at he
    · rename_i vs hvs
      simp only [evalE, evalArgs_unemb ctx σ args args' vs ha hvs]
      exact builtin_of_frag he
    · cases he

theorem evalArgs_unemb (ctx : Ctx) (σ : Scope) :
    ∀ (es : List Expr) (es' : List Frag.Expr) (vs : List ℕ),
      unembEs es = some es' → Frag.evalArgs ctx.frag σ es' = some vs → evalArgs ctx σ es = some vs
  | [], es', vs, h, he => by
    simp only [unembEs, Option.some.injEq] at h
    subst h
    simpa [Frag.evalArgs, evalArgs] using he
  | e :: es, es', vs, h, he => by
    simp only [unembEs] at h
    split at h
    · rename_i e' es'' h1 h2
      cases h
      simp only [Frag.evalArgs] at he
      split at he
      · rename_i ws hws
        split at he
        · rename_i w hw
          cases he
          simp [evalArgs, evalArgs_unemb ctx σ es es'' ws h2 hws, evalE_unemb ctx σ e e' w h1 hw]
        · cases he
      · cases he
    · cases h
end

theorem rhs_unemb {ctx : Ctx} {st : St} {e : Expr} {e' : Frag.Expr} {v : ℕ}
    (h : unembE e = some e') (he : Frag.evalE ctx.frag st.scope e' = some v) :
    rhs ctx [] st e = some (.inr ([v], st.mem)) := by
  have := evalE_unemb ctx st.scope e e' v h he
  cases e with
  | call f args => simp [rhs, Funs.find, this]
  | lit n => simp [rhs, this]
  | var x => simp [rhs, this]

mutual
/-- **On the straight-line fragment the Yul semantics is the fragment's**, with no function in
scope, and memory untouched. -/
theorem execS_unemb (ctx : Ctx) : ∀ (s : Stmt) (s' : Frag.Stmt) (σ σ' : Scope) (m : Mem),
    unembS s = some s' → Frag.execS ctx.frag σ s' = some σ' →
      execS ctx [] ⟨σ, m⟩ s = some (.inr (⟨σ', m⟩, []))
  | .block ss, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨ss', hs, rfl⟩ := h
    simp only [Frag.execS, Option.map_eq_some_iff] at he
    obtain ⟨σ'', h1, rfl⟩ := he
    simp [execS, execL_unemb ctx ss ss' σ σ'' m hs h1, closeBlock]
  | .letv [x] e, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨e', hu, rfl⟩ := h
    simp only [Frag.execS] at he
    split at he
    · rename_i v hv
      have hr := rhs_unemb (st := ⟨σ, m⟩) hu hv
      split_ifs at he with hx
      cases he
      simp [execS, hr, declare, hx]
    · cases he
  | .assign [x] e, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨e', hu, rfl⟩ := h
    simp only [Frag.execS] at he
    split at he
    · rename_i v hv
      have hr := rhs_unemb (st := ⟨σ, m⟩) hu hv
      simp [execS, hr, assignAll, he]
    · cases he
  | .ifs c body, s', σ, σ', m, h, he => by
    simp only [unembS] at h
    split at h
    · rename_i c' b' hc hb
      cases h
      simp only [Frag.execS] at he
      cases hv : Frag.evalE ctx.frag σ c' with
      | none => simp [hv] at he
      | some v =>
        have hev := evalE_unemb ctx σ c c' v hc hv
        rw [hv] at he
        cases v with
        | zero =>
          simp only [Option.some.injEq] at he
          subst he
          simp [execS, hev]
        | succ k =>
          simp only [Option.map_eq_some_iff] at he
          obtain ⟨σ'', h1, rfl⟩ := he
          simp [execS, hev, execL_unemb ctx body b' σ σ'' m hb h1, closeBlock]
    · cases h
  | .letv [] _, _, _, _, _, h, _ => by simp [unembS] at h
  | .letv (_ :: _ :: _) _, _, _, _, _, h, _ => by simp [unembS] at h
  | .assign [] _, _, _, _, _, h, _ => by simp [unembS] at h
  | .assign (_ :: _ :: _) _, _, _, _, _, h, _ => by simp [unembS] at h
  | .switch _ _, _, _, _, _, h, _ => by simp [unembS] at h
  | .arm _ _, _, _, _, _, h, _ => by simp [unembS] at h
  | .forLoop _ _ _ _, _, _, _, _, h, _ => by simp [unembS] at h
  | .exprStmt _, _, _, _, _, h, _ => by simp [unembS] at h
  | .funDef _ _ _ _, _, _, _, _, h, _ => by simp [unembS] at h

theorem execL_unemb (ctx : Ctx) : ∀ (ss : List Stmt) (ss' : List Frag.Stmt) (σ σ' : Scope)
    (m : Mem), unembL ss = some ss' → Frag.execL ctx.frag σ ss' = some σ' →
      execL ctx [] ⟨σ, m⟩ ss = some (.inr (⟨σ', m⟩, []))
  | [], ss', σ, σ', m, h, he => by
    simp only [unembL, Option.some.injEq] at h
    subst h
    simp only [Frag.execL, Option.some.injEq] at he
    subst he
    rfl
  | s :: ss, ss', σ, σ', m, h, he => by
    simp only [unembL] at h
    split at h
    · rename_i s' ss'' h1 h2
      cases h
      simp only [Frag.execL] at he
      split at he
      · rename_i σ'' h3
        simp [execL, execS_unemb ctx s s' σ σ'' m h1 h3, execL_unemb ctx ss ss'' σ'' σ' m h2 he]
      · cases he
    · cases h
end

end Zkapi.Yul
