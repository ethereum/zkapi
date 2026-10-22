import ZkapiPoC.Semantics

/-! # Proof of concept: the permutation's fragment runs the same in both semantics

`unembS` reads a statement of this module's larger fragment as a statement of
`ZkapiFormal.Yul` (single-variable `let`, assignment, `if`, blocks, calls of builtins). Where it
does, and with no user function in scope, the larger semantics computes exactly what
`Zkapi.Yul.Frag.execS` computes, leaving memory alone (`execS_unemb`). So `Zkapi.Yul`'s theorems about
the permutation apply inside the PoC's `permute` function. -/

namespace Zkapi.PoC

mutual
def unembE : Expr → Option Yul.Frag.Expr
  | .lit n => some (.lit n)
  | .var x => some (.var x)
  | .call f args => (unembEs args).map (.call f)

def unembEs : List Expr → Option (List Yul.Frag.Expr)
  | [] => some []
  | e :: es =>
    match unembE e, unembEs es with
    | some e', some es' => some (e' :: es')
    | _, _ => none
end

mutual
def unembS : Stmt → Option Yul.Frag.Stmt
  | .block ss => (unembL ss).map .block
  | .letv [x] e => (unembE e).map (.letv x)
  | .assign x e => (unembE e).map (.assign x)
  | .ifs c body =>
    match unembE c, unembL body with
    | some c', some b' => some (.ifs c' b')
    | _, _ => none
  | _ => none

def unembL : List Stmt → Option (List Yul.Frag.Stmt)
  | [] => some []
  | s :: ss =>
    match unembS s, unembL ss with
    | some s', some ss' => some (s' :: ss')
    | _, _ => none
end

theorem builtin_sub {ctx : Ctx} {m : Mem} {f : String} {vs : List ℕ} {v : ℕ}
    (h : Yul.Frag.builtin ⟨ctx.calldata.length⟩ f vs = some v) : builtin ctx m f vs = some v := by
  unfold Yul.Frag.builtin at h
  split at h <;> first | (cases h; rfl) | cases h

mutual
theorem evalE_unemb (ctx : Ctx) (m : Mem) (σ : Yul.Scope) : ∀ (e : Expr) (e' : Yul.Frag.Expr) (v : ℕ),
    unembE e = some e' → Yul.Frag.evalE ⟨ctx.calldata.length⟩ σ e' = some v → evalE ctx m σ e = some v
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
    simp only [Yul.Frag.evalE] at he
    split at he
    · rename_i vs hvs
      simp only [evalE, evalArgs_unemb ctx m σ args args' vs ha hvs]
      exact builtin_sub he
    · cases he

theorem evalArgs_unemb (ctx : Ctx) (m : Mem) (σ : Yul.Scope) :
    ∀ (es : List Expr) (es' : List Yul.Frag.Expr) (vs : List ℕ),
      unembEs es = some es' → Yul.Frag.evalArgs ⟨ctx.calldata.length⟩ σ es' = some vs →
        evalArgs ctx m σ es = some vs
  | [], es', vs, h, he => by
    simp only [unembEs, Option.some.injEq] at h
    subst h
    simpa [Yul.Frag.evalArgs, evalArgs] using he
  | e :: es, es', vs, h, he => by
    simp only [unembEs] at h
    split at h
    · rename_i e' es'' h1 h2
      cases h
      simp only [Yul.Frag.evalArgs] at he
      split at he
      · rename_i ws hws
        split at he
        · rename_i w hw
          cases he
          simp [evalArgs, evalArgs_unemb ctx m σ es es'' ws h2 hws, evalE_unemb ctx m σ e e' w h1 hw]
        · cases he
      · cases he
    · cases h
end

theorem rhs_unemb {ctx : Ctx} {st : St} {e : Expr} {e' : Yul.Frag.Expr} {v : ℕ}
    (h : unembE e = some e') (he : Yul.Frag.evalE ⟨ctx.calldata.length⟩ st.scope e' = some v) :
    rhs ctx [] st e = some (.inr ([v], st.mem)) := by
  have := evalE_unemb ctx st.mem st.scope e e' v h he
  cases e with
  | call f args => simp [rhs, Funs.find, this]
  | lit n => simp [rhs, this]
  | var x => simp [rhs, this]

mutual
/-- **On the shared fragment the larger semantics is `Zkapi.Yul`'s**, with no function in scope,
and memory untouched. -/
theorem execS_unemb (ctx : Ctx) : ∀ (s : Stmt) (s' : Yul.Frag.Stmt) (σ σ' : Yul.Scope) (m : Mem),
    unembS s = some s' → Yul.Frag.execS ⟨ctx.calldata.length⟩ σ s' = some σ' →
      execS ctx [] ⟨σ, m⟩ s = some (.inr (⟨σ', m⟩, []))
  | .block ss, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨ss', hs, rfl⟩ := h
    simp only [Yul.Frag.execS, Option.map_eq_some_iff] at he
    obtain ⟨σ'', h1, rfl⟩ := he
    simp [execS, execL_unemb ctx ss ss' σ σ'' m hs h1, closeBlock]
  | .letv [x] e, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨e', hu, rfl⟩ := h
    simp only [Yul.Frag.execS] at he
    split at he
    · rename_i v hv
      have hr := rhs_unemb (st := ⟨σ, m⟩) hu hv
      split_ifs at he with hx
      cases he
      simp [execS, hr, declare, hx]
    · cases he
  | .assign x e, s', σ, σ', m, h, he => by
    simp only [unembS, Option.map_eq_some_iff] at h
    obtain ⟨e', hu, rfl⟩ := h
    simp only [Yul.Frag.execS] at he
    split at he
    · rename_i v hv
      have hr := rhs_unemb (st := ⟨σ, m⟩) hu hv
      simp [execS, hr, he]
    · cases he
  | .ifs c body, s', σ, σ', m, h, he => by
    simp only [unembS] at h
    split at h
    · rename_i c' b' hc hb
      cases h
      simp only [Yul.Frag.execS] at he
      cases hv : Yul.Frag.evalE ⟨ctx.calldata.length⟩ σ c' with
      | none => simp [hv] at he
      | some v =>
        have hev := evalE_unemb ctx m σ c c' v hc hv
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
  | .switch _ _, _, _, _, _, h, _ => by simp [unembS] at h
  | .arm _ _, _, _, _, _, h, _ => by simp [unembS] at h
  | .exprStmt _, _, _, _, _, h, _ => by simp [unembS] at h
  | .funDef _ _ _ _, _, _, _, _, h, _ => by simp [unembS] at h

theorem execL_unemb (ctx : Ctx) : ∀ (ss : List Stmt) (ss' : List Yul.Frag.Stmt) (σ σ' : Yul.Scope)
    (m : Mem), unembL ss = some ss' → Yul.Frag.execL ⟨ctx.calldata.length⟩ σ ss' = some σ' →
      execL ctx [] ⟨σ, m⟩ ss = some (.inr (⟨σ', m⟩, []))
  | [], ss', σ, σ', m, h, he => by
    simp only [unembL, Option.some.injEq] at h
    subst h
    simp only [Yul.Frag.execL, Option.some.injEq] at he
    subst he
    rfl
  | s :: ss, ss', σ, σ', m, h, he => by
    simp only [unembL] at h
    split at h
    · rename_i s' ss'' h1 h2
      cases h
      simp only [Yul.Frag.execL] at he
      split at he
      · rename_i σ'' h3
        simp [execL, execS_unemb ctx s s' σ σ'' m h1 h3, execL_unemb ctx ss ss'' σ'' σ' m h2 he]
      · cases he
    · cases h
end

end Zkapi.PoC
