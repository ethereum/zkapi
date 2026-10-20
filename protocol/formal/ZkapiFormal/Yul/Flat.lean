import ZkapiFormal.Yul.Fragment
import ZkapiFormal.Lazy.Straight

/-! # Scoped Yul and the flat straight-line program agree

`ZkapiFormal.Lazy.Straight` runs the unrolled permutation as a flat list of assignments on one
environment, with block braces as no-ops. This module proves that this is what Yul's scoped
semantics computes (here the straight-line fragment's, `ZkapiFormal.Yul.Fragment`, which
`ZkapiFormal.Yul.Embed` relates to the Yul semantics), for every program of the fragment that is
*well scoped*: every variable it reads or assigns is visible, and no `let` redeclares a visible
name (`wsL`, a decidable check, run by the kernel on the parsed source). The proof is generic
(`execL_flat`): it holds for any such program, with the scope's variables matching the flat
environment (`Agree`) before and after.

`flatE`/`flatS` read a Yul expression or statement as a `Zkapi.Lazy` one: the variables
`s0 s1 s2 x y z q`, literals, `add(a, b)`, `addmod(a, b, P)` and `mulmod(a, b, P)`, where `P` is
the variable holding the modulus. -/

namespace Zkapi.Yul.Frag

open Zkapi.Lazy (Var Env W)

/-- The Yul name of a straight-line program variable. -/
def _root_.Zkapi.Lazy.Var.name : Var → String
  | .s0 => "s0" | .s1 => "s1" | .s2 => "s2" | .x => "x" | .y => "y" | .z => "z" | .q => "q"

/-- The straight-line program variable with a Yul name. -/
def varOf (x : String) : Option Var :=
  if x = "s0" then some .s0 else if x = "s1" then some .s1 else if x = "s2" then some .s2
  else if x = "x" then some .x else if x = "y" then some .y else if x = "z" then some .z
  else if x = "q" then some .q else none

theorem varOf_some {x : String} {u : Var} (h : varOf x = some u) : x = u.name := by
  unfold varOf at h
  split_ifs at h <;> cases h <;> assumption

theorem name_ne_P (u : Var) : u.name ≠ "P" := by cases u <;> decide

theorem name_inj {u v : Var} (h : u.name = v.name) : u = v := by
  cases u <;> cases v <;> first | rfl | exact absurd h (by decide)

/-- A Yul expression as a straight-line program expression. -/
def flatE : Expr → Option Lazy.Expr
  | .lit n => some (.lit n)
  | .var x => (varOf x).map .var
  | .call f [a, b] =>
    if f = "add" then
      match flatE a, flatE b with
      | some a', some b' => some (.add a' b')
      | _, _ => none
    else none
  | .call f [a, b, .var m] =>
    if m = "P" then
      if f = "addmod" then
        match flatE a, flatE b with
        | some a', some b' => some (.addmod a' b')
        | _, _ => none
      else if f = "mulmod" then
        match flatE a, flatE b with
        | some a', some b' => some (.mulmod a' b')
        | _, _ => none
      else none
    else none
  | _ => none

mutual
/-- A Yul statement as straight-line program statements (a block becomes `openB … closeB`). -/
def flatS : Stmt → Option (List Lazy.Stmt)
  | .block ss => (flatL ss).map fun l => .openB :: (l ++ [.closeB])
  | .letv x e =>
    match varOf x, flatE e with
    | some u, some e' => some [.letv u e']
    | _, _ => none
  | .assign x e =>
    match varOf x, flatE e with
    | some u, some e' => some [.assign u e']
    | _, _ => none
  | .ifs _ _ => none

def flatL : List Stmt → Option (List Lazy.Stmt)
  | [] => some []
  | s :: ss =>
    match flatS s, flatL ss with
    | some a, some b => some (a ++ b)
    | _, _ => none
end

/-! ## Well-scopedness (static) -/

mutual
/-- Every variable the expression reads is in `D`. -/
def varsIn (D : List String) : Expr → Bool
  | .lit _ => true
  | .var x => D.contains x
  | .call _ args => varsInL D args

def varsInL (D : List String) : List Expr → Bool
  | [] => true
  | e :: es => varsIn D e && varsInL D es
end

mutual
/-- The names visible after the statement, given the names `D` visible before; `none` if the
statement reads or assigns a name that is not visible or redeclares a visible one. -/
def wsS (D : List String) : Stmt → Option (List String)
  | .block ss => (wsL D ss).map fun _ => D
  | .letv x e => if varsIn D e && !D.contains x then some (x :: D) else none
  | .assign x e => if varsIn D e && D.contains x then some D else none
  | .ifs c ss => if varsIn D c then (wsL D ss).map fun _ => D else none

def wsL (D : List String) : List Stmt → Option (List String)
  | [] => some D
  | s :: ss =>
    match wsS D s with
    | some D' => wsL D' ss
    | none => none
end

mutual
theorem wsS_suffix : ∀ (D : List String) (s : Stmt) (D' : List String), wsS D s = some D' →
    ∃ new, D' = new ++ D
  | D, .block ss, D', h => by
    simp only [wsS, Option.map_eq_some_iff] at h
    obtain ⟨_, -, rfl⟩ := h
    exact ⟨[], rfl⟩
  | D, .letv x e, D', h => by
    simp only [wsS] at h
    split_ifs at h
    cases h
    exact ⟨[x], rfl⟩
  | D, .assign x e, D', h => by
    simp only [wsS] at h
    split_ifs at h
    cases h
    exact ⟨[], rfl⟩
  | D, .ifs c ss, D', h => by
    simp only [wsS] at h
    split_ifs at h
    simp only [Option.map_eq_some_iff] at h
    obtain ⟨_, -, rfl⟩ := h
    exact ⟨[], rfl⟩

theorem wsL_suffix : ∀ (D : List String) (ss : List Stmt) (D' : List String), wsL D ss = some D' →
    ∃ new, D' = new ++ D
  | D, [], D', h => by
    simp only [wsL, Option.some.injEq] at h
    exact ⟨[], by simp [h]⟩
  | D, s :: ss, D', h => by
    simp only [wsL] at h
    split at h
    · rename_i D1 h1
      obtain ⟨n1, rfl⟩ := wsS_suffix D s D1 h1
      obtain ⟨n2, rfl⟩ := wsL_suffix _ ss D' h
      exact ⟨n2 ++ n1, by simp⟩
    · cases h
end

/-! ## Scopes -/

theorem lookup_of_mem : ∀ (σ : Scope) (x : String), x ∈ (Scope.names σ) →
    ∃ v, Scope.lookup σ x = some v ∧ (x, v) ∈ σ
  | [], x, h => by simp [Scope.names] at h
  | (y, w) :: σ, x, h => by
    by_cases hx : x = y
    · subst hx; exact ⟨w, by simp [Scope.lookup], by simp⟩
    · have h' : x ∈ (Scope.names σ) := by
        simp only [Scope.names, List.map_cons, List.mem_cons] at h
        rcases h with h | h
        · exact absurd h hx
        · exact h
      obtain ⟨v, h1, h2⟩ := lookup_of_mem σ x h'
      exact ⟨v, by simp [Scope.lookup, hx, h1], List.mem_cons_of_mem _ h2⟩

theorem lookup_none : ∀ (σ : Scope) (x : String), x ∉ (Scope.names σ) → Scope.lookup σ x = none
  | [], _, _ => rfl
  | (y, w) :: σ, x, h => by
    simp only [Scope.names, List.map_cons, List.mem_cons, not_or] at h
    simp [Scope.lookup, h.1, lookup_none σ x h.2]

theorem set_spec : ∀ (σ : Scope) (x : String) (v : ℕ), x ∈ (Scope.names σ) → (Scope.names σ).Nodup →
    ∃ σ', Scope.set σ x v = some σ' ∧ (Scope.names σ') = (Scope.names σ) ∧
      ∀ y w, (y, w) ∈ σ' → (y = x ∧ w = v) ∨ (y ≠ x ∧ (y, w) ∈ σ)
  | [], _, _, h, _ => by simp [Scope.names] at h
  | (y, w) :: σ, x, v, h, hn => by
    simp only [Scope.names, List.map_cons, List.nodup_cons] at hn
    by_cases hx : x = y
    · subst hx
      refine ⟨(x, v) :: σ, by simp [Scope.set], rfl, fun z u hz => ?_⟩
      rcases List.mem_cons.1 hz with hz | hz
      · cases hz; exact Or.inl ⟨rfl, rfl⟩
      · have hm : z ∈ σ.map Prod.fst := by simpa using List.mem_map_of_mem (f := Prod.fst) hz
        have : z ≠ x := fun e => hn.1 (e ▸ hm)
        exact Or.inr ⟨this, List.mem_cons_of_mem _ hz⟩
    · have h' : x ∈ (Scope.names σ) := by
        simp only [Scope.names, List.map_cons, List.mem_cons] at h
        rcases h with h | h
        · exact absurd h hx
        · exact h
      obtain ⟨σ', h1, h2, h3⟩ := set_spec σ x v h' hn.2
      refine ⟨(y, w) :: σ', by simp [Scope.set, hx, h1], by simp [Scope.names] at h2 ⊢; exact h2,
        fun z u hz => ?_⟩
      rcases List.mem_cons.1 hz with hz | hz
      · cases hz; exact Or.inr ⟨Ne.symm (Ne.symm hx) |>.symm, by simp⟩
      · rcases h3 z u hz with h | ⟨hne, hm⟩
        · exact Or.inl h
        · exact Or.inr ⟨hne, List.mem_cons_of_mem _ hm⟩

/-! ## Agreement -/

/-- The visible variables hold what the flat environment holds, and `P` holds `p`. -/
def Agree (σ : Scope) (env : Env) : Prop :=
  ∀ x v, (x, v) ∈ σ → (x = "P" → v = Zkapi.p) ∧ ∀ u : Var, x = u.name → v = env u

theorem p_ne_zero : Zkapi.p ≠ 0 := by decide

theorem evalE_flat (ctx : Ctx) {σ : Scope} {env : Env} (hA : Agree σ env) :
    ∀ (e : Expr) (e' : Lazy.Expr), flatE e = some e' → varsIn (Scope.names σ) e = true →
      evalE ctx σ e = some (e'.eval env)
  | .lit n, e', h, _ => by
    simp only [flatE, Option.some.injEq] at h
    subst h
    rfl
  | .var x, e', h, hv => by
    simp only [flatE, Option.map_eq_some_iff] at h
    obtain ⟨u, hu, rfl⟩ := h
    simp only [varsIn, List.contains_iff_mem] at hv
    obtain ⟨v, h1, h2⟩ := lookup_of_mem σ x hv
    simp only [evalE, h1, Lazy.Expr.eval, (hA x v h2).2 u (varOf_some hu)]
  | .call f [a, b], e', h, hv => by
    simp only [flatE] at h
    split_ifs at h with hf
    split at h
    · rename_i a' b' ha hb
      cases h
      simp only [varsIn, varsInL, Bool.and_true, Bool.and_eq_true] at hv
      have ea := evalE_flat ctx hA a a' ha hv.1
      have eb := evalE_flat ctx hA b b' hb hv.2
      subst hf
      simp [evalE, evalArgs, ea, eb, builtin, Lazy.Expr.eval, Lazy.evmAdd, W]
    · cases h
  | .call f [a, b, .var m], e', h, hv => by
    simp only [flatE] at h
    simp only [varsIn, varsInL, Bool.and_true, Bool.and_eq_true, List.contains_iff_mem] at hv
    obtain ⟨vP, hP1, hP2⟩ := lookup_of_mem σ m hv.2.2
    split_ifs at h with hm hf hf'
    · split at h
      · rename_i a' b' ha hb
        cases h
        have ea := evalE_flat ctx hA a a' ha hv.1
        have eb := evalE_flat ctx hA b b' hb hv.2.1
        have hp := (hA m vP hP2).1 hm
        subst hf hp
        simp [evalE, evalArgs, ea, eb, hP1, builtin, Lazy.Expr.eval, Lazy.evmAddmod, p_ne_zero]
      · cases h
    · split at h
      · rename_i a' b' ha hb
        cases h
        have ea := evalE_flat ctx hA a a' ha hv.1
        have eb := evalE_flat ctx hA b b' hb hv.2.1
        have hp := (hA m vP hP2).1 hm
        subst hf' hp
        simp [evalE, evalArgs, ea, eb, hP1, builtin, Lazy.Expr.eval, Lazy.evmMulmod, p_ne_zero]
      · cases h
  | .call _ [], _, h, _ => by simp [flatE] at h
  | .call _ [_], _, h, _ => by simp [flatE] at h
  | .call _ [_, _, .lit _], _, h, _ => by simp [flatE] at h
  | .call _ [_, _, .call _ _], _, h, _ => by simp [flatE] at h
  | .call _ (_ :: _ :: _ :: _ :: _), _, h, _ => by simp [flatE] at h

theorem agree_declare {σ : Scope} {env : Env} (hA : Agree σ env) {u : Var} (hx : u.name ∉ (Scope.names σ))
    (v : ℕ) : Agree ((u.name, v) :: σ) (Function.update env u v) := by
  intro y w hy
  rcases List.mem_cons.1 hy with h0 | h1
  · cases h0
    refine ⟨fun h => absurd h (name_ne_P u), fun u' hu' => ?_⟩
    rw [name_inj hu'.symm]; simp
  · have hm : y ∈ σ.map Prod.fst := List.mem_map_of_mem (f := Prod.fst) h1
    refine ⟨(hA y w h1).1, fun u' hu' => ?_⟩
    have hne : u' ≠ u := by
      intro e
      subst e
      exact hx (hu' ▸ hm)
    rw [Function.update_of_ne hne]
    exact (hA y w h1).2 u' hu'

theorem agree_set {σ σ' : Scope} {env : Env} (hA : Agree σ env) {u : Var} {v : ℕ}
    (h : ∀ y w, (y, w) ∈ σ' → (y = u.name ∧ w = v) ∨ (y ≠ u.name ∧ (y, w) ∈ σ)) :
    Agree σ' (Function.update env u v) := by
  intro y w hy
  rcases h y w hy with ⟨rfl, rfl⟩ | ⟨hne, hm⟩
  · refine ⟨fun h => absurd h (name_ne_P u), fun u' hu' => ?_⟩
    rw [name_inj hu'.symm]; simp
  · refine ⟨(hA y w hm).1, fun u' hu' => ?_⟩
    have : u' ≠ u := by rintro rfl; exact hne hu'
    rw [Function.update_of_ne this]
    exact (hA y w hm).2 u' hu'

theorem lazy_exec_block (l : List Lazy.Stmt) (env : Env) :
    Lazy.exec (.openB :: (l ++ [.closeB])) env = Lazy.exec l env := by
  simp [Lazy.exec, Lazy.Stmt.exec, Lazy.exec_append]

mutual
/-- **Scoped execution of a well-scoped statement is the flat execution.** -/
theorem execS_flat (ctx : Ctx) : ∀ (s : Stmt) (σ : Scope) (env : Env) (l : List Lazy.Stmt)
    (D' : List String), flatS s = some l → wsS (Scope.names σ) s = some D' → (Scope.names σ).Nodup →
    Agree σ env →
      ∃ σ', execS ctx σ s = some σ' ∧ (Scope.names σ') = D' ∧ D'.Nodup ∧ Agree σ' (Lazy.exec l env)
  | .block ss, σ, env, l, D', hf, hw, hn, hA => by
    simp only [flatS, Option.map_eq_some_iff] at hf
    obtain ⟨l', hl', rfl⟩ := hf
    simp only [wsS, Option.map_eq_some_iff] at hw
    obtain ⟨D'', hw', rfl⟩ := hw
    obtain ⟨σ'', h1, h2, -, h4⟩ := execL_flat ctx ss σ env l' D'' hl' hw' hn hA
    obtain ⟨new, rfl⟩ := wsL_suffix _ ss D'' hw'
    have hlen : σ''.length - σ.length = new.length := by
      have := congrArg List.length h2
      simp only [Scope.names, List.length_map, List.length_append] at this
      omega
    refine ⟨exitBlock σ σ'', by simp [execS, h1], ?_, hn, ?_⟩
    · simp only [exitBlock, hlen, Scope.names, List.map_drop]
      simp only [Scope.names] at h2
      rw [h2]; simp
    · rw [lazy_exec_block]
      intro y w hy
      exact h4 y w (List.mem_of_mem_drop hy)
  | .letv x e, σ, env, l, D', hf, hw, hn, hA => by
    simp only [flatS] at hf
    split at hf
    · rename_i u e' hu he
      cases hf
      simp only [wsS, Bool.and_eq_true, Bool.not_eq_eq_eq_not, Bool.not_true] at hw
      split_ifs at hw with hc
      cases hw
      have hx := varOf_some hu
      subst hx
      have ev := evalE_flat ctx hA e e' he hc.1
      refine ⟨(u.name, e'.eval env) :: σ, ?_, rfl, List.nodup_cons.2 ⟨?_, hn⟩, ?_⟩
      · simp [execS, ev, lookup_none σ u.name (by simpa using hc.2)]
      · simpa using hc.2
      · exact agree_declare hA (by simpa using hc.2) _
    · cases hf
  | .assign x e, σ, env, l, D', hf, hw, hn, hA => by
    simp only [flatS] at hf
    split at hf
    · rename_i u e' hu he
      cases hf
      simp only [wsS, Bool.and_eq_true, List.contains_iff_mem] at hw
      split_ifs at hw with hc
      cases hw
      have hx := varOf_some hu
      subst hx
      have ev := evalE_flat ctx hA e e' he hc.1
      obtain ⟨σ', h1, h2, h3⟩ := set_spec σ u.name (e'.eval env) hc.2 hn
      exact ⟨σ', by simp [execS, ev, h1], h2, h2 ▸ hn, agree_set hA h3⟩
    · cases hf
  | .ifs _ _, _, _, _, _, hf, _, _, _ => by simp [flatS] at hf

/-- **Scoped execution of a well-scoped statement list is the flat execution.** -/
theorem execL_flat (ctx : Ctx) : ∀ (ss : List Stmt) (σ : Scope) (env : Env) (l : List Lazy.Stmt)
    (D' : List String), flatL ss = some l → wsL (Scope.names σ) ss = some D' → (Scope.names σ).Nodup →
    Agree σ env →
      ∃ σ', execL ctx σ ss = some σ' ∧ (Scope.names σ') = D' ∧ D'.Nodup ∧ Agree σ' (Lazy.exec l env)
  | [], σ, env, l, D', hf, hw, hn, hA => by
    simp only [flatL, Option.some.injEq] at hf
    simp only [wsL, Option.some.injEq] at hw
    subst hf hw
    exact ⟨σ, rfl, rfl, hn, hA⟩
  | s :: ss, σ, env, l, D', hf, hw, hn, hA => by
    simp only [flatL] at hf
    split at hf
    · rename_i a b ha hb
      cases hf
      simp only [wsL] at hw
      split at hw
      · rename_i D1 hw1
        obtain ⟨σ1, h1, h2, h3, h4⟩ := execS_flat ctx s σ env a D1 ha hw1 hn hA
        obtain ⟨σ2, g1, g2, g3, g4⟩ :=
          execL_flat ctx ss σ1 _ b D' hb (h2 ▸ hw) (h2 ▸ h3) h4
        refine ⟨σ2, by simp [execL, h1, g1], g2, g3, ?_⟩
        rw [Lazy.exec_append]; exact g4
      · cases hw
    · cases hf
end

end Zkapi.Yul.Frag
