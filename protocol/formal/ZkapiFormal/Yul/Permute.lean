import ZkapiFormal.Yul.Flat
import ZkapiFormal.Yul.Embed
import ZkapiFormal.Yul.Beq
import ZkapiFormal.Yul.Exec
import ZkapiFormal.Yul.Shape
import ZkapiFormal.Data.Yul
import ZkapiFormal.Lazy.Permutation

/-! # The kernel parses the runtime's assembly block; its `permute` computes the permutation

`ZkapiFormal.Data.Yul` holds the token stream of the whole assembly block of the vault's Poseidon
runtime, `protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol`, as the generator's lexer
extracted it: every token, punctuation included, only whitespace and comments dropped. Here the
kernel

1. parses it with the Yul grammar of `ZkapiFormal.Yul.Syntax` (`blockOK_source`);
2. checks that the block is exactly three statements:
   * `function permute(s0, s1, s2) -> r0, r1, r2 { … }`, whose body is `let P := p`, then
     `if gt(calldatasize(), 0xffffffffffff) { P := 1 }`, then 65 statements that read, statement
     for statement, as the verified straight-line `Zkapi.Lazy.program` (every literal, every
     `add`/`addmod` choice, every operand and target) and are well scoped, then
     `r0 := s0  r1 := s1  r2 := s2`;
   * `if lt(calldatasize(), 4) { revert(0, 0) }`;
   * the dispatcher, exactly as `ZkapiFormal.Yul.Shape.dispatch` states it;

and `yul_permute` proves, with the generic simulation `Frag.execL_flat` and `execL_unemb`, that
the function `permute` the block defines maps any words `a b c` to `wordPermute a b c` (the
canonical representatives of the reference permutation of the inputs reduced mod p,
`Zkapi.Lazy.wordPermute_eq`) and leaves memory alone, provided the never-taken branch is not taken:
the calldata is shorter than `2^48` bytes. -/

namespace Zkapi.Yul

open Zkapi.Lazy (Var Env W initEnv wordPermute program)

/-! ## The head of `permute`'s body -/

namespace Frag

/-- `let P := p`. -/
def headP : Stmt := .letv "P" (.lit Zkapi.p)

/-- `if gt(calldatasize(), 0xffffffffffff) { P := 1 }`. -/
def headIf : Stmt := .ifs (.call "gt" [.call "calldatasize" [], .lit 0xffffffffffff]) [.assign "P" (.lit 1)]

/-- The two statements before the rounds. -/
def headOK : List Stmt → Bool
  | [.letv x (.lit m), .ifs (.call g [.call c [], .lit k]) [.assign y (.lit o)]] =>
    x == "P" && m == Zkapi.p && g == "gt" && c == "calldatasize" && k == 0xffffffffffff &&
      y == "P" && o == 1
  | _ => false

theorem headOK_spec {h0 h1 : Stmt} (h : headOK [h0, h1] = true) : h0 = headP ∧ h1 = headIf := by
  unfold headOK at h
  split at h
  · rename_i x m g c k y o heq
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨⟨⟨⟨⟨⟨rfl, rfl⟩, rfl⟩, rfl⟩, rfl⟩, rfl⟩, rfl⟩ := h
    simp only [List.cons.injEq] at heq
    obtain ⟨rfl, rfl, -⟩ := heq
    exact ⟨rfl, rfl⟩
  · cases h

end Frag

/-- The names visible in `permute`'s rounds: the modulus, the parameters, the return variables. -/
def fnNames : List String := ["P", "s0", "s1", "s2", "r0", "r1", "r2"]

/-! ## The block -/

/-- What the kernel checks on the token stream of the runtime's assembly block. -/
def blockOK (toks : List Tok) : Bool :=
  match parseBody toks with
  | some [.funDef f ps rs body, s1, s2] =>
    f == "permute" && ps == ["s0", "s1", "s2"] && rs == ["r0", "r1", "r2"] &&
      beqS s1 ifShort && beqS s2 dispatch && beqL (body.drop (body.length - 3)) retTail &&
      match unembL (body.take (body.length - 3)) with
      | some (h0 :: h1 :: rs') =>
        Frag.headOK [h0, h1] && Frag.flatL rs' == some program &&
          Frag.wsL fnNames rs' == some fnNames
      | _ => false
  | _ => false

theorem blockOK_spec {toks : List Tok} (h : blockOK toks = true) :
    ∃ pre rs', parseBody toks =
        some [.funDef "permute" ["s0", "s1", "s2"] ["r0", "r1", "r2"] (pre ++ retTail), ifShort,
          dispatch] ∧
      unembL pre = some (Frag.headP :: Frag.headIf :: rs') ∧ Frag.flatL rs' = some program ∧
      Frag.wsL fnNames rs' = some fnNames := by
  unfold blockOK at h
  split at h
  · rename_i f ps rs body s1 s2 hp
    simp only [Bool.and_eq_true, beq_iff_eq] at h
    obtain ⟨⟨⟨⟨⟨⟨rfl, rfl⟩, rfl⟩, h1⟩, h2⟩, h3⟩, h4⟩ := h
    split at h4
    · rename_i h0 h1' rs' hu
      simp only [Bool.and_eq_true, beq_iff_eq] at h4
      obtain ⟨⟨hh, hf⟩, hw⟩ := h4
      obtain ⟨rfl, rfl⟩ := Frag.headOK_spec hh
      have ht := beqL_eq _ _ h3
      refine ⟨body.take (body.length - 3), rs', ?_, hu, hf, hw⟩
      rw [hp, beqS_eq _ _ h1, beqS_eq _ _ h2, ← ht, List.take_append_drop]
    · cases h4
  · cases h

set_option maxRecDepth 100000 in
/-- **The kernel parses the runtime's assembly block** and finds `permute` (the verified program),
the short-calldata check and the dispatcher. -/
theorem blockOK_source : blockOK Data.yulBlock = true := by decide +kernel

/-- The parsed assembly block of the runtime. -/
def blockAst : List Stmt := (parseBody Data.yulBlock).getD []

theorem blockAst_spec :
    ∃ pre rs', blockAst =
        [.funDef "permute" ["s0", "s1", "s2"] ["r0", "r1", "r2"] (pre ++ retTail), ifShort, dispatch] ∧
      unembL pre = some (Frag.headP :: Frag.headIf :: rs') ∧ Frag.flatL rs' = some program ∧
      Frag.wsL fnNames rs' = some fnNames := by
  obtain ⟨pre, rs', hp, hu, hf, hw⟩ := blockOK_spec blockOK_source
  exact ⟨pre, rs', by simp only [blockAst, hp, Option.getD_some], hu, hf, hw⟩

/-! ## `permute` -/

theorem names_seven {σ : Scope} {n₁ n₂ n₃ n₄ n₅ n₆ n₇ : String}
    (h : Scope.names σ = [n₁, n₂, n₃, n₄, n₅, n₆, n₇]) :
    ∃ v₁ v₂ v₃ v₄ v₅ v₆ v₇,
      σ = [(n₁, v₁), (n₂, v₂), (n₃, v₃), (n₄, v₄), (n₅, v₅), (n₆, v₆), (n₇, v₇)] := by
  match σ, h with
  | [(_, v₁), (_, v₂), (_, v₃), (_, v₄), (_, v₅), (_, v₆), (_, v₇)], h =>
    simp only [Scope.names, List.map_cons, List.map_nil, List.cons.injEq] at h
    obtain ⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl, -⟩ := h
    exact ⟨v₁, v₂, v₃, v₄, v₅, v₆, v₇, rfl⟩

/-- `permute`'s body, from the call's fresh scope: the rounds leave `wordPermute` in `s0 s1 s2`
(by `Frag.execL_flat` and `program_spec`, through `execL_unemb`), and the tail copies them to
`r0 r1 r2`. -/
theorem permute_body (ctx : Ctx) (hlen : ctx.calldata.length ≤ 0xffffffffffff) {pre : List Stmt}
    {rs' : List Frag.Stmt} (hu : unembL pre = some (Frag.headP :: Frag.headIf :: rs'))
    (hf : Frag.flatL rs' = some program) (hw : Frag.wsL fnNames rs' = some fnNames) (a b c : ℕ)
    (m : Mem) :
    ∃ σ, execL ctx [] ⟨[("s0", a), ("s1", b), ("s2", c), ("r0", 0), ("r1", 0), ("r2", 0)], m⟩
        (pre ++ retTail) = some (.inr (⟨σ, m⟩, [])) ∧
      results σ ["r0", "r1", "r2"] =
        some [(wordPermute a b c).1, (wordPermute a b c).2.1, (wordPermute a b c).2.2] := by
  set σ₀ : Scope := [("s0", a), ("s1", b), ("s2", c), ("r0", 0), ("r1", 0), ("r2", 0)]
  set σ₁ : Scope := ("P", Zkapi.p) :: σ₀
  have h0 : Frag.execS ctx.frag σ₀ Frag.headP = some σ₁ := by
    simp [Frag.execS, Frag.headP, Frag.evalE, Scope.lookup, σ₀, σ₁]
  have h1 : Frag.execS ctx.frag σ₁ Frag.headIf = some σ₁ := by
    have : ¬ (0xffffffffffff < ctx.calldata.length) := by omega
    simp [Frag.execS, Frag.headIf, Frag.evalE, Frag.evalArgs, Frag.builtin, Ctx.frag, this]
  have hA : Frag.Agree σ₁ (initEnv a b c) := by
    intro x v hx
    simp only [σ₁, σ₀, List.mem_cons, Prod.mk.injEq, List.not_mem_nil, or_false] at hx
    rcases hx with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ |
      ⟨rfl, rfl⟩
    · exact ⟨fun _ => rfl, fun u hu => absurd hu.symm (Frag.name_ne_P u)⟩
    all_goals
      refine ⟨fun h => absurd h (by decide), fun u hu => ?_⟩
      cases u <;> first | rfl | exact absurd hu (by decide)
  have hn : (Scope.names σ₁).Nodup := by simp [σ₁, σ₀, Scope.names]
  have hnames : Scope.names σ₁ = fnNames := rfl
  obtain ⟨σ₂, e2, n2, -, a2⟩ :=
    Frag.execL_flat ctx.frag rs' σ₁ (initEnv a b c) program fnNames hf (hnames ▸ hw) hn hA
  obtain ⟨v₁, v₂, v₃, v₄, v₅, v₆, v₇, rfl⟩ := names_seven n2
  have g (x : String) (u : Var) (v : ℕ)
      (hm : (x, v) ∈ [("P", v₁), ("s0", v₂), ("s1", v₃), ("s2", v₄), ("r0", v₅), ("r1", v₆),
        ("r2", v₇)]) (hu : x = u.name) :
      v = Zkapi.Lazy.exec program (initEnv a b c) u := (a2 x v hm).2 u hu
  have g2 := g "s0" .s0 v₂ (by simp) rfl
  have g3 := g "s1" .s1 v₃ (by simp) rfl
  have g4 := g "s2" .s2 v₄ (by simp) rfl
  have hpre : Frag.execL ctx.frag σ₀ (Frag.headP :: Frag.headIf :: rs') =
      some [("P", v₁), ("s0", v₂), ("s1", v₃), ("s2", v₄), ("r0", v₅), ("r1", v₆), ("r2", v₇)] := by
    simp only [Frag.execL, h0, h1, e2]
  have hpoc := execL_unemb ctx pre _ σ₀ _ m hu hpre
  refine ⟨[("P", v₁), ("s0", v₂), ("s1", v₃), ("s2", v₄), ("r0", v₂), ("r1", v₃), ("r2", v₄)], ?_, ?_⟩
  · rw [execL_append, hpoc]
    simp [retTail, execL, execS, rhs, evalE, Scope.lookup, Scope.set, assignAll]
  · simp [results, Scope.lookup, g2, g3, g4, wordPermute]

/-- The meaning the definition `function permute(s0, s1, s2) -> r0, r1, r2 { body }` gives
`permute` (`execS` of `funDef`, with no function defined before it). -/
def permFn (ctx : Ctx) (body : List Stmt) : Fn := fun vs m =>
  match frame ["s0", "s1", "s2"] ["r0", "r1", "r2"] vs with
  | none => none
  | some σ =>
    match execL ctx [] ⟨σ, m⟩ body with
    | some (.inr (st', _)) => (results st'.scope ["r0", "r1", "r2"]).map fun outs => .inr (outs, st'.mem)
    | some (.inl h) => some (.inl h)
    | none => none

theorem exec_funDef (ctx : Ctx) (st : St) (body : List Stmt) :
    execS ctx [] st (.funDef "permute" ["s0", "s1", "s2"] ["r0", "r1", "r2"] body) =
      some (.inr (st, [("permute", permFn ctx body)])) := by
  rw [execS]; rfl

/-- `F` computes `P` on three words and leaves memory alone. -/
def Computes (F : Fn) (P : ℕ → ℕ → ℕ → ℕ × ℕ × ℕ) : Prop :=
  ∀ a b c m, F [a, b, c] m = some (.inr ([(P a b c).1, (P a b c).2.1, (P a b c).2.2], m))

/-- A function that computes the permutation on words and leaves memory alone. -/
def IsPermute (F : Fn) : Prop := Computes F wordPermute

/-- **The runtime's `permute` computes the permutation.** The parsed assembly block starts with
the definition of `permute`, followed by the short-calldata check and the dispatcher; the
function that definition gives `permute`, called with any words `a b c` and any memory, returns
`wordPermute a b c` (the canonical representatives of the reference permutation of `(a, b, c)`
reduced mod p, `Zkapi.Lazy.wordPermute_eq`) and leaves memory unchanged. The hypothesis is that
the never-taken branch is not taken: the calldata is shorter than `2^48` bytes (a transaction's
gas limit keeps it far below that). -/
theorem yul_permute :
    ∃ body, blockAst =
        [.funDef "permute" ["s0", "s1", "s2"] ["r0", "r1", "r2"] body, ifShort, dispatch] ∧
      ∀ ctx : Ctx, ctx.calldata.length ≤ 0xffffffffffff → IsPermute (permFn ctx body) := by
  obtain ⟨pre, rs', hb, hu, hf, hw⟩ := blockAst_spec
  refine ⟨pre ++ retTail, hb, fun ctx hlen a b c m => ?_⟩
  obtain ⟨σ, hbody, hres⟩ := permute_body ctx hlen hu hf hw a b c m
  simp only [permFn, frame, List.length_cons, List.length_nil, ite_true, List.zip_cons_cons,
    List.zip_nil_right, List.map_cons, List.map_nil, List.cons_append, List.nil_append, hbody,
    hres, Option.map_some]

end Zkapi.Yul
