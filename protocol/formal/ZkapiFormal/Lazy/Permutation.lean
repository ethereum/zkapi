import ZkapiFormal.Lazy.Program

/-! # The unrolled program computes zkAPI's Poseidon

`program_spec`: for all inputs `a b c` (words of any size), every `ADD` in the 65 rounds adds
two values whose exact sum is below `2^256`, and the outputs are canonical (below `p`) and equal
the scaled permutation, hence the reference permutation, of the inputs reduced mod p
(`wordPermute_eq`). `compressWord` and `hash5Word` compose `wordPermute` the way
The runtime's `compress` and `hash5` compose `permute` (with `addmod` between the sponge's
permutations), and equal zkAPI's `compress` and `hash5` on the reduced inputs. -/

namespace Zkapi.Lazy

open Zkapi.Poseidon (State Mat mix sbox iterate)

set_option maxRecDepth 100000

/-- Every constant the program adds lazily is canonical. -/
theorem fullK_lt : ∀ r : Fin 8, ∀ i : Fin 3, fullK r i < p := by decide +kernel

theorem scaledN_lt : ∀ j : Fin 56, scaledN j 0 < p := by decide +kernel

theorem lastKN_lt : ∀ i : Fin 3, lastKN i < p := by decide +kernel

/-! The lane bounds the program threads (multiples of `p`): below `3p` after every full round;
during the partial rounds lane 0 stays below `3p` and lanes 1 and 2 cycle through
`3, 4, 5, 1, 2` (reduced by `addmod` every fifth round), ending at `4p` before round 60; canonical
after the last round. -/

theorem round0_bounds : round0.2 = ⟨3, 3, 3⟩ := by decide +kernel

theorem phase1_bounds : phase1.2 = ⟨3, 3, 3⟩ := by decide +kernel

theorem phase2_bounds : phase2.2 = ⟨3, 4, 4⟩ := by decide +kernel

theorem phase3_bounds : phase3.2 = ⟨3, 3, 3⟩ := by decide +kernel

/-- The bounds after the last round: every output lane is below `p`. -/
theorem phase4_bounds : phase4.2 = ⟨1, 1, 1⟩ := by decide +kernel

theorem renderList_spec {α : Type} (step : α → Bounds → List Stmt × Bounds)
    (fstep : α → State → State)
    (hstep : ∀ r bd env σ, Inv bd env σ →
      Safe (step r bd).1 env ∧ Inv (step r bd).2 (exec (step r bd).1 env) (fstep r σ)) :
    ∀ (rs : List α) (bd : Bounds) (env : Env) (σ : State), Inv bd env σ →
      Safe (renderList step rs bd).1.flatten env ∧
        Inv (renderList step rs bd).2 (exec (renderList step rs bd).1.flatten env)
          (rs.foldl (fun s r => fstep r s) σ)
  | [], _, _, _, h => ⟨trivial, h⟩
  | r :: rs, bd, env, σ, h => by
    obtain ⟨hs, hi⟩ := hstep r bd env σ h
    obtain ⟨hs', hi'⟩ := renderList_spec step fstep hstep rs _ _ _ hi
    simp only [renderList, List.flatten_cons, List.foldl_cons]
    rw [safe_append, exec_append]
    exact ⟨⟨hs, hs'⟩, hi'⟩

theorem iterate_eq_foldl {n : ℕ} (step : Fin n → State → State) (s : State) :
    iterate step s = (List.finRange n).foldl (fun s r => step r s) s := by
  unfold iterate
  rfl

theorem iterate_succ {n : ℕ} (step : Fin (n + 1) → State → State) (s : State) :
    iterate step s = (List.finRange n).foldl (fun s r => step r.succ s) (step 0 s) := by
  rw [iterate_eq_foldl, List.finRange_succ, List.foldl_cons, List.foldl_map]

/-- The inputs in `s0 s1 s2`; the scratch variables start at zero (they are written before
they are read). -/
def initEnv (a b c : ℕ) : Env
  | .s0 => a
  | .s1 => b
  | .s2 => c
  | _ => 0

/-- **The unrolled program.** No `ADD` overflows, and the outputs are canonical and are the
scaled permutation of the inputs. -/
theorem program_spec (a b c : ℕ) :
    Safe program (initEnv a b c) ∧
      Inv ⟨1, 1, 1⟩ (exec program (initEnv a b c)) (Poseidon.Scaled.permute ![(a : F), b, c]) := by
  have h0 := full_first_spec (fullK 0) mdsN ⟨1, 1, 1⟩ (initEnv a b c) ![(a : F), b, c] rfl rfl rfl
  have h1 := renderList_spec prefixStep (fun r => Poseidon.Sparse.prefixRound r.succ)
    (fun r bd env σ h => full_spec (fullK ⟨r.val + 1, by omega⟩) (fullK_lt _) mdsN false bd env σ h)
    (List.finRange 3) round0.2 _ _ h0.2
  have h2 := renderList_spec partialStep Poseidon.Scaled.partialRound
    (fun j bd env σ h => partial_spec (scaledN j 0) (scaledN j 1) (scaledN j 2) (scaledN j 3)
      (scaledN j 4) (scaledN_lt j) bd env σ h)
    (List.finRange 56) phase1.2 _ _ h1.2
  have h3 := last_spec lastKN lastKN_lt lastMN phase2.2 _ _ h2.2
  have h4 := renderList_spec suffixStep Poseidon.Sparse.suffixRound
    (fun r bd env σ h => full_spec (fullK ⟨r.val + 4, by omega⟩) (fullK_lt _) mdsN (r.val == 3)
      bd env σ h)
    (List.finRange 4) phase3.2 _ _ h3.2
  have hperm : Poseidon.Scaled.permute ![(a : F), b, c] =
      (List.finRange 4).foldl (fun s r => Poseidon.Sparse.suffixRound r s)
        (mix (matF lastMN) ![
          sbox ((List.finRange 56).foldl (fun s r => Poseidon.Scaled.partialRound r s)
            ((List.finRange 3).foldl (fun s r => Poseidon.Sparse.prefixRound r.succ s)
              (mix (matF mdsN) (fun i => sbox (![(a : F), b, c] i + fullK 0 i)))) 0 + lastKN 0),
          (List.finRange 56).foldl (fun s r => Poseidon.Scaled.partialRound r s)
            ((List.finRange 3).foldl (fun s r => Poseidon.Sparse.prefixRound r.succ s)
              (mix (matF mdsN) (fun i => sbox (![(a : F), b, c] i + fullK 0 i)))) 1 + lastKN 1,
          (List.finRange 56).foldl (fun s r => Poseidon.Scaled.partialRound r s)
            ((List.finRange 3).foldl (fun s r => Poseidon.Sparse.prefixRound r.succ s)
              (mix (matF mdsN) (fun i => sbox (![(a : F), b, c] i + fullK 0 i)))) 2 + lastKN 2]) := by
    unfold Poseidon.Scaled.permute
    rw [iterate_eq_foldl, iterate_eq_foldl, iterate_succ]
    rfl
  change Safe phase1.1.flatten _ ∧ Inv phase1.2 (exec phase1.1.flatten _) _ at h1
  change Safe phase2.1.flatten _ ∧ Inv phase2.2 (exec phase2.1.flatten _) _ at h2
  change Safe phase3.1 _ ∧ Inv phase3.2 (exec phase3.1 _) _ at h3
  change Safe phase4.1.flatten _ ∧ Inv phase4.2 (exec phase4.1.flatten _) _ at h4
  rw [phase4_bounds] at h4
  rw [hperm]
  refine ⟨?_, ?_⟩
  · simp only [program, rounds, List.flatten_cons, List.flatten_append, List.append_assoc,
      safe_append]
    exact ⟨h0.1, h1.1, h2.1, h3.1, h4.1⟩
  · simp only [program, rounds, List.flatten_cons, List.flatten_append, List.append_assoc,
      exec_append]
    exact h4.2

/-- The program's three outputs. -/
def wordPermute (a b c : ℕ) : ℕ × ℕ × ℕ :=
  let e := exec program (initEnv a b c)
  (e .s0, e .s1, e .s2)

/-- **The unrolled program computes the reference permutation**: its outputs are the canonical
representatives of `Poseidon.permute` of the inputs reduced mod p. -/
theorem wordPermute_eq (a b c : ℕ) :
    wordPermute a b c =
      ((Poseidon.permute ![(a : F), b, c] 0).val, (Poseidon.permute ![(a : F), b, c] 1).val,
        (Poseidon.permute ![(a : F), b, c] 2).val) := by
  obtain ⟨-, h0, h1, h2⟩ := program_spec a b c
  rw [Poseidon.Scaled.permute_eq_reference] at h0 h1 h2
  simp only [wordPermute, h0.eq_val, h1.eq_val, h2.eq_val]

theorem wordPermute_safe (a b c : ℕ) : Safe program (initEnv a b c) := (program_spec a b c).1

/-- Every literal of the program is a word. -/
theorem program_lits : ∀ s ∈ program, s.litsBelow W = true := by decide +kernel

theorem initEnv_lt_W {a b c : ℕ} (ha : a < W) (hb : b < W) (hc : c < W) :
    ∀ v, initEnv a b c v < W := by
  intro v
  cases v <;> simp only [initEnv, ha, hb, hc] <;> decide

/-- With word inputs, every variable holds a word after every statement of the program (any
prefix `program.take n`), and so does every expression it evaluates (`Expr.eval_lt_W`, which
applies to subexpressions too): the natural-number semantics is the EVM's word semantics
throughout. -/
theorem program_words_prefix (a b c : ℕ) (ha : a < W) (hb : b < W) (hc : c < W) (n : ℕ) :
    ∀ v, exec (program.take n) (initEnv a b c) v < W :=
  exec_lt_W _ _ (initEnv_lt_W ha hb hc) fun s hs => program_lits s (List.mem_of_mem_take hs)

/-- The final environment, the case `n ≥ program.length` of `program_words_prefix`. -/
theorem program_words (a b c : ℕ) (ha : a < W) (hb : b < W) (hc : c < W) :
    ∀ v, exec program (initEnv a b c) v < W :=
  exec_lt_W program _ (initEnv_lt_W ha hb hc) program_lits

/-- The runtime's `compress(capacity, left, right)` on words. -/
def compressWord (capacity left right : ℕ) : ℕ := (wordPermute capacity left right).2.1

/-- The runtime's `hash5(a, b, c, d, e)` on words: three permutations with `addmod` between them,
as its dispatcher computes it, from a zero capacity. (The runtime computes that zero as
`shr(255, calldatasize())`, which is 0 for calldata shorter than `2^255` bytes;
`Zkapi.Yul.exec_hash5Arm` runs it.) -/
def hash5Word (a b c d e : ℕ) : ℕ :=
  let s := wordPermute 0 a b
  let t := wordPermute s.1 (evmAddmod s.2.1 c) (evmAddmod s.2.2 d)
  (wordPermute t.1 (evmAddmod t.2.1 e) t.2.2).2.1

theorem compressWord_eq (capacity left right : ℕ) :
    compressWord capacity left right = (Poseidon.compress capacity left right).val := by
  simp only [compressWord, wordPermute_eq, Poseidon.compress]

theorem hash5Word_eq (a b c d e : ℕ) :
    hash5Word a b c d e = (Poseidon.hash5 a b c d e).val := by
  have absorb2 (s : State) (x y : ℕ) :
      ![(((Poseidon.permute s 0).val : ℕ) : F), ((evmAddmod (Poseidon.permute s 1).val x : ℕ) : F),
        ((evmAddmod (Poseidon.permute s 2).val y : ℕ) : F)] = Poseidon.permute s + ![0, (x : F), (y : F)] := by
    funext i
    fin_cases i <;> simp [cast_evmAddmod]
  have absorb1 (s : State) (x : ℕ) :
      ![(((Poseidon.permute s 0).val : ℕ) : F), ((evmAddmod (Poseidon.permute s 1).val x : ℕ) : F),
        (((Poseidon.permute s 2).val : ℕ) : F)] = Poseidon.permute s + ![0, (x : F), 0] := by
    funext i
    fin_cases i <;> simp [cast_evmAddmod]
  simp only [hash5Word, wordPermute_eq, Poseidon.hash5, Nat.cast_zero, absorb2, absorb1]

end Zkapi.Lazy
