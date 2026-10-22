import ZkapiFormal.Yul.Permute
import ZkapiFormal.Lazy.Paths

/-! # The runtime's four entry points, for all calldata

`runtime_block` states what the runtime's assembly block (parsed by the kernel,
`ZkapiFormal.Yul.Permute`) does for **every** calldata shorter than `2^48` bytes and any initial
memory, in the Yul semantics of `ZkapiFormal.Yul.Semantics`: it halts as `runtimeSpec` says.
`runtime_fallback` adds solc's code around the block (`fallbackRun`: the call value is rejected).
`runtimeSpec` is solc's ABI decoding of the replaced library's four public functions, followed
by the word-level functions `compressWord`, `hash5Word`, `insertPath32Word` and
`compressPairPath32Word`, which `ZkapiFormal.Lazy` equates with zkAPI's Poseidon, `compress`,
sponge and Merkle paths (`runtime_compress`, `runtime_hash5`, `runtime_insertPath32`,
`runtime_compressPairPath32`).

The proofs never unfold the semantics on `permute`'s code: the dispatcher's arms are proved for
any function `F` that computes the permutation (`IsPermute F`), and `yul_permute` provides the
runtime's. The loops use the bounded loop lemma `exec_for` with the loop invariants of
`Zkapi.Lazy.insertStep` and `Zkapi.Lazy.pairStep`. -/

namespace Zkapi.Yul

open Zkapi.Lazy (W wordPermute compressWord hash5Word insertPath32Word compressPairPath32Word
  insertStep pairStep stepW bitW)

/-! ## The specification -/

/-- The 32-byte big-endian encoding of a word (the ABI encoding of a `uint256`). -/
def be32 (v : ℕ) : List ℕ := (List.range 32).map fun k => v / 256 ^ (31 - k) % 256

/-- The function selector: the first 4 bytes of the calldata. -/
def selector (cd : List ℕ) : ℕ := cdWord cd 0 / 2 ^ 224

/-- The siblings of a `uint256[32]` argument at byte offset `base`: element `l` is the calldata
word at `base + 32 l`. -/
def sibAt (cd : List ℕ) (base : ℕ) : ℕ → ℕ := fun l => cdWord cd (base + 32 * l)

/-- **What the runtime must do with calldata `cd`**: what the replaced library's public functions
did, decoded as solc's ABI decoder decodes their arguments.

* Fewer than 4 bytes, or a selector that is not one of the four: `revert` with no data.
* `compress(uint256,uint256,uint256)`, `hash5(uint256 × 5)`,
  `insertPath32(uint256,uint32,uint256,uint256[32])` and
  `compressPairPath32(uint256,uint32,uint256,uint256,uint256[32],uint256)`: solc's decoder reverts
  with no data when the arguments are shorter than their head (96, 160, 1120 and 1184 bytes after
  the selector) and when `index`, a `uint32`, is not a clean word (`2^32 ≤ index`). Otherwise the
  arguments are the calldata words at their offsets, and the function returns the ABI encoding of
  its results.

The results are the word-level functions of `ZkapiFormal.Lazy` (`compressWord_eq`,
`hash5Word_eq`, `insertPath32Word_eq`, `insertPath32Word_root`, `compressPairPath32Word_eq`). -/
def runtimeSpec (cd : List ℕ) : Halt :=
  if cd.length < 4 then .rev []
  else if selector cd = selCompress then
    if cd.length < 4 + 96 then .rev []
    else .ret (be32 (compressWord (cdWord cd 4) (cdWord cd 36) (cdWord cd 68)))
  else if selector cd = selHash5 then
    if cd.length < 4 + 160 then .rev []
    else .ret (be32 (hash5Word (cdWord cd 4) (cdWord cd 36) (cdWord cd 68) (cdWord cd 100)
      (cdWord cd 132)))
  else if selector cd = selInsertPath32 then
    if cd.length < 4 + 1120 then .rev []
    else if 2 ^ 32 ≤ cdWord cd 36 then .rev []
    else
      let r := insertPath32Word (cdWord cd 4) (cdWord cd 36) (cdWord cd 68) (sibAt cd 100)
      .ret (be32 r.1 ++ be32 r.2)
  else if selector cd = selCompressPairPath32 then
    if cd.length < 4 + 1184 then .rev []
    else if 2 ^ 32 ≤ cdWord cd 36 then .rev []
    else
      let r := compressPairPath32Word (cdWord cd 4) (cdWord cd 36) (cdWord cd 68) (cdWord cd 100)
        (sibAt cd 132) (cdWord cd 1156)
      .ret (be32 r.1 ++ be32 r.2.1 ++ be32 r.2.2)
  else .rev []

/-! ## Memory -/

theorem bytesOf_add (m : Mem) (p n k : ℕ) :
    bytesOf m p (n + k) = bytesOf m p n ++ bytesOf m (p + n) k := by
  simp only [bytesOf, List.range_add, List.map_append, List.map_map]
  congr 1
  apply List.map_congr_left
  intro i _
  simp [Nat.add_assoc]

theorem bytesOf_mstore_self (m : Mem) (p v : ℕ) : bytesOf (mstore m p v) p 32 = be32 v := by
  simp only [bytesOf, be32, mstore]
  apply List.map_congr_left
  intro k hk
  have : k < 32 := List.mem_range.1 hk
  simp [this]

theorem bytesOf_mstore_other (m : Mem) (p n q v : ℕ) (h : p + n ≤ q ∨ q + 32 ≤ p) :
    bytesOf (mstore m q v) p n = bytesOf m p n := by
  simp only [bytesOf, mstore]
  apply List.map_congr_left
  intro k hk
  have : k < n := List.mem_range.1 hk
  have : ¬ (q ≤ p + k ∧ p + k < q + 32) := by omega
  simp [this]

theorem bytesOf_ret1 (m : Mem) (a : ℕ) : bytesOf (mstore m 0x80 a) 0x80 0x20 = be32 a :=
  bytesOf_mstore_self m 0x80 a

theorem bytesOf_ret2 (m : Mem) (a b : ℕ) :
    bytesOf (mstore (mstore m 0x80 a) 0xa0 b) 0x80 0x40 = be32 a ++ be32 b := by
  rw [show (0x40 : ℕ) = 32 + 32 from rfl, bytesOf_add, bytesOf_mstore_other _ _ _ _ _ (by omega),
    bytesOf_mstore_self, show (0x80 + 32 : ℕ) = 0xa0 from rfl, bytesOf_mstore_self]

theorem bytesOf_ret3 (m : Mem) (a b c : ℕ) :
    bytesOf (mstore (mstore (mstore m 0x80 a) 0xa0 b) 0xc0 c) 0x80 0x60 =
      be32 a ++ be32 b ++ be32 c := by
  rw [show (0x60 : ℕ) = 32 + 32 + 32 from rfl, bytesOf_add, bytesOf_add,
    bytesOf_mstore_other _ _ _ _ _ (by omega), bytesOf_mstore_other _ _ _ _ _ (by omega),
    bytesOf_mstore_self, show (0x80 + 32 : ℕ) = 0xa0 from rfl,
    bytesOf_mstore_other _ _ _ _ _ (by omega), bytesOf_mstore_self,
    show (0xa0 + 32 : ℕ) = 0xc0 from rfl, bytesOf_mstore_self]

/-! ## Word arithmetic of the checks -/

theorem toInt_small {a : ℕ} (h : a < 2 ^ 255) : toInt a = a := by
  unfold toInt
  split
  · rfl
  · contradiction

/-- `sub(calldatasize(), 4)` on calldata of `4` to `2^48` bytes. -/
theorem sub_four {n : ℕ} (h4 : 4 ≤ n) (hn : n ≤ 0xffffffffffff) : (n + (W - 4 % W)) % W = n - 4 := by
  have hW : (W : ℕ) = 2 ^ 256 := rfl
  rw [hW, show (4 : ℕ) % 2 ^ 256 = 4 by norm_num,
    show n + (2 ^ 256 - 4) = (n - 4) + 2 ^ 256 by omega, Nat.add_mod_right,
    Nat.mod_eq_of_lt (by omega)]

/-- `slt(sub(calldatasize(), 4), k)`: the signed comparison is the unsigned one here. -/
theorem slt_small {a k : ℕ} (ha : a < 2 ^ 255) (hk : k < 2 ^ 255) :
    (if toInt a < toInt k then 1 else 0) = (if a < k then 1 else 0) := by
  rw [toInt_small ha, toInt_small hk]
  by_cases h : a < k <;> simp [h]

/-- solc's `uint32` check: `index` equals `and(index, 0xffffffff)` iff it is below `2^32`. -/
theorem clean_uint32 (i : ℕ) : (i = i &&& 0xffffffff) ↔ i < 2 ^ 32 := by
  rw [show (0xffffffff : ℕ) = 2 ^ 32 - 1 by norm_num, Nat.and_two_pow_sub_one_eq_mod]
  constructor
  · intro h; rw [h]; exact Nat.mod_lt _ (by norm_num)
  · intro h; rw [Nat.mod_eq_of_lt h]

/-- The sibling's offset `add(base, shl(5, level))`. -/
theorem sibling_offset {base k : ℕ} (hb : base ≤ 132) (hk : k < 32) :
    (base + (if 5 < 256 then k * 2 ^ 5 % W else 0)) % W = base + 32 * k := by
  have hW : (W : ℕ) = 2 ^ 256 := rfl
  simp only [show (5 : ℕ) < 256 by norm_num, ite_true, hW]
  rw [Nat.mod_eq_of_lt (show k * 2 ^ 5 < 2 ^ 256 by omega), Nat.mod_eq_of_lt (by omega)]
  ring

/-- `and(shr(level, index), 1)` is the loops' bit. -/
theorem bit_eq {k i : ℕ} (hk : k < 32) : (if k < 256 then i / 2 ^ k else 0) &&& 1 = bitW i k := by
  simp [show k < 256 by omega, bitW, Nat.shiftRight_eq_div_pow]

theorem bitW_le_one (i k : ℕ) : bitW i k = 0 ∨ bitW i k = 1 := by
  unfold bitW
  rcases Nat.mod_two_eq_zero_or_one (i >>> k) with h | h
  · left; rw [Nat.and_one_is_mod, h]
  · right; rw [Nat.and_one_is_mod, h]

/-! ## The checks -/

section
variable {ctx : Ctx} {fs : Funs} {st : St}

theorem exec_revertBlock : closeBlock st fs (execL ctx fs st [revert00]) = some (.inl (.rev [])) := by
  rw [execL_singleton, revert00, exec_revert00]; rfl

theorem exec_ifShort :
    execS ctx fs st ifShort =
      if ctx.calldata.length < 4 then some (.inl (.rev [])) else some (.inr (st, fs)) := by
  by_cases h : ctx.calldata.length < 4
  · rw [ifShort, exec_if_ne (v := 1) (by simp [evalE_call, evalArgs_cons, h]) one_ne_zero,
      exec_revertBlock]
    simp only [h, ite_true]
  · rw [ifShort, exec_if_zero (by simp [evalE_call, evalArgs_cons, h])]
    simp only [h, ite_false]

theorem exec_lenCheck {n : ℕ} (hn : n < 2 ^ 255) (h4 : 4 ≤ ctx.calldata.length)
    (hlen : ctx.calldata.length ≤ 0xffffffffffff) :
    execS ctx fs st (lenCheck n) =
      if ctx.calldata.length < 4 + n then some (.inl (.rev [])) else some (.inr (st, fs)) := by
  have he : evalE ctx st.scope
      (.call "slt" [.call "sub" [.call "calldatasize" [], .lit 4], .lit n]) =
      some (if ctx.calldata.length < 4 + n then 1 else 0) := by
    simp only [evalE_call, evalArgs_cons, evalArgs_nil, evalE_lit, Option.bind_some,
      Option.map_some, builtin_calldatasize, builtin_sub, builtin_slt, sub_four h4 hlen]
    rw [slt_small (by omega) hn]
    by_cases h : ctx.calldata.length < 4 + n
    · simp [h, show ctx.calldata.length - 4 < n by omega]
    · simp [h, show ¬ (ctx.calldata.length - 4 < n) by omega]
  by_cases h : ctx.calldata.length < 4 + n
  · rw [lenCheck, exec_if_ne he (by simp [h]), exec_revertBlock]
    simp only [h, ite_true]
  · rw [lenCheck, exec_if_zero (by rw [he]; simp [h])]
    simp only [h, ite_false]

theorem exec_indexCheck {i : ℕ} (hi : Scope.lookup st.scope "index" = some i) :
    execS ctx fs st indexCheck = if 2 ^ 32 ≤ i then some (.inl (.rev [])) else some (.inr (st, fs)) := by
  have he : evalE ctx st.scope
      (.call "iszero" [.call "eq" [.var "index", .call "and" [.var "index", .lit 0xffffffff]]]) =
      some (if 2 ^ 32 ≤ i then 1 else 0) := by
    simp only [evalE_call, evalArgs_cons, evalArgs_nil, evalE_lit, evalE_var, hi, Option.bind_some,
      Option.map_some, builtin_and, builtin_eq, builtin_iszero]
    by_cases h : 2 ^ 32 ≤ i
    · have : ¬ (i = i &&& 0xffffffff) := fun e => absurd ((clean_uint32 i).1 e) (by omega)
      rw [ite_eq_right_iff.2 (fun e => absurd e this)]; simp only [ite_true, h]
    · have : i = i &&& 0xffffffff := (clean_uint32 i).2 (by omega)
      rw [← this]; simp only [ite_true, h, ite_false, one_ne_zero]
  by_cases h : 2 ^ 32 ≤ i
  · rw [indexCheck, exec_if_ne he (by simp only [h, ite_true]; decide), exec_revertBlock]
    simp only [h, ite_true]
  · rw [indexCheck, exec_if_zero (by rw [he]; simp only [h, ite_false])]
    simp only [h, ite_false]

end

/-! ## The word functions, for any permutation `P`

The arms are proved for a function `F` that computes an arbitrary `P` (`Computes F P`), so the
kernel never sees `wordPermute`'s definition while checking them; `P := wordPermute` is
substituted at the end, where these definitions are the word functions of `ZkapiFormal.Lazy`
(`compressP_eq` … `pairPath32P_eq`, by `rfl`). -/

/-- A permutation of three words. -/
abbrev Perm := ℕ → ℕ → ℕ → ℕ × ℕ × ℕ

def compressP (P : Perm) (capacity left right : ℕ) : ℕ := (P capacity left right).2.1

def hash5P (P : Perm) (a b c d e : ℕ) : ℕ :=
  let s := P 0 a b
  let t := P s.1 ((s.2.1 + c) % Zkapi.p) ((s.2.2 + d) % Zkapi.p)
  (P t.1 ((t.2.1 + e) % Zkapi.p) t.2.2).2.1

def stepP (P : Perm) (capacity index : ℕ) (sib : ℕ → ℕ) (level node : ℕ) : ℕ :=
  if bitW index level = 0 then compressP P capacity node (sib level)
  else compressP P capacity (sib level) node

def insertStepP (P : Perm) (capacity index : ℕ) (sib : ℕ → ℕ) (st : ℕ × ℕ × Bool) (level : ℕ) :
    ℕ × ℕ × Bool :=
  let completed := if bitW index level = 0 ∧ st.2.2 = true then st.1 else st.2.1
  let completing := if bitW index level = 0 then false else st.2.2
  (stepP P capacity index sib level st.1, completed, completing)

def insertFold (P : Perm) (capacity index leaf : ℕ) (sib : ℕ → ℕ) (k : ℕ) : ℕ × ℕ × Bool :=
  (List.range k).foldl (insertStepP P capacity index sib) (leaf, leaf, true)

def insertPath32P (P : Perm) (capacity index leaf : ℕ) (sib : ℕ → ℕ) : ℕ × ℕ :=
  let r := insertFold P capacity index leaf sib 32
  (r.1, if r.2.2 then r.1 else r.2.1)

def pairStepP (P : Perm) (capacity index nodeLevel : ℕ) (sib : ℕ → ℕ) (st : ℕ × ℕ × ℕ)
    (level : ℕ) : ℕ × ℕ × ℕ :=
  let newNode := if level = nodeLevel then st.2.1 else st.2.2
  (stepP P capacity index sib level st.1, stepP P capacity index sib level st.2.1, newNode)

def pairFold (P : Perm) (capacity index oldLeaf newLeaf nodeLevel : ℕ) (sib : ℕ → ℕ) (k : ℕ) :
    ℕ × ℕ × ℕ :=
  (List.range k).foldl (pairStepP P capacity index nodeLevel sib) (oldLeaf, newLeaf, newLeaf)

def pairPath32P (P : Perm) (capacity index oldLeaf newLeaf : ℕ) (sib : ℕ → ℕ) (nodeLevel : ℕ) :
    ℕ × ℕ × ℕ :=
  let r := pairFold P capacity index oldLeaf newLeaf nodeLevel sib 32
  (r.1, r.2.1, if 32 ≤ nodeLevel then r.2.1 else r.2.2)

-- These bridges rewrite with the definitions' equations: a `rfl` proof (or `simp`'s closing
-- step) makes the kernel reduce the projections of `wordPermute`, i.e. the whole program.
theorem compressP_eq (c l r : ℕ) : compressP wordPermute c l r = compressWord c l r := by
  rw [compressP, compressWord]

theorem hash5P_eq (a b c d e : ℕ) : hash5P wordPermute a b c d e = hash5Word a b c d e := by
  rw [hash5P, hash5Word]; simp only [Zkapi.Lazy.evmAddmod]

theorem stepP_eq (c i : ℕ) (sib : ℕ → ℕ) : stepP wordPermute c i sib = stepW c i sib := by
  funext level node
  rw [stepP, stepW, compressP_eq, compressP_eq]

theorem insertPath32P_eq (c i l : ℕ) (sib : ℕ → ℕ) :
    insertPath32P wordPermute c i l sib = insertPath32Word c i l sib := by
  have : insertStepP wordPermute c i sib = insertStep c i sib := by
    funext st level
    simp only [insertStepP, insertStep, stepP_eq]
  simp only [insertPath32P, insertPath32Word, insertFold, this]

theorem pairPath32P_eq (c i o n : ℕ) (sib : ℕ → ℕ) (nl : ℕ) :
    pairPath32P wordPermute c i o n sib nl = compressPairPath32Word c i o n sib nl := by
  have : pairStepP wordPermute c i nl sib = pairStep c i nl sib := by
    funext st level
    simp only [pairStepP, pairStep, stepP_eq]
  simp only [pairPath32P, compressPairPath32Word, pairFold, this]

theorem insertFold_succ (P : Perm) (c i l : ℕ) (sib : ℕ → ℕ) (k : ℕ) :
    insertFold P c i l sib (k + 1) = insertStepP P c i sib (insertFold P c i l sib k) k := by
  simp [insertFold, List.range_succ, List.foldl_append]

theorem pairFold_succ (P : Perm) (c i o n nl : ℕ) (sib : ℕ → ℕ) (k : ℕ) :
    pairFold P c i o n nl sib (k + 1) = pairStepP P c i nl sib (pairFold P c i o n nl sib k) k := by
  simp [pairFold, List.range_succ, List.foldl_append]

/-! ## `compress` and `hash5` -/

section
variable {ctx : Ctx} {F : Fn} {P : Perm}

theorem exec_compressArm (hF : Computes F P) (m : Mem) (h4 : 4 ≤ ctx.calldata.length)
    (hlen : ctx.calldata.length ≤ 0xffffffffffff) :
    execL ctx [("permute", F)] ⟨[], m⟩ compressArm =
      some (.inl (if ctx.calldata.length < 4 + 96 then .rev []
        else .ret (be32 (compressP P (cdWord ctx.calldata 4) (cdWord ctx.calldata 36)
          (cdWord ctx.calldata 68))))) := by
  rw [compressArm, execL_cons, exec_lenCheck (by norm_num) h4 hlen]
  by_cases h : ctx.calldata.length < 4 + 96
  · simp only [h, ite_true]
  · simp only [h, ite_false]
    unfold Computes at hF
    simp [letPermute, cl, mstoreVar, returnLit, execL_cons, execS, rhs, Funs.find, evalArgs_cons,
      evalE_calldataload_lit, hF, declare, Scope.lookup, compressP, bytesOf_ret1]

theorem exec_hash5Arm (hF : Computes F P) (m : Mem) (h4 : 4 ≤ ctx.calldata.length)
    (hlen : ctx.calldata.length ≤ 0xffffffffffff) :
    execL ctx [("permute", F)] ⟨[], m⟩ hash5Arm =
      some (.inl (if ctx.calldata.length < 4 + 160 then .rev []
        else .ret (be32 (hash5P P (cdWord ctx.calldata 4) (cdWord ctx.calldata 36)
          (cdWord ctx.calldata 68) (cdWord ctx.calldata 100) (cdWord ctx.calldata 132))))) := by
  rw [hash5Arm, execL_cons, exec_lenCheck (by norm_num) h4 hlen]
  by_cases h : ctx.calldata.length < 4 + 160
  · simp only [h, ite_true]
  · simp only [h, ite_false]
    unfold Computes at hF
    -- `shr(255, calldatasize())` is 0.
    have hz : ctx.calldata.length / 2 ^ 255 = 0 := Nat.div_eq_of_lt (by omega)
    simp only [Nat.reducePow] at hz
    simp [letPermute, cl, mstoreVar, returnLit, execL_cons, execS, rhs, Funs.find, evalArgs_cons,
      evalE_call, hF, declare, assignAll, Scope.lookup, Scope.set, hz, Frag.p_ne_zero, hash5P,
      bytesOf_ret1]

end

/-! ## The Merkle-path loops -/

section
variable {ctx : Ctx} {F : Fn} {P : Perm} {m : Mem}

/-- `let sibling := calldataload(add(base, shl(5, level)))` at level `k`. -/
theorem exec_letSibling {base k : ℕ} (hb : base ≤ 132) (hk : k < 32) {σ : Scope}
    (hl : Scope.lookup σ "level" = some k) (hs : Scope.lookup σ "sibling" = none) :
    execS ctx [("permute", F)] ⟨σ, m⟩ (letSibling base) =
      some (.inr (⟨("sibling", cdWord ctx.calldata (base + 32 * k)) :: σ, m⟩, [("permute", F)])) := by
  have he : evalE ctx σ
      (.call "calldataload" [.call "add" [.lit base, .call "shl" [.lit 5, .var "level"]]]) =
      some (cdWord ctx.calldata (base + 32 * k)) := by
    rw [evalE_call1 (evalE_call2 (evalE_lit _ base)
      (evalE_call2 (evalE_lit _ 5) (by rw [evalE_var, hl]) (builtin_shl 5 k)) (builtin_add _ _))
      (builtin_calldataload _), sibling_offset hb hk]
  exact exec_letv (rhs_pure (by intro f args h; cases h; simp [Funs.find]) he)
    (by simp [declare, hs])

/-- `and(shr(level, index), 1)` at level `k`. -/
theorem eval_bitExpr {k i : ℕ} (hk : k < 32) {σ : Scope} (hl : Scope.lookup σ "level" = some k)
    (hi : Scope.lookup σ "index" = some i) : evalE ctx σ bitExpr = some (bitW i k) := by
  rw [bitExpr, evalE_call2 (evalE_call2 (by rw [evalE_var, hl]) (by rw [evalE_var, hi])
    (builtin_shr k i)) (evalE_lit _ 1) (builtin_and _ _), bit_eq hk]

/-- The loop's `lt(level, 32)`. -/
theorem eval_lt32 {k : ℕ} {σ : Scope} (hl : Scope.lookup σ "level" = some k) :
    evalE ctx σ (.call "lt" [.var "level", .lit 32]) = some (if k < 32 then 1 else 0) :=
  evalE_call2 (by rw [evalE_var, hl]) (evalE_lit _ 32) (builtin_lt _ _)

/-- The loop's post block `level := add(level, 1)`. -/
theorem exec_post {k : ℕ} (hk : k < 32) (rest : Scope) :
    closeBlock ⟨("level", k) :: rest, m⟩ [("permute", F)]
      (execL ctx [("permute", F)] ⟨("level", k) :: rest, m⟩
        [.assign ["level"] (.call "add" [.var "level", .lit 1])]) =
      some (.inr (⟨("level", k + 1) :: rest, m⟩, [("permute", F)])) := by
  have he : evalE ctx (("level", k) :: rest) (.call "add" [.var "level", .lit 1]) = some (k + 1) := by
    rw [evalE_call2 (by rw [evalE_var, lookup_cons_eq]) (evalE_lit _ 1) (builtin_add _ _),
      Nat.mod_eq_of_lt (show k + 1 < W by unfold W; omega)]
  rw [execL_singleton, exec_assign (σ := ("level", k + 1) :: rest)
    (rhs_pure (by intro f args h; cases h; simp [Funs.find]) he)
    (by simp [assignAll, Scope.set]), closeBlock_inr]
  simp [exitBlock]

/-! ### `insertPath32` -/

/-- The variables of `insertPath32`'s arm before and after the loop, for the state `t` =
`(root, completed, completing)`. -/
def insRest (c i : ℕ) (t : ℕ × ℕ × Bool) : Scope :=
  [("completing", if t.2.2 then 1 else 0), ("completed", t.2.1), ("root", t.1), ("capacity", c),
    ("index", i)]

/-- One iteration of `insertPath32`'s loop is `insertStepP`. -/
theorem insert_iter (hF : Computes F P) {k : ℕ} (hk : k < 32) (c i : ℕ) (t : ℕ × ℕ × Bool) :
    Iter ctx [("permute", F)] insertBody [.assign ["level"] (.call "add" [.var "level", .lit 1])]
      ⟨("level", k) :: insRest c i t, m⟩
      ⟨("level", k + 1) :: insRest c i (insertStepP P c i (sibAt ctx.calldata 100) t k), m⟩ := by
  refine ⟨⟨("level", k) :: insRest c i (insertStepP P c i (sibAt ctx.calldata 100) t k), m⟩, ?_,
    exec_post hk _⟩
  rw [insertBody, execL_cons_inr (exec_letSibling (by norm_num) hk (by simp [Scope.lookup])
      (by simp [insRest, Scope.lookup])), execL_singleton,
    exec_switch (eval_bitExpr (i := i) hk (by simp [Scope.lookup]) (by simp [insRest, Scope.lookup])),
    execArms_case, execArms_default]
  unfold Computes at hF
  obtain ⟨r, cpl, b⟩ := t
  rcases bitW_le_one i k with hb | hb <;> cases b <;>
    simp [hb, letPermute, execL_cons, execL_nil, execS, rhs, Funs.find, evalArgs_cons, hF, declare, assignAll,
      Scope.lookup, Scope.set, closeBlock, exitBlock, insRest, insertStepP, stepP, compressP, sibAt]

/-- `insertPath32`'s loop runs 32 iterations of `insertStepP`. -/
theorem exec_insertLoop (hF : Computes F P) (c i leaf : ℕ) :
    execS ctx [("permute", F)] ⟨insRest c i (leaf, leaf, true), m⟩ (for32 insertBody) =
      some (.inr (⟨insRest c i (insertFold P c i leaf (sibAt ctx.calldata 100) 32), m⟩,
        [("permute", F)])) := by
  have h := exec_for (ctx := ctx) (fs := [("permute", F)]) (st := ⟨insRest c i (leaf, leaf, true), m⟩)
    (init := [.letv ["level"] (.lit 0)]) (c := .call "lt" [.var "level", .lit 32])
    (post := [.assign ["level"] (.call "add" [.var "level", .lit 1])]) (body := insertBody)
    (fs₁ := [("permute", F)])
    (fun k => ⟨("level", k) :: insRest c i (insertFold P c i leaf (sibAt ctx.calldata 100) k), m⟩) 32
    (by
      rw [execL_singleton]
      exact exec_letv (rhs_pure (by intro f args h; cases h) (evalE_lit _ 0))
        (by simp [declare, insRest, Scope.lookup, insertFold]))
    (fun k hk => ⟨1, by rw [eval_lt32 (lookup_cons_eq _ _ _)]; simp [hk], one_ne_zero⟩)
    (by rw [eval_lt32 (lookup_cons_eq _ _ _)]; simp)
    (fun k hk => by rw [insertFold_succ]; exact insert_iter hF hk c i _)
    (by unfold loopFuel; norm_num)
  rw [for32, h]
  simp [exitBlock, insRest]

/-- **`insertPath32`'s arm.** -/
theorem exec_insertArm (hF : Computes F P) (m : Mem) (h4 : 4 ≤ ctx.calldata.length)
    (hlen : ctx.calldata.length ≤ 0xffffffffffff) :
    execL ctx [("permute", F)] ⟨[], m⟩ insertArm =
      some (.inl (if ctx.calldata.length < 4 + 1120 then .rev []
        else if 2 ^ 32 ≤ cdWord ctx.calldata 36 then .rev []
        else
          let r := insertPath32P P (cdWord ctx.calldata 4) (cdWord ctx.calldata 36)
            (cdWord ctx.calldata 68) (sibAt ctx.calldata 100)
          .ret (be32 r.1 ++ be32 r.2))) := by
  rw [insertArm, execL_cons, exec_lenCheck (by norm_num) h4 hlen]
  by_cases h : ctx.calldata.length < 4 + 1120
  · simp only [h, ite_true]
  · simp only [h, ite_false]
    set i := cdWord ctx.calldata 36
    set c := cdWord ctx.calldata 4
    set leaf := cdWord ctx.calldata 68
    have h1 : execS ctx [("permute", F)] ⟨[], m⟩ (.letv ["index"] (cl 36)) =
        some (.inr (⟨[("index", i)], m⟩, [("permute", F)])) := by
      simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, i]
    rw [execL_cons_inr h1, execL_cons, exec_indexCheck (i := i) (by simp [Scope.lookup])]
    by_cases hi : 2 ^ 32 ≤ i
    · simp only [hi, ite_true]
    · simp only [hi, ite_false]
      have hc1 : execS ctx [("permute", F)] ⟨[("index", i)], m⟩ (.letv ["capacity"] (cl 4)) =
          some (.inr (⟨[("capacity", c), ("index", i)], m⟩, [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, c]
      have hc2 : execS ctx [("permute", F)] ⟨[("capacity", c), ("index", i)], m⟩
          (.letv ["root"] (cl 68)) =
          some (.inr (⟨[("root", leaf), ("capacity", c), ("index", i)], m⟩, [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, leaf]
      have hc3 : execS ctx [("permute", F)] ⟨[("root", leaf), ("capacity", c), ("index", i)], m⟩
          (.letv ["completed"] (.var "root")) =
          some (.inr (⟨[("completed", leaf), ("root", leaf), ("capacity", c), ("index", i)], m⟩,
            [("permute", F)])) := by
        simp [execS, rhs, declare, Scope.lookup]
      have hc4 : execS ctx [("permute", F)]
          ⟨[("completed", leaf), ("root", leaf), ("capacity", c), ("index", i)], m⟩
          (.letv ["completing"] (.lit 1)) =
          some (.inr (⟨insRest c i (leaf, leaf, true), m⟩, [("permute", F)])) := by
        simp [execS, rhs, declare, Scope.lookup, insRest]
      rw [execL_cons_inr hc1, execL_cons_inr hc2, execL_cons_inr hc3, execL_cons_inr hc4,
        execL_cons_inr (exec_insertLoop hF c i leaf)]
      unfold insertPath32P
      generalize insertFold P c i leaf (sibAt ctx.calldata 100) 32 = R
      obtain ⟨r, cpl, b⟩ := R
      cases b <;>
        simp [execL_cons, execL_nil, execS, rhs, evalArgs_cons, assignAll, Scope.lookup,
          Scope.set, closeBlock, exitBlock, insRest, mstoreVar, returnLit, bytesOf_ret2]

/-! ### `compressPairPath32` -/

/-- The variables of `compressPairPath32`'s arm before and after the loop, for the state `t` =
`(oldRoot, newRoot, newNode)`. -/
def pairRest (c i nl : ℕ) (t : ℕ × ℕ × ℕ) : Scope :=
  [("nodeLevel", nl), ("newNode", t.2.2), ("newRoot", t.2.1), ("oldRoot", t.1), ("capacity", c),
    ("index", i)]

/-- The loop body's first statement, `if eq(level, nodeLevel) { newNode := newRoot }`. -/
theorem exec_pairIf {k : ℕ} (c i nl : ℕ) (t : ℕ × ℕ × ℕ) :
    execS ctx [("permute", F)] ⟨("level", k) :: pairRest c i nl t, m⟩
      (.ifs (.call "eq" [.var "level", .var "nodeLevel"]) [.assign ["newNode"] (.var "newRoot")]) =
      some (.inr (⟨("level", k) :: pairRest c i nl (t.1, t.2.1, if k = nl then t.2.1 else t.2.2), m⟩,
        [("permute", F)])) := by
  obtain ⟨o, n, nn⟩ := t
  by_cases hk : k = nl
  · subst hk
    simp [execS, evalE_call, evalArgs_cons, execL_cons, execL_nil, rhs, assignAll, Scope.lookup,
      Scope.set, closeBlock, exitBlock, pairRest]
  · simp [execS, evalE_call, evalArgs_cons, pairRest, Scope.lookup, hk]

/-- One iteration of `compressPairPath32`'s loop is `pairStepP`. -/
theorem pair_iter (hF : Computes F P) {k : ℕ} (hk : k < 32) (c i nl : ℕ) (t : ℕ × ℕ × ℕ) :
    Iter ctx [("permute", F)] pairBody [.assign ["level"] (.call "add" [.var "level", .lit 1])]
      ⟨("level", k) :: pairRest c i nl t, m⟩
      ⟨("level", k + 1) :: pairRest c i nl (pairStepP P c i nl (sibAt ctx.calldata 132) t k), m⟩ := by
  refine ⟨⟨("level", k) :: pairRest c i nl (pairStepP P c i nl (sibAt ctx.calldata 132) t k), m⟩, ?_,
    exec_post hk _⟩
  rw [pairBody, execL_cons_inr (exec_pairIf c i nl t),
    execL_cons_inr (exec_letSibling (by norm_num) hk (by simp [Scope.lookup])
      (by simp [pairRest, Scope.lookup])), execL_singleton,
    exec_switch (eval_bitExpr (i := i) hk (by simp [Scope.lookup]) (by simp [pairRest, Scope.lookup])),
    execArms_case, execArms_default]
  unfold Computes at hF
  obtain ⟨o, n, nn⟩ := t
  rcases bitW_le_one i k with hb | hb <;>
    simp [hb, letPermute, execL_cons, execL_nil, execS, rhs, Funs.find, evalArgs_cons, hF, declare,
      assignAll, Scope.lookup, Scope.set, closeBlock, exitBlock, pairRest, pairStepP, stepP,
      compressP, sibAt]

/-- `compressPairPath32`'s loop runs 32 iterations of `pairStepP`. -/
theorem exec_pairLoop (hF : Computes F P) (c i oldLeaf newLeaf nl : ℕ) :
    execS ctx [("permute", F)] ⟨pairRest c i nl (oldLeaf, newLeaf, newLeaf), m⟩ (for32 pairBody) =
      some (.inr (⟨pairRest c i nl (pairFold P c i oldLeaf newLeaf nl (sibAt ctx.calldata 132) 32), m⟩,
        [("permute", F)])) := by
  have h := exec_for (ctx := ctx) (fs := [("permute", F)])
    (st := ⟨pairRest c i nl (oldLeaf, newLeaf, newLeaf), m⟩)
    (init := [.letv ["level"] (.lit 0)]) (c := .call "lt" [.var "level", .lit 32])
    (post := [.assign ["level"] (.call "add" [.var "level", .lit 1])]) (body := pairBody)
    (fs₁ := [("permute", F)])
    (fun k => ⟨("level", k) :: pairRest c i nl
      (pairFold P c i oldLeaf newLeaf nl (sibAt ctx.calldata 132) k), m⟩) 32
    (by
      rw [execL_singleton]
      exact exec_letv (rhs_pure (by intro f args h; cases h) (evalE_lit _ 0))
        (by simp [declare, pairRest, Scope.lookup, pairFold]))
    (fun k hk => ⟨1, by rw [eval_lt32 (lookup_cons_eq _ _ _)]; simp [hk], one_ne_zero⟩)
    (by rw [eval_lt32 (lookup_cons_eq _ _ _)]; simp)
    (fun k hk => by rw [pairFold_succ]; exact pair_iter hF hk c i nl _)
    (by unfold loopFuel; norm_num)
  rw [for32, h]
  simp [exitBlock, pairRest]

/-- **`compressPairPath32`'s arm.** -/
theorem exec_pairArm (hF : Computes F P) (m : Mem) (h4 : 4 ≤ ctx.calldata.length)
    (hlen : ctx.calldata.length ≤ 0xffffffffffff) :
    execL ctx [("permute", F)] ⟨[], m⟩ pairArm =
      some (.inl (if ctx.calldata.length < 4 + 1184 then .rev []
        else if 2 ^ 32 ≤ cdWord ctx.calldata 36 then .rev []
        else
          let r := pairPath32P P (cdWord ctx.calldata 4) (cdWord ctx.calldata 36)
            (cdWord ctx.calldata 68) (cdWord ctx.calldata 100) (sibAt ctx.calldata 132)
            (cdWord ctx.calldata 1156)
          .ret (be32 r.1 ++ be32 r.2.1 ++ be32 r.2.2))) := by
  rw [pairArm, execL_cons, exec_lenCheck (by norm_num) h4 hlen]
  by_cases h : ctx.calldata.length < 4 + 1184
  · simp only [h, ite_true]
  · simp only [h, ite_false]
    set i := cdWord ctx.calldata 36
    set c := cdWord ctx.calldata 4
    set o := cdWord ctx.calldata 68
    set n := cdWord ctx.calldata 100
    set nl := cdWord ctx.calldata 1156
    have h1 : execS ctx [("permute", F)] ⟨[], m⟩ (.letv ["index"] (cl 36)) =
        some (.inr (⟨[("index", i)], m⟩, [("permute", F)])) := by
      simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, i]
    rw [execL_cons_inr h1, execL_cons, exec_indexCheck (i := i) (by simp [Scope.lookup])]
    by_cases hi : 2 ^ 32 ≤ i
    · simp only [hi, ite_true]
    · simp only [hi, ite_false]
      have hc1 : execS ctx [("permute", F)] ⟨[("index", i)], m⟩ (.letv ["capacity"] (cl 4)) =
          some (.inr (⟨[("capacity", c), ("index", i)], m⟩, [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, c]
      have hc2 : execS ctx [("permute", F)] ⟨[("capacity", c), ("index", i)], m⟩
          (.letv ["oldRoot"] (cl 68)) =
          some (.inr (⟨[("oldRoot", o), ("capacity", c), ("index", i)], m⟩, [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, o]
      have hc3 : execS ctx [("permute", F)] ⟨[("oldRoot", o), ("capacity", c), ("index", i)], m⟩
          (.letv ["newRoot"] (cl 100)) =
          some (.inr (⟨[("newRoot", n), ("oldRoot", o), ("capacity", c), ("index", i)], m⟩,
            [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, n]
      have hc4 : execS ctx [("permute", F)]
          ⟨[("newRoot", n), ("oldRoot", o), ("capacity", c), ("index", i)], m⟩
          (.letv ["newNode"] (.var "newRoot")) =
          some (.inr (⟨[("newNode", n), ("newRoot", n), ("oldRoot", o), ("capacity", c),
            ("index", i)], m⟩, [("permute", F)])) := by
        simp [execS, rhs, declare, Scope.lookup]
      have hc5 : execS ctx [("permute", F)]
          ⟨[("newNode", n), ("newRoot", n), ("oldRoot", o), ("capacity", c), ("index", i)], m⟩
          (.letv ["nodeLevel"] (cl 1156)) =
          some (.inr (⟨pairRest c i nl (o, n, n), m⟩, [("permute", F)])) := by
        simp [execS, rhs, cl, Funs.find, evalE_calldataload_lit, declare, Scope.lookup, pairRest, nl]
      rw [execL_cons_inr hc1, execL_cons_inr hc2, execL_cons_inr hc3, execL_cons_inr hc4,
        execL_cons_inr hc5, execL_cons_inr (exec_pairLoop hF c i o n nl)]
      unfold pairPath32P
      generalize pairFold P c i o n nl (sibAt ctx.calldata 132) 32 = R
      obtain ⟨ro, rn, rnn⟩ := R
      by_cases hl : nl < 32
      · simp [hl, show ¬ (32 ≤ nl) by omega, execL_cons, execS, evalE_call,
          evalArgs_cons, Scope.lookup, pairRest, mstoreVar, returnLit, bytesOf_ret3]
      · simp [hl, show 32 ≤ nl by omega, execL_cons, execL_nil, execS, rhs, evalE_call,
          evalArgs_cons, assignAll, Scope.lookup, Scope.set, closeBlock, exitBlock, pairRest,
          mstoreVar, returnLit, bytesOf_ret3]

end

/-! ## The runtime -/

theorem eval_selector (ctx : Ctx) (σ : Scope) :
    evalE ctx σ (.call "shr" [.lit 224, cl 0]) = some (selector ctx.calldata) := by
  rw [cl, evalE_call2 (evalE_lit _ 224) (evalE_calldataload_lit _ 0) (builtin_shr _ _)]
  simp [selector]

/-- **The runtime's assembly block, for all calldata.** For every calldata `cd` shorter than
`2^48` bytes, every call value and every initial memory, the kernel-parsed assembly block of
`Bn254PoseidonRuntime`, run in the Yul semantics, halts as `runtimeSpec cd` says: `revert` with
no data exactly where solc's ABI decoder of the replaced library reverts (short calldata, unknown
selector, arguments shorter than the head, an unclean `uint32` index), and otherwise `return` of
the ABI encoding of `compressWord`, `hash5Word`, `insertPath32Word` or `compressPairPath32Word` of
the calldata words. -/
theorem runtime_block (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff) (m : Mem) :
    run ⟨cd, v⟩ m blockAst = some (.inl (runtimeSpec cd)) := by
  obtain ⟨body, hb, hperm⟩ := yul_permute
  have hF : Computes (permFn ⟨cd, v⟩ body) wordPermute := hperm ⟨cd, v⟩ hlen
  rw [hb, run, execL_cons_inr (exec_funDef _ _ body), execL_cons, exec_ifShort]
  unfold runtimeSpec
  by_cases h4 : cd.length < 4
  · simp only [h4, ite_true]
  · have h4' : 4 ≤ cd.length := by omega
    simp only [h4, ite_false]
    rw [execL_singleton, dispatch, exec_switch (eval_selector _ _), execArms_case, execArms_case,
      execArms_case, execArms_case, execArms_default]
    by_cases s1 : selector cd = selCompress
    · rw [ite_eq_left_of_eq_true _ _ (eq_true s1.symm), exec_compressArm hF m h4' hlen, closeBlock_halt, compressP_eq]
      simp only [s1, ite_true]
    · rw [ite_eq_right_of_eq_false _ _ (eq_false (Ne.symm s1))]
      simp only [s1, ite_false]
      by_cases s2 : selector cd = selHash5
      · rw [ite_eq_left_of_eq_true _ _ (eq_true s2.symm), exec_hash5Arm hF m h4' hlen, closeBlock_halt, hash5P_eq]
        simp only [s2, ite_true]
      · rw [ite_eq_right_of_eq_false _ _ (eq_false (Ne.symm s2))]
        simp only [s2, ite_false]
        by_cases s3 : selector cd = selInsertPath32
        · rw [ite_eq_left_of_eq_true _ _ (eq_true s3.symm), exec_insertArm hF m h4' hlen, closeBlock_halt, insertPath32P_eq]
          simp only [s3, ite_true]
        · rw [ite_eq_right_of_eq_false _ _ (eq_false (Ne.symm s3))]
          simp only [s3, ite_false]
          by_cases s4 : selector cd = selCompressPairPath32
          · rw [ite_eq_left_of_eq_true _ _ (eq_true s4.symm), exec_pairArm hF m h4' hlen, closeBlock_halt, pairPath32P_eq]
            simp only [s4, ite_true]
          · rw [ite_eq_right_of_eq_false _ _ (eq_false (Ne.symm s4)), exec_revertBlock]
            simp only [s4, ite_false]

/-- **The runtime contract, for all calldata.** With solc's code around the block
(`fallbackRun`: the fallback is not `payable`, so a call with value reverts with no data), the
runtime halts as `runtimeSpec` says on every call without value. (The vault calls it with
`STATICCALL`, whose call value is 0.) -/
theorem runtime_fallback (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff) (m : Mem) :
    fallbackRun ⟨cd, v⟩ m blockAst = some (if v ≠ 0 then .rev [] else runtimeSpec cd) := by
  unfold fallbackRun
  by_cases hv : v = 0
  · simp [hv, runtime_block cd 0 hlen]
  · simp [hv]

/-! ## The entry points against zkAPI's reference definitions -/

open Zkapi.Poseidon (pathNode merkleRoot) in
/-- `compress`: zkAPI's `compress` (`compress_fields`) of the three argument words reduced mod p,
for every word, canonical or not. -/
theorem runtime_compress (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff) (m : Mem)
    (hsel : selector cd = selCompress) (h : 4 + 96 ≤ cd.length) :
    run ⟨cd, v⟩ m blockAst = some (.inl (.ret (be32
      (Poseidon.compress (cdWord cd 4 : F) (cdWord cd 36 : F) (cdWord cd 68 : F)).val))) := by
  rw [runtime_block cd v hlen m, runtimeSpec, Zkapi.Lazy.compressWord_eq]
  simp [hsel, show ¬ cd.length < 4 by omega, show ¬ cd.length < 4 + 96 by omega]

/-- `hash5`: zkAPI's sponge (`hash_fields`) over the five argument words reduced mod p. -/
theorem runtime_hash5 (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff) (m : Mem)
    (hsel : selector cd = selHash5) (h : 4 + 160 ≤ cd.length) :
    run ⟨cd, v⟩ m blockAst = some (.inl (.ret (be32
      (Poseidon.hashFields [(cdWord cd 4 : F), (cdWord cd 36 : F), (cdWord cd 68 : F),
        (cdWord cd 100 : F), (cdWord cd 132 : F)]).val))) := by
  rw [runtime_block cd v hlen m, runtimeSpec, Zkapi.Lazy.hash5Word_eq, Poseidon.hash5_eq_hashFields]
  simp [hsel, selCompress, selHash5, show ¬ cd.length < 4 by omega, show ¬ cd.length < 4 + 160 by omega]

/-- `insertPath32` with a clean `index`: the root is zkAPI's path node at height 32 (for
`capacity = DOMAIN_NODE`, `merkle_root`, `runtime_insertPath32_root`), and the completed node is
the path's node at the lowest zero bit of `index` (`insertPath32Word_eq`). -/
theorem runtime_insertPath32 (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff) (m : Mem)
    (hsel : selector cd = selInsertPath32) (h : 4 + 1120 ≤ cd.length) (hi : cdWord cd 36 < 2 ^ 32) :
    run ⟨cd, v⟩ m blockAst = some (.inl (.ret (
      be32 (Poseidon.pathNode (cdWord cd 4 : F) (cdWord cd 36) (cdWord cd 68 : F)
        (fun l => (sibAt cd 100 l : F)) 32).val ++
      be32 (Zkapi.Lazy.pathNodeW (cdWord cd 4) (cdWord cd 36) (cdWord cd 68) (sibAt cd 100)
        ((Zkapi.Lazy.lowZero (cdWord cd 36) 32).getD 32))))) := by
  rw [runtime_block cd v hlen m, runtimeSpec, Zkapi.Lazy.insertPath32Word_eq,
    ← ((Zkapi.Lazy.pathNodeW_eq _ _ _ _ 32).2 (by norm_num))]
  simp [hsel, selCompress, selHash5, selInsertPath32, show ¬ cd.length < 4 by omega, show ¬ cd.length < 4 + 1120 by omega,
    show ¬ 4294967296 ≤ cdWord cd 36 by norm_num at hi; omega]

/-- `insertPath32`'s root for the note tree's capacity `DOMAIN_NODE` is zkAPI's `merkle_root`. -/
theorem runtime_insertPath32_root (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff)
    (m : Mem) (hsel : selector cd = selInsertPath32) (h : 4 + 1120 ≤ cd.length)
    (hi : cdWord cd 36 < 2 ^ 32) (hcap : cdWord cd 4 = 0x7a6b6170692e76322e6e6f6465) :
    ∃ rest, run ⟨cd, v⟩ m blockAst = some (.inl (.ret (
      be32 (Poseidon.merkleRoot (cdWord cd 36) (cdWord cd 68 : F)
        (fun l => (sibAt cd 100 l : F))).val ++ rest))) := by
  refine ⟨be32 (Zkapi.Lazy.pathNodeW (cdWord cd 4) (cdWord cd 36) (cdWord cd 68) (sibAt cd 100)
    ((Zkapi.Lazy.lowZero (cdWord cd 36) 32).getD 32)), ?_⟩
  rw [runtime_insertPath32 cd v hlen m hsel h hi, Poseidon.merkleRoot]
  simp only [hcap, Poseidon.domainNode, Nat.cast_ofNat]

/-- `compressPairPath32` with a clean `index`: both roots are zkAPI's path nodes at height 32,
and the third result is the new path's node at `nodeLevel` (the new root from 32 on). -/
theorem runtime_compressPairPath32 (cd : List ℕ) (v : ℕ) (hlen : cd.length ≤ 0xffffffffffff)
    (m : Mem) (hsel : selector cd = selCompressPairPath32) (h : 4 + 1184 ≤ cd.length)
    (hi : cdWord cd 36 < 2 ^ 32) :
    run ⟨cd, v⟩ m blockAst = some (.inl (.ret (
      be32 (Poseidon.pathNode (cdWord cd 4 : F) (cdWord cd 36) (cdWord cd 68 : F)
        (fun l => (sibAt cd 132 l : F)) 32).val ++
      be32 (Poseidon.pathNode (cdWord cd 4 : F) (cdWord cd 36) (cdWord cd 100 : F)
        (fun l => (sibAt cd 132 l : F)) 32).val ++
      be32 (Zkapi.Lazy.pathNodeW (cdWord cd 4) (cdWord cd 36) (cdWord cd 100) (sibAt cd 132)
        (min (cdWord cd 1156) 32))))) := by
  rw [runtime_block cd v hlen m, runtimeSpec, Zkapi.Lazy.compressPairPath32Word_eq,
    ← ((Zkapi.Lazy.pathNodeW_eq _ _ (cdWord cd 68) _ 32).2 (by norm_num)),
    ← ((Zkapi.Lazy.pathNodeW_eq _ _ (cdWord cd 100) _ 32).2 (by norm_num))]
  simp [hsel, selCompress, selHash5, selInsertPath32, selCompressPairPath32, show ¬ cd.length < 4 by omega, show ¬ cd.length < 4 + 1184 by omega,
    show ¬ 4294967296 ≤ cdWord cd 36 by norm_num at hi; omega]

end Zkapi.Yul
