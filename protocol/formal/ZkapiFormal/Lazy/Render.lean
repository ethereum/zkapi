import ZkapiFormal.Lazy.Straight
import ZkapiFormal.Data.Reference
import ZkapiFormal.Data.Sparse
import ZkapiFormal.Data.Scaled

/-! # The unrolled program

`rounds` is the straight-line program of the unrolled, scaled-sparse, lazily reduced
permutation, one statement list per round, built from the schedule's constants exactly as
zkapi-proof `poseidon_runtime.rs` `permute_body` renders it (a port of the prototype's
`gen/gen_unrolled.py --form scaled --lazy`: `Gen.add`, `Gen.row`, `full_round`,
`partial_scaled`, `last_partial`): every lane carries a bound `m` (the value is
below `m · p`), a sum becomes a plain `add` when the operands' bounds total at most 5 and an
`addmod` otherwise, the first round adds its constants with `addmod` (so inputs of any width are
reduced) and the last round's final additions are `addmod` (so outputs are canonical).

`ZkapiFormal.Yul.Permute` proves that the runtime's `permute` body parses to `rounds` (after the
modulus binding and the opaque branch); `ZkapiFormal.Lazy.Program` proves what `rounds`
computes. -/

namespace Zkapi.Lazy

/-- Bounds of the three lanes, as multiples of `p`. -/
structure Bounds where
  m0 : ℕ
  m1 : ℕ
  m2 : ℕ
  deriving DecidableEq, Repr

/-- gen_unrolled.py `Gen.add`: a lazy sum and its bound. -/
def lz (a : Expr) (ma : ℕ) (b : Expr) (mb : ℕ) : Expr × ℕ :=
  if ma + mb ≤ 5 then (.add a b, ma + mb) else (.addmod a b, 1)

/-- The S-box block: `{ let q := mulmod(v, v, P)  v := mulmod(mulmod(q, q, P), v, P) }`. -/
def sboxBlock (v : Var) : List Stmt :=
  [.openB, .letv .q (.mulmod (.var v) (.var v)),
    .assign v (.mulmod (.mulmod (.var .q) (.var .q)) (.var v)), .closeB]

/-- `mulmod(v, c, P)`. -/
def term (v : Var) (c : ℕ) : Expr := .mulmod (.var v) (.lit c)

/-- gen_unrolled.py `Gen.row`: `mulmod(x, c0) + mulmod(y, c1) + mulmod(z, c2)`, the last
addition an `addmod` when `reduceOut`. -/
def row (c0 c1 c2 : ℕ) (reduceOut : Bool) : Expr × ℕ :=
  let e := lz (term .x c0) 1 (term .y c1) 1
  if reduceOut then (.addmod e.1 (term .z c2), 1) else lz e.1 e.2 (term .z c2) 1

/-- gen_unrolled.py `full_round`. -/
def fullStmts (k0 k1 k2 : ℕ) (mat : Fin 3 → Fin 3 → ℕ) (first last : Bool) (bd : Bounds) :
    List Stmt × Bounds :=
  let ex := if first then Expr.addmod (.var .s0) (.lit k0) else (lz (.var .s0) bd.m0 (.lit k0) 1).1
  let ey := if first then Expr.addmod (.var .s1) (.lit k1) else (lz (.var .s1) bd.m1 (.lit k1) 1).1
  let ez := if first then Expr.addmod (.var .s2) (.lit k2) else (lz (.var .s2) bd.m2 (.lit k2) 1).1
  let r0 := row (mat 0 0) (mat 0 1) (mat 0 2) last
  let r1 := row (mat 1 0) (mat 1 1) (mat 1 2) last
  let r2 := row (mat 2 0) (mat 2 1) (mat 2 2) last
  ([.openB, .letv .x ex, .letv .y ey, .letv .z ez] ++ sboxBlock .x ++ sboxBlock .y ++
      sboxBlock .z ++ [.assign .s0 r0.1, .assign .s1 r1.1, .assign .s2 r2.1, .closeB],
    ⟨r0.2, r1.2, r2.2⟩)

/-- gen_unrolled.py `partial_scaled`. -/
def partialStmts (k b c w1 w2 : ℕ) (bd : Bounds) : List Stmt × Bounds :=
  let ex := (lz (.var .s0) bd.m0 (.lit k) 1).1
  let e0 := lz (.var .x) 1 (term .s1 b) 1
  let e0' := lz e0.1 e0.2 (term .s2 c) 1
  let e1 := lz (.var .s1) bd.m1 (term .x w1) 1
  let e2 := lz (.var .s2) bd.m2 (term .x w2) 1
  ([.openB, .letv .x ex] ++ sboxBlock .x ++
      [.assign .s0 e0'.1, .assign .s1 e1.1, .assign .s2 e2.1, .closeB],
    ⟨e0'.2, e1.2, e2.2⟩)

/-- gen_unrolled.py `last_partial`. -/
def lastStmts (k : Fin 3 → ℕ) (mat : Fin 3 → Fin 3 → ℕ) (bd : Bounds) : List Stmt × Bounds :=
  let e0 := (lz (.var .s0) bd.m0 (.lit (k 0)) 1).1
  let e1 := (lz (.var .s1) bd.m1 (.lit (k 1)) 1).1
  let e2 := (lz (.var .s2) bd.m2 (.lit (k 2)) 1).1
  let r0 := row (mat 0 0) (mat 0 1) (mat 0 2) false
  let r1 := row (mat 1 0) (mat 1 1) (mat 1 2) false
  let r2 := row (mat 2 0) (mat 2 1) (mat 2 2) false
  ([.openB, .letv .x e0, .letv .y e1, .letv .z e2] ++ sboxBlock .x ++
      [.assign .s0 r0.1, .assign .s1 r1.1, .assign .s2 r2.1, .closeB],
    ⟨r0.2, r1.2, r2.2⟩)

/-- Render a list of rounds, threading the bounds. -/
def renderList {α : Type} (step : α → Bounds → List Stmt × Bounds) :
    List α → Bounds → List (List Stmt) × Bounds
  | [], bd => ([], bd)
  | r :: rs, bd =>
    let o := step r bd
    let rest := renderList step rs o.2
    (o.1 :: rest.1, rest.2)

/-! ## The schedule's constants as words -/

/-- Full-round constants (index `r < 4`: round `r`; `4 + r`: round `61 + r`). -/
def fullK (r : Fin 8) (i : Fin 3) : ℕ := (Data.sparseFullData.get r).get i

/-- The MDS matrix. -/
def mdsN (i j : Fin 3) : ℕ := (Data.mdsData.get i).get j

/-- Scaled partial round `j`: `k̂, b̂, ĉ, ŵ1, ŵ2`. -/
def scaledN (j : Fin 56) (n : Fin 5) : ℕ := (Data.scaledPartialData.get j).get n

/-- The last partial round's constants and matrix. -/
def lastKN (i : Fin 3) : ℕ := Data.scaledLastKData.get i
def lastMN (i l : Fin 3) : ℕ := (Data.scaledLastMData.get i).get l

/-- Round 0: the first full round. -/
def round0 : List Stmt × Bounds := fullStmts (fullK 0 0) (fullK 0 1) (fullK 0 2) mdsN true false ⟨1, 1, 1⟩

/-- Rounds 1-3. -/
def prefixStep (r : Fin 3) (bd : Bounds) : List Stmt × Bounds :=
  let c := fullK ⟨r.val + 1, by omega⟩
  fullStmts (c 0) (c 1) (c 2) mdsN false false bd

/-- Partial rounds 0-55 (rounds 4-59). -/
def partialStep (j : Fin 56) (bd : Bounds) : List Stmt × Bounds :=
  partialStmts (scaledN j 0) (scaledN j 1) (scaledN j 2) (scaledN j 3) (scaledN j 4) bd

/-- Rounds 61-64; the last reduces its outputs. -/
def suffixStep (r : Fin 4) (bd : Bounds) : List Stmt × Bounds :=
  let c := fullK ⟨r.val + 4, by omega⟩
  fullStmts (c 0) (c 1) (c 2) mdsN false (r.val == 3) bd

/-- Rounds 1-3, from round 0's bounds. -/
def phase1 : List (List Stmt) × Bounds := renderList prefixStep (List.finRange 3) round0.2

/-- Rounds 4-59. -/
def phase2 : List (List Stmt) × Bounds := renderList partialStep (List.finRange 56) phase1.2

/-- Round 60. -/
def phase3 : List Stmt × Bounds := lastStmts lastKN lastMN phase2.2

/-- Rounds 61-64. -/
def phase4 : List (List Stmt) × Bounds := renderList suffixStep (List.finRange 4) phase3.2

/-- The 65 rounds of the unrolled permutation, in order. -/
def rounds : List (List Stmt) := round0.1 :: (phase1.1 ++ phase2.1 ++ phase3.1 :: phase4.1)

/-- The whole straight-line body. -/
def program : List Stmt := rounds.flatten

end Zkapi.Lazy
