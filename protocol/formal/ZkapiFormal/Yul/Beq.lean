import ZkapiFormal.Yul.Syntax

/-! # Structural equality of Yul syntax

A Boolean equality on expressions and statements (`beqS`), which the kernel evaluates on the parsed
runtime, and its soundness (`beqS_eq`): comparing the parse with Lean's own statement of the code
by `beqS` proves them equal. -/

namespace Zkapi.Yul

mutual
def beqE : Expr → Expr → Bool
  | .lit a, .lit b => a == b
  | .var a, .var b => a == b
  | .call f as, .call g bs => f == g && beqEs as bs
  | _, _ => false

def beqEs : List Expr → List Expr → Bool
  | [], [] => true
  | a :: as, b :: bs => beqE a b && beqEs as bs
  | _, _ => false
end

mutual
def beqS : Stmt → Stmt → Bool
  | .block a, .block b => beqL a b
  | .letv xs e, .letv ys f => xs == ys && beqE e f
  | .assign xs e, .assign ys f => xs == ys && beqE e f
  | .ifs c a, .ifs d b => beqE c d && beqL a b
  | .switch c a, .switch d b => beqE c d && beqL a b
  | .arm k a, .arm l b => k == l && beqL a b
  | .forLoop i c p a, .forLoop j d q b => beqL i j && beqE c d && beqL p q && beqL a b
  | .exprStmt e, .exprStmt f => beqE e f
  | .funDef f ps rs a, .funDef g qs ts b => f == g && ps == qs && rs == ts && beqL a b
  | _, _ => false

def beqL : List Stmt → List Stmt → Bool
  | [], [] => true
  | a :: as, b :: bs => beqS a b && beqL as bs
  | _, _ => false
end

mutual
theorem beqE_eq : ∀ a b : Expr, beqE a b = true → a = b
  | .lit _, .lit _, h => by simp only [beqE, beq_iff_eq] at h; rw [h]
  | .var _, .var _, h => by simp only [beqE, beq_iff_eq] at h; rw [h]
  | .call f as, .call g bs, h => by
    simp only [beqE, Bool.and_eq_true, beq_iff_eq] at h
    rw [h.1, beqEs_eq as bs h.2]
  | .lit _, .var _, h | .lit _, .call _ _, h | .var _, .lit _, h | .var _, .call _ _, h
  | .call _ _, .lit _, h | .call _ _, .var _, h => by simp [beqE] at h

theorem beqEs_eq : ∀ a b : List Expr, beqEs a b = true → a = b
  | [], [], _ => rfl
  | a :: as, b :: bs, h => by
    simp only [beqEs, Bool.and_eq_true] at h
    rw [beqE_eq a b h.1, beqEs_eq as bs h.2]
  | [], _ :: _, h | _ :: _, [], h => by simp [beqEs] at h
end

mutual
theorem beqS_eq : ∀ a b : Stmt, beqS a b = true → a = b
  | .block a, .block b, h => by simp only [beqS] at h; rw [beqL_eq a b h]
  | .letv xs e, .letv ys f, h => by
    simp only [beqS, Bool.and_eq_true, beq_iff_eq] at h; rw [h.1, beqE_eq e f h.2]
  | .assign xs e, .assign ys f, h => by
    simp only [beqS, Bool.and_eq_true, beq_iff_eq] at h; rw [h.1, beqE_eq e f h.2]
  | .ifs c a, .ifs d b, h => by
    simp only [beqS, Bool.and_eq_true] at h; rw [beqE_eq c d h.1, beqL_eq a b h.2]
  | .switch c a, .switch d b, h => by
    simp only [beqS, Bool.and_eq_true] at h; rw [beqE_eq c d h.1, beqL_eq a b h.2]
  | .arm k a, .arm l b, h => by
    simp only [beqS, Bool.and_eq_true, beq_iff_eq] at h; rw [h.1, beqL_eq a b h.2]
  | .forLoop i c p a, .forLoop j d q b, h => by
    simp only [beqS, Bool.and_eq_true] at h
    rw [beqL_eq i j h.1.1.1, beqE_eq c d h.1.1.2, beqL_eq p q h.1.2, beqL_eq a b h.2]
  | .exprStmt e, .exprStmt f, h => by simp only [beqS] at h; rw [beqE_eq e f h]
  | .funDef f ps rs a, .funDef g qs ts b, h => by
    simp only [beqS, Bool.and_eq_true, beq_iff_eq] at h
    rw [h.1.1.1, h.1.1.2, h.1.2, beqL_eq a b h.2]
  | .block _, .letv _ _, h | .block _, .assign _ _, h | .block _, .ifs _ _, h
  | .block _, .switch _ _, h | .block _, .arm _ _, h | .block _, .forLoop _ _ _ _, h
  | .block _, .exprStmt _, h | .block _, .funDef _ _ _ _, h | .letv _ _, .block _, h
  | .letv _ _, .assign _ _, h | .letv _ _, .ifs _ _, h | .letv _ _, .switch _ _, h
  | .letv _ _, .arm _ _, h | .letv _ _, .forLoop _ _ _ _, h | .letv _ _, .exprStmt _, h
  | .letv _ _, .funDef _ _ _ _, h | .assign _ _, .block _, h | .assign _ _, .letv _ _, h
  | .assign _ _, .ifs _ _, h | .assign _ _, .switch _ _, h | .assign _ _, .arm _ _, h
  | .assign _ _, .forLoop _ _ _ _, h | .assign _ _, .exprStmt _, h | .assign _ _, .funDef _ _ _ _, h
  | .ifs _ _, .block _, h | .ifs _ _, .letv _ _, h | .ifs _ _, .assign _ _, h
  | .ifs _ _, .switch _ _, h | .ifs _ _, .arm _ _, h | .ifs _ _, .forLoop _ _ _ _, h
  | .ifs _ _, .exprStmt _, h | .ifs _ _, .funDef _ _ _ _, h | .switch _ _, .block _, h
  | .switch _ _, .letv _ _, h | .switch _ _, .assign _ _, h | .switch _ _, .ifs _ _, h
  | .switch _ _, .arm _ _, h | .switch _ _, .forLoop _ _ _ _, h | .switch _ _, .exprStmt _, h
  | .switch _ _, .funDef _ _ _ _, h | .arm _ _, .block _, h | .arm _ _, .letv _ _, h
  | .arm _ _, .assign _ _, h | .arm _ _, .ifs _ _, h | .arm _ _, .switch _ _, h
  | .arm _ _, .forLoop _ _ _ _, h | .arm _ _, .exprStmt _, h | .arm _ _, .funDef _ _ _ _, h
  | .forLoop _ _ _ _, .block _, h | .forLoop _ _ _ _, .letv _ _, h | .forLoop _ _ _ _, .assign _ _, h
  | .forLoop _ _ _ _, .ifs _ _, h | .forLoop _ _ _ _, .switch _ _, h | .forLoop _ _ _ _, .arm _ _, h
  | .forLoop _ _ _ _, .exprStmt _, h | .forLoop _ _ _ _, .funDef _ _ _ _, h | .exprStmt _, .block _, h
  | .exprStmt _, .letv _ _, h | .exprStmt _, .assign _ _, h | .exprStmt _, .ifs _ _, h
  | .exprStmt _, .switch _ _, h | .exprStmt _, .arm _ _, h | .exprStmt _, .forLoop _ _ _ _, h
  | .exprStmt _, .funDef _ _ _ _, h | .funDef _ _ _ _, .block _, h | .funDef _ _ _ _, .letv _ _, h
  | .funDef _ _ _ _, .assign _ _, h | .funDef _ _ _ _, .ifs _ _, h | .funDef _ _ _ _, .switch _ _, h
  | .funDef _ _ _ _, .arm _ _, h | .funDef _ _ _ _, .forLoop _ _ _ _, h | .funDef _ _ _ _, .exprStmt _, h => by simp [beqS] at h

theorem beqL_eq : ∀ a b : List Stmt, beqL a b = true → a = b
  | [], [], _ => rfl
  | a :: as, b :: bs, h => by
    simp only [beqL, Bool.and_eq_true] at h
    rw [beqS_eq a b h.1, beqL_eq as bs h.2]
  | [], _ :: _, h | _ :: _, [], h => by simp [beqL] at h
end

end Zkapi.Yul
