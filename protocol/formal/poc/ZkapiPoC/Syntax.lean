/-! # Proof of concept: a larger Yul fragment

The implementation layer needs more of Yul than the permutation body: function definitions and
calls, `switch`, multi-variable `let`, expression statements (`mstore`, `return`, `revert`), and
builtins that read calldata and memory. This module is the syntax and parser for that fragment, in
the style of `ZkapiFormal.Yul.Syntax` (grammar of the Yul specification, every token kept,
fuel-bounded total parser):

```
Statement = Block | FunctionDefinition | VariableDeclaration | Assignment | If | Switch
          | ExpressionStatement
FunctionDefinition = 'function' Identifier '(' IdentifierList? ')' ( '->' IdentifierList )? Block
VariableDeclaration = 'let' IdentifierList ':=' Expression
Switch = 'switch' Expression ( 'case' Literal Block )* ( 'default' Block )?
ExpressionStatement = FunctionCall
```
-/

namespace Zkapi.PoC

inductive Tok
  | kwLet | kwIf | kwFunction | kwSwitch | kwCase | kwDefault
  | lb | rb | lp | rp | comma | assign | arrow
  | ident (s : String)
  | num (n : Nat)
  deriving DecidableEq, Repr

inductive Expr
  | lit (n : Nat)
  | var (x : String)
  | call (f : String) (args : List Expr)
  deriving Repr

inductive Stmt
  | block (ss : List Stmt)
  | letv (xs : List String) (e : Expr)
  | assign (x : String) (e : Expr)
  | ifs (c : Expr) (body : List Stmt)
  | switch (c : Expr) (arms : List Stmt)
  /-- A `case k { … }` (`some k`) or `default { … }` (`none`) arm; only inside `switch`. -/
  | arm (k : Option Nat) (body : List Stmt)
  | exprStmt (e : Expr)
  | funDef (f : String) (params rets : List String) (body : List Stmt)
  deriving Repr

mutual
def parseExpr : Nat → List Tok → Option (Expr × List Tok)
  | 0, _ => none
  | _ + 1, .num k :: r => if k < 2 ^ 256 then some (.lit k, r) else none
  | _ + 1, .ident f :: .lp :: .rp :: r => some (.call f [], r)
  | n + 1, .ident f :: .lp :: r =>
    match parseArgs n r with
    | some (args, r) => some (.call f args, r)
    | none => none
  | _ + 1, .ident x :: r => some (.var x, r)
  | _ + 1, _ => none

def parseArgs : Nat → List Tok → Option (List Expr × List Tok)
  | 0, _ => none
  | n + 1, r =>
    match parseExpr n r with
    | some (e, .rp :: r) => some ([e], r)
    | some (e, .comma :: r) =>
      match parseArgs n r with
      | some (es, r) => some (e :: es, r)
      | none => none
    | _ => none
end

/-- `Identifier ( ',' Identifier )*`. -/
def parseIdents : Nat → List Tok → Option (List String × List Tok)
  | 0, _ => none
  | n + 1, .ident x :: .comma :: r =>
    match parseIdents n r with
    | some (xs, r) => some (x :: xs, r)
    | none => none
  | _ + 1, .ident x :: r => some ([x], r)
  | _ + 1, _ => none

mutual
def parseStmt : Nat → List Tok → Option (Stmt × List Tok)
  | 0, _ => none
  | n + 1, .lb :: r =>
    match parseBlock n r with
    | some (ss, r) => some (.block ss, r)
    | none => none
  | n + 1, .kwFunction :: .ident f :: .lp :: r =>
    let ps : Option (List String × List Tok) :=
      match r with
      | .rp :: r => some ([], r)
      | _ =>
        match parseIdents n r with
        | some (ps, .rp :: r) => some (ps, r)
        | _ => none
    match ps with
    | some (ps, .arrow :: r) =>
      match parseIdents n r with
      | some (rs, .lb :: r) =>
        match parseBlock n r with
        | some (body, r) => some (.funDef f ps rs body, r)
        | none => none
      | _ => none
    | some (ps, .lb :: r) =>
      match parseBlock n r with
      | some (body, r) => some (.funDef f ps [] body, r)
      | none => none
    | _ => none
  | n + 1, .kwLet :: r =>
    match parseIdents n r with
    | some (xs, .assign :: r) =>
      match parseExpr n r with
      | some (e, r) => some (.letv xs e, r)
      | none => none
    | _ => none
  | n + 1, .kwIf :: r =>
    match parseExpr n r with
    | some (c, .lb :: r) =>
      match parseBlock n r with
      | some (ss, r) => some (.ifs c ss, r)
      | none => none
    | _ => none
  | n + 1, .kwSwitch :: r =>
    match parseExpr n r with
    | some (c, r) =>
      match parseCases n r with
      | some (arms, r) => some (.switch c arms, r)
      | none => none
    | none => none
  | n + 1, .ident x :: .assign :: r =>
    match parseExpr n r with
    | some (e, r) => some (.assign x e, r)
    | none => none
  | n + 1, .ident f :: .lp :: r =>
    match parseExpr (n + 1) (.ident f :: .lp :: r) with
    | some (e, r) => some (.exprStmt e, r)
    | none => none
  | _ + 1, _ => none

/-- `( 'case' Literal Block )* ( 'default' Block )?`, as arms. -/
def parseCases : Nat → List Tok → Option (List Stmt × List Tok)
  | 0, _ => none
  | n + 1, .kwCase :: .num k :: .lb :: r =>
    if k < 2 ^ 256 then
      match parseBlock n r with
      | some (ss, r) =>
        match parseCases n r with
        | some (arms, r) => some (.arm (some k) ss :: arms, r)
        | none => none
      | none => none
    else none
  | n + 1, .kwDefault :: .lb :: r =>
    match parseBlock n r with
    | some (ss, r) => some ([.arm none ss], r)
    | none => none
  | _ + 1, r => some ([], r)

def parseBlock : Nat → List Tok → Option (List Stmt × List Tok)
  | 0, _ => none
  | _ + 1, .rb :: r => some ([], r)
  | n + 1, r =>
    match parseStmt n r with
    | some (s, r) =>
      match parseBlock n r with
      | some (ss, r) => some (s :: ss, r)
      | none => none
    | none => none
end

def parseBody (toks : List Tok) : Option (List Stmt) :=
  match parseBlock (toks.length + 2) (toks ++ [.rb]) with
  | some (ss, []) => some ss
  | _ => none

end Zkapi.PoC
