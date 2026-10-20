/-! # Yul: tokens, abstract syntax and parser

The fragment of Yul (Solidity inline assembly, EVM dialect) the vault's Poseidon runtime is
written in: the whole body of its `assembly ("memory-safe") { … }` block, i.e. the function
`permute`, the dispatcher, the ABI checks and the Merkle-path loops. Comments, whitespace and the
Solidity around the block are handled by the generator (`scripts/generate.py`: `lex_yul` drops
only whitespace and comments, so the token stream is the source text; `check_glue` pins the
Solidity wrapper).

The parser follows the grammar of the Yul specification
(<https://docs.soliditylang.org/en/latest/yul.html#specification-of-yul>), restricted to the
fragment:

```
Block = '{' Statement* '}'
Statement = Block | FunctionDefinition | VariableDeclaration | Assignment | If | Switch | ForLoop
          | ExpressionStatement
FunctionDefinition = 'function' Identifier '(' IdentifierList? ')' ( '->' IdentifierList )? Block
VariableDeclaration = 'let' IdentifierList ':=' Expression
Assignment = IdentifierList ':=' Expression
If = 'if' Expression Block
Switch = 'switch' Expression ( 'case' Literal Block )* ( 'default' Block )?
ForLoop = 'for' Block Expression Block Block
ExpressionStatement = FunctionCall
Expression = FunctionCall | Identifier | Literal
FunctionCall = Identifier '(' ( Expression ( ',' Expression )* )? ')'
IdentifierList = Identifier ( ',' Identifier )*
Literal = NumberLiteral                       (below 2^256)
```

Left out because the runtime does not use them: `break`, `continue`, `leave`, string, boolean and
hex literals, and declarations without an initial value. The generator rejects a source that
uses them (`lean_tok`), and so would this parser.

Every token is kept, punctuation included, so the parse is determined by the token stream. The
parser is a total function with a fuel bound (the token count suffices), evaluated by the kernel
in `ZkapiFormal.Yul.Permute`. -/

namespace Zkapi.Yul

/-- Yul tokens. `ident` covers variables, function and builtin names; `num` is a number
literal's value (hexadecimal or decimal in the source). -/
inductive Tok
  | kwLet | kwIf | kwFunction | kwSwitch | kwCase | kwDefault | kwFor
  | lb | rb | lp | rp | comma | assign | arrow
  | ident (s : String)
  | num (n : Nat)
  deriving DecidableEq, Repr

/-- Yul expressions. -/
inductive Expr
  | lit (n : Nat)
  | var (x : String)
  | call (f : String) (args : List Expr)
  deriving Repr

/-- Yul statements of the fragment. -/
inductive Stmt
  | block (ss : List Stmt)
  /-- `let x₁, …, xₙ := e`. -/
  | letv (xs : List String) (e : Expr)
  /-- `x₁, …, xₙ := e`. -/
  | assign (xs : List String) (e : Expr)
  | ifs (c : Expr) (body : List Stmt)
  | switch (c : Expr) (arms : List Stmt)
  /-- A `case k { … }` (`some k`) or `default { … }` (`none`) arm; only inside `switch`. -/
  | arm (k : Option Nat) (body : List Stmt)
  /-- `for { init } cond { post } { body }`. -/
  | forLoop (init : List Stmt) (cond : Expr) (post : List Stmt) (body : List Stmt)
  | exprStmt (e : Expr)
  | funDef (f : String) (params rets : List String) (body : List Stmt)
  deriving Repr

mutual
/-- `Expression`, returning the rest of the tokens. -/
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

/-- `Expression ( ',' Expression )* ')'`, after the opening parenthesis. -/
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
/-- `Statement`, returning the rest of the tokens. -/
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
  | n + 1, .kwFor :: .lb :: r =>
    match parseBlock n r with
    | some (init, r) =>
      match parseExpr n r with
      | some (c, .lb :: r) =>
        match parseBlock n r with
        | some (post, .lb :: r) =>
          match parseBlock n r with
          | some (body, r) => some (.forLoop init c post body, r)
          | none => none
        | _ => none
      | _ => none
    | none => none
  | n + 1, .ident f :: .lp :: r =>
    match parseExpr (n + 1) (.ident f :: .lp :: r) with
    | some (e, r) => some (.exprStmt e, r)
    | none => none
  | n + 1, .ident x :: r =>
    match parseIdents n (.ident x :: r) with
    | some (xs, .assign :: r) =>
      match parseExpr n r with
      | some (e, r) => some (.assign xs e, r)
      | none => none
    | _ => none
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

/-- `Statement* '}'`: the statements of a block, after its opening brace, up to and including
its closing brace. -/
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

/-- The statements of a block body (the tokens between its braces); `none` unless the tokens are
exactly a sequence of statements. -/
def parseBody (toks : List Tok) : Option (List Stmt) :=
  match parseBlock (toks.length + 2) (toks ++ [.rb]) with
  | some (ss, []) => some ss
  | _ => none

end Zkapi.Yul
