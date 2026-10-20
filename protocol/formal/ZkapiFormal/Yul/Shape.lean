import ZkapiFormal.Yul.Syntax
import ZkapiFormal.Field

/-! # The runtime's code around `permute`, as Lean states it

The statements of the runtime's assembly block after `function permute`, written as Yul syntax
trees: the short-calldata check and the dispatcher with its four entry points and their ABI checks.
`ZkapiFormal.Yul.Permute` has the kernel parse the runtime's tokens and compare the parse with
these trees (`blockOK_source`), so the proofs about the entry points (`ZkapiFormal.Yul.Entry`)
are about the runtime's code. They read as the source does
(`protocol/contracts/src/poseidon/Bn254PoseidonRuntime.sol`). -/

namespace Zkapi.Yul

/-- `calldataload(i)`. -/
def cl (i : ℕ) : Expr := .call "calldataload" [.lit i]

/-- `revert(0, 0)`. -/
def revert00 : Stmt := .exprStmt (.call "revert" [.lit 0, .lit 0])

/-- `if slt(sub(calldatasize(), 4), n) { revert(0, 0) }`: solc's check that the arguments hold
the `n`-byte head. -/
def lenCheck (n : ℕ) : Stmt :=
  .ifs (.call "slt" [.call "sub" [.call "calldatasize" [], .lit 4], .lit n]) [revert00]

/-- `if iszero(eq(index, and(index, 0xffffffff))) { revert(0, 0) }`: solc's check that `index`
is a clean `uint32`. -/
def indexCheck : Stmt :=
  .ifs (.call "iszero" [.call "eq" [.var "index", .call "and" [.var "index", .lit 0xffffffff]]])
    [revert00]

/-- `mstore(p, x)`. -/
def mstoreVar (p : ℕ) (x : String) : Stmt := .exprStmt (.call "mstore" [.lit p, .var x])

/-- `return(p, n)`. -/
def returnLit (p n : ℕ) : Stmt := .exprStmt (.call "return" [.lit p, .lit n])

/-- `let x₀, x₁, x₂ := permute(a, b, c)`. -/
def letPermute (xs : List String) (a b c : Expr) : Stmt := .letv xs (.call "permute" [a, b, c])

/-- `if lt(calldatasize(), 4) { revert(0, 0) }` -/
def ifShort : Stmt := .ifs (.call "lt" [.call "calldatasize" [], .lit 4]) [revert00]

/-- `compress(uint256,uint256,uint256)`. -/
def compressArm : List Stmt :=
  [lenCheck 96,
   letPermute ["c0", "c1", "c2"] (cl 4) (cl 36) (cl 68),
   mstoreVar 0x80 "c1",
   returnLit 0x80 0x20]

/-- `hash5(uint256,uint256,uint256,uint256,uint256)`. -/
def hash5Arm : List Stmt :=
  [lenCheck 160,
   .letv ["zero"] (.call "shr" [.lit 255, .call "calldatasize" []]),
   letPermute ["h0", "h1", "h2"] (.var "zero") (cl 4) (cl 36),
   .assign ["h0", "h1", "h2"] (.call "permute" [.var "h0",
     .call "addmod" [.var "h1", cl 68, .lit Zkapi.p], .call "addmod" [.var "h2", cl 100, .lit Zkapi.p]]),
   .assign ["h0", "h1", "h2"] (.call "permute" [.var "h0",
     .call "addmod" [.var "h1", cl 132, .lit Zkapi.p], .var "h2"]),
   mstoreVar 0x80 "h1",
   returnLit 0x80 0x20]

/-- `for { let level := 0 } lt(level, 32) { level := add(level, 1) } { body }`. -/
def for32 (body : List Stmt) : Stmt :=
  .forLoop [.letv ["level"] (.lit 0)] (.call "lt" [.var "level", .lit 32])
    [.assign ["level"] (.call "add" [.var "level", .lit 1])] body

/-- `let sibling := calldataload(add(base, shl(5, level)))`. -/
def letSibling (base : ℕ) : Stmt :=
  .letv ["sibling"] (.call "calldataload" [.call "add" [.lit base, .call "shl" [.lit 5, .var "level"]]])

/-- `and(shr(level, index), 1)`. -/
def bitExpr : Expr := .call "and" [.call "shr" [.var "level", .var "index"], .lit 1]

/-- The body of `insertPath32`'s loop. -/
def insertBody : List Stmt :=
  [letSibling 100,
   .switch bitExpr
     [.arm (some 0)
        [.ifs (.var "completing") [.assign ["completed"] (.var "root"), .assign ["completing"] (.lit 0)],
         letPermute ["a0", "a1", "a2"] (.var "capacity") (.var "root") (.var "sibling"),
         .assign ["root"] (.var "a1")],
      .arm none
        [letPermute ["a0", "a1", "a2"] (.var "capacity") (.var "sibling") (.var "root"),
         .assign ["root"] (.var "a1")]]]

/-- `insertPath32(uint256,uint32,uint256,uint256[32])`. -/
def insertArm : List Stmt :=
  [lenCheck 1120,
   .letv ["index"] (cl 36),
   indexCheck,
   .letv ["capacity"] (cl 4),
   .letv ["root"] (cl 68),
   .letv ["completed"] (.var "root"),
   .letv ["completing"] (.lit 1),
   for32 insertBody,
   .ifs (.var "completing") [.assign ["completed"] (.var "root")],
   mstoreVar 0x80 "root",
   mstoreVar 0xa0 "completed",
   returnLit 0x80 0x40]

/-- The body of `compressPairPath32`'s loop. -/
def pairBody : List Stmt :=
  [.ifs (.call "eq" [.var "level", .var "nodeLevel"]) [.assign ["newNode"] (.var "newRoot")],
   letSibling 132,
   .switch bitExpr
     [.arm (some 0)
        [letPermute ["a0", "a1", "a2"] (.var "capacity") (.var "oldRoot") (.var "sibling"),
         .assign ["oldRoot"] (.var "a1"),
         letPermute ["b0", "b1", "b2"] (.var "capacity") (.var "newRoot") (.var "sibling"),
         .assign ["newRoot"] (.var "b1")],
      .arm none
        [letPermute ["a0", "a1", "a2"] (.var "capacity") (.var "sibling") (.var "oldRoot"),
         .assign ["oldRoot"] (.var "a1"),
         letPermute ["b0", "b1", "b2"] (.var "capacity") (.var "sibling") (.var "newRoot"),
         .assign ["newRoot"] (.var "b1")]]]

/-- `compressPairPath32(uint256,uint32,uint256,uint256,uint256[32],uint256)`. -/
def pairArm : List Stmt :=
  [lenCheck 1184,
   .letv ["index"] (cl 36),
   indexCheck,
   .letv ["capacity"] (cl 4),
   .letv ["oldRoot"] (cl 68),
   .letv ["newRoot"] (cl 100),
   .letv ["newNode"] (.var "newRoot"),
   .letv ["nodeLevel"] (cl 1156),
   for32 pairBody,
   .ifs (.call "iszero" [.call "lt" [.var "nodeLevel", .lit 32]]) [.assign ["newNode"] (.var "newRoot")],
   mstoreVar 0x80 "oldRoot",
   mstoreVar 0xa0 "newRoot",
   mstoreVar 0xc0 "newNode",
   returnLit 0x80 0x60]

/-- The selectors: those of the replaced library's public functions. -/
def selCompress : ℕ := 0x2d0c7694
def selHash5 : ℕ := 0xc98aeff5
def selInsertPath32 : ℕ := 0x21d2c645
def selCompressPairPath32 : ℕ := 0xf6073d4e

/-- `switch shr(224, calldataload(0)) case … default { revert(0, 0) }` -/
def dispatch : Stmt :=
  .switch (.call "shr" [.lit 224, cl 0])
    [.arm (some selCompress) compressArm,
     .arm (some selHash5) hash5Arm,
     .arm (some selInsertPath32) insertArm,
     .arm (some selCompressPairPath32) pairArm,
     .arm none [revert00]]

/-- The end of `permute`'s body. -/
def retTail : List Stmt :=
  [.assign ["r0"] (.var "s0"), .assign ["r1"] (.var "s1"), .assign ["r2"] (.var "s2")]

end Zkapi.Yul
