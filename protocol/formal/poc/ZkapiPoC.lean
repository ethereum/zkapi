import ZkapiPoC.Syntax
import ZkapiPoC.Semantics
import ZkapiPoC.Embed
import ZkapiPoC.Data
import ZkapiPoC.Compress
import ZkapiPoC.Audit

/-! # Proof of concept for the implementation layer

`Zkapi.PoC.poc_compress`: the assembly block of `poc/PoseidonFallback.sol` (dispatcher, ABI
check, the production runtime's permutation as a Yul function), parsed by the kernel, returns
`compress` of the calldata words for every calldata shorter than `2^48` bytes, and reverts on
short calldata or an unknown selector. See `poc/README.md`. -/
