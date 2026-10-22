import Mathlib.Data.ZMod.Basic

/-! # The BN254 scalar field

`p` is the order of BN254's scalar field (`Fr`, the field of zkAPI's Poseidon and of its circuits);
`F = ZMod p`. Adapted from msp-formal-curve `Spec/Basic.lean` (Apache-2.0, same author).

Nothing below needs `p` to be prime: every proof in this project is a polynomial identity over
the commutative ring `ZMod p` plus finite certificates checked by the kernel. -/

namespace Zkapi

/-- The BN254 scalar field order (`Fr::MODULUS`, Solidity `FIELD_MODULUS`). -/
def p : ℕ := 21888242871839275222246405745257275088548364400416034343698204186575808495617

theorem p_eq_hex : p = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001 := rfl

instance : NeZero p := ⟨by decide⟩

/-- The BN254 scalar field. -/
abbrev F := ZMod p

end Zkapi
