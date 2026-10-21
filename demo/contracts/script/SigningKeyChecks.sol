// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SigningKeyChecks – off-chain checks of the vault's signing keys (Deploy.s.sol, design
///        section 10.4 item 3), kept apart from the vault so they can be tested without linking it.
abstract contract SigningKeyChecks {
    // Baby-JubJub as ark-ed-on-bn254 defines it (the circuits' and the signers' curve): the twisted
    // Edwards curve x^2 + y^2 = 1 + d x^2 y^2 over the BN254 scalar field, d = 168696 / 168700, whose
    // prime-order subgroup has order BJJ_ORDER (cofactor 8). The identity is (0, 1).
    uint256 internal constant BJJ_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant BJJ_D = 9706598848417545097372247223557719406784115219466060233080913168975159366771;
    uint256 internal constant BJJ_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    // The published development keys (seeds 0x1, state, and 0x2, clearance), which must never be
    // pinned in a vault outside a local chain.
    uint256 internal constant DEV_STATE_KEY_X = 0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32;
    uint256 internal constant DEV_STATE_KEY_Y = 0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f;
    uint256 internal constant DEV_CLEARANCE_KEY_X = 0x1812b84c2101217b0939a2f542535075eeaa81d07dab701a899a55db26e85be4;
    uint256 internal constant DEV_CLEARANCE_KEY_Y = 0x0be80d0f61a801533a94a03b12683474f86ca012941db1c568c53dc877b16fd6;

    /// The vault's signing keys are immutable and its constructor checks only that each coordinate
    /// is a field element and neither key is (0, 0), so a typo (swapped or truncated coordinates,
    /// one key for both roles) would deploy a vault no signed state can ever verify against. Both
    /// keys must be points of Baby-JubJub's prime-order subgroup other than the identity (as
    /// `zkapi signing-keys` derives them), and distinct; off local chains neither may be a
    /// published development key.
    function _checkSigningKeys(uint256 stateX, uint256 stateY, uint256 clearanceX, uint256 clearanceY, bool local)
        internal
        pure
    {
        _checkSigningKey("STATE_SIGNING_KEY", stateX, stateY);
        _checkSigningKey("CLEARANCE_SIGNING_KEY", clearanceX, clearanceY);
        require(stateX != clearanceX || stateY != clearanceY, "STATE_SIGNING_KEY and CLEARANCE_SIGNING_KEY must differ");
        if (!local) {
            require(!_isDevelopmentKey(stateX, stateY), "STATE_SIGNING_KEY is a published development key");
            require(!_isDevelopmentKey(clearanceX, clearanceY), "CLEARANCE_SIGNING_KEY is a published development key");
        }
    }

    function _checkSigningKey(string memory name, uint256 x, uint256 y) internal pure {
        require(x < BJJ_FIELD && y < BJJ_FIELD, string.concat(name, "_X/Y must be below the BN254 scalar field order"));
        require(_onBabyJubJub(x, y), string.concat(name, "_X/Y is not a Baby-JubJub point (swapped or mistyped?)"));
        require(x != 0 || y != 1, string.concat(name, "_X/Y is the identity"));
        (uint256 ox, uint256 oy, uint256 oz) = _babyJubJubMul(x, y, BJJ_ORDER);
        require(ox == 0 && oy == oz, string.concat(name, "_X/Y is not in the prime-order subgroup"));
    }

    function _isDevelopmentKey(uint256 x, uint256 y) internal pure returns (bool) {
        return (x == DEV_STATE_KEY_X && y == DEV_STATE_KEY_Y) || (x == DEV_CLEARANCE_KEY_X && y == DEV_CLEARANCE_KEY_Y);
    }

    function _onBabyJubJub(uint256 x, uint256 y) internal pure returns (bool) {
        uint256 xx = mulmod(x, x, BJJ_FIELD);
        uint256 yy = mulmod(y, y, BJJ_FIELD);
        return addmod(xx, yy, BJJ_FIELD) == addmod(1, mulmod(BJJ_D, mulmod(xx, yy, BJJ_FIELD), BJJ_FIELD), BJJ_FIELD);
    }

    /// k * (x, y) in projective coordinates (X : Y : Z), the affine point being (X / Z, Y / Z).
    function _babyJubJubMul(uint256 x, uint256 y, uint256 k)
        internal
        pure
        returns (uint256 rx, uint256 ry, uint256 rz)
    {
        (rx, ry, rz) = (0, 1, 1);
        for (uint256 bit = 256; bit > 0; --bit) {
            (rx, ry, rz) = _babyJubJubAdd(rx, ry, rz, rx, ry, rz);
            if ((k >> (bit - 1)) & 1 == 1) (rx, ry, rz) = _babyJubJubAdd(rx, ry, rz, x, y, 1);
        }
    }

    /// Projective twisted Edwards addition with a = 1 (add-2008-bbjlp). It is unified (it also
    /// doubles) and complete on this curve, since d is not a square in the field.
    function _babyJubJubAdd(uint256 x1, uint256 y1, uint256 z1, uint256 x2, uint256 y2, uint256 z2)
        internal
        pure
        returns (uint256 x3, uint256 y3, uint256 z3)
    {
        uint256 q = BJJ_FIELD;
        uint256 a = mulmod(z1, z2, q);
        uint256 b = mulmod(a, a, q);
        uint256 c = mulmod(x1, x2, q);
        uint256 d = mulmod(y1, y2, q);
        uint256 e = mulmod(BJJ_D, mulmod(c, d, q), q);
        uint256 f = addmod(b, q - e, q);
        uint256 g = addmod(b, e, q);
        uint256 h = addmod(mulmod(addmod(x1, y1, q), addmod(x2, y2, q), q), q - addmod(c, d, q), q);
        x3 = mulmod(mulmod(a, f, q), h, q);
        y3 = mulmod(mulmod(a, g, q), addmod(d, q - c, q), q);
        z3 = mulmod(f, g, q);
    }
}
