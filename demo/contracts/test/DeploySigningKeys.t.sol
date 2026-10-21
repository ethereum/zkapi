// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SigningKeyChecks} from "../script/SigningKeyChecks.sol";

/// @dev Exposes the deployment script's signing-key checks.
contract DeploySigningKeysHarness is SigningKeyChecks {
    function checkSigningKeys(uint256 sx, uint256 sy, uint256 cx, uint256 cy, bool local) external pure {
        _checkSigningKeys(sx, sy, cx, cy, local);
    }

    function mul(uint256 x, uint256 y, uint256 k) external pure returns (uint256, uint256, uint256) {
        return _babyJubJubMul(x, y, k);
    }
}

/// @dev Deploy.s.sol refuses signing keys that are not points of Baby-JubJub's prime-order
///      subgroup (ark-ed-on-bn254), the identity, one key for both roles, and off local chains
///      the published development keys, before it deploys anything. Vectors were computed
///      independently (affine arithmetic in Python).
contract DeploySigningKeysTest is Test {
    uint256 constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041;
    // The development keys of seeds 0x1 (state) and 0x2 (clearance).
    uint256 constant DEV_SX = 0x2b8cfd91b905cae31d41e7dedf4a927ee3bc429aad7e344d59d2810d82876c32;
    uint256 constant DEV_SY = 0x2aaa6c24a758209e90aced1f10277b762a7c1115dbc0e16ac276fc2c671a861f;
    uint256 constant DEV_CX = 0x1812b84c2101217b0939a2f542535075eeaa81d07dab701a899a55db26e85be4;
    uint256 constant DEV_CY = 0x0be80d0f61a801533a94a03b12683474f86ca012941db1c568c53dc877b16fd6;
    // Subgroup points with one coordinate between 2^63 and 2^64 (odd, so no double holds it):
    // serializeUint would write it as a bare JSON number that JavaScript rounds.
    uint256 constant WIDE_Y_X = 0x05503c73ffee28fcacc324d533595173a637420b99492265bf57c2c286f59cd7;
    uint256 constant WIDE_Y_Y = 9_223_372_036_854_775_867;
    uint256 constant WIDE_X_X = 9_223_372_036_854_775_849;
    uint256 constant WIDE_X_Y = 0x2f46a27130a593f9edcbdaf446ca1029bb5c18d0c9a12ac3c7e9be74b61444f1;

    string constant STATE_OFF_CURVE = "STATE_SIGNING_KEY_X/Y is not a Baby-JubJub point (swapped or mistyped?)";
    string constant CLEARANCE_OFF_CURVE = "CLEARANCE_SIGNING_KEY_X/Y is not a Baby-JubJub point (swapped or mistyped?)";
    string constant STATE_OFF_SUBGROUP = "STATE_SIGNING_KEY_X/Y is not in the prime-order subgroup";
    string constant CLEARANCE_OFF_SUBGROUP = "CLEARANCE_SIGNING_KEY_X/Y is not in the prime-order subgroup";

    DeploySigningKeysHarness harness;

    function setUp() public {
        harness = new DeploySigningKeysHarness();
    }

    function test_acceptsSubgroupKeys() public view {
        harness.checkSigningKeys(DEV_SX, DEV_SY, DEV_CX, DEV_CY, true);
        harness.checkSigningKeys(WIDE_Y_X, WIDE_Y_Y, WIDE_X_X, WIDE_X_Y, false);
        // -P = (-x, y) is in the subgroup with P.
        harness.checkSigningKeys(P - WIDE_Y_X, WIDE_Y_Y, WIDE_X_X, WIDE_X_Y, false);
    }

    /// The scalar multiplication itself: (l + 1) P = P projectively, and 8l kills any curve point.
    function test_scalarMultiplication() public view {
        (uint256 x, uint256 y, uint256 z) = harness.mul(DEV_SX, DEV_SY, ORDER + 1);
        assertEq(x, mulmod(DEV_SX, z, P));
        assertEq(y, mulmod(DEV_SY, z, P));
        (x, y, z) = harness.mul(P - DEV_SX, P - DEV_SY, ORDER);
        assertEq(x, 0);
        assertEq(y, P - z);
        (x, y, z) = harness.mul(P - DEV_SX, P - DEV_SY, 8 * ORDER);
        assertEq(x, 0);
        assertEq(y, z);
    }

    /// The CI simulation's former keys (11, 12) and (13, 14) are not curve points.
    function test_refusesKeysOffTheCurve() public {
        vm.expectRevert(bytes(STATE_OFF_CURVE));
        harness.checkSigningKeys(11, 12, DEV_CX, DEV_CY, true);
        vm.expectRevert(bytes(CLEARANCE_OFF_CURVE));
        harness.checkSigningKeys(DEV_SX, DEV_SY, 13, 14, true);
        // A truncated coordinate.
        vm.expectRevert(bytes(STATE_OFF_CURVE));
        harness.checkSigningKeys(DEV_SX >> 4, DEV_SY, DEV_CX, DEV_CY, true);
    }

    /// Points of small order, and points with a small-order component, are on the curve but not
    /// in the prime-order subgroup: (0, -1) has order 2, (1, 0) order 4, (-x, -y) is P plus the
    /// order-2 point, and the swapped (y, x) is -P plus an order-4 point.
    function test_refusesPointsOutsideThePrimeOrderSubgroup() public {
        vm.expectRevert(bytes(STATE_OFF_SUBGROUP));
        harness.checkSigningKeys(0, P - 1, DEV_CX, DEV_CY, true);
        vm.expectRevert(bytes(STATE_OFF_SUBGROUP));
        harness.checkSigningKeys(1, 0, DEV_CX, DEV_CY, true);
        vm.expectRevert(bytes(STATE_OFF_SUBGROUP));
        harness.checkSigningKeys(P - DEV_SX, P - DEV_SY, DEV_CX, DEV_CY, true);
        vm.expectRevert(bytes(CLEARANCE_OFF_SUBGROUP));
        harness.checkSigningKeys(DEV_SX, DEV_SY, DEV_CY, DEV_CX, true);
        vm.expectRevert(bytes("STATE_SIGNING_KEY_X/Y is the identity"));
        harness.checkSigningKeys(0, 1, DEV_CX, DEV_CY, true);
    }

    function test_refusesCoordinatesOutsideTheField() public {
        vm.expectRevert(bytes("STATE_SIGNING_KEY_X/Y must be below the BN254 scalar field order"));
        harness.checkSigningKeys(DEV_SX + P, DEV_SY, DEV_CX, DEV_CY, true);
        vm.expectRevert(bytes("CLEARANCE_SIGNING_KEY_X/Y must be below the BN254 scalar field order"));
        harness.checkSigningKeys(DEV_SX, DEV_SY, DEV_CX, DEV_CY + P, true);
    }

    function test_refusesOneKeyForBothRoles() public {
        vm.expectRevert(bytes("STATE_SIGNING_KEY and CLEARANCE_SIGNING_KEY must differ"));
        harness.checkSigningKeys(WIDE_X_X, WIDE_X_Y, WIDE_X_X, WIDE_X_Y, false);
    }

    /// Off local chains neither development key may be pinned, in either role.
    function test_refusesDevelopmentKeysOffLocalChains() public {
        vm.expectRevert(bytes("STATE_SIGNING_KEY is a published development key"));
        harness.checkSigningKeys(DEV_SX, DEV_SY, WIDE_X_X, WIDE_X_Y, false);
        vm.expectRevert(bytes("STATE_SIGNING_KEY is a published development key"));
        harness.checkSigningKeys(DEV_CX, DEV_CY, WIDE_X_X, WIDE_X_Y, false);
        vm.expectRevert(bytes("CLEARANCE_SIGNING_KEY is a published development key"));
        harness.checkSigningKeys(WIDE_Y_X, WIDE_Y_Y, DEV_CX, DEV_CY, false);
        vm.expectRevert(bytes("CLEARANCE_SIGNING_KEY is a published development key"));
        harness.checkSigningKeys(WIDE_Y_X, WIDE_Y_Y, DEV_SX, DEV_SY, false);
    }
}
