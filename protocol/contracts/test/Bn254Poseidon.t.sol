// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";

contract Bn254PoseidonTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;

    function test_matchesRustVectors() public pure {
        assertEq(
            Bn254Poseidon.compress(0x7a6b6170692e76322e6e6f6465, 1, 2),
            0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1
        );
        assertEq(
            Bn254Poseidon.compress(0x7a6b6170692e76322e6e6f6465, 0, 0),
            0x03b561b48dcefd3f971d0959dc5332965246b6b1c358db6eb3fb00aee48fabe4
        );
        assertEq(Bn254Poseidon.hash5(1, 2, 3, 4, 5), 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457);
    }

    /// compressSubtree is the complete binary tree of compress over its leaves; an empty subtree
    /// of height h is ZERO_HASHES[h].
    function test_compressSubtreeIsTheBinaryTreeOfCompress() public pure {
        uint256[] memory four = new uint256[](4);
        for (uint256 i = 0; i < 4; ++i) {
            four[i] = 11 + i;
        }
        assertEq(Bn254Poseidon.compressSubtree(DOMAIN_NODE, four), _node(_node(11, 12), _node(13, 14)), "four leaves");
        uint256[] memory one = new uint256[](1);
        one[0] = 42;
        assertEq(Bn254Poseidon.compressSubtree(DOMAIN_NODE, one), 42, "one leaf");
        assertEq(Bn254Poseidon.compressSubtree(DOMAIN_NODE, new uint256[](16)), MerkleUpdateLib.zeroHash(4), "empty");
    }

    function test_compressSubtreeRefusesAWidthThatIsNotAPowerOfTwo() public {
        uint256[3] memory widths = [uint256(0), 3, 12];
        for (uint256 i = 0; i < widths.length; ++i) {
            vm.expectRevert();
            this.subtree(new uint256[](widths[i]));
        }
    }

    /// compressPairPath from startLevel hashes the two nodes up with siblings[startLevel..31] and
    /// ignores the siblings below.
    function test_compressPairPathStartsAtItsLevel() public pure {
        uint256[32] memory siblings;
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = 1000 + level;
        }
        uint32 index = 0x0000_0054; // bits 2, 4 and 6 set
        (uint256 oldRoot, uint256 newRoot) = Bn254Poseidon.compressPairPath(DOMAIN_NODE, index, 7, 8, siblings, 2);
        uint256 expectedOld = 7;
        uint256 expectedNew = 8;
        for (uint256 level = 2; level < 32; ++level) {
            bool right = ((index >> level) & 1) == 1;
            expectedOld = right ? _node(siblings[level], expectedOld) : _node(expectedOld, siblings[level]);
            expectedNew = right ? _node(siblings[level], expectedNew) : _node(expectedNew, siblings[level]);
        }
        assertEq(oldRoot, expectedOld);
        assertEq(newRoot, expectedNew);
        siblings[0] = 1;
        siblings[1] = 2;
        (uint256 oldAgain, uint256 newAgain) = Bn254Poseidon.compressPairPath(DOMAIN_NODE, index, 7, 8, siblings, 2);
        assertEq(oldAgain, oldRoot);
        assertEq(newAgain, newRoot);
    }

    function subtree(uint256[] memory leaves) external pure returns (uint256) {
        return Bn254Poseidon.compressSubtree(DOMAIN_NODE, leaves);
    }

    function _node(uint256 left, uint256 right) private pure returns (uint256) {
        return Bn254Poseidon.compress(DOMAIN_NODE, left, right);
    }
}
