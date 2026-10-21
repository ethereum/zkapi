// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";

contract Bn254PoseidonTest is Test {
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
}
