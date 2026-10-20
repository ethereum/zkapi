// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {NoteLeafLib} from "../../src/libraries/NoteLeafLib.sol";
import {Bn254PoseidonReference} from "../reference/Bn254PoseidonReference.sol";

/// @dev The vault's Poseidon in tests: src/poseidon/Bn254PoseidonRuntime.sol, taken from its
///      artifact. Tests never import that file: it is compiled with the legacy pipeline, and an
///      importer would join its compiler profile.
library PoseidonRuntime {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    string internal constant ARTIFACT = "Bn254PoseidonRuntime.sol:Bn254PoseidonRuntime";
    /// @dev Where etch puts it: an address no test creates.
    address internal constant ADDRESS = address(uint160(uint256(keccak256("zkapi.test.poseidon-runtime"))));

    /// @dev The runtime code at ADDRESS (written once) and ADDRESS. No nonce moves, so the vault
    ///      and adapter addresses that the proof fixtures bind stay where they are.
    function etch() internal returns (address) {
        if (ADDRESS.code.length == 0) VM.etch(ADDRESS, VM.getDeployedCode(ARTIFACT));
        return ADDRESS;
    }

    /// @dev A fresh deployment by its creation code (a CREATE from the calling contract).
    function deploy() internal returns (address deployed) {
        bytes memory code = VM.getCode(ARTIFACT);
        assembly ("memory-safe") {
            deployed := create(0, add(code, 0x20), mload(code))
        }
        require(deployed != address(0), "Bn254PoseidonRuntime creation failed");
    }
}

/// @dev Expected values, computed with the independent reference implementation (the former
///      Bn254Poseidon library) rather than with the runtime the vault uses.
library ReferenceHashes {
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"

    /// @dev The note tree's node hash.
    function node(uint256 left, uint256 right) internal pure returns (uint256) {
        return Bn254PoseidonReference.compress(DOMAIN_NODE, left, right);
    }

    /// @dev NoteLeafLib.computeLeaf's leaf.
    function leaf(uint32 noteId, bytes32 commitment, uint128 depositAmount, uint64 expiryTs)
        internal
        pure
        returns (uint256)
    {
        return Bn254PoseidonReference.hash5(
            NoteLeafLib.DOMAIN_LEAF, uint256(noteId), uint256(commitment), uint256(depositAmount), uint256(expiryTs)
        );
    }
}
