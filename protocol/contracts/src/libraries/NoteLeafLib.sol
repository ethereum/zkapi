// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBn254Poseidon} from "../interfaces/IBn254Poseidon.sol";

library NoteLeafLib {
    uint256 internal constant DOMAIN_LEAF = 0x7a6b6170692e76322e6c656166; // "zkapi.v2.leaf"

    /// @notice The note leaf hash5("zkapi.v2.leaf", noteId, commitment, depositAmount, expiryTs)
    ///         (zkapi_core::v2::note_leaf), by the vault's Poseidon.
    function computeLeaf(
        IBn254Poseidon poseidon,
        uint32 noteId,
        bytes32 commitment,
        uint128 depositAmount,
        uint64 expiryTs
    ) internal pure returns (uint256) {
        return poseidon.hash5(
            DOMAIN_LEAF, uint256(noteId), uint256(commitment), uint256(depositAmount), uint256(expiryTs)
        );
    }
}
