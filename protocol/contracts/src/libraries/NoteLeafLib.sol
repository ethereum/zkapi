// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IBn254Poseidon} from "../interfaces/IBn254Poseidon.sol";
import {MerkleUpdateLib} from "./MerkleUpdateLib.sol";

/// @title NoteLeafLib
/// @notice The note leaf of circuit zkapi-v2-concession-v2: one Poseidon permutation with the leaf
///         domain in the capacity lane, L = P(d_leaf', commitment, F)[1] where
///         F = noteId * 2^192 + depositAmount * 2^64 + expiryTs (zkapi_core::v2::note_leaf). The
///         vault stores L per note and appends it to the request tree; withdrawal proofs publish L
///         and F, and bind L to the owner's registration commitment.
library NoteLeafLib {
    uint256 internal constant DOMAIN_LEAF = 0x7a6b6170692e7632632e6c656166; // "zkapi.v2c.leaf"
    /// @dev Every packed F is below 2^FIELDS_BITS.
    uint256 internal constant FIELDS_BITS = 224;

    /// @notice F = noteId * 2^192 + depositAmount * 2^64 + expiryTs: injective, and below 2^224.
    function pack(uint32 noteId, uint128 depositAmount, uint64 expiryTs) internal pure returns (uint256) {
        return (uint256(noteId) << 192) | (uint256(depositAmount) << 64) | uint256(expiryTs);
    }

    /// @notice The (noteId, depositAmount, expiryTs) of a packed F; the caller has checked that F is
    ///         below 2^224, so each part is exact.
    function unpack(uint256 fields) internal pure returns (uint32 noteId, uint128 depositAmount, uint64 expiryTs) {
        // casting to 'uint32', 'uint128' and 'uint64' is safe because each takes exactly its own
        // bits of a value below 2^224: noteId bits 192-223, depositAmount bits 64-191, expiryTs 0-63
        // forge-lint: disable-next-line(unsafe-typecast)
        noteId = uint32(fields >> 192);
        // forge-lint: disable-next-line(unsafe-typecast)
        depositAmount = uint128(fields >> 64);
        // forge-lint: disable-next-line(unsafe-typecast)
        expiryTs = uint64(fields);
    }

    /// @notice L = P(d_leaf', commitment, fields)[1], by the vault's Poseidon.
    function computeLeaf(IBn254Poseidon poseidon, bytes32 commitment, uint256 fields) internal view returns (uint256) {
        return MerkleUpdateLib.compress(poseidon, DOMAIN_LEAF, uint256(commitment), fields);
    }
}
