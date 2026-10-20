// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title IBn254Poseidon
/// @notice The vault's Poseidon over the BN254 scalar field: src/poseidon/Bn254PoseidonRuntime.sol,
///         deployed once and passed to the vault's constructor. Every function is pure, so the
///         vault calls it with STATICCALL and a failed call reverts the vault's call.
interface IBn254Poseidon {
    /// @notice One permutation of the state (capacity, left, right), its lane 1: the note tree's
    ///         node hash with capacity = DOMAIN_NODE (zkapi_core::v2::compress_fields).
    function compress(uint256 capacity, uint256 left, uint256 right) external pure returns (uint256);

    /// @notice The sponge over five inputs (zkapi_core::v2::hash_fields), the note leaf.
    function hash5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e) external pure returns (uint256);

    /// @notice The root of the depth-32 tree with leaf at index, from the leaf's siblings (bottom
    ///         up), and the node the insertion completes: the path's node at the level of the
    ///         lowest zero bit of index (the leaf itself when index is even, the root when every
    ///         bit is set).
    function insertPath32(uint256 capacity, uint32 index, uint256 leaf, uint256[32] calldata siblings)
        external
        pure
        returns (uint256 root, uint256 completed);

    /// @notice The roots of the depth-32 tree with oldLeaf and with newLeaf at index, from the
    ///         leaf's siblings (bottom up), and the new path's node at nodeLevel (the leaf at 0,
    ///         the root at 32 and above): 64 compressions with capacity as the node domain.
    function compressPairPath32(
        uint256 capacity,
        uint32 index,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] calldata siblings,
        uint256 nodeLevel
    ) external pure returns (uint256 oldRoot, uint256 newRoot, uint256 newNode);
}
