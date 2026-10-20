// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Errors} from "./Errors.sol";
import {IBn254Poseidon} from "../interfaces/IBn254Poseidon.sol";

/// @title MerkleUpdateLib
/// @notice The request tree: depth 32, zero leaves, node = compress("zkapi.v2.node", left, right) of
///         the vault's Poseidon (zkapi_core::v2::merkle_node), note ID as the leaf index, each note's
///         leaf its stored leaf (zero once retired). Only request proofs use the tree; exits are
///         bound to the stored leaf itself. The vault keeps the tree as its frontier and computes
///         the root on demand (root, the currentRoot() view): `filled[t]`, t >= 1, holds the
///         complete left subtree of height t that the next right subtree at that height is hashed
///         with; `filled[0]` is never stored, the left leaf being the note's own word.
/// @dev `filled[t]` is meaningful while bit t of the next index is set: it is written by the append
///      that completes a subtree of height t (the index's trailing ones), and by a retirement inside
///      that subtree (retire). Entries at zero bits are subtrees already absorbed into higher ones.
///      The hashing is done by the vault's IBn254Poseidon (compress), called with STATICCALL; a
///      failed call reverts the caller.
library MerkleUpdateLib {
    uint256 internal constant MERKLE_DEPTH = 32;
    uint256 internal constant FIELD_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"
    /// @dev ZERO_HASHES[i]: the root of an empty subtree of height i, 33 words from height 0 (the
    ///      zero leaf) to 32 (EMPTY_ROOT): zkapi_core::merkle::compute_zero_hashes, printed by
    ///      `cargo run -p zkapi-core --example poseidon_vectors`.
    bytes internal constant ZERO_HASHES = hex"0000000000000000000000000000000000000000000000000000000000000000"
        hex"03b561b48dcefd3f971d0959dc5332965246b6b1c358db6eb3fb00aee48fabe4"
        hex"03dc3bd54a66bb606a5a65c4420332bb1ca46ca81807b5c6bd07513340d4f447"
        hex"1d4a0344466f644ea623aca5fcd706399e00c8db9b2f64644dd720f7e2da8637"
        hex"0bc2d0b66e03d008f67c1ce3cfa5668ed702e1fc63a8263af4715e34e6e73186"
        hex"0323fc7ef522cf2afe1b55ddba658e12e4c469737173b38e40058dd1d902cf42"
        hex"25e4864e6fc215e565a84ffa86447027bea749de648243c5b698621f67b830f5"
        hex"051fe7618eb582271b816a0eab7932441db20b1b8fc6e4edb1b5e931dab76dd1"
        hex"29c535b21baa10dec4cb9df2420b4d17a8c6de7035c1139aa12a6947e5ad33b5"
        hex"2f9f7b2cf344632165441ede1508b25b5f9c2ef75785452f9905636c83e82ea7"
        hex"088ad4ce01cad380d4bf7819d98252d7ea177cfec7b9b098b05dd0796368ea84"
        hex"10a3526f3e7bc912fb9327f0772f220de131eb0f05668cf9e97778a249b80f7d"
        hex"17cbfba7484b1a3f66bf35b561e874bca48d9177eb5ad5fe2674f1a4504295a7"
        hex"0344b62d59f6b9ca3c77fe7b8c50cb8f7011e24f4c5322831adaf7463c0d0aee"
        hex"1622d71880cdc7d575f0f5c25e4b0a22d385c59a5b5b9b3e7015ecbd9f2d3f0f"
        hex"2e67e74e249a19a9f861a09f0d292c0f912c905686390f9392b1d998d6d1c458"
        hex"300556c6ca01ae5216ac40739da004673a915b1290a3cb98e73f3862dce979b8"
        hex"260fdb3c8ba4a5887b4ea9e4366e95e3739106c6fe109d50c414a066c2c4ccb8"
        hex"1cd14ba35abc09506d6a64b2f4368f6a0fa90b4806d3de97979ebe3108c80deb"
        hex"2b98c728b234ef2461496ac37444650e081519ecec71a9a9c6a87c449f8fdaca"
        hex"14a4db65f45211c1e92d1d55438fc954265d43420765503c5b3fa32e1f8be813"
        hex"13430a532736848c7257eeaa378e918b46b09b6d2ddac15daf881727f2458881"
        hex"0349afc05bb1ceb4731513adde6bb0abddba5166a823496041b50da1a41ae038"
        hex"19d0172bf591e5c70b71a458814be47900849768f0720b2942f8c020f891fca2"
        hex"0fbdd5ddb51c4f5e149adf94742f174005ab4e1c434754ce4d1ff81e589e367d"
        hex"0d184c91cbfb4a23df0dfe738d0914aabaa6e3906c7f08ced95882a7648b1355"
        hex"0fc70b969992a3b988540f56ae93aa5e0e4da776763ba0b332cd8d3cd932e9d1"
        hex"25b5f22c7f68518ce5a5fadb2dcfa48410111b89e84afa384b05b0fa717fe46e"
        hex"1d72100e8134ce7a10aebdf0290343d026dfbfa578f0ecf694b8292db06b4e8e"
        hex"1daea6f2611eb3e555a4aa4af8a1d9a995733ea15ce1e64715ee0419ea21fbd6"
        hex"2a0c071ff0f8457ac989e489d8c49e0a4f50b35cc73ff43b91a2b99d38ef9aaf"
        hex"26a160bb312d0bb45883d22c7a893a96101cf5b79daa5afaa65b241a4c0cd4e7"
        hex"1eb94e909bac5b6e3331993876bdde00f84b31e0103a29af6617fc021318b81e";
    /// @notice The root of the empty tree (ZERO_HASHES[32]).
    uint256 internal constant EMPTY_ROOT = 0x1eb94e909bac5b6e3331993876bdde00f84b31e0103a29af6617fc021318b81e;

    /// @notice One permutation of (capacity, left, right), its lane 1: `poseidon.compress`, called
    ///         with STATICCALL from scratch memory (the call's revert data is bubbled).
    function compress(IBn254Poseidon poseidon, uint256 capacity, uint256 left, uint256 right)
        internal
        view
        returns (uint256 out)
    {
        assembly ("memory-safe") {
            let m := mload(0x40)
            // compress(uint256,uint256,uint256)
            mstore(m, shl(224, 0x2d0c7694))
            mstore(add(m, 0x04), capacity)
            mstore(add(m, 0x24), left)
            mstore(add(m, 0x44), right)
            if iszero(and(gt(returndatasize(), 0x1f), staticcall(gas(), poseidon, m, 0x64, 0x00, 0x20))) {
                returndatacopy(m, 0x00, returndatasize())
                revert(m, returndatasize())
            }
            out := mload(0x00)
        }
    }

    function poseidonNodeHash(IBn254Poseidon poseidon, uint256 left, uint256 right) internal view returns (uint256) {
        return compress(poseidon, DOMAIN_NODE, left, right);
    }

    /// @notice The root of an empty subtree of height `level` (0 for a leaf, 32 for the tree).
    function zeroHash(uint256 level) internal pure returns (uint256 value) {
        bytes memory zeros = ZERO_HASHES;
        assembly ("memory-safe") {
            value := mload(add(add(zeros, 0x20), mul(level, 0x20)))
        }
    }

    /// @notice Appends `leaf` at the odd `index`, the next free slot, next to `leftLeaf` (the leaf at
    ///         index - 1): hashes the pair, then once per further trailing one of `index` with the
    ///         frontier entry of that level, and stores the completed subtree at the level of the
    ///         index's lowest zero bit. trailing_ones(index) compressions, one per append on average.
    ///         An even index completes nothing and needs no call.
    /// @dev The caller guarantees index < 2^32 - 1 (TreeFull), so the stored level is at most 31.
    function append(IBn254Poseidon poseidon, uint256[32] storage filled, uint32 index, uint256 leftLeaf, uint256 leaf)
        internal
    {
        uint256 node = compress(poseidon, DOMAIN_NODE, leftLeaf, leaf);
        uint256 level = 1;
        while ((index >> level) & 1 == 1) {
            node = compress(poseidon, DOMAIN_NODE, filled[level], node);
            unchecked {
                ++level;
            }
        }
        filled[level] = node;
    }

    /// @notice The root of the tree with `nextIndex` leaves whose last leaf is `lastLeaf` (zero when
    ///         nextIndex is even, where it is unused): over the bits of nextIndex from the bottom, a
    ///         set bit hashes the frontier entry (the last leaf at level 0) to the left of the node so
    ///         far, a clear bit hashes the node with an empty subtree on the right, and below the
    ///         lowest set bit the node is an empty subtree. At most 32 compressions.
    function root(IBn254Poseidon poseidon, uint256[32] storage filled, uint32 nextIndex, uint256 lastLeaf)
        internal
        view
        returns (uint256 node)
    {
        bytes memory zeros = ZERO_HASHES;
        bool empty = true;
        for (uint256 level = 0; level < MERKLE_DEPTH;) {
            if ((nextIndex >> level) & 1 == 1) {
                node = compress(poseidon, DOMAIN_NODE, level == 0 ? lastLeaf : filled[level], node);
                empty = false;
            } else if (empty) {
                assembly ("memory-safe") {
                    node := mload(add(add(zeros, 0x40), mul(level, 0x20)))
                }
            } else {
                uint256 zero;
                assembly ("memory-safe") {
                    zero := mload(add(add(zeros, 0x20), mul(level, 0x20)))
                }
                node = compress(poseidon, DOMAIN_NODE, node, zero);
            }
            unchecked {
                ++level;
            }
        }
    }

    /// @notice The level whose frontier entry a retirement of `index` rewrites while `nextIndex` is
    ///         the next free slot: the highest bit where the two differ. Below it, `index` lies in the
    ///         complete left subtree `filled[level]` (or, at level 0, it is the last leaf).
    function retireLevel(uint32 index, uint32 nextIndex) internal pure returns (uint256 level) {
        uint256 differing = uint256(index ^ nextIndex);
        level = MERKLE_DEPTH - 1;
        while ((differing >> level) & 1 == 0) {
            unchecked {
                --level;
            }
        }
    }

    /// @notice Sets the leaf at `index` (below `nextIndex`) from `oldLeaf` to zero in the frontier:
    ///         nothing to rewrite at level 0 (the leaf is the caller's own word); otherwise the old
    ///         and new nodes of `index`'s subtree of that level are computed from siblings[0..level)
    ///         (bottom up), the old one must equal `filled[level]` (else StaleRoot), and the new one
    ///         replaces it. siblings[level..32) are never read; callers zero-fill them. 2 * level
    ///         compressions.
    /// @dev A retirement elsewhere in the same subtree changes `filled[level]`, so a path read
    ///      before it is stale; deposits only ever change it by completing a subtree, which moves
    ///      `level` instead (a fresh path then gives the new level).
    function retire(
        IBn254Poseidon poseidon,
        uint256[32] storage filled,
        uint32 nextIndex,
        uint32 index,
        uint256 oldLeaf,
        uint256[32] calldata siblings
    ) internal {
        uint256 level = retireLevel(index, nextIndex);
        if (level == 0) return;
        uint256 oldNode = oldLeaf;
        uint256 newNode = 0;
        for (uint256 height = 0; height < level;) {
            uint256 sibling = siblings[height];
            if ((index >> height) & 1 == 0) {
                oldNode = compress(poseidon, DOMAIN_NODE, oldNode, sibling);
                newNode = compress(poseidon, DOMAIN_NODE, newNode, sibling);
            } else {
                oldNode = compress(poseidon, DOMAIN_NODE, sibling, oldNode);
                newNode = compress(poseidon, DOMAIN_NODE, sibling, newNode);
            }
            unchecked {
                ++height;
            }
        }
        if (oldNode != filled[level]) revert Errors.StaleRoot();
        filled[level] = newNode;
    }
}
