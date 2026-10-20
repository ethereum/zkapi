// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {IBn254Poseidon} from "../src/interfaces/IBn254Poseidon.sol";
import {PoseidonRuntime, ReferenceHashes} from "./helpers/PoseidonRuntime.sol";

/// @dev The vault's use of MerkleUpdateLib with arbitrary leaves: the leaf words, the frontier and
///      the next index as the vault stores them (filled[0] unused, the left leaf of an append from
///      the leaf words).
contract MerkleUpdateHarness {
    IBn254Poseidon internal immutable poseidon;
    uint256[32] internal filled;
    mapping(uint32 => uint256) public leaves;
    uint32 public next;

    constructor(IBn254Poseidon poseidon_) {
        poseidon = poseidon_;
    }

    function setState(uint32 next_, uint256[32] calldata filled_) external {
        next = next_;
        filled = filled_;
    }

    function setLeaf(uint32 index, uint256 leaf) external {
        leaves[index] = leaf;
    }

    function append(uint256 leaf) external {
        uint32 index = next;
        if (index & 1 == 1) MerkleUpdateLib.append(poseidon, filled, index, leaves[index - 1], leaf);
        leaves[index] = leaf;
        next = index + 1;
    }

    function root() external view returns (uint256) {
        uint32 count = next;
        return MerkleUpdateLib.root(poseidon, filled, count, count & 1 == 1 ? leaves[count - 1] : 0);
    }

    function retire(uint32 index, uint256[32] calldata siblings) external {
        MerkleUpdateLib.retire(poseidon, filled, next, index, leaves[index], siblings);
        leaves[index] = 0;
    }

    function frontierNode(uint256 level) external view returns (uint256) {
        return filled[level];
    }
}

/// @dev A full sparse tree for the differential tests: every node stored, updated along the path of
///      each set leaf with the vault's Poseidon (the runtime, which Bn254PoseidonRuntimeTest and
///      protocol/formal tie to the reference; the cross-language vectors use Rust's tree).
contract ReferenceTree {
    IBn254Poseidon internal immutable poseidon;
    mapping(uint256 => mapping(uint256 => uint256)) internal nodes;
    mapping(uint256 => bool) internal set;

    constructor(IBn254Poseidon poseidon_) {
        poseidon = poseidon_;
    }

    function node(uint256 level, uint256 index) public view returns (uint256) {
        if (!set[(level << 32) | index]) return MerkleUpdateLib.zeroHash(level);
        return nodes[level][index];
    }

    function setLeaf(uint32 index, uint256 leaf) external {
        nodes[0][index] = leaf;
        set[index] = true;
        uint256 at = index;
        for (uint256 level = 0; level < 32; ++level) {
            uint256 parent = at >> 1;
            uint256 value =
                MerkleUpdateLib.poseidonNodeHash(poseidon, node(level, parent << 1), node(level, (parent << 1) | 1));
            nodes[level + 1][parent] = value;
            set[((level + 1) << 32) | parent] = true;
            at = parent;
        }
    }

    function root() external view returns (uint256) {
        return node(32, 0);
    }

    function siblings(uint32 index) external view returns (uint256[32] memory path) {
        uint256 at = index;
        for (uint256 level = 0; level < 32; ++level) {
            path[level] = node(level, at ^ 1);
            at >>= 1;
        }
    }
}

contract MerkleUpdateLibTest is Test {
    string internal vectors;
    MerkleUpdateHarness internal harness;
    IBn254Poseidon internal poseidon;

    function setUp() public {
        vectors = vm.readFile("test/fixtures/frontier-vectors.json");
        poseidon = IBn254Poseidon(PoseidonRuntime.etch());
        harness = new MerkleUpdateHarness(poseidon);
    }

    uint256[] internal leaves;

    /// The vectors' leaves, parsed once (each cheatcode call copies the whole file to memory).
    function _leaf(uint256 index) internal returns (uint256) {
        if (leaves.length == 0) leaves = vm.parseJsonUintArray(vectors, ".leaves");
        return leaves[index];
    }

    function _words(string memory key) internal view returns (uint256[32] memory out) {
        uint256[] memory parsed = vm.parseJsonUintArray(vectors, key);
        assertEq(parsed.length, 32);
        for (uint256 i = 0; i < 32; ++i) {
            out[i] = parsed[i];
        }
    }

    /// The first siblings of a path; the rest zero-filled or garbage.
    function _cut(uint256[32] memory path, uint256 level, bool garbage) internal pure returns (uint256[32] memory) {
        for (uint256 i = level; i < 32; ++i) {
            path[i] = garbage ? uint256(keccak256(abi.encode(i))) : 0;
        }
        return path;
    }

    /// The empty tree's root is ZERO_HASHES[32], and the compression helper is the reference node.
    function test_emptyRootAndNodeHash() public view {
        assertEq(harness.root(), MerkleUpdateLib.EMPTY_ROOT);
        assertEq(MerkleUpdateLib.zeroHash(32), MerkleUpdateLib.EMPTY_ROOT);
        assertEq(MerkleUpdateLib.poseidonNodeHash(poseidon, 1, 2), ReferenceHashes.node(1, 2));
    }

    /// Appends of the Rust vectors' 1,100 leaves: the computed root equals zkapi_core's Frontier (and
    /// full tree) after every append up to 80 and around every 2^k up to 2^10, and each append
    /// writes the frontier entry of its trailing ones.
    function test_rootsMatchTheRustFrontier() public {
        uint256 checkpoints = vm.parseJsonUint(vectors, ".root_count");
        uint256[] memory nexts = new uint256[](checkpoints);
        uint256[] memory roots = new uint256[](checkpoints);
        for (uint256 i = 0; i < checkpoints; ++i) {
            string memory at = string.concat(".roots[", vm.toString(i), "]");
            nexts[i] = vm.parseJsonUint(vectors, string.concat(at, ".next"));
            roots[i] = vm.parseJsonUint(vectors, string.concat(at, ".root"));
        }
        uint256 checkpoint = 0;
        for (uint256 index = 0; index <= 1_100; ++index) {
            if (checkpoint < checkpoints && nexts[checkpoint] == index) {
                assertEq(harness.root(), roots[checkpoint], vm.toString(index));
                ++checkpoint;
            }
            if (index < 1_100) harness.append(_leaf(index));
        }
        assertEq(checkpoint, checkpoints);
    }

    /// Retirements of the Rust vectors, in order, from the 1,100-leaf tree: with the siblings beyond
    /// the level zero-filled or garbage, the root equals Rust's after each.
    function test_retirementsMatchTheRustFrontier() public {
        for (uint256 index = 0; index < 1_100; ++index) {
            harness.append(_leaf(index));
        }
        uint256 count = vm.parseJsonUint(vectors, ".retirement_count");
        for (uint256 i = 0; i < count; ++i) {
            string memory at = string.concat(".retirements[", vm.toString(i), "]");
            // casting to 'uint32' is safe because the vectors' indices are below 1,100
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 index = uint32(vm.parseJsonUint(vectors, string.concat(at, ".index")));
            uint256 level = vm.parseJsonUint(vectors, string.concat(at, ".level"));
            assertEq(MerkleUpdateLib.retireLevel(index, harness.next()), level);
            uint256[32] memory path = _words(string.concat(at, ".siblings"));
            uint256 snapshot = vm.snapshotState();
            harness.retire(index, _cut(path, level, true));
            uint256 withGarbage = harness.root();
            vm.revertToState(snapshot);
            harness.retire(index, _cut(path, level, false));
            assertEq(harness.root(), vm.parseJsonUint(vectors, string.concat(at, ".root")));
            assertEq(withGarbage, harness.root());
        }
    }

    /// The vault's storage written directly at high indices (2^20, 2^31, 2^32 - 10), as Rust
    /// synthesizes it: the root, the appends after it and a deep retirement match.
    function test_syntheticHighIndicesMatchTheRustFrontier() public {
        uint256 states = vm.parseJsonUint(vectors, ".synthetic_count");
        for (uint256 s = 0; s < states; ++s) {
            string memory at = string.concat(".synthetic[", vm.toString(s), "]");
            harness = new MerkleUpdateHarness(poseidon);
            // casting to 'uint32' is safe because the vectors' indices are below 2^32
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 start = uint32(vm.parseJsonUint(vectors, string.concat(at, ".next")));
            harness.setState(start, _words(string.concat(at, ".filled")));
            uint256[] memory indices = vm.parseJsonUintArray(vectors, string.concat(at, ".leaf_indices"));
            uint256[] memory values = vm.parseJsonUintArray(vectors, string.concat(at, ".leaf_values"));
            for (uint256 i = 0; i < indices.length; ++i) {
                // forge-lint: disable-next-line(unsafe-typecast)
                harness.setLeaf(uint32(indices[i]), values[i]);
            }
            assertEq(harness.root(), vm.parseJsonUint(vectors, string.concat(at, ".root")));
            uint256[] memory appended = vm.parseJsonUintArray(vectors, string.concat(at, ".append_leaves"));
            uint256[] memory roots = vm.parseJsonUintArray(vectors, string.concat(at, ".append_roots"));
            for (uint256 i = 0; i < appended.length; ++i) {
                harness.append(appended[i]);
                assertEq(harness.root(), roots[i]);
            }
            // forge-lint: disable-next-line(unsafe-typecast)
            uint32 retired = uint32(vm.parseJsonUint(vectors, string.concat(at, ".retire.index")));
            uint256 level = vm.parseJsonUint(vectors, string.concat(at, ".retire.level"));
            harness.retire(retired, _cut(_words(string.concat(at, ".retire.siblings")), level, false));
            assertEq(harness.root(), vm.parseJsonUint(vectors, string.concat(at, ".retire.root")));
        }
    }

    /// Wrong siblings below the level, a path the level has since moved past, and a second
    /// retirement in the same subtree with a path read before the first: StaleRoot.
    function test_retireRefusesStalePaths() public {
        ReferenceTree tree = new ReferenceTree(poseidon);
        for (uint32 index = 0; index < 6; ++index) {
            harness.append(_leaf(index));
            tree.setLeaf(index, _leaf(index));
        }
        // Leaf 1 against next 6: level 2.
        assertEq(MerkleUpdateLib.retireLevel(1, 6), 2);
        uint256[32] memory path = _cut(tree.siblings(1), 2, false);
        uint256[32] memory wrong = path;
        wrong[1] ^= 1;
        vm.expectRevert(Errors.StaleRoot.selector);
        harness.retire(1, wrong);
        // Two more appends complete leaf 1's subtree of height 3: the level moves to 3 and the
        // zero-filled level-2 path no longer reproduces filled[3].
        harness.append(_leaf(6));
        harness.append(_leaf(7));
        tree.setLeaf(6, _leaf(6));
        tree.setLeaf(7, _leaf(7));
        assertEq(MerkleUpdateLib.retireLevel(1, 8), 3);
        vm.expectRevert(Errors.StaleRoot.selector);
        harness.retire(1, path);
        // Same subtree: the path of 0 read before 1 is retired is stale afterwards.
        uint256[32] memory pathOf0 = _cut(tree.siblings(0), 3, false);
        harness.retire(1, _cut(tree.siblings(1), 3, false));
        tree.setLeaf(1, 0);
        assertEq(harness.root(), tree.root());
        vm.expectRevert(Errors.StaleRoot.selector);
        harness.retire(0, pathOf0);
        harness.retire(0, _cut(tree.siblings(0), 3, false));
        tree.setLeaf(0, 0);
        assertEq(harness.root(), tree.root());
    }

    /// At level 0 (the last leaf of an odd count) nothing is read: any siblings retire it.
    function test_retireAtLevelZeroReadsNoSibling() public {
        for (uint32 index = 0; index < 5; ++index) {
            harness.append(_leaf(index));
        }
        assertEq(MerkleUpdateLib.retireLevel(4, 5), 0);
        uint256[32] memory garbage;
        for (uint256 i = 0; i < 32; ++i) {
            garbage[i] = i + 1;
        }
        uint256 frontierBefore = harness.frontierNode(2);
        harness.retire(4, garbage);
        assertEq(harness.frontierNode(2), frontierBefore);
        ReferenceTree tree = new ReferenceTree(poseidon);
        for (uint32 index = 0; index < 4; ++index) {
            tree.setLeaf(index, _leaf(index));
        }
        assertEq(harness.root(), tree.root());
    }

    /// forge-config: default.fuzz.runs = 48
    /// Random appends and retirements (at most 40 operations) against the full tree: the computed
    /// root agrees after every operation.
    function testFuzz_appendAndRetireMatchTheFullTree(uint256 seed) public {
        ReferenceTree tree = new ReferenceTree(poseidon);
        uint32[] memory live = new uint32[](40);
        uint256 liveCount;
        for (uint256 step = 0; step < 40; ++step) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            if (liveCount == 0 || seed % 3 != 0) {
                uint32 index = harness.next();
                uint256 leaf = (seed >> 8) % MerkleUpdateLib.FIELD_MODULUS;
                if (leaf == 0) leaf = 1;
                harness.append(leaf);
                tree.setLeaf(index, leaf);
                live[liveCount++] = index;
            } else {
                uint256 pick = (seed >> 16) % liveCount;
                uint32 index = live[pick];
                live[pick] = live[--liveCount];
                uint256 level = MerkleUpdateLib.retireLevel(index, harness.next());
                harness.retire(index, _cut(tree.siblings(index), level, (seed >> 24) & 1 == 1));
                tree.setLeaf(index, 0);
            }
            assertEq(harness.root(), tree.root());
        }
    }
}
