// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {IBn254Poseidon} from "../src/interfaces/IBn254Poseidon.sol";
import {Bn254PoseidonReference} from "./reference/Bn254PoseidonReference.sol";
import {PoseidonRuntime} from "./helpers/PoseidonRuntime.sol";

/// @dev The vault's Poseidon (src/poseidon/Bn254PoseidonRuntime.sol, legacy-compiled, deployed
///      from its artifact) against known answers from zkapi-core and, call for call, against the
///      independent reference implementation (the former Bn254Poseidon library): the same success
///      and the same returned bytes for any calldata, including non-canonical words, dirty uint32
///      high bits, short or long calldata and unknown selectors. The runtime is also pinned: its
///      source is the setup's generated copy and its code hashes to poseidon-runtime.json's
///      runtime_codehash.
contract Bn254PoseidonRuntimeTest is Test {
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"
    bytes4 internal constant COMPRESS = 0x2d0c7694;
    bytes4 internal constant HASH5 = 0xc98aeff5;
    bytes4 internal constant INSERT_PATH = 0x21d2c645;
    bytes4 internal constant PAIR_PATH = 0xf6073d4e;
    /// ABI head sizes after the selector: 3, 5, 3 + 32 and 5 + 32 words.
    uint256 internal constant COMPRESS_ARGS = 96;
    uint256 internal constant HASH5_ARGS = 160;
    uint256 internal constant INSERT_PATH_ARGS = 1120;
    uint256 internal constant PAIR_PATH_ARGS = 1184;

    address internal runtime;
    address internal oracle;

    function setUp() public {
        runtime = PoseidonRuntime.deploy();
        oracle = address(Bn254PoseidonReference);
    }

    // ------------------------------------------------------------------ known answers

    /// zkapi-core's merkle_node(1, 2), the empty tree's first zero hash and hash_fields([1..5])
    /// (protocol/formal checks these vectors against its specification in the Lean kernel).
    function test_matchesRustVectors() public view {
        _assertCompress(
            0x7a6b6170692e76322e6e6f6465, 1, 2, 0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1
        );
        _assertCompress(
            0x7a6b6170692e76322e6e6f6465, 0, 0, 0x03b561b48dcefd3f971d0959dc5332965246b6b1c358db6eb3fb00aee48fabe4
        );
        _assertHash5(1, 2, 3, 4, 5, 0x26081ccbe44f775603e118e5d9152fbbff51c9d7af1a96c9d25ddc7cbed55457);
    }

    function _assertCompress(uint256 capacity, uint256 left, uint256 right, uint256 expected) internal view {
        assertEq(IBn254Poseidon(runtime).compress(capacity, left, right), expected, "runtime compress");
        assertEq(Bn254PoseidonReference.compress(capacity, left, right), expected, "reference compress");
    }

    function _assertHash5(uint256 a, uint256 b, uint256 c, uint256 d, uint256 e, uint256 expected) internal view {
        assertEq(IBn254Poseidon(runtime).hash5(a, b, c, d, e), expected, "runtime hash5");
        assertEq(Bn254PoseidonReference.hash5(a, b, c, d, e), expected, "reference hash5");
    }

    /// The tree's zero hashes from the runtime's insertPath32 on an empty frontier: inserting the
    /// zero leaf at index 0 with the zero siblings gives the empty root.
    function test_emptyTreeRoot() public view {
        uint256[32] memory zeros;
        uint256 z;
        for (uint256 level = 0; level < 32; ++level) {
            zeros[level] = z;
            z = IBn254Poseidon(runtime).compress(DOMAIN_NODE, z, z);
        }
        assertEq(z, 0x1eb94e909bac5b6e3331993876bdde00f84b31e0103a29af6617fc021318b81e, "EMPTY_ROOT");
        (uint256 root, uint256 completed) = IBn254Poseidon(runtime).insertPath32(DOMAIN_NODE, 0, 0, zeros);
        assertEq(root, z);
        assertEq(completed, 0);
    }

    // ------------------------------------------------------------------ differential

    /// Every argument word goes through _word, so canonical words, words just above p, multiples of
    /// p plus a small offset and words near 2^256 all occur often (a uniform word is >= p about 81%
    /// of the time).
    function testFuzz_compress(uint256 capacity, uint256 left, uint256 right) public view {
        _same(abi.encodePacked(COMPRESS, _word(capacity), _word(left), _word(right)));
    }

    function testFuzz_hash5(uint256[5] memory words) public view {
        for (uint256 i = 0; i < 5; ++i) {
            words[i] = _word(words[i]);
        }
        _same(abi.encodePacked(HASH5, words));
    }

    function testFuzz_insertPath32(
        uint256 capacity,
        uint256 indexWord,
        uint256 leaf,
        uint256[32] memory siblings,
        bool dirtyIndex
    ) public view {
        if (!dirtyIndex) indexWord = uint32(indexWord);
        _words(siblings);
        _same(abi.encodePacked(INSERT_PATH, _word(capacity), indexWord, _word(leaf), siblings));
    }

    function testFuzz_compressPairPath32(
        uint256 capacity,
        uint256 indexWord,
        uint256 oldLeaf,
        uint256 newLeaf,
        uint256[32] memory siblings,
        uint256 nodeLevel,
        bool dirtyIndex
    ) public view {
        if (!dirtyIndex) indexWord = uint32(indexWord);
        if (nodeLevel % 3 != 0) nodeLevel %= 40;
        _words(siblings);
        _same(
            abi.encodePacked(PAIR_PATH, _word(capacity), indexWord, _word(oldLeaf), _word(newLeaf), siblings, nodeLevel)
        );
    }

    /// Maps a fuzzed seed onto one of the input classes that matter for a modular implementation:
    /// the raw word, x mod p, p + x, 2^256 - 1 - k, p - 1 - k, k * p + d (k in 1..5) and small words.
    function _word(uint256 seed) internal pure returns (uint256) {
        uint256 kind = seed & 7;
        uint256 x = seed >> 3;
        if (kind == 0) return seed;
        if (kind == 1 || kind == 7) return x % P;
        if (kind == 2) return P + x % (type(uint256).max - P);
        if (kind == 3) return type(uint256).max - (x & 0xff);
        if (kind == 4) return P - 1 - (x & 0xff);
        if (kind == 5) return (x % 5 + 1) * P + ((x >> 8) & 0xffff);
        return x & 0xff;
    }

    function _words(uint256[32] memory words) internal pure {
        for (uint256 i = 0; i < 32; ++i) {
            words[i] = _word(words[i]);
        }
    }

    /// Any calldata at all.
    function testFuzz_anyCalldata(bytes calldata data) public view {
        _same(data);
    }

    /// One of the four selectors followed by `length` pseudo-random bytes, lengths clustered around
    /// each entry point's minimum.
    function testFuzz_lengths(uint8 which, uint16 length, bytes32 seed) public view {
        (bytes4 selector, uint256 args) = _entry(which);
        length = uint16(bound(length, args > 40 ? args - 40 : 0, args + 72));
        _same(abi.encodePacked(selector, _stream(seed, length)));
    }

    /// Every entry point at its minimum length and one byte either side, with word sizes of
    /// extra data, on fixed words that include 0, p - 1, p, p + 1 and 2^256 - 1.
    function test_lengthBoundaries() public view {
        for (uint8 which = 0; which < 4; ++which) {
            (bytes4 selector, uint256 args) = _entry(which);
            bytes memory body = _edgeWords(args);
            for (uint256 cut = 0; cut <= 2; ++cut) {
                bytes memory shorter = _prefix(body, args - cut);
                (bool ok,) = runtime.staticcall(abi.encodePacked(selector, shorter));
                assertEq(ok, cut == 0, "only the full length succeeds");
                _same(abi.encodePacked(selector, shorter));
            }
            _same(abi.encodePacked(selector, body, uint8(1)));
            _same(abi.encodePacked(selector, body, uint256(type(uint256).max), uint256(7)));
            _same(abi.encodePacked(selector));
            _same(abi.encodePacked(selector, uint8(1), uint8(2)));
        }
    }

    function test_shortCalldataAndUnknownSelectors() public view {
        _same("");
        _same(hex"2d");
        _same(hex"2d0c76");
        _same(hex"c98aef");
        _same(abi.encodePacked(bytes4(0x00000000), _edgeWords(PAIR_PATH_ARGS)));
        _same(abi.encodePacked(bytes4(0x2d0c7695), _edgeWords(COMPRESS_ARGS)));
        _same(abi.encodePacked(bytes4(0xffffffff), _edgeWords(HASH5_ARGS)));
        for (uint8 which = 0; which < 4; ++which) {
            (bytes4 selector,) = _entry(which);
            (bool ok, bytes memory ret) = runtime.staticcall(abi.encodePacked(selector ^ bytes4(0x00000100)));
            assertFalse(ok);
            assertEq(ret.length, 0, "reverts with no data");
        }
    }

    /// Non-canonical words (at or above p, up to 2^256 - 1) on every input, as the reference reduces them.
    function test_nonCanonicalInputs() public view {
        uint256[6] memory words = [uint256(0), P - 1, P, P + 1, type(uint256).max, 2 * P + 5];
        for (uint256 i = 0; i < words.length; ++i) {
            for (uint256 j = 0; j < words.length; ++j) {
                _same(abi.encodePacked(COMPRESS, words[i], words[j], words[(i + j) % words.length]));
                _same(abi.encodePacked(HASH5, words[i], words[j], words[(i + 1) % 6], words[(j + 2) % 6], words[i]));
            }
        }
        assertEq(
            IBn254Poseidon(runtime).compress(DOMAIN_NODE + P, 1 + P, 2 + 2 * P),
            0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1
        );
        uint256[32] memory siblings;
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = words[level % words.length];
        }
        for (uint256 i = 0; i < words.length; ++i) {
            _same(abi.encodePacked(INSERT_PATH, words[i], uint256(0x5a5a5a5a), words[(i + 3) % 6], siblings));
            _same(
                abi.encodePacked(
                    PAIR_PATH, words[i], uint256(0xa5a5a5a5), words[(i + 1) % 6], words[(i + 4) % 6], siblings, i * 7
                )
            );
        }
    }

    /// index must be a clean uint32: any high bit set reverts, as solc's ABI decoder does.
    function test_dirtyIndexReverts() public view {
        uint256[32] memory siblings;
        uint256[5] memory indices =
            [uint256(1) << 32, (uint256(1) << 32) | 5, type(uint256).max, uint256(1) << 255, (uint256(1) << 32) - 1];
        for (uint256 i = 0; i < indices.length; ++i) {
            bytes memory insert = abi.encodePacked(INSERT_PATH, DOMAIN_NODE, indices[i], uint256(9), siblings);
            bytes memory pair =
                abi.encodePacked(PAIR_PATH, DOMAIN_NODE, indices[i], uint256(9), uint256(0), siblings, uint256(3));
            bool clean = indices[i] <= type(uint32).max;
            (bool ok,) = runtime.staticcall(insert);
            assertEq(ok, clean, "insertPath32");
            (ok,) = runtime.staticcall(pair);
            assertEq(ok, clean, "compressPairPath32");
            _same(insert);
            _same(pair);
        }
    }

    /// nodeLevel 0 is the leaf, 32 and anything above it the root, as in the reference.
    function test_nodeLevels() public view {
        uint256[32] memory siblings;
        for (uint256 level = 0; level < 32; ++level) {
            siblings[level] = uint256(keccak256(abi.encode(level))) % P;
        }
        uint256[8] memory levels = [uint256(0), 1, 5, 31, 32, 33, 1 << 64, type(uint256).max];
        for (uint256 i = 0; i < levels.length; ++i) {
            bytes memory data = abi.encodePacked(
                PAIR_PATH, DOMAIN_NODE, uint256(0x8000_0001), uint256(11), uint256(12), siblings, levels[i]
            );
            _same(data);
            (,, uint256 newNode) =
                IBn254Poseidon(runtime).compressPairPath32(DOMAIN_NODE, 0x8000_0001, 11, 12, siblings, levels[i]);
            if (levels[i] == 0) assertEq(newNode, 12, "the leaf at level 0");
            if (levels[i] >= 32) {
                (, uint256 newRoot,) =
                    IBn254Poseidon(runtime).compressPairPath32(DOMAIN_NODE, 0x8000_0001, 11, 12, siblings, 0);
                assertEq(newNode, newRoot, "the root from level 32 on");
            }
        }
        for (uint32 index = 0; index < 9; ++index) {
            _same(abi.encodePacked(INSERT_PATH, DOMAIN_NODE, uint256(index), uint256(77), siblings));
        }
        _same(abi.encodePacked(INSERT_PATH, DOMAIN_NODE, uint256(type(uint32).max), uint256(77), siblings));
    }

    /// The runtime takes no ether: a call with value reverts, whatever the calldata. The vault
    /// only ever STATICCALLs it, which carries none.
    function test_rejectsCallValue() public {
        vm.deal(address(this), 1 ether);
        (bool ok, bytes memory ret) =
            runtime.call{value: 1}(abi.encodePacked(COMPRESS, DOMAIN_NODE, uint256(1), uint256(2)));
        assertFalse(ok);
        assertEq(ret.length, 0);
        (ok,) = runtime.call{value: 1}("");
        assertFalse(ok);
        (ok,) = payable(runtime).call{value: 0}(abi.encodePacked(COMPRESS, DOMAIN_NODE, uint256(1), uint256(2)));
        assertTrue(ok);
        assertEq(runtime.balance, 0);
    }

    // ------------------------------------------------------------------ pins

    /// The setup's generated source is the one compiled here, the sidecar's SHA-256 is its hash,
    /// and the compiled runtime (and a deployed one) hashes to the sidecar's runtime_codehash.
    function test_runtimeIsThePinnedGeneratorOutput() public view {
        string memory dir = _setupDir();
        string memory source = vm.readFile(string.concat(vm.projectRoot(), "/src/poseidon/Bn254PoseidonRuntime.sol"));
        assertEq(source, vm.readFile(string.concat(dir, "/Bn254PoseidonRuntime.sol")), "src copy is the setup's");
        string memory sidecar = vm.readFile(string.concat(dir, "/poseidon-runtime.json"));
        assertEq(vm.parseJsonString(sidecar, ".contract"), "Bn254PoseidonRuntime");
        assertEq(vm.parseJsonString(sidecar, ".source_sha256"), _hex(sha256(bytes(source))), "source_sha256");
        bytes32 pinned = vm.parseJsonBytes32(sidecar, ".runtime_codehash");
        assertEq(keccak256(vm.getDeployedCode(PoseidonRuntime.ARTIFACT)), pinned, "compiled runtime codehash");
        assertEq(runtime.codehash, pinned, "deployed runtime codehash");
        assertFalse(vm.parseJsonBool(sidecar, ".compiler.via_ir"));
        assertEq(vm.parseJsonUint(sidecar, ".compiler.optimizer_runs"), 10_000);
        assertEq(vm.parseJsonString(sidecar, ".compiler.solc"), "0.8.28");
        bytes4[4] memory selectors = [COMPRESS, HASH5, INSERT_PATH, PAIR_PATH];
        for (uint256 i = 0; i < 4; ++i) {
            string memory entry = string.concat(".entry_points[", vm.toString(i), "]");
            assertEq(vm.parseJsonBytes(sidecar, string.concat(entry, ".selector")), abi.encodePacked(selectors[i]));
        }
        assertFalse(vm.keyExistsJson(sidecar, ".entry_points[4]"));
        assertEq(IBn254Poseidon.compress.selector, COMPRESS);
        assertEq(IBn254Poseidon.hash5.selector, HASH5);
        assertEq(IBn254Poseidon.insertPath32.selector, INSERT_PATH);
        assertEq(IBn254Poseidon.compressPairPath32.selector, PAIR_PATH);
        assertEq(Bn254PoseidonReference.insertPath32.selector, INSERT_PATH);
        assertEq(Bn254PoseidonReference.compressPairPath32.selector, PAIR_PATH);
    }

    /// The point of the runtime: well under the 24,576-byte limit, and a 32-level insertion
    /// (32 permutations) costs about half of the reference's.
    function test_sizeAndCost() public {
        assertLt(runtime.code.length, 24_576);
        uint256[32] memory siblings;
        bytes memory data = abi.encodePacked(INSERT_PATH, DOMAIN_NODE, uint256(5), uint256(7), siblings);
        vm.cool(runtime);
        (bool ok,) = runtime.staticcall(data);
        assertTrue(ok);
        uint256 fast = vm.lastCallGas().gasTotalUsed;
        vm.cool(oracle);
        (ok,) = oracle.staticcall(data);
        assertTrue(ok);
        uint256 slow = vm.lastCallGas().gasTotalUsed;
        emit log_named_uint("insertPath32 runtime", fast);
        emit log_named_uint("insertPath32 reference", slow);
        assertLt(fast, 450_000, "runtime insertPath32");
        assertLt(fast * 10, slow * 6, "under 60% of the reference");
    }

    // ------------------------------------------------------------------ helpers

    /// The same success and the same returned bytes from the runtime and the reference (`oracle`).
    function _same(bytes memory data) internal view {
        (bool okRuntime, bytes memory retRuntime) = runtime.staticcall(data);
        (bool okReference, bytes memory retReference) = oracle.staticcall(data);
        assertEq(okRuntime, okReference, "success differs");
        assertEq(retRuntime, retReference, "returned bytes differ");
        if (!okRuntime) assertEq(retRuntime.length, 0, "reverts carry no data");
    }

    function _entry(uint8 which) internal pure returns (bytes4 selector, uint256 args) {
        which %= 4;
        if (which == 0) return (COMPRESS, COMPRESS_ARGS);
        if (which == 1) return (HASH5, HASH5_ARGS);
        if (which == 2) return (INSERT_PATH, INSERT_PATH_ARGS);
        return (PAIR_PATH, PAIR_PATH_ARGS);
    }

    /// `length` bytes of keccak stream from `seed`.
    function _stream(bytes32 seed, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; i += 32) {
            bytes32 word = keccak256(abi.encode(seed, i));
            for (uint256 k = 0; k < 32 && i + k < length; ++k) {
                out[i + k] = word[k];
            }
        }
    }

    /// `args` bytes of argument words: an index word (the second) kept a clean uint32, the
    /// others cycling through edge values.
    function _edgeWords(uint256 args) internal pure returns (bytes memory out) {
        uint256[6] memory edges = [uint256(0), P - 1, P, P + 1, type(uint256).max, 12345];
        for (uint256 w = 0; w < args / 32; ++w) {
            out = abi.encodePacked(out, w == 1 ? uint256(0x1234_5678) : edges[w % edges.length]);
        }
    }

    function _prefix(bytes memory data, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i = 0; i < length; ++i) {
            out[i] = data[i];
        }
    }

    function _hex(bytes32 value) internal pure returns (string memory) {
        bytes memory text = bytes(vm.toString(value));
        bytes memory out = new bytes(64);
        for (uint256 i = 0; i < 64; ++i) {
            out[i] = text[i + 2];
        }
        return string(out);
    }

    /// The setup directory, named as Groth16ProofAdapterTest.setupPath names it.
    function _setupDir() internal view returns (string memory) {
        string memory dir = vm.envOr("ZKAPI_SETUP_DIR", string(""));
        if (bytes(dir).length == 0) return string.concat(vm.projectRoot(), "/../setup/v2-concession-dev");
        if (bytes(dir)[0] == "/") return dir;
        return string.concat(vm.projectRoot(), "/../rust/", dir);
    }
}
