// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {BatchTestBase} from "./BatchTestBase.sol";

struct UserOpsPerAggregator {
    PackedUserOperation[] userOps;
    address aggregator;
    bytes signature;
}

interface IEntryPointAggregated {
    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary) external;
}

/// @dev An aggregator whose validateSignatures runs the adapter call carried in `signature`, as
///      an IAggregator route to the records would.
contract RecordingAggregator {
    address public immutable adapter;

    constructor(address adapter_) {
        adapter = adapter_;
    }

    function validateSignatures(PackedUserOperation[] calldata, bytes calldata signature) external {
        (bool ok,) = adapter.call(signature);
        require(ok, "adapter call failed");
    }
}

/// @dev The review suites of the batch verifier, ported to the generated adapter: the differential
///      fuzz against the AND of single verifications, single-word tampering of a valid batch,
///      subsets, aliasing at +r for every input, truncation, and the static context of an
///      IAggregator (EntryPoint v0.7.0's validateSignatures), where the records cannot be written.
contract BatchAdversarialTest is BatchTestBase {
    address constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address constant SENDER_CREATOR = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;

    /// The pool the fuzzers draw from: 12 folded withdrawals (closes and escapes) and 4 generic ones.
    bytes[] pool;

    function setUp() public {
        _loadBatchFixtures();
        adapter = _deployAdapter();
        for (uint256 i = 0; i < 6; ++i) {
            pool.push(bytes.concat(abi.encode(w[i]), wp[i]));
            pool.push(bytes.concat(abi.encode(w[N + i]), wp[N + i]));
        }
        for (uint256 i = 0; i < FOREIGN; ++i) {
            pool.push(bytes.concat(abi.encode(fw[i]), fwp[i]));
        }
    }

    /// An item's raw words (16) and proof (256 bytes).
    function _split(bytes memory item) internal pure returns (bytes memory words, bytes memory proof) {
        words = new bytes(0x200);
        proof = new bytes(0x100);
        for (uint256 i = 0; i < 0x200; ++i) {
            words[i] = item[i];
        }
        for (uint256 i = 0; i < 0x100; ++i) {
            proof[i] = item[0x200 + i];
        }
    }

    /// assertValidWithdrawal of raw words, which need not decode, from a fresh frame (no record
    /// exists in these tests, so it always verifies in full); a failing precompile burns its gas.
    function _single(bytes memory item) internal returns (bool ok) {
        (bytes memory words, bytes memory proof) = _split(item);
        bytes memory data = bytes.concat(
            adapter.assertValidWithdrawal.selector, words, abi.encode(uint256(0x220), uint256(0x100)), proof
        );
        (ok,) = address(adapter).staticcall{gas: 1_000_000}(data);
    }

    function _batch(bytes[] memory items) internal returns (bool ok, bytes memory ret) {
        bytes memory inputs;
        bytes memory proofs;
        for (uint256 i = 0; i < items.length; ++i) {
            (bytes memory words, bytes memory proof) = _split(items[i]);
            inputs = bytes.concat(inputs, words);
            proofs = bytes.concat(proofs, proof);
        }
        (ok, ret) = address(adapter).staticcall{gas: 10_000_000}(
            _rawBatchCall(adapter.verifyWithdrawalBatch.selector, 0x200, inputs, proofs)
        );
    }

    function _wordAt(bytes memory b, uint256 offset) internal pure returns (uint256 v) {
        assembly ("memory-safe") {
            v := mload(add(add(b, 0x20), offset))
        }
    }

    function _setWordAt(bytes memory b, uint256 offset, uint256 v) internal pure {
        assembly ("memory-safe") {
            mstore(add(add(b, 0x20), offset), v)
        }
    }

    /// The operator-batch-exits review's differential fuzz: a batch of up to six items drawn from
    /// the pool (duplicates allowed), one of them possibly tampered at one word (any input or proof
    /// word, by a small xor that often keeps a narrow field clean, or by a full delta), verifies
    /// exactly when every item verifies alone.
    /// forge-config: default.fuzz.runs = 3001
    function testFuzz_batchMatchesTheAndOfSingles(uint256 seed, uint8 victim, uint8 word, uint256 delta, uint8 mode)
        public
    {
        uint256 n = 1 + seed % 6;
        bytes[] memory items = new bytes[](n);
        for (uint256 i = 0; i < n; ++i) {
            items[i] = _copy(pool[uint256(keccak256(abi.encode(seed, i))) % pool.length]);
        }
        if (mode % 5 == 1 && n > 1) items[n - 1] = _copy(items[0]);
        if (mode % 5 >= 2) {
            uint256 v = victim % n;
            uint256 offset = 32 * uint256(word % 24);
            uint256 x = _wordAt(items[v], offset);
            unchecked {
                x = mode % 5 == 2 ? x ^ (delta & 0xffff) : x + (delta == 0 ? 1 : delta);
            }
            _setWordAt(items[v], offset, x);
        }
        bool expected = true;
        for (uint256 i = 0; i < n; ++i) {
            if (!_single(items[i])) expected = false;
        }
        (bool ok,) = _batch(items);
        assertEq(ok, expected, "the batch is the AND of its singles");
    }

    /// The gasless multi-exit review's tamper fuzz: any nonzero change of any one word of any item
    /// of a valid eight-item batch is refused.
    /// forge-config: default.fuzz.runs = 1024
    function testFuzz_singleWordTamperIsRefused(uint8 item, uint8 word, uint256 delta) public {
        item = uint8(bound(item, 0, 7));
        word = uint8(bound(word, 0, 23));
        delta = bound(delta, 1, type(uint256).max);
        bytes[] memory items = new bytes[](8);
        for (uint256 i = 0; i < 8; ++i) {
            items[i] = _copy(pool[i]);
        }
        uint256 x = _wordAt(items[item], 32 * uint256(word));
        unchecked {
            x += delta;
        }
        _setWordAt(items[item], 32 * uint256(word), x);
        (bool ok,) = _batch(items);
        assertFalse(ok, "a tampered batch was accepted");
    }

    /// Every nonempty subset of the pool's first eight items verifies, and its Once variant records
    /// exactly its items.
    function testFuzz_subsetsVerify(uint8 mask) public {
        vm.assume(mask != 0);
        uint256 n;
        for (uint256 i = 0; i < 8; ++i) {
            if (mask & (1 << i) != 0) ++n;
        }
        bytes[] memory items = new bytes[](n);
        uint256 j;
        for (uint256 i = 0; i < 8; ++i) {
            if (mask & (1 << i) != 0) items[j++] = pool[i];
        }
        (bool ok,) = _batch(items);
        assertTrue(ok);
    }

    /// Aliasing at +r: every input word of every position, plus the scalar field order, is refused:
    /// InvalidProof() for a field element, the empty revert for a narrow field (whose high bits it
    /// sets).
    function test_everyInputPlusRIsRefused() public {
        for (uint256 position = 0; position < 3; ++position) {
            for (uint256 k = 0; k < 16; ++k) {
                bytes[] memory items = new bytes[](3);
                for (uint256 i = 0; i < 3; ++i) {
                    items[i] = _copy(pool[i]);
                }
                uint256 x = _wordAt(items[position], 32 * k);
                _setWordAt(items[position], 32 * k, x + R);
                (bool ok, bytes memory ret) = _batch(items);
                assertFalse(ok, "aliased input");
                bool narrow = k <= 2 || k == 8 || k == 9 || k == 10 || k == 12 || k == 14 || k == 15;
                if (narrow) assertEq(ret.length, 0, "a narrow field");
                else assertTrue(_isInvalidProof(ret), "a field element");
            }
        }
    }

    /// Truncated proofs: every length that is not 256 · n is refused.
    function testFuzz_truncatedProofsAreRefused(uint16 cut) public {
        bytes memory inputs;
        bytes memory proofs;
        for (uint256 i = 0; i < 3; ++i) {
            (bytes memory words, bytes memory proof) = _split(pool[i]);
            inputs = bytes.concat(inputs, words);
            proofs = bytes.concat(proofs, proof);
        }
        uint256 keep = bound(cut, 0, proofs.length - 1);
        bytes memory shorter = new bytes(keep);
        for (uint256 i = 0; i < keep; ++i) {
            shorter[i] = proofs[i];
        }
        (bool ok, bytes memory ret) =
            address(adapter).staticcall(_rawBatchCall(adapter.verifyWithdrawalBatch.selector, 0x200, inputs, shorter));
        assertFalse(ok);
        assertTrue(_isInvalidProof(ret));
    }

    /// The IAggregator route to the records is closed: EntryPoint v0.7.0 calls validateSignatures in
    /// a static context, where an aggregator that runs verifyWithdrawalBatchOnce fails
    /// (SignatureValidationFailed), while the view batch runs there (its dummy operation fails
    /// later, for another reason).
    function test_entryPointAggregatorCannotRecord() public {
        vm.etch(ENTRY_POINT, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/entrypoint-v0.7.0.runtime.hex"))));
        vm.etch(SENDER_CREATOR, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/sender-creator-v0.7.0.runtime.hex"))));
        RecordingAggregator aggregator = new RecordingAggregator(address(adapter));
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 2);
        bytes4 signatureFailed = bytes4(keccak256("SignatureValidationFailed(address)"));
        for (uint256 k = 0; k < 2; ++k) {
            UserOpsPerAggregator[] memory opa = new UserOpsPerAggregator[](1);
            opa[0].userOps = new PackedUserOperation[](1);
            opa[0].userOps[0].sender = address(0xdead);
            opa[0].aggregator = address(aggregator);
            opa[0].signature = k == 0
                ? abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs))
                : abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs));
            vm.prank(address(0xb0b), address(0xb0b));
            (bool ok, bytes memory ret) = ENTRY_POINT.call{gas: 5_000_000}(
                abi.encodeCall(IEntryPointAggregated.handleAggregatedOps, (opa, payable(address(0xb0b))))
            );
            assertFalse(ok);
            if (k == 0) assertEq(bytes4(ret), signatureFailed, "Once fails in validateSignatures");
            else assertTrue(bytes4(ret) != signatureFailed, "the view batch passes validateSignatures");
            console.logBytes(ret);
        }
    }
}
