// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {BatchTestBase} from "./BatchTestBase.sol";

/// @dev The adapter against the reference batch verifier (zkapi-proof's batch module) through the
///      shared vectors of test/fixtures/batch-verifier-vectors.json, which the Rust tests recompute:
///      the transcript (seed and challenges, recomputed here from the bytes), the outcome of every
///      case (success, InvalidProof() or the empty revert of a dirty field) and, run with the tracer
///      (-vvv, as CI runs), the exact pairing input the adapter hands to the precompile.
contract BatchVectorsTest is BatchTestBase {
    string vectors;

    function setUp() public {
        _loadBatchFixtures();
        adapter = _deployAdapter();
        vectors = vm.readFile("test/fixtures/batch-verifier-vectors.json");
    }

    function _case(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "].", field);
    }

    function _cases() internal view returns (uint256 n) {
        while (vm.keyExistsJson(vectors, string.concat(".cases[", vm.toString(n), "]"))) ++n;
    }

    /// The constants the transcript and the records start from, as the generator derives them.
    function test_constants() public view {
        assertEq(vm.parseJsonBytes32(vectors, ".batch_domain"), keccak256("zkapi.groth16.batch.v1"));
        bytes32 record = keccak256("zkapi.groth16.request-record.v1");
        assertEq(vm.parseJsonBytes32(vectors, ".request_record"), record);
        assertGe(uint256(record), 1 << 160, "no destination can name a request record");
        assertEq(vm.parseJsonBytes32(vectors, ".withdrawal_vk_hash"), adapter.WITHDRAWAL_VK_HASH());
        assertEq(vm.parseJsonBytes32(vectors, ".request_vk_hash"), adapter.REQUEST_VK_HASH());
    }

    /// Every case's seed and challenges recomputed from its bytes, and the adapter's outcome.
    function test_transcriptsAndOutcomes() public {
        uint256 count = _cases();
        assertGt(count, 20, "vectors");
        for (uint256 i = 0; i < count; ++i) {
            (bytes memory data, bool request, uint256 n, bytes memory inputs, bytes memory proofs) = _callOf(i);
            // the transcript
            bytes32 seed;
            bool seeded = n >= 2 && proofs.length == 256 * n;
            if (seeded) {
                bytes32 vkHash = request ? adapter.REQUEST_VK_HASH() : adapter.WITHDRAWAL_VK_HASH();
                seed = keccak256(abi.encodePacked(keccak256("zkapi.groth16.batch.v1"), vkHash, n, inputs, proofs));
                assertEq(vm.parseJsonBytes32(vectors, _case(i, "seed")), seed, "seed");
            }
            uint256[] memory challenges = vm.parseJsonUintArray(vectors, _case(i, "challenges"));
            assertEq(challenges.length, n, "one challenge per item");
            for (uint256 k = 0; k < n; ++k) {
                uint256 r = k == 0 || !seeded ? 1 : uint256(keccak256(abi.encode(seed, k))) >> 128;
                assertEq(challenges[k], r, "challenge");
            }
            // the outcome
            vm.cool(address(adapter));
            (bool ok, bytes memory ret) = address(adapter).call{gas: 30_000_000}(data);
            string memory outcome = vm.parseJsonString(vectors, _case(i, "outcome"));
            string memory name = vm.parseJsonString(vectors, _case(i, "name"));
            if (keccak256(bytes(outcome)) == keccak256("ok")) {
                assertTrue(ok, name);
            } else if (keccak256(bytes(outcome)) == keccak256("invalid_proof")) {
                assertFalse(ok, name);
                assertEq(ret, abi.encodeWithSelector(Errors.InvalidProof.selector), name);
            } else {
                assertEq(outcome, "dirty_field");
                assertFalse(ok, name);
                assertEq(ret.length, 0, name);
            }
        }
    }

    /// With the tracer: the pairing input of every case that reaches the pairing is the reference's,
    /// byte for byte, so the adapter computes the reference's transcript, challenges, combination
    /// and shared multi-scalar multiplication.
    function test_pairingInputIsTheReferences() public {
        bool tracer;
        try vm.startDebugTraceRecording() {
            tracer = true;
        } catch {}
        if (!tracer) {
            console.log("the pairing-input check needs the tracer: run forge test -vvv");
            vm.skip(true);
        }
        vm.stopAndReturnDebugTraceRecording();
        uint256 count = _cases();
        uint256 checked;
        for (uint256 i = 0; i < count; ++i) {
            if (!vm.keyExistsJson(vectors, _case(i, "pairing_input"))) continue;
            bytes memory expected;
            try vm.parseJsonBytes(vectors, _case(i, "pairing_input")) returns (bytes memory b) {
                expected = b;
            } catch {
                continue; // null
            }
            if (expected.length == 0) continue;
            (bytes memory data,, uint256 n,,) = _callOf(i);
            // A trace keeps every step in memory, whose cost grows with its square: one external
            // frame per case (its memory is freed on return), and no case above four items.
            if (n > 4) continue;
            (bytes memory pairing, uint256 pairings) = this.tracePairing(data);
            assertEq(pairings, 1, "one pairing");
            assertEq(pairing, expected, vm.parseJsonString(vectors, _case(i, "name")));
            ++checked;
        }
        assertGt(checked, 8, "pairing inputs checked");
    }

    /// The adapter's pairing-precompile input for `data`, traced in a frame of its own.
    function tracePairing(bytes calldata data) external returns (bytes memory pairing, uint256 pairings) {
        vm.startDebugTraceRecording();
        (bool ok,) = address(adapter).call{gas: 30_000_000}(data);
        Vm.DebugStep[] memory steps = vm.stopAndReturnDebugTraceRecording();
        ok;
        for (uint256 k = 0; k < steps.length; ++k) {
            if (steps[k].contractAddr == address(adapter) && steps[k].opcode == 0xfa && steps[k].stack[1] == 8) {
                pairing = steps[k].memoryInput;
                ++pairings;
            }
        }
    }

    /// The case's raw verify*Batch calldata (its words need not decode).
    function _callOf(uint256 i)
        internal
        view
        returns (bytes memory data, bool request, uint256 n, bytes memory inputs, bytes memory proofs)
    {
        request = keccak256(bytes(vm.parseJsonString(vectors, _case(i, "kind")))) == keccak256("request");
        n = vm.parseJsonUint(vectors, _case(i, "n"));
        inputs = vm.parseJsonBytes(vectors, _case(i, "inputs"));
        proofs = vm.parseJsonBytes(vectors, _case(i, "proofs"));
        data = request
            ? _rawBatchCall(adapter.verifyRequestBatch.selector, 0x180, inputs, proofs)
            : _rawBatchCall(adapter.verifyWithdrawalBatch.selector, 0x200, inputs, proofs);
        assertEq(inputs.length, n * (request ? 0x180 : 0x200), "whole statements");
    }
}
