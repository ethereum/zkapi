// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Groth16ProofAdapter} from "../../src/adapters/Groth16ProofAdapter.sol";
import {IZkApiProofAdapter} from "../../src/interfaces/IZkApiProofAdapter.sol";
import {IZkApiBatchProofAdapter} from "../../src/interfaces/IZkApiBatchProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {BatchTestBase} from "./BatchTestBase.sol";

/// @dev Calls that must share one transaction with what they check (a record is transient).
contract BatchRecordCaller {
    function batchOnceThenAssert(
        Groth16ProofAdapter adapter,
        Types.WithdrawalPublicInputs[] calldata ins,
        bytes calldata proofs,
        Types.WithdrawalPublicInputs calldata asserted,
        bytes calldata assertedProof
    ) external returns (uint256 gasUsed) {
        adapter.verifyWithdrawalBatchOnce(ins, proofs);
        uint256 g0 = gasleft();
        adapter.assertValidWithdrawal(asserted, assertedProof);
        gasUsed = g0 - gasleft();
    }

    function requestBatchOnceThenAssert(
        Groth16ProofAdapter adapter,
        Types.RequestPublicInputs[] calldata ins,
        bytes calldata proofs,
        Types.RequestPublicInputs calldata asserted,
        bytes calldata assertedProof
    ) external returns (uint256 gasUsed) {
        adapter.verifyRequestBatchOnce(ins, proofs);
        uint256 g0 = gasleft();
        adapter.assertValidRequest(asserted, assertedProof);
        gasUsed = g0 - gasleft();
    }

    /// A batch (Once or view, by `data`), then a raw call (which may revert), in one transaction.
    function thenTry(Groth16ProofAdapter adapter, bytes calldata first, bytes calldata second)
        external
        returns (bool ok, bytes memory ret, uint256 gasUsed)
    {
        (bool firstOk,) = address(adapter).call(first);
        require(firstOk, "first call");
        uint256 g0 = gasleft();
        (ok, ret) = address(adapter).staticcall(second);
        gasUsed = g0 - gasleft();
    }
}

/// @dev The generated adapter's random-linear-combination batch verification
///      (verifyWithdrawalBatch, verifyRequestBatch and their Once variants) against real proofs
///      (BatchTestBase): it accepts exactly the batches whose every item verifies alone, with the
///      single verification's checks and errors, refuses the cancellation a fixed combination
///      admits, and its Once variants leave the records the vault's single calls then find.
contract BatchVerifierTest is BatchTestBase {
    BatchRecordCaller caller;

    function setUp() public {
        _loadBatchFixtures();
        adapter = _deployAdapter();
        caller = new BatchRecordCaller();
    }

    function _wb(Types.WithdrawalPublicInputs[] memory ins, bytes memory prs)
        internal
        returns (bool ok, bytes memory ret)
    {
        (ok,, ret) = _call(address(adapter), abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs)));
    }

    function _qb(Types.RequestPublicInputs[] memory ins, bytes memory prs)
        internal
        returns (bool ok, bytes memory ret)
    {
        (ok,, ret) = _call(address(adapter), abi.encodeCall(adapter.verifyRequestBatch, (ins, prs)));
    }

    // ------------------------------------------------------------------------------ correctness

    function test_supportsBothInterfaces() public view {
        assertTrue(adapter.supportsInterface(type(IZkApiProofAdapter).interfaceId), "the single interface stays");
        assertTrue(adapter.supportsInterface(type(IZkApiBatchProofAdapter).interfaceId));
        assertTrue(adapter.supportsInterface(0x01ffc9a7));
        assertFalse(adapter.supportsInterface(0xffffffff));
        assertFalse(adapter.supportsInterface(IZkApiBatchProofAdapter.verifyWithdrawalBatch.selector));
    }

    /// Every fixture statement verifies alone; the foreign ones on the generic path.
    function test_fixtureProofsVerifySingly() public view {
        for (uint256 i = 0; i < 2 * N; ++i) {
            adapter.assertValidWithdrawal(w[i], wp[i]);
            adapter.assertValidRequest(q[i], qp[i]);
        }
        for (uint256 i = 0; i < FOREIGN; ++i) {
            adapter.assertValidWithdrawal(fw[i], fwp[i]);
            adapter.assertValidRequest(fq[i], fqp[i]);
        }
    }

    /// Batches of 1 to 16 closes, escapes, mixed withdrawals and requests verify, view and Once.
    function test_validBatchesVerify() public {
        for (uint256 n = 1; n <= N; ++n) {
            (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, n);
            (bool ok,) = _wb(ins, prs);
            assertTrue(ok, "closes");
            (ins, prs) = _w(N - n / 2, n);
            (ok,) = _wb(ins, prs);
            assertTrue(ok, "closes and escapes");
            (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(N - n / 2, n);
            (ok,) = _qb(rins, rprs);
            assertTrue(ok, "requests");
        }
        (Types.WithdrawalPublicInputs[] memory ins16, bytes memory prs16) = _w(16, 16);
        adapter.verifyWithdrawalBatchOnce(ins16, prs16);
        (Types.RequestPublicInputs[] memory rins16, bytes memory rprs16) = _q(8, 16);
        adapter.verifyRequestBatchOnce(rins16, rprs16);
    }

    /// A wrong statement anywhere (one input off, two items' inputs swapped) fails the whole batch,
    /// at position 0 (r_0 = 1), in the middle and last.
    function test_anyWrongStatementFailsTheBatch() public {
        uint256[4] memory sizes = [uint256(2), 3, 8, 16];
        for (uint256 k = 0; k < 4; ++k) {
            uint256 n = sizes[k];
            for (uint256 bad = 0; bad < n; bad += (n > 4 ? 5 : 1)) {
                (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, n);
                ins[bad].withdrawalNullifier += 1;
                (bool ok, bytes memory ret) = _wb(ins, prs);
                assertFalse(ok, "nullifier off by one");
                assertTrue(_isInvalidProof(ret));
                (ins, prs) = _w(0, n);
                ins[bad].finalBalance += 1;
                (ok,) = _wb(ins, prs);
                assertFalse(ok, "balance off by one");
                (ins, prs) = _w(0, n);
                ins[bad].destination = address(uint160(ins[bad].destination) ^ 1);
                (ok,) = _wb(ins, prs);
                assertFalse(ok, "another destination");
                (ins, prs) = _w(0, n);
                uint256 other = (bad + 1) % n;
                (ins[bad], ins[other]) = (ins[other], ins[bad]);
                (ok,) = _wb(ins, prs);
                assertFalse(ok, "inputs swapped, proofs not");
                (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(0, n);
                rins[bad].requestNullifier += 1;
                (ok,) = _qb(rins, rprs);
                assertFalse(ok, "request nullifier off by one");
            }
        }
    }

    /// Reordering whole items keeps a valid batch valid (each r_i changes, every item still holds).
    function test_permutedItemsStillVerify() public {
        Types.WithdrawalPublicInputs[] memory ins = new Types.WithdrawalPublicInputs[](8);
        bytes[] memory ps = new bytes[](8);
        for (uint256 i = 0; i < 8; ++i) {
            ins[i] = w[7 - i];
            ps[i] = wp[7 - i];
        }
        (bool ok,) = _wb(ins, _concat(ps));
        assertTrue(ok);
    }

    /// The attack a fixed or predictable combination admits: two invalid proofs whose errors cancel
    /// in the plain sum (C_1 + G, C_2 - G). The unweighted aggregate (every r_i = 1) holds; the
    /// Fiat-Shamir challenges refuse the batch.
    function test_cancellingInvalidPairIsRefused() public {
        (Types.WithdrawalPublicInputs[] memory ins,) = _w(0, 4);
        bytes[] memory ps = new bytes[](4);
        for (uint256 i = 0; i < 4; ++i) {
            ps[i] = _copy(wp[i]);
        }
        (uint256 x1, uint256 y1) = _ecAdd(_word(ps[1], 6), _word(ps[1], 7), 1, 2);
        (uint256 x2, uint256 y2) = _ecAdd(_word(ps[2], 6), _word(ps[2], 7), 1, Q - 2);
        _setWord(ps[1], 6, x1);
        _setWord(ps[1], 7, y1);
        _setWord(ps[2], 6, x2);
        _setWord(ps[2], 7, y2);
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(ins[1], ps[1]);
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(ins[2], ps[2]);
        assertTrue(_naiveAggregateHolds(ps), "the unweighted sum is fooled");
        (bool ok, bytes memory ret) = _wb(ins, _concat(ps));
        assertFalse(ok, "the RLC batch refuses");
        assertTrue(_isInvalidProof(ret));
    }

    /// A malleated proof (-A, -B, C) of a valid proof is valid, alone and in a batch next to the
    /// original: proofs are malleable and re-randomizable, so nothing may key uniqueness on proof
    /// bytes (the vault keys on nullifiers).
    function test_malleatedProofIsValid() public {
        bytes memory m = _copy(wp[3]);
        _setWord(m, 1, (Q - _word(m, 1)) % Q);
        _setWord(m, 4, (Q - _word(m, 4)) % Q);
        _setWord(m, 5, (Q - _word(m, 5)) % Q);
        adapter.assertValidWithdrawal(w[3], m);
        Types.WithdrawalPublicInputs[] memory ins = new Types.WithdrawalPublicInputs[](2);
        ins[0] = w[3];
        ins[1] = w[3];
        (bool ok,) = _wb(ins, bytes.concat(wp[3], m));
        assertTrue(ok, "one statement with two proofs");
    }

    /// The same valid item twice verifies (independent r_i, r_j); the same invalid item twice does
    /// not (its coefficient is r_i + r_j), wherever the valid one sits.
    function test_duplicates() public {
        Types.WithdrawalPublicInputs[] memory ins = new Types.WithdrawalPublicInputs[](3);
        ins[0] = w[5];
        ins[1] = w[5];
        ins[2] = w[6];
        (bool ok,) = _wb(ins, bytes.concat(wp[5], wp[5], wp[6]));
        assertTrue(ok, "a valid duplicate");
        ins[0].withdrawalNullifier += 1;
        ins[1].withdrawalNullifier += 1;
        (ok,) = _wb(ins, bytes.concat(wp[5], wp[5], wp[6]));
        assertFalse(ok, "an invalid duplicate");
        ins[0] = w[5];
        ins[1] = w[5];
        ins[1].withdrawalNullifier += 1;
        ins[2] = w[5];
        ins[2].withdrawalNullifier += 1;
        (ok,) = _wb(ins, bytes.concat(wp[5], wp[5], wp[5]));
        assertFalse(ok, "an invalid duplicate after a valid first item");
    }

    /// The identity (0, 0) as A, C or B of one item at positions 0, 1 and 2: valid encodings, which
    /// the precompiles accept, whose item equation fails, so the batch does.
    function test_identityPointsAreRefused() public {
        for (uint256 which = 0; which < 3; ++which) {
            for (uint256 item = 0; item < 3; ++item) {
                (Types.WithdrawalPublicInputs[] memory ins,) = _w(0, 3);
                bytes[] memory ps = new bytes[](3);
                for (uint256 i = 0; i < 3; ++i) {
                    ps[i] = _copy(wp[i]);
                }
                uint256 from = which == 0 ? 0 : which == 1 ? 6 : 2;
                uint256 to = which == 2 ? 6 : from + 2;
                for (uint256 k = from; k < to; ++k) {
                    _setWord(ps[item], k, 0);
                }
                (bool ok, bytes memory ret) = _wb(ins, _concat(ps));
                assertFalse(ok, "an identity point");
                assertTrue(_isInvalidProof(ret));
            }
        }
    }

    /// Range and encoding checks, each as the single verification: an input at or above r (the same
    /// scalar as x - r) and a proof coordinate at or above q revert InvalidProof(); so do an
    /// off-curve point, an empty batch, a proofs length other than 256 · n and an array of fewer
    /// statements than proofs; a dirty narrow field reverts empty, as the ABI decoder would.
    function test_rangeAndEncodingChecks() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 4);
        ins[2].withdrawalNullifier += R;
        (bool ok, bytes memory ret) = _wb(ins, prs);
        assertFalse(ok);
        assertTrue(_isInvalidProof(ret), "nullifier + r");
        (ins, prs) = _w(0, 4);
        ins[3].activeRoot += R;
        (ok, ret) = _wb(ins, prs);
        assertTrue(!ok && _isInvalidProof(ret), "root + r");
        (ins,) = _w(0, 4);
        bytes[] memory ps = new bytes[](4);
        for (uint256 i = 0; i < 4; ++i) {
            ps[i] = _copy(wp[i]);
        }
        _setWord(ps[3], 7, _word(ps[3], 7) + Q);
        (ok, ret) = _wb(ins, _concat(ps));
        assertTrue(!ok && _isInvalidProof(ret), "C.y + q");
        for (uint256 i = 0; i < 4; ++i) {
            ps[i] = _copy(wp[i]);
        }
        _setWord(ps[1], 0, _word(ps[1], 0) ^ 1);
        (ok, ret) = _wb(ins, _concat(ps));
        assertTrue(!ok && _isInvalidProof(ret), "off-curve A");
        // a dirty uint32 noteId of item 1, as raw calldata
        (ins, prs) = _w(0, 3);
        bytes memory raw;
        for (uint256 i = 0; i < 3; ++i) {
            raw = bytes.concat(raw, abi.encode(ins[i]));
        }
        raw[0x200 + 8 * 0x20 + 27] = 0x01; // bit 32 of item 1's noteId
        vm.cool(address(adapter));
        (ok, ret) = address(adapter).call(_rawBatchCall(adapter.verifyWithdrawalBatch.selector, 0x200, raw, prs));
        assertFalse(ok);
        assertEq(ret.length, 0, "empty revert, as the ABI decoder");
        // lengths
        (ok, ret) = _wb(new Types.WithdrawalPublicInputs[](0), "");
        assertTrue(!ok && _isInvalidProof(ret), "empty batch");
        (ins, prs) = _w(0, 3);
        (ok, ret) = _wb(ins, bytes.concat(prs, bytes1(0)));
        assertTrue(!ok && _isInvalidProof(ret), "a byte too many");
        (ok, ret) = _wb(ins, _slice(prs, 0, prs.length - 1));
        assertTrue(!ok && _isInvalidProof(ret), "a byte short");
        (Types.WithdrawalPublicInputs[] memory two,) = _w(0, 2);
        (ok, ret) = _wb(two, prs);
        assertTrue(!ok && _isInvalidProof(ret), "fewer statements than proofs");
    }

    /// Calldata whose array claims more statements than it carries is refused by the ABI decoder
    /// before the adapter reads anything (an empty revert): the truncation of the review suites.
    function test_truncatedCalldataIsRefused() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 3);
        bytes memory data = abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs));
        for (uint256 cut = 32; cut <= 0x400; cut += 0x1e0) {
            bytes memory shortData = _slice(data, 0, data.length - prs.length - 64 - cut);
            vm.cool(address(adapter));
            (bool ok, bytes memory ret) = address(adapter).call(shortData);
            assertFalse(ok, "truncated");
            assertEq(ret.length, 0);
        }
    }

    /// Statements of another vault take the generic path, alone or mixed with folded ones; a wrong
    /// one among them, or a foreign proof relabelled as the folded vault's, fails the batch.
    function test_mixedFoldedAndGenericItems() public {
        Types.WithdrawalPublicInputs[] memory ins = new Types.WithdrawalPublicInputs[](6);
        bytes[] memory ps = new bytes[](6);
        for (uint256 i = 0; i < 3; ++i) {
            ins[2 * i] = w[i];
            ps[2 * i] = wp[i];
            ins[2 * i + 1] = fw[i];
            ps[2 * i + 1] = fwp[i];
        }
        (bool ok,) = _wb(ins, _concat(ps));
        assertTrue(ok, "mixed");
        Types.WithdrawalPublicInputs[] memory only = new Types.WithdrawalPublicInputs[](2);
        only[0] = fw[2];
        only[1] = fw[3];
        (ok,) = _wb(only, bytes.concat(fwp[2], fwp[3]));
        assertTrue(ok, "generic only");
        ins[3].finalBalance += 1;
        (ok,) = _wb(ins, _concat(ps));
        assertFalse(ok, "a generic item wrong");
        ins[3] = fw[1];
        ins[3].contractAddress = vaultAddress;
        (ok,) = _wb(ins, _concat(ps));
        assertFalse(ok, "a foreign proof relabelled as the folded vault");
        Types.RequestPublicInputs[] memory rins = new Types.RequestPublicInputs[](3);
        rins[0] = q[0];
        rins[1] = fq[0];
        rins[2] = fq[1];
        (ok,) = _qb(rins, bytes.concat(qp[0], fqp[0], fqp[1]));
        assertTrue(ok, "mixed requests");
    }

    // ------------------------------------------------------------------------------ records

    /// verifyWithdrawalBatchOnce leaves the records verifyWithdrawalOnce leaves: each item's
    /// assertValidWithdrawal is then a lookup, within the same transaction.
    function test_withdrawalBatchOnceRecordsEveryItem() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(10, 6);
        for (uint256 i = 0; i < 6; ++i) {
            uint256 used = caller.batchOnceThenAssert(adapter, ins, prs, ins[i], wp[10 + i]);
            assertLt(used, 5_000, "a lookup");
        }
    }

    /// verifyRequestBatchOnce leaves a record per request that assertValidRequest finds.
    function test_requestBatchOnceRecordsEveryItem() public {
        (Types.RequestPublicInputs[] memory ins, bytes memory prs) = _q(14, 5);
        for (uint256 i = 0; i < 5; ++i) {
            uint256 used = caller.requestBatchOnceThenAssert(adapter, ins, prs, ins[i], qp[14 + i]);
            assertLt(used, 5_000, "a lookup");
        }
    }

    /// The view variants record nothing, a failed batch records nothing, a record names exactly the
    /// verified bytes (a malleated twin of a recorded proof is verified in full), and the two
    /// record namespaces never meet: a request record does not stand for a withdrawal and the
    /// reverse.
    function test_recordsAreExact() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 3);
        (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(0, 3);
        bytes memory assertW = abi.encodeCall(adapter.assertValidWithdrawal, (ins[1], wp[1]));
        bytes memory assertQ = abi.encodeCall(adapter.assertValidRequest, (rins[1], qp[1]));
        // view: a full verification follows
        (bool ok,, uint256 used) =
            caller.thenTry(adapter, abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs)), assertW);
        assertTrue(ok);
        assertGt(used, 150_000, "the view batch recorded nothing");
        (ok,, used) = caller.thenTry(adapter, abi.encodeCall(adapter.verifyRequestBatch, (rins, rprs)), assertQ);
        assertTrue(ok);
        assertGt(used, 150_000, "the view batch recorded nothing");
        // a failed Once batch records nothing (its revert undoes any write)
        (Types.WithdrawalPublicInputs[] memory bad,) = _w(0, 3);
        bad[2].finalBalance += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        caller.batchOnceThenAssert(adapter, bad, prs, ins[1], wp[1]);
        // a malleated twin of a recorded proof: verified in full, and valid
        bytes memory twin = _copy(wp[1]);
        _setWord(twin, 1, (Q - _word(twin, 1)) % Q);
        _setWord(twin, 4, (Q - _word(twin, 4)) % Q);
        _setWord(twin, 5, (Q - _word(twin, 5)) % Q);
        (ok,, used) = caller.thenTry(
            adapter,
            abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs)),
            abi.encodeCall(adapter.assertValidWithdrawal, (ins[1], twin))
        );
        assertTrue(ok);
        assertGt(used, 150_000, "only the recorded bytes are a lookup");
        // (before any request record exists in this transaction)
        (ok,, used) = caller.thenTry(adapter, abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs)), assertQ);
        assertTrue(ok);
        assertGt(used, 150_000, "a withdrawal record is not a request record");
        // a request record never stands for a withdrawal, nor the reverse: the recorded request's
        // own bytes read as a withdrawal statement (its 12 words and 4 zero words) do not verify
        // (raw calldata: a request's words are no valid withdrawal tuple for the ABI decoder)
        bytes memory asWithdrawal = bytes.concat(
            adapter.assertValidWithdrawal.selector,
            abi.encode(rins[1]),
            new bytes(128),
            abi.encode(uint256(0x220), uint256(0x100)),
            qp[1]
        );
        bytes memory ret;
        (ok, ret,) = caller.thenTry(adapter, abi.encodeCall(adapter.verifyRequestBatchOnce, (rins, rprs)), asWithdrawal);
        assertFalse(ok, "a request record is not a withdrawal record");
    }

    /// A record lasts one transaction (EIP-1153).
    /// forge-config: default.isolate = true
    function test_recordsLastOneTransaction() public {
        (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(0, 2);
        adapter.verifyRequestBatchOnce(rins, rprs);
        adapter.assertValidRequest(rins[0], qp[0]);
        assertGt(vm.lastCallGas().gasTotalUsed, 150_000, "verified again in a new transaction");
    }

    /// A static context (EntryPoint v0.7's IAggregator.validateSignatures, declared view) cannot run
    /// the Once variants: TSTORE halts there. The view variants run.
    function test_staticContextCannotRecord() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 2);
        // TSTORE in a static context is an exceptional halt: it consumes what the call was given.
        (bool okOnce,) =
            address(adapter).staticcall{gas: 2_000_000}(abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs)));
        (bool okView,) =
            address(adapter).staticcall{gas: 2_000_000}(abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs)));
        assertFalse(okOnce, "Once under STATICCALL");
        assertTrue(okView, "the view batch under STATICCALL");
        (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(0, 2);
        (okOnce,) =
            address(adapter).staticcall{gas: 2_000_000}(abi.encodeCall(adapter.verifyRequestBatchOnce, (rins, rprs)));
        (okView,) =
            address(adapter).staticcall{gas: 2_000_000}(abi.encodeCall(adapter.verifyRequestBatch, (rins, rprs)));
        assertFalse(okOnce);
        assertTrue(okView);
    }

    // ------------------------------------------------------------------------------ helpers

    function _slice(bytes memory data, uint256 from, uint256 to) internal pure returns (bytes memory out) {
        out = new bytes(to - from);
        for (uint256 i = from; i < to; ++i) {
            out[i - from] = data[i];
        }
    }

    /// Whether the unweighted aggregate (every r_i = 1) of the tampered proofs equals that of the
    /// valid ones, which is 1: the two differ only in their C points, so it holds iff Π e(C'_i,
    /// delta) · Π e(-C_i, delta) == 1, one pairing call with the setup's delta.
    function _naiveAggregateHolds(bytes[] memory ps) internal view returns (bool) {
        string memory manifest = _setupManifest();
        uint256[4] memory delta = [
            vm.parseJsonUint(manifest, ".withdrawal.delta_g2[0][1]"),
            vm.parseJsonUint(manifest, ".withdrawal.delta_g2[0][0]"),
            vm.parseJsonUint(manifest, ".withdrawal.delta_g2[1][1]"),
            vm.parseJsonUint(manifest, ".withdrawal.delta_g2[1][0]")
        ];
        uint256 n = ps.length;
        uint256[] memory input = new uint256[](12 * n);
        for (uint256 i = 0; i < n; ++i) {
            for (uint256 h = 0; h < 2; ++h) {
                uint256 at = 12 * i + 6 * h;
                input[at] = h == 0 ? _word(ps[i], 6) : _word(wp[i], 6);
                input[at + 1] = h == 0 ? _word(ps[i], 7) : (Q - _word(wp[i], 7)) % Q;
                for (uint256 k = 0; k < 4; ++k) {
                    input[at + 2 + k] = delta[k];
                }
            }
        }
        uint256[1] memory out;
        bool ok;
        assembly ("memory-safe") {
            ok := staticcall(gas(), 8, add(input, 0x20), mul(mload(input), 0x20), out, 0x20)
        }
        return ok && out[0] == 1;
    }
}
