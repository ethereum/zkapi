// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {Types} from "../../src/libraries/Types.sol";
import {BatchTestBase} from "./BatchTestBase.sol";

/// @dev Calls whose cost must be measured inside one transaction (a record is transient).
contract RecordedLookupProbe {
    function withdrawal(
        address adapter,
        Types.WithdrawalPublicInputs[] calldata ins,
        bytes calldata proofs,
        Types.WithdrawalPublicInputs calldata one,
        bytes calldata proof
    ) external returns (uint256 used) {
        (bool ok,) = adapter.call(
            abi.encodeWithSignature(
                "verifyWithdrawalBatchOnce((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)[],bytes)",
                ins,
                proofs
            )
        );
        require(ok, "batch");
        uint256 g = gasleft();
        (ok,) = adapter.staticcall(
            abi.encodeWithSignature(
                "assertValidWithdrawal((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64),bytes)",
                one,
                proof
            )
        );
        used = g - gasleft();
        require(ok, "lookup");
    }

    function request(
        address adapter,
        Types.RequestPublicInputs[] calldata ins,
        bytes calldata proofs,
        Types.RequestPublicInputs calldata one,
        bytes calldata proof
    ) external returns (uint256 used) {
        (bool ok,) = adapter.call(
            abi.encodeWithSignature(
                "verifyRequestBatchOnce((uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)[],bytes)",
                ins,
                proofs
            )
        );
        require(ok, "batch");
        uint256 g = gasleft();
        (ok,) = adapter.staticcall(
            abi.encodeWithSignature(
                "assertValidRequest((uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256),bytes)",
                one,
                proof
            )
        );
        used = g - gasleft();
        require(ok, "lookup");
    }
}

/// @dev The batch verifier's gas against the single verifications, pinned in
///      snapshots/batch-verifier-gas.json (FORGE_SNAPSHOT_CHECK compares it in CI; regenerate it with
///      a full `forge test`), the EIP-170 size gate of the generated adapter, the closed-form bound
///      ZkApiExitBatcher.gasBound relies on, and the ERC-7562 opcode audit of the batch frames.
///      Every call goes to a cold adapter; the frame is the callee's execution gas.
contract BatchGasTest is BatchTestBase {
    string constant GROUP = "batch-verifier-gas";

    function setUp() public {
        _loadBatchFixtures();
        adapter = _deployAdapter();
    }

    function _frame(bytes memory data) internal returns (uint256 frame) {
        bool ok;
        (ok, frame,) = _call(address(adapter), data);
        assertTrue(ok, "the call verified");
    }

    function _name(string memory prefix, uint256 n) internal pure returns (string memory) {
        return string.concat(prefix, n < 10 ? "_n0" : "_n", vm.toString(n));
    }

    /// The generated adapter, batch section included, stays under EIP-170.
    function test_sizeGate() public view {
        uint256 size = address(adapter).code.length;
        console.log("Groth16ProofAdapter runtime bytes", size);
        assertLt(size, 24_576, "EIP-170");
    }

    /// Batch frames for n = 1, 2, 4, 8 and 16 of each kind (view and Once), against the sum of the
    /// single verifications of the same statements, and the cost of a recorded lookup.
    function test_gasTables() public {
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        // The single verifications first: once a Once batch has recorded a statement, its single
        // verification in this transaction is a lookup.
        uint256[5] memory wSingles;
        uint256[5] memory qSingles;
        for (uint256 k = 0; k < 5; ++k) {
            uint256 from = N - ns[k] / 2;
            for (uint256 i = 0; i < ns[k]; ++i) {
                wSingles[k] += _frame(abi.encodeCall(adapter.assertValidWithdrawal, (w[from + i], wp[from + i])));
                qSingles[k] += _frame(abi.encodeCall(adapter.assertValidRequest, (q[from + i], qp[from + i])));
            }
        }
        vm.snapshotValue(
            GROUP, "assertValidWithdrawal", _frame(abi.encodeCall(adapter.assertValidWithdrawal, (w[3], wp[3])))
        );
        vm.snapshotValue(GROUP, "assertValidRequest", _frame(abi.encodeCall(adapter.assertValidRequest, (q[3], qp[3]))));
        console.log("kind, n, batch frame, per item, Once frame, sum of single frames");
        for (uint256 k = 0; k < 5; ++k) {
            uint256 n = ns[k];
            (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(N - n / 2, n);
            uint256 view_ = _frame(abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs)));
            uint256 once = _frame(abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs)));
            console.log(
                string.concat(
                    "withdrawal, ",
                    vm.toString(n),
                    ", ",
                    vm.toString(view_),
                    ", ",
                    vm.toString(view_ / n),
                    ", ",
                    vm.toString(once),
                    ", ",
                    vm.toString(wSingles[k])
                )
            );
            vm.snapshotValue(GROUP, _name("verifyWithdrawalBatch", n), view_);
            vm.snapshotValue(GROUP, _name("verifyWithdrawalBatchOnce", n), once);
            vm.snapshotValue(GROUP, _name("assertValidWithdrawalSum", n), wSingles[k]);
            (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(N - n / 2, n);
            view_ = _frame(abi.encodeCall(adapter.verifyRequestBatch, (rins, rprs)));
            once = _frame(abi.encodeCall(adapter.verifyRequestBatchOnce, (rins, rprs)));
            console.log(
                string.concat(
                    "request, ",
                    vm.toString(n),
                    ", ",
                    vm.toString(view_),
                    ", ",
                    vm.toString(view_ / n),
                    ", ",
                    vm.toString(once),
                    ", ",
                    vm.toString(qSingles[k])
                )
            );
            vm.snapshotValue(GROUP, _name("verifyRequestBatch", n), view_);
            vm.snapshotValue(GROUP, _name("verifyRequestBatchOnce", n), once);
            vm.snapshotValue(GROUP, _name("assertValidRequestSum", n), qSingles[k]);
        }
        // single verifications (a request's now checks for a record first)
        vm.snapshotValue(
            GROUP, "assertValidWithdrawal", _frame(abi.encodeCall(adapter.assertValidWithdrawal, (w[3], wp[3])))
        );
        vm.snapshotValue(GROUP, "assertValidRequest", _frame(abi.encodeCall(adapter.assertValidRequest, (q[3], qp[3]))));
        // recorded lookups, inside the transaction of the batch that recorded them
        RecordedLookupProbe probe = new RecordedLookupProbe();
        (Types.WithdrawalPublicInputs[] memory wins, bytes memory wprs) = _w(0, 2);
        uint256 hit = probe.withdrawal(address(adapter), wins, wprs, wins[1], wp[1]);
        (Types.RequestPublicInputs[] memory qins, bytes memory qprs) = _q(0, 2);
        uint256 qhit = probe.request(address(adapter), qins, qprs, qins[1], qp[1]);
        console.log("recorded lookups (warm adapter): withdrawal, request", hit, qhit);
        assertLt(hit, 5_000);
        assertLt(qhit, 5_000);
        vm.snapshotValue(GROUP, "assertValidWithdrawalRecorded", hit);
        vm.snapshotValue(GROUP, "assertValidRequestRecorded", qhit);
    }

    /// ZkApiExitBatcher.gasBound counts VERIFY_BASE_GAS + n · VERIFY_ITEM_GAS for the verification of
    /// n proofs by verify*BatchOnce called from the batcher. It holds, with at least 10% to spare, on
    /// the worst case at every size up to MAX_ITEMS: every item on the generic path (statements of
    /// another vault: every input enters the multi-scalar multiplication and IC0 joins the folded
    /// IC0'), a folded item among them, and every input sum a full multiplication.
    function test_verificationBoundHolds() public {
        uint256 base = BATCHER_VERIFY_BASE_GAS;
        uint256 per = BATCHER_VERIFY_ITEM_GAS;
        uint256[8] memory ns = [uint256(1), 2, 3, 4, 8, 16, 32, 64];
        console.log("n, worst withdrawal Once frame, worst request Once frame, bound");
        for (uint256 k = 0; k < ns.length; ++k) {
            uint256 n = ns[k];
            Types.WithdrawalPublicInputs[] memory ins = new Types.WithdrawalPublicInputs[](n);
            bytes memory prs;
            Types.RequestPublicInputs[] memory rins = new Types.RequestPublicInputs[](n);
            bytes memory rprs;
            for (uint256 i = 0; i < n; ++i) {
                bool folded = i == 1;
                ins[i] = folded ? w[7] : fw[i % FOREIGN];
                prs = bytes.concat(prs, folded ? wp[7] : fwp[i % FOREIGN]);
                rins[i] = folded ? q[7] : fq[i % FOREIGN];
                rprs = bytes.concat(rprs, folded ? qp[7] : fqp[i % FOREIGN]);
            }
            uint256 wf = _frame(abi.encodeCall(adapter.verifyWithdrawalBatchOnce, (ins, prs)));
            uint256 rf = _frame(abi.encodeCall(adapter.verifyRequestBatchOnce, (rins, rprs)));
            uint256 bound = base + per * n;
            console.log(
                string.concat(vm.toString(n), ", ", vm.toString(wf), ", ", vm.toString(rf), ", ", vm.toString(bound))
            );
            // the batcher's own call costs about 3,000 + 900 per item over the frame (its ABI
            // re-encoding of the arrays and the call)
            assertLe(((wf + 3_000 + 900 * n) * 11) / 10, bound, "withdrawal bound");
            assertLe(((rf + 3_000 + 900 * n) * 11) / 10, bound, "request bound");
        }
    }

    /// The batch frames under the ERC-7562 rules a validation frame must meet, should a paymaster
    /// ever verify a batch in validation: no OP-011 opcode, GAS only right before a call (OP-012),
    /// calls only to the core BN254 precompiles 0x06-0x08 (OP-062), no SLOAD, SSTORE, TLOAD or
    /// BALANCE, one pairing per batch, and TSTORE only in the Once variants, once per item, at
    /// keccak256(destination ‖ x) for a withdrawal (STO-021 when every destination is the sender).
    /// Needs the tracer (-vvv).
    function test_opcodeAudit_batchVerification() public {
        bool tracer;
        try vm.startDebugTraceRecording() {
            tracer = true;
        } catch {}
        if (!tracer) {
            console.log("opcode audit needs the tracer: run forge test -vvv");
            vm.skip(true);
        }
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, 3);
        adapter.verifyWithdrawalBatchOnce(ins, prs);
        (Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _q(0, 3);
        adapter.verifyRequestBatch(rins, rprs);
        Vm.DebugStep[] memory steps = vm.stopAndReturnDebugTraceRecording();
        uint256 audited;
        uint256 tstores;
        uint256 pairings;
        bytes32[] memory associated = new bytes32[](8);
        uint256 associatedCount;
        for (uint256 i = 0; i < steps.length; ++i) {
            Vm.DebugStep memory st = steps[i];
            if (st.contractAddr != address(adapter)) continue;
            ++audited;
            uint8 o = st.opcode;
            assertFalse(
                o == 0x42 || o == 0x43 || o == 0x48 || o == 0x3a || o == 0x32 || o == 0x41 || o == 0x40 || o == 0x44
                    || o == 0x45 || o == 0x49 || o == 0x4a || o == 0xff || o == 0xf0 || o == 0xf2 || o == 0xfe
                    || o == 0xf5,
                "OP-011"
            );
            assertFalse(o == 0x54 || o == 0x55 || o == 0x5c || o == 0x31 || o == 0x47, "no state access");
            assertFalse(o == 0xf1 || o == 0xf4, "no CALL or DELEGATECALL");
            if (o == 0x5a) assertEq(steps[i + 1].opcode, 0xfa, "OP-012: GAS right before STATICCALL");
            if (o == 0xfa) {
                uint256 target = st.stack[1];
                assertTrue(target >= 6 && target <= 8, "OP-062: the core BN254 precompiles only");
                if (target == 8) ++pairings;
            }
            if (o == 0x20 && st.memoryInput.length == 64) {
                for (uint256 k = 0; k < 3; ++k) {
                    if (bytes32(st.memoryInput) == bytes32(uint256(uint160(ins[k].destination)))) {
                        associated[associatedCount++] = keccak256(st.memoryInput);
                    }
                }
            }
            if (o == 0x5d) {
                bool senderSlot;
                for (uint256 k = 0; k < associatedCount; ++k) {
                    if (bytes32(st.stack[0]) == associated[k]) senderSlot = true;
                }
                assertTrue(senderSlot, "STO-021: a record is keccak256(destination || x)");
                ++tstores;
            }
        }
        assertGt(audited, 1000, "frames traced");
        assertEq(pairings, 2, "one pairing per batch");
        assertEq(tstores, 3, "one record per item, Once only");
    }

    /// The precompile calls and EVM steps of a single verification and of batches of 1, 2 and 3: the
    /// batch's overhead over the precompiles it calls (needs the tracer).
    function test_traceProbe() public {
        try vm.startDebugTraceRecording() {}
        catch {
            vm.skip(true);
        }
        vm.stopAndReturnDebugTraceRecording();
        _profile("single", abi.encodeCall(adapter.assertValidWithdrawal, (w[0], wp[0])));
        for (uint256 n = 1; n <= 3; ++n) {
            (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _w(0, n);
            _profile(
                string.concat("batch n=", vm.toString(n)), abi.encodeCall(adapter.verifyWithdrawalBatch, (ins, prs))
            );
        }
    }

    function _profile(string memory label, bytes memory data) internal {
        vm.startDebugTraceRecording();
        (bool ok,) = address(adapter).call(data);
        Vm.DebugStep[] memory steps = vm.stopAndReturnDebugTraceRecording();
        assertTrue(ok);
        uint256 total = vm.lastCallGas().gasTotalUsed;
        uint256[9] memory calls;
        uint256 evmSteps;
        for (uint256 i = 0; i < steps.length; ++i) {
            if (steps[i].contractAddr != address(adapter)) continue;
            ++evmSteps;
            if (steps[i].opcode == 0xfa) ++calls[steps[i].stack[1]];
        }
        uint256 precompiles = 150 * calls[6] + 6_000 * calls[7];
        console.log(label);
        console.log("  frame gas, ecAdd, ecMul calls", total, calls[6], calls[7]);
        console.log(
            "  pairings, EVM steps, gas outside ecAdd/ecMul and pairings", calls[8], evmSteps, total - precompiles
        );
    }
}
