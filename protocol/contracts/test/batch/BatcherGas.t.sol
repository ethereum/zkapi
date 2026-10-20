// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/Test.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {ZkApiExitBatcher} from "../../src/periphery/ZkApiExitBatcher.sol";
import {BatcherTestBase} from "./BatcherTestBase.sol";

/// @dev Measures one item's vault call as the batcher makes it: after the batch verification that
///      recorded it, in the same transaction, with the gas the call itself used.
contract ItemGasProbe {
    function close(ZkApiVault vault, Types.WithdrawalPublicInputs[] calldata ins, bytes calldata proofs)
        external
        returns (uint256 used)
    {
        (bool ok,) = address(vault.proofAdapter())
            .call(
                abi.encodeWithSignature(
                    "verifyWithdrawalBatchOnce((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)[],bytes)",
                    ins,
                    proofs
                )
            );
        require(ok, "verify");
        uint256 g = gasleft();
        vault.mutualClose(ins[0], proofs[0:256]);
        used = g - gasleft();
    }

    function escape(ZkApiVault vault, Types.WithdrawalPublicInputs[] calldata ins, bytes calldata proofs)
        external
        returns (uint256 used)
    {
        (bool ok,) = address(vault.proofAdapter())
            .call(
                abi.encodeWithSignature(
                    "verifyWithdrawalBatchOnce((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)[],bytes)",
                    ins,
                    proofs
                )
            );
        require(ok, "verify");
        uint256 g = gasleft();
        vault.initiateEscapeWithdrawal(ins[0], proofs[0:256]);
        used = g - gasleft();
    }

    function challenge(
        ZkApiVault vault,
        uint32 noteId,
        uint128 amount,
        Types.RequestPublicInputs[] calldata ins,
        bytes calldata proofs
    ) external returns (uint256 used) {
        (bool ok,) = address(vault.proofAdapter())
            .call(
                abi.encodeWithSignature(
                    "verifyRequestBatchOnce((uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256)[],bytes)",
                    ins,
                    proofs
                )
            );
        require(ok, "verify");
        uint256 g = gasleft();
        if (amount == 0) vault.challengeEscapeWithdrawal(noteId, ins[0], proofs[0:256]);
        else vault.raiseEscapeConcession(noteId, ins[0], proofs[0:256], amount);
        used = g - gasleft();
    }

    function finalize(ZkApiVault vault, uint32 noteId) external returns (uint256 used) {
        uint256 g = gasleft();
        vault.finalizeEscapeWithdrawal(noteId);
        used = g - gasleft();
    }
}

/// @dev Realistic transaction gas of every exit, single (the vault's own entry point) and batched
///      (ZkApiExitBatcher, n = 1, 2, 4, 8, 16), with the generated adapter on this base: every account
///      cold, 21,000 + calldata + execution, refunds capped at a fifth, EIP-7623's floor (the method
///      of test/GasBaseline.t.sol), pinned in snapshots/exit-batcher-gas.json (checked in CI with
///      FORGE_SNAPSHOT_CHECK; regenerate with a full `forge test`). Also the gas one item's vault
///      call needs in a batch, which the per-kind caps must cover.
contract BatcherGasTest is BatcherTestBase {
    string constant GROUP = "exit-batcher-gas";

    function setUp() public {
        _deployVaultAndBatcher(true);
    }

    function _name(string memory kind, uint256 n) internal pure returns (string memory) {
        return string.concat(kind, n < 10 ? "_n0" : "_n", vm.toString(n));
    }

    function _record(string memory kind, uint256 single, uint256[5] memory batched) internal {
        vm.snapshotValue(GROUP, string.concat(kind, "_single"), single);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        string memory line = string.concat(kind, ": single ", vm.toString(single));
        for (uint256 k = 0; k < 5; ++k) {
            vm.snapshotValue(GROUP, _name(kind, ns[k]), batched[k]);
            line = string.concat(
                line,
                " | n=",
                vm.toString(ns[k]),
                " ",
                vm.toString(batched[k]),
                " (",
                vm.toString(batched[k] / ns[k]),
                "/item)"
            );
        }
        console.log(line);
    }

    function test_closeGas() public {
        uint256 snapshot = vm.snapshotState();
        uint256 single = _txGas(address(vault), abi.encodeCall(vault.mutualClose, (w[0], wp[0])));
        vm.revertToState(snapshot);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        uint256[5] memory batched;
        for (uint256 k = 0; k < 5; ++k) {
            (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, ns[k]);
            batched[k] = _txGas(address(batcher), abi.encodeCall(batcher.mutualCloseBatch, (ins, prs)));
            assertEq(uint256(_status(ns[k] - 1)), uint256(Types.NoteStatus.Closed));
            vm.revertToState(snapshot);
        }
        _record("close", single, batched);
    }

    function test_escapeGas() public {
        uint256 snapshot = vm.snapshotState();
        uint256 single = _txGas(address(vault), abi.encodeCall(vault.initiateEscapeWithdrawal, (w[N], wp[N])));
        vm.revertToState(snapshot);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        uint256[5] memory batched;
        for (uint256 k = 0; k < 5; ++k) {
            (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _escapes(0, ns[k]);
            batched[k] = _txGas(address(batcher), abi.encodeCall(batcher.initiateEscapeBatch, (ins, prs)));
            assertEq(uint256(_status(ns[k] - 1)), uint256(Types.NoteStatus.PendingWithdrawal));
            vm.revertToState(snapshot);
        }
        _record("escape", single, batched);
    }

    /// The gas a close's and an escape's vault call takes in a batch (after the recorded
    /// verification, the vault, treasury and destination cold), against the caps: a close pays the
    /// treasury with up to 100,000 and the destination with what is left, so its cap leaves 100,000
    /// for the treasury and 50,000 for a destination with code; an escape pays nothing but writes
    /// four fresh slots, and its cap leaves 100,000.
    function test_itemGasFitsTheCaps() public {
        ItemGasProbe probe = new ItemGasProbe();
        uint256 snapshot = vm.snapshotState();
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 2);
        _coolAll();
        uint256 close = probe.close(vault, ins, prs);
        vm.revertToState(snapshot);
        (ins, prs) = _escapes(0, 2);
        _coolAll();
        uint256 escape = probe.escape(vault, ins, prs);
        console.log("one item's vault call in a batch: close, escape", close, escape);
        vm.snapshotValue(GROUP, "item_close", close);
        vm.snapshotValue(GROUP, "item_escape", escape);
        assertLe(close + 100_000 + 50_000, CLOSE_GAS, "close cap");
        assertLe(escape + 100_000, ESCAPE_GAS, "escape cap");
    }
}

/// @dev Defeats, raises and finalizations of escapes initiated in setUp, so that the measured
///      transactions find them in their starting state (slots written earlier in the same
///      transaction would be cheaper to change and refund more to clear).
contract BatcherPendingGasTest is BatcherTestBase {
    string constant GROUP = "exit-batcher-gas";

    function setUp() public {
        _deployVaultAndBatcher(true);
        _initiateAll(N);
    }

    function _name(string memory kind, uint256 n) internal pure returns (string memory) {
        return string.concat(kind, n < 10 ? "_n0" : "_n", vm.toString(n));
    }

    function _record(string memory kind, uint256 single, uint256[5] memory batched) internal {
        vm.snapshotValue(GROUP, string.concat(kind, "_single"), single);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        string memory line = string.concat(kind, ": single ", vm.toString(single));
        for (uint256 k = 0; k < 5; ++k) {
            vm.snapshotValue(GROUP, _name(kind, ns[k]), batched[k]);
            line = string.concat(
                line,
                " | n=",
                vm.toString(ns[k]),
                " ",
                vm.toString(batched[k]),
                " (",
                vm.toString(batched[k] / ns[k]),
                "/item)"
            );
        }
        console.log(line);
    }

    function _challengeGas(bool raise) internal {
        uint256 snapshot = vm.snapshotState();
        (uint32[] memory ids1, uint128[] memory a1, Types.RequestPublicInputs[] memory r1, bytes memory p1) =
            _challenges(0, 1, raise);
        uint256 single = _txGas(
            address(vault),
            raise
                ? abi.encodeCall(vault.raiseEscapeConcession, (ids1[0], r1[0], p1, a1[0]))
                : abi.encodeCall(vault.challengeEscapeWithdrawal, (ids1[0], r1[0], p1))
        );
        vm.revertToState(snapshot);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        uint256[5] memory batched;
        for (uint256 k = 0; k < 5; ++k) {
            (uint32[] memory ids, uint128[] memory amounts, Types.RequestPublicInputs[] memory ins, bytes memory prs) =
                _challenges(0, ns[k], raise);
            batched[k] = _txGas(address(batcher), abi.encodeCall(batcher.challengeBatch, (ids, amounts, ins, prs)));
            vm.revertToState(snapshot);
        }
        _record(raise ? "raise" : "defeat", single, batched);
    }

    function test_defeatGas() public {
        _challengeGas(false);
    }

    function test_raiseGas() public {
        _challengeGas(true);
    }

    function test_finalizeGas() public {
        vm.warp(block.timestamp + 1 days);
        uint256 snapshot = vm.snapshotState();
        uint256 single = _txGas(address(vault), abi.encodeCall(vault.finalizeEscapeWithdrawal, (0)));
        vm.revertToState(snapshot);
        uint256[5] memory ns = [uint256(1), 2, 4, 8, 16];
        uint256[5] memory batched;
        for (uint256 k = 0; k < 5; ++k) {
            uint32[] memory ids = new uint32[](ns[k]);
            for (uint256 i = 0; i < ns[k]; ++i) {
                ids[i] = uint32(i);
            }
            batched[k] = _txGas(address(batcher), abi.encodeCall(batcher.finalizeBatch, (ids)));
            vm.revertToState(snapshot);
        }
        _record("finalize", single, batched);
    }

    /// The gas one item's vault call takes in a batch (after its recorded verification, the vault,
    /// treasury and destination cold), against its kind's cap: each cap leaves room for what the
    /// call may hand on (a finalization pushes up to 100,000 to the destination and as much to the
    /// treasury) and at least 100,000 more.
    function test_itemGasFitsTheCaps() public {
        ItemGasProbe probe = new ItemGasProbe();
        uint256 snapshot = vm.snapshotState();
        (,, Types.RequestPublicInputs[] memory rins, bytes memory rprs) = _challenges(0, 2, false);
        _coolAll();
        uint256 defeat = probe.challenge(vault, 0, 0, rins, rprs);
        vm.revertToState(snapshot);
        (,, rins, rprs) = _challenges(0, 2, true);
        _coolAll();
        uint256 raise = probe.challenge(vault, 0, RAISE, rins, rprs);
        vm.revertToState(snapshot);
        vm.warp(block.timestamp + 1 days);
        _coolAll();
        uint256 finalize = probe.finalize(vault, 0);
        console.log("one item's vault call in a batch: defeat, raise, finalize", defeat, raise, finalize);
        vm.snapshotValue(GROUP, "item_defeat", defeat);
        vm.snapshotValue(GROUP, "item_raise", raise);
        vm.snapshotValue(GROUP, "item_finalize", finalize);
        assertLe(defeat + 100_000, DEFEAT_GAS, "defeat cap");
        assertLe(raise + 100_000, RAISE_GAS, "raise cap");
        assertLe(finalize + 200_000 + 50_000, FINALIZE_GAS, "finalize cap");
    }
}

/// @dev The same 16 closes as separate transactions (isolate mode: every top-level call is its own
///      transaction, with its own warm set, refund and transient storage): the batched close stays
///      within the snapshot's per-item figure, and the singles' total within theirs.
contract BatcherIsolatedGasTest is BatcherTestBase {
    function setUp() public {
        _deployVaultAndBatcher(true);
    }

    /// forge-config: default.isolate = true
    function test_isolatedSixteenClosesBatchedAndSingle() public {
        uint256 snapshot = vm.snapshotState();
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        vm.prank(RELAYER, RELAYER);
        uint256 applied = batcher.mutualCloseBatch(ins, prs);
        assertEq(applied, (1 << N) - 1);
        uint256 batched = vm.lastCallGas().gasTotalUsed;
        vm.revertToState(snapshot);
        uint256 singles;
        for (uint256 i = 0; i < N; ++i) {
            vm.prank(RELAYER, RELAYER);
            vault.mutualClose(w[i], wp[i]);
            singles += vm.lastCallGas().gasTotalUsed;
        }
        console.log("isolated transactions: 16 closes batched, 16 single closes", batched, singles);
        assertLt(batched / N, 140_000, "about 129k per item including the verification");
        assertLt(batched * 2, singles, "batching more than halves the cost");
    }
}
