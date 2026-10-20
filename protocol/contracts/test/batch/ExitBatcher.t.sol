// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {ZkApiExitBatcher} from "../../src/periphery/ZkApiExitBatcher.sol";
import {AcceptAllProofs} from "../mocks/MockProofAdapters.sol";
import {PoseidonRuntime} from "../helpers/PoseidonRuntime.sol";
import {BatcherTestBase} from "./BatcherTestBase.sol";

/// @dev A destination that, when paid, lands another batch through the batcher: the vault's
///      reentrancy guard refuses the inner vault calls, so the inner items are skipped and the
///      outer close still pays.
contract ReentrantDestination {
    ZkApiExitBatcher public batcher;
    bytes public innerCall;
    uint256 public innerApplied = type(uint256).max;

    function arm(ZkApiExitBatcher batcher_, bytes calldata innerCall_) external {
        batcher = batcher_;
        innerCall = innerCall_;
    }

    receive() external payable {
        (bool ok, bytes memory ret) = address(batcher).call(innerCall);
        if (ok) innerApplied = abi.decode(ret, (uint256));
    }
}

/// @dev ZkApiExitBatcher with the real vault, adapter and proofs: all or nothing on the proofs,
///      item by item on the state (a front-run item is verified, then skipped), a destination that
///      burns or refuses its payout costs at most its own cap, the batch is never starved into a
///      skip (BatchOutOfGas), and every kind lands, alone and in batches.
contract ExitBatcherTest is BatcherTestBase {
    function setUp() public {
        _deployVaultAndBatcher(true);
    }

    function _all(uint256 n) internal pure returns (uint256) {
        return n == 256 ? type(uint256).max : (1 << n) - 1;
    }

    // ---------------------------------------------------------------------------- construction

    function test_constructorBindsTheVaultAndItsAdapter() public view {
        assertEq(address(batcher.vault()), address(vault));
        assertEq(address(batcher.adapter()), address(adapter));
        assertEq(batcher.itemGas(batcher.KIND_CLOSE()), CLOSE_GAS);
        assertEq(batcher.itemGas(batcher.KIND_ESCAPE()), ESCAPE_GAS);
        assertEq(batcher.itemGas(batcher.KIND_DEFEAT()), DEFEAT_GAS);
        assertEq(batcher.itemGas(batcher.KIND_RAISE()), RAISE_GAS);
        assertEq(batcher.itemGas(batcher.KIND_FINALIZE()), FINALIZE_GAS);
        assertEq(batcher.MAX_ITEMS(), 64);
        // the verification bound BatchGasTest measures
        assertEq(batcher.VERIFY_BASE_GAS(), BATCHER_VERIFY_BASE_GAS);
        assertEq(batcher.VERIFY_ITEM_GAS(), BATCHER_VERIFY_ITEM_GAS);
    }

    function test_constructorRefusesAnAdapterWithoutBatchVerificationAndBadCaps() public {
        AcceptAllProofs mock = new AcceptAllProofs();
        ZkApiVault other = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(mock),
            w[0].stateSigningKeyX,
            w[0].stateSigningKeyY,
            w[0].clearanceSigningKeyX,
            w[0].clearanceSigningKeyY,
            address(this),
            7 days,
            PoseidonRuntime.etch()
        );
        vm.expectRevert(ZkApiExitBatcher.NotABatchAdapter.selector);
        new ZkApiExitBatcher(other, _caps());
        uint256[5] memory caps = _caps();
        caps[3] = 49_999;
        vm.expectRevert(abi.encodeWithSelector(ZkApiExitBatcher.ItemGasOutOfRange.selector, uint8(3), 49_999));
        new ZkApiExitBatcher(vault, caps);
        caps = _caps();
        caps[0] = 2_000_001;
        vm.expectRevert(abi.encodeWithSelector(ZkApiExitBatcher.ItemGasOutOfRange.selector, uint8(0), 2_000_001));
        new ZkApiExitBatcher(vault, caps);
        vm.expectRevert(abi.encodeWithSelector(ZkApiExitBatcher.UnknownKind.selector, uint8(5)));
        batcher.itemGas(5);
    }

    /// The batcher takes no ETH: nothing is payable and it has no receive.
    function test_holdsNoEth() public {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(batcher).call{value: 1}("");
        assertFalse(ok, "no receive");
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 1);
        (ok,) = address(batcher).call{value: 1}(abi.encodeCall(batcher.mutualCloseBatch, (ins, prs)));
        assertFalse(ok, "not payable");
        assertEq(address(batcher).balance, 0);
    }

    function test_shapeChecks() public {
        Types.WithdrawalPublicInputs[] memory none = new Types.WithdrawalPublicInputs[](0);
        vm.expectRevert(ZkApiExitBatcher.EmptyBatch.selector);
        batcher.mutualCloseBatch(none, "");
        Types.WithdrawalPublicInputs[] memory many = new Types.WithdrawalPublicInputs[](65);
        vm.expectRevert(abi.encodeWithSelector(ZkApiExitBatcher.BatchTooLarge.selector, 65, 64));
        batcher.initiateEscapeBatch(many, "");
        (uint32[] memory ids, uint128[] memory amounts, Types.RequestPublicInputs[] memory ins, bytes memory prs) =
            _challenges(0, 3, false);
        uint32[] memory two = new uint32[](2);
        vm.expectRevert(ZkApiExitBatcher.LengthMismatch.selector);
        batcher.challengeBatch(two, amounts, ins, prs);
        uint128[] memory four = new uint128[](4);
        vm.expectRevert(ZkApiExitBatcher.LengthMismatch.selector);
        batcher.challengeBatch(ids, four, ins, prs);
        uint32[] memory noNotes = new uint32[](0);
        vm.expectRevert(ZkApiExitBatcher.EmptyBatch.selector);
        batcher.finalizeBatch(noNotes);
        // the proofs' length is the adapter's check: InvalidProof()
        (Types.WithdrawalPublicInputs[] memory cins, bytes memory cprs) = _closes(0, 2);
        vm.expectRevert(Errors.InvalidProof.selector);
        batcher.mutualCloseBatch(cins, bytes.concat(cprs, bytes1(0)));
    }

    // ---------------------------------------------------------------------------- closes

    /// Sixteen closes: every destination gets its finalBalance, the treasury the rest, every note
    /// is closed and the batcher keeps nothing.
    function test_closeBatchPaysEveryItem() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        uint256 treasuryBefore = TREASURY.balance;
        vm.recordLogs();
        vm.prank(RELAYER, RELAYER);
        uint256 applied = batcher.mutualCloseBatch(ins, prs);
        assertEq(applied, _all(N));
        uint256 closes;
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == keccak256("MutualClose(uint32,uint256,uint128,address)")) ++closes;
            assertTrue(logs[i].topics[0] != ZkApiExitBatcher.ItemSkipped.selector, "nothing skipped");
        }
        assertEq(closes, N);
        for (uint256 i = 0; i < N; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Closed));
            assertEq(_destination(i).balance, 1 + uint256(ins[i].finalBalance) * 1 gwei);
        }
        assertEq(TREASURY.balance - treasuryBefore, uint256(N) * (DEPOSIT - ins[0].finalBalance) * 1 gwei);
        assertEq(address(batcher).balance, 0);
    }

    /// Half the notes were closed by their owners first: the batch still verifies every proof (all
    /// or nothing) and skips those items with the vault's reason; the others land.
    function test_frontRunItemsAreSkipped() public {
        for (uint256 i = 1; i < N; i += 2) {
            vault.mutualClose(w[i], wp[i]);
        }
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        vm.recordLogs();
        uint256 applied = batcher.mutualCloseBatch(ins, prs);
        uint256 even;
        for (uint256 i = 0; i < N; i += 2) {
            even |= 1 << i;
        }
        assertEq(applied, even);
        Vm.Log[] memory logs = vm.getRecordedLogs();
        uint256 skipped;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] != ZkApiExitBatcher.ItemSkipped.selector) continue;
            uint256 index = uint256(logs[i].topics[1]);
            assertEq(index % 2, 1, "only the front-run items");
            assertEq(uint256(logs[i].topics[2]), batcher.KIND_CLOSE());
            assertEq(uint256(logs[i].topics[3]), index, "the note");
            bytes memory reason = abi.decode(logs[i].data, (bytes));
            assertEq(bytes4(reason), Errors.NoteNotActive.selector);
            ++skipped;
        }
        assertEq(skipped, N / 2);
    }

    /// One invalid proof fails the whole batch: nothing lands.
    function test_oneInvalidProofRevertsTheBatch() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 8);
        ins[5].finalBalance += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        batcher.mutualCloseBatch(ins, prs);
        for (uint256 i = 0; i < 8; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Active));
        }
        // a front-run item's proof is checked too: a skipped item cannot carry a bad proof
        vault.mutualClose(w[2], wp[2]);
        (ins, prs) = _closes(0, 4);
        bytes memory bad = bytes.concat(prs);
        bad[2 * 256 + 255] ^= 0x01;
        vm.expectRevert();
        batcher.mutualCloseBatch(ins, bad);
    }

    /// A destination that burns all the gas it is paid with costs at most the close's cap: its item
    /// is skipped (no reason: it ran out of gas) and the other fifteen land.
    function test_gasBurningDestinationCostsItsCapOnly() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        uint256 snapshot = vm.snapshotState();
        uint256 honest = _txGas(address(batcher), abi.encodeCall(batcher.mutualCloseBatch, (ins, prs)));
        vm.revertToState(snapshot);
        vm.etch(_destination(0), hex"5b5f56"); // JUMPDEST PUSH0 JUMP: burns every gas it gets
        vm.recordLogs();
        uint256 burned = _txGas(address(batcher), abi.encodeCall(batcher.mutualCloseBatch, (ins, prs)));
        Vm.Log[] memory logs = vm.getRecordedLogs();
        bool sawSkip;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].topics[0] == ZkApiExitBatcher.ItemSkipped.selector) {
                assertEq(uint256(logs[i].topics[1]), 0);
                assertEq(abi.decode(logs[i].data, (bytes)).length, 4, "the vault's NativeTransferFailed");
                sawSkip = true;
            }
        }
        assertTrue(sawSkip);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active), "the burner's note stays active");
        for (uint256 i = 1; i < N; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Closed));
        }
        emit log_named_uint("16 closes, honest destinations (tx gas)", honest);
        emit log_named_uint("16 closes, item 0 burns its payout's gas (tx gas)", burned);
        assertLe(burned, honest + CLOSE_GAS, "the burn costs at most the item's cap");
    }

    /// A destination that refuses its payout: the vault reverts its close (the submitter chose the
    /// destination), the item is skipped with NativeTransferFailed and the rest land.
    function test_refusingDestinationIsSkipped() public {
        vm.etch(_destination(3), hex"5f5ffd"); // PUSH0 PUSH0 REVERT
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 6);
        vm.expectEmit(true, true, true, true, address(batcher));
        emit ZkApiExitBatcher.ItemSkipped(3, 0, 3, abi.encodeWithSelector(Errors.NativeTransferFailed.selector));
        uint256 applied = batcher.mutualCloseBatch(ins, prs);
        assertEq(applied, _all(6) & ~uint256(1 << 3));
    }

    /// The submitter cannot starve the tail into skips: at every gas limit the batch either reverts
    /// as a whole (BatchOutOfGas after the verification's up-front reserve) or lands every item.
    function test_starvedBatchRevertsNeverSkips() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        bytes memory data = abi.encodeCall(batcher.mutualCloseBatch, (ins, prs));
        uint8[] memory kinds = new uint8[](N);
        uint256 bound = batcher.gasBound(kinds);
        uint256 reverted;
        for (uint256 g = 1_500_000; g <= bound; g += 150_000) {
            uint256 snapshot = vm.snapshotState();
            (bool ok, bytes memory ret) = address(batcher).call{gas: g}(data);
            if (ok) {
                assertEq(abi.decode(ret, (uint256)), _all(N), "landed: every item");
            } else {
                assertEq(bytes4(ret), ZkApiExitBatcher.BatchOutOfGas.selector, "BatchOutOfGas, never a skip");
                for (uint256 i = 0; i < N; ++i) {
                    assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Active));
                }
                ++reverted;
            }
            vm.revertToState(snapshot);
        }
        assertGt(reverted, 20, "short limits revert");
        (bool landed, bytes memory out) = address(batcher).call{gas: bound}(data);
        assertTrue(landed, "the bound lands the batch");
        assertEq(abi.decode(out, (uint256)), _all(N));
    }

    /// The least gas that lands the batch (what eth_estimateGas finds) is at least the reserve, so a
    /// simulation's estimate covers destinations that burn their whole cap at inclusion.
    function test_estimateCoversHostileDestinations() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 8);
        bytes memory data = abi.encodeCall(batcher.mutualCloseBatch, (ins, prs));
        // binary search for the least gas that lands the honest batch
        uint256 lo = 500_000;
        uint256 hi = 10_000_000;
        while (hi - lo > 1_000) {
            uint256 mid = (lo + hi) / 2;
            uint256 snapshot = vm.snapshotState();
            (bool ok,) = address(batcher).call{gas: mid}(data);
            vm.revertToState(snapshot);
            if (ok) hi = mid;
            else lo = mid;
        }
        uint256 estimate = hi;
        // every destination now burns its payout's gas: the estimate still lands the batch
        for (uint256 i = 0; i < 8; ++i) {
            vm.etch(_destination(i), hex"5b5f56");
        }
        (bool landed, bytes memory out) = address(batcher).call{gas: estimate}(data);
        assertTrue(landed, "the honest estimate lands the hostile batch");
        assertEq(abi.decode(out, (uint256)), 0, "every item skipped, none starved");
        emit log_named_uint("least gas of 8 closes", estimate);
    }

    /// A destination that re-enters the batcher with another batch while it is paid: the vault's
    /// reentrancy guard refuses the inner calls, which are skipped; the outer close is paid.
    function test_reentrantDestination() public {
        // the outer close's cap leaves the destination room for a whole inner batch, whose own
        // caps are small
        uint256[5] memory caps = _caps();
        caps[0] = 2_000_000;
        ZkApiExitBatcher outer = new ZkApiExitBatcher(vault, caps);
        caps[0] = 50_000;
        ZkApiExitBatcher inner = new ZkApiExitBatcher(vault, caps);
        ReentrantDestination reentrant = new ReentrantDestination();
        vm.etch(_destination(0), address(reentrant).code);
        (Types.WithdrawalPublicInputs[] memory innerIns, bytes memory innerProofs) = _closes(1, 2);
        ReentrantDestination(payable(_destination(0)))
            .arm(inner, abi.encodeCall(inner.mutualCloseBatch, (innerIns, innerProofs)));
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 1);
        assertEq(outer.mutualCloseBatch(ins, prs), 1, "the outer close is paid");
        assertEq(ReentrantDestination(payable(_destination(0))).innerApplied(), 0, "inner items skipped");
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Active));
    }

    /// While the vault is paused, closes and escapes are refused by the vault and skipped; the batch
    /// itself still lands (its proofs verify).
    function test_pausedVaultSkipsExits() public {
        vault.pause();
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, 3);
        assertEq(batcher.mutualCloseBatch(ins, prs), 0);
        (ins, prs) = _escapes(0, 3);
        assertEq(batcher.initiateEscapeBatch(ins, prs), 0);
    }

    // ---------------------------------------------------------------------------- escapes

    /// Escapes, then defeats, raises and finalizations of the pending ones, each kind in a batch.
    function test_escapeDefeatRaiseFinalizeBatches() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _escapes(0, 8);
        assertEq(batcher.initiateEscapeBatch(ins, prs), _all(8));
        for (uint256 i = 0; i < 8; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.PendingWithdrawal));
        }
        // a second batch of the same escapes: every item is skipped (ReplayedNullifier or not active)
        assertEq(batcher.initiateEscapeBatch(ins, prs), 0);
        // defeat notes 0-2, raise notes 3-5 in one challenge batch
        (uint32[] memory dIds, uint128[] memory dAmounts, Types.RequestPublicInputs[] memory dIns, bytes memory dPrs) =
            _challenges(0, 3, false);
        (uint32[] memory rIds, uint128[] memory rAmounts, Types.RequestPublicInputs[] memory rIns, bytes memory rPrs) =
            _challenges(3, 3, true);
        uint32[] memory ids = new uint32[](6);
        uint128[] memory amounts = new uint128[](6);
        Types.RequestPublicInputs[] memory reqs = new Types.RequestPublicInputs[](6);
        for (uint256 i = 0; i < 3; ++i) {
            (ids[i], amounts[i], reqs[i]) = (dIds[i], dAmounts[i], dIns[i]);
            (ids[3 + i], amounts[3 + i], reqs[3 + i]) = (rIds[i], rAmounts[i], rIns[i]);
        }
        assertEq(batcher.challengeBatch(ids, amounts, reqs, bytes.concat(dPrs, rPrs)), _all(6));
        for (uint256 i = 0; i < 3; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Active), "defeated");
            (,, uint128 conceded) = vault.pendingConcessions(uint32(3 + i));
            assertEq(conceded, RAISE, "raised");
        }
        // the same challenges again: all skipped (not pending, or not a raise)
        assertEq(batcher.challengeBatch(ids, amounts, reqs, bytes.concat(dPrs, rPrs)), 0);
        // finalize notes 3-7 after the deadline; a refusing destination is credited by the vault
        vm.warp(block.timestamp + 1 days);
        vm.etch(_destination(4), hex"5f5ffd");
        uint32[] memory fin = new uint32[](6);
        for (uint256 i = 0; i < 6; ++i) {
            fin[i] = uint32(2 + i); // note 2 was defeated: skipped
        }
        assertEq(batcher.finalizeBatch(fin), _all(6) & ~uint256(1));
        for (uint256 i = 3; i < 8; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Closed));
        }
        assertEq(vault.escapePayoutCredits(_destination(4)), DEPOSIT - RAISE, "credited");
        assertEq(address(batcher).balance, 0);
    }

    /// gasBound adds the verification bound only when proofs are verified, and each kind's reserve.
    function test_gasBound() public view {
        uint8[] memory kinds = new uint8[](3);
        kinds[0] = 2;
        kinds[1] = 3;
        kinds[2] = 2;
        uint256 expected = batcher.VERIFY_BASE_GAS() + 3 * batcher.VERIFY_ITEM_GAS() + 2
            * ((DEFEAT_GAS * 64) / 63 + batcher.ITEM_OVERHEAD_GAS()) + (RAISE_GAS * 64) / 63
            + batcher.ITEM_OVERHEAD_GAS() + batcher.RESERVE_MARGIN_GAS();
        assertEq(batcher.gasBound(kinds), expected);
        uint8[] memory finals = new uint8[](2);
        finals[0] = 4;
        finals[1] = 4;
        assertEq(
            batcher.gasBound(finals),
            2 * ((FINALIZE_GAS * 64) / 63 + batcher.ITEM_OVERHEAD_GAS()) + batcher.RESERVE_MARGIN_GAS()
        );
    }
}

/// @dev Closes to never-used destinations: the payout creates each account (EIP-161, 25,000 gas).
contract ExitBatcherFreshDestinationTest is BatcherTestBase {
    function setUp() public {
        _deployVaultAndBatcher(false);
    }

    /// Closes to never-used destinations (EIP-161: the payout creates the account) fit the cap.
    function test_freshDestinationsFitTheCap() public {
        (Types.WithdrawalPublicInputs[] memory ins, bytes memory prs) = _closes(0, N);
        for (uint256 i = 0; i < N; ++i) {
            assertEq(_destination(i).balance, 0);
            assertEq(_destination(i).codehash, bytes32(0), "never used");
        }
        uint256 fresh = _txGas(address(batcher), abi.encodeCall(batcher.mutualCloseBatch, (ins, prs)));
        for (uint256 i = 0; i < N; ++i) {
            assertEq(uint256(_status(i)), uint256(Types.NoteStatus.Closed), "every item landed");
        }
        emit log_named_uint("16 closes to never-used destinations (tx gas)", fresh);
    }
}
