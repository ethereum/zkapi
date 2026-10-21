// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalAccountFactory} from "../../src/gasless/ZkApiWithdrawalAccountFactory.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {ToggleableDestination} from "../NativeEthVault.t.sol";
import {GaslessTestBase, SelfFundedAccount} from "./GaslessTestBase.sol";

/// @dev The griefing bounds of section 2.6: a replayed close (alone and inside a bundle), the
///      forward that recovers it, attempt exhaustion and release, allowForward, the ceiling
///      arithmetic, and the credits no owner function can touch.
contract GriefingTest is GaslessTestBase {
    function setUp() public {
        _setUpGasless();
    }

    /// G2a: the public calldata replayed before the bundle's transaction makes on-chain validation
    /// refuse the operation (the bundler, not the float, pays); replayed inside the bundle, after
    /// validation, the execution reverts, the float loses one bounded operation, S is stranded with
    /// the payout, and one forward recovers it.
    function test_closeFrontRunByADirectReplay() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        address s = op.sender;
        vm.prank(user);
        vault.mutualClose(inputs, PROOF);
        assertEq(s.balance, uint256(BIG - 1_000_000) * 1 gwei, "the payout reached S anyway");
        _refused(op, ZkApiWithdrawalPaymaster.NoteNotActive.selector);
        assertEq(paymaster.attempts(_closeKey(1001)), 0, "nothing counted");
        // the owner lets S forward it (no paymaster-recorded evidence exists)
        paymaster.allowForward(s);
        Vm.Log[] memory logs = _handle(_forwardOp());
        assertEq(payee.balance, _settled(logs).paidOut);

        // the same race inside a bundle
        uint32 id2 = _bigNote(43);
        (op, inputs) = _closeOp(id2, 1002, BIG - 1_000_000);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        uint256 maxCost = _maxCost(_gas(CLOSE, false));
        logs = _bundledWithReplay(op, abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256)));

        (bool success, uint256 actualGasCost,) = _userOpEventOf(logs, s);
        assertFalse(success, "the execution reverted");
        bool found;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (
                logs[i].emitter == ENTRY_POINT && logs[i].topics[0] == IEntryPoint.UserOperationRevertReason.selector
                    && address(uint160(uint256(logs[i].topics[2]))) == s
            ) {
                (, bytes memory revertReason) = abi.decode(logs[i].data, (uint256, bytes));
                assertEq(
                    revertReason,
                    abi.encodeWithSelector(
                        ZkApiWithdrawalAccount.VaultCallFailed.selector,
                        abi.encodeWithSelector(Errors.NoteNotActive.selector)
                    ),
                    "the vault's error bubbles"
                );
                found = true;
            }
        }
        assertTrue(found, "UserOperationRevertReason");
        (found,) = _find(logs, address(paymaster), ZkApiWithdrawalPaymaster.SponsorshipFailed.selector);
        assertTrue(found, "SponsorshipFailed");
        assertFalse(_settled(logs).found);
        assertTrue(paymaster.stranded(s), "stranded");
        assertGe(paymaster.lostWei(), actualGasCost, "the metric bounds the loss");
        assertLe(
            paymaster.lostWei(), actualGasCost + (gp.callFloor[0] + gp.postOpFloor) * _gasPrice(_gas(CLOSE, false))
        );
        assertEq(
            depositBefore - entryPoint.balanceOf(address(paymaster)), actualGasCost, "the float lost exactly the cost"
        );
        assertLe(actualGasCost, maxCost, "bounded by the prefund");
        assertEq(paymaster.attempts(_closeKey(1002)), 1, "counted");
        assertEq(s.balance, uint256(BIG - 1_000_000) * 1 gwei, "the payout is in S");

        // the forward delivers the balance minus its own charge
        uint256 payeeBefore = payee.balance;
        logs = _handle(_forwardOp());
        (success,,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.kind, FORWARD);
        assertEq(e.noteId, type(uint32).max, "no escape evidence");
        assertEq(e.received, uint256(BIG - 1_000_000) * 1 gwei);
        assertEq(payee.balance - payeeBefore, e.received - e.charged);
        assertEq(s.balance, 0);
        assertFalse(paymaster.stranded(s), "evidence consumed");
        vm.deal(s, 0.05 ether);
        _refused(_forwardOp(), ZkApiWithdrawalPaymaster.NotStranded.selector);
    }

    /// G2a in a bundle: a self-funded account replays the close in the operation before ours.
    function test_replayInsideTheBundle() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        SelfFundedAccount replayer = new SelfFundedAccount(ENTRY_POINT);
        vm.deal(address(replayer), 1 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _selfFundedOp(replayer, address(vault), abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256)));
        ops[1] = op;
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        uint256 maxCost = _maxCost(_gas(CLOSE, true));

        Vm.Log[] memory logs = _handleOps(ops);

        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        bool ourSuccess;
        uint256 ourCost;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == ENTRY_POINT && logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector) {
                if (address(uint160(uint256(logs[i].topics[2]))) == op.sender) {
                    (, ourSuccess, ourCost,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                }
            }
        }
        assertFalse(ourSuccess, "our close reverted");
        assertEq(depositBefore - entryPoint.balanceOf(address(paymaster)), ourCost);
        assertLe(ourCost, maxCost, "the float pays at most the prefund");
        assertLe(ourCost, maxCost * PRIORITY_CEILING / MAX_FEE + maxCost, "and never more than the capped tip adds");
        assertTrue(paymaster.stranded(op.sender));
        assertEq(op.sender.balance, uint256(BIG - 1_000_000) * 1 gwei, "the payout is in S for the forward");
    }

    /// G2c: a third party's finalization before the bundle is refused in validation; inside the
    /// bundle it strands S, and the forward then settles the debt and its own charge.
    function test_thirdPartyFinalizeBeforeTheSponsoredOne() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory escape,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(escape);
        address s = escape.sender;
        uint256 debt = paymaster.owed(s);
        vm.warp(_deadline(id));
        PackedUserOperation memory finalize = _finalizeOp(id);
        uint256 snap = vm.snapshotState();
        vault.finalizeEscapeWithdrawal(id);
        _refused(finalize, ZkApiWithdrawalPaymaster.NotPendingEscape.selector);
        vm.revertToState(snap);

        Vm.Log[] memory logs = _bundledWithReplay(finalize, abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (id)));
        (bool success, uint256 cost,) = _userOpEventOf(logs, s);
        assertFalse(success);
        assertTrue(paymaster.stranded(s));
        assertGe(paymaster.lostWei(), cost);
        assertEq(s.balance, uint256(BIG - 2_000_000) * 1 gwei);
        // the forward settles the debt and the forward's own charge out of the payout
        logs = _handle(_forwardOp());
        SettledEvent memory e = _settled(logs);
        assertTrue(e.found);
        assertEq(e.noteId, id, "the finalized escape is the evidence too");
        assertEq(e.owedPaid, debt);
        assertEq(payee.balance, e.received - e.charged - debt);
        assertEq(paymaster.escapeNotePlusOne(s), 0);
        assertEq(paymaster.owed(s), 0);
    }

    /// The EntryPoint validates every operation of a bundle before executing any: the same close
    /// at three consecutive nonces would pass the state checks three times, settle once and revert
    /// twice at the float's expense, burning the key's attempts for free. The second validation of
    /// a key in one transaction is refused instead, so the bundle fails validation (the bundler
    /// pays) and nothing is counted.
    function test_sameKeyTwiceInOneBundleFailsValidation() public {
        factory.createAccount(ownerAddr, payee);
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, BIG - 1_000_000);
        PackedUserOperation[] memory ops = new PackedUserOperation[](3);
        for (uint256 i = 0; i < 3; ++i) {
            ops[i] = abi.decode(abi.encode(op), (PackedUserOperation));
            ops[i].nonce = op.nonce + i;
            ops[i] = _sign(ops[i], OWNER_KEY);
        }
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        (bool ok, bytes memory data) = _tryHandleOps(ops);
        assertFalse(ok, "the bundle fails validation");
        (string memory reason, bytes memory inner) = _failedOpWithRevert(data);
        assertEq(reason, "AA33 reverted");
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.SponsorshipInFlight.selector, _closeKey(1001)));
        assertEq(entryPoint.balanceOf(address(paymaster)), depositBefore, "uncharged");
        assertEq(paymaster.attempts(_closeKey(1001)), 0, "nothing counted");
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        // alone, the operation is sponsored as usual
        Vm.Log[] memory logs = _handle(op);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        assertEq(paymaster.attempts(_closeKey(1001)), 1);
        // the same for a finalization replayed at the next nonce
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory escape,) = _escapeOp(id2, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(escape);
        vm.warp(_deadline(id2));
        PackedUserOperation memory finalize = _finalizeOp(id2);
        ops = new PackedUserOperation[](2);
        ops[0] = finalize;
        ops[1] = abi.decode(abi.encode(finalize), (PackedUserOperation));
        ops[1].nonce = finalize.nonce + 1;
        ops[1] = _sign(ops[1], OWNER_KEY);
        (ok, data) = _tryHandleOps(ops);
        assertFalse(ok);
        (, inner) = _failedOpWithRevert(data);
        assertEq(bytes4(inner), ZkApiWithdrawalPaymaster.SponsorshipInFlight.selector);
        assertEq(paymaster.attempts(_finalizeKey(id2)), 0);
        logs = _handle(finalize);
        (success,,) = _userOpEvent(logs);
        assertTrue(success, "alone, the finalization is sponsored");
    }

    /// Two sponsored operations on one note under different keys, from two transit accounts (so a
    /// compliant bundler bundles them): an escape and a close of the note, or closes at two of its
    /// nullifiers. All pass the note's state checks, at most one can execute, and the rest would
    /// revert after the full verification at the float's expense with nothing reaching their
    /// senders. The note is locked like a key: the bundle fails validation, nothing is charged or
    /// counted, and each operation alone is sponsored as usual.
    function test_twoOperationsOnOneNoteInOneBundleFailValidation() public {
        address payee2 = address(0x9A7EF);
        uint32 id = _bigNote(42);
        bytes32 noteLock = keccak256(abi.encode(bytes32("note"), uint256(id)));
        (PackedUserOperation memory escape,) = _escapeOpFor(payee2, id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        (PackedUserOperation memory close,) = _closeOp(id, 2001, BIG - 1_000_000);
        (PackedUserOperation memory close2,) = _closeOpFor(payee2, id, 3001, BIG - 1_000_000);
        assertTrue(escape.sender != close.sender, "different transit accounts");
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));

        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = escape;
        ops[1] = close;
        (bool ok, bytes memory data) = _tryHandleOps(ops);
        assertFalse(ok, "an escape and a close of one note fail validation");
        (string memory reason, bytes memory inner) = _failedOpWithRevert(data);
        assertEq(reason, "AA33 reverted");
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.SponsorshipInFlight.selector, noteLock));

        // two closes of the note at different nullifiers
        ops[0] = close;
        ops[1] = close2;
        (ok, data) = _tryHandleOps(ops);
        assertFalse(ok, "two closes of one note fail validation");
        (reason, inner) = _failedOpWithRevert(data);
        assertEq(reason, "AA33 reverted");
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.SponsorshipInFlight.selector, noteLock));

        assertEq(entryPoint.balanceOf(address(paymaster)), depositBefore, "uncharged");
        assertEq(paymaster.lostWei(), 0, "no loss recorded");
        assertEq(paymaster.attempts(_escapeKey(id)), 0, "nothing counted");
        assertEq(paymaster.attempts(_closeKey(2001)), 0);
        assertEq(paymaster.attempts(_closeKey(3001)), 0);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        assertFalse(paymaster.stranded(close.sender));

        // alone, the escape is sponsored; the lock is per note, so the note's finalization and a
        // close of another note share a bundle
        Vm.Log[] memory logs = _handle(escape);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success, "alone, the escape is sponsored");
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.PendingWithdrawal));
        vm.warp(_deadline(id));
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory closeOther,) = _closeOp(id2, 4001, BIG - 1_000_000);
        ops[0] = _finalizeOpFor(payee2, id);
        ops[1] = closeOther;
        logs = _handleOps(ops);
        assertEq(_count(logs, address(paymaster), ZkApiWithdrawalPaymaster.Settled.selector), 2, "both settled");
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        assertEq(uint256(_status(id2)), uint256(Types.NoteStatus.Closed));
    }

    /// Two notes of one transit account, closed in one bundle: each sponsorship is counted for
    /// the sender separately, so both forward, settle and pay the payee.
    function test_twoNotesOfOneAccountInOneBundle() public {
        address s = factory.createAccount(ownerAddr, payee);
        uint32 idA = _bigNote(42);
        uint32 idB = _bigNote(43);
        (PackedUserOperation memory opA,) = _closeOp(idA, 1001, BIG - 1_000_000);
        (PackedUserOperation memory opB,) = _closeOp(idB, 1002, BIG - 2_000_000);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = opA;
        ops[1] = opB;
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handleOps(ops);
        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        assertEq(_count(logs, address(paymaster), ZkApiWithdrawalPaymaster.Settled.selector), 2, "both settled");
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.UserOperationRevertReason.selector));
        assertFalse(_has(logs, ENTRY_POINT, IEntryPoint.PostOpRevertReason.selector));
        uint256 paidOut;
        uint256 charged;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == address(paymaster) && logs[i].topics[0] == ZkApiWithdrawalPaymaster.Settled.selector)
            {
                (,, uint256 received, uint256 chargedWei,, uint256 paid) =
                    abi.decode(logs[i].data, (uint8, uint32, uint256, uint256, uint256, uint256));
                assertTrue(
                    received == uint256(BIG - 1_000_000) * 1 gwei || received == uint256(BIG - 2_000_000) * 1 gwei,
                    "each operation received its own payout"
                );
                paidOut += paid;
                charged += chargedWei;
            }
        }
        assertEq(payee.balance, paidOut, "the payee was paid both");
        assertEq(paidOut + charged, uint256(2 * BIG - 3_000_000) * 1 gwei, "nothing lost");
        assertEq(s.balance, 0);
        assertFalse(paymaster.stranded(s), "nothing stranded");
        assertEq(paymaster.received(s), 0);
        assertEq(paymaster.receivedGas(s), 0);
        assertGe(entryPoint.balanceOf(address(paymaster)), depositBefore + 2 * FLAT_FEE, "the float never pays");
        assertEq(uint256(_status(idA)), uint256(Types.NoteStatus.Closed));
        assertEq(uint256(_status(idB)), uint256(Types.NoteStatus.Closed));
    }

    /// An unsponsored operation of S (its own EntryPoint deposit pays) that closes the note ahead
    /// of the sponsored close of the same note, in one bundle: it forwards the payout while the
    /// sponsorship is in flight, the sponsored execution reverts, and the forwarded payout is
    /// credited to the payee rather than left outside the accounting.
    function test_unsponsoredCloseAheadOfTheSponsoredOneCreditsThePayee() public {
        address s = factory.createAccount(ownerAddr, payee);
        entryPoint.depositTo{value: 1 ether}(s);
        uint32 id = _bigNote(42);
        (PackedUserOperation memory sponsored, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _unsponsoredOp(s, 7, _callData(_closeCall(inputs)));
        ops[1] = sponsored;
        Vm.Log[] memory logs = _handleOps(ops);
        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        // the first UserOperationEvent of S is the unsponsored operation's
        (bool unsponsoredSuccess,,) = _userOpEventOf(logs, s);
        assertTrue(unsponsoredSuccess, "the unsponsored close executed");
        assertTrue(
            _has(logs, address(paymaster), ZkApiWithdrawalPaymaster.SponsorshipFailed.selector),
            "the sponsored one reverted"
        );
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.PayoutCredited.selector), "credited");
        uint256 payout = uint256(BIG - 1_000_000) * 1 gwei;
        assertEq(paymaster.credits(payee), payout, "the whole payout is the payee's credit");
        assertEq(paymaster.totalCredits(), payout);
        assertEq(address(paymaster).balance, payout, "nothing outside the accounting");
        assertEq(s.balance, 0);
        assertEq(paymaster.received(s), 0);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CreditsReserved.selector);
        paymaster.rescueUnaccounted(1, user);
        paymaster.claimCredit(payee);
        assertEq(payee.balance, payout);
        assertEq(address(paymaster).balance, 0);
    }

    /// An escape's debt cannot be dodged by pairing the sponsored finalization with an unsponsored
    /// one: S's own deposit finalizes first (the vault pays S, S repays while the sponsorship is in
    /// flight), the sponsored finalization reverts, and its postOp deducts the debt from what
    /// arrived before crediting the rest to the payee. The float loses only the reverted operation.
    function test_unsponsoredFinalizeAheadOfTheSponsoredOneSettlesTheDebt() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory escape,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(escape);
        address s = escape.sender;
        uint256 debt = paymaster.owed(s);
        assertGt(debt, 0);
        entryPoint.depositTo{value: 1 ether}(s);
        vm.warp(_deadline(id));
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _unsponsoredOp(s, 7, _callData(_finalizeCall(id)));
        ops[1] = _finalizeOp(id);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        uint256 lostBefore = paymaster.lostWei();

        Vm.Log[] memory logs = _handleOps(ops);

        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        (bool unsponsoredSuccess,,) = _userOpEventOf(logs, s);
        assertTrue(unsponsoredSuccess, "the unsponsored finalization executed");
        assertTrue(
            _has(logs, address(paymaster), ZkApiWithdrawalPaymaster.SponsorshipFailed.selector),
            "the sponsored one reverted"
        );
        uint256 ourCost;
        for (uint256 i = 0; i < logs.length; ++i) {
            if (
                logs[i].emitter == ENTRY_POINT && logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector
                    && logs[i].topics[1] == entryPoint.getUserOpHash(ops[1])
            ) {
                (,, ourCost,) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
            }
        }
        uint256 payout = uint256(BIG - 2_000_000) * 1 gwei;
        assertEq(paymaster.owed(s), 0, "the debt is settled");
        assertEq(paymaster.credits(payee), payout - debt, "only the rest is the payee's credit");
        assertEq(paymaster.totalCredits(), payout - debt);
        assertEq(address(paymaster).balance, payout - debt, "nothing outside the accounting");
        assertEq(
            entryPoint.balanceOf(address(paymaster)),
            depositBefore - ourCost + debt,
            "the float paid the reverted operation and recovered the debt"
        );
        assertGe(paymaster.lostWei() - lostBefore, ourCost, "the loss is recorded");
        assertTrue(paymaster.stranded(s));
        assertEq(s.balance, 0);
        assertEq(paymaster.received(s), 0);
        paymaster.claimCredit(payee);
        assertEq(payee.balance, payout - debt);
    }

    /// The same with a close: a defeated escape leaves S a debt, and an unsponsored close of S ahead
    /// of the sponsored one pays it before the payee is credited.
    function test_unsponsoredCloseAheadOfTheSponsoredOneSettlesTheDebt() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory escape,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(escape);
        address s = escape.sender;
        uint256 debt = paymaster.owed(s);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, _evidence(2002, 100_000), PROOF);
        assertEq(paymaster.owed(s), debt, "the defeated escape's debt persists");
        entryPoint.depositTo{value: 1 ether}(s);
        (PackedUserOperation memory sponsored, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 2003, BIG - 1_000_000);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _unsponsoredOp(s, 7, _callData(_closeCall(inputs)));
        ops[1] = sponsored;
        Vm.Log[] memory logs = _handleOps(ops);
        assertEq(_count(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector), 2);
        assertTrue(
            _has(logs, address(paymaster), ZkApiWithdrawalPaymaster.SponsorshipFailed.selector),
            "the sponsored one reverted"
        );
        uint256 payout = uint256(BIG - 1_000_000) * 1 gwei;
        assertEq(paymaster.owed(s), 0, "the debt is settled");
        assertEq(paymaster.credits(payee), payout - debt);
        assertEq(address(paymaster).balance, payout - debt);
        assertTrue(paymaster.stranded(s));
    }

    function test_allowForwardForABalanceWithoutEvidence() public {
        address s = factory.createAccount(ownerAddr, payee);
        uint32 id = _bigNote(42);
        vm.prank(user);
        vault.mutualClose(_closeTo(id, 1001, BIG - 1_000_000, s), PROOF);
        _refused(_forwardOp(), ZkApiWithdrawalPaymaster.NotStranded.selector);
        vm.prank(user);
        vm.expectRevert();
        paymaster.allowForward(s);
        vm.recordLogs();
        paymaster.allowForward(s);
        assertTrue(_has(vm.getRecordedLogs(), address(paymaster), ZkApiWithdrawalPaymaster.ForwardAllowed.selector));
        Vm.Log[] memory logs = _handle(_forwardOp());
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        assertEq(payee.balance, _settled(logs).paidOut);
        assertEq(s.balance, 0);
    }

    /// G6: with every field bounded, one sponsorship costs the float at most the prefund, and the
    /// prefund is bounded by the caps and the ceilings.
    function test_ceilingArithmetic() public view {
        uint256 maxGas = gp.pvgCap + gp.verificationCap + gp.callHardCap[1] + gp.pmVerificationCap + gp.postOpCap;
        assertEq(maxGas, 2_496_000);
        assertLe(maxGas * MAX_FEE_CEILING, 0.25 ether, "under the hard cap of the policy at these ceilings");
        assertEq(
            gp.finalizeReserveGas,
            gp.pvgFloor + gp.verificationFloor + gp.callFloor[2] + gp.pmVerificationFloor + gp.postOpFloor
        );
        assertEq(gp.maxAttempts, 3);
        assertLt(gp.verificationCap, 500_000, "LIM-060");
        assertLt(gp.pmVerificationCap, 500_000, "LIM-060");
        assertEq(gp.pmVerificationCap, 496_000, "MAX_VERIFICATION_GAS - VALIDATION_GAS_SLACK");
        assertEq(paymaster.ENTRY_POINT_V070_CODEHASH(), ENTRY_POINT_CODEHASH);
    }

    function test_feeCeilingsAndPolicyBounds() public {
        vm.expectRevert(ZkApiWithdrawalPaymaster.CeilingOutOfRange.selector);
        paymaster.setFeeCeilings(500 gwei + 1, 5 gwei);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CeilingOutOfRange.selector);
        paymaster.setFeeCeilings(100 gwei, 20 gwei + 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CeilingOutOfRange.selector);
        paymaster.setFeeCeilings(0, 5 gwei);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CeilingOutOfRange.selector);
        paymaster.setFeeCeilings(100 gwei, 0);
        vm.prank(user);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotFeeKeeper.selector);
        paymaster.setFeeCeilings(50 gwei, 2 gwei);
        paymaster.setFeeKeeper(user);
        vm.prank(user);
        paymaster.setFeeCeilings(50 gwei, 2 gwei);
        assertEq(paymaster.maxFeeCeiling(), 50 gwei);
        assertEq(paymaster.priorityFeeCeiling(), 2 gwei);
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.flatFeeWei = uint64(0.001 ether + 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.PolicyOutOfBounds.selector);
        paymaster.setPolicy(p);
        p = _defaultPolicy();
        p.maxSponsoredCost = uint128(0.25 ether + 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.PolicyOutOfBounds.selector);
        paymaster.setPolicy(p);
        vm.prank(user);
        vm.expectRevert();
        paymaster.setPolicy(_defaultPolicy());
    }

    function test_rescueUnaccountedCannotTouchCredits() public {
        ToggleableDestination wallet = new ToggleableDestination();
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _closeOpFor(address(wallet), id, 1001, BIG - 1_000_000);
        _handle(op);
        uint256 credited = paymaster.credits(address(wallet));
        assertGt(credited, 0);
        assertEq(address(paymaster).balance, credited);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CreditsReserved.selector);
        paymaster.rescueUnaccounted(1, user);
        vm.expectRevert(ZkApiWithdrawalPaymaster.ZeroAmount.selector);
        paymaster.rescueUnaccounted(0, user);
        // ETH forced in outside the accounting
        vm.deal(address(paymaster), address(paymaster).balance + 1 ether);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CreditsReserved.selector);
        paymaster.rescueUnaccounted(1 ether + 1, user);
        vm.prank(user);
        vm.expectRevert();
        paymaster.rescueUnaccounted(1 ether, user);
        uint256 before = user.balance;
        paymaster.rescueUnaccounted(1 ether, user);
        assertEq(user.balance - before, 1 ether);
        assertEq(address(paymaster).balance, credited, "the credits stay");
        wallet.setAccepting(true);
        paymaster.claimCredit(address(wallet));
        assertEq(address(wallet).balance, credited);
    }

    function test_stakeAndDepositManagement() public {
        IEntryPoint.DepositInfo memory info = entryPoint.getDepositInfo(address(paymaster));
        assertTrue(info.staked);
        assertEq(info.stake, 1 ether);
        assertEq(info.unstakeDelaySec, UNSTAKE_DELAY);
        info = entryPoint.getDepositInfo(address(factory));
        assertTrue(info.staked);
        vm.prank(user);
        vm.expectRevert();
        paymaster.withdrawTo(payable(user), 1 ether);
        uint256 before = user.balance;
        paymaster.withdrawTo(payable(user), 1 ether);
        assertEq(user.balance - before, 1 ether);
        vm.prank(user);
        vm.expectRevert();
        paymaster.unlockStake();
        paymaster.unlockStake();
        vm.warp(vm.getBlockTimestamp() + UNSTAKE_DELAY);
        paymaster.withdrawStake(payable(user));
        assertEq(user.balance - before, 2 ether);
        vm.prank(user);
        vm.expectRevert(bytes4(keccak256("NotPaymasterOwner()")));
        factory.unlockStake();
        factory.unlockStake();
        vm.warp(vm.getBlockTimestamp() + UNSTAKE_DELAY);
        factory.withdrawStake(payable(user));
        assertEq(user.balance - before, 3 ether);
    }

    /// The stake is not an asset at risk: the EntryPoint rewrites the stake's terms on every
    /// addStake (the delay can only grow, a pending unlock is cancelled), so an open addStake would
    /// let a stranger freeze the operator's stake for 1 wei. A stranger may only add to a locked
    /// stake at its current delay; the first stake, a longer delay and a re-lock are the owner's.
    function test_strangerCannotAlterTheStakeTerms() public {
        bytes4 locked = ZkApiWithdrawalPaymaster.StakeTermsLocked.selector;
        // A top-up at the current delay changes only the amount.
        vm.prank(user);
        paymaster.addStake{value: 1}(UNSTAKE_DELAY);
        IEntryPoint.DepositInfo memory info = entryPoint.getDepositInfo(address(paymaster));
        assertTrue(info.staked);
        assertEq(info.stake, 1 ether + 1);
        assertEq(info.unstakeDelaySec, UNSTAKE_DELAY);
        assertEq(info.withdrawTime, 0);
        // A longer delay is refused, with or without value.
        vm.prank(user);
        vm.expectRevert(locked);
        paymaster.addStake{value: 1}(type(uint32).max);
        vm.prank(user);
        vm.expectRevert(locked);
        paymaster.addStake(UNSTAKE_DELAY + 1);
        // A pending unlock cannot be cancelled, even at the current delay.
        paymaster.unlockStake();
        info = entryPoint.getDepositInfo(address(paymaster));
        uint48 withdrawTime = info.withdrawTime;
        assertEq(withdrawTime, vm.getBlockTimestamp() + UNSTAKE_DELAY);
        vm.prank(user);
        vm.expectRevert(locked);
        paymaster.addStake{value: 1}(UNSTAKE_DELAY);
        info = entryPoint.getDepositInfo(address(paymaster));
        assertFalse(info.staked);
        assertEq(info.withdrawTime, withdrawTime, "the unlock stands");
        assertEq(info.stake, 1 ether + 1);
        // The owner may re-lock, unlock again and withdraw once due.
        paymaster.addStake{value: 1}(UNSTAKE_DELAY);
        info = entryPoint.getDepositInfo(address(paymaster));
        assertTrue(info.staked);
        assertEq(info.withdrawTime, 0);
        paymaster.unlockStake();
        vm.warp(vm.getBlockTimestamp() + UNSTAKE_DELAY);
        uint256 before = user.balance;
        paymaster.withdrawStake(payable(user));
        assertEq(user.balance - before, 1 ether + 2);
        // A withdrawn stake is a fresh one: only the owner may stake again, at any delay.
        vm.prank(user);
        vm.expectRevert(locked);
        paymaster.addStake{value: 1}(UNSTAKE_DELAY);
        paymaster.addStake{value: 1 ether}(UNSTAKE_DELAY / 2);
        info = entryPoint.getDepositInfo(address(paymaster));
        assertTrue(info.staked);
        assertEq(info.unstakeDelaySec, UNSTAKE_DELAY / 2);
        // A fresh paymaster and its factory: nobody can pick their delay before the owner does.
        ZkApiWithdrawalPaymaster fresh = new ZkApiWithdrawalPaymaster(
            entryPoint, vault, address(this), _defaultPolicy(), MAX_FEE_CEILING, PRIORITY_CEILING
        );
        ZkApiWithdrawalAccountFactory freshFactory = fresh.factory();
        vm.prank(user);
        vm.expectRevert(locked);
        fresh.addStake{value: 1}(UNSTAKE_DELAY);
        vm.prank(user);
        vm.expectRevert(ZkApiWithdrawalAccountFactory.StakeTermsLocked.selector);
        freshFactory.addStake{value: 1}(UNSTAKE_DELAY);
        fresh.addStake{value: 1 ether}(UNSTAKE_DELAY);
        freshFactory.addStake{value: 1 ether}(UNSTAKE_DELAY);
        assertTrue(entryPoint.getDepositInfo(address(fresh)).staked);
        assertTrue(entryPoint.getDepositInfo(address(freshFactory)).staked);
        // The factory follows the same rule under the paymaster's owner.
        bytes4 lockedFactory = ZkApiWithdrawalAccountFactory.StakeTermsLocked.selector;
        vm.prank(user);
        factory.addStake{value: 1}(UNSTAKE_DELAY);
        info = entryPoint.getDepositInfo(address(factory));
        assertEq(info.stake, 1 ether + 1);
        assertEq(info.unstakeDelaySec, UNSTAKE_DELAY);
        vm.prank(user);
        vm.expectRevert(lockedFactory);
        factory.addStake{value: 1}(type(uint32).max);
        factory.unlockStake();
        info = entryPoint.getDepositInfo(address(factory));
        withdrawTime = info.withdrawTime;
        vm.prank(user);
        vm.expectRevert(lockedFactory);
        factory.addStake{value: 1}(UNSTAKE_DELAY);
        info = entryPoint.getDepositInfo(address(factory));
        assertFalse(info.staked);
        assertEq(info.withdrawTime, withdrawTime, "the factory's unlock stands");
        factory.addStake{value: 1}(UNSTAKE_DELAY);
        assertTrue(entryPoint.getDepositInfo(address(factory)).staked);
    }
}
