// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {Types} from "../../src/libraries/Types.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev Sponsored escapes: the initiation's debt, the finalization window, raises, defeats, a third
///      party's finalization and the forward that follows, one open sponsored escape per transit
///      account, and the owner's write-off.
contract EscapeTest is GaslessTestBase {
    uint128 constant PAYOUT = BIG - 2_000_000;
    uint128 constant CONCEDED = 1_000_000;

    function setUp() public {
        _setUpGasless();
    }

    function _sponsoredEscape(uint32 id) internal returns (address s, SettledEvent memory e, uint256 actualGasCost) {
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, PAYOUT, CONCEDED);
        s = op.sender;
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 cost,) = _userOpEvent(logs);
        assertTrue(success, "escape sponsored");
        e = _settled(logs);
        actualGasCost = cost;
    }

    function test_initiationRecordsTheDebt() public {
        uint32 id = _bigNote(42);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        vm.recordLogs();
        (address s, SettledEvent memory e, uint256 actualGasCost) = _sponsoredEscape(id);
        assertEq(e.kind, ESCAPE);
        assertEq(e.noteId, id);
        assertEq(e.received, 0, "nothing is paid at initiation");
        assertEq(e.paidOut, 0);
        assertEq(e.owedPaid, 0);
        assertGe(e.charged, actualGasCost + FLAT_FEE);
        assertLe(e.charged, actualGasCost + FLAT_FEE + gp.marginGas * _gasPrice(_gas(ESCAPE, true)));
        assertEq(paymaster.owed(s), e.charged, "the charge is the debt");
        assertEq(paymaster.escapeNotePlusOne(s), uint256(id) + 1);
        assertTrue(paymaster.escapeSponsored(id));
        assertEq(
            depositBefore - entryPoint.balanceOf(address(paymaster)), actualGasCost, "the float paid the initiation"
        );
        (bool exists,,, uint128 finalBalance, address destination,) = vault.pendingWithdrawals(id);
        assertTrue(exists);
        assertEq(finalBalance, PAYOUT);
        assertEq(destination, s);
        assertEq(s.balance, 0);
    }

    /// A balance that reached S directly (a close paid to it outside any sponsorship) is forwarded
    /// by a sponsored escape initiation like by every other path: the debt, old and new, is settled
    /// first and deposited, and only the rest is credited to the payee. The old debt is a defeated
    /// escape's (a pending one would refuse the second initiation: EscapeEvidencePending).
    function test_initiationWithABalanceInSSettlesTheDebtFirst() public {
        uint32 idA = _bigNote(42);
        (address s,,) = _sponsoredEscape(idA);
        uint256 debt = paymaster.owed(s);
        assertGt(debt, 0);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(idA, _evidence(2002, 100_000), PROOF);
        assertEq(paymaster.owed(s), debt, "the defeated escape's debt persists");
        uint32 idB = _bigNote(43);
        vm.prank(user);
        vault.mutualClose(_closeTo(idB, 3001, BIG - 1_000_000, s), PROOF);
        uint256 balance = uint256(BIG - 1_000_000) * 1 gwei;
        assertEq(s.balance, balance);
        uint32 idC = _bigNote(44);
        (PackedUserOperation memory op,) = _escapeOp(idC, 4001, 4002, PAYOUT, CONCEDED);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 actualGasCost,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.kind, ESCAPE);
        assertEq(e.received, balance, "S forwarded the balance");
        assertGe(e.charged, actualGasCost + FLAT_FEE, "the float never pays");
        assertLe(
            e.charged,
            actualGasCost + FLAT_FEE + (gp.marginGas + gp.creditGas) * _gasPrice(_gas(ESCAPE, false)),
            "at most the margin and the credit bookkeeping above the real cost"
        );
        assertEq(e.owedPaid, debt + e.charged, "the old debt and this initiation's charge were deducted");
        assertEq(e.paidOut, balance - e.owedPaid);
        assertEq(paymaster.owed(s), 0, "nothing is owed any more");
        assertEq(paymaster.credits(payee), e.paidOut, "the rest is the payee's credit");
        assertEq(address(paymaster).balance, paymaster.totalCredits());
        assertEq(s.balance, 0);
        assertEq(
            entryPoint.balanceOf(address(paymaster)) + actualGasCost - depositBefore,
            e.owedPaid,
            "the deducted amount replenished the float"
        );
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idC) + 1);
        assertTrue(paymaster.escapeSponsored(idC));
        paymaster.claimCredit(payee);
        assertEq(payee.balance, e.paidOut);
    }

    function test_finalizationIsDueAtTheDeadlineAndRepaysTheDebt() public {
        uint32 id = _bigNote(42);
        (address s,, uint256 escapeCost) = _sponsoredEscape(id);
        uint256 debt = paymaster.owed(s);
        PackedUserOperation memory op = _finalizeOp(id);
        (bool ok, bytes memory data) = _tryHandle(op);
        assertFalse(ok);
        assertEq(_failedOp(data), "AA32 paymaster expired or not due");
        vm.warp(_deadline(id) - 1);
        (ok, data) = _tryHandle(op);
        assertFalse(ok, "one second early");
        vm.warp(_deadline(id));
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 finalizeCost,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.kind, FINALIZE);
        assertEq(e.received, uint256(PAYOUT) * 1 gwei);
        assertEq(e.owedPaid, debt, "the initiation's debt is collected");
        assertEq(e.paidOut, e.received - e.charged - debt);
        assertEq(payee.balance, e.paidOut);
        assertEq(paymaster.owed(s), 0);
        assertEq(paymaster.escapeNotePlusOne(s), 0, "the escape record is closed");
        assertEq(entryPoint.balanceOf(address(paymaster)) - depositBefore, e.charged + debt - finalizeCost);
        assertGe(
            entryPoint.balanceOf(address(paymaster)),
            INITIAL_DEPOSIT + 2 * FLAT_FEE,
            "both operations paid for themselves"
        );
        escapeCost;
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
    }

    /// A raise lowers the finalization's payout: still sponsored while it covers the debt and the
    /// cost; otherwise the user finalizes directly and sweep settles the debt.
    function test_raiseLowersThePayout() public {
        uint32 id = _bigNote(42);
        (address s,,) = _sponsoredEscape(id);
        uint256 debt = paymaster.owed(s);
        // a moderate raise
        Types.RequestPublicInputs memory request = _evidence(2001, 20_000_000);
        vm.prank(challenger);
        vault.raiseEscapeConcession(id, request, PROOF, 20_000_000);
        uint128 raised = PAYOUT + CONCEDED - 20_000_000;
        assertEq(_pendingFinalBalance(id), raised);
        vm.warp(_deadline(id));
        Vm.Log[] memory logs = _handle(_finalizeOp(id));
        SettledEvent memory e = _settled(logs);
        assertEq(e.received, uint256(raised) * 1 gwei, "the raised payout");
        assertEq(e.owedPaid, debt);
        assertEq(payee.balance, e.received - e.charged - debt);

        // a raise that leaves too little: refused, finalized directly, swept
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory op,) = _escapeOp(id2, 3001, 3002, PAYOUT, CONCEDED);
        _handle(op);
        uint256 debt2 = paymaster.owed(s);
        assertGt(debt2, 0);
        uint128 bigRaise = PAYOUT + CONCEDED - 1_000_000;
        request = _evidence(3001, bigRaise);
        vm.prank(challenger);
        vault.raiseEscapeConcession(id2, request, PROOF, bigRaise);
        assertEq(_pendingFinalBalance(id2), 1_000_000);
        vm.warp(_deadline(id2));
        _refused(_finalizeOp(id2), ZkApiWithdrawalPaymaster.PayoutBelowCost.selector);
        vault.finalizeEscapeWithdrawal(id2);
        assertEq(s.balance, 1_000_000 gwei);
        uint256 payeeBefore = payee.balance;
        ZkApiWithdrawalAccount(payable(s)).sweep();
        assertEq(
            paymaster.owed(s), debt2 - 1_000_000 gwei < debt2 ? debt2 - 1_000_000 gwei : 0, "the sweep repays first"
        );
        assertEq(payee.balance, payeeBefore, "nothing left for the payee");
    }

    function test_defeatedEscapeKeepsTheDebtUntilTheNextClose() public {
        uint32 id = _bigNote(42);
        (address s,,) = _sponsoredEscape(id);
        uint256 debt = paymaster.owed(s);
        Types.RequestPublicInputs memory request = _evidence(2002, 100_000);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        assertEq(paymaster.owed(s), debt, "the debt persists");
        assertTrue(paymaster.escapeSponsored(id), "one sponsored initiation per note, ever");
        (PackedUserOperation memory again,) = _escapeOp(id, 2003, 2004, PAYOUT, CONCEDED);
        _refused(again, ZkApiWithdrawalPaymaster.EscapeAlreadySponsored.selector);
        // the user's next close from S pays the debt first
        (PackedUserOperation memory close,) = _closeOp(id, 2003, BIG - 1_000_000);
        Vm.Log[] memory logs = _handle(close);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.kind, CLOSE);
        assertEq(e.owedPaid, debt);
        assertEq(paymaster.owed(s), 0);
        assertEq(payee.balance, e.received - e.charged - debt);
    }

    function test_thirdPartyFinalizationThenForward() public {
        uint32 id = _bigNote(42);
        (address s,,) = _sponsoredEscape(id);
        uint256 debt = paymaster.owed(s);
        vm.warp(_deadline(id));
        vm.prank(user);
        vault.finalizeEscapeWithdrawal(id);
        assertEq(s.balance, uint256(PAYOUT) * 1 gwei, "the payout sits in S");
        assertFalse(paymaster.stranded(s), "no paymaster-recorded failure");
        // the closed note of S's sponsored escape is the evidence
        PackedUserOperation memory forward = _forwardOp();
        Vm.Log[] memory logs = _handle(forward);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.kind, FORWARD);
        assertEq(e.noteId, id, "the forward names the escape's note");
        assertEq(e.received, uint256(PAYOUT) * 1 gwei);
        assertEq(e.owedPaid, debt);
        assertEq(payee.balance, e.received - e.charged - debt);
        assertEq(paymaster.owed(s), 0);
        assertEq(paymaster.escapeNotePlusOne(s), 0, "evidence consumed");
        assertEq(s.balance, 0);
        // the evidence is gone
        vm.deal(s, 0.05 ether);
        _refused(_forwardOp(), ZkApiWithdrawalPaymaster.NotStranded.selector);
    }

    // ------------------------------------------------ one open sponsored escape per account

    /// A second sponsored escape from S while the first is pending, or closed by a third party with
    /// its payout in S, would overwrite the FORWARD evidence: refused, uncounted, until the first
    /// one settles (here through FORWARD); then the record is replaced.
    function test_secondSponsoredEscapeWaitsForTheFirstToSettle() public {
        uint32 idA = _bigNote(42);
        (address s,,) = _sponsoredEscape(idA);
        uint32 idB = _bigNote(43);
        (PackedUserOperation memory second,) = _escapeOp(idB, 3001, 3002, PAYOUT, CONCEDED);
        bytes memory inner = _refused(second, ZkApiWithdrawalPaymaster.EscapeEvidencePending.selector);
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.EscapeEvidencePending.selector, idA));
        assertEq(paymaster.attempts(_escapeKey(idB)), 0, "uncounted");
        (,,,,, bool escapeOpen) = paymaster.quote(ESCAPE, s, idB, 0, 0, 0);
        assertFalse(escapeOpen, "the quote says so");
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idA) + 1, "the record stands");
        // a third party finalizes the first: the payout sits in S, the record is the evidence
        vm.warp(_deadline(idA));
        vm.prank(user);
        vault.finalizeEscapeWithdrawal(idA);
        assertEq(uint256(_status(idA)), uint256(Types.NoteStatus.Closed));
        assertEq(s.balance, uint256(PAYOUT) * 1 gwei);
        (second,) = _escapeOp(idB, 3001, 3002, PAYOUT, CONCEDED);
        inner = _refused(second, ZkApiWithdrawalPaymaster.EscapeEvidencePending.selector);
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.EscapeEvidencePending.selector, idA));
        // FORWARD settles it and consumes the record; the second escape is sponsored and recorded
        Vm.Log[] memory logs = _handle(_forwardOp());
        assertEq(_settled(logs).noteId, idA);
        assertEq(paymaster.escapeNotePlusOne(s), 0);
        assertEq(s.balance, 0);
        (second,) = _escapeOp(idB, 3001, 3002, PAYOUT, CONCEDED);
        (,,,,, escapeOpen) = paymaster.quote(ESCAPE, s, idB, 0, 0, 0);
        assertTrue(escapeOpen);
        logs = _handle(second);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success, "sponsored once the first escape settled");
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idB) + 1, "the record names the second escape");
        assertEq(paymaster.attempts(_escapeKey(idB)), 1);
    }

    /// The first escape closed by a third party and swept (S empty): nothing is left to forward, so
    /// the record is stale and the second escape replaces it.
    function test_secondSponsoredEscapeAllowedOnceTheFirstPayoutIsSwept() public {
        uint32 idA = _bigNote(42);
        (address s,,) = _sponsoredEscape(idA);
        vm.warp(_deadline(idA));
        vm.prank(user);
        vault.finalizeEscapeWithdrawal(idA);
        ZkApiWithdrawalAccount(payable(s)).sweep();
        assertEq(s.balance, 0);
        assertEq(paymaster.owed(s), 0, "the sweep settled the debt");
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idA) + 1, "the stale record");
        uint32 idB = _bigNote(43);
        (PackedUserOperation memory second,) = _escapeOp(idB, 3001, 3002, PAYOUT, CONCEDED);
        Vm.Log[] memory logs = _handle(second);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idB) + 1, "replaced");
    }

    /// The first escape defeated (the note active again): the record is stale and a second escape
    /// of another note replaces it.
    function test_secondSponsoredEscapeAllowedAfterADefeat() public {
        uint32 idA = _bigNote(42);
        (address s,,) = _sponsoredEscape(idA);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(idA, _evidence(2002, 100_000), PROOF);
        assertEq(uint256(_status(idA)), uint256(Types.NoteStatus.Active));
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idA) + 1);
        uint32 idB = _bigNote(43);
        (PackedUserOperation memory second,) = _escapeOp(idB, 3001, 3002, PAYOUT, CONCEDED);
        (,,,,, bool escapeOpen) = paymaster.quote(ESCAPE, s, idB, 0, 0, 0);
        assertTrue(escapeOpen);
        Vm.Log[] memory logs = _handle(second);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success, "sponsored after the defeat");
        assertEq(paymaster.escapeNotePlusOne(s), uint256(idB) + 1, "replaced");
        assertGt(paymaster.owed(s), 0, "both initiations are owed");
    }

    /// A sponsored CLOSE of the recorded note (after its escape was defeated) settles the note and
    /// clears the record, like a sponsored FINALIZE of it does.
    function test_sponsoredCloseOfTheRecordedNoteClearsTheRecord() public {
        uint32 id = _bigNote(42);
        (address s,,) = _sponsoredEscape(id);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, _evidence(2002, 100_000), PROOF);
        assertEq(paymaster.escapeNotePlusOne(s), uint256(id) + 1);
        (PackedUserOperation memory close,) = _closeOp(id, 2003, BIG - 1_000_000);
        Vm.Log[] memory logs = _handle(close);
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success);
        assertEq(_settled(logs).noteId, id);
        assertEq(paymaster.escapeNotePlusOne(s), 0, "cleared");
        assertEq(paymaster.owed(s), 0, "the debt was paid out of the close");
        // and a later sponsored escape of another note is open
        uint32 idB = _bigNote(43);
        (,,,,, bool escapeOpen) = paymaster.quote(ESCAPE, s, idB, 0, 0, 0);
        assertTrue(escapeOpen);
    }

    function test_writeOffDebt() public {
        uint32 id = _bigNote(42);
        (address s,,) = _sponsoredEscape(id);
        uint256 debt = paymaster.owed(s);
        vm.prank(user);
        vm.expectRevert();
        paymaster.writeOffDebt(s);
        vm.recordLogs();
        paymaster.writeOffDebt(s);
        (bool found, Vm.Log memory log) =
            _find(vm.getRecordedLogs(), address(paymaster), ZkApiWithdrawalPaymaster.DebtWrittenOff.selector);
        assertTrue(found);
        assertEq(abi.decode(log.data, (uint256)), debt);
        assertEq(paymaster.owed(s), 0);
        // a later finalization settles without a deduction
        vm.warp(_deadline(id));
        Vm.Log[] memory logs = _handle(_finalizeOp(id));
        SettledEvent memory e = _settled(logs);
        assertEq(e.owedPaid, 0);
    }

    function test_quoteForAnEscape() public {
        address s = factory.createAccount(ownerAddr, payee);
        OpGas memory g = _gas(ESCAPE, false);
        (
            uint256 requiredWei,
            uint256 owedWei,
            uint256 flatFeeWei,
            uint256 reserveWei,
            bool attemptsLeft,
            bool escapeOpen
        ) = paymaster.quote(ESCAPE, s, 0, 0, _maxCost(g), g.maxFee);
        assertEq(owedWei, 0);
        assertEq(flatFeeWei, FLAT_FEE);
        assertEq(reserveWei, gp.finalizeReserveGas * g.maxFee);
        assertEq(requiredWei, _maxCost(g) + 2 * FLAT_FEE + reserveWei + MIN_ESCAPE_NET);
        assertTrue(attemptsLeft);
        assertTrue(escapeOpen);
        uint32 id = _bigNote(42);
        _sponsoredEscape(id);
        (requiredWei, owedWei,,, attemptsLeft, escapeOpen) = paymaster.quote(CLOSE, s, id, 9, _maxCost(g), g.maxFee);
        assertEq(owedWei, paymaster.owed(s));
        assertEq(requiredWei, _maxCost(g) + FLAT_FEE + owedWei);
        assertTrue(attemptsLeft);
        assertFalse(escapeOpen, "the note's escape was sponsored");
        (,,,, attemptsLeft,) = paymaster.quote(ESCAPE, s, id, 0, 0, 0);
        assertTrue(attemptsLeft, "one of three attempts used");
        vm.expectRevert(ZkApiWithdrawalPaymaster.InvalidKind.selector);
        paymaster.quote(9, s, id, 0, 0, 0);
    }
}
