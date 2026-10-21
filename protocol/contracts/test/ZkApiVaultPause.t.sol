// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {ToggleableDestination} from "./NativeEthVault.t.sol";
import {AcceptAllProofs} from "./mocks/MockProofAdapters.sol";

contract RejectingTreasury {
    receive() external payable {
        revert();
    }
}

contract GasBurningTreasury {
    receive() external payable {
        while (true) {}
    }
}

/// Accepts payments with about 45k gas, well inside TREASURY_PAYOUT_GAS and ESCAPE_PAYOUT_GAS.
contract CostlyTreasury {
    uint256 public payments;
    mapping(uint256 => uint256) private receipts;

    receive() external payable {
        receipts[++payments] = msg.value;
    }
}

/// @dev Pause, expiry, treasury-timelock and guard-coverage regressions. Escapes from the state at
///      nullifier n name the successor n + SUCCESSOR; a defeat carries a request at the successor.
contract ZkApiVaultPauseTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant UNITS = 1_000_000;
    uint256 constant SUCCESSOR = 1_000_000;
    uint64 constant MAX_PAUSE = 7 days;
    /// TREASURY_PAYOUT_GAS and ESCAPE_PAYOUT_GAS as the docs state them. Pinned here rather than
    /// read from the vault, so that raising a cap fails the gas-burning payee bounds.
    uint256 constant DOCUMENTED_PAYOUT_GAS = 100_000;
    address user = address(0x1234);
    address treasury = address(0x5678);
    ZkApiVault vault;
    uint256[32] emptySiblings;

    function setUp() public {
        vm.warp(1_700_000_000);
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.compress(DOMAIN_NODE, zero, zero);
        }
        vault = new ZkApiVault(
            treasury,
            30 days,
            24 hours,
            100_000,
            address(new AcceptAllProofs()),
            11,
            12,
            13,
            14,
            address(this),
            MAX_PAUSE
        );
        vm.deal(user, 100 ether);
    }

    // ---------------------------------------------------------------- expiry

    function test_claimExpiredRevertsWhilePaused() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(expiry);
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(id);
        vm.warp(expiry + 7 days);
        vault.unpause();
        // The note had already expired when the pause began, but nobody could claim it
        // while users were locked out, and its owner gets the unpause grace to exit.
        uint256 claimAt = expiry + 7 days + vault.unpauseClaimGrace();
        assertEq(vault.effectiveExpiry(id), claimAt);
        vm.warp(claimAt - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(claimAt);
        vault.claimExpired(id);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
    }

    function test_pauseExtendsExpiryAndKeepsExitsAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        Types.WithdrawalPublicInputs memory close = _withdrawal(id, 99, true);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 98, false);
        vm.warp(expiry - 1 days);
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.mutualClose(close, "");
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "");
        vm.warp(expiry + 30 days);
        vault.unpause();
        // One day remained when the pause began; one day remains after it.
        assertEq(vault.effectiveExpiry(id), expiry + 31 days);

        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(escape, "");
        vm.revertToState(snapshot);
        vault.mutualClose(close, "");
        assertEq(user.balance, 100 ether - uint256(UNITS) * 1 gwei + 700_000 gwei);
        vm.revertToState(snapshot);

        vm.warp(expiry + 31 days - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(expiry + 31 days);
        vault.claimExpired(id);
    }

    function test_repeatedPausesAccumulateOnlyAfterDeposit() public {
        uint32 first = _deposit(42);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 3 days);
        vault.unpause();
        vm.warp(vm.getBlockTimestamp() + vault.PAUSE_COOLDOWN());
        uint32 second = _deposit(43);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 5 days);
        vault.unpause();
        vm.warp(vm.getBlockTimestamp() + vault.PAUSE_COOLDOWN());
        vault.pause();
        vault.unpause(); // zero-length pause
        (,, uint64 firstExpiry,) = vault.notes(first);
        (,, uint64 secondExpiry,) = vault.notes(second);
        assertEq(vault.totalPausedDuration(), 8 days);
        assertEq(vault.effectiveExpiry(first), firstExpiry + 8 days);
        assertEq(vault.effectiveExpiry(second), secondExpiry + 5 days);
    }

    function test_effectiveExpiryProjectsWhilePaused() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        assertEq(vault.effectiveExpiry(id), expiry);
        assertEq(vault.effectiveExpiry(7), 0);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 2 days);
        assertEq(vault.effectiveExpiry(id), expiry + 2 days);
        vm.warp(vm.getBlockTimestamp() + 3 days);
        assertEq(vault.effectiveExpiry(id), expiry + 5 days);
    }

    function testFuzz_effectiveExpiryMatchesPauseModel(uint32[6] memory gaps, uint8 depositAfter) public {
        (uint32 id, uint256 shiftedExpiry) = _depositAmidPauses(gaps, depositAfter);
        // Expiry moves by the pause time since the deposit, and never lands inside the
        // grace that follows the latest unpause (which just happened).
        assertEq(vault.lastUnpausedAt(), vm.getBlockTimestamp());
        uint256 claimAt = shiftedExpiry;
        uint256 graceEnd = vm.getBlockTimestamp() + vault.unpauseClaimGrace();
        if (graceEnd > claimAt) claimAt = graceEnd;
        _assertClaimableExactlyAt(id, claimAt);
    }

    /// With pauses before and after the deposit, a challenge before, near or after the
    /// pause-shifted expiry leaves the note claimable at the latest of that expiry, challengePeriod
    /// after the challenge, and unpauseClaimGrace after the latest unpause: the grace never
    /// lowers the expiry and is never lost to the paused time folded into the note's expiry.
    function testFuzz_challengeGraceMatchesPauseModel(
        uint32[6] memory gaps,
        uint8 depositAfter,
        uint32 challengeLead,
        uint32 escapeAge
    ) public {
        (uint32 id, uint256 shiftedExpiry) = _depositAmidPauses(gaps, depositAfter);
        uint256 period = vault.challengePeriod();
        // Challenge up to 2 periods before the shifted expiry, or up to a period after it.
        uint256 challengedAt = shiftedExpiry + period - (challengeLead % (3 * period));
        if (challengedAt <= vm.getBlockTimestamp()) challengedAt = vm.getBlockTimestamp() + 1;
        uint256 initiatedAt = challengedAt - (escapeAge % period);
        if (initiatedAt < vm.getBlockTimestamp()) initiatedAt = vm.getBlockTimestamp();
        vm.warp(initiatedAt);
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "");
        vm.warp(challengedAt);
        vault.challengeEscapeWithdrawal(id, _request(101 + SUCCESSOR), "");

        uint256 claimAt = shiftedExpiry;
        if (challengedAt + period > claimAt) claimAt = challengedAt + period;
        uint256 unpauseGraceEnd = vault.lastUnpausedAt() + vault.unpauseClaimGrace();
        if (unpauseGraceEnd > claimAt) claimAt = unpauseGraceEnd;
        _assertClaimableExactlyAt(id, claimAt);
    }

    function test_inFlightEscapeResolvesWhilePaused() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        Types.RequestPublicInputs memory request = _request(101 + SUCCESSOR);
        vault.initiateEscapeWithdrawal(escape, "");
        vault.pause();

        uint256 snapshot = vm.snapshotState();
        vault.challengeEscapeWithdrawal(id, request, "");
        (,,, Types.NoteStatus status) = vault.notes(id);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        assertFalse(vault.usedNullifiers(101));
        vm.revertToState(snapshot);

        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        uint256 before = user.balance;
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance - before, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
    }

    function test_challengeDuringPauseGrantsGraceAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        Types.RequestPublicInputs memory request = _request(101 + SUCCESSOR);
        vm.warp(expiry - 1 hours);
        vault.initiateEscapeWithdrawal(escape, "");
        vm.warp(expiry + 1 hours);
        vault.pause();
        vault.challengeEscapeWithdrawal(id, request, "");
        vm.warp(vm.getBlockTimestamp() + 10 days);
        vault.unpause();
        uint256 graceEnd = vm.getBlockTimestamp() + vault.challengePeriod();
        assertEq(vault.effectiveExpiry(id), graceEnd);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(graceEnd);
        vault.claimExpired(id);
    }

    /// A challenge after a completed pause longer than challengePeriod still grants exactly
    /// challengePeriod of unpaused time. The challenge comes an hour after the unpause, so the
    /// grace ends an hour after the unpause claim grace and the latter cannot hide it.
    function test_challengeSoonAfterCompletedPauseGetsExactGrace() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(expiry - 2 hours);
        vault.pause();
        vm.warp(expiry + 10 days);
        vault.unpause();
        // Two hours of note time remain; escape with one of them left and challenge an hour
        // after the unpause, well before the challenge deadline.
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "");
        _challengeAndAssertExactGrace(id);
    }

    /// The same when the challenge falls weeks after lastUnpausedAt + unpauseClaimGrace, where
    /// only the paused time folded into the active clock separates the grace end from the
    /// challenge time.
    function test_challengeLongAfterCompletedPauseGetsExactGrace() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(vm.getBlockTimestamp() + 1 days);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 10 days);
        vault.unpause();
        // Paused time moved expiry by 10 days; escape an hour before that and challenge at the
        // last moment of the challenge window, after the shifted expiry.
        vm.warp(uint256(expiry) + 10 days - 1 hours);
        assertGt(vm.getBlockTimestamp(), vault.lastUnpausedAt() + vault.unpauseClaimGrace() + 20 days);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        vault.initiateEscapeWithdrawal(escape, "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline - 1);
        _challengeAndAssertExactGrace(id);
    }

    /// A note deposited after a completed pause longer than challengePeriod keeps its expiry on
    /// the active clock, already shifted back by that pause. The grace guard must compare the
    /// grace end with that shifted expiry, not the wall-clock expiryTs: challenged an hour before
    /// its wall-clock expiry, the note still gets the full challengePeriod.
    function test_challengeOnNoteDepositedAfterPauseGetsExactGrace() public {
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 10 days);
        vault.unpause();
        vm.warp(vm.getBlockTimestamp() + 2 days);
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        assertEq(vault.effectiveExpiry(id), expiry);
        vm.warp(uint256(expiry) - 2 hours);
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "");
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        // The pause precedes the deposit, so the grace must exceed expiryTs, not just the
        // active-clock expiry (expiryTs - 10 days) that the guard compares against.
        assertGt(vm.getBlockTimestamp() + vault.challengePeriod(), uint256(expiry));
        _challengeAndAssertExactGrace(id);
    }

    /// Challenges the pending escape of `id` (nullifier 101) at the current time and checks that
    /// the note becomes claimable exactly challengePeriod later, not a second earlier.
    function _challengeAndAssertExactGrace(uint32 id) private {
        Types.RequestPublicInputs memory request = _request(101 + SUCCESSOR);
        uint256 challengedAt = vm.getBlockTimestamp();
        vault.challengeEscapeWithdrawal(id, request, "");
        uint256 graceEnd = challengedAt + vault.challengePeriod();
        assertGt(graceEnd, vault.lastUnpausedAt() + vault.unpauseClaimGrace());
        assertEq(vault.effectiveExpiry(id), graceEnd);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(graceEnd);
        vault.claimExpired(id);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
    }

    function test_pauseJustBeforeExpiryLeavesClaimGraceAfterUnpause() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 98, false);
        vm.warp(expiry - 1);
        vault.pause();
        uint256 unpausedAt = uint256(expiry) - 1 + 5 days;
        vm.warp(unpausedAt);
        vault.unpause();
        // One second of note time was left, but every unpause restores the full grace.
        uint256 claimAt = unpausedAt + vault.unpauseClaimGrace();
        assertEq(vault.lastUnpausedAt(), unpausedAt);
        assertEq(vault.effectiveExpiry(id), claimAt);
        vm.warp(claimAt - 1);
        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(escape, "");
        vm.revertToState(snapshot);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(claimAt);
        vault.claimExpired(id);
        assertEq(treasury.balance, uint256(UNITS) * 1 gwei);
    }

    /// A malicious owner front-runs an exit attempt with a short pause. It cannot do so again
    /// within PAUSE_COOLDOWN of the unpause, so the user's retry goes through; and each unpause
    /// restarts the claim grace, so the pause costs the note no time.
    function test_pauseCooldownLetsTheNextExitThrough() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        uint256 time = uint256(expiry) - 1 hours;
        vm.warp(time);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 99, false);
        vault.pause(); // mined just before the user's transaction
        vm.prank(user);
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "");
        time += 12;
        vm.warp(time);
        vault.unpause();
        assertEq(vault.effectiveExpiry(id), time + vault.unpauseClaimGrace());
        // The owner tries again just before the retry, and up to the last second of the cooldown.
        vm.expectRevert(Errors.PauseCooldown.selector);
        vault.pause();
        vm.warp(time + vault.PAUSE_COOLDOWN() - 1);
        vm.expectRevert(Errors.PauseCooldown.selector);
        vault.pause();
        vm.warp(time + 6);
        escape = _withdrawal(id, 99, false);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(escape, "");
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - uint256(UNITS) * 1 gwei + 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
    }

    function test_pauseCooldownStartsAtEachUnpause() public {
        vm.expectEmit(address(vault));
        emit Events.Paused(address(this));
        vault.pause(); // the first pause needs no cooldown
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vault.unpause();
        uint256 unpausedAt = vm.getBlockTimestamp();
        vm.warp(unpausedAt + vault.PAUSE_COOLDOWN() - 1);
        vm.expectRevert(Errors.PauseCooldown.selector);
        vault.pause();
        vm.warp(unpausedAt + vault.PAUSE_COOLDOWN());
        vault.pause();
        assertTrue(vault.paused());
        // A long pause does not shorten the next cooldown.
        vm.warp(vm.getBlockTimestamp() + 30 days);
        vault.unpause();
        vm.expectRevert(Errors.PauseCooldown.selector);
        vault.pause();
    }

    /// A pause blocks escapes and closes for at most maxPauseDuration, even if never lifted;
    /// deposits and expiry sweeps stay blocked for as long as it lasts, so nothing is seized.
    function test_boundedPauseReopensExitsButNeverSweeps() public {
        uint32 escaping = _deposit(42);
        uint32 closing = _deposit(43);
        uint32 idle = _deposit(44);
        address lost = address(0xdead);
        vault.pause();
        uint256 pausedAt = vm.getBlockTimestamp();
        vault.transferOwnership(lost);
        vm.prank(lost);
        vault.acceptOwnership();

        vm.warp(pausedAt + MAX_PAUSE - 1);
        Types.WithdrawalPublicInputs memory escape = _withdrawal(escaping, 101, false);
        Types.WithdrawalPublicInputs memory close = _withdrawal(closing, 99, true);
        vm.expectRevert(Errors.Paused.selector);
        vault.initiateEscapeWithdrawal(escape, "");
        vm.expectRevert(Errors.Paused.selector);
        vault.mutualClose(close, "");

        vm.warp(pausedAt + MAX_PAUSE);
        assertTrue(vault.paused());
        vault.initiateEscapeWithdrawal(escape, "");
        vault.mutualClose(close, "");
        vm.prank(user);
        vm.expectRevert(Errors.Paused.selector);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(bytes32(uint256(45)), UNITS);

        // The escape finalizes while still paused; the sweep never opens.
        vm.warp(_deadline(escaping));
        vault.finalizeEscapeWithdrawal(escaping);
        assertEq(user.balance, 100 ether - 3 * uint256(UNITS) * 1 gwei + 1_400_000 gwei);
        vm.warp(vm.getBlockTimestamp() + 3650 days);
        vm.expectRevert(Errors.Paused.selector);
        vault.claimExpired(idle);
        assertEq(treasury.balance, 600_000 gwei);
    }

    /// Defeats, raises, finalizations, payout claims and leaf retirements all work while paused.
    function test_exitResolutionStaysOpenWhilePaused() public {
        uint32 defeated = _deposit(42);
        uint32 raised = _deposit(43);
        uint32 closed = _deposit(44);
        vault.initiateEscapeWithdrawal(_withdrawal(defeated, 101, false), "");
        vault.initiateEscapeWithdrawal(_withdrawal(raised, 201, false), "");
        vault.mutualClose(_withdrawal(closed, 301, true), "");
        vault.pause();
        vault.challengeEscapeWithdrawal(defeated, _request(101 + SUCCESSOR), "");
        assertEq(uint256(_status(defeated)), uint256(Types.NoteStatus.Active));
        vault.raiseEscapeConcession(raised, _request(201), "", 50_000);
        (,, uint128 conceded) = vault.pendingConcessions(raised);
        assertEq(conceded, 50_000);
        uint256[32] memory path = _path(closed);
        vault.retireClosedLeaf(closed, path);
        vm.warp(_deadline(raised));
        vault.finalizeEscapeWithdrawal(raised);
        assertEq(uint256(_status(raised)), uint256(Types.NoteStatus.Closed));
        assertTrue(vault.paused());
    }

    function test_pauseAndUnpauseEmitAndRejectRedundantCalls() public {
        vm.expectEmit(address(vault));
        emit Events.Paused(address(this));
        vault.pause();
        assertTrue(vault.paused());
        assertEq(vault.pausedAt(), vm.getBlockTimestamp());
        vm.expectRevert(Errors.Paused.selector);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vm.expectEmit(address(vault));
        emit Events.Unpaused(address(this));
        vault.unpause();
        assertEq(vault.totalPausedDuration(), 1 hours);
        assertEq(vault.pausedAt(), 0);
        vm.expectRevert(Errors.NotPaused.selector);
        vault.unpause();
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.pause();
    }

    function test_renounceOwnershipRevertsWhilePaused() public {
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.renounceOwnership();
        vault.unpause();
        vault.renounceOwnership();
        assertEq(vault.owner(), address(0));
    }

    function test_renounceOwnershipClearsPendingOwner() public {
        address rotated = address(0xB0B);
        vault.transferOwnership(rotated);
        vault.renounceOwnership();
        assertEq(vault.owner(), address(0));
        assertEq(vault.pendingOwner(), address(0));
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        assertEq(vault.owner(), address(0));
    }

    /// The exempt owner actions used for incident key rotation still work while paused. The
    /// old key stays in charge until the nominee accepts.
    function test_ownerKeyRotationWorksWhilePaused() public {
        address rotated = address(0xB0B);
        vault.pause();
        vm.expectEmit(address(vault));
        emit Ownable2Step.OwnershipTransferStarted(address(this), rotated);
        vault.transferOwnership(rotated);
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), rotated);
        vm.prank(rotated);
        vm.expectEmit(address(vault));
        emit Ownable.OwnershipTransferred(address(this), rotated);
        vault.acceptOwnership();
        assertEq(vault.owner(), rotated);
        assertEq(vault.pendingOwner(), address(0));
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        vault.unpause();
        vm.prank(rotated);
        vault.unpause();
        assertFalse(vault.paused());
        assertEq(vault.lastUnpausedAt(), vm.getBlockTimestamp());
    }

    /// A mistyped rotation during a pause no longer strands the vault: the old owner can still
    /// unpause and replace the nomination, after which the mistyped address cannot accept.
    function test_mistypedTransferWhilePausedLeavesOwnerInControl() public {
        address mistyped = address(0xdead);
        address rotated = address(0xB0B);
        vault.pause();
        vault.transferOwnership(mistyped);
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), mistyped);
        vault.transferOwnership(rotated);
        assertEq(vault.pendingOwner(), rotated);
        vm.prank(mistyped);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, mistyped));
        vault.acceptOwnership();
        vault.unpause();
        assertFalse(vault.paused());
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), rotated);
    }

    function test_onlyPendingOwnerCanAcceptOwnership() public {
        address rotated = address(0xB0B);
        vault.pause();
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        vault.transferOwnership(rotated);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.acceptOwnership();
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, address(this)));
        vault.acceptOwnership();
        // Nominating the zero address cancels the transfer.
        vault.transferOwnership(address(0));
        vm.prank(rotated);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, rotated));
        vault.acceptOwnership();
        assertEq(vault.owner(), address(this));
        assertEq(vault.pendingOwner(), address(0));
    }

    // -------------------------------------------------------------- treasury

    function test_setTreasuryIsTwoStepAndTimelocked() public {
        address next = address(0xA4513425);
        uint64 readyAt = uint64(vm.getBlockTimestamp()) + vault.treasuryChangeDelay();
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeScheduled(next, readyAt);
        vault.setTreasury(next);
        assertEq(vault.treasury(), treasury);
        assertEq(vault.pendingTreasury(), next);
        assertEq(vault.pendingTreasuryReadyAt(), readyAt);
        vm.warp(readyAt - 1);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        vm.warp(readyAt);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, user));
        vault.acceptTreasury();
        vm.expectEmit(address(vault));
        emit Events.TreasurySet(next);
        vault.acceptTreasury();
        assertEq(vault.treasury(), next);
        assertEq(vault.pendingTreasury(), address(0));
        vm.expectRevert(Errors.NoPendingTreasuryChange.selector);
        vault.acceptTreasury();
        vm.expectRevert(Errors.Unauthorized.selector);
        vault.setTreasury(address(0));
        vm.expectRevert(Errors.Unauthorized.selector);
        vault.setTreasury(address(vault));
    }

    function test_rescheduleRestartsTreasuryTimelock() public {
        vault.setTreasury(address(0xA));
        uint256 firstReady = vault.pendingTreasuryReadyAt();
        vm.warp(firstReady - 1);
        vault.setTreasury(address(0xB));
        vm.warp(firstReady);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
    }

    function test_treasuryChangeBlockedWhilePausedButCancellable() public {
        vault.setTreasury(address(0xA));
        uint256 readyAt = vault.pendingTreasuryReadyAt();
        vault.pause();
        vm.expectRevert(Errors.Paused.selector);
        vault.setTreasury(address(0xB));
        vm.warp(readyAt);
        vm.expectRevert(Errors.Paused.selector);
        vault.acceptTreasury();
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeCancelled(address(0xA));
        vault.cancelTreasuryChange();
        vault.unpause();
        vm.expectRevert(Errors.NoPendingTreasuryChange.selector);
        vault.acceptTreasury();
        assertEq(vault.treasury(), treasury);
    }

    function test_treasuryTimelockCountsOnlyUnpausedTime() public {
        uint256 time = vm.getBlockTimestamp();
        // An earlier pause leaves the active clock 3 days behind the wall clock.
        vault.pause();
        time += 3 days;
        vm.warp(time);
        vault.unpause();
        address next = address(0xA11CE);
        uint256 delay = vault.treasuryChangeDelay();
        uint64 readyAt = uint64(time - 3 days + delay);
        vm.expectEmit(address(vault));
        emit Events.TreasuryChangeScheduled(next, readyAt);
        vault.setTreasury(next);
        assertEq(vault.pendingTreasuryReadyAt(), readyAt);

        // Half the delay passes unpaused; then a long pause carries the wall clock past it.
        time += delay / 2;
        vm.warp(time);
        vault.pause();
        time += 10 * delay;
        vm.warp(time);
        vault.unpause();
        // Users still get the other half of the delay, unpaused, to react.
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        time += delay / 2 - 1;
        vm.warp(time);
        vm.expectRevert(Errors.TreasuryChangeNotReady.selector);
        vault.acceptTreasury();
        vm.warp(time + 1);
        vault.acceptTreasury();
        assertEq(vault.treasury(), next);
    }

    function test_treasuryDelayAndClaimGraceAreAtLeastChallengePeriod() public {
        assertEq(vault.treasuryChangeDelay(), vault.MIN_TREASURY_CHANGE_DELAY());
        assertEq(vault.unpauseClaimGrace(), 1 days);
        ZkApiVault slow = new ZkApiVault(
            treasury, 30 days, 5 days, 100_000, address(new AcceptAllProofs()), 11, 12, 13, 14, address(this), 10 days
        );
        assertEq(slow.treasuryChangeDelay(), 5 days);
        assertEq(slow.unpauseClaimGrace(), 5 days);
        ZkApiVault fast = new ZkApiVault(
            treasury, 30 days, 1 hours, 100_000, address(new AcceptAllProofs()), 11, 12, 13, 14, address(this), 2 hours
        );
        assertEq(fast.treasuryChangeDelay(), 2 days);
        assertEq(fast.unpauseClaimGrace(), 1 days);
    }

    function test_rejectingTreasuryCannotFreezePayouts() public {
        uint32 escaping = _deposit(42);
        uint32 expiring = _deposit(43);
        address rejecting = address(new RejectingTreasury());
        _switchTreasury(rejecting);
        vault.initiateEscapeWithdrawal(_withdrawal(escaping, 101, false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(escaping);
        vm.warp(deadline);
        uint256 before = user.balance;
        vault.finalizeEscapeWithdrawal(escaping);
        assertEq(user.balance - before, 700_000 gwei);
        assertEq(vault.treasuryArrears(), 300_000);
        (,, uint64 expiry,) = vault.notes(expiring);
        vm.warp(expiry);
        vault.claimExpired(expiring);
        assertEq(vault.treasuryArrears(), 300_000 + UNITS);
        assertEq(address(vault).balance, uint256(300_000 + UNITS) * 1 gwei);
        _switchTreasury(treasury);
        vm.expectEmit(address(vault));
        emit Events.TreasuryArrearsPaid(treasury, 300_000 + UNITS);
        vault.withdrawTreasuryArrears();
        assertEq(treasury.balance, uint256(300_000 + UNITS) * 1 gwei);
        assertEq(address(vault).balance, 0);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.withdrawTreasuryArrears();
    }

    /// A treasury that burns all the gas it is given adds at most the documented cap (plus the
    /// arrears bookkeeping) to every payout that pushes to it, however much gas the caller sends.
    function test_gasBurningTreasuryIsBoundedOnMutualClose() public {
        uint32 id = _deposit(42);
        bytes memory close = abi.encodeCall(vault.mutualClose, (_withdrawal(id, 99, true), ""));
        _assertGasBurningTreasuryBounded("mutualClose", close, 300_000);
    }

    /// The same bound on finalizeEscapeWithdrawal, a user's own exit.
    function test_gasBurningTreasuryIsBoundedOnEscapeFinalization() public {
        uint32 id = _deposit(42);
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        bytes memory finalize = abi.encodeCall(vault.finalizeEscapeWithdrawal, (id));
        _assertGasBurningTreasuryBounded("finalizeEscapeWithdrawal", finalize, 300_000);
    }

    /// The same bound on claimExpired.
    function test_gasBurningTreasuryIsBoundedOnExpiryClaim() public {
        uint32 id = _deposit(42);
        vm.warp(vault.effectiveExpiry(id));
        bytes memory claim = abi.encodeCall(vault.claimExpired, (id));
        _assertGasBurningTreasuryBounded("claimExpired", claim, UNITS);
    }

    /// A caller cannot starve a working treasury of gas to push its share into arrears: any
    /// gas limit either pays the treasury or reverts the whole close.
    function test_underfundedGasCannotForceTreasuryDeferral() public {
        uint32 id = _deposit(42);
        CostlyTreasury costly = new CostlyTreasury();
        _switchTreasury(address(costly));
        bytes memory close = abi.encodeCall(vault.mutualClose, (_withdrawal(id, 99, true), ""));
        uint256 snapshot = vm.snapshotState();
        uint256 gasBefore = gasleft();
        (bool ok,) = address(vault).call(close);
        uint256 used = gasBefore - gasleft();
        assertTrue(ok);
        assertEq(costly.payments(), 1);
        vm.revertToState(snapshot);

        uint256 paid;
        uint256 reverted;
        for (uint256 limit = 25_000; limit <= used + 150_000; limit += 2_500) {
            (ok,) = address(vault).call{gas: limit}(close);
            if (ok) {
                ++paid;
                assertEq(costly.payments(), 1);
            } else {
                ++reverted;
                (,,, Types.NoteStatus status) = vault.notes(id);
                assertEq(uint256(status), uint256(Types.NoteStatus.Active));
            }
            assertEq(vault.treasuryArrears(), 0);
            vm.revertToState(snapshot);
        }
        assertGt(paid, 0);
        assertGt(reverted, 0);
    }

    // -------------------------------------------------------- escape payouts

    /// A destination that burns all the gas it is given adds at most ESCAPE_PAYOUT_GAS (plus the
    /// credit bookkeeping) to finalizeEscapeWithdrawal, however much gas the caller sends, and
    /// the treasury share is still paid.
    function test_gasBurningDestinationIsBoundedOnEscapeFinalization() public {
        assertEq(vault.ESCAPE_PAYOUT_GAS(), DOCUMENTED_PAYOUT_GAS, "documented cap");
        uint32 id = _deposit(42);
        address burner = address(new GasBurningTreasury());
        // A funded treasury, so neither run pays a new-account surcharge (the user is funded).
        vm.deal(treasury, 1 ether);
        bytes memory finalize = abi.encodeCall(vault.finalizeEscapeWithdrawal, (id));
        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(_withdrawal(id, 101, false), "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        uint256 baseline = _gasUsed(finalize, 30_000_000);
        assertEq(vault.escapePayoutCredits(user), 0, "baseline pays the destination");
        vm.revertToState(snapshot);

        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        escape.destination = burner;
        vault.initiateEscapeWithdrawal(escape, "");
        vm.warp(deadline);
        // 1M gas of headroom, 63/64 of which an uncapped push would burn.
        uint256 used = _gasUsed(finalize, baseline + 1_000_000);
        emit log_named_uint("finalizeEscapeWithdrawal gas with a normal destination", baseline);
        emit log_named_uint("finalizeEscapeWithdrawal gas with a gas-burning destination", used);
        assertEq(vault.escapePayoutCredits(burner), 700_000, "payout credited");
        assertEq(treasury.balance, 1 ether + 300_000 gwei, "treasury paid");
        assertEq(vault.treasuryArrears(), 0);
        // Beyond the gas it forwards, a failed push only records the credit (one SSTORE, at most
        // 22,100) and emits EscapePayoutDeferred.
        assertLt(used, baseline + DOCUMENTED_PAYOUT_GAS + 30_000);
    }

    /// A caller cannot starve a destination that accepts within ESCAPE_PAYOUT_GAS to turn its
    /// payout into a credit: any gas limit either pays it or reverts the whole finalization.
    function test_underfundedGasCannotForceEscapePayoutCredit() public {
        uint32 id = _deposit(42);
        // A funded treasury keeps the rest of the call cheap, so a starved push would leave
        // enough gas to finish if the vault kept any for the credit.
        vm.deal(treasury, 1 ether);
        CostlyTreasury costly = new CostlyTreasury();
        Types.WithdrawalPublicInputs memory escape = _withdrawal(id, 101, false);
        escape.destination = address(costly);
        vault.initiateEscapeWithdrawal(escape, "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(id);
        vm.warp(deadline);
        bytes memory finalize = abi.encodeCall(vault.finalizeEscapeWithdrawal, (id));
        uint256 snapshot = vm.snapshotState();
        uint256 used = _gasUsed(finalize, 30_000_000);
        assertEq(costly.payments(), 1);
        vm.revertToState(snapshot);

        uint256 paid;
        uint256 reverted;
        for (uint256 limit = 25_000; limit <= used + 50_000; limit += 1_000) {
            (bool ok,) = address(vault).call{gas: limit}(finalize);
            if (ok) {
                ++paid;
                assertEq(costly.payments(), 1);
            } else {
                ++reverted;
                (,,, Types.NoteStatus status) = vault.notes(id);
                assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
            }
            assertEq(vault.escapePayoutCredits(address(costly)), 0);
            vm.revertToState(snapshot);
        }
        assertGt(paid, 0);
        assertGt(reverted, 0);
    }

    /// Credited escape payouts accumulate per destination and stay claimable while paused, like
    /// the escapes they complete.
    function test_claimEscapePayoutWorksWhilePaused() public {
        uint32 first = _deposit(42);
        uint32 second = _deposit(43);
        ToggleableDestination recipient = new ToggleableDestination();
        Types.WithdrawalPublicInputs memory escape = _withdrawal(first, 101, false);
        escape.destination = address(recipient);
        vault.initiateEscapeWithdrawal(escape, "");
        escape = _withdrawal(second, 102, false);
        escape.destination = address(recipient);
        vault.initiateEscapeWithdrawal(escape, "");
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(second);
        vm.warp(deadline);
        vault.pause();
        vault.finalizeEscapeWithdrawal(first);
        vault.finalizeEscapeWithdrawal(second);
        assertEq(vault.escapePayoutCredits(address(recipient)), 1_400_000);
        assertEq(treasury.balance, 600_000 gwei);

        vm.expectRevert(Errors.NativeTransferFailed.selector);
        vault.claimEscapePayout(address(recipient));
        recipient.setAccepting(true);
        vm.prank(user);
        vault.claimEscapePayout(address(recipient));
        assertTrue(vault.paused());
        assertEq(address(recipient).balance, 1_400_000 gwei);
        assertEq(vault.escapePayoutCredits(address(recipient)), 0);
        assertEq(address(vault).balance, 0);
    }

    // -------------------------------------------------------- guard coverage

    /// Every state-changing external function must be classified. Guarded ones revert Paused()
    /// for the whole pause; bounded ones (the exits) revert Paused() until pausedAt +
    /// maxPauseDuration and not after; exempt ones (in-flight escape resolution, credited payout
    /// claims, leaf retirement and owner-recovery actions) stay open.
    function test_pauseGuardCoverage() public {
        string[7] memory guarded = [
            "deposit",
            "claimExpired",
            "setTreasury",
            "acceptTreasury",
            "withdrawTreasuryArrears",
            "renounceOwnership",
            "pause"
        ];
        string[2] memory bounded = ["initiateEscapeWithdrawal", "mutualClose"];
        string[9] memory exempt = [
            "challengeEscapeWithdrawal",
            "raiseEscapeConcession",
            "finalizeEscapeWithdrawal",
            "claimEscapePayout",
            "retireClosedLeaf",
            "unpause",
            "cancelTreasuryChange",
            "transferOwnership",
            "acceptOwnership"
        ];
        string memory artifact = vm.readFile(string.concat(vm.projectRoot(), "/out/ZkApiVault.sol/ZkApiVault.json"));
        uint256 mutating;
        for (uint256 i = 0;; ++i) {
            string memory entry = string.concat(".abi[", vm.toString(i), "]");
            if (!vm.keyExistsJson(artifact, entry)) break;
            if (!_eq(vm.parseJsonString(artifact, string.concat(entry, ".type")), "function")) continue;
            string memory mutability = vm.parseJsonString(artifact, string.concat(entry, ".stateMutability"));
            if (_eq(mutability, "view") || _eq(mutability, "pure")) continue;
            string memory name = vm.parseJsonString(artifact, string.concat(entry, ".name"));
            uint256 matches;
            for (uint256 j = 0; j < guarded.length; ++j) {
                if (_eq(name, guarded[j])) ++matches;
            }
            for (uint256 j = 0; j < bounded.length; ++j) {
                if (_eq(name, bounded[j])) ++matches;
            }
            for (uint256 j = 0; j < exempt.length; ++j) {
                if (_eq(name, exempt[j])) ++matches;
            }
            assertEq(matches, 1, string.concat("unclassified or duplicated pause policy: ", name));
            ++mutating;
        }
        assertEq(mutating, guarded.length + bounded.length + exempt.length, "stale pause classification");

        // pause()'s NatSpec is the list operator docs quote; it must match the guards. Its three
        // parts: blocked until unpause, blocked for at most maxPauseDuration, open.
        string memory notice = vm.parseJsonString(artifact, ".metadata.output.userdoc.methods['pause()'].notice");
        string[] memory parts = vm.split(notice, "Blocks for at most maxPauseDuration:");
        assertEq(parts.length, 2, "pause() notice must name the bounded functions");
        string[] memory rest = vm.split(parts[1], "Stay open while paused:");
        assertEq(rest.length, 2, "pause() notice must split blocked from open functions");
        string[3] memory sections = [parts[0], rest[0], rest[1]];
        for (uint256 j = 0; j < guarded.length; ++j) {
            if (_eq(guarded[j], "pause")) continue;
            _assertOnlyIn(sections, 0, guarded[j]);
        }
        for (uint256 j = 0; j < bounded.length; ++j) {
            _assertOnlyIn(sections, 1, bounded[j]);
        }
        for (uint256 j = 0; j < exempt.length; ++j) {
            if (_eq(exempt[j], "unpause")) continue;
            _assertOnlyIn(sections, 2, exempt[j]);
        }

        vault.pause();
        string[] memory signatures = vm.parseJsonKeys(artifact, ".methodIdentifiers");
        uint256 checked;
        for (uint256 i = 0; i < signatures.length; ++i) {
            string memory name = _name(signatures[i]);
            bool isGuarded;
            for (uint256 j = 0; j < guarded.length; ++j) {
                if (_eq(name, guarded[j])) isGuarded = true;
            }
            for (uint256 j = 0; j < bounded.length; ++j) {
                if (_eq(name, bounded[j])) isGuarded = true;
            }
            if (!isGuarded) continue;
            assertEq(_pausedRevert(signatures[i]), Errors.Paused.selector, signatures[i]);
            ++checked;
        }
        assertEq(checked, guarded.length + bounded.length);

        // At pausedAt + maxPauseDuration the bounded functions pass the guard (and fail later on
        // the zero arguments), while the guarded ones still revert Paused().
        vm.warp(vault.pausedAt() + vault.maxPauseDuration());
        for (uint256 i = 0; i < signatures.length; ++i) {
            string memory name = _name(signatures[i]);
            bool isBounded;
            bool isGuarded;
            for (uint256 j = 0; j < bounded.length; ++j) {
                if (_eq(name, bounded[j])) isBounded = true;
            }
            for (uint256 j = 0; j < guarded.length; ++j) {
                if (_eq(name, guarded[j])) isGuarded = true;
            }
            if (isBounded) assertNotEq(_pausedRevert(signatures[i]), Errors.Paused.selector, signatures[i]);
            if (isGuarded) assertEq(_pausedRevert(signatures[i]), Errors.Paused.selector, signatures[i]);
        }
    }

    /// The revert selector of calling `signature` with all-zero arguments (it must revert).
    function _pausedRevert(string memory signature) private returns (bytes4) {
        // Zero calldata decodes for every signature; the guard runs before any argument check.
        (bool success, bytes memory reason) =
            address(vault).call(abi.encodePacked(bytes4(keccak256(bytes(signature))), new bytes(70 * 32)));
        assertFalse(success, signature);
        return bytes4(reason);
    }

    function _assertOnlyIn(string[3] memory sections, uint256 index, string memory name) private pure {
        for (uint256 k = 0; k < 3; ++k) {
            assertEq(vm.contains(sections[k], name), k == index, string.concat("pause() notice: ", name));
        }
    }

    // --------------------------------------------------------------- helpers

    function _deposit(bytes32 commitment) private returns (uint32 id) {
        id = vault.nextNoteId();
        vm.prank(user);
        vault.deposit{value: uint256(UNITS) * 1 gwei}(commitment, UNITS);
    }

    function _deposit(uint256 commitment) private returns (uint32) {
        return _deposit(bytes32(commitment));
    }

    function _status(uint32 id) private view returns (Types.NoteStatus status) {
        (,,, status) = vault.notes(id);
    }

    function _deadline(uint32 id) private view returns (uint64 deadline) {
        (,,,,, deadline) = vault.pendingWithdrawals(id);
    }

    /// Runs three unpaused-gap-then-pause rounds and deposits note `id` before round
    /// `depositAfter % 4` (3: after all of them). Unpaused gaps last from PAUSE_COOLDOWN to beyond
    /// the TTL. Returns the
    /// note's expiryTs moved by the pause time since its deposit; ends right after an unpause.
    function _depositAmidPauses(uint32[6] memory gaps, uint8 depositAfter)
        private
        returns (uint32 id, uint256 shiftedExpiry)
    {
        uint256 deposited = depositAfter % 4;
        uint256 pausedSinceDeposit;
        for (uint256 i = 0; i < 3; ++i) {
            if (i == deposited) id = _deposit(bytes32(uint256(42)));
            // Unpaused gaps of at least PAUSE_COOLDOWN, so every pause is allowed.
            vm.warp(vm.getBlockTimestamp() + 1 days + (gaps[2 * i] % 20 days));
            vault.pause();
            uint256 duration = gaps[2 * i + 1] % 10 days;
            vm.warp(vm.getBlockTimestamp() + duration);
            vault.unpause();
            if (i >= deposited) pausedSinceDeposit += duration;
        }
        if (deposited == 3) id = _deposit(bytes32(uint256(42)));
        (,, uint64 expiry,) = vault.notes(id);
        shiftedExpiry = uint256(expiry) + pausedSinceDeposit;
    }

    /// effectiveExpiry(id) is `claimAt`, and claimExpired fails a second before it and succeeds at it.
    function _assertClaimableExactlyAt(uint32 id, uint256 claimAt) private {
        assertEq(vault.effectiveExpiry(id), claimAt);
        vm.warp(claimAt - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(claimAt);
        vault.claimExpired(id);
    }

    function _switchTreasury(address next) private {
        vault.setTreasury(next);
        vm.warp(vm.getBlockTimestamp() + vault.treasuryChangeDelay());
        vault.acceptTreasury();
    }

    /// Runs `payout` twice from the same state and time: with the funded EOA treasury, which it
    /// must pay, then with a GasBurningTreasury, whose `share` it must defer to arrears. The second
    /// run gets 1M gas of headroom, 63/64 of which an uncapped push would burn. It may use at most
    /// the documented cap plus 30k more than the first: beyond the gas it forwards, a failed push
    /// only records the arrears (one SSTORE, at most 22,100) and emits TreasuryPaymentDeferred.
    function _assertGasBurningTreasuryBounded(string memory label, bytes memory payout, uint128 share) private {
        assertEq(vault.TREASURY_PAYOUT_GAS(), DOCUMENTED_PAYOUT_GAS, "documented cap");
        // A funded treasury, so the baseline push pays no new-account surcharge.
        vm.deal(treasury, 1 ether);
        vault.setTreasury(address(new GasBurningTreasury()));
        vm.warp(vm.getBlockTimestamp() + vault.treasuryChangeDelay());
        uint256 snapshot = vm.snapshotState();
        uint256 baseline = _gasUsed(payout, 30_000_000);
        assertEq(treasury.balance, 1 ether + uint256(share) * 1 gwei, "baseline pays the treasury");
        vm.revertToState(snapshot);

        vault.acceptTreasury();
        uint256 used = _gasUsed(payout, baseline + 1_000_000);
        emit log_named_uint(string.concat(label, " gas with a normal treasury"), baseline);
        emit log_named_uint(string.concat(label, " gas with a gas-burning treasury"), used);
        assertEq(vault.treasuryArrears(), share, "share deferred");
        assertLt(used, baseline + DOCUMENTED_PAYOUT_GAS + 30_000, label);
    }

    function _gasUsed(bytes memory data, uint256 limit) private returns (uint256 used) {
        uint256 gasBefore = gasleft();
        (bool ok,) = address(vault).call{gas: limit}(data);
        used = gasBefore - gasleft();
        assertTrue(ok);
    }

    /// Exits leave leaves in place (no test here retires one), so every deposited note's leaf.
    function _leafAt(uint32 index) private view returns (uint256) {
        if (index >= vault.nextNoteId()) return 0;
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(index);
        return NoteLeafLib.computeLeaf(index, commitment, amount, expiry);
    }

    /// Path for slots 0..3 of a tree whose other leaves are empty.
    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        require(index < 4, "test tree");
        siblings = emptySiblings;
        siblings[0] = _leafAt(index ^ 1);
        uint32 otherPair = (index >> 1) ^ 1;
        siblings[1] = Bn254Poseidon.compress(DOMAIN_NODE, _leafAt(otherPair * 2), _leafAt(otherPair * 2 + 1));
    }

    /// A close (kind 1) or an escape (kind 0, successor nullifier + SUCCESSOR) with a 700,000
    /// payout. Valid for ten years: these tests build statements before long warps.
    function _withdrawal(uint32 id, uint256 nullifier, bool clearance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs(
            2,
            uint64(block.chainid),
            address(vault),
            vault.currentRoot(),
            11,
            12,
            13,
            14,
            id,
            700_000,
            user,
            nullifier,
            clearance ? 1 : 0,
            clearance ? 0 : nullifier + SUCCESSOR,
            0,
            uint64(vm.getBlockTimestamp()) + 3650 days
        );
    }

    function _request(uint256 nullifier) private view returns (Types.RequestPublicInputs memory) {
        return Types.RequestPublicInputs(
            2,
            uint64(block.chainid),
            address(vault),
            vault.currentRoot(),
            11,
            12,
            uint64(vm.getBlockTimestamp()),
            100_000,
            nullifier,
            1,
            2,
            3
        );
    }

    function _name(string memory signature) private pure returns (string memory) {
        bytes memory raw = bytes(signature);
        uint256 end;
        while (raw[end] != "(") ++end;
        bytes memory out = new bytes(end);
        for (uint256 i = 0; i < end; ++i) {
            out[i] = raw[i];
        }
        return string(out);
    }

    function _eq(string memory left, string memory right) private pure returns (bool) {
        return keccak256(bytes(left)) == keccak256(bytes(right));
    }
}
