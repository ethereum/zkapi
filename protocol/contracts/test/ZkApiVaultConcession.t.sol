// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";
import {ToggleableDestination} from "./NativeEthVault.t.sol";

/// @dev The concession exit (circuit zkapi-v2-concession-v1, vault revision 3) against the mock
///      adapter: initiation, defeat, raise, finalization, the re-escape rules of the design's
///      section 4.6, close, expiry, retirement and the any-known-root rule (Amendment A1).
///      Note 0's states S_i have nullifiers N(i) = 1000 + i; the escape from S_i names N(i) and
///      its successor N(i + 1). The balance of S_2 is 790,000 of a 1,000,000 deposit.
contract ZkApiVaultConcessionTest is VaultTestBase {
    uint128 constant B2 = 790_000;
    uint128 constant SB2 = 100_000;

    function setUp() public {
        vm.warp(1_700_000_000);
        _setUpVault();
    }

    function N(uint256 i) internal pure returns (uint256) {
        return 1000 + i;
    }

    /// Escape from S_i with conceded c and payout balance - c.
    function _escapeFrom(uint32 id, uint256 i, uint128 balance, uint128 c)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return _escape(id, N(i), N(i + 1), balance - c, c);
    }

    function _initiate(Types.WithdrawalPublicInputs memory inputs) internal {
        vm.prank(user);
        vault.initiateEscapeWithdrawal(inputs, PROOF);
    }

    // ================================================================== initiation

    function test_escapeConsumesBothNullifiersAndRecordsTheConcession() public {
        uint32 id = _deposit(42);
        uint256 root = vault.currentRoot();
        Types.WithdrawalPublicInputs memory inputs = _escapeFrom(id, 2, B2, SB2);
        uint64 deadline = uint64(vm.getBlockTimestamp()) + CHALLENGE_PERIOD;

        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalInitiated(id, N(2), B2 - SB2, user, deadline, root);
        vm.expectEmit(address(vault));
        emit Events.EscapeConcessionRecorded(id, N(3), B2, SB2);
        _initiate(inputs);

        assertTrue(vault.usedNullifiers(N(2)));
        assertTrue(vault.usedNullifiers(N(3)));
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists, uint256 activeRoot, uint256 nullifier, uint128 finalBalance, address destination, uint64 dl) =
            vault.pendingWithdrawals(id);
        assertTrue(exists);
        assertEq(activeRoot, inputs.activeRoot);
        assertEq(nullifier, N(2));
        assertEq(finalBalance, B2 - SB2);
        assertEq(destination, user);
        assertEq(dl, deadline);
        (uint256 next, uint128 stateBalance, uint128 conceded) = _concession(id);
        assertEq(next, N(3));
        assertEq(stateBalance, B2);
        assertEq(conceded, SB2);
        // No Merkle work: the root and its history are untouched.
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// An unrelated deposit mined first changes nothing about the escape. The pending record keeps
    /// the proof's root, but the events report the live root: the indexer and the clients' log
    /// rebuild require every root-bearing event other than NoteDeposited and ClosedLeafRetired to
    /// carry the current computed root. A defeat after a further deposit reports the root live at
    /// the defeat, neither the proof's root nor the one live at initiation.
    function test_depositLandingFirstDoesNotInvalidateTheEscape() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory inputs = _escapeFrom(id, 2, B2, 0);
        uint256 proofRoot = inputs.activeRoot;
        _deposit(43);
        _deposit(44);
        assertNotEq(vault.currentRoot(), proofRoot);
        uint256 liveRoot = vault.currentRoot();
        uint64 deadline = uint64(vm.getBlockTimestamp()) + CHALLENGE_PERIOD;
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalInitiated(id, N(2), B2, user, deadline, liveRoot);
        _initiate(inputs);
        (, uint256 activeRoot,,,,) = vault.pendingWithdrawals(id);
        assertEq(activeRoot, proofRoot);
        assertEq(vault.currentRoot(), liveRoot);

        _deposit(45);
        uint256 defeatRoot = vault.currentRoot();
        assertNotEq(defeatRoot, liveRoot);
        assertNotEq(defeatRoot, proofRoot);
        Types.RequestPublicInputs memory request = _evidence(N(3), SB2);
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalChallenged(id, N(2), defeatRoot);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        assertEq(vault.currentRoot(), defeatRoot);
    }

    function test_escapeAcceptsOnlyKindZero() public {
        uint32 id = _deposit(42);
        uint8[4] memory kinds = [KIND_CLOSE, KIND_OWNERSHIP, 3, type(uint8).max];
        for (uint256 i = 0; i < kinds.length; ++i) {
            Types.WithdrawalPublicInputs memory inputs = _escapeFrom(id, 2, B2, 0);
            inputs.kind = kinds[i];
            vm.expectRevert(Errors.WrongWithdrawalKind.selector);
            vault.initiateEscapeWithdrawal(inputs, PROOF);
        }
        _assertUntouched(id);
    }

    function test_mutualCloseAcceptsOnlyKindOne() public {
        uint32 id = _deposit(42);
        uint8[4] memory kinds = [KIND_ESCAPE, KIND_OWNERSHIP, 3, type(uint8).max];
        for (uint256 i = 0; i < kinds.length; ++i) {
            Types.WithdrawalPublicInputs memory inputs = _close(id, N(2), B2);
            inputs.kind = kinds[i];
            vm.expectRevert(Errors.WrongWithdrawalKind.selector);
            vault.mutualClose(inputs, PROOF);
        }
        _assertUntouched(id);
    }

    /// An ownership proof (kind 2: destination 0, no successor, no concession) is refused by its
    /// kind before anything else about it is examined.
    function test_ownershipProofIsRejectedByEveryEntryPoint() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory ownership = _withdrawal(KIND_OWNERSHIP, id, N(2), 0, B2, 0);
        ownership.destination = address(0);
        vm.expectRevert(Errors.WrongWithdrawalKind.selector);
        vault.initiateEscapeWithdrawal(ownership, PROOF);
        vm.expectRevert(Errors.WrongWithdrawalKind.selector);
        vault.mutualClose(ownership, PROOF);
        _assertUntouched(id);
    }

    function test_escapeAndCloseExpireAfterValidUntil() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory escape = _escapeFrom(id, 2, B2, 0);
        Types.WithdrawalPublicInputs memory close = _close(id, N(2), B2);
        vm.warp(escape.validUntil + 1);
        vm.expectRevert(Errors.ProofExpired.selector);
        vault.initiateEscapeWithdrawal(escape, PROOF);
        vm.expectRevert(Errors.ProofExpired.selector);
        vault.mutualClose(close, PROOF);
        _assertUntouched(id);

        // validUntil is the last second at which the proof is accepted.
        vm.warp(escape.validUntil);
        uint256 snapshot = vm.snapshotState();
        vault.initiateEscapeWithdrawal(escape, PROOF);
        vm.revertToState(snapshot);
        vault.mutualClose(close, PROOF);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
    }

    function test_escapeRefusesAMissingOrSelfSuccessor() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory inputs = _escapeFrom(id, 2, B2, 0);
        inputs.nextNullifier = 0;
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        vault.initiateEscapeWithdrawal(inputs, PROOF);
        inputs.nextNullifier = inputs.withdrawalNullifier;
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        vault.initiateEscapeWithdrawal(inputs, PROOF);
        _assertUntouched(id);
    }

    function test_withdrawalsCheckEveryDeploymentBindingField() public {
        uint32 id = _deposit(42);
        for (uint256 field = 0; field < 7; ++field) {
            Types.WithdrawalPublicInputs memory escape = _escapeFrom(id, 2, B2, 0);
            Types.WithdrawalPublicInputs memory close = _close(id, N(2), B2);
            _breakBinding(escape, field);
            _breakBinding(close, field);
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.initiateEscapeWithdrawal(escape, PROOF);
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.mutualClose(close, PROOF);
        }
        _assertUntouched(id);
    }

    function test_withdrawalsRefuseZeroOrVaultDestination() public {
        uint32 id = _deposit(42);
        address[2] memory refused = [address(0), address(vault)];
        for (uint256 i = 0; i < refused.length; ++i) {
            Types.WithdrawalPublicInputs memory escape = _escapeFrom(id, 2, B2, 0);
            escape.destination = refused[i];
            vm.expectRevert(Errors.InvalidDestination.selector);
            vault.initiateEscapeWithdrawal(escape, PROOF);
            Types.WithdrawalPublicInputs memory close = _close(id, N(2), B2);
            close.destination = refused[i];
            vm.expectRevert(Errors.InvalidDestination.selector);
            vault.mutualClose(close, PROOF);
        }
        _assertUntouched(id);
    }

    function test_escapeRefusesBalanceAboveTheDeposit() public {
        uint32 id = _deposit(42);
        _escapeReverts(_escape(id, N(0), N(1), DEPOSIT - 99, 100), Errors.InvalidBalance.selector);
        // Two maximal amounts do not overflow into a panic.
        _escapeReverts(_escape(id, N(0), N(1), type(uint128).max, type(uint128).max), Errors.InvalidBalance.selector);
        _assertUntouched(id);
        // A genesis escape may concede part of the deposit.
        _initiate(_escape(id, N(0), N(1), DEPOSIT - 250_000, 250_000));
        (, uint128 stateBalance, uint128 conceded) = _concession(id);
        assertEq(stateBalance, DEPOSIT);
        assertEq(conceded, 250_000);
    }

    function test_escapeRefusesAConsumedNullifierOrSuccessor() public {
        uint32 a = _deposit(42);
        uint32 b = _deposit(43);
        _initiate(_escape(b, 5000, 5001, 1, 0));
        _escapeReverts(_escape(a, 5001, 6000, 1, 0), Errors.ReplayedNullifier.selector);
        _escapeReverts(_escape(a, 6000, 5000, 1, 0), Errors.ReplayedNullifier.selector);
        _assertUntouched(a);
    }

    function test_secondEscapeWhilePendingReverts() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        _escapeReverts(_escapeFrom(id, 4, 600_000, 0), Errors.NoteNotActive.selector);
        _closeReverts(_close(id, N(4), 600_000), Errors.NoteNotActive.selector);
    }

    function test_escapeRefusesAChallengedStateOrASupersededOne() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        _defeat(id, N(3));
        _escapeReverts(_escapeFrom(id, 2, B2, SB2), Errors.ChallengedNullifier.selector);
        _escapeReverts(_escapeFrom(id, 1, 940_000, 0), Errors.SupersededState.selector);
        // The flags are checked before the root and the proof.
        Types.WithdrawalPublicInputs memory unknownRoot = _escapeFrom(id, 1, 940_000, 0);
        unknownRoot.activeRoot = 12_345;
        vm.expectRevert(Errors.SupersededState.selector);
        vault.initiateEscapeWithdrawal(unknownRoot, PROOF);
    }

    /// The vault consumes only canonical nullifiers, even behind an adapter that accepts anything
    /// (the mock): N + r is the same scalar to a verifier that reduced it, and would otherwise slip
    /// past ChallengedNullifier, SupersededState and ReplayedNullifier, or record a successor that
    /// the real successor request cannot match. The real adapter refuses them too
    /// (ZkApiVaultGroth16Test, ZkApiVaultMutationTest).
    function test_withdrawalsConsumeOnlyCanonicalNullifiers() public {
        uint256 r = SCALAR_MODULUS;
        uint32 id = _deposit(42);
        _escapeReverts(_escape(id, N(2) + r, N(3), B2, 0), Errors.InvalidFelt.selector);
        _escapeReverts(_escape(id, N(2), N(3) + r, B2, 0), Errors.InvalidFelt.selector);
        _escapeReverts(_escape(id, type(uint256).max, N(3), B2, 0), Errors.InvalidFelt.selector);
        _closeReverts(_close(id, N(2) + r, B2), Errors.InvalidFelt.selector);
        _assertUntouched(id);

        _initiate(_escapeFrom(id, 2, B2, 0));
        _escapeReverts(_escape(id, N(5) + r, N(6), 1, 0), Errors.NoteNotActive.selector);
        _defeat(id, N(3));
        // The defeated state renamed, and the state below it naming the renamed successor.
        _escapeReverts(_escape(id, N(2) + r, N(3), B2, 0), Errors.InvalidFelt.selector);
        _escapeReverts(_escape(id, N(1), N(2) + r, 940_000, 0), Errors.InvalidFelt.selector);
        _closeReverts(_close(id, N(2) + r, B2), Errors.InvalidFelt.selector);
        _assertUntouched(id);
        assertFalse(vault.usedNullifiers(N(2) + r));
        assertFalse(vault.usedNullifiers(N(3) + r));
    }

    // ====================================================================== defeat

    /// Only a request proof at the successor nullifier defeats: a request at the escaped
    /// nullifier itself (the withholding operator's evidence) never does.
    function test_defeatOnlyAtTheSuccessorNullifier() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        uint256[3] memory wrong = [N(2), N(4), 777];
        for (uint256 i = 0; i < wrong.length; ++i) {
            Types.RequestPublicInputs memory request = _evidence(wrong[i], SB2);
            vm.prank(challenger);
            vm.expectRevert(Errors.NotSuccessorEvidence.selector);
            vault.challengeEscapeWithdrawal(id, request, PROOF);
        }
        _assertPending(id, N(2), N(3));
        _defeat(id, N(3));
    }

    function test_defeatReleasesBothNullifiersFlagsTheStateAndGrantsGrace() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(uint256(expiry) - 1 hours);
        _initiate(_escapeFrom(id, 2, B2, SB2));
        uint256 root = vault.currentRoot();
        vm.warp(_deadline(id) - 1);
        Types.RequestPublicInputs memory request = _evidence(N(3), 50_000);
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalChallenged(id, N(2), root);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);

        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(id);
        assertFalse(exists);
        (uint256 next, uint128 stateBalance, uint128 conceded) = _concession(id);
        assertEq(next, 0);
        assertEq(stateBalance, 0);
        assertEq(conceded, 0);
        assertFalse(vault.usedNullifiers(N(2)));
        assertFalse(vault.usedNullifiers(N(3)));
        assertTrue(vault.challengedNullifiers(N(2)));
        assertFalse(vault.challengedNullifiers(N(3)));
        assertEq(vault.currentRoot(), root);
        // The challenge came after expiryTs, so the grace sets the sweep time.
        uint256 graceEnd = vm.getBlockTimestamp() + CHALLENGE_PERIOD;
        assertEq(vault.effectiveExpiry(id), graceEnd);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        // The owner exits from the successor in the meantime; its nullifier N(3) is free again.
        _initiate(_escapeFrom(id, 3, 750_000, 0));
        _assertPending(id, N(3), N(4));
    }

    function test_defeatChecksPendingDeadlineBindingAndProof() public {
        uint32 id = _deposit(42);
        Types.RequestPublicInputs memory request = _evidence(N(3), SB2);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        _initiate(_escapeFrom(id, 2, B2, 0));
        for (uint256 field = 0; field < 5; ++field) {
            Types.RequestPublicInputs memory invalid = _request(N(3), SB2);
            _breakBinding(invalid, field);
            adapter.acceptRequest(invalid, PROOF);
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.challengeEscapeWithdrawal(id, invalid, PROOF);
        }
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(id, request, hex"bad0");
        vm.warp(_deadline(id));
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        _assertPending(id, N(2), N(3));
    }

    /// The defeat checks neither the request's root nor its time: historical evidence counts.
    function test_defeatAcceptsHistoricalEvidence() public {
        uint32 id = _deposit(42);
        Types.RequestPublicInputs memory old = _evidence(N(3), SB2);
        vm.warp(vm.getBlockTimestamp() + 20 days);
        _deposit(43);
        _initiate(_escapeFrom(id, 2, B2, 0));
        assertNotEq(old.activeRoot, vault.currentRoot());
        _defeat(id, old);
    }

    // ======================================================================= raise

    function test_raiseTakesTheMinimumOfAmountBoundAndStateBalance() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        Types.RequestPublicInputs memory request = _evidence(N(2), SB2);

        // amount binds
        vm.expectEmit(address(vault));
        emit Events.EscapeConcessionRaised(id, N(2), 40_000, B2 - 40_000);
        vm.prank(challenger);
        vault.raiseEscapeConcession(id, request, PROOF, 40_000);
        _assertConcession(id, 40_000);
        // the request's solvency bound binds
        vm.prank(challenger);
        vault.raiseEscapeConcession(id, request, PROOF, type(uint128).max);
        _assertConcession(id, SB2);

        // the state balance binds
        uint32 small = _deposit(43);
        _initiate(_escape(small, 7000, 7001, 60_000, 0));
        Types.RequestPublicInputs memory big = _evidence(7000, 500_000);
        vault.raiseEscapeConcession(small, big, PROOF, 400_000);
        (, uint128 stateBalance, uint128 conceded) = _concession(small);
        assertEq(stateBalance, 60_000);
        assertEq(conceded, 60_000);
        assertEq(_pendingFinalBalance(small), 0);
    }

    function test_raiseIsMonotone() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        Types.RequestPublicInputs memory request = _evidence(N(2), SB2);
        vault.raiseEscapeConcession(id, request, PROOF, 40_000);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, request, PROOF, 30_000);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, request, PROOF, 40_000);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, request, PROOF, 0);
        vault.raiseEscapeConcession(id, request, PROOF, 40_001);
        _assertConcession(id, 40_001);
    }

    /// A raise can never take more than the bound the owner's own request proof carries: an
    /// escape that already concedes that bound cannot be raised with it.
    function test_raiseCannotExceedTheRequestsBound() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, SB2));
        Types.RequestPublicInputs memory request = _evidence(N(2), SB2);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, request, PROOF, type(uint128).max);
        _assertConcession(id, SB2);
    }

    /// NotARaise is decided before the proof is verified, so a challenger cannot burn a
    /// verification on a raise that would change nothing.
    function test_notARaiseIsCheckedBeforeVerification() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, SB2));
        Types.RequestPublicInputs memory unverified = _request(N(2), SB2);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, unverified, hex"bad0", 1_000_000);
        unverified.solvencyBound = 2 * SB2;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.raiseEscapeConcession(id, unverified, hex"bad0", 1_000_000);
    }

    function test_raiseNeedsStateEvidence() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        uint256[3] memory wrong = [N(3), N(1), 777];
        for (uint256 i = 0; i < wrong.length; ++i) {
            Types.RequestPublicInputs memory request = _evidence(wrong[i], SB2);
            vm.expectRevert(Errors.NotStateEvidence.selector);
            vault.raiseEscapeConcession(id, request, PROOF, SB2);
        }
        _assertConcession(id, 0);
    }

    function test_raiseChecksPendingDeadlineAndBinding() public {
        uint32 id = _deposit(42);
        Types.RequestPublicInputs memory request = _evidence(N(2), SB2);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.raiseEscapeConcession(id, request, PROOF, SB2);
        _initiate(_escapeFrom(id, 2, B2, 0));
        for (uint256 field = 0; field < 5; ++field) {
            Types.RequestPublicInputs memory invalid = _request(N(2), SB2);
            _breakBinding(invalid, field);
            adapter.acceptRequest(invalid, PROOF);
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.raiseEscapeConcession(id, invalid, PROOF, SB2);
        }
        vm.warp(_deadline(id));
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.raiseEscapeConcession(id, request, PROOF, SB2);
        _assertConcession(id, 0);
    }

    function test_raiseKeepsTheDeadlineAndNullifiersAndADefeatStillWorks() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        uint64 deadline = _deadline(id);
        vm.warp(deadline - 10);
        vault.raiseEscapeConcession(id, _evidence(N(2), SB2), PROOF, SB2);
        assertEq(_deadline(id), deadline);
        assertTrue(vault.usedNullifiers(N(2)));
        assertTrue(vault.usedNullifiers(N(3)));
        assertFalse(vault.challengedNullifiers(N(2)));
        _defeat(id, N(3));
        (uint256 next,, uint128 conceded) = _concession(id);
        assertEq(next, 0);
        assertEq(conceded, 0);
    }

    // ==================================================================== finalize

    function test_finalizePaysTheRaisedPayout() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        vault.raiseEscapeConcession(id, _evidence(N(2), SB2), PROOF, 40_000);
        vm.warp(_deadline(id));
        uint256 before = user.balance;
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalFinalized(id, N(2), B2 - 40_000, user);
        vm.prank(challenger);
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance - before, uint256(B2 - 40_000) * 1 gwei);
        assertEq(treasury.balance, uint256(DEPOSIT - (B2 - 40_000)) * 1 gwei);
        assertEq(address(vault).balance, 0);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        (uint256 next, uint128 stateBalance, uint128 conceded) = _concession(id);
        assertEq(next + stateBalance + conceded, 0);
        // Finalized escapes keep their nullifiers consumed.
        assertTrue(vault.usedNullifiers(N(2)));
        assertTrue(vault.usedNullifiers(N(3)));
    }

    function test_finalizeCreditsTheRaisedPayoutWhenThePushFails() public {
        uint32 id = _deposit(42);
        ToggleableDestination wallet = new ToggleableDestination();
        Types.WithdrawalPublicInputs memory inputs = _escapeFrom(id, 2, B2, 0);
        inputs.destination = address(wallet);
        _initiate(inputs);
        vault.raiseEscapeConcession(id, _evidence(N(2), SB2), PROOF, SB2);
        vm.warp(_deadline(id));
        vm.expectEmit(address(vault));
        emit Events.EscapePayoutDeferred(id, address(wallet), B2 - SB2);
        vault.finalizeEscapeWithdrawal(id);
        assertEq(vault.escapePayoutCredits(address(wallet)), B2 - SB2);
        assertEq(treasury.balance, uint256(DEPOSIT - (B2 - SB2)) * 1 gwei);
        wallet.setAccepting(true);
        vault.claimEscapePayout(address(wallet));
        assertEq(address(wallet).balance, uint256(B2 - SB2) * 1 gwei);
        assertEq(address(vault).balance, 0);
    }

    // ================================================== re-escape rules (section 4.6)

    /// The owner spent S_0 .. S_5 (the operator archived R_0 .. R_5) and escapes from the stale
    /// S_4. After R_5 defeats it: S_4 again reverts ChallengedNullifier and S_3 SupersededState,
    /// both cheaply; S_2 is verified and recorded, and R_3 defeats it, flagging N_2, so S_1 then
    /// reverts SupersededState; S_0 is defeated by R_1. A newer state is judged on its own
    /// evidence: S_5 (no request at N_6) finalizes.
    function test_reEscapeRulesAfterADefeat() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 4, 500_000, 0));
        _defeat(id, N(5));

        _escapeReverts(_escapeFrom(id, 4, 500_000, 0), Errors.ChallengedNullifier.selector);
        _escapeReverts(_escapeFrom(id, 3, 600_000, 0), Errors.SupersededState.selector);

        _initiate(_escapeFrom(id, 2, B2, 0));
        _defeat(id, N(3));
        _escapeReverts(_escapeFrom(id, 2, B2, 0), Errors.ChallengedNullifier.selector);
        _escapeReverts(_escapeFrom(id, 1, 940_000, 0), Errors.SupersededState.selector);

        _initiate(_escapeFrom(id, 0, DEPOSIT, 0));
        _defeat(id, N(1));
        assertTrue(vault.challengedNullifiers(N(0)));
        assertTrue(vault.challengedNullifiers(N(2)));
        assertTrue(vault.challengedNullifiers(N(4)));
        for (uint256 i = 0; i < 5; ++i) {
            assertFalse(vault.usedNullifiers(N(i)));
        }

        // The newest state: R_5's own nullifier N_5 is free again after the first defeat.
        _initiate(_escapeFrom(id, 5, 450_000, 0));
        Types.RequestPublicInputs memory r5 = _evidence(N(5), SB2);
        vm.expectRevert(Errors.NotSuccessorEvidence.selector);
        vault.challengeEscapeWithdrawal(id, r5, PROOF);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        assertEq(treasury.balance, uint256(DEPOSIT - 450_000) * 1 gwei);
    }

    // ======================================================================= close

    function test_mutualClosePaysAndLeavesTheTree() public {
        uint32 id = _deposit(42);
        uint256 root = vault.currentRoot();
        Types.WithdrawalPublicInputs memory close = _close(id, N(2), B2);
        // A kind-1 proof publishes no successor; the vault ignores the word and consumes only N.
        close.nextNullifier = N(3);
        vm.expectEmit(address(vault));
        emit Events.MutualClose(id, N(2), B2, user);
        vault.mutualClose(close, PROOF);
        assertEq(user.balance, 100 ether - uint256(DEPOSIT) * 1 gwei + uint256(B2) * 1 gwei);
        assertEq(treasury.balance, uint256(DEPOSIT - B2) * 1 gwei);
        assertTrue(vault.usedNullifiers(N(2)));
        assertFalse(vault.usedNullifiers(N(3)));
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        assertEq(vault.currentRoot(), root);
        _closeReverts(_close(id, N(3), B2), Errors.NoteNotActive.selector);
    }

    /// The operator's clearance is its consent: a close does not consult challengedNullifiers.
    function test_mutualCloseAtADefeatedState() public {
        uint32 id = _deposit(42);
        _initiate(_escapeFrom(id, 2, B2, 0));
        _defeat(id, N(3));
        vault.mutualClose(_close(id, N(2), B2), PROOF);
        assertTrue(vault.usedNullifiers(N(2)));
        assertTrue(vault.challengedNullifiers(N(2)));
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
    }

    // ====================================================================== expiry

    function test_claimExpiredTakesNoSiblingsAndLeavesTheLeaf() public {
        uint32 id = _deposit(42);
        uint256 root = vault.currentRoot();
        vm.warp(vault.effectiveExpiry(id) - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(vault.effectiveExpiry(id));
        vm.expectEmit(address(vault));
        emit Events.ExpiredClaimed(id, DEPOSIT, root);
        vm.prank(challenger);
        vault.claimExpired(id);
        assertEq(vault.currentRoot(), root);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        assertEq(treasury.balance, uint256(DEPOSIT) * 1 gwei);
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.claimExpired(id);
    }

    function test_pendingEscapeCannotBeSweptAtExpiry() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(uint256(expiry) - 1 hours);
        _initiate(_escapeFrom(id, 2, B2, 0));
        vm.warp(uint256(expiry) + 1 hours);
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.claimExpired(id);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - uint256(DEPOSIT - B2) * 1 gwei);
    }

    // ========================================================== retireClosedLeaf

    function test_retireClosedLeafNeedsAClosedNote() public {
        uint32 id = _deposit(42);
        uint256[32] memory path = _path(id);
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(id, path);
        _initiate(_escapeFrom(id, 2, B2, 0));
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(id, path);
        path = _path(7);
        vm.expectRevert(Errors.NoteNotClosed.selector);
        vault.retireClosedLeaf(7, path);
    }

    function test_retireClosedLeafRemovesTheLeafOnce() public {
        uint32 a = _deposit(42);
        uint32 b = _deposit(43);
        vault.mutualClose(_close(a, N(2), B2), PROOF);
        uint256 oldRoot = vault.currentRoot();
        uint256[32] memory path = _path(a);
        // The root of the tree that holds only note b's leaf.
        uint256 expected = _leafOf(b);
        expected = Bn254Poseidon.compress(DOMAIN_NODE, 0, expected);
        for (uint256 level = 1; level < 32; ++level) {
            expected = Bn254Poseidon.compress(DOMAIN_NODE, expected, emptySiblings[level]);
        }
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vm.expectEmit(address(vault));
        emit Events.ClosedLeafRetired(a, expected);
        vm.prank(address(0xD00D)); // permissionless
        vault.retireClosedLeaf(a, path);
        retired[a] = true;
        assertEq(vault.currentRoot(), expected);
        assertTrue(vault.knownRoots(expected));
        assertTrue(vault.isKnownRoot(oldRoot));
        // A second retirement finds the leaf gone.
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(a, path);
        path = _path(a);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(a, path);
        // A deposit and an exit of the other note still work on the new tree.
        _deposit(44);
        vault.mutualClose(_close(b, 9000, DEPOSIT), PROOF);
    }

    function test_retireClosedLeafAfterEscapeAndExpiry() public {
        uint32 escaped = _deposit(42);
        uint32 expired = _deposit(43);
        _initiate(_escapeFrom(escaped, 2, B2, 0));
        vm.warp(_deadline(escaped));
        vault.finalizeEscapeWithdrawal(escaped);
        _retire(escaped);
        vm.warp(vault.effectiveExpiry(expired));
        vault.claimExpired(expired);
        _retire(expired);
        // The tree is empty again.
        uint256 empty;
        for (uint256 level = 0; level < 32; ++level) {
            empty = Bn254Poseidon.compress(DOMAIN_NODE, empty, empty);
        }
        assertEq(vault.currentRoot(), empty);
    }

    // ===================================================== known roots (Amendment A1)

    /// Every root the vault set stays known for good: the empty tree's, each deposit's and each
    /// retirement's. A root it never held is unknown.
    function test_everyRootTheVaultHeldStaysKnown() public {
        uint256[6] memory roots;
        roots[0] = vault.currentRoot();
        uint32 a = _deposit(42);
        roots[1] = vault.currentRoot();
        uint32 b = _deposit(43);
        roots[2] = vault.currentRoot();
        vault.mutualClose(_close(a, N(2), B2), PROOF);
        _retire(a);
        roots[3] = vault.currentRoot();
        _deposit(44);
        roots[4] = vault.currentRoot();
        vault.mutualClose(_close(b, 9000, DEPOSIT), PROOF);
        _retire(b);
        roots[5] = vault.currentRoot();
        vm.warp(vm.getBlockTimestamp() + 3650 days);
        for (uint256 i = 0; i < roots.length; ++i) {
            assertTrue(vault.isKnownRoot(roots[i]));
            assertTrue(vault.knownRoots(roots[i]));
        }
        assertFalse(vault.isKnownRoot(12_345));
        assertFalse(vault.isKnownRoot(0));
    }

    /// A client exits with the Merkle path it saved at deposit: an escape and a close at their
    /// notes' deposit-time roots, after later deposits, a retirement and more than the old
    /// one-day root window.
    function test_exitsAtTheDepositTimeRootAfterLaterDepositsAndARetirement() public {
        uint32 a = _deposit(42);
        Types.WithdrawalPublicInputs memory escape = _escapeFrom(a, 2, B2, 0);
        uint32 b = _deposit(43);
        Types.WithdrawalPublicInputs memory close = _close(b, 9000, 800_000);
        uint32 c = _deposit(44);
        vault.mutualClose(_close(c, 9100, DEPOSIT), PROOF);
        _retire(c);
        _deposit(45);
        vm.warp(vm.getBlockTimestamp() + 2 days);
        assertNotEq(vault.currentRoot(), escape.activeRoot);
        assertNotEq(vault.currentRoot(), close.activeRoot);
        // Both roots were replaced more than ROOT_HISTORY_WINDOW ago.
        escape.validUntil = uint64(vm.getBlockTimestamp());
        close.validUntil = uint64(vm.getBlockTimestamp());
        _initiate(escape);
        vault.mutualClose(close, PROOF);
        assertEq(uint256(_status(a)), uint256(Types.NoteStatus.PendingWithdrawal));
        assertEq(uint256(_status(b)), uint256(Types.NoteStatus.Closed));
    }

    function test_withdrawalsRefuseARootTheVaultNeverHeld() public {
        uint32 id = _deposit(42);
        Types.WithdrawalPublicInputs memory escape = _escapeFrom(id, 2, B2, 0);
        Types.WithdrawalPublicInputs memory close = _close(id, N(2), B2);
        escape.activeRoot = 12_345;
        close.activeRoot = 12_345;
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.initiateEscapeWithdrawal(escape, PROOF);
        vm.expectRevert(Errors.UnknownRoot.selector);
        vault.mutualClose(close, PROOF);
        _assertUntouched(id);
    }

    // ========================================= closed notes stay closed (Amendment A1)

    uint256 constant CLOSED_BY_MUTUAL_CLOSE = 0;
    uint256 constant CLOSED_BY_FINALIZED_ESCAPE = 1;
    uint256 constant CLOSED_BY_EXPIRY_CLAIM = 2;

    /// Under Amendment A1 a Closed note's leaf stays provable for good: in every root the vault
    /// held before the leaf is retired, and in every root if it never is. The Active check of
    /// initiateEscapeWithdrawal and mutualClose is then the only barrier to a second payout. For
    /// each way a note closes, an escape and a close from an older unconsumed state (S_0), from
    /// the closing state (S_2) and from a newer unconsumed state (S_4) revert NoteNotActive at the
    /// note's deposit-time root and at the root live when it closed, before and after its leaf
    /// is retired, and at the root after the retirement.
    function test_closedNoteNeverExitsAgain() public {
        for (uint256 route = 0; route < 3; ++route) {
            uint256 snapshot = vm.snapshotState();
            uint32 id = _deposit(42);
            uint256 depositRoot = vault.currentRoot();
            _deposit(43);
            _closeBy(route, id);
            uint256 closedRoot = vault.currentRoot();
            assertNotEq(closedRoot, depositRoot);
            uint256 held = address(vault).balance;

            _assertNeverExitsAgain(id, depositRoot);
            _assertNeverExitsAgain(id, closedRoot);
            _retire(id);
            assertTrue(vault.isKnownRoot(depositRoot));
            assertTrue(vault.isKnownRoot(closedRoot));
            _assertNeverExitsAgain(id, depositRoot);
            _assertNeverExitsAgain(id, closedRoot);
            _assertNeverExitsAgain(id, vault.currentRoot());

            assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
            assertEq(address(vault).balance, held);
            // The refused exits consumed nothing.
            uint256[4] memory fresh = [N(0), N(1), N(4), N(5)];
            for (uint256 i = 0; i < fresh.length; ++i) {
                assertFalse(vault.usedNullifiers(fresh[i]));
            }
            vm.revertToState(snapshot);
        }
    }

    /// A note id never deposited has no leaf, but the mock adapter accepts any statement: an escape
    /// or a close of it (zero balance, the only one its zero deposit admits) reverts NoteNotActive
    /// rather than recording a pending escape that the later deposit at that id would inherit.
    function test_exitsOfANoteNeverDepositedRevert() public {
        _deposit(42);
        uint32 future = vault.nextNoteId();
        _escapeReverts(_escape(future, N(0), N(1), 0, 0), Errors.NoteNotActive.selector);
        _closeReverts(_close(future, N(0), 0), Errors.NoteNotActive.selector);
        (bool exists,,,,,) = vault.pendingWithdrawals(future);
        assertFalse(exists);
        assertFalse(vault.usedNullifiers(N(0)));
        assertEq(uint256(_status(future)), uint256(Types.NoteStatus.Uninitialized));
    }

    function _closeBy(uint256 route, uint32 id) internal {
        if (route == CLOSED_BY_MUTUAL_CLOSE) {
            vault.mutualClose(_close(id, N(2), B2), PROOF);
        } else if (route == CLOSED_BY_FINALIZED_ESCAPE) {
            _initiate(_escapeFrom(id, 2, B2, SB2));
            vm.warp(_deadline(id));
            vault.finalizeEscapeWithdrawal(id);
        } else {
            vm.warp(vault.effectiveExpiry(id));
            vault.claimExpired(id);
        }
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
    }

    /// Escapes and closes of Closed note `id` from S_0, S_2 and S_4 at `root` (a fresh proof:
    /// validUntil is in the future) revert NoteNotActive.
    function _assertNeverExitsAgain(uint32 id, uint256 root) internal {
        uint256[3] memory states = [uint256(0), 2, 4];
        uint128[3] memory balances = [DEPOSIT, B2, 600_000];
        for (uint256 i = 0; i < states.length; ++i) {
            Types.WithdrawalPublicInputs memory escape = _escapeFrom(id, states[i], balances[i], 0);
            escape.activeRoot = root;
            _escapeReverts(escape, Errors.NoteNotActive.selector);
            escape = _escapeFrom(id, states[i], balances[i], balances[i] / 2);
            escape.activeRoot = root;
            _escapeReverts(escape, Errors.NoteNotActive.selector);
            Types.WithdrawalPublicInputs memory close = _close(id, N(states[i]), balances[i]);
            close.activeRoot = root;
            _closeReverts(close, Errors.NoteNotActive.selector);
        }
    }

    // ============================================================ separate notes

    /// Escapes of two notes run side by side; a defeat of one leaves the other pending and
    /// finalizable.
    function test_notesAreIndependent() public {
        uint32 a = _deposit(42);
        uint32 b = _deposit(42); // the same registration (secret) for both notes
        _initiate(_escape(a, 100, 101, 500_000, 0));
        _initiate(_escape(b, 200, 201, 900_000, 100_000));
        _defeat(a, 101);
        _assertPending(b, 200, 201);
        vm.warp(_deadline(b));
        vault.finalizeEscapeWithdrawal(b);
        assertEq(uint256(_status(a)), uint256(Types.NoteStatus.Active));
        assertEq(uint256(_status(b)), uint256(Types.NoteStatus.Closed));
        assertEq(treasury.balance, 100_000 gwei);
    }

    // ================================================================ constructor

    function test_constructorRequiresMaxPauseOfAtLeastTwoChallengePeriods() public {
        vm.expectRevert(Errors.Unauthorized.selector);
        _newVault(CHALLENGE_PERIOD, 2 * CHALLENGE_PERIOD - 1);
        vm.expectRevert(Errors.Unauthorized.selector);
        _newVault(type(uint64).max, type(uint64).max);
        ZkApiVault tight = _newVault(CHALLENGE_PERIOD, 2 * CHALLENGE_PERIOD);
        assertEq(tight.maxPauseDuration(), 2 * CHALLENGE_PERIOD);
        assertEq(tight.CONCESSION_ESCAPE_VERSION(), 1);
        assertEq(tight.PAUSE_COOLDOWN(), 1 days);
        assertEq(tight.ROOT_HISTORY_WINDOW(), 1 days);
        assertTrue(tight.isKnownRoot(tight.currentRoot()));
    }

    // ================================================================== helpers

    function _defeat(uint32 id, uint256 successorNullifier) internal {
        _defeat(id, _evidence(successorNullifier, SB2));
    }

    function _defeat(uint32 id, Types.RequestPublicInputs memory request) internal {
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
    }

    function _assertPending(uint32 id, uint256 nullifier, uint256 next) internal view {
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,, uint256 pendingNullifier,,,) = vault.pendingWithdrawals(id);
        assertTrue(exists);
        assertEq(pendingNullifier, nullifier);
        (uint256 pendingNext,,) = _concession(id);
        assertEq(pendingNext, next);
        assertTrue(vault.usedNullifiers(nullifier));
        assertTrue(vault.usedNullifiers(next));
    }

    function _assertConcession(uint32 id, uint128 expected) internal view {
        (, uint128 stateBalance, uint128 conceded) = _concession(id);
        assertEq(conceded, expected);
        assertEq(_pendingFinalBalance(id) + conceded, stateBalance);
    }

    function _assertUntouched(uint32 id) internal view {
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(id);
        assertFalse(exists);
        for (uint256 i = 0; i < 6; ++i) {
            assertFalse(vault.usedNullifiers(N(i)));
        }
    }

    function _breakBinding(Types.WithdrawalPublicInputs memory inputs, uint256 field) internal pure {
        if (field == 0) inputs.protocolVersion += 1;
        if (field == 1) inputs.chainId += 1;
        if (field == 2) inputs.contractAddress = address(0xdead);
        if (field == 3) inputs.stateSigningKeyX += 1;
        if (field == 4) inputs.stateSigningKeyY += 1;
        if (field == 5) inputs.clearanceSigningKeyX += 1;
        if (field == 6) inputs.clearanceSigningKeyY += 1;
    }

    function _breakBinding(Types.RequestPublicInputs memory inputs, uint256 field) internal pure {
        if (field == 0) inputs.protocolVersion += 1;
        if (field == 1) inputs.chainId += 1;
        if (field == 2) inputs.contractAddress = address(0xdead);
        if (field == 3) inputs.stateSigningKeyX += 1;
        if (field == 4) inputs.stateSigningKeyY += 1;
    }
}
