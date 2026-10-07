// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Isolates vault checks; the real adapter has separate Groth16 fixture tests.
contract MockProofAdapter is IZkApiProofAdapter {
    bytes32 private acceptedRequest;

    function acceptRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external {
        acceptedRequest = keccak256(abi.encode(inputs, proof));
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view {
        if (keccak256(abi.encode(inputs, proof)) != acceptedRequest) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

contract ZkApiVaultTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint256 constant STATE_X = 11;
    uint256 constant STATE_Y = 12;
    uint256 constant CLEAR_X = 13;
    uint256 constant CLEAR_Y = 14;

    MockProofAdapter adapter;
    ZkApiVault vault;
    address user = address(0x1234);
    address treasury = address(0x5678);
    uint256[32] emptySiblings;

    function setUp() public {
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        adapter = new MockProofAdapter();
        vault = new ZkApiVault(
            treasury, 30 days, 24 hours, 100_000, address(adapter), STATE_X, STATE_Y, CLEAR_X, CLEAR_Y, address(this)
        );
        vm.deal(user, uint256(DEPOSIT) * 1 gwei);
    }

    function test_depositAndMutualClose() public {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
        uint256 depositedRoot = vault.currentRoot();

        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: depositedRoot,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: 0,
            finalBalance: 700_000,
            destination: user,
            withdrawalNullifier: 99,
            hasClearance: true,
            withdrawalTag: 100
        });
        vault.mutualClose(inputs, "", emptySiblings);
        assertEq(user.balance, 700_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
        assertTrue(vault.usedNullifiers(99));
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    function test_escapeHatchWaitsThenFinalizesFromAnyAccount() public {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
        uint256 depositedRoot = vault.currentRoot();

        Types.WithdrawalPublicInputs memory inputs = Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: depositedRoot,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: 0,
            finalBalance: 800_000,
            destination: user,
            withdrawalNullifier: 101,
            hasClearance: false,
            withdrawalTag: 102
        });
        vault.initiateEscapeWithdrawal(inputs, "", emptySiblings);

        (,,, Types.NoteStatus pendingStatus,) = vault.notes(0);
        assertEq(uint256(pendingStatus), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        assertEq(deadline, uint64(block.timestamp + 24 hours));
        assertTrue(vault.usedNullifiers(101));

        vm.expectRevert(Errors.ChallengeNotExpired.selector);
        vault.finalizeEscapeWithdrawal(0);

        vm.warp(deadline);
        vm.prank(address(0xbeef));
        vault.finalizeEscapeWithdrawal(0);

        assertEq(user.balance, 800_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
        (,,, Types.NoteStatus finalStatus,) = vault.notes(0);
        assertEq(uint256(finalStatus), uint256(Types.NoteStatus.Closed));
        (bool stillExists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(stillExists);
    }

    function test_challengesRequestAtEscapeRoot() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _initiateEscape(emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
    }

    function test_challengesHistoricalRequestAfterUnrelatedDeposit() public {
        _depositFirstNote();
        Types.RequestPublicInputs memory request = _archiveRequest();
        _depositSecondNote();
        uint256 escapeRoot = vault.currentRoot();
        assertNotEq(escapeRoot, request.activeRoot);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);

        _initiateEscape(siblings);
        _challengeAndAssertRestored(request, siblings, escapeRoot);
        (,,, Types.NoteStatus otherStatus,) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Active));
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
    }

    function test_challengesHistoricalRequestAfterUnrelatedClose() public {
        _depositFirstNote();
        _depositSecondNote();
        Types.RequestPublicInputs memory request = _archiveRequest();

        Types.WithdrawalPublicInputs memory other = _withdrawalInputs(1, 202, true);
        vault.mutualClose(other, "", _siblingsWithOtherLeaf(0));
        uint256 escapeRoot = vault.currentRoot();
        assertNotEq(escapeRoot, request.activeRoot);

        _initiateEscape(emptySiblings);
        _challengeAndAssertRestored(request, emptySiblings, escapeRoot);
        (,,, Types.NoteStatus otherStatus,) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Closed));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_historicalChallengeRestoresAgainstTreeChangedWhilePending() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        Types.WithdrawalPublicInputs memory other = _withdrawalInputs(1, 202, true);
        vault.mutualClose(other, "", emptySiblings);

        _challengeAndAssertRestored(request, emptySiblings, request.activeRoot);
        (,,, Types.NoteStatus otherStatus,) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Closed));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_historicalChallengeRejectsDifferentNullifier() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        request.requestNullifier += 1;
        adapter.acceptRequest(request, hex"cafe");
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);

        vm.expectRevert(Errors.ReplayedNullifier.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
    }

    function test_historicalChallengePreservesDeploymentAndKeyBinding() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        for (uint256 field = 0; field < 5; ++field) {
            Types.RequestPublicInputs memory invalid = _requestInputs(request.activeRoot);
            if (field == 0) invalid.protocolVersion += 1;
            if (field == 1) invalid.chainId += 1;
            if (field == 2) invalid.contractAddress = address(0xdead);
            if (field == 3) invalid.stateSigningKeyX += 1;
            if (field == 4) invalid.stateSigningKeyY += 1;
            // Even evidence accepted by the adapter must match this deployment.
            adapter.acceptRequest(invalid, hex"cafe");

            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            vault.challengeEscapeWithdrawal(0, invalid, hex"cafe", siblings);
            _assertPending();
        }
    }

    function test_historicalChallengeStillVerifiesOriginalProofAndRoot() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"bad0", siblings);
        _assertPending();

        // Replacing the archived root must not bypass the adapter verification.
        (, uint256 escapeRoot,,,,) = vault.pendingWithdrawals(0);
        request.activeRoot = escapeRoot;
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
    }

    function test_historicalChallengeStillRequiresCurrentRestorationWitness() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", emptySiblings);
        _assertPending();
    }

    function test_historicalChallengeStillExpiresAtDeadline() public {
        Types.RequestPublicInputs memory request = _pendingAfterRootChange();
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vm.warp(deadline);
        vm.expectRevert(Errors.ChallengeExpired.selector);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        _assertPending();
        vault.finalizeEscapeWithdrawal(0);
        assertEq(user.balance, 800_000 gwei);
    }

    function test_escapeStillRejectsStaleRootAfterUnrelatedDeposit() public {
        _depositFirstNote();
        Types.WithdrawalPublicInputs memory withdrawal = _withdrawalInputs(0, 101, false);
        _depositSecondNote();
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.initiateEscapeWithdrawal(withdrawal, "", siblings);
    }

    function _depositFirstNote() private {
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT, emptySiblings);
    }

    function _depositSecondNote() private {
        vm.deal(user, user.balance + uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory siblings = _siblingsWithOtherLeaf(0);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(43)), DEPOSIT, siblings);
    }

    function _siblingsWithOtherLeaf(uint32 otherNoteId) private view returns (uint256[32] memory siblings) {
        siblings = emptySiblings;
        (bytes32 commitment, uint128 amount, uint64 expiryTs,,) = vault.notes(otherNoteId);
        siblings[0] = NoteLeafLib.computeLeaf(otherNoteId, commitment, amount, expiryTs);
    }

    function _requestInputs(uint256 root) private view returns (Types.RequestPublicInputs memory) {
        return Types.RequestPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: root,
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            requestTime: uint64(block.timestamp),
            solvencyBound: 100_000,
            requestNullifier: 101,
            authorizationTag: 103,
            anonymousCommitmentX: 104,
            anonymousCommitmentY: 105
        });
    }

    function _archiveRequest() private returns (Types.RequestPublicInputs memory request) {
        request = _requestInputs(vault.currentRoot());
        adapter.acceptRequest(request, hex"cafe");
        adapter.assertValidRequest(request, hex"cafe");
    }

    function _withdrawalInputs(uint32 noteId, uint256 nullifier, bool clearance)
        private
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            clearanceSigningKeyX: CLEAR_X,
            clearanceSigningKeyY: CLEAR_Y,
            noteId: noteId,
            finalBalance: 800_000,
            destination: user,
            withdrawalNullifier: nullifier,
            hasClearance: clearance,
            withdrawalTag: 102
        });
    }

    function _initiateEscape(uint256[32] memory siblings) private {
        vault.initiateEscapeWithdrawal(_withdrawalInputs(0, 101, false), "", siblings);
    }

    function _pendingAfterRootChange() private returns (Types.RequestPublicInputs memory request) {
        _depositFirstNote();
        request = _archiveRequest();
        _depositSecondNote();
        _initiateEscape(_siblingsWithOtherLeaf(1));
    }

    function _assertPending() private view {
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertTrue(exists);
        assertTrue(vault.usedNullifiers(101));
    }

    function _challengeAndAssertRestored(
        Types.RequestPublicInputs memory request,
        uint256[32] memory siblings,
        uint256 expectedRoot
    ) private {
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        // Archived authorizations need not be fresh when the challenge arrives.
        vm.warp(deadline - 1);
        vm.prank(treasury);
        vault.challengeEscapeWithdrawal(0, request, hex"cafe", siblings);
        assertEq(vault.currentRoot(), expectedRoot);
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertTrue(vault.usedNullifiers(101));
        vm.warp(deadline);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
    }

    function test_claimExpiredExtendsByPausedTimeDuringNoteLifetime() public {
        // Pre-deposit pause should not count toward Alice's extension.
        vault.pause();
        vm.warp(block.timestamp + 5 days);
        vault.unpause();
        assertEq(vault.totalPausedTime(), 5 days);

        _depositFirstNote();
        (,, uint64 aliceExpiry,, uint64 aliceSnapshot) = vault.notes(0);
        assertEq(aliceSnapshot, 5 days);

        vault.pause();
        vm.warp(block.timestamp + 2 days);
        vault.unpause();

        address bob = address(0xB0B);
        vm.deal(bob, uint256(DEPOSIT) * 1 gwei);
        uint256[32] memory bobSiblings = _siblingsWithOtherLeaf(0);
        vm.prank(bob);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(43)), DEPOSIT, bobSiblings);
        (,, uint64 bobExpiry,, uint64 bobSnapshot) = vault.notes(1);
        assertEq(bobSnapshot, 7 days);

        vault.pause();
        vm.warp(block.timestamp + 3 days);
        vault.unpause();
        assertEq(vault.totalPausedTime(), 10 days);

        // Alice lived through pauses #2+#3 (5d); Bob only through #3 (3d).
        uint256 aliceExtension = uint256(vault.totalPausedTime()) - uint256(aliceSnapshot);
        uint256 bobExtension = uint256(vault.totalPausedTime()) - uint256(bobSnapshot);
        assertEq(aliceExtension, 5 days);
        assertEq(bobExtension, 3 days);

        uint256 aliceEffective = uint256(aliceExpiry) + aliceExtension;
        uint256 bobEffective = uint256(bobExpiry) + bobExtension;

        // Original expiry is not enough for either note.
        uint256[32] memory aliceSiblings = _siblingsWithOtherLeaf(1);
        uint256[32] memory bobSiblingsForClaim = _siblingsWithOtherLeaf(0);

        vm.warp(uint256(aliceExpiry));
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, aliceSiblings);
        vm.warp(uint256(bobExpiry));
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(1, bobSiblingsForClaim);

        // Claim Alice first (longer extension from earlier deposit), then Bob.
        vm.warp(aliceEffective - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, aliceSiblings);

        vm.warp(aliceEffective);
        vault.claimExpired(0, aliceSiblings);
        (,,, Types.NoteStatus aliceStatus,) = vault.notes(0);
        assertEq(uint256(aliceStatus), uint256(Types.NoteStatus.Closed));

        vm.warp(bobEffective - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(1, emptySiblings);

        vm.warp(bobEffective);
        vault.claimExpired(1, emptySiblings);
        (,,, Types.NoteStatus bobStatus,) = vault.notes(1);
        assertEq(uint256(bobStatus), uint256(Types.NoteStatus.Closed));
        assertEq(treasury.balance, 2 * uint256(DEPOSIT) * 1 gwei);
    }

    function test_claimExpiredBlockedWhilePausedPastOriginalExpiry() public {
        _depositFirstNote();
        (,, uint64 expiryTs,,) = vault.notes(0);

        vault.pause();
        vm.warp(uint256(expiryTs) + 1 days);

        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);

        // Live pause continues to extend every second.
        vm.warp(block.timestamp + 10 days);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(0, emptySiblings);

        vault.unpause();
        // After unpause, extension freezes at the completed pause duration.
        vm.warp(uint256(expiryTs) + vault.totalPausedTime());
        vault.claimExpired(0, emptySiblings);
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
    }

    function test_pauseCannotResetPausedAtWhileAlreadyPaused() public {
        vault.pause();
        uint64 firstPausedAt = vault.pausedAt();
        vm.warp(block.timestamp + 1 days);
        vm.expectRevert(Errors.Paused.selector);
        vault.pause();
        assertEq(vault.pausedAt(), firstPausedAt);

        vault.unpause();
        assertEq(vault.totalPausedTime(), 1 days);
        assertEq(vault.pausedAt(), 0);
        assertFalse(vault.paused());

        vm.expectRevert(Errors.NotPaused.selector);
        vault.unpause();
    }
}
