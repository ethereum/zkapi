// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";

/// @dev Deposits, the basic exit lifecycle and the post-defeat grace, against the mock adapter.
contract ZkApiVaultTest is VaultTestBase {
    function setUp() public {
        _setUpVault();
    }

    function test_depositInsertsTheLeafAndRecordsTheRoot() public {
        uint256 emptyRoot = vault.currentRoot();
        assertTrue(vault.isKnownRoot(emptyRoot));
        uint256 depositedAt = 1_700_000_123;
        vm.warp(depositedAt);
        // Rounded up to the day (a literal expression would divide exactly).
        uint64 expiry = uint64(((depositedAt + 30 days + 1 days - 1) / 1 days) * 1 days);
        assertEq(expiry % 1 days, 0);
        uint256 leaf = NoteLeafLib.computeLeaf(0, bytes32(uint256(42)), DEPOSIT, expiry);
        uint256 root = leaf;
        for (uint256 level = 0; level < 32; ++level) {
            root = _hashNode(root, emptySiblings[level]);
        }
        vm.expectEmit(address(vault));
        emit Events.NoteDeposited(0, bytes32(uint256(42)), DEPOSIT, expiry, root);
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT);
        uint32 id = 0;
        assertEq(vault.nextNoteId(), 1);
        (bytes32 commitment, uint128 amount, uint64 expiryTs, Types.NoteStatus status) = vault.notes(id);
        assertEq(commitment, bytes32(uint256(42)));
        assertEq(amount, DEPOSIT);
        assertEq(expiryTs, expiry);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        assertEq(vault.currentRoot(), root);
        assertTrue(vault.knownRoots(root));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    function test_depositRejectsBadInputs() public {
        vm.startPrank(user);
        vm.expectRevert(Errors.ZeroAmount.selector);
        vault.deposit(bytes32(uint256(42)), 0);
        vm.expectRevert(Errors.InvalidCommitment.selector);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(0), DEPOSIT);
        vm.expectRevert(Errors.InvalidFelt.selector);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(type(uint256).max), DEPOSIT);
        vm.stopPrank();
        assertEq(vault.nextNoteId(), 0);
    }

    function test_depositAndMutualClose() public {
        uint32 id = _deposit(42);
        vault.mutualClose(_close(id, 99, 700_000), PROOF);
        assertEq(user.balance, 100 ether - 300_000 gwei);
        assertEq(treasury.balance, 300_000 gwei);
        assertTrue(vault.usedNullifiers(99));
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
    }

    function test_escapeWaitsThenFinalizesFromAnyAccount() public {
        uint32 id = _deposit(42);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, 800_000, 0), PROOF);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.PendingWithdrawal));
        uint64 deadline = _deadline(id);
        assertEq(deadline, uint64(vm.getBlockTimestamp() + 24 hours));
        assertTrue(vault.usedNullifiers(101));
        assertTrue(vault.usedNullifiers(102));

        vm.warp(deadline - 1);
        vm.expectRevert(Errors.ChallengeNotExpired.selector);
        vault.finalizeEscapeWithdrawal(id);
        vm.warp(deadline);
        vm.prank(address(0xbeef));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - 200_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        (bool exists,,,,,) = vault.pendingWithdrawals(id);
        assertFalse(exists);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(id);
    }

    /// k stale escapes, each from a state whose successor was spent, are defeated one by one;
    /// the newest state, never spent, still withdraws without operator help.
    function test_staleEscapesAreDefeatedAndTheNewestStateWithdraws() public {
        uint32 id = _deposit(42);
        uint256 k = 4;
        // States S_0..S_k with nullifiers 1000 + 2i; each escape from S_i is defeated by the
        // archived request at S_{i+1}'s nullifier.
        for (uint256 i = 0; i < k; ++i) {
            uint256 nullifier = 1000 + 2 * i;
            vault.initiateEscapeWithdrawal(_escape(id, nullifier, nullifier + 2, 800_000, 0), PROOF);
            Types.RequestPublicInputs memory successor = _evidence(nullifier + 2, 100_000);
            vm.prank(challenger);
            vault.challengeEscapeWithdrawal(id, successor, PROOF);
            assertFalse(vault.usedNullifiers(nullifier));
            assertTrue(vault.challengedNullifiers(nullifier));
            assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        }
        for (uint256 i = 0; i < k; ++i) {
            uint256 nullifier = 1000 + 2 * i;
            _escapeReverts(_escape(id, nullifier, nullifier + 2, 800_000, 0), Errors.ChallengedNullifier.selector);
        }
        uint256 newest = 1000 + 2 * k;
        assertFalse(vault.challengedNullifiers(newest));

        uint256 snapshot = vm.snapshotState();
        vault.mutualClose(_close(id, newest, 800_000), PROOF);
        assertEq(treasury.balance, 200_000 gwei);
        vm.revertToState(snapshot);

        // Without operator help: no evidence exists at the newest state's successor.
        vault.initiateEscapeWithdrawal(_escape(id, newest, newest + 2, 800_000, 0), PROOF);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - 200_000 gwei);
        assertEq(treasury.balance, 200_000 gwei);
    }

    function test_defeatNearExpiryGrantsGraceBeforeClaim() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(uint256(expiry) - 1 hours);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, 800_000, 0), PROOF);
        uint64 deadline = _deadline(id);
        Types.RequestPublicInputs memory successor = _evidence(102, 100_000);
        vm.warp(deadline - 1);
        vault.challengeEscapeWithdrawal(id, successor, PROOF);
        uint256 graceEnd = uint256(deadline) - 1 + vault.challengePeriod();
        assertEq(vault.effectiveExpiry(id), graceEnd);
        vm.warp(graceEnd - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(graceEnd);
        vault.claimExpired(id);
        assertEq(treasury.balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// The post-defeat grace only ever extends expiry: a defeat early in a note's life leaves its
    /// expiry where it was, rather than pulling it in to challengePeriod after the defeat.
    function test_earlyDefeatNeverLowersExpiry() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, 800_000, 0), PROOF);
        vault.challengeEscapeWithdrawal(id, _evidence(102, 100_000), PROOF);
        uint256 defeatedAt = vm.getBlockTimestamp();
        assertLt(defeatedAt + vault.challengePeriod(), expiry);
        assertEq(vault.effectiveExpiry(id), expiry);
        vm.warp(defeatedAt + vault.challengePeriod());
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(uint256(expiry) - 1);
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
        vm.warp(expiry);
        vault.claimExpired(id);
        assertEq(treasury.balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// The same at the last moment of a challenge window that closes well before expiry.
    function test_defeatAtDeadlineFarFromExpiryKeepsExpiry() public {
        uint32 id = _deposit(42);
        (,, uint64 expiry,) = vault.notes(id);
        vm.warp(vm.getBlockTimestamp() + 10 days);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, 800_000, 0), PROOF);
        Types.RequestPublicInputs memory successor = _evidence(102, 100_000);
        uint64 deadline = _deadline(id);
        vm.warp(deadline - 1);
        vault.challengeEscapeWithdrawal(id, successor, PROOF);
        assertEq(vault.effectiveExpiry(id), expiry);
        vm.warp(uint256(deadline) - 1 + vault.challengePeriod());
        vm.expectRevert(Errors.NoteNotExpired.selector);
        vault.claimExpired(id);
    }

    function _hashNode(uint256 left, uint256 right) private pure returns (uint256) {
        return Bn254Poseidon.compress(DOMAIN_NODE, left, right);
    }
}
