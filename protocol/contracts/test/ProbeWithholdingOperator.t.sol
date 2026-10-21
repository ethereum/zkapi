// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";

/// @dev Regression of the closure-audit probe ProbeWithholdingOperator. On the note-bound vault
///      (circuit zkapi-v2-note-bound-v1) a withholding operator defeated every escape the owner
///      could build and swept the whole deposit: "treasury gain (gwei): 777777". With the
///      concession exit the treasury gains exactly D - (B_k - sb_k): the charges the owner already
///      paid plus at most the bound of the request whose successor was withheld.
///      The owner's states S_0..S_k have nullifiers 100 + i; the operator archived every request
///      R_0..R_k the owner sent (R_i at N_i, bound sb_i) and withholds S_{k+1}.
contract ProbeWithholdingOperator is VaultTestBase {
    uint128 constant D = 777_777;
    uint128 constant SB = 100_000;

    function setUp() public {
        vm.warp(1_700_000_000);
        _setUpVault();
    }

    /// The probe's own scenario: one request at genesis (k = 0, B_0 = D), successor withheld,
    /// clearance refused. Gain sb_0, not D.
    function test_withholdingOperatorGainsOnlyTheBoundAtGenesis() public {
        uint256 gain = _withholdingRound(0, D, SB);
        assertEq(gain, uint256(D - (D - SB)) * 1 gwei);
        emit log_named_uint("treasury gain (gwei)", gain / 1 gwei);
    }

    /// After k = 3 served requests with charges 60,000, 150,000 and 40,000 (B_3 = 527,777).
    function test_withholdingOperatorGainsOnlyChargesPlusTheBound() public {
        uint128 balance = D - 60_000 - 150_000 - 40_000;
        uint256 gain = _withholdingRound(3, balance, SB);
        assertEq(gain, uint256(D - (balance - SB)) * 1 gwei);
        emit log_named_uint("treasury gain (gwei)", gain / 1 gwei);
    }

    /// The owner escapes early with c = 0; the operator's raise with R_k reaches at most sb_k,
    /// so the gain is the same bound.
    function test_raiseAfterAnEarlyEscapeIsCappedAtTheBound() public {
        uint128 balance = D - 60_000;
        uint32 id = _depositD();
        Types.RequestPublicInputs memory rk = _evidence(101, SB);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, balance, 0), PROOF);
        vm.prank(challenger);
        vault.raiseEscapeConcession(id, rk, PROOF, type(uint128).max);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(treasury.balance, uint256(D - (balance - SB)) * 1 gwei);
    }

    /// The honest variant: an owner who spent the successor S_{k+1} (the operator holds R_{k+1})
    /// cannot exit from S_k; its stale escape is defeated, and it exits from S_{k+1}.
    function test_spentSuccessorDefeatsTheStaleEscape() public {
        uint32 id = _depositD();
        Types.RequestPublicInputs memory successor = _evidence(102, SB);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, D, 0), PROOF);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, successor, PROOF);
        assertTrue(vault.challengedNullifiers(101));
        Types.WithdrawalPublicInputs memory again = _escape(id, 101, 102, D, SB);
        _escapeReverts(again, Errors.ChallengedNullifier.selector);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id, 102, 103, D - 50_000, 0), PROOF);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(treasury.balance, 50_000 gwei);
    }

    /// The owner at S_k escapes conceding sb_k. Every archived request is tried as a defeat and
    /// R_k as a raise; none lands. Returns the treasury's gain at finalization.
    function _withholdingRound(uint256 k, uint128 balance, uint128 bound) private returns (uint256) {
        uint32 id = _depositD();
        Types.RequestPublicInputs[] memory archived = new Types.RequestPublicInputs[](k + 1);
        for (uint256 i = 0; i <= k; ++i) {
            archived[i] = _evidence(100 + i, i == k ? bound : 200_000);
        }
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id, 100 + k, 101 + k, balance - bound, bound), PROOF);
        vm.startPrank(challenger);
        for (uint256 i = 0; i <= k; ++i) {
            vm.expectRevert(Errors.NotSuccessorEvidence.selector);
            vault.challengeEscapeWithdrawal(id, archived[i], PROOF);
        }
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(id, archived[k], PROOF, type(uint128).max);
        vm.stopPrank();
        // Expiry cannot sweep a pending escape.
        vm.warp(vault.effectiveExpiry(id));
        vm.expectRevert(Errors.NoteNotActive.selector);
        vault.claimExpired(id);
        uint256 before = treasury.balance;
        vault.finalizeEscapeWithdrawal(id);
        assertEq(user.balance, 100 ether - uint256(D) * 1 gwei + uint256(balance - bound) * 1 gwei);
        assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Closed));
        return treasury.balance - before;
    }

    function _depositD() private returns (uint32 id) {
        id = vault.nextNoteId();
        vm.prank(user);
        vault.deposit{value: uint256(D) * 1 gwei}(bytes32(uint256(42)), D);
    }
}
