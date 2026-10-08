// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev Rust-generated proofs, real verifier and normal vault deployment.
/// Regenerate test/fixtures/vault-challenge.json with vault_challenge_fixture.rs.
contract ZkApiVaultGroth16Test is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    address constant DEPLOYER = address(0xf00d);
    address constant USER = 0x1111111111111111111111111111111111111111;
    address constant TREASURY = address(0xbeef);

    Groth16ProofAdapter adapter;
    ZkApiVault vault;
    string fixtures;
    uint256[32] emptySiblings;

    function setUp() public {
        vm.chainId(31_337);
        vm.warp(2_000_000_000);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        assertEq(vm.parseJsonString(fixtures, ".circuit_id"), "zkapi-v2-note-bound-v1");
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.hash3(DOMAIN_NODE, zero, zero);
        }
        adapter = new Groth16ProofAdapter();
        (Types.WithdrawalPublicInputs memory parameters,) = _withdrawal("escape_after_deposit");
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(adapter),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY,
            address(this)
        );
        assertEq(address(vault), parameters.contractAddress);
        vm.deal(USER, 2 * uint256(DEPOSIT) * 1 gwei);
    }

    function test_realHistoricalRequestChallengesAfterDeposit() public {
        _depositA();
        (Types.RequestPublicInputs memory request, bytes memory requestProof) = _request("request_before_deposit");
        assertEq(request.activeRoot, vault.currentRoot());
        adapter.assertValidRequest(request, requestProof);
        _depositB();
        uint256 restoredRoot = vault.currentRoot();
        assertNotEq(request.activeRoot, restoredRoot);
        (Types.WithdrawalPublicInputs memory withdrawal, bytes memory withdrawalProof) =
            _withdrawal("escape_after_deposit");
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vault.initiateEscapeWithdrawal(withdrawal, withdrawalProof, siblings);
        _challenge(request, requestProof, siblings, restoredRoot);
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
        assertEq(USER.balance, 0);
        assertEq(TREASURY.balance, 0);
    }

    function test_realHistoricalRequestChallengesAfterClose() public {
        _depositA();
        _depositB();
        (Types.RequestPublicInputs memory request, bytes memory requestProof) = _request("request_before_close");
        assertEq(request.activeRoot, vault.currentRoot());
        adapter.assertValidRequest(request, requestProof);
        (Types.WithdrawalPublicInputs memory other, bytes memory otherProof) = _withdrawal("close_b");
        vault.mutualClose(other, otherProof, _siblingsWithOtherLeaf(0));
        uint256 restoredRoot = vault.currentRoot();
        assertNotEq(request.activeRoot, restoredRoot);
        (Types.WithdrawalPublicInputs memory withdrawal, bytes memory withdrawalProof) =
            _withdrawal("escape_after_close");
        vault.initiateEscapeWithdrawal(withdrawal, withdrawalProof, emptySiblings);
        _challenge(request, requestProof, emptySiblings, restoredRoot);
        (,,, Types.NoteStatus otherStatus,) = vault.notes(1);
        assertEq(uint256(otherStatus), uint256(Types.NoteStatus.Closed));
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
        assertEq(USER.balance, uint256(DEPOSIT) * 1 gwei);
        assertEq(TREASURY.balance, 0);
    }

    function test_realHistoricalRequestCannotHaveItsRootRewritten() public {
        _depositA();
        (Types.RequestPublicInputs memory request, bytes memory requestProof) = _request("request_before_deposit");
        _depositB();
        request.activeRoot = vault.currentRoot();
        (Types.WithdrawalPublicInputs memory withdrawal, bytes memory withdrawalProof) =
            _withdrawal("escape_after_deposit");
        uint256[32] memory siblings = _siblingsWithOtherLeaf(1);
        vault.initiateEscapeWithdrawal(withdrawal, withdrawalProof, siblings);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, request, requestProof, siblings);
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.PendingWithdrawal));
    }

    function _depositA() private {
        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_a_registration");
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT, emptySiblings);
    }

    function _depositB() private {
        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_b_registration");
        uint256[32] memory siblings = _siblingsWithOtherLeaf(0);
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT, siblings);
    }

    function _siblingsWithOtherLeaf(uint32 otherNoteId) private view returns (uint256[32] memory siblings) {
        siblings = emptySiblings;
        (bytes32 commitment, uint128 amount, uint64 expiry,,) = vault.notes(otherNoteId);
        siblings[0] = NoteLeafLib.computeLeaf(otherNoteId, commitment, amount, expiry);
    }

    function _request(string memory name) private view returns (Types.RequestPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.RequestPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _withdrawal(string memory name) private view returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.WithdrawalPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _challenge(
        Types.RequestPublicInputs memory request,
        bytes memory proof,
        uint256[32] memory siblings,
        uint256 restoredRoot
    ) private {
        (,,,,, uint64 deadline) = vault.pendingWithdrawals(0);
        vm.warp(deadline - 1);
        vm.prank(TREASURY);
        vault.challengeEscapeWithdrawal(0, request, proof, siblings);
        assertEq(vault.currentRoot(), restoredRoot);
        (,,, Types.NoteStatus status,) = vault.notes(0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        (bool exists,,,,,) = vault.pendingWithdrawals(0);
        assertFalse(exists);
        assertTrue(vault.usedNullifiers(request.requestNullifier));
        vm.warp(deadline);
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
    }
}
