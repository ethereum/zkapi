// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Bn254Poseidon} from "../../src/libraries/Bn254Poseidon.sol";
import {MerkleUpdateLib} from "../../src/libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "../../src/libraries/NoteLeafLib.sol";
import {MockProofAdapter} from "../mocks/MockProofAdapters.sol";

/// @dev A vault with the MockProofAdapter (every withdrawal verifies; a request verifies once
///      registered) and builders for its statements. Nullifiers are arbitrary nonzero numbers:
///      the mock does not relate them to states. Times come from vm.getBlockTimestamp(): via-IR
///      may reuse a block.timestamp read from before a warp.
abstract contract VaultTestBase is Test {
    uint256 internal constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465; // "zkapi.v2.node"
    uint256 internal constant SCALAR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint128 internal constant DEPOSIT = 1_000_000;
    uint256 internal constant STATE_X = 11;
    uint256 internal constant STATE_Y = 12;
    uint256 internal constant CLEAR_X = 13;
    uint256 internal constant CLEAR_Y = 14;
    uint64 internal constant CHALLENGE_PERIOD = 24 hours;
    uint64 internal constant MAX_PAUSE = 7 days;
    uint64 internal constant VALIDITY = 3 hours;
    uint8 internal constant KIND_ESCAPE = 0;
    uint8 internal constant KIND_CLOSE = 1;
    uint8 internal constant KIND_OWNERSHIP = 2;
    bytes internal constant PROOF = hex"cafe";

    MockProofAdapter internal adapter;
    ZkApiVault internal vault;
    address internal user = address(0x1234);
    address internal treasury = address(0x5678);
    address internal challenger = address(0xBEEF);
    uint256[32] internal emptySiblings;

    function _setUpVault() internal {
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = MerkleUpdateLib.zeroHash(level);
        }
        adapter = new MockProofAdapter();
        vault = _newVault(CHALLENGE_PERIOD, MAX_PAUSE);
        vm.deal(user, 100 ether);
    }

    function _newVault(uint64 challengePeriod, uint64 maxPauseDuration) internal returns (ZkApiVault) {
        return new ZkApiVault(
            treasury,
            30 days,
            challengePeriod,
            100_000,
            address(adapter),
            STATE_X,
            STATE_Y,
            CLEAR_X,
            CLEAR_Y,
            address(this),
            maxPauseDuration
        );
    }

    // ------------------------------------------------------------------- deposits and paths

    /// Deposits a note with `commitment` at the next slot.
    function _deposit(uint256 commitment) internal returns (uint32 id) {
        id = vault.nextNoteId();
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(commitment), DEPOSIT);
    }

    /// The node hash of the note tree.
    function _node(uint256 left, uint256 right) internal pure returns (uint256) {
        return Bn254Poseidon.compress(DOMAIN_NODE, left, right);
    }

    function _leafOf(uint32 noteId) internal view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiryTs,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
    }

    /// The leaf the tree holds at `index`, given which leaves were retired.
    function _treeLeaf(uint32 index) internal view returns (uint256) {
        if (index >= vault.nextNoteId() || retired[index]) return 0;
        return _leafOf(index);
    }

    mapping(uint32 => bool) internal retired;

    /// Live-tree siblings for slots 0..7 (the path retireClosedLeaf takes); later slots are empty.
    function _path(uint32 index) internal view returns (uint256[32] memory siblings) {
        require(index < 8, "test tree");
        siblings = emptySiblings;
        siblings[0] = _treeLeaf(index ^ 1);
        uint32 pair = (index >> 1) ^ 1;
        siblings[1] = _node(_treeLeaf(pair * 2), _treeLeaf(pair * 2 + 1));
        uint32 quad = (index >> 2) ^ 1;
        siblings[2] = _node(
            _node(_treeLeaf(quad * 4), _treeLeaf(quad * 4 + 1)), _node(_treeLeaf(quad * 4 + 2), _treeLeaf(quad * 4 + 3))
        );
    }

    function _retire(uint32 noteId) internal {
        uint256[32] memory path = _path(noteId);
        vault.retireClosedLeaf(noteId, path);
        retired[noteId] = true;
    }

    // ------------------------------------------------------------------------- statements

    function _withdrawal(
        uint8 kind,
        uint32 noteId,
        uint256 nullifier,
        uint256 next,
        uint128 finalBalance,
        uint128 conceded
    ) internal view returns (Types.WithdrawalPublicInputs memory) {
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
            finalBalance: finalBalance,
            destination: user,
            withdrawalNullifier: nullifier,
            kind: kind,
            nextNullifier: next,
            conceded: conceded,
            validUntil: uint64(vm.getBlockTimestamp()) + VALIDITY
        });
    }

    /// An escape from the state at `nullifier` (successor nullifier `next`) with balance
    /// finalBalance + conceded.
    function _escape(uint32 noteId, uint256 nullifier, uint256 next, uint128 finalBalance, uint128 conceded)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return _withdrawal(KIND_ESCAPE, noteId, nullifier, next, finalBalance, conceded);
    }

    function _close(uint32 noteId, uint256 nullifier, uint128 finalBalance)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory)
    {
        return _withdrawal(KIND_CLOSE, noteId, nullifier, 0, finalBalance, 0);
    }

    function _request(uint256 nullifier, uint128 solvencyBound)
        internal
        view
        returns (Types.RequestPublicInputs memory)
    {
        return Types.RequestPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            activeRoot: vault.currentRoot(),
            stateSigningKeyX: STATE_X,
            stateSigningKeyY: STATE_Y,
            requestTime: uint64(vm.getBlockTimestamp()),
            solvencyBound: solvencyBound,
            requestNullifier: nullifier,
            authorizationTag: 103,
            anonymousCommitmentX: 104,
            anonymousCommitmentY: 105
        });
    }

    /// A request proof at `nullifier` that the mock adapter accepts (the operator's evidence).
    function _evidence(uint256 nullifier, uint128 solvencyBound)
        internal
        returns (Types.RequestPublicInputs memory request)
    {
        request = _request(nullifier, solvencyBound);
        adapter.acceptRequest(request, PROOF);
    }

    /// expectRevert with the statement built first: building it calls the vault, and
    /// expectRevert applies to the next call.
    function _escapeReverts(Types.WithdrawalPublicInputs memory inputs, bytes4 err) internal {
        vm.expectRevert(err);
        vault.initiateEscapeWithdrawal(inputs, PROOF);
    }

    function _closeReverts(Types.WithdrawalPublicInputs memory inputs, bytes4 err) internal {
        vm.expectRevert(err);
        vault.mutualClose(inputs, PROOF);
    }

    // ------------------------------------------------------------------------------ reads

    function _status(uint32 noteId) internal view returns (Types.NoteStatus status) {
        (,,, status) = vault.notes(noteId);
    }

    function _deadline(uint32 noteId) internal view returns (uint64 deadline) {
        (,,,,, deadline) = vault.pendingWithdrawals(noteId);
    }

    function _pendingFinalBalance(uint32 noteId) internal view returns (uint128 finalBalance) {
        (,,, finalBalance,,) = vault.pendingWithdrawals(noteId);
    }

    function _concession(uint32 noteId) internal view returns (uint256 next, uint128 stateBalance, uint128 conceded) {
        (next, stateBalance, conceded) = vault.pendingConcessions(noteId);
    }
}
