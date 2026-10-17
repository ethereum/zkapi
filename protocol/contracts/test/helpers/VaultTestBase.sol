// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Bn254Poseidon} from "../../src/libraries/Bn254Poseidon.sol";
import {MerkleUpdateLib} from "../../src/libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "../../src/libraries/NoteLeafLib.sol";
import {MockProofAdapter} from "../mocks/MockProofAdapters.sol";

/// @dev A vault with the MockProofAdapter (every withdrawal verifies; a request or an insertion
///      verifies once registered) and builders for its statements. Withdrawals name their note as
///      the vault stores it. The request tree is mirrored from storage (activated notes' recorded
///      leaves, retired ones zero), which gives activations their new roots and retirements and
///      on-chain activations their paths. `activator` (the operator's activation worker) submits
///      proved activations; on-chain ones first wait for the fallback to open. Nullifiers are
///      arbitrary nonzero numbers: the mock does not relate them to states. Times come from
///      vm.getBlockTimestamp(): via-IR may reuse a block.timestamp read from before a warp.
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
    address internal activator = address(0xACC);
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
        return _newVault(challengePeriod, maxPauseDuration, activator);
    }

    function _newVault(uint64 challengePeriod, uint64 maxPauseDuration, address activator_)
        internal
        returns (ZkApiVault)
    {
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
            maxPauseDuration,
            activator_
        );
    }

    // ------------------------------------------------------------------- deposits and paths

    /// Deposits a note with `commitment` at the next slot. It is recorded, not activated.
    function _deposit(uint256 commitment) internal returns (uint32 id) {
        id = vault.nextNoteId();
        vm.prank(user);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(commitment), DEPOSIT);
    }

    /// The node hash of the note tree.
    function _node(uint256 left, uint256 right) internal pure returns (uint256) {
        return Bn254Poseidon.compress(DOMAIN_NODE, left, right);
    }

    /// The recorded (immutable) leaf of note `noteId`, whatever its status.
    function _leafOf(uint32 noteId) internal view returns (uint256) {
        (bytes32 commitment, uint128 amount, uint64 expiryTs,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiryTs);
    }

    /// uint256(amount) | uint256(expiryTs) << 128: a withdrawal's noteMetadata and an insertion's M_j.
    function _metadata(uint128 amount, uint64 expiryTs) internal pure returns (uint256) {
        return uint256(amount) | (uint256(expiryTs) << 128);
    }

    /// Note `noteId`'s registration commitment and metadata as the vault stores them (zero for a
    /// note never recorded).
    function _binding(uint32 noteId) internal view returns (uint256 commitment, uint256 metadata) {
        (bytes32 c, uint128 amount, uint64 expiryTs,) = vault.notes(noteId);
        return (uint256(c), _metadata(amount, expiryTs));
    }

    /// Notes whose leaf _retire zeroed.
    mapping(uint32 => bool) internal retired;

    /// The request tree mirrored from storage with notes 0 .. activated - 1 appended (retired
    /// leaves zero): its root and the siblings of slot `index`. Hashes about max(activated, index)
    /// nodes plus a path, enough for the few dozen notes a test records.
    function _mirror(uint256 activated, uint32 index)
        internal
        view
        returns (uint256 root, uint256[32] memory siblings)
    {
        uint256 width = activated > index ? activated : uint256(index) + 1;
        uint256[] memory nodes = new uint256[](width);
        for (uint256 i = 0; i < activated; ++i) {
            if (!retired[uint32(i)]) nodes[i] = _leafOf(uint32(i));
        }
        uint256 position = index;
        for (uint256 level = 0; level < 32; ++level) {
            uint256 empty = MerkleUpdateLib.zeroHash(level);
            siblings[level] = (position ^ 1) < width ? nodes[position ^ 1] : empty;
            uint256 parents = (width + 1) / 2;
            for (uint256 i = 0; i < parents; ++i) {
                nodes[i] = _node(nodes[2 * i], 2 * i + 1 < width ? nodes[2 * i + 1] : empty);
            }
            width = parents;
            position >>= 1;
        }
        root = nodes[0];
    }

    /// The siblings of slot `index` in the vault's request tree (activateNotesOnChain takes those
    /// of the first slot it fills, retireClosedLeaf those of the leaf it zeroes).
    function _path(uint32 index) internal view returns (uint256[32] memory siblings) {
        (, siblings) = _mirror(vault.activationCursor(), index);
    }

    /// The mirrored root of the vault's request tree, which must equal currentRoot.
    function _mirrorRoot() internal view returns (uint256 root) {
        (root,) = _mirror(vault.activationCursor(), 0);
    }

    function _retire(uint32 noteId) internal {
        uint256[32] memory path = _path(noteId);
        vault.retireClosedLeaf(noteId, path);
        retired[noteId] = true;
    }

    // ------------------------------------------------------------------------- activation

    /// The insertion statement activateNotes must build for notes first .. first + count - 1, read
    /// back from the vault: [oldRoot, newRoot, first, C_0, M_0, ..., C_{count-1}, M_{count-1}].
    function _insertionInputs(uint32 first, uint256 count, uint256 oldRoot, uint256 newRoot)
        internal
        view
        returns (uint256[] memory inputs)
    {
        inputs = new uint256[](3 + 2 * count);
        inputs[0] = oldRoot;
        inputs[1] = newRoot;
        inputs[2] = first;
        for (uint256 j = 0; j < count; ++j) {
            (inputs[3 + 2 * j], inputs[4 + 2 * j]) = _binding(uint32(first + j));
        }
    }

    /// Prepares a proved activation of the next `count` notes as the operator's worker does, from
    /// the state now: the mirrored root with them appended, and their insertion statement
    /// registered with the mock adapter (PROOF then verifies for exactly that statement).
    function _prepareActivation(uint256 count) internal returns (uint32 first, uint256 oldRoot, uint256 newRoot) {
        first = vault.activationCursor();
        oldRoot = vault.currentRoot();
        (newRoot,) = _mirror(uint256(first) + count, 0);
        adapter.acceptInsertion(count, _insertionInputs(first, count, oldRoot, newRoot), PROOF);
    }

    /// Activates the next `count` notes with a (mock) insertion proof from the activator; returns
    /// the new root.
    function _activate(uint256 count) internal returns (uint256 newRoot) {
        (uint32 first, uint256 oldRoot, uint256 root) = _prepareActivation(count);
        vm.prank(activator);
        vault.activateNotes(first, count, oldRoot, root, PROOF);
        return root;
    }

    /// Warps to activationFallbackOpensAt if the on-chain fallback is not open yet.
    function _openFallback() internal {
        uint64 opensAt = vault.activationFallbackOpensAt();
        if (vm.getBlockTimestamp() < opensAt) vm.warp(opensAt);
    }

    /// Activates the next `count` notes on-chain, with the mirrored siblings of the first slot,
    /// once the fallback is open (up to ACTIVATION_FALLBACK_DELAY later).
    function _activateOnChain(uint256 count) internal {
        _openFallback();
        uint32 first = vault.activationCursor();
        uint256[32] memory siblings = _path(first);
        vault.activateNotesOnChain(first, count, siblings);
    }

    /// Activates every recorded note with proofs, in the largest aligned batches that fit.
    function _activateAll() internal {
        for (uint256 cursor = vault.activationCursor(); cursor < vault.nextNoteId(); cursor = vault.activationCursor()) {
            uint256 pending = vault.nextNoteId() - cursor;
            if (cursor % 16 == 0 && pending >= 16) _activate(16);
            else if (cursor % 4 == 0 && pending >= 4) _activate(4);
            else _activate(1);
        }
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
        (uint256 commitment, uint256 metadata) = _binding(noteId);
        return Types.WithdrawalPublicInputs({
            protocolVersion: 2,
            chainId: uint64(block.chainid),
            contractAddress: address(vault),
            registrationCommitment: commitment,
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
            validUntil: uint64(vm.getBlockTimestamp()) + VALIDITY,
            noteMetadata: metadata
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
        (,,,, deadline) = vault.pendingWithdrawals(noteId);
    }

    function _pendingFinalBalance(uint32 noteId) internal view returns (uint128 finalBalance) {
        (,, finalBalance,,) = vault.pendingWithdrawals(noteId);
    }

    function _concession(uint32 noteId) internal view returns (uint256 next, uint128 stateBalance, uint128 conceded) {
        (next, stateBalance, conceded) = vault.pendingConcessions(noteId);
    }
}
