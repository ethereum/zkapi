// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";

/// @dev Activation (vault revision 4) against the mock adapter. Recorded notes are appended to the
///      request tree in id order, in aligned batches of 1, 4 or 16: proved (activateNotes, whose
///      insertion statement the vault builds from its records, so the mock, which accepts only the
///      exact statement a test registered, sees [oldRoot, newRoot, first, C_0, M_0, ...]) or
///      on-chain (activateNotesOnChain). Both are permissionless. Every root is checked against
///      VaultTestBase's mirror of the tree, built from the vault's records.
contract ZkApiVaultActivationTest is VaultTestBase {
    address constant WORKER = address(0xACC);
    address constant STRANGER = address(0x5157);

    function setUp() public {
        vm.warp(1_700_000_000);
        _setUpVault();
    }

    // ============================================================== proved activation

    /// One batch of each size from an empty tree: the vault hands the adapter exactly the
    /// statement built from its records, sets the proved root, advances the cursor and emits
    /// NotesActivated(proved = true); the notes' records and statuses do not change.
    function test_provedActivationOfEachSize() public {
        uint256[3] memory sizes = [uint256(1), 4, 16];
        for (uint256 s = 0; s < sizes.length; ++s) {
            uint256 snapshot = vm.snapshotState();
            uint256 count = sizes[s];
            _depositMany(count);
            (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(count);
            assertEq(first, 0);
            assertEq(oldRoot, MerkleUpdateLib.EMPTY_ROOT);
            uint256[] memory inputs = _insertionInputs(first, count, oldRoot, newRoot);
            assertEq(inputs.length, 3 + 2 * count);
            vm.expectCall(
                address(adapter), abi.encodeCall(IZkApiProofAdapter.assertValidInsertion, (count, inputs, PROOF))
            );
            vm.expectEmit(address(vault));
            emit Events.NotesActivated(0, uint32(count), newRoot, true);
            vm.prank(WORKER);
            vault.activateNotes(first, count, oldRoot, newRoot, PROOF);
            assertEq(vault.activationCursor(), count);
            assertEq(vault.currentRoot(), newRoot);
            assertEq(vault.currentRoot(), _mirrorRoot());
            assertTrue(vault.isActivated(uint32(count - 1)));
            assertFalse(vault.isActivated(uint32(count)));
            for (uint32 id = 0; id < count; ++id) {
                assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
            }
            vm.revertToState(snapshot);
        }
    }

    /// Batches of every size in one tree, each aligned to its size at the cursor:
    /// 1, 1, 1, 1, 4, 4, 4, 16, 1, 1, 1, 1 (36 notes).
    function test_provedActivationOfMixedSizes() public {
        _depositMany(36);
        uint256[12] memory batches = [uint256(1), 1, 1, 1, 4, 4, 4, 16, 1, 1, 1, 1];
        for (uint256 i = 0; i < batches.length; ++i) {
            uint32 first = vault.activationCursor();
            uint256 newRoot = _activate(batches[i]);
            assertEq(vault.activationCursor(), first + batches[i]);
            assertEq(newRoot, _mirrorRoot());
        }
        assertEq(vault.activationCursor(), 36);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// The statement names every note as recorded, so a proof of anything else does not verify:
    /// a statement with another commitment or metadata for a note, another first note, the notes
    /// in another order or another root is refused InvalidProof, and nothing changes.
    function test_provedActivationVerifiesTheStatementBuiltFromStorage() public {
        _depositMany(4);
        uint256 oldRoot = vault.currentRoot();
        (uint256 newRoot,) = _mirror(4, 0);
        uint256[] memory honest = _insertionInputs(0, 4, oldRoot, newRoot);
        for (uint256 variant = 0; variant < 5; ++variant) {
            uint256[] memory forged = _insertionInputs(0, 4, oldRoot, newRoot);
            if (variant == 0) forged[3] += 1;
            if (variant == 1) forged[4] += 1;
            if (variant == 2) forged[2] = 4;
            if (variant == 3) (forged[3], forged[5]) = (honest[5], honest[3]);
            if (variant == 4) forged[0] += 1;
            adapter.acceptInsertion(4, forged, PROOF);
        }
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot, PROOF);
        // A root the proof was not made for, and another proof of the right statement.
        adapter.acceptInsertion(4, honest, PROOF);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot + 1, PROOF);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot, hex"bad0");
        assertEq(vault.activationCursor(), 0);
        assertEq(vault.currentRoot(), MerkleUpdateLib.EMPTY_ROOT);
        vm.prank(STRANGER);
        vault.activateNotes(0, 4, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), newRoot);
    }

    // ================================================================ stale and invalid

    /// A competing activation that lands first moves the cursor, so a prepared one names a stale
    /// first note: StaleActivation, before verification. Rebuilt from the new state it lands.
    function test_competingActivationMakesAPreparedOneStale() public {
        _depositMany(5);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(4);
        _activateOnChain(1);
        vm.expectRevert(Errors.StaleActivation.selector);
        vm.prank(WORKER);
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        // The same batch rebuilt from the new cursor is misaligned; the next singleton lands.
        uint256 root = vault.currentRoot();
        vm.expectRevert(Errors.InvalidActivation.selector);
        vault.activateNotes(1, 4, root, newRoot, PROOF);
        _activate(1);
        assertEq(vault.activationCursor(), 2);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// A retirement that lands first changes the root under a prepared activation at the same
    /// cursor: StaleActivation (proved) and StaleRoot (on-chain, its path is stale). Both rebuilt
    /// from the new state land.
    function test_retirementLandingFirstMakesAPreparedActivationStale() public {
        _depositMany(2);
        _activate(1);
        vault.mutualClose(_close(0, 99, 500_000), PROOF);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(1);
        uint256[32] memory preparedPath = _path(first);
        _retire(0);
        assertNotEq(vault.currentRoot(), oldRoot);
        vm.expectRevert(Errors.StaleActivation.selector);
        vm.prank(WORKER);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.activateNotesOnChain(first, 1, preparedPath);
        assertEq(vault.activationCursor(), 1);

        uint256 snapshot = vm.snapshotState();
        _activate(1);
        uint256 provedRoot = vault.currentRoot();
        vm.revertToState(snapshot);
        _activateOnChain(1);
        assertEq(vault.currentRoot(), provedRoot);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// Deposits that land between a proof's preparation and its submission change neither the
    /// cursor nor the root, so they do not invalidate it.
    function test_depositsBetweenPreparationAndSubmissionKeepAProofValid() public {
        _depositMany(4);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(4);
        _depositMany(13);
        vm.prank(WORKER);
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        assertEq(vault.activationCursor(), 4);
        assertEq(vault.currentRoot(), newRoot);
        // A singleton prepared at slot 4 survives three more deposits.
        (first, oldRoot, newRoot) = _prepareActivation(1);
        _depositMany(3);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// Counts other than 1, 4 and 16, batches not aligned to their count, and batches reaching
    /// past the recorded notes revert InvalidActivation from either entry point; a first note
    /// other than the cursor reverts StaleActivation. Nothing changes.
    function test_invalidActivationsRevert() public {
        _depositMany(3);
        uint256[32] memory siblings = _path(0);
        uint256 root = vault.currentRoot();
        uint256[7] memory badCounts = [uint256(0), 2, 3, 5, 8, 32, type(uint256).max];
        for (uint256 i = 0; i < badCounts.length; ++i) {
            _activationReverts(0, badCounts[i], root, siblings, Errors.InvalidActivation.selector);
        }
        // Past nextNoteId: four notes of three, and the first unrecorded note.
        _activationReverts(0, 4, root, siblings, Errors.InvalidActivation.selector);
        _activationReverts(0, 16, root, siblings, Errors.InvalidActivation.selector);
        _activationReverts(1, 1, root, siblings, Errors.StaleActivation.selector);
        _activate(1);
        _activate(1);
        _activate(1);
        root = vault.currentRoot();
        siblings = _path(3);
        _activationReverts(3, 1, root, siblings, Errors.InvalidActivation.selector);
        // Misaligned: four notes from slot 3, sixteen from slot 4.
        _depositMany(17);
        _activationReverts(3, 4, root, siblings, Errors.InvalidActivation.selector);
        _activate(1);
        root = vault.currentRoot();
        siblings = _path(4);
        _activationReverts(4, 16, root, siblings, Errors.InvalidActivation.selector);
        // Ahead of or behind the cursor.
        _activationReverts(8, 4, root, siblings, Errors.StaleActivation.selector);
        _activationReverts(0, 4, root, siblings, Errors.StaleActivation.selector);
        assertEq(vault.activationCursor(), 4);
        assertEq(vault.currentRoot(), _mirrorRoot());
        _activate(4);
    }

    // ============================================================= on-chain activation

    /// Anyone activates a batch of each size on-chain with the siblings of its first slot: the
    /// root it hashes equals the mirror's, and NotesActivated says proved = false. Siblings below
    /// the batch's subtree height are ignored; a wrong sibling above it reverts StaleRoot.
    function test_onChainActivationOfEachSizeByAThirdParty() public {
        uint256[3] memory sizes = [uint256(1), 4, 16];
        uint256[3] memory heights = [uint256(0), 2, 4];
        for (uint256 s = 0; s < sizes.length; ++s) {
            uint256 snapshot = vm.snapshotState();
            uint256 count = sizes[s];
            // A proved batch ahead of this one, so its path is not all zero hashes.
            _depositMany(2 * count);
            _activate(count);
            uint32 first = vault.activationCursor();
            (uint256 expected,) = _mirror(uint256(first) + count, 0);

            uint256[32] memory wrong = _path(first);
            wrong[heights[s]] += 1;
            vm.expectRevert(Errors.StaleRoot.selector);
            vm.prank(STRANGER);
            vault.activateNotesOnChain(first, count, wrong);
            wrong = _path(first);
            wrong[31] = 0;
            vm.expectRevert(Errors.StaleRoot.selector);
            vm.prank(STRANGER);
            vault.activateNotesOnChain(first, count, wrong);

            uint256[32] memory siblings = _path(first);
            for (uint256 level = 0; level < heights[s]; ++level) {
                siblings[level] = uint256(keccak256(abi.encode(level))) % SCALAR_MODULUS;
            }
            vm.expectEmit(address(vault));
            emit Events.NotesActivated(first, uint32(count), expected, false);
            vm.prank(STRANGER);
            vault.activateNotesOnChain(first, count, siblings);
            assertEq(vault.currentRoot(), expected);
            assertEq(vault.currentRoot(), _mirrorRoot());
            assertEq(vault.activationCursor(), first + count);
            vm.revertToState(snapshot);
        }
    }

    /// Proved and on-chain activations follow each other in any order on one tree: each on-chain
    /// one authenticates the root the proved ones before it set.
    function test_provedAndOnChainActivationsInterleave() public {
        _depositMany(32);
        uint256 deposited = vm.snapshotState();
        _activate(4);
        _activateOnChain(4);
        _activate(1);
        _activateOnChain(1);
        _activateOnChain(1);
        _activate(1);
        _activate(4);
        assertEq(vault.currentRoot(), _mirrorRoot());
        _activateOnChain(16);
        assertEq(vault.activationCursor(), 32);
        assertEq(vault.currentRoot(), _mirrorRoot());
        uint256 onChainRoot = vault.currentRoot();
        // The same notes, all proved, give the same root.
        vm.revertToState(deposited);
        _activateAll();
        assertEq(vault.currentRoot(), onChainRoot);
    }

    // ================================================================= retirement

    /// A retired leaf stays zero when later notes are appended behind it: the hole is kept by
    /// proved and on-chain activations alike, including when the retired leaf was the last one.
    function test_retirementThenAppendKeepsTheHole() public {
        _depositMany(1);
        _activate(1);
        vault.mutualClose(_close(0, 99, DEPOSIT), PROOF);
        _retire(0);
        assertEq(vault.currentRoot(), MerkleUpdateLib.EMPTY_ROOT);
        _depositMany(1);
        _activateOnChain(1);
        uint256 onlySlotOne = _leafOf(1);
        onlySlotOne = _node(0, onlySlotOne);
        for (uint256 level = 1; level < 32; ++level) {
            onlySlotOne = _node(onlySlotOne, MerkleUpdateLib.zeroHash(level));
        }
        assertEq(vault.currentRoot(), onlySlotOne);

        _depositMany(6);
        _activate(1);
        _activate(1);
        _activate(4);
        vault.mutualClose(_close(5, 98, DEPOSIT), PROOF);
        _retire(5);
        _depositMany(8);
        _activate(4);
        _activateOnChain(4);
        assertEq(vault.activationCursor(), 16);
        assertEq(vault.currentRoot(), _mirrorRoot());
        assertTrue(retired[0] && retired[5]);
    }

    /// A note closed before it is activated (a mutual close, a finalized escape) is still appended
    /// with its original leaf, and stays Closed; so is a pending escape's note, which stays
    /// pending. A Closed note can be retired only once activated.
    function test_notesClosedBeforeActivationAreAppendedAndThenRetired() public {
        _depositMany(8);
        vault.mutualClose(_close(1, 99, 400_000), PROOF);
        vault.initiateEscapeWithdrawal(_escape(2, 101, 102, 600_000, 0), PROOF);
        vault.initiateEscapeWithdrawal(_escape(5, 201, 202, 300_000, 0), PROOF);
        vm.warp(_deadline(2));
        vault.finalizeEscapeWithdrawal(2);
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Closed));
        assertEq(uint256(_status(2)), uint256(Types.NoteStatus.Closed));
        uint256[32] memory unactivatedPath = _path(1);
        vm.expectRevert(Errors.NoteNotActivated.selector);
        vault.retireClosedLeaf(1, unactivatedPath);

        // Proved: the statement carries the closed notes' recorded values.
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(4);
        vm.expectCall(
            address(adapter),
            abi.encodeCall(
                IZkApiProofAdapter.assertValidInsertion, (4, _insertionInputs(first, 4, oldRoot, newRoot), PROOF)
            )
        );
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        // On-chain: the vault hashes the pending note's recorded leaf.
        _activateOnChain(4);
        assertEq(vault.currentRoot(), _mirrorRoot());
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Closed));
        assertEq(uint256(_status(2)), uint256(Types.NoteStatus.Closed));
        assertEq(uint256(_status(5)), uint256(Types.NoteStatus.PendingWithdrawal));
        (bytes32 commitment, uint128 amount,,) = vault.notes(1);
        assertEq(commitment, bytes32(uint256(1001)));
        assertEq(amount, DEPOSIT);

        _retire(1);
        _retire(2);
        assertEq(vault.currentRoot(), _mirrorRoot());
        vm.warp(_deadline(5));
        vault.finalizeEscapeWithdrawal(5);
        _retire(5);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    // ===================================================================== gas

    /// Transaction gas of activateNotesOnChain for each batch size (21,000 + calldata + execution,
    /// cold vault and Poseidon library), under the ceilings and pinned in
    /// snapshots/activation-gas.json (checked in CI with FORGE_SNAPSHOT_CHECK). The no-prover
    /// fallback hashes the batch's leaves, its subtree and two paths above it.
    function test_onChainActivationGas() public {
        _depositMany(16);
        uint256 snapshot = vm.snapshotState();
        uint256[3] memory sizes = [uint256(1), 4, 16];
        uint256[3] memory ceilings = [uint256(2_000_000), 2_500_000, 3_500_000];
        string[3] memory names = ["activateNotesOnChain1", "activateNotesOnChain4", "activateNotesOnChain16"];
        for (uint256 s = 0; s < sizes.length; ++s) {
            uint256[32] memory siblings = _path(0);
            uint256 txGas = _txGas(abi.encodeCall(vault.activateNotesOnChain, (0, sizes[s], siblings)), names[s]);
            assertLe(txGas, ceilings[s], names[s]);
            vm.snapshotValue("activation-gas", names[s], txGas);
            vm.revertToState(snapshot);
        }
    }

    /// Transaction gas of retireClosedLeaf (cold vault and Poseidon library), which hashes the
    /// original leaf and two 32-level paths, pinned in snapshots/activation-gas.json.
    function test_retireClosedLeafGas() public {
        _depositMany(4);
        _activate(4);
        vault.mutualClose(_close(1, 99, DEPOSIT), PROOF);
        uint256[32] memory path = _path(1);
        uint256 txGas = _txGas(abi.encodeCall(vault.retireClosedLeaf, (1, path)), "retireClosedLeaf");
        retired[1] = true;
        assertEq(vault.currentRoot(), _mirrorRoot());
        assertLe(txGas, 2_000_000, "retireClosedLeaf");
        vm.snapshotValue("activation-gas", "retireClosedLeaf", txGas);
    }

    // ================================================================== helpers

    /// Deposits `n` notes with distinct commitments 1000 + noteId.
    function _depositMany(uint256 n) internal {
        for (uint256 i = 0; i < n; ++i) {
            _deposit(1000 + vault.nextNoteId());
        }
    }

    /// Both entry points revert `err` for a batch of `count` from `first`.
    function _activationReverts(
        uint32 first,
        uint256 count,
        uint256 expectedRoot,
        uint256[32] memory siblings,
        bytes4 err
    ) internal {
        vm.expectRevert(err);
        vault.activateNotes(first, count, expectedRoot, 1, PROOF);
        vm.expectRevert(err);
        vault.activateNotesOnChain(first, count, siblings);
    }

    /// Runs `data` against the vault (it must succeed) and returns its transaction gas.
    function _txGas(bytes memory data, string memory label) internal returns (uint256 txGas) {
        vm.cool(address(vault));
        vm.cool(address(Bn254Poseidon));
        vm.prank(STRANGER);
        (bool ok,) = address(vault).call(data);
        assertTrue(ok, label);
        uint256 calldataGas;
        for (uint256 i = 0; i < data.length; ++i) {
            calldataGas += data[i] == 0 ? 4 : 16;
        }
        txGas = 21_000 + calldataGas + vm.lastCallGas().gasTotalUsed;
        emit log_named_uint(string.concat(label, " transaction gas"), txGas);
    }
}
