// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
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
///      on-chain (activateNotesOnChain). Only the activator proves batches; anyone activates
///      on-chain once ACTIVATION_FALLBACK_DELAY has passed since the latest proved activation, the
///      deployment or the latest unpause. Every root is checked against VaultTestBase's mirror of
///      the tree, built from the vault's records.
contract ZkApiVaultActivationTest is VaultTestBase {
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
            vm.prank(activator);
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
        vm.startPrank(activator);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot, PROOF);
        // A root the proof was not made for, and another proof of the right statement.
        adapter.acceptInsertion(4, honest, PROOF);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot + 1, PROOF);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.activateNotes(0, 4, oldRoot, newRoot, hex"bad0");
        vm.stopPrank();
        assertEq(vault.activationCursor(), 0);
        assertEq(vault.currentRoot(), MerkleUpdateLib.EMPTY_ROOT);
        // The honest proof lands from the activator only.
        vm.expectRevert(Errors.NotActivator.selector);
        vm.prank(STRANGER);
        vault.activateNotes(0, 4, oldRoot, newRoot, PROOF);
        vm.prank(activator);
        vault.activateNotes(0, 4, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), newRoot);
    }

    // ================================================================ stale and invalid

    /// A competing activation that lands first moves the cursor, so a prepared one names a stale
    /// first note: StaleActivation, before verification. Rebuilt from the new state it lands. A
    /// stranger's proof of a competing singleton is refused (NotActivator); its on-chain singleton,
    /// once the fallback has opened, is the competitor here.
    function test_competingActivationMakesAPreparedOneStale() public {
        _depositMany(5);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(4);
        (,, uint256 singletonRoot) = _prepareActivation(1);
        vm.expectRevert(Errors.NotActivator.selector);
        vm.prank(STRANGER);
        vault.activateNotes(first, 1, oldRoot, singletonRoot, PROOF);
        _openFallback();
        uint256[32] memory siblings = _path(first);
        vm.prank(STRANGER);
        vault.activateNotesOnChain(first, 1, siblings);
        assertEq(vault.currentRoot(), singletonRoot);
        vm.expectRevert(Errors.StaleActivation.selector);
        vm.prank(activator);
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        // The same batch rebuilt from the new cursor is misaligned; the next singleton lands.
        uint256 root = vault.currentRoot();
        vm.expectRevert(Errors.InvalidActivation.selector);
        vm.prank(activator);
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
        vm.prank(activator);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        _openFallback();
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
        vm.prank(activator);
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        assertEq(vault.activationCursor(), 4);
        assertEq(vault.currentRoot(), newRoot);
        // A singleton prepared at slot 4 survives three more deposits.
        (first, oldRoot, newRoot) = _prepareActivation(1);
        _depositMany(3);
        vm.prank(activator);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// Counts other than 1, 4 and 16, batches not aligned to their count, and batches reaching
    /// past the recorded notes revert InvalidActivation from either entry point (the activator's
    /// proved one, the open fallback); a first note other than the cursor reverts StaleActivation.
    /// Nothing changes.
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

    /// Anyone activates a batch of each size on-chain, once the fallback is open, with the siblings
    /// of its first slot: the root it hashes equals the mirror's, and NotesActivated says proved =
    /// false. Siblings below the batch's subtree height are ignored; a wrong sibling above it
    /// reverts StaleRoot.
    function test_onChainActivationOfEachSizeByAThirdParty() public {
        uint256[3] memory sizes = [uint256(1), 4, 16];
        uint256[3] memory heights = [uint256(0), 2, 4];
        for (uint256 s = 0; s < sizes.length; ++s) {
            uint256 snapshot = vm.snapshotState();
            uint256 count = sizes[s];
            // A proved batch ahead of this one, so its path is not all zero hashes; the fallback
            // opens ACTIVATION_FALLBACK_DELAY after it.
            _depositMany(2 * count);
            _activate(count);
            _openFallback();
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

    // ======================================================= activator and fallback

    /// The constructor refuses a zero activator. A deployment records its activator, emits
    /// ActivatorChanged(address(0), activator) and opens the fallback ACTIVATION_FALLBACK_DELAY
    /// (one hour) later.
    function test_deploymentSetsTheActivatorAndTheFallbackOpening() public {
        vm.expectRevert(Errors.Unauthorized.selector);
        _newVault(CHALLENGE_PERIOD, MAX_PAUSE, address(0));
        address predicted = vm.computeCreateAddress(address(this), vm.getNonce(address(this)));
        vm.expectEmit(predicted);
        emit Events.ActivatorChanged(address(0), activator);
        ZkApiVault fresh = _newVault(CHALLENGE_PERIOD, MAX_PAUSE);
        assertEq(address(fresh), predicted);
        assertEq(fresh.activator(), activator);
        assertEq(fresh.ACTIVATION_FALLBACK_DELAY(), 1 hours);
        assertEq(fresh.activationFallbackOpensAt(), vm.getBlockTimestamp() + 1 hours);
    }

    /// Only the activator calls activateNotes: anyone else, the owner included, is refused
    /// NotActivator even with a proof the adapter accepts, and before any other check (a bad
    /// count, a stale root). The activator lands the same batch.
    function test_onlyTheActivatorProvesBatches() public {
        _depositMany(4);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(4);
        address[4] memory others = [address(this), STRANGER, user, challenger];
        assertEq(vault.owner(), others[0]);
        for (uint256 i = 0; i < others.length; ++i) {
            vm.expectRevert(Errors.NotActivator.selector);
            vm.prank(others[i]);
            vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
            vm.expectRevert(Errors.NotActivator.selector);
            vm.prank(others[i]);
            vault.activateNotes(first + 1, 3, oldRoot + 1, newRoot, PROOF);
        }
        assertEq(vault.activationCursor(), 0);
        vm.prank(activator);
        vault.activateNotes(first, 4, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), newRoot);
    }

    /// setActivator: only the owner, never to zero, and also while paused (a lost or compromised
    /// worker key is replaced at once); it emits ActivatorChanged and leaves the fallback's
    /// opening alone. The previous activator is refused from then on and the new one proves.
    function test_setActivatorReplacesTheActivator() public {
        address next = address(0xACC2);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, activator));
        vm.prank(activator);
        vault.setActivator(next);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, STRANGER));
        vm.prank(STRANGER);
        vault.setActivator(STRANGER);
        vm.expectRevert(Errors.Unauthorized.selector);
        vault.setActivator(address(0));
        assertEq(vault.activator(), activator);

        vault.pause();
        uint64 opensAt = vault.activationFallbackOpensAt();
        vm.expectEmit(address(vault));
        emit Events.ActivatorChanged(activator, next);
        vault.setActivator(next);
        assertEq(vault.activator(), next);
        assertEq(vault.activationFallbackOpensAt(), opensAt);
        vault.unpause();

        _depositMany(1);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(1);
        vm.expectRevert(Errors.NotActivator.selector);
        vm.prank(activator);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        vm.prank(next);
        vault.activateNotes(first, 1, oldRoot, newRoot, PROOF);
        assertEq(vault.currentRoot(), newRoot);
    }

    /// The fallback is closed from the deployment until ACTIVATION_FALLBACK_DELAY after it, to the
    /// second, and stays open after that.
    function test_fallbackOpensTheDelayAfterDeployment() public {
        _depositMany(2);
        _assertFallbackOpensAt(vm.getBlockTimestamp() + 1 hours);
        vm.warp(vm.getBlockTimestamp() + 30 days);
        _activateOnChain(1);
        assertEq(vault.activationCursor(), 2);
    }

    /// A proved activation closes the fallback until ACTIVATION_FALLBACK_DELAY after it, whether
    /// it was open (long after the deployment) or not yet (sooner than the delay after it).
    function test_provedActivationClosesTheFallbackForAnotherDelay() public {
        _depositMany(4);
        vm.warp(vm.getBlockTimestamp() + 30 minutes);
        _activate(1);
        _assertFallbackOpensAt(vm.getBlockTimestamp() + 1 hours);
        vm.warp(vm.getBlockTimestamp() + 5 days);
        _activate(1);
        _assertFallbackOpensAt(vm.getBlockTimestamp() + 1 hours);
    }

    /// An unpause closes the fallback until ACTIVATION_FALLBACK_DELAY after it, however long ago
    /// the latest proved activation was, so the activator resumes before anyone else may; while
    /// paused, the fallback reverts Paused.
    function test_unpauseClosesTheFallbackForAnotherDelay() public {
        _depositMany(2);
        _activateOnChain(1);
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 3 days);
        uint256[32] memory siblings = _path(1);
        vm.expectRevert(Errors.Paused.selector);
        vault.activateNotesOnChain(1, 1, siblings);
        vault.unpause();
        _assertFallbackOpensAt(vm.getBlockTimestamp() + 1 hours);
    }

    /// On-chain activations do not move activationFallbackOpensAt: once open, the fallback stays
    /// open for any number of them in a row, in one block and later.
    function test_onChainActivationsKeepTheFallbackOpen() public {
        _depositMany(36);
        _openFallback();
        uint64 opensAt = vault.activationFallbackOpensAt();
        uint256[8] memory batches = [uint256(1), 1, 1, 1, 4, 4, 4, 16];
        for (uint256 i = 0; i < batches.length; ++i) {
            _activateOnChain(batches[i]);
        }
        vm.warp(vm.getBlockTimestamp() + 1);
        for (uint256 i = 0; i < 4; ++i) {
            _activateOnChain(1);
        }
        assertEq(vault.activationFallbackOpensAt(), opensAt);
        assertEq(vault.activationCursor(), 36);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// While the fallback is closed, every on-chain activation reverts ActivationFallbackClosed,
    /// before the range, alignment, cursor and path checks.
    function test_closedFallbackRevertsBeforeTheRangeChecks() public {
        _depositMany(3);
        _activate(1);
        uint256[32] memory siblings = _path(1);
        uint256[32] memory wrong = _path(1);
        wrong[0] += 1;
        uint32[6] memory firsts = [uint32(1), 1, 1, 1, 0, 1];
        uint256[6] memory counts = [uint256(0), 2, 4, 16, 1, 1];
        for (uint256 i = 0; i < firsts.length; ++i) {
            vm.expectRevert(Errors.ActivationFallbackClosed.selector);
            vault.activateNotesOnChain(firsts[i], counts[i], siblings);
        }
        vm.expectRevert(Errors.ActivationFallbackClosed.selector);
        vault.activateNotesOnChain(1, 1, wrong);
        _openFallback();
        vm.expectRevert(Errors.InvalidActivation.selector);
        vault.activateNotesOnChain(1, 4, siblings);
        vm.expectRevert(Errors.StaleActivation.selector);
        vault.activateNotesOnChain(0, 1, siblings);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.activateNotesOnChain(1, 1, wrong);
        vault.activateNotesOnChain(1, 1, siblings);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    /// The front-running the activator role and the fallback delay prevent: the worker fills a
    /// 16-note batch at slot 16 while a stranger activates one note ahead of it, which would
    /// misalign the cursor and force batches of 1, 1, 1, 4, 4 and 4 for the other fifteen notes.
    /// While the activator has proved within the delay, the stranger's proof (insertion keys are
    /// public) is NotActivator and its on-chain singleton ActivationFallbackClosed, so the batch
    /// lands aligned. Once the activator has been idle for the delay, the stranger activates every
    /// pending note on-chain, and the activator then resumes from the new cursor, which closes the
    /// fallback again: proof, fallback, proof.
    function test_strangerCannotBreakABatchButActivatesOnceTheActivatorIsIdle() public {
        _depositMany(32);
        _activate(16);
        (uint32 first, uint256 oldRoot, uint256 newRoot) = _prepareActivation(16);
        (,, uint256 singletonRoot) = _prepareActivation(1);
        uint256[32] memory siblings = _path(first);
        vm.warp(vault.activationFallbackOpensAt() - 1);
        vm.startPrank(STRANGER);
        vm.expectRevert(Errors.NotActivator.selector);
        vault.activateNotes(first, 1, oldRoot, singletonRoot, PROOF);
        vm.expectRevert(Errors.ActivationFallbackClosed.selector);
        vault.activateNotesOnChain(first, 1, siblings);
        vm.stopPrank();
        vm.prank(activator);
        vault.activateNotes(first, 16, oldRoot, newRoot, PROOF);
        assertEq(vault.activationCursor(), 32);

        // The activator goes idle with 21 notes pending; a delay later the stranger activates
        // them all on-chain, in aligned batches.
        _depositMany(21);
        vm.warp(vm.getBlockTimestamp() + vault.ACTIVATION_FALLBACK_DELAY());
        uint256[3] memory batches = [uint256(16), 4, 1];
        for (uint256 i = 0; i < batches.length; ++i) {
            first = vault.activationCursor();
            siblings = _path(first);
            vm.prank(STRANGER);
            vault.activateNotesOnChain(first, batches[i], siblings);
        }
        assertEq(vault.activationCursor(), 53);
        assertEq(vault.currentRoot(), _mirrorRoot());

        // The activator resumes, and the stranger is held off again.
        _depositMany(2);
        _activate(1);
        siblings = _path(54);
        vm.expectRevert(Errors.ActivationFallbackClosed.selector);
        vm.prank(STRANGER);
        vault.activateNotesOnChain(54, 1, siblings);
        assertEq(vault.activationCursor(), 54);
        assertEq(vault.currentRoot(), _mirrorRoot());
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
        vm.prank(activator);
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
        // Note 5's deadline (note 2's) has passed: the on-chain activation waited for the fallback.
        assertGe(vm.getBlockTimestamp(), _deadline(5));
        vault.finalizeEscapeWithdrawal(5);
        _retire(5);
        assertEq(vault.currentRoot(), _mirrorRoot());
    }

    // ===================================================================== gas

    /// Transaction gas of activateNotesOnChain for each batch size (21,000 + calldata + execution,
    /// cold vault and Poseidon library) once the fallback is open, under the ceilings and pinned in
    /// snapshots/activation-gas.json (checked in CI with FORGE_SNAPSHOT_CHECK). The no-prover
    /// fallback hashes the batch's leaves, its subtree and two paths above it.
    function test_onChainActivationGas() public {
        _depositMany(16);
        _openFallback();
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

    /// activationFallbackOpensAt is `opensAt`: an on-chain activation of the next note reverts
    /// ActivationFallbackClosed at opensAt - 1 and lands at opensAt.
    function _assertFallbackOpensAt(uint256 opensAt) internal {
        assertEq(vault.activationFallbackOpensAt(), opensAt);
        uint32 first = vault.activationCursor();
        uint256[32] memory siblings = _path(first);
        vm.warp(opensAt - 1);
        vm.expectRevert(Errors.ActivationFallbackClosed.selector);
        vm.prank(STRANGER);
        vault.activateNotesOnChain(first, 1, siblings);
        vm.warp(opensAt);
        vm.prank(STRANGER);
        vault.activateNotesOnChain(first, 1, siblings);
        assertEq(vault.activationCursor(), first + 1);
    }

    /// Both entry points revert `err` for a batch of `count` from `first`: the activator's proved
    /// one, and the fallback once open.
    function _activationReverts(
        uint32 first,
        uint256 count,
        uint256 expectedRoot,
        uint256[32] memory siblings,
        bytes4 err
    ) internal {
        vm.expectRevert(err);
        vm.prank(activator);
        vault.activateNotes(first, count, expectedRoot, 1, PROOF);
        _openFallback();
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
