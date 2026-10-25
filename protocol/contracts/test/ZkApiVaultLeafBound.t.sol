// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";
import {ReferenceHashes} from "./helpers/PoseidonRuntime.sol";
import {VaultStorage} from "./helpers/VaultStorage.sol";

/// @dev Vault revision 4 (leaf-bound exits, Amendment A3 of docs/design/concession-exit.md) against
///      the leaf-binding mock adapter: the note word and its leaf binding, minDeposit, the computed
///      request root and its views, retirement over a sub-path, the escape record's deposit and
///      expiry, pause epochs and the defeat's fast path, recordRoot, and the removed interface.
contract ZkApiVaultLeafBoundTest is VaultTestBase {
    uint128 constant B2 = 790_000;

    function setUp() public {
        vm.warp(1_700_000_000);
        _setUpVault();
    }

    // ================================================================== note words

    /// A deposit writes one word, its leaf | Active << 254, which noteRecord reads back and every
    /// exit and sweep changes only in the status bits (a retirement zeroes the leaf).
    function test_noteWordLayoutThroughTheLifecycle() public {
        uint32 id = _deposit(42);
        uint256 leaf = _leafOf(id);
        assertEq(VaultStorage.word(address(vault), VaultStorage.noteSlot(id)), leaf | (uint256(1) << 254));
        (uint256 stored, Types.NoteStatus status) = vault.noteRecord(id);
        assertEq(stored, leaf);
        assertEq(uint256(status), uint256(Types.NoteStatus.Active));
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, B2, 0), PROOF);
        assertEq(VaultStorage.word(address(vault), VaultStorage.noteSlot(id)), leaf | (uint256(2) << 254));
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(VaultStorage.word(address(vault), VaultStorage.noteSlot(id)), leaf | (uint256(3) << 254));
        _retire(id);
        assertEq(VaultStorage.word(address(vault), VaultStorage.noteSlot(id)), uint256(3) << 254);
        (stored, status) = vault.noteRecord(id);
        assertEq(stored, 0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Closed));
        (stored, status) = vault.noteRecord(id + 1);
        assertEq(stored, 0);
        assertEq(uint256(status), uint256(Types.NoteStatus.Uninitialized));
    }

    /// The stored word is exactly NoteLeafLib's leaf over the deposit's fields, and that equals
    /// zkapi_core's vector (spec C.1: s = 42 gives R, n = 7, D = 5,000,000, e = 4,000,000,000).
    function test_leafVectorsMatchRust() public pure {
        assertEq(
            NoteLeafLib.pack(7, 5_000_000, 4_000_000_000),
            0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800
        );
        assertEq(
            ReferenceHashes.leaf(
                7, bytes32(0x26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc), 5_000_000, 4_000_000_000
            ),
            0x1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f
        );
        assertEq(
            ReferenceHashes.leafOfFields(bytes32(uint256(1)), (uint256(1) << 64) + 1),
            0x00381941483a5233ff52ff1e1a0b79464c7316b7b4f609468ba5de81d2686d42
        );
    }

    /// pack and unpack are inverse at the field boundaries, and no two packings collide.
    function testFuzz_packingIsInjective(uint32 n, uint128 d, uint64 e, uint32 n2, uint128 d2, uint64 e2) public pure {
        uint256 fields = NoteLeafLib.pack(n, d, e);
        assertLt(fields, uint256(1) << 224);
        (uint32 un, uint128 ud, uint64 ue) = NoteLeafLib.unpack(fields);
        assertEq(un, n);
        assertEq(ud, d);
        assertEq(ue, e);
        if (n != n2 || d != d2 || e != e2) assertNotEq(fields, NoteLeafLib.pack(n2, d2, e2));
    }

    // ================================================================ leaf binding

    /// A statement whose fields name the note but carry another deposit or expiry, with the leaf
    /// of those fields (what a prover who knows the secret could prove): the mock adapter accepts
    /// it, the vault refuses it, since the stored leaf binds the real fields.
    function test_forgedFieldsWithTheirOwnLeafAreRefused() public {
        uint32 id = _deposit(42);
        NoteData memory data = noteData[id];
        uint256[3] memory forged = [
            NoteLeafLib.pack(id, data.amount * 2, data.expiryTs),
            NoteLeafLib.pack(id, data.amount, data.expiryTs + 1 days),
            NoteLeafLib.pack(id, data.amount + 1, data.expiryTs - 1)
        ];
        for (uint256 i = 0; i < forged.length; ++i) {
            Types.WithdrawalPublicInputs memory escape = _escape(id, 101, 102, data.amount, 0);
            escape.noteFields = forged[i];
            escape.noteLeaf = ReferenceHashes.leafOfFields(data.commitment, forged[i]);
            adapter.assertValidWithdrawal(escape, PROOF);
            _escapeReverts(escape, Errors.NoteLeafMismatch.selector);
            Types.WithdrawalPublicInputs memory close = _close(id, 103, data.amount);
            close.noteFields = forged[i];
            close.noteLeaf = escape.noteLeaf;
            _closeReverts(close, Errors.NoteLeafMismatch.selector);
        }
        // This note's leaf with another note's fields: the stored leaf of the note the fields
        // name is not this one.
        uint32 other = _deposit(43);
        Types.WithdrawalPublicInputs memory moved = _escape(id, 101, 102, B2, 0);
        moved.noteFields = _fields(other);
        _escapeReverts(moved, Errors.NoteLeafMismatch.selector);
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
    }

    /// noteFields at or above 2^224 never reaches the leaf check: with the low 224 bits of the
    /// note's fields (which the uint32 note ID read alone would accept) it reverts
    /// InvalidNoteFields, as does any top bit.
    function test_fieldsAboveTheirWidthAreRefused() public {
        uint32 id = _deposit(42);
        uint256[3] memory wide =
            [_fields(id) + (uint256(1) << 224), _fields(id) | (uint256(1) << 255), type(uint256).max];
        for (uint256 i = 0; i < wide.length; ++i) {
            Types.WithdrawalPublicInputs memory escape = _escape(id, 101, 102, B2, 0);
            escape.noteFields = wide[i];
            _escapeReverts(escape, Errors.InvalidNoteFields.selector);
            Types.WithdrawalPublicInputs memory close = _close(id, 103, B2);
            close.noteFields = wide[i];
            _closeReverts(close, Errors.InvalidNoteFields.selector);
        }
    }

    /// A deposit above MAX_NATIVE_UNITS cannot be stored, so only a broken proof system could
    /// present one; a stored leaf over such fields (written directly) still makes the exit revert
    /// InvalidBalance before anything is narrowed or paid.
    function test_depositAboveTheUnitBoundIsRefused() public {
        uint32 id = _deposit(42);
        uint128 tooMuch = vault.MAX_NATIVE_UNITS() + 1;
        uint256 fields = NoteLeafLib.pack(id, tooMuch, noteData[id].expiryTs);
        uint256 leaf = ReferenceHashes.leafOfFields(noteData[id].commitment, fields);
        VaultStorage.setNote(address(vault), id, leaf, VaultStorage.ACTIVE);
        Types.WithdrawalPublicInputs memory escape = _escape(id, 101, 102, tooMuch, 0);
        escape.noteFields = fields;
        escape.noteLeaf = leaf;
        _escapeReverts(escape, Errors.InvalidBalance.selector);
        Types.WithdrawalPublicInputs memory close = _close(id, 103, tooMuch);
        close.noteFields = fields;
        close.noteLeaf = leaf;
        _closeReverts(close, Errors.InvalidBalance.selector);
    }

    /// The payout is bounded by the D the leaf binds: a close above it, an escape whose balance
    /// exceeds it, revert InvalidBalance.
    function test_payoutsAreBoundedByTheBoundDeposit() public {
        uint32 id = _deposit(42);
        _closeReverts(_close(id, 101, DEPOSIT + 1), Errors.InvalidBalance.selector);
        _escapeReverts(_escape(id, 101, 102, DEPOSIT, 1), Errors.InvalidBalance.selector);
        vault.mutualClose(_close(id, 101, DEPOSIT), PROOF);
        assertEq(treasury.balance, 0);
    }

    // ============================================================ the escape record

    /// The escape record carries the note's D and e (gate G1): slot 1 packs the deadline, the
    /// payout, the concession and D, 64 bits each, and N_{k+1}'s word holds e above the
    /// destination. Checked at the bounds: D = MAX_NATIVE_UNITS, e = 2^64 - 1 and a full 160-bit
    /// destination, with a raise and the finalization, which pays D - f to the treasury.
    function test_escapeRecordCarriesTheDepositAndExpiryAtTheirBounds() public {
        uint128 max = vault.MAX_NATIVE_UNITS();
        vm.deal(user, uint256(max) * 1 gwei);
        uint32 id = _depositAmount(42, max);
        // The note's expiry written as the largest uint64 (no deposit can reach it).
        uint64 e = type(uint64).max;
        uint256 fields = NoteLeafLib.pack(id, max, e);
        uint256 leaf = ReferenceHashes.leafOfFields(bytes32(uint256(42)), fields);
        VaultStorage.setNote(address(vault), id, leaf, VaultStorage.ACTIVE);
        noteData[id].expiryTs = e;
        address destination = address(type(uint160).max);
        uint256 next = SCALAR_MODULUS - 1;
        Types.WithdrawalPublicInputs memory inputs = _escape(id, 7, next, max - 3, 3);
        inputs.destination = destination;
        vault.initiateEscapeWithdrawal(inputs, PROOF);

        uint64 deadline = _deadline(id);
        bytes32 recordSlot = VaultStorage.escapeSlot(id);
        assertEq(VaultStorage.word(address(vault), recordSlot), 7, "withdrawalNullifier");
        uint256 packed = VaultStorage.word(address(vault), bytes32(uint256(recordSlot) + 1));
        assertEq(uint64(packed), deadline, "challengeDeadline");
        assertEq(uint64(packed >> 64), max - 3, "finalBalance");
        assertEq(uint64(packed >> 128), 3, "conceded");
        assertEq(uint64(packed >> 192), max, "depositAmount");
        uint256 nextWord = VaultStorage.word(address(vault), VaultStorage.nullifierSlot(next));
        assertEq(nextWord & 3, 1, "USED, not CHALLENGED");
        assertEq(address(uint160(nextWord >> 2)), destination, "destination");
        assertEq(uint64(nextWord >> 162), e, "expiryTs");
        assertEq(nextWord >> 226, 0, "nothing above the expiry");
        (,,,, address pendingTo,) = vault.pendingWithdrawals(id);
        assertEq(pendingTo, destination);

        vault.raiseEscapeConcession(id, _evidence(7, max), PROOF, max - 1);
        (,, uint128 conceded) = _concession(id);
        assertEq(conceded, max - 1);
        vm.warp(deadline);
        vault.finalizeEscapeWithdrawal(id);
        assertEq(destination.balance, 1 gwei);
        assertEq(treasury.balance, uint256(max - 1) * 1 gwei);
    }

    /// The defeat reads e from the record: near the expiry (written as e above), the grace is the
    /// exact max(e - pausedBefore, graceUntil) rule.
    function test_defeatTakesTheExpiryFromTheRecord() public {
        uint32 id = _deposit(42);
        uint64 e = noteData[id].expiryTs;
        vm.warp(uint256(e) - 2 hours);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, B2, 0), PROOF);
        vm.warp(_deadline(id) - 1);
        vault.challengeEscapeWithdrawal(id, _evidence(102, 1), PROOF);
        assertEq(vault.graceUntil(id), vm.getBlockTimestamp() + CHALLENGE_PERIOD);
        assertEq(_effectiveExpiry(id), vm.getBlockTimestamp() + CHALLENGE_PERIOD);
        // N_{k+1}'s word is cleared with the escape.
        assertEq(VaultStorage.word(address(vault), VaultStorage.nullifierSlot(102)), 0);
    }

    // ================================================================= minDeposit

    function test_depositsBelowMinDepositAreRefused() public {
        ZkApiVault floor = new ZkApiVault(
            treasury,
            NOTE_TTL,
            CHALLENGE_PERIOD,
            100_000,
            address(adapter),
            STATE_X,
            STATE_Y,
            CLEAR_X,
            CLEAR_Y,
            address(this),
            MAX_PAUSE,
            address(vault.poseidon()),
            1_000_000
        );
        assertEq(floor.minDeposit(), 1_000_000);
        vm.startPrank(user);
        vm.expectRevert(Errors.ZeroAmount.selector);
        floor.deposit(bytes32(uint256(42)), 0);
        vm.expectRevert(Errors.DepositTooSmall.selector);
        floor.deposit{value: 999_999 gwei}(bytes32(uint256(42)), 999_999);
        // The value check comes first.
        vm.expectRevert(Errors.InvalidNativeValue.selector);
        floor.deposit{value: 1 gwei}(bytes32(uint256(42)), 999_999);
        floor.deposit{value: 1_000_000 gwei}(bytes32(uint256(42)), 1_000_000);
        vm.stopPrank();
        assertEq(floor.nextNoteId(), 1);
    }

    function test_constructorBoundsMinDeposit() public {
        address poseidon = address(vault.poseidon());
        uint128 max = vault.MAX_NATIVE_UNITS();
        uint128[2] memory refused = [uint128(0), max + 1];
        for (uint256 i = 0; i < refused.length; ++i) {
            vm.expectRevert(Errors.InvalidBalance.selector);
            new ZkApiVault(
                treasury,
                NOTE_TTL,
                CHALLENGE_PERIOD,
                100_000,
                address(adapter),
                STATE_X,
                STATE_Y,
                CLEAR_X,
                CLEAR_Y,
                address(this),
                MAX_PAUSE,
                poseidon,
                refused[i]
            );
        }
        ZkApiVault top = new ZkApiVault(
            treasury,
            NOTE_TTL,
            CHALLENGE_PERIOD,
            100_000,
            address(adapter),
            STATE_X,
            STATE_Y,
            CLEAR_X,
            CLEAR_Y,
            address(this),
            MAX_PAUSE,
            poseidon,
            max
        );
        assertEq(top.minDeposit(), max);
    }

    // ================================================================ the tree view

    /// One fresh slot per deposit (its word), plus the frontier entry of level t at note ID
    /// 2^t - 1, checked over the first 16 deposits; currentRoot() equals the full reference tree's
    /// root after each of the first eight, and after retirements.
    function test_depositsWriteOneFreshSlotAndTheRootMatchesTheReference() public {
        for (uint32 i = 0; i < 16; ++i) {
            bytes memory data = abi.encodeCall(ZkApiVault.deposit, (bytes32(uint256(500 + i)), DEPOSIT));
            uint256 fresh = _freshSlots(data, uint256(DEPOSIT) * 1 gwei);
            bool firstWrite = i == 1 || i == 3 || i == 7 || i == 15;
            assertEq(fresh, firstWrite ? 2 : 1, vm.toString(uint256(i)));
            _depositAmount(500 + i, DEPOSIT);
            if (i < 8) assertEq(vault.currentRoot(), _referenceRoot(), vm.toString(uint256(i)));
        }
    }

    function test_rootMatchesTheReferenceAcrossRetirements() public {
        for (uint32 i = 0; i < 7; ++i) {
            _deposit(600 + i);
        }
        uint32[4] memory order = [uint32(2), 6, 0, 3];
        for (uint256 k = 0; k < order.length; ++k) {
            vault.mutualClose(_close(order[k], 900 + k, 1), PROOF);
            _retire(order[k]);
            assertEq(vault.currentRoot(), _referenceRoot());
        }
        _deposit(700);
        assertEq(vault.currentRoot(), _referenceRoot());
    }

    /// noteLeaves reads the stored leaves (zero once retired) and refuses ranges past nextNoteId;
    /// rebuilt from it the tree has the vault's root.
    function test_noteLeavesRebuildsTheTree() public {
        for (uint32 i = 0; i < 5; ++i) {
            _deposit(800 + i);
        }
        vault.mutualClose(_close(1, 77, 1), PROOF);
        _retire(1);
        uint256[] memory leaves = vault.noteLeaves(0, 5);
        assertEq(leaves.length, 5);
        assertEq(leaves[1], 0);
        for (uint32 i = 0; i < 5; ++i) {
            assertEq(leaves[i], _treeLeaf(i));
        }
        assertEq(vault.noteLeaves(2, 3)[0], leaves[2]);
        assertEq(vault.noteLeaves(5, 0).length, 0);
        vm.expectRevert(Errors.InvalidNoteRange.selector);
        vault.noteLeaves(0, 6);
        vm.expectRevert(Errors.InvalidNoteRange.selector);
        vault.noteLeaves(5, 1);
        vm.expectRevert(Errors.InvalidNoteRange.selector);
        vault.noteLeaves(type(uint32).max, 2);
        // The rebuild: an appending frontier over the page.
        uint256 root = _rootOfLeaves(leaves);
        assertEq(root, vault.currentRoot());
    }

    /// frontier() returns nextNoteId, the stored levels, and the last leaf at index 0 for an odd
    /// count; with it alone the root can be recomputed (entries at clear bits ignored).
    function test_frontierViewRecomputesTheRoot() public {
        for (uint32 i = 0; i < 6; ++i) {
            _deposit(900 + i);
        }
        (uint32 next, uint256[32] memory nodes) = vault.frontier();
        assertEq(next, 6);
        assertEq(nodes[0], 0);
        assertEq(nodes[1], _node(_leafOf(4), _leafOf(5)));
        assertEq(nodes[2], _node(_node(_leafOf(0), _leafOf(1)), _node(_leafOf(2), _leafOf(3))));
        _deposit(906);
        (next, nodes) = vault.frontier();
        assertEq(nodes[0], _leafOf(6));
        // Bits of 7: 0, 1, 2 set; the root from these three entries.
        uint256 node = _node(nodes[0], 0);
        node = _node(nodes[1], node);
        node = _node(nodes[2], node);
        for (uint256 level = 3; level < 32; ++level) {
            node = _node(node, emptySiblings[level]);
        }
        assertEq(node, vault.currentRoot());
    }

    /// TreeFull at note ID 2^32 - 1, the last index (whose append would complete the whole tree).
    function test_depositRefusesTheLastIndex() public {
        VaultStorage.setNextNoteId(address(vault), type(uint32).max);
        vm.prank(user);
        vm.expectRevert(Errors.TreeFull.selector);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(42)), DEPOSIT);
        // The one before is accepted (31 trailing ones: level 31).
        VaultStorage.setNextNoteId(address(vault), type(uint32).max - 1);
        _deposit(42);
        assertEq(vault.nextNoteId(), type(uint32).max);
    }

    // ============================================================== retirement

    /// The vault reads siblings[0..level) only: garbage beyond the level retires the same way as
    /// zero-filled siblings (the challenger zero-fills them).
    function test_retirementIgnoresSiblingsBeyondItsLevel() public {
        for (uint32 i = 0; i < 6; ++i) {
            _deposit(100 + i);
        }
        vault.mutualClose(_close(1, 55, 1), PROOF);
        uint256 level = MerkleUpdateLib.retireLevel(1, 6);
        assertEq(level, 2);
        uint256[32] memory path = _path(1);
        uint256 snapshot = vm.snapshotState();
        uint256[32] memory garbage = path;
        for (uint256 i = level; i < 32; ++i) {
            garbage[i] = uint256(keccak256(abi.encode(i)));
        }
        vault.retireClosedLeaf(1, garbage);
        uint256 rootWithGarbage = vault.currentRoot();
        vm.revertToState(snapshot);
        uint256[32] memory zeroFilled = path;
        for (uint256 i = level; i < 32; ++i) {
            zeroFilled[i] = 0;
        }
        vault.retireClosedLeaf(1, zeroFilled);
        retired[1] = true;
        assertEq(vault.currentRoot(), rootWithGarbage);
        assertEq(vault.currentRoot(), _referenceRoot());
    }

    /// Contention: a retirement inside the same subtree lands first, so a path read before it is
    /// stale (StaleRoot); the refreshed path retires. A second retirement of the same note finds
    /// the leaf gone.
    function test_retirementContentionNeedsAFreshPath() public {
        for (uint32 i = 0; i < 6; ++i) {
            _deposit(100 + i);
        }
        vault.mutualClose(_close(0, 55, 1), PROOF);
        vault.mutualClose(_close(1, 56, 1), PROOF);
        uint256[32] memory staleOf0 = _path(0);
        _retire(1);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(0, staleOf0);
        _retire(0);
        assertEq(vault.currentRoot(), _referenceRoot());
        uint256[32] memory again = _path(0);
        vm.expectRevert(Errors.StaleRoot.selector);
        vault.retireClosedLeaf(0, again);
    }

    /// The last leaf of an odd count retires at level 0: no sibling is read and no frontier entry
    /// changes.
    function test_retirementAtLevelZero() public {
        for (uint32 i = 0; i < 5; ++i) {
            _deposit(100 + i);
        }
        vault.mutualClose(_close(4, 55, 1), PROOF);
        uint256[32] memory garbage;
        for (uint256 i = 0; i < 32; ++i) {
            garbage[i] = i + 1;
        }
        vm.record();
        vault.retireClosedLeaf(4, garbage);
        (, bytes32[] memory writes) = vm.accesses(address(vault));
        for (uint256 i = 0; i < writes.length; ++i) {
            assertTrue(
                uint256(writes[i]) < VaultStorage.SLOT_FILLED || uint256(writes[i]) >= VaultStorage.SLOT_FILLED + 32
            );
        }
        retired[4] = true;
        assertEq(vault.currentRoot(), _referenceRoot());
    }

    // ============================================================= pause epochs

    /// One epoch per unpause after a deposit; consecutive unpauses with no deposit between them
    /// share one record, overwritten with the newer total.
    function test_pauseEpochsRecordEachUnpauseAfterADeposit() public {
        uint32 a = _deposit(1);
        _pauseFor(2 hours);
        assertEq(vault.pauseEpochCount(), 1);
        _pauseFor(3 hours);
        assertEq(vault.pauseEpochCount(), 1, "no deposit since: overwritten");
        assertEq(VaultStorage.word(address(vault), VaultStorage.epochSlot(0)), (uint256(1) << 64) | 5 hours);
        uint32 b = _deposit(2);
        _pauseFor(1 hours);
        assertEq(vault.pauseEpochCount(), 2);
        uint32 c = _deposit(3);
        assertEq(vault.pausedBefore(a), 0);
        assertEq(vault.pausedBefore(b), 5 hours);
        assertEq(vault.pausedBefore(c), 6 hours);
        assertEq(vault.totalPausedDuration(), 6 hours);
    }

    /// pausedBefore over many epochs (the binary search below the latest) equals the paused time
    /// that preceded each deposit.
    function test_pausedBeforeOverManyEpochs() public {
        uint64[] memory expected = new uint64[](40);
        uint64 total;
        for (uint32 i = 0; i < 40; ++i) {
            expected[i] = total;
            _deposit(1000 + i);
            if (i % 3 != 2) {
                uint64 pause = uint64(1 hours + i);
                _pauseFor(pause);
                total += pause;
            }
        }
        assertGt(vault.pauseEpochCount(), 20);
        for (uint32 i = 0; i < 40; ++i) {
            assertEq(vault.pausedBefore(i), expected[i], vm.toString(uint256(i)));
        }
        assertEq(vault.pausedBefore(40), total);
    }

    /// A defeat long before the expiry reads no pause epoch and writes no grace (the fast path);
    /// one within a challenge period of the expiry, with an epoch after the deposit, reads the
    /// epochs and writes the exact grace.
    function test_defeatFastPathReadsNoEpoch() public {
        uint32 id = _deposit(42);
        _pauseFor(1 hours);
        _deposit(43);
        _pauseFor(1 hours);
        assertEq(vault.pauseEpochCount(), 2);
        vault.initiateEscapeWithdrawal(_escape(id, 101, 102, B2, 0), PROOF);
        Types.RequestPublicInputs memory successor = _evidence(102, 1);
        vm.record();
        vault.challengeEscapeWithdrawal(id, successor, PROOF);
        (bytes32[] memory reads,) = vm.accesses(address(vault));
        for (uint256 i = 0; i < reads.length; ++i) {
            assertTrue(reads[i] != VaultStorage.epochSlot(0) && reads[i] != VaultStorage.epochSlot(1), "epoch read");
        }
        assertEq(vault.graceUntil(id), 0);

        // The slow path: within a challenge period of the expiry.
        uint64 e = noteData[id].expiryTs;
        vm.warp(e);
        vault.initiateEscapeWithdrawal(_escape(id, 102, 103, B2, 0), PROOF);
        successor = _evidence(103, 1);
        vm.warp(_deadline(id) - 1);
        vm.record();
        vault.challengeEscapeWithdrawal(id, successor, PROOF);
        (reads,) = vm.accesses(address(vault));
        bool epochRead;
        for (uint256 i = 0; i < reads.length; ++i) {
            if (reads[i] == VaultStorage.epochSlot(1)) epochRead = true;
        }
        assertTrue(epochRead, "the exact lookup reads the latest epoch");
        // The note's active expiry is e (no pause before its deposit); the grace extends it.
        uint256 graceEnd = vm.getBlockTimestamp() - vault.totalPausedDuration() + CHALLENGE_PERIOD;
        assertEq(vault.graceUntil(id), graceEnd);
        assertGt(graceEnd, e);
    }

    /// forge-config: default.fuzz.runs = 64
    /// The expiry model of revision 3 (an active-clock expiry per note: e minus the paused time
    /// before its deposit, raised by each defeat's grace) against pause epochs and graceUntil, over
    /// random deposits, pauses and defeats of three notes.
    function testFuzz_effectiveExpiryMatchesTheRevisionThreeModel(uint256 seed) public {
        uint256[3] memory modelActive;
        uint256 nullifier = 10_000;
        for (uint256 step = 0; step < 24; ++step) {
            seed = uint256(keccak256(abi.encode(seed, step)));
            uint256 op = seed % 4;
            uint32 k = uint32((seed >> 8) % 3);
            if (op == 0 && vault.nextNoteId() < 3) {
                uint32 id = _deposit(2000 + step);
                modelActive[id] = noteData[id].expiryTs - vault.totalPausedDuration();
            } else if (op == 1) {
                _pauseFor(uint64(1 + ((seed >> 16) % 5 days)));
            } else if (op == 2 && k < vault.nextNoteId()) {
                uint32 id = k;
                if (_status(id) != Types.NoteStatus.Active) continue;
                nullifier += 2;
                vault.initiateEscapeWithdrawal(_escape(id, nullifier, nullifier + 1, 1, 0), PROOF);
                Types.RequestPublicInputs memory successor = _evidence(nullifier + 1, 1);
                vm.warp(vm.getBlockTimestamp() + ((seed >> 24) % CHALLENGE_PERIOD));
                vault.challengeEscapeWithdrawal(id, successor, PROOF);
                uint256 graceEnd = vm.getBlockTimestamp() - vault.totalPausedDuration() + CHALLENGE_PERIOD;
                if (graceEnd > modelActive[id]) modelActive[id] = graceEnd;
            } else {
                vm.warp(vm.getBlockTimestamp() + 1 + ((seed >> 32) % 20 days));
            }
            for (uint32 id = 0; id < vault.nextNoteId(); ++id) {
                uint256 claimAt = modelActive[id] + vault.totalPausedDuration();
                uint256 unpausedAt = vault.lastUnpausedAt();
                if (unpausedAt != 0 && unpausedAt + 1 days > claimAt) claimAt = unpausedAt + 1 days;
                if (!vault.paused()) assertEq(_effectiveExpiry(id), claimAt, "effective expiry");
            }
        }
    }

    // ================================================================= recordRoot

    /// recordRoot stores the live root with the note count and block, keeps the first record of a
    /// root, emits every time, and is open while paused; nothing else reads it.
    function test_recordRootIsAnAuditTrail() public {
        uint256 empty = vault.currentRoot();
        vm.roll(100);
        vm.expectEmit(address(vault));
        emit Events.RootRecorded(empty, 0, 100);
        assertEq(vault.recordRoot(), empty);
        (uint32 count, uint64 blockNumber) = vault.recordedRoot(empty);
        assertEq(count, 0);
        assertEq(blockNumber, 100);
        _deposit(42);
        vm.roll(101);
        uint256 root = vault.recordRoot();
        assertEq(root, vault.currentRoot());
        (count, blockNumber) = vault.recordedRoot(root);
        assertEq(count, 1);
        assertEq(blockNumber, 101);
        // A second record of the same root keeps the first.
        vm.roll(150);
        vm.expectEmit(address(vault));
        emit Events.RootRecorded(root, 1, 150);
        vault.recordRoot();
        (, blockNumber) = vault.recordedRoot(root);
        assertEq(blockNumber, 101);
        (count, blockNumber) = vault.recordedRoot(12_345);
        assertEq(count + blockNumber, 0);
        vault.pause();
        vm.prank(address(0xD00D));
        vault.recordRoot();
    }

    // ===================================================== removed interface (fail closed)

    /// The revision-3 selectors stale consumers might call are gone: notes, knownRoots,
    /// isKnownRoot, ROOT_HISTORY_WINDOW, and the old claimExpired, effectiveExpiry, mutualClose
    /// and initiateEscapeWithdrawal. Each reverts (no fallback), so they fail closed.
    function test_revisionThreeSelectorsRevert() public {
        _deposit(42);
        bytes4[8] memory removed =
            [bytes4(0x9f18e4ed), 0x12ad7381, 0xa6232a93, 0x1fe72de0, 0xa940507e, 0x7cb4a03c, 0x72cd2e44, 0xa38d62aa];
        for (uint256 i = 0; i < removed.length; ++i) {
            (bool ok, bytes memory ret) = address(vault).call(abi.encodePacked(removed[i], new bytes(0x400)));
            assertFalse(ok, vm.toString(abi.encodePacked(removed[i])));
            assertEq(ret.length, 0);
        }
    }

    // ================================================================= helpers

    function _pauseFor(uint64 duration) internal {
        uint64 unpausedAt = vault.lastUnpausedAt();
        if (unpausedAt != 0 && vm.getBlockTimestamp() < uint256(unpausedAt) + 1 days) {
            vm.warp(uint256(unpausedAt) + 1 days);
        }
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + duration);
        vault.unpause();
    }

    /// The root of a tree with these leaves at 0..n-1 (n <= 8), by the reference Poseidon.
    function _rootOfLeaves(uint256[] memory leaves) internal view returns (uint256 root) {
        uint256[8] memory level;
        for (uint256 i = 0; i < leaves.length; ++i) {
            level[i] = leaves[i];
        }
        root = _node(
            _node(_node(level[0], level[1]), _node(level[2], level[3])),
            _node(_node(level[4], level[5]), _node(level[6], level[7]))
        );
        for (uint256 h = 3; h < 32; ++h) {
            root = _node(root, emptySiblings[h]);
        }
    }

    /// Vault slots a deposit with `data` writes from zero to nonzero; the state is left as before.
    function _freshSlots(bytes memory data, uint256 value) internal returns (uint256 fresh) {
        uint256 before = vm.snapshotState();
        vm.record();
        vm.prank(user);
        (bool ok,) = address(vault).call{value: value}(data);
        assertTrue(ok);
        (, bytes32[] memory writes) = vm.accesses(address(vault));
        bytes32[] memory values = new bytes32[](writes.length);
        for (uint256 i = 0; i < writes.length; ++i) {
            values[i] = vm.load(address(vault), writes[i]);
        }
        vm.revertToState(before);
        for (uint256 i = 0; i < writes.length; ++i) {
            bool counted;
            for (uint256 j = 0; j < i; ++j) {
                if (writes[j] == writes[i]) counted = true;
            }
            if (!counted && values[i] != 0 && vm.load(address(vault), writes[i]) == 0) ++fresh;
        }
    }
}

/// @dev VaultStorage's slots against the vault's own getters, so that tests writing synthetic
///      states fail here first if the layout moves.
contract VaultStorageLayoutTest is VaultTestBase {
    function setUp() public {
        vm.warp(1_700_000_000);
        _setUpVault();
    }

    function test_slotsMatchTheGetters() public {
        uint32 id = _deposit(42);
        _deposit(43);
        _deposit(44);
        assertEq(
            VaultStorage.word(address(vault), bytes32(VaultStorage.SLOT_TREASURY_PAUSED_NEXT)),
            uint256(uint160(treasury)) | (uint256(3) << VaultStorage.NEXT_NOTE_ID_SHIFT)
        );
        VaultStorage.setNextNoteId(address(vault), 3);
        assertEq(vault.treasury(), treasury);
        assertEq(VaultStorage.word(address(vault), VaultStorage.noteSlot(id)) & VaultStorage.LEAF_MASK, _leafOf(id));
        assertEq(VaultStorage.word(address(vault), VaultStorage.filledSlot(1)), _node(_leafOf(0), _leafOf(1)));
        vault.pause();
        vm.warp(vm.getBlockTimestamp() + 1 hours);
        vault.unpause();
        assertEq(VaultStorage.word(address(vault), VaultStorage.epochSlot(0)), (uint256(3) << 64) | 1 hours);
        assertEq(
            VaultStorage.word(address(vault), bytes32(VaultStorage.SLOT_UNPAUSE)),
            uint256(vm.getBlockTimestamp()) | (uint256(1) << 64)
        );
        assertEq(VaultStorage.word(address(vault), bytes32(VaultStorage.SLOT_PAUSE_CLOCK)), uint256(1 hours) << 64);
        vault.initiateEscapeWithdrawal(_escape(id, 5, 6, 1, 0), PROOF);
        assertEq(VaultStorage.word(address(vault), VaultStorage.escapeSlot(id)), 5);
        assertEq(VaultStorage.word(address(vault), VaultStorage.nullifierSlot(5)), (uint256(6) << 2) | 1);
        vault.challengeEscapeWithdrawal(id, _evidence(6, 1), PROOF);
        vault.recordRoot();
        assertEq(
            VaultStorage.word(
                address(vault), VaultStorage.mapSlot(vault.currentRoot(), VaultStorage.SLOT_RECORDED_ROOTS)
            ),
            (uint256(block.number) << 32) | 3
        );
    }
}
