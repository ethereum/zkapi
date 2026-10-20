// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";

/// @dev ZkApiVault's storage layout (forge inspect ZkApiVault storageLayout), for tests that read
///      the packed records or write synthetic states (high note IDs, frontiers, pause epochs).
///      VaultStorageLayoutTest pins every slot against the vault's own getters, so a layout change
///      fails there first.
library VaultStorage {
    Vm private constant VM = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    /// treasury (bits 0-159) | paused (160-167) | nextNoteId (168-199).
    uint256 internal constant SLOT_TREASURY_PAUSED_NEXT = 2;
    uint256 internal constant NEXT_NOTE_ID_SHIFT = 168;
    /// pausedAt (0-63) | totalPausedDuration (64-127) | treasuryArrears (128-255).
    uint256 internal constant SLOT_PAUSE_CLOCK = 3;
    /// lastUnpausedAt (0-63) | pauseEpochCount (64-95).
    uint256 internal constant SLOT_UNPAUSE = 5;
    uint256 internal constant SLOT_NOTES = 6;
    uint256 internal constant SLOT_ESCAPES = 7;
    uint256 internal constant SLOT_NULLIFIER_WORDS = 8;
    uint256 internal constant SLOT_GRACE_UNTIL = 9;
    uint256 internal constant SLOT_PAUSE_EPOCHS = 11;
    uint256 internal constant SLOT_RECORDED_ROOTS = 12;
    uint256 internal constant SLOT_FILLED = 13;

    uint256 internal constant STATUS_SHIFT = 254;
    uint256 internal constant LEAF_MASK = (uint256(1) << 254) - 1;
    uint256 internal constant ACTIVE = 1;
    uint256 internal constant PENDING = 2;
    uint256 internal constant CLOSED = 3;

    function mapSlot(uint256 key, uint256 slot) internal pure returns (bytes32) {
        return keccak256(abi.encode(key, slot));
    }

    function noteSlot(uint32 noteId) internal pure returns (bytes32) {
        return mapSlot(noteId, SLOT_NOTES);
    }

    /// Slot 0 of the escape record of `noteId` (withdrawalNullifier); slot 1 is
    /// challengeDeadline | finalBalance << 64 | conceded << 128 | depositAmount << 192.
    function escapeSlot(uint32 noteId) internal pure returns (bytes32) {
        return mapSlot(noteId, SLOT_ESCAPES);
    }

    function nullifierSlot(uint256 nullifier) internal pure returns (bytes32) {
        return mapSlot(nullifier, SLOT_NULLIFIER_WORDS);
    }

    function epochSlot(uint32 index) internal pure returns (bytes32) {
        return mapSlot(index, SLOT_PAUSE_EPOCHS);
    }

    function filledSlot(uint256 level) internal pure returns (bytes32) {
        return bytes32(SLOT_FILLED + level);
    }

    function word(address vault, bytes32 slot) internal view returns (uint256) {
        return uint256(VM.load(vault, slot));
    }

    /// Writes nextNoteId, keeping the treasury and the pause flag of its slot.
    function setNextNoteId(address vault, uint32 next) internal {
        bytes32 slot = bytes32(SLOT_TREASURY_PAUSED_NEXT);
        uint256 value = uint256(VM.load(vault, slot));
        value = (value & ~(uint256(type(uint32).max) << NEXT_NOTE_ID_SHIFT)) | (uint256(next) << NEXT_NOTE_ID_SHIFT);
        VM.store(vault, slot, bytes32(value));
    }

    function setNote(address vault, uint32 noteId, uint256 leaf, uint256 status) internal {
        VM.store(vault, noteSlot(noteId), bytes32(leaf | (status << STATUS_SHIFT)));
    }

    function setFilled(address vault, uint256 level, uint256 node) internal {
        VM.store(vault, filledSlot(level), bytes32(node));
    }
}
