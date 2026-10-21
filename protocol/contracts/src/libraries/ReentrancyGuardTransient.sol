// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title ReentrancyGuardTransient
/// @notice OpenZeppelin's ReentrancyGuard on a transient slot (EIP-1153): the same guarantee and
///         error, at about 300 gas per guarded call instead of a storage write and its reset.
abstract contract ReentrancyGuardTransient {
    /// @dev keccak256("zkapi.ReentrancyGuardTransient.status") - 1; a hash, so it coincides with no
    ///      transient slot a contract keys by an address or a hash of its own.
    bytes32 private constant STATUS_SLOT = 0x8705bd7c6783811c050f156e889f6a4a0ff9c2889d9e2dadd9275ad623d62d55;

    error ReentrancyGuardReentrantCall();

    modifier nonReentrant() {
        _nonReentrantBefore();
        _;
        _nonReentrantAfter();
    }

    function _nonReentrantBefore() private {
        bool entered;
        assembly ("memory-safe") {
            entered := tload(STATUS_SLOT)
        }
        if (entered) revert ReentrancyGuardReentrantCall();
        assembly ("memory-safe") {
            tstore(STATUS_SLOT, 1)
        }
    }

    function _nonReentrantAfter() private {
        assembly ("memory-safe") {
            tstore(STATUS_SLOT, 0)
        }
    }
}
