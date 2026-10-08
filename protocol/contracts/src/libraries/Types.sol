// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Types – Shared zkAPI v2 data structures
library Types {
    enum NoteStatus {
        Uninitialized,
        Active,
        PendingWithdrawal,
        Closed
    }

    struct Note {
        bytes32 commitment;
        uint128 depositAmount;
        uint64 expiryTs;
        NoteStatus status;
        /// @dev Snapshot of vault cumulative paused time at deposit. Used so
        /// claimExpired treats only pauses during this note's lifetime as an
        /// extension of expiryTs (expiryTs itself stays immutable for leaves).
        uint64 pausedSnapshot;
    }

    struct PendingWithdrawalData {
        bool exists;
        uint256 activeRoot;
        uint256 withdrawalNullifier;
        uint128 finalBalance;
        address destination;
        uint64 challengeDeadline;
    }

    /// @dev Field order is the exact Groth16 public-input order.
    struct RequestPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint64 requestTime;
        uint128 solvencyBound;
        uint256 requestNullifier;
        uint256 authorizationTag;
        uint256 anonymousCommitmentX;
        uint256 anonymousCommitmentY;
    }

    /// @dev Field order is the exact Groth16 public-input order.
    struct WithdrawalPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 activeRoot;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint256 clearanceSigningKeyX;
        uint256 clearanceSigningKeyY;
        uint32 noteId;
        uint128 finalBalance;
        address destination;
        uint256 withdrawalNullifier;
        bool hasClearance;
        uint256 withdrawalTag;
    }
}
