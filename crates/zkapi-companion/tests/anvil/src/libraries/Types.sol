// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice The request and withdrawal statements' public inputs (circuit
///         zkapi-v2-concession-v2), for compiling the generated adapter alone in the companion's
///         Anvil test. Field order is the public-input order.
library Types {
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

    struct WithdrawalPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        uint256 registrationCommitment;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint256 clearanceSigningKeyX;
        uint256 clearanceSigningKeyY;
        uint32 noteId;
        uint128 finalBalance;
        address destination;
        uint256 withdrawalNullifier;
        uint8 kind;
        uint256 nextNullifier;
        uint128 conceded;
        uint64 validUntil;
        uint256 noteMetadata;
    }
}
