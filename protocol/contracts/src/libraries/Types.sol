// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Types – Shared zkAPI v2 data structures
library Types {
    /// @dev A note's status, the top two bits of its storage word (ZkApiVault._notes: the leaf in
    ///      bits 0-253, the status in 254-255). Uninitialized is the zero word; a retired note is
    ///      Closed with a zero leaf.
    enum NoteStatus {
        Uninitialized,
        Active,
        PendingWithdrawal,
        Closed
    }

    /// @dev A pending escape's own record, 2 slots. The rest of the escape lives in the words of
    ///      the two nullifiers it consumes, which are written anyway (ZkApiVault._nullifierWords):
    ///      N_k's word holds N_{k+1}, and N_{k+1}'s word the destination and the note's expiryTs.
    ///      The getters pendingWithdrawals (6 words: exists, a zero word where revision 2 had the
    ///      proof's activeRoot, withdrawalNullifier, finalBalance, destination, challengeDeadline)
    ///      and pendingConcessions (3 words: nextNullifier, stateBalance, conceded) are what clients
    ///      and the challenger decode; `exists` is challengeDeadline != 0 and stateBalance =
    ///      finalBalance + conceded.
    ///      The vault keeps no deposit or expiry per note (only the leaf that binds them), so the
    ///      record carries the note's D, proven by the escape's leaf-bound noteFields, for the
    ///      finalization's treasury share, and N_{k+1}'s word carries e for the defeat's grace.
    ///      Every amount is at most D, which the vault bounds by MAX_NATIVE_UNITS (< 2^53) before
    ///      it writes the record with checked casts, so uint64 holds each.
    struct Escape {
        /// @dev N_k of the state the escape leaves.
        uint256 withdrawalNullifier;
        /// @dev Nonzero exactly while the escape is pending.
        uint64 challengeDeadline;
        /// @dev The current payout: the state balance B_k minus `conceded`.
        uint64 finalBalance;
        /// @dev c; a raise only ever increases it.
        uint64 conceded;
        /// @dev The note's deposit D (from the escape's noteFields): finalization pays the
        ///      treasury D - finalBalance.
        uint64 depositAmount;
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

    /// @dev Field order is the exact Groth16 public-input order (16 inputs) of circuit
    ///      zkapi-v2-concession-v2. A static tuple, so its ABI words are the public inputs in order.
    struct WithdrawalPublicInputs {
        uint16 protocolVersion;
        uint64 chainId;
        address contractAddress;
        /// @dev The note's leaf P(d_leaf', R, noteFields)[1], which the vault stored at deposit.
        uint256 noteLeaf;
        uint256 stateSigningKeyX;
        uint256 stateSigningKeyY;
        uint256 clearanceSigningKeyX;
        uint256 clearanceSigningKeyY;
        /// @dev noteId * 2^192 + depositAmount * 2^64 + expiryTs (NoteLeafLib.pack): below 2^224
        ///      for every note; the vault refuses a wider value (InvalidNoteFields).
        uint256 noteFields;
        /// @dev The payout: the state balance minus `conceded`.
        uint128 finalBalance;
        /// @dev Zero for an ownership proof (kind 2).
        address destination;
        /// @dev N_k = H(d_null', s, noteId, anchor) of the state the exit leaves.
        uint256 withdrawalNullifier;
        /// @dev 0 escape, 1 mutual close, 2 ownership proof (never accepted by the vault).
        uint8 kind;
        /// @dev N_{k+1}, the nullifier of the state's derived successor, for an escape; 0 otherwise.
        uint256 nextNullifier;
        /// @dev The amount an escape gives up; 0 unless kind is 0.
        uint128 conceded;
        /// @dev The latest second at which the vault accepts the proof.
        uint64 validUntil;
    }
}
