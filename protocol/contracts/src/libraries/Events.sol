// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Events – All events emitted by ZkApiVault
abstract contract Events {
    /// @notice A note was recorded. Its leaf enters the request tree when it is activated
    ///         (NotesActivated); it can exit at once.
    event NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment, uint128 amount, uint64 expiryTs);

    /// @notice Notes firstNoteId .. firstNoteId + count - 1 were appended to the request tree, whose
    ///         root is now newRoot. `proved` tells a proved batch from the on-chain fallback.
    event NotesActivated(uint32 indexed firstNoteId, uint32 count, uint256 newRoot, bool proved);

    /// @notice The address allowed to call activateNotes changed (from address(0) at deployment).
    event ActivatorChanged(address indexed previousActivator, address indexed newActivator);

    event MutualClose(uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination);

    /// @notice An escape started. Escapes do no Merkle work, so `currentRoot` is the unchanged root.
    ///         EscapeConcessionRecorded follows in the same call.
    event EscapeWithdrawalInitiated(
        uint32 indexed noteId,
        uint256 nullifier,
        uint128 finalBalance,
        address destination,
        uint64 challengeDeadline,
        uint256 currentRoot
    );

    /// @notice The concession side of the escape just initiated: `nextNullifier` (N_{k+1}) is the
    ///         only nullifier whose request proof defeats it, and finalBalance + conceded == stateBalance.
    event EscapeConcessionRecorded(
        uint32 indexed noteId, uint256 nextNullifier, uint128 stateBalance, uint128 conceded
    );

    /// @notice A request proof at the escaped nullifier raised the concession to `conceded`;
    ///         `finalBalance` is the new payout.
    event EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier, uint128 conceded, uint128 finalBalance);

    /// @notice A request proof at the successor nullifier defeated the escape. `currentRoot` is the
    ///         unchanged root (the leaf was never removed).
    event EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier, uint256 currentRoot);

    /// @notice A Closed note's leaf was removed from the tree.
    event ClosedLeafRetired(uint32 indexed noteId, uint256 newRoot);

    /// @notice The escape closed. It does not by itself mean `destination` received
    ///         `finalBalance`: when an EscapePayoutDeferred for the same noteId and destination
    ///         precedes it in the transaction, the balance was credited to
    ///         escapePayoutCredits(destination) instead and reaches it via claimEscapePayout.
    event EscapeWithdrawalFinalized(
        uint32 indexed noteId, uint256 nullifier, uint128 finalBalance, address destination
    );

    /// @notice `currentRoot` is the unchanged root: an expiry claim leaves the leaf in place.
    event ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount, uint256 currentRoot);

    event ProofAdapterSet(address indexed newAdapter);

    /// @notice Emitted when a scheduled treasury change takes effect.
    event TreasurySet(address indexed newTreasury);

    /// @notice `readyAt` is on the vault's active clock (wall clock minus all paused time).
    event TreasuryChangeScheduled(address indexed newTreasury, uint64 readyAt);

    event TreasuryChangeCancelled(address indexed cancelledTreasury);

    /// @notice A treasury push failed; `amount` gwei units were added to treasuryArrears.
    event TreasuryPaymentDeferred(address indexed treasury, uint128 amount);

    event TreasuryArrearsPaid(address indexed treasury, uint128 amount);

    /// @notice A finalized escape's push to `destination` failed; `amount` gwei units were added to
    ///         escapePayoutCredits(destination). EscapeWithdrawalFinalized follows in the same call.
    event EscapePayoutDeferred(uint32 indexed noteId, address indexed destination, uint128 amount);

    /// @notice claimEscapePayout paid `destination` its credited escape payouts.
    event EscapePayoutClaimed(address indexed destination, uint128 amount);

    /// @dev Same signatures as OpenZeppelin Pausable for monitoring compatibility.
    event Paused(address account);

    event Unpaused(address account);
}
