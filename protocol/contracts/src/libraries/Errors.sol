// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title Errors – Custom revert reasons for zkAPI
library Errors {
    error InvalidNativeValue();
    error NativeTransferFailed();
    /// @notice The supplied proof did not verify.
    error InvalidProof();

    /// @notice The Merkle siblings do not reproduce the current root.
    error StaleRoot();

    /// @notice A withdrawal proof's activeRoot is neither current nor retired within ROOT_HISTORY_WINDOW.
    error UnknownRoot();

    /// @notice The nullifier has already been consumed.
    error ReplayedNullifier();

    /// @notice An escape at this nullifier was defeated by a challenge; exit from the successor state.
    error ChallengedNullifier();

    /// @notice The withdrawal destination is the zero address or the vault itself.
    error InvalidDestination();

    /// @notice The note is not in Active status.
    error NoteNotActive();

    /// @notice The note is in PendingWithdrawal status (unexpected).
    error NotePendingWithdrawal();

    /// @notice The note has passed its expiry timestamp.
    error NoteExpired();

    /// @notice The note has not yet reached its expiry timestamp.
    error NoteNotExpired();

    /// @notice The deposit amount is zero or otherwise insufficient.
    error InsufficientDeposit();

    /// @notice The commitment is zero or otherwise invalid.
    error InvalidCommitment();

    /// @notice finalBalance exceeds the deposit amount.
    error InvalidBalance();

    /// @notice The challenge period has already elapsed.
    error ChallengeExpired();

    /// @notice The challenge period has not yet elapsed.
    error ChallengeNotExpired();

    /// @notice Expected PendingWithdrawal status but note is not pending.
    error NotPendingWithdrawal();

    /// @notice A proof is for another protocol, chain, contract, or signing key.
    error InvalidDeploymentBinding();

    /// @notice The sibling array length or values are invalid.
    error InvalidSiblings();

    /// @notice A zero amount was provided where a nonzero value is required.
    error ZeroAmount();

    /// @notice The contract is paused.
    error Paused();

    /// @notice The contract is not paused.
    error NotPaused();

    /// @notice No treasury change is scheduled.
    error NoPendingTreasuryChange();

    /// @notice The scheduled treasury change is still inside its timelock.
    error TreasuryChangeNotReady();

    /// @notice The caller is not authorized for this operation.
    error Unauthorized();

    /// @notice A field value is outside the BN254 scalar field.
    error InvalidFelt();

    /// @notice The withdrawal proof's kind is not the one this entry point accepts: escapes take
    ///         kind 0, mutual closes kind 1, and no entry point accepts an ownership proof (kind 2).
    error WrongWithdrawalKind();

    /// @notice An escape from the state just below a defeated escape: its successor nullifier
    ///         belongs to a state that was spent, so successor evidence exists.
    error SupersededState();

    /// @notice A defeat must carry a request proof at the escape's successor nullifier.
    error NotSuccessorEvidence();

    /// @notice A raise must carry a request proof at the escaped state's nullifier.
    error NotStateEvidence();

    /// @notice The raise would not increase the escape's concession.
    error NotARaise();

    /// @notice The withdrawal proof's validUntil has passed.
    error ProofExpired();

    /// @notice A pause within PAUSE_COOLDOWN of the latest unpause.
    error PauseCooldown();

    /// @notice retireClosedLeaf on a note that is not Closed.
    error NoteNotClosed();

    /// @notice A withdrawal statement's registrationCommitment or noteMetadata is not what the vault
    ///         stores for its note.
    error NoteBindingMismatch();

    /// @notice An activation named another first note or root than the vault's current ones (a
    ///         competing activation or a retirement landed first): rebuild it from the new state.
    error StaleActivation();

    /// @notice An activation of an unsupported count (1, 4 or 16), off the count's alignment, or of
    ///         notes not yet recorded.
    error InvalidActivation();

    /// @notice A retirement named a note that is not in the request tree yet.
    error NoteNotActivated();

    /// @notice activateNotes from an address other than the vault's activator.
    error NotActivator();

    /// @notice activateNotesOnChain before activationFallbackOpensAt: a proved activation, the
    ///         deployment or an unpause happened less than ACTIVATION_FALLBACK_DELAY ago.
    error ActivationFallbackClosed();
}
