//! Client error types.

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Sepolia password is missing or incorrect")]
    TestnetPasswordRequired,
    #[error("no active note")]
    NoActiveNote,
    #[error("note already exists")]
    NoteAlreadyExists,
    #[error("insufficient balance: need {needed}, have {available}")]
    InsufficientBalance { needed: u128, available: u128 },
    #[error("stale root")]
    StaleRoot,
    #[error("server error: {0}")]
    ServerError(String),
    #[error("invalid server response: {0}")]
    InvalidResponse(String),
    #[error("pending request exists, must recover first")]
    PendingRequest,
    /// A signed note state without the anchor of its predecessor cannot
    /// prove a request (the request circuit checks that its anchor is derived
    /// from the predecessor's nullifier). Exits never need it.
    #[error("prev_anchor_missing: this note state has no predecessor anchor; requests are refused, exits remain available")]
    PrevAnchorMissing,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("proof generation failed: {0}")]
    ProofGeneration(String),
    #[error("verification failed: {0}")]
    VerificationFailed(String),
    /// The server refused a clearance with a code that reserves nothing:
    /// `clearance_ownership_required`, `legacy_clearance_capacity`, or
    /// `nullifier_used` (a request already owns the nullifier).
    #[error("clearance refused: {0}")]
    ClearanceRefused(String),
    /// C2: a request proof at this state already carries another bound.
    #[error("bound_fixed_at_state: every request proof at this note state must carry the solvency bound {bound}, not {requested}")]
    BoundFixedAtState { bound: u128, requested: u128 },
    /// C3: an exit is in progress at this note; no request proof is made.
    #[error("exit_locked: an exit of this note is in progress, so no request proof is made")]
    ExitLocked,
    /// C4: too close to the latest time to start an exit.
    #[error("note_near_expiry: the note is too close to the latest time to start an exit for a new request to settle first")]
    NoteNearExpiry,
    /// C5: an ownership proof of this state was sent, or may have been.
    #[error("ownership_proof_sent: an ownership proof of this note state was sent, so no request proof is made from it")]
    OwnershipProofSent,
    /// The server signed a successor that fails S3, S4 or S5. It is treated
    /// like a withheld successor and archived as `invalid_successor`.
    #[error("invalid_successor: {0}")]
    InvalidSuccessor(String),
    /// A valid successor arrived after an exit proof of its predecessor was
    /// released. It is archived as `late_successor` and installed only once
    /// the exit lock is released (E6).
    #[error("late_successor: a valid successor arrived after an exit proof was released; it is kept until the exit lock is released")]
    LateSuccessor,
    /// The exit lock does not allow this proof (C3), or is missing.
    #[error("exit_lock_conflict: {0}")]
    ExitLockConflict(String),
    /// C3: an escape concedes at most `bound_at_state`.
    #[error("concession_above_bound: an escape from this state may concede at most {bound}, not {conceded}")]
    ConcessionAboveBound { conceded: u128, bound: u128 },
}
