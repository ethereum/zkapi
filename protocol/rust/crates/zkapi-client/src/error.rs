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
    /// `clearance_ownership_required`, `legacy_clearance_capacity`,
    /// `nullifier_used` (a request already owns the nullifier),
    /// `note_binding_mismatch` (the ownership proof names other values than
    /// the vault records for the note) or `note_not_active` (the note is no
    /// longer `Active`).
    #[error("clearance refused: {0}")]
    ClearanceRefused(String),
    /// The operator answered every clearance retry with `note_not_recorded`:
    /// its chain view does not hold the note's deposit yet.
    #[error("note_not_recorded: the operator has not yet observed this note's deposit; retry the clearance later")]
    NoteNotRecorded,
    /// The vault records the note with other values than the wallet's: an
    /// exit names the note by its registration commitment, amount and expiry,
    /// and the vault refuses one that differs from its record.
    #[error("note_binding_mismatch: {0}")]
    NoteBindingMismatch(String),
    /// The note is not in the request tree yet. Notes are activated in id
    /// order, and `queue_position` notes are activated before this one (0:
    /// it is next). Exits do not wait for activation.
    #[error("note_not_activated: the note is not in the request tree yet ({queue_position} notes are activated before it); exits remain available")]
    NoteNotActivated { queue_position: u32 },
    /// A request's Merkle path does not lead from the note's leaf to its
    /// `active_root`: the path is stale, or the note is not activated.
    #[error(
        "merkle_path_mismatch: the Merkle path does not lead from the note's leaf to active_root"
    )]
    MerklePathMismatch,
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
