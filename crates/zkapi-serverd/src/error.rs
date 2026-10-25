//! Server error types.

use thiserror::Error;

/// Errors that can occur during server-side request processing.
#[derive(Error, Debug)]
pub enum ServerError {
    /// Emitted before a native request nullifier is reserved. Existing bound
    /// requests retain their quote and never return this during recovery.
    #[error("native billing quote expired before request acceptance")]
    NativeQuoteExpired,

    /// A newer finalized oracle round exists before request acceptance.
    /// Recover this exact request before preparing another proof.
    #[error("native billing quote superseded before request acceptance")]
    NativeQuoteSuperseded,

    #[error("invalid proof: {0}")]
    InvalidProof(String),

    /// O5': a request's `active_root` is neither the vault's latest root
    /// nor one the vault replaced within `request_root_grace_seconds`.
    /// Requests only: clearance checks the note leaf, never a root.
    #[error("stale root: latest is {latest_root}")]
    StaleRoot { latest_root: String },

    /// A clearance ownership proof's `note_leaf` is not the leaf the vault
    /// stores for its note (`noteRecord(note_id)`; 0 for an unknown or
    /// retired note).
    #[error("the ownership proof's note leaf is not the vault's leaf for note {note_id}")]
    NoteLeafMismatch { note_id: u32 },

    /// The vault's note is not Active (an escape is pending, or it is
    /// closed): no clearance is signed.
    #[error("note {note_id} is not active in the vault")]
    NoteNotActive { note_id: u32 },

    #[error("replayed nullifier")]
    Replay,

    #[error("note expired")]
    NoteExpired,

    #[error("internal error: {0}")]
    Internal(String),

    /// A deterministic settlement failure, such as a corrupt persisted quote.
    /// Settlement absorbs it by finalizing at the proof-bound worst case.
    #[error("lease cannot be settled from measured usage: {0}")]
    Unsettleable(String),

    /// POST /v2/withdraw/clearance without a kind-2 ownership proof.
    #[error("clearance requires a kind-2 ownership proof of the note")]
    ClearanceOwnershipRequired,

    #[error("capacity exhausted")]
    CapacityExhausted,

    #[error("nullifier already used")]
    NullifierUsed,

    #[error("database error: {0}")]
    Database(String),

    /// The store holds a lease row for this ID that it cannot decode. It
    /// never heals by itself (an operator restores its saved request with
    /// `zkapi settlement reopen --saved-request`, also for a pending lease,
    /// which the settlement sweep skips until then, or repairs another
    /// undecodable column by hand, which that command names); the request's
    /// nullifier record stays readable and authoritative. The decoding error
    /// is logged, not returned.
    #[error(
        "lease record cannot be decoded until an operator repairs it; GET /v2/nullifiers/{{request_nullifier}} is authoritative"
    )]
    LeaseRecordUnreadable,

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("protocol mismatch: {0}")]
    ProtocolMismatch(String),

    #[error("OpenRouter lease is already active or awaiting settlement")]
    LeasePending,

    #[error(
        "OpenRouter lease settlement is still pending; retry after {retry_after_seconds} seconds"
    )]
    LeaseSettlementPending { retry_after_seconds: u64 },

    #[error("OA org rejected the key allowance or duration; recover the saved request")]
    OaKeyPolicyRejected,

    /// O5': the server has not read the vault's currentRoot() within
    /// `root_max_staleness_seconds`, so it admits no request. Nothing was
    /// reserved. The indexer never causes it.
    #[error("the current Merkle root is unavailable: {0}; retry shortly")]
    RootUnavailable(String),

    /// The request's lease budget exceeds the operator's per-request ceiling
    /// (`--request-limit-max-usd-micros`). Nothing was reserved.
    #[error(
        "the request's lease budget of {limit_micro_usd} micro-USD exceeds this server's \
         ceiling of {max_micro_usd} micro-USD; prove a lower solvency bound"
    )]
    RequestLimitExceeded {
        limit_micro_usd: u128,
        max_micro_usd: u128,
    },

    /// The nullifier is consumed or challenged on chain, or appears in a
    /// vault event: the server no longer serves its request data.
    #[error("the nullifier is published on chain")]
    Published,

    /// A chain (or indexer) read the answer depends on failed; nothing is
    /// served until it succeeds.
    #[error("chain state is unavailable: {0}; retry shortly")]
    ChainReadUnavailable(String),

    #[error(
        "OA org key issuance was rate limited ({reason}); retry after {retry_after_seconds} seconds"
    )]
    OaRateLimited {
        reason: String,
        retry_after_seconds: u64,
    },
}

impl ServerError {
    /// Return a machine-readable error code string for the error.
    pub fn error_code(&self) -> &str {
        match self {
            ServerError::NativeQuoteExpired => "native_quote_expired",
            ServerError::NativeQuoteSuperseded => "native_quote_superseded",
            ServerError::InvalidProof(_) => "invalid_proof",
            ServerError::StaleRoot { .. } => "stale_root",
            ServerError::NoteLeafMismatch { .. } => "note_leaf_mismatch",
            ServerError::NoteNotActive { .. } => "note_not_active",
            ServerError::Replay => "replay",
            ServerError::NoteExpired => "note_expired",
            ServerError::Internal(_) => "internal_error",
            ServerError::Unsettleable(_) => "lease_unsettleable",
            ServerError::ClearanceOwnershipRequired => "clearance_ownership_required",
            ServerError::CapacityExhausted => "capacity_exhausted",
            ServerError::NullifierUsed => "nullifier_used",
            ServerError::Database(_) => "database_error",
            ServerError::LeaseRecordUnreadable => "lease_record_unreadable",
            ServerError::InvalidRequest(_) => "invalid_request",
            ServerError::ProtocolMismatch(_) => "protocol_mismatch",
            ServerError::LeasePending => "lease_pending",
            ServerError::LeaseSettlementPending { .. } => "lease_settlement_pending",
            ServerError::OaKeyPolicyRejected => "oa_key_policy_rejected",
            ServerError::OaRateLimited { reason, .. } => reason,
            ServerError::RootUnavailable(_) => "root_unavailable",
            ServerError::RequestLimitExceeded { .. } => "request_limit_exceeded",
            ServerError::Published => "published",
            ServerError::ChainReadUnavailable(_) => "chain_read_unavailable",
        }
    }

    /// Whether the client should retry the request.
    pub fn is_retriable(&self) -> bool {
        match self {
            ServerError::NativeQuoteExpired => true,
            ServerError::NativeQuoteSuperseded => false,
            ServerError::StaleRoot { .. } => true,
            // The stored leaf of a note never changes while it is Active.
            ServerError::NoteLeafMismatch { .. } => false,
            // A pending escape or a closed note does not become Active again.
            ServerError::NoteNotActive { .. } => false,
            ServerError::Internal(_) => true,
            ServerError::Database(_) => true,
            // Only an operator's repair of the row changes the answer.
            ServerError::LeaseRecordUnreadable => false,
            ServerError::Unsettleable(_) => false,
            ServerError::ClearanceOwnershipRequired => false,
            ServerError::InvalidProof(_) => false,
            ServerError::Replay => false,
            ServerError::NoteExpired => false,
            // Clearance proof verification is bounded; retry after backoff.
            ServerError::CapacityExhausted => true,
            ServerError::NullifierUsed => false,
            ServerError::InvalidRequest(_) => false,
            ServerError::ProtocolMismatch(_) => false,
            ServerError::LeasePending => true,
            ServerError::LeaseSettlementPending { .. } => true,
            ServerError::OaKeyPolicyRejected => false,
            ServerError::OaRateLimited { .. } => true,
            ServerError::RootUnavailable(_) => true,
            ServerError::RequestLimitExceeded { .. } => false,
            ServerError::Published => false,
            ServerError::ChainReadUnavailable(_) => true,
        }
    }
}
