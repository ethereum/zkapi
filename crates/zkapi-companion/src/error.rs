use axum::http::StatusCode;
use thiserror::Error;
use zkapi_client::error::ClientError;
use zkapi_types::Felt252;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Sepolia password is missing or incorrect; stop the daemon and run zkapi-clientd config to enter the current shared password")]
    TestnetPasswordRequired,
    #[error("inference is awaiting settlement; retry withdrawal after settlement")]
    PendingSettlement,
    #[error("withdrawal transaction is awaiting finalized confirmation")]
    OaWithdrawalPending,
    #[error("a withdrawal is reserved for a different destination or note state; resume the saved withdrawal")]
    WithdrawalConflict,
    #[error("wallet is busy in another process")]
    WalletBusy,
    #[error("wallet has no active note; fund it first")]
    NoActiveNote,
    #[error("wallet balance is too low for this request")]
    InsufficientBalance,
    #[error("wallet has a pending request; recover it before spending again")]
    PendingRequest,
    #[error("OpenRouter lease pending: {0}")]
    LeasePending(String),
    #[error("withdrawal pending: {0}")]
    WithdrawalPending(String),
    #[error(
        "another chat ({active_session_id}) owns the current ephemeral key until {expires_at}"
    )]
    LeaseSessionConflict {
        active_session_id: String,
        expires_at: u64,
    },
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("upstream returned {status}: {message}")]
    UpstreamResponse { status: StatusCode, message: String },
    #[error("OA key verification failed: {0}")]
    KeyVerification(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("wallet error: {0}")]
    Wallet(String),
    #[error("indexer error: {0}")]
    Indexer(String),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("receipt journal missing: the server reports this note state's nullifier {0} settled by a request this wallet holds no journal or archive record of, so its receipt cannot be installed and neither chat requests nor a withdrawal can continue from this state; an earlier release deleted that request's journal (a lying server could claim the same). Contact the zkAPI operator with this nullifier")]
    ReceiptJournalMissing(Felt252),
    #[error("this note state is withdrawal-only: a withdrawal clearance request carrying its ownership proof was sent, or may have been sent, and whoever saw that request may hold the proof, which is a valid escape at this state; on this vault a chat request from this state would let them escape and challenge it, which burns the note's nullifier, so no chat request is made from it and its withdrawal reservation is not released. Retry the withdrawal (in zkapi-clientd: config --menu, then withdraw) to close the note")]
    OwnershipProofSent,
    #[error("bound_fixed_at_state: every request from this note state must carry the solvency bound {bound}; this request needs {requested}. Choose a cheaper model, or wait for the earlier request to settle")]
    BoundFixedAtState { bound: u128, requested: u128 },
    #[error("exit_locked: an exit of this note is in progress, so no chat request is made; finish or cancel the withdrawal")]
    ExitLocked,
    #[error("note_near_expiry: the note is too close to the latest time to start an exit for a new request to settle first; withdraw the balance")]
    NoteNearExpiry,
    #[error("invalid_successor: the server signed a successor that fails the wallet's checks ({0}); the state is treated as withheld, so withdraw by escape")]
    InvalidSuccessor(String),
    #[error("late_successor: a successor arrived after an exit proof was released; it is kept until that exit is dead")]
    LateSuccessor,
    #[error("escape_required: a mutual close is not possible from this note state; use the escape withdrawal")]
    EscapeRequired(serde_json::Value),
    #[error("conceded_mismatch: the confirmed concession is not the one the exit rules allow now; review the escape again")]
    ConcededMismatch(serde_json::Value),
    #[error("device_not_newest: another device spent this note state; restore the newest backup before exiting")]
    DeviceNotNewest,
    #[error("exit_lock_conflict: {0}")]
    ExitLockConflict(String),
    #[error("note_not_activated: the deposit is recorded but the note is not in the request tree yet ({queue_position} notes are activated before it), so it cannot pay for requests; retry once the operator's batch activates it (withdrawals are available now)")]
    NoteNotActivated {
        queue_position: u32,
        /// The vault's `activationCursor()` the refusal was decided at.
        activation_cursor: Option<u32>,
    },
    #[error("indexer_root_lag: the vault activated the note (its activation cursor is {activation_cursor}), but the operator's indexer has not caught up with that activation yet, so no request can be proved against its tree; retry in a few seconds")]
    IndexerRootLag {
        /// The vault's `activationCursor()`, past the note.
        activation_cursor: u32,
    },
    #[error("note_binding_mismatch: {0}")]
    NoteBindingMismatch(String),
    #[error("note_not_recorded: the operator has not observed this note's deposit yet; retry the withdrawal shortly")]
    NoteNotRecorded,
    #[error("this note state is reserved for a withdrawal: the server holds a clearance for its nullifier (an earlier withdrawal reserved it, or the operator released a stuck state) and refuses every request at it as a replay, so no chat request can settle this state; withdraw the balance by mutual close (in zkapi-clientd: config --menu, then withdraw), which sets the refused request aside first")]
    ClearanceReservedState,
}

impl AuthError {
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::TestnetPasswordRequired => StatusCode::UNAUTHORIZED,
            Self::WalletBusy
            | Self::PendingSettlement
            | Self::OaWithdrawalPending
            | Self::WithdrawalConflict
            | Self::ReceiptJournalMissing(_)
            | Self::OwnershipProofSent
            | Self::ClearanceReservedState
            | Self::BoundFixedAtState { .. }
            | Self::ExitLocked
            | Self::NoteNearExpiry
            | Self::InvalidSuccessor(_)
            | Self::LateSuccessor
            | Self::EscapeRequired(_)
            | Self::ConcededMismatch(_)
            | Self::DeviceNotNewest
            | Self::ExitLockConflict(_)
            | Self::NoteNotActivated { .. }
            | Self::NoteBindingMismatch(_)
            | Self::NoteNotRecorded => StatusCode::CONFLICT,
            Self::NoActiveNote | Self::InsufficientBalance => StatusCode::PAYMENT_REQUIRED,
            Self::IndexerRootLag { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::PendingRequest
            | Self::LeasePending(_)
            | Self::WithdrawalPending(_)
            | Self::LeaseSessionConflict { .. } => StatusCode::CONFLICT,
            Self::InvalidInput(_) | Self::Serialization(_) => StatusCode::BAD_REQUEST,
            Self::UpstreamResponse { status, .. } => *status,
            Self::Wallet(_) | Self::Indexer(_) | Self::Upstream(_) | Self::KeyVerification(_) => {
                StatusCode::BAD_GATEWAY
            }
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::TestnetPasswordRequired => "testnet_password_required",
            Self::WalletBusy => "wallet_busy",
            Self::PendingSettlement => "pending_settlement",
            Self::OaWithdrawalPending => "withdrawal_pending",
            Self::WithdrawalConflict => "withdrawal_conflict",
            Self::NoActiveNote => "no_active_note",
            Self::InsufficientBalance => "insufficient_balance",
            Self::PendingRequest => "pending_request",
            Self::LeasePending(_) => "lease_pending",
            Self::WithdrawalPending(_) => "withdrawal_pending",
            Self::LeaseSessionConflict { .. } => "lease_session_conflict",
            Self::Upstream(_) | Self::UpstreamResponse { .. } => "upstream_error",
            Self::KeyVerification(_) => "key_verification_failed",
            Self::InvalidInput(_) => "invalid_input",
            Self::Wallet(_) => "wallet_error",
            Self::Indexer(_) => "indexer_error",
            Self::Serialization(_) => "serialization_error",
            Self::ReceiptJournalMissing(_) => "receipt_journal_missing",
            Self::ClearanceReservedState => "clearance_reserved_state",
            Self::OwnershipProofSent => "ownership_proof_sent",
            Self::BoundFixedAtState { .. } => "bound_fixed_at_state",
            Self::ExitLocked => "exit_locked",
            Self::NoteNearExpiry => "note_near_expiry",
            Self::InvalidSuccessor(_) => "invalid_successor",
            Self::LateSuccessor => "late_successor",
            Self::EscapeRequired(_) => "escape_required",
            Self::ConcededMismatch(_) => "conceded_mismatch",
            Self::DeviceNotNewest => "device_not_newest",
            Self::ExitLockConflict(_) => "exit_lock_conflict",
            Self::NoteNotActivated { .. } => "note_not_activated",
            Self::IndexerRootLag { .. } => "indexer_root_lag",
            Self::NoteBindingMismatch(_) => "note_binding_mismatch",
            Self::NoteNotRecorded => "note_not_recorded",
        }
    }

    /// Structured detail for the bridge: the exit decision behind
    /// `escape_required` and `conceded_mismatch`, the activation queue
    /// behind `note_not_activated`, and the vault's cursor behind
    /// `indexer_root_lag`.
    pub fn detail(&self) -> Option<serde_json::Value> {
        match self {
            Self::EscapeRequired(detail) | Self::ConcededMismatch(detail) => Some(detail.clone()),
            Self::NoteNotActivated {
                queue_position,
                activation_cursor,
            } => Some(serde_json::json!({
                "activated": false,
                "queue_position": queue_position,
                "activation_cursor": activation_cursor,
                "retriable": true,
            })),
            Self::IndexerRootLag { activation_cursor } => Some(serde_json::json!({
                "activated": true,
                "activation_cursor": activation_cursor,
                "retriable": true,
            })),
            _ => None,
        }
    }

    /// The note state's nullifier the owner gives the operator, for
    /// `receipt_journal_missing` only.
    pub fn nullifier(&self) -> Option<String> {
        match self {
            Self::ReceiptJournalMissing(nullifier) => Some(nullifier.to_string()),
            _ => None,
        }
    }

    pub fn funding_url(&self) -> Option<&'static str> {
        matches!(self, Self::NoActiveNote | Self::InsufficientBalance).then_some("/funding")
    }
}

impl From<ClientError> for AuthError {
    fn from(value: ClientError) -> Self {
        match value {
            ClientError::TestnetPasswordRequired => Self::TestnetPasswordRequired,
            ClientError::NoActiveNote => Self::NoActiveNote,
            ClientError::InsufficientBalance { .. } => Self::InsufficientBalance,
            ClientError::PendingRequest => Self::PendingRequest,
            ClientError::BoundFixedAtState { bound, requested } => {
                Self::BoundFixedAtState { bound, requested }
            }
            ClientError::ExitLocked => Self::ExitLocked,
            ClientError::NoteNearExpiry => Self::NoteNearExpiry,
            ClientError::OwnershipProofSent => Self::OwnershipProofSent,
            ClientError::InvalidSuccessor(reason) => Self::InvalidSuccessor(reason),
            ClientError::LateSuccessor => Self::LateSuccessor,
            ClientError::ExitLockConflict(reason) => Self::ExitLockConflict(reason),
            ClientError::NoteNotActivated { queue_position } => Self::NoteNotActivated {
                queue_position,
                activation_cursor: None,
            },
            ClientError::NoteBindingMismatch(reason) => Self::NoteBindingMismatch(reason),
            ClientError::NoteNotRecorded => Self::NoteNotRecorded,
            other => Self::Wallet(other.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_failure_retains_safe_status_and_code() {
        let error = AuthError::from(ClientError::TestnetPasswordRequired);
        assert_eq!(error.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(error.code(), "testnet_password_required");
        assert_eq!(error.funding_url(), None);
    }

    #[test]
    fn activation_and_binding_refusals_have_their_own_codes() {
        let error = AuthError::from(ClientError::NoteNotActivated { queue_position: 3 });
        assert_eq!(error.code(), "note_not_activated");
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert_eq!(error.detail().unwrap()["queue_position"], 3);
        assert_eq!(error.detail().unwrap()["retriable"], true);
        let error = AuthError::NoteNotActivated {
            queue_position: 0,
            activation_cursor: Some(7),
        };
        assert_eq!(error.detail().unwrap()["activation_cursor"], 7);
        assert!(error.to_string().contains("withdrawals are available"));
        let error = AuthError::from(ClientError::NoteBindingMismatch("other values".into()));
        assert_eq!(error.code(), "note_binding_mismatch");
        assert!(error.to_string().contains("other values"));
        assert_eq!(
            AuthError::from(ClientError::NoteNotRecorded).code(),
            "note_not_recorded"
        );
    }

    #[test]
    fn an_indexer_behind_the_vaults_activation_is_retriable() {
        let error = AuthError::IndexerRootLag {
            activation_cursor: 9,
        };
        assert_eq!(error.code(), "indexer_root_lag");
        assert_eq!(error.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        let detail = error.detail().unwrap();
        assert_eq!(detail["activated"], true);
        assert_eq!(detail["activation_cursor"], 9);
        assert_eq!(detail["retriable"], true);
        assert!(error.to_string().contains("retry"));
    }

    #[test]
    fn upstream_http_status_is_not_disguised_as_bad_gateway() {
        let error = AuthError::UpstreamResponse {
            status: StatusCode::TOO_MANY_REQUESTS,
            message: "rate limited".to_string(),
        };
        assert_eq!(error.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error.funding_url(), None);
    }
}
