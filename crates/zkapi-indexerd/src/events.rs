//! Contract event types for the indexer (vault revision 4, circuit
//! `zkapi-v2-concession-v2`).
//!
//! `NoteDeposited` records a note and leaves the request tree unchanged.
//! Only `NotesActivated` (appends the leaves of the next recorded notes) and
//! `ClosedLeafRetired` (zeroes an activated, closed note's leaf) change
//! leaves. Every other event that carries a root carries the vault's
//! unchanged `currentRoot`.

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

/// The vault events the indexer mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultEvent {
    /// `NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment,
    /// uint128 amount, uint64 expiryTs)`: the note is recorded; its leaf
    /// enters the tree when it is activated.
    NoteDeposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
    },
    /// `NotesActivated(uint32 indexed firstNoteId, uint32 count,
    /// uint256 newRoot, bool proved)`: the leaves of notes
    /// `first_note_id .. first_note_id + count` were appended, by a proved
    /// batch (`activateNotes`) or on-chain (`activateNotesOnChain`).
    NotesActivated {
        first_note_id: u32,
        count: u32,
        new_root: Felt252,
        proved: bool,
    },
    /// `MutualClose(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination)`. No leaf removal.
    MutualClose {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    /// `EscapeWithdrawalInitiated(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination, uint64 challengeDeadline,
    /// uint256 currentRoot)`. No Merkle work: `current_root` is unchanged.
    EscapeWithdrawalInitiated {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
        challenge_deadline: u64,
        current_root: Felt252,
    },
    /// `EscapeConcessionRecorded(uint32 indexed noteId, uint256 nextNullifier,
    /// uint128 stateBalance, uint128 conceded)`, emitted right after the
    /// initiation it belongs to.
    EscapeConcessionRecorded {
        note_id: u32,
        next_nullifier: Felt252,
        state_balance: u128,
        conceded: u128,
    },
    /// `EscapeConcessionRaised(uint32 indexed noteId, uint256 nullifier,
    /// uint128 conceded, uint128 finalBalance)`.
    EscapeConcessionRaised {
        note_id: u32,
        nullifier: Felt252,
        conceded: u128,
        final_balance: u128,
    },
    /// `EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier,
    /// uint256 currentRoot)`: a defeat by successor evidence. The leaf was
    /// never removed, so `current_root` is unchanged.
    EscapeWithdrawalChallenged {
        note_id: u32,
        nullifier: Felt252,
        current_root: Felt252,
    },
    /// `EscapeWithdrawalFinalized(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination)`.
    EscapeWithdrawalFinalized {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    /// `ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount,
    /// uint256 currentRoot)`. No leaf removal.
    ExpiredClaimed {
        note_id: u32,
        deposit_amount: u128,
        current_root: Felt252,
    },
    /// `ClosedLeafRetired(uint32 indexed noteId, uint256 newRoot)`: an
    /// activated, closed note's leaf was zeroed.
    ClosedLeafRetired { note_id: u32, new_root: Felt252 },
}

impl VaultEvent {
    /// The nullifiers the event makes public: a `withdrawalNullifier` or a
    /// `nextNullifier` (§5.2). The server never serves request data or
    /// evidence for one.
    pub fn published_nullifiers(&self) -> Vec<Felt252> {
        match self {
            Self::MutualClose { nullifier, .. }
            | Self::EscapeWithdrawalInitiated { nullifier, .. }
            | Self::EscapeConcessionRaised { nullifier, .. }
            | Self::EscapeWithdrawalChallenged { nullifier, .. }
            | Self::EscapeWithdrawalFinalized { nullifier, .. } => vec![*nullifier],
            Self::EscapeConcessionRecorded { next_nullifier, .. } => vec![*next_nullifier],
            Self::NoteDeposited { .. }
            | Self::NotesActivated { .. }
            | Self::ExpiredClaimed { .. }
            | Self::ClosedLeafRetired { .. } => Vec::new(),
        }
    }
}
