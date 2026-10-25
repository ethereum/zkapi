//! Contract event types for the indexer (vault revision 4, circuit
//! `zkapi-v2-concession-v2`).
//!
//! The note tree is append-only: only `NoteDeposited` (sets a leaf) and
//! `ClosedLeafRetired` (zeroes a closed note's leaf) change leaves. No event
//! carries a root: the vault computes `currentRoot()` on demand, and the
//! indexer reads it at a block hash.

use serde::{Deserialize, Serialize};
use zkapi_types::Felt252;

/// The vault events the indexer mirrors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VaultEvent {
    /// `NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment,
    /// uint128 amount, uint64 expiryTs)`: the note's leaf preimage, from
    /// which the leaf the vault stored is recomputed.
    NoteDeposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
    },
    /// `MutualClose(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination)`. No leaf removal.
    MutualClose {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    /// `EscapeWithdrawalInitiated(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination, uint64 challengeDeadline)`.
    /// No leaf removal.
    EscapeWithdrawalInitiated {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
        challenge_deadline: u64,
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
    /// `EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier)`:
    /// a defeat by successor evidence. The leaf was never removed.
    EscapeWithdrawalChallenged { note_id: u32, nullifier: Felt252 },
    /// `EscapeWithdrawalFinalized(uint32 indexed noteId, uint256 nullifier,
    /// uint128 finalBalance, address destination)`.
    EscapeWithdrawalFinalized {
        note_id: u32,
        nullifier: Felt252,
        final_balance: u128,
    },
    /// `ExpiredClaimed(uint32 indexed noteId, uint128 depositAmount)`. No
    /// leaf removal.
    ExpiredClaimed { note_id: u32, deposit_amount: u128 },
    /// `ClosedLeafRetired(uint32 indexed noteId)`: a closed note's leaf was
    /// zeroed.
    ClosedLeafRetired { note_id: u32 },
}

impl VaultEvent {
    /// The note the event is about.
    pub fn note_id(&self) -> u32 {
        match self {
            Self::NoteDeposited { note_id, .. }
            | Self::MutualClose { note_id, .. }
            | Self::EscapeWithdrawalInitiated { note_id, .. }
            | Self::EscapeConcessionRecorded { note_id, .. }
            | Self::EscapeConcessionRaised { note_id, .. }
            | Self::EscapeWithdrawalChallenged { note_id, .. }
            | Self::EscapeWithdrawalFinalized { note_id, .. }
            | Self::ExpiredClaimed { note_id, .. }
            | Self::ClosedLeafRetired { note_id, .. } => *note_id,
        }
    }

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
            | Self::ExpiredClaimed { .. }
            | Self::ClosedLeafRetired { .. } => Vec::new(),
        }
    }
}
