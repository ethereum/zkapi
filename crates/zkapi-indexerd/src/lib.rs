//! Indexer: mirrors a revision-4 vault's events into a local Merkle tree view.
//!
//! The indexer maintains a full copy of the vault's append-only note tree by
//! consuming contract events in block order: `NoteDeposited` sets a leaf
//! (recomputed from its preimage, which the mirror keeps for operator sweeps)
//! and `ClosedLeafRetired` zeroes one; exits leave the tree unchanged. No
//! event carries a root. It serves the latest root with its block hash
//! (`/v1/tree/root`), sibling paths and the leaf set (`/v1/tree/snapshot`,
//! from which clients rebuild paths locally), the published-nullifier table
//! (`/v1/nullifiers/{N}/published`, §5.2), the open escapes with their
//! concession to the challenger, and, internally, each note's deposit
//! preimage (`/v1/notes/{id}/deposit`). Exits need no path or root from it.
//!
//! Every served view is a state the vault verifiably had: `currentRoot()` and
//! `nextNoteId()` read by block hash must equal the mirror. A durable
//! checkpoint is kept `confirmations` blocks below the head; reorgs are
//! absorbed or trigger a rebuild, and any unresolved mismatch fails closed
//! (HTTP 503) rather than serving a root the vault never had. The indexer
//! refuses a vault whose `CONCESSION_ESCAPE_VERSION()` or
//! `LEAF_BOUND_EXIT_VERSION()` is not 1. It can start from the vault's state
//! (`noteLeaves` pages at one block hash) instead of logs from deployment.
//!
//! That check covers the tree only. Note statuses, open escapes and
//! published nullifiers come from the same logs, but escapes change no leaf,
//! so they are hints: consumers read `noteRecord(note)`,
//! `pendingWithdrawals(note)`, `pendingConcessions(note)` and
//! `usedNullifiers(N)` from the vault.
//!
//! The indexer is NOT trusted. Incorrect paths only cause proof or tx failure.

pub mod events;
pub mod http;
pub mod poller;
pub mod service;
#[cfg(test)]
mod test_chain;
pub mod tree_mirror;

pub use http::{create_router, run_indexer, IndexerConfig};
pub use poller::{
    BlockRef, JsonRpcLogPoller, PollOutcome, PollerConfig, CIRCUIT_ID, STATE_PAGE_SIZE,
};
pub use service::{
    HealthResponse, IndexerService, NextNoteIdResponse, NoteDepositResponse,
    PendingEscapesResponse, PublishedNullifierResponse, ServiceSettings, SyncStatus,
    TreePathResponse, TreeRootResponse, TreeSnapshotResponse, TreeView,
};
pub use tree_mirror::{
    EscapeClose, MirrorError, MissedReEscape, NotePreimage, NoteStatus, PendingEscape, TreeMirror,
};
