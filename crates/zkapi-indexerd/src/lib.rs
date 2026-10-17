//! Indexer: mirrors a revision-4 vault's events into a local Merkle tree view.
//!
//! The indexer maintains a full copy of the vault's recorded notes and its
//! append-only request tree by consuming contract events in block order:
//! `NoteDeposited` records a note (commitment, amount, expiry) without
//! touching the tree, `NotesActivated` appends the leaves of the next aligned
//! batch of 1, 4 or 16 recorded notes at the activation cursor, and
//! `ClosedLeafRetired` zeroes an activated, closed note's leaf; exits leave
//! the tree unchanged, and every root an event carries must equal the
//! mirrored root. It serves the latest root with the activation cursor,
//! sibling paths (for any slot: the cursor's slot gives an activation batch
//! its path), the leaf set and every recorded note (`/v1/tree/snapshot`, from
//! which clients rebuild paths locally), the published-nullifier table
//! (`/v1/nullifiers/{N}/published`, §5.2) and the open escapes with their
//! concession to the challenger.
//!
//! Every served view is a state the vault verifiably had: `currentRoot()`,
//! `nextNoteId()` and `activationCursor()` read by block hash must equal the
//! mirror. A durable checkpoint is kept `confirmations` blocks below the
//! head; reorgs are absorbed or trigger a rebuild, and any unresolved
//! mismatch fails closed (HTTP 503) rather than serving a root the vault
//! never had. The indexer refuses a vault whose `CONCESSION_ESCAPE_VERSION()`
//! or `NOTE_BOUND_EXIT_VERSION()` is not 1.
//!
//! That check covers the tree and the number of recorded notes only. Records
//! above the activation cursor, note statuses, open escapes and published
//! nullifiers come from the same logs, but change no root (a pending record
//! is checked when its activation's root is), so they are hints: consumers
//! read `notes(noteId)`, `pendingWithdrawals(note)`, `pendingConcessions(note)`
//! and `usedNullifiers(N)` from the vault.
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
pub use poller::{BlockRef, JsonRpcLogPoller, PollOutcome, PollerConfig, CIRCUIT_ID};
pub use service::{
    HealthResponse, IndexerService, NextNoteIdResponse, PendingEscapesResponse,
    PublishedNullifierResponse, ServiceSettings, SyncStatus, TreePathResponse, TreeRootResponse,
    TreeSnapshotResponse, TreeView,
};
pub use tree_mirror::{
    EscapeClose, MirrorError, MissedReEscape, NoteRecord, NoteStatus, PendingEscape, TreeMirror,
};
