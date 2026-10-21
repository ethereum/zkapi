//! Local mirror of the vault's note tree and note lifecycle, maintained from
//! contract events.
//!
//! Vault revision 3 keeps an append-only note tree (§4, §5.5): a deposit
//! inserts its note's leaf, and only `retireClosedLeaf` removes one, of a
//! Closed note. Escapes, defeats, raises, mutual closes, finalizations and
//! expiry claims change a note's status but never the tree, and every root
//! such an event carries must equal the mirrored root. The mirror also keeps
//!
//! * every root the vault ever set (`knownRoots`, Amendment A1): the empty
//!   root and the root after each deposit and retirement, any of which a
//!   proof may use;
//! * the published-nullifier table (§5.2): every `withdrawalNullifier` and
//!   `nextNullifier` a vault event made public;
//! * the open escapes with their concession (`PendingEscape`).

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::OnceLock;

use zkapi_core::leaf::compute_note_leaf;
use zkapi_core::merkle::MerkleTree;
use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::events::VaultEvent;

/// A note's status as the vault's events establish it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteStatus {
    Active,
    PendingWithdrawal,
    Closed,
}

/// An escape withdrawal the vault holds open until it is defeated or
/// finalized, as last applied from the vault's logs.
///
/// Escapes change no leaf, so the indexer's root check does not cover this
/// list: it is a hint the challenger uses to check the completeness of its
/// own event scan. Consumers read `pendingWithdrawals(note)` and
/// `pendingConcessions(note)` from the vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingEscape {
    pub note_id: u32,
    pub withdrawal_nullifier: Felt252,
    pub challenge_deadline: u64,
    /// The current payout: `state_balance - conceded`.
    #[serde(default)]
    pub final_balance: u128,
    /// `N_{k+1}`, from `EscapeConcessionRecorded`: the only nullifier whose
    /// request proof defeats the escape. None until that event is applied
    /// (or after a missed re-escape).
    #[serde(default)]
    pub next_nullifier: Option<Felt252>,
    #[serde(default)]
    pub state_balance: Option<u128>,
    #[serde(default)]
    pub conceded: Option<u128>,
}

/// The vault event that ended (or, for a raise, changed) an escape other
/// than the one the mirror lists for its note.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EscapeClose {
    /// `EscapeWithdrawalChallenged`: a defeat returned the note to Active.
    Challenged,
    /// `EscapeWithdrawalFinalized`: the vault finalized the escape (paid the
    /// destination or, if the push failed, credited the payout).
    Finalized,
    /// `EscapeConcessionRaised`: the escape was raised. It stays open; the
    /// listing takes the event's nullifier.
    Raised,
}

impl EscapeClose {
    pub const ALL: [EscapeClose; 3] = [
        EscapeClose::Challenged,
        EscapeClose::Finalized,
        EscapeClose::Raised,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            EscapeClose::Challenged => "challenged",
            EscapeClose::Finalized => "finalized",
            EscapeClose::Raised => "raised",
        }
    }
}

/// A defeat, raise or finalization of an escape other than the one listed
/// for its note. The vault holds at most one escape per note, so the mirror
/// never applied this escape's initiation: the logs missed a defeat of the
/// listed escape and a re-escape of the note, or a reorganization below the
/// checkpoint replaced the note's escape. Neither changes the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MissedReEscape {
    pub note_id: u32,
    /// The listed escape, which the mirror never saw end.
    pub listed_nullifier: Felt252,
    /// The escape the event names, which the mirror never saw initiated.
    pub nullifier: Felt252,
    pub closed_by: EscapeClose,
}

impl std::fmt::Display for MissedReEscape {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "note {} escape {} was {} while escape {} was listed",
            self.note_id,
            self.nullifier,
            self.closed_by.as_str(),
            self.listed_nullifier
        )
    }
}

/// Serializable mirror state, paired atomically with the indexer's block
/// cursor in its checkpoint.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TreeMirrorSnapshot {
    pub next_note_id: u32,
    /// The leaf each note was deposited with, by note id.
    pub deposited_leaves: Vec<Felt252>,
    /// Each note's status, by note id.
    pub statuses: Vec<NoteStatus>,
    /// Closed notes whose leaf `ClosedLeafRetired` zeroed, ascending.
    pub retired: Vec<u32>,
    pub pending_escapes: Vec<PendingEscape>,
    /// The published-nullifier table, ascending.
    pub published_nullifiers: Vec<Felt252>,
    /// Every root the vault set, ascending.
    pub known_roots: Vec<Felt252>,
}

/// A vault event that cannot follow the mirror's current state. The caller
/// discards the staged mirror the event was applied to.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorError {
    #[error("deposit for note {got} does not follow next note id {expected}")]
    NonContiguousDeposit { expected: u32, got: u32 },
    #[error("note {note_id} was never deposited")]
    UnknownNote { note_id: u32 },
    #[error("note {note_id} is not active")]
    NoteNotActive { note_id: u32 },
    #[error("note {note_id} has no pending escape withdrawal")]
    NoteNotPending { note_id: u32 },
    #[error("note {note_id} is not closed")]
    NoteNotClosed { note_id: u32 },
    #[error("the leaf of note {note_id} is already retired")]
    LeafAlreadyRetired { note_id: u32 },
    #[error("the concession of note {note_id} does not follow its escape's initiation")]
    ConcessionOutOfOrder { note_id: u32 },
    #[error("inconsistent concession for note {note_id}: {detail}")]
    InconsistentConcession { note_id: u32, detail: String },
    #[error("event root {event} does not match mirror root {mirror}")]
    RootMismatch { event: Felt252, mirror: Felt252 },
    #[error("note id space is exhausted")]
    NoteIdOverflow,
}

/// A mirror of the vault's note tree and note lifecycle.
#[derive(Clone)]
pub struct TreeMirror {
    tree: MerkleTree,
    /// The leaf each note was deposited with, by note id.
    deposited: Vec<Felt252>,
    statuses: Vec<NoteStatus>,
    retired: BTreeSet<u32>,
    pending_escapes: BTreeMap<u32, PendingEscape>,
    published: HashSet<Felt252>,
    known_roots: HashSet<Felt252>,
}

impl TreeMirror {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            deposited: Vec::new(),
            statuses: Vec::new(),
            retired: BTreeSet::new(),
            pending_escapes: BTreeMap::new(),
            published: HashSet::new(),
            known_roots: HashSet::from([Self::empty_root()]),
        }
    }

    /// Root of the empty tree, which the vault sets (and records as known)
    /// in its constructor.
    pub fn empty_root() -> Felt252 {
        static EMPTY_ROOT: OnceLock<Felt252> = OnceLock::new();
        *EMPTY_ROOT.get_or_init(|| MerkleTree::new().root())
    }

    /// True before the first deposit.
    pub fn is_empty(&self) -> bool {
        self.deposited.is_empty()
    }

    /// The current root.
    pub fn root(&self) -> Felt252 {
        self.tree.root()
    }

    /// The next note id the vault assigns.
    pub fn next_note_id(&self) -> u32 {
        self.deposited.len() as u32
    }

    /// All current leaves, indexed 0..next_note_id (zero for a retired leaf).
    ///
    /// This backs the privacy-safe snapshot endpoint: a client fetches the same
    /// full leaf vector regardless of which note it cares about, rebuilds the
    /// tree locally, and derives any sibling path without revealing its note_id
    /// to the (untrusted) indexer.
    pub fn current_leaves(&self) -> Vec<Felt252> {
        (0..self.next_note_id())
            .map(|i| self.tree.get_leaf(i))
            .collect()
    }

    /// The status of `note_id`, if it was deposited.
    pub fn note_status(&self, note_id: u32) -> Option<NoteStatus> {
        self.statuses.get(note_id as usize).copied()
    }

    /// Open escape withdrawals in note-id order (hints; see `PendingEscape`).
    pub fn pending_escapes(&self) -> Vec<PendingEscape> {
        self.pending_escapes.values().copied().collect()
    }

    /// Whether a vault event made `nullifier` public.
    pub fn is_published(&self, nullifier: &Felt252) -> bool {
        self.published.contains(nullifier)
    }

    pub fn published_count(&self) -> usize {
        self.published.len()
    }

    /// Whether the vault ever set `root` (A1: the vault accepts any of them).
    pub fn is_known_root(&self, root: &Felt252) -> bool {
        self.known_roots.contains(root)
    }

    pub fn known_root_count(&self) -> usize {
        self.known_roots.len()
    }

    /// Capture the mirror for a checkpoint.
    pub fn snapshot(&self) -> TreeMirrorSnapshot {
        let mut published: Vec<_> = self.published.iter().copied().collect();
        published.sort_unstable_by_key(|felt| felt.0);
        let mut known_roots: Vec<_> = self.known_roots.iter().copied().collect();
        known_roots.sort_unstable_by_key(|felt| felt.0);
        TreeMirrorSnapshot {
            next_note_id: self.next_note_id(),
            deposited_leaves: self.deposited.clone(),
            statuses: self.statuses.clone(),
            retired: self.retired.iter().copied().collect(),
            pending_escapes: self.pending_escapes(),
            published_nullifiers: published,
            known_roots,
        }
    }

    /// Restore a mirror from a checkpoint, checking that it is consistent.
    pub fn from_snapshot(snapshot: TreeMirrorSnapshot) -> Result<Self, String> {
        let notes = snapshot.next_note_id as usize;
        if snapshot.deposited_leaves.len() != notes || snapshot.statuses.len() != notes {
            return Err(format!(
                "snapshot has {} deposited leaves and {} statuses but next_note_id is {}",
                snapshot.deposited_leaves.len(),
                snapshot.statuses.len(),
                snapshot.next_note_id
            ));
        }
        if let Some(note_id) = snapshot.deposited_leaves.iter().position(Felt252::is_zero) {
            return Err(format!(
                "snapshot has an empty deposited leaf for note {note_id}"
            ));
        }
        let mut retired = BTreeSet::new();
        for note_id in snapshot.retired {
            match snapshot.statuses.get(note_id as usize) {
                None => return Err("snapshot retires a leaf beyond next_note_id".to_string()),
                Some(NoteStatus::Closed) => {}
                Some(_) => {
                    return Err(format!(
                        "snapshot retires the leaf of note {note_id}, which is not closed"
                    ))
                }
            }
            if !retired.insert(note_id) {
                return Err(format!("snapshot retires note {note_id} twice"));
            }
        }
        let mut pending_escapes = BTreeMap::new();
        for escape in snapshot.pending_escapes {
            match snapshot.statuses.get(escape.note_id as usize) {
                None => {
                    return Err("snapshot contains a pending escape beyond next_note_id".to_string())
                }
                Some(NoteStatus::PendingWithdrawal) => {}
                Some(_) => {
                    return Err(format!(
                        "snapshot has a pending escape for note {}, which is not pending",
                        escape.note_id
                    ))
                }
            }
            if pending_escapes.insert(escape.note_id, escape).is_some() {
                return Err(format!(
                    "snapshot repeats the pending escape of note {}",
                    escape.note_id
                ));
            }
        }
        let pending_notes = snapshot
            .statuses
            .iter()
            .filter(|status| **status == NoteStatus::PendingWithdrawal)
            .count();
        if pending_notes != pending_escapes.len() {
            return Err("snapshot has a pending note without its escape".to_string());
        }
        let mut published = HashSet::with_capacity(snapshot.published_nullifiers.len());
        for nullifier in snapshot.published_nullifiers {
            if nullifier.is_zero() || !published.insert(nullifier) {
                return Err("snapshot has a zero or repeated published nullifier".to_string());
            }
        }

        let mut tree = MerkleTree::new();
        for (note_id, leaf) in snapshot.deposited_leaves.iter().enumerate() {
            if !retired.contains(&(note_id as u32)) {
                tree.set_leaf(note_id as u32, *leaf);
            }
        }
        let known_roots: HashSet<Felt252> = snapshot.known_roots.iter().copied().collect();
        if known_roots.len() != snapshot.known_roots.len() {
            return Err("snapshot repeats a known root".to_string());
        }
        if !known_roots.contains(&Self::empty_root()) || !known_roots.contains(&tree.root()) {
            return Err("snapshot's known roots lack the empty or the current root".to_string());
        }
        Ok(Self {
            tree,
            deposited: snapshot.deposited_leaves,
            statuses: snapshot.statuses,
            retired,
            pending_escapes,
            published,
            known_roots,
        })
    }

    /// The sibling path of a note's slot in the current tree.
    pub fn get_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// Deprecated alias of `get_path`: the siblings of a slot do not depend
    /// on its leaf. Exits no longer need a zero-slot path.
    pub fn get_zero_path(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        self.tree.get_siblings(note_id)
    }

    /// The current leaf of a slot (zero if unused or retired).
    pub fn get_leaf(&self, note_id: u32) -> Felt252 {
        self.tree.get_leaf(note_id)
    }

    /// Apply a contract event after checking that it can follow the mirrored
    /// vault state, including the root the vault emitted with it.
    ///
    /// Returns the missed re-escape that an event naming an unlisted
    /// nullifier implies; the caller's batch-end check of the root and next
    /// note id remains the safety check of the tree.
    ///
    /// On error the mirror may be partially updated and must be discarded.
    pub fn apply_event(
        &mut self,
        event: &VaultEvent,
    ) -> Result<Option<MissedReEscape>, MirrorError> {
        let missed = self.check(event)?;
        self.transition(event);
        match event {
            VaultEvent::NoteDeposited { new_root: root, .. }
            | VaultEvent::ClosedLeafRetired { new_root: root, .. }
            | VaultEvent::EscapeWithdrawalInitiated {
                current_root: root, ..
            }
            | VaultEvent::EscapeWithdrawalChallenged {
                current_root: root, ..
            }
            | VaultEvent::ExpiredClaimed {
                current_root: root, ..
            } => self.require_root(root)?,
            VaultEvent::MutualClose { .. }
            | VaultEvent::EscapeConcessionRecorded { .. }
            | VaultEvent::EscapeConcessionRaised { .. }
            | VaultEvent::EscapeWithdrawalFinalized { .. } => {}
        }
        Ok(missed)
    }

    /// Unchecked event application, for tests and reference chains whose
    /// events carry placeholder roots.
    #[cfg(test)]
    pub(crate) fn process_event(&mut self, event: &VaultEvent) {
        self.transition(event);
    }

    /// Whether `event` can follow the mirrored state, and the missed
    /// re-escape it implies.
    fn check(&self, event: &VaultEvent) -> Result<Option<MissedReEscape>, MirrorError> {
        match event {
            VaultEvent::NoteDeposited { note_id, .. } => {
                // The vault assigns ids sequentially from 0, so a gap, a repeat
                // or a reordering means the log stream is incomplete.
                if *note_id != self.next_note_id() {
                    return Err(MirrorError::NonContiguousDeposit {
                        expected: self.next_note_id(),
                        got: *note_id,
                    });
                }
                note_id.checked_add(1).ok_or(MirrorError::NoteIdOverflow)?;
                Ok(None)
            }
            VaultEvent::MutualClose { note_id, .. }
            | VaultEvent::EscapeWithdrawalInitiated { note_id, .. }
            | VaultEvent::ExpiredClaimed { note_id, .. } => {
                if self.status(*note_id)? != NoteStatus::Active {
                    return Err(MirrorError::NoteNotActive { note_id: *note_id });
                }
                Ok(None)
            }
            VaultEvent::EscapeConcessionRecorded {
                note_id,
                next_nullifier,
                state_balance,
                conceded,
            } => {
                let escape = self.pending(*note_id)?;
                if escape.next_nullifier.is_some() {
                    return Err(MirrorError::ConcessionOutOfOrder { note_id: *note_id });
                }
                let inconsistent = |detail: &str| MirrorError::InconsistentConcession {
                    note_id: *note_id,
                    detail: detail.to_string(),
                };
                if next_nullifier.is_zero() || *next_nullifier == escape.withdrawal_nullifier {
                    return Err(inconsistent(
                        "the next nullifier is zero or the escaped nullifier",
                    ));
                }
                if escape.final_balance.checked_add(*conceded) != Some(*state_balance) {
                    return Err(inconsistent(
                        "final balance plus conceded is not the state balance",
                    ));
                }
                Ok(None)
            }
            VaultEvent::EscapeConcessionRaised {
                note_id,
                nullifier,
                conceded,
                final_balance,
            } => {
                let missed = self.missed_re_escape(*note_id, nullifier, EscapeClose::Raised)?;
                if missed.is_none() {
                    let escape = self.pending(*note_id)?;
                    let inconsistent = |detail: &str| MirrorError::InconsistentConcession {
                        note_id: *note_id,
                        detail: detail.to_string(),
                    };
                    if escape.conceded.is_some_and(|listed| *conceded <= listed) {
                        return Err(inconsistent("a raise must increase the concession"));
                    }
                    if escape
                        .state_balance
                        .is_some_and(|state| final_balance.checked_add(*conceded) != Some(state))
                    {
                        return Err(inconsistent(
                            "final balance plus conceded is not the state balance",
                        ));
                    }
                }
                Ok(missed)
            }
            VaultEvent::EscapeWithdrawalChallenged {
                note_id, nullifier, ..
            } => self.missed_re_escape(*note_id, nullifier, EscapeClose::Challenged),
            VaultEvent::EscapeWithdrawalFinalized {
                note_id, nullifier, ..
            } => self.missed_re_escape(*note_id, nullifier, EscapeClose::Finalized),
            VaultEvent::ClosedLeafRetired { note_id, .. } => {
                if self.status(*note_id)? != NoteStatus::Closed {
                    return Err(MirrorError::NoteNotClosed { note_id: *note_id });
                }
                if self.retired.contains(note_id) {
                    return Err(MirrorError::LeafAlreadyRetired { note_id: *note_id });
                }
                Ok(None)
            }
        }
    }

    /// The state change an event makes. Never fails; `check` runs first.
    fn transition(&mut self, event: &VaultEvent) {
        for nullifier in event.published_nullifiers() {
            self.published.insert(nullifier);
        }
        let set_status = |statuses: &mut Vec<NoteStatus>, note_id: u32, status| {
            if let Some(slot) = statuses.get_mut(note_id as usize) {
                *slot = status;
            }
        };
        match event {
            VaultEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                ..
            } => {
                let leaf = compute_note_leaf(*note_id, commitment, *amount, *expiry_ts);
                self.tree.set_leaf(*note_id, leaf);
                self.deposited.push(leaf);
                self.statuses.push(NoteStatus::Active);
                self.known_roots.insert(self.tree.root());
            }
            VaultEvent::MutualClose { note_id, .. }
            | VaultEvent::ExpiredClaimed { note_id, .. } => {
                set_status(&mut self.statuses, *note_id, NoteStatus::Closed);
            }
            VaultEvent::EscapeWithdrawalInitiated {
                note_id,
                nullifier,
                final_balance,
                challenge_deadline,
                ..
            } => {
                set_status(&mut self.statuses, *note_id, NoteStatus::PendingWithdrawal);
                self.pending_escapes.insert(
                    *note_id,
                    PendingEscape {
                        note_id: *note_id,
                        withdrawal_nullifier: *nullifier,
                        challenge_deadline: *challenge_deadline,
                        final_balance: *final_balance,
                        next_nullifier: None,
                        state_balance: None,
                        conceded: None,
                    },
                );
            }
            VaultEvent::EscapeConcessionRecorded {
                note_id,
                next_nullifier,
                state_balance,
                conceded,
            } => {
                if let Some(escape) = self.pending_escapes.get_mut(note_id) {
                    escape.next_nullifier = Some(*next_nullifier);
                    escape.state_balance = Some(*state_balance);
                    escape.conceded = Some(*conceded);
                }
            }
            VaultEvent::EscapeConcessionRaised {
                note_id,
                nullifier,
                conceded,
                final_balance,
            } => {
                if let Some(escape) = self.pending_escapes.get_mut(note_id) {
                    if escape.withdrawal_nullifier != *nullifier {
                        // A re-escape the logs missed: its successor nullifier
                        // and initial concession are unknown.
                        escape.withdrawal_nullifier = *nullifier;
                        escape.next_nullifier = None;
                    }
                    escape.conceded = Some(*conceded);
                    escape.final_balance = *final_balance;
                    escape.state_balance = final_balance.checked_add(*conceded);
                }
            }
            VaultEvent::EscapeWithdrawalChallenged { note_id, .. } => {
                set_status(&mut self.statuses, *note_id, NoteStatus::Active);
                self.pending_escapes.remove(note_id);
            }
            VaultEvent::EscapeWithdrawalFinalized { note_id, .. } => {
                set_status(&mut self.statuses, *note_id, NoteStatus::Closed);
                self.pending_escapes.remove(note_id);
            }
            VaultEvent::ClosedLeafRetired { note_id, .. } => {
                if (*note_id as usize) < self.deposited.len() {
                    self.tree.set_leaf(*note_id, Felt252::ZERO);
                    self.retired.insert(*note_id);
                    self.known_roots.insert(self.tree.root());
                }
            }
        }
    }

    fn status(&self, note_id: u32) -> Result<NoteStatus, MirrorError> {
        self.note_status(note_id)
            .ok_or(MirrorError::UnknownNote { note_id })
    }

    /// The listed escape of a pending note.
    fn pending(&self, note_id: u32) -> Result<&PendingEscape, MirrorError> {
        if self.status(note_id)? != NoteStatus::PendingWithdrawal {
            return Err(MirrorError::NoteNotPending { note_id });
        }
        self.pending_escapes
            .get(&note_id)
            .ok_or(MirrorError::NoteNotPending { note_id })
    }

    /// Check that the note has a listed escape. An event for another
    /// nullifier ends or raises a re-escape the mirror missed: the event
    /// applies to the listing, and the missed re-escape is returned.
    fn missed_re_escape(
        &self,
        note_id: u32,
        nullifier: &Felt252,
        closed_by: EscapeClose,
    ) -> Result<Option<MissedReEscape>, MirrorError> {
        let escape = self.pending(note_id)?;
        if escape.withdrawal_nullifier == *nullifier {
            return Ok(None);
        }
        Ok(Some(MissedReEscape {
            note_id,
            listed_nullifier: escape.withdrawal_nullifier,
            nullifier: *nullifier,
            closed_by,
        }))
    }

    fn require_root(&self, event_root: &Felt252) -> Result<(), MirrorError> {
        let mirror = self.root();
        if mirror != *event_root {
            return Err(MirrorError::RootMismatch {
                event: *event_root,
                mirror,
            });
        }
        Ok(())
    }
}

impl Default for TreeMirror {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Builds events whose roots are what the vault would emit, by replaying
    /// them on a reference mirror.
    pub(crate) struct Reference(pub(crate) TreeMirror);

    impl Reference {
        pub(crate) fn new() -> Self {
            Self(TreeMirror::new())
        }

        pub(crate) fn deposit(&mut self, commitment: u64) -> VaultEvent {
            let mut event = VaultEvent::NoteDeposited {
                note_id: self.0.next_note_id(),
                commitment: Felt252::from_u64(commitment),
                amount: 1_000,
                expiry_ts: 1_700_000_000,
                new_root: Felt252::ZERO,
            };
            self.0.process_event(&event);
            if let VaultEvent::NoteDeposited { new_root, .. } = &mut event {
                *new_root = self.0.root();
            }
            event
        }

        pub(crate) fn close(&mut self, note_id: u32) -> VaultEvent {
            let event = VaultEvent::MutualClose {
                note_id,
                nullifier: Felt252::from_u64(7_000 + note_id as u64),
                final_balance: 10,
            };
            self.0.process_event(&event);
            event
        }

        /// The initiation and the concession record of an escape at
        /// `nullifier` (its successor is `nullifier + 1`), conceding 5.
        pub(crate) fn escape(&mut self, note_id: u32, nullifier: u64) -> [VaultEvent; 2] {
            let events = [
                VaultEvent::EscapeWithdrawalInitiated {
                    note_id,
                    nullifier: Felt252::from_u64(nullifier),
                    final_balance: 10,
                    challenge_deadline: 1_700_086_400,
                    current_root: self.0.root(),
                },
                VaultEvent::EscapeConcessionRecorded {
                    note_id,
                    next_nullifier: Felt252::from_u64(nullifier + 1),
                    state_balance: 15,
                    conceded: 5,
                },
            ];
            for event in &events {
                self.0.process_event(event);
            }
            events
        }

        pub(crate) fn raise(&mut self, note_id: u32, nullifier: u64, conceded: u128) -> VaultEvent {
            let event = VaultEvent::EscapeConcessionRaised {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                conceded,
                final_balance: 15 - conceded,
            };
            self.0.process_event(&event);
            event
        }

        pub(crate) fn challenge(&mut self, note_id: u32, nullifier: u64) -> VaultEvent {
            let event = VaultEvent::EscapeWithdrawalChallenged {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                current_root: self.0.root(),
            };
            self.0.process_event(&event);
            event
        }

        pub(crate) fn finalize(&mut self, note_id: u32, nullifier: u64) -> VaultEvent {
            let event = VaultEvent::EscapeWithdrawalFinalized {
                note_id,
                nullifier: Felt252::from_u64(nullifier),
                final_balance: 10,
            };
            self.0.process_event(&event);
            event
        }

        pub(crate) fn claim(&mut self, note_id: u32) -> VaultEvent {
            let event = VaultEvent::ExpiredClaimed {
                note_id,
                deposit_amount: 1_000,
                current_root: self.0.root(),
            };
            self.0.process_event(&event);
            event
        }

        pub(crate) fn retire(&mut self, note_id: u32) -> VaultEvent {
            self.0.process_event(&VaultEvent::ClosedLeafRetired {
                note_id,
                new_root: Felt252::ZERO,
            });
            VaultEvent::ClosedLeafRetired {
                note_id,
                new_root: self.0.root(),
            }
        }
    }

    /// Apply complete logs, which never imply a missed re-escape.
    pub(crate) fn apply_all(mirror: &mut TreeMirror, events: &[VaultEvent]) {
        for event in events {
            assert_eq!(mirror.apply_event(event), Ok(None), "{event:?}");
        }
    }

    #[test]
    fn exits_leave_the_tree_and_only_a_retirement_removes_a_leaf() {
        let mut reference = Reference::new();
        let deposits = [
            reference.deposit(100),
            reference.deposit(101),
            reference.deposit(102),
        ];
        let deposited_root = reference.0.root();
        let mut events = Vec::new();
        events.extend(reference.escape(0, 900));
        events.push(reference.raise(0, 900, 7));
        events.push(reference.challenge(0, 900));
        // G2: a later escape of the same note uses a new nullifier.
        events.extend(reference.escape(0, 903));
        events.push(reference.finalize(0, 903));
        events.push(reference.close(1));
        events.push(reference.claim(2));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &deposits);
        for event in &events {
            assert_eq!(mirror.apply_event(event), Ok(None));
            // Escapes, defeats, raises, closes, finalizations and claims do
            // no Merkle work.
            assert_eq!(mirror.root(), deposited_root, "{event:?}");
        }
        assert_eq!(mirror.note_status(0), Some(NoteStatus::Closed));
        assert_eq!(mirror.note_status(1), Some(NoteStatus::Closed));
        assert_eq!(mirror.note_status(2), Some(NoteStatus::Closed));
        assert!(mirror.current_leaves().iter().all(|leaf| !leaf.is_zero()));
        assert!(mirror.pending_escapes().is_empty());

        let retire = reference.retire(1);
        mirror.apply_event(&retire).unwrap();
        assert!(mirror.get_leaf(1).is_zero());
        assert!(!mirror.get_leaf(0).is_zero());
        assert_ne!(mirror.root(), deposited_root);
        assert_eq!(mirror.root(), reference.0.root());
        // A leaf is retired once.
        assert_eq!(
            mirror.clone().apply_event(&retire),
            Err(MirrorError::LeafAlreadyRetired { note_id: 1 })
        );
    }

    #[test]
    fn every_root_the_vault_set_stays_known() {
        let mut reference = Reference::new();
        let mut mirror = TreeMirror::new();
        assert!(mirror.is_known_root(&TreeMirror::empty_root()));
        let mut roots = vec![TreeMirror::empty_root()];
        for commitment in 100..103 {
            mirror.apply_event(&reference.deposit(commitment)).unwrap();
            roots.push(mirror.root());
        }
        apply_all(&mut mirror, &[reference.close(0)]);
        mirror.apply_event(&reference.retire(0)).unwrap();
        roots.push(mirror.root());
        // A1: the deposit-time roots stay valid after later deposits and a
        // retirement; nothing else is a known root.
        for root in &roots {
            assert!(mirror.is_known_root(root), "{root}");
        }
        assert_eq!(mirror.known_root_count(), roots.len());
        assert!(!mirror.is_known_root(&Felt252::from_u64(5)));
        let restored = TreeMirror::from_snapshot(mirror.snapshot()).unwrap();
        for root in &roots {
            assert!(restored.is_known_root(root));
        }
    }

    #[test]
    fn exits_publish_both_nullifiers() {
        let mut reference = Reference::new();
        let mut events = vec![reference.deposit(100), reference.deposit(101)];
        events.extend(reference.escape(0, 900));
        events.push(reference.raise(0, 900, 6));
        events.push(reference.challenge(0, 900));
        events.extend(reference.escape(0, 902));
        events.push(reference.finalize(0, 902));
        events.push(reference.close(1));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        for published in [900, 901, 902, 903, 7_001] {
            assert!(
                mirror.is_published(&Felt252::from_u64(published)),
                "{published}"
            );
        }
        assert_eq!(mirror.published_count(), 5);
        assert!(!mirror.is_published(&Felt252::from_u64(904)));
    }

    #[test]
    fn pending_escapes_carry_the_concession_and_its_raises() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let [initiated, recorded] = reference.escape(0, 900);
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit, initiated]);
        assert_eq!(
            mirror.pending_escapes(),
            vec![PendingEscape {
                note_id: 0,
                withdrawal_nullifier: Felt252::from_u64(900),
                challenge_deadline: 1_700_086_400,
                final_balance: 10,
                next_nullifier: None,
                state_balance: None,
                conceded: None,
            }]
        );
        mirror.apply_event(&recorded).unwrap();
        // A second record of the same escape cannot follow.
        assert_eq!(
            mirror.clone().apply_event(&recorded),
            Err(MirrorError::ConcessionOutOfOrder { note_id: 0 })
        );
        mirror.apply_event(&reference.raise(0, 900, 9)).unwrap();
        assert_eq!(
            mirror.pending_escapes(),
            vec![PendingEscape {
                note_id: 0,
                withdrawal_nullifier: Felt252::from_u64(900),
                challenge_deadline: 1_700_086_400,
                final_balance: 6,
                next_nullifier: Some(Felt252::from_u64(901)),
                state_balance: Some(15),
                conceded: Some(9),
            }]
        );
        // A raise never lowers the concession, and keeps the state balance.
        for (conceded, final_balance) in [(9, 6), (8, 7), (12, 4)] {
            assert!(matches!(
                mirror
                    .clone()
                    .apply_event(&VaultEvent::EscapeConcessionRaised {
                        note_id: 0,
                        nullifier: Felt252::from_u64(900),
                        conceded,
                        final_balance,
                    }),
                Err(MirrorError::InconsistentConcession { .. })
            ));
        }
    }

    #[test]
    fn a_concession_that_does_not_add_up_is_refused() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let [initiated, _] = reference.escape(0, 900);
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit, initiated]);
        for (next, state_balance, conceded) in [(901, 16, 5), (0, 15, 5), (900, 15, 5)] {
            assert!(matches!(
                mirror
                    .clone()
                    .apply_event(&VaultEvent::EscapeConcessionRecorded {
                        note_id: 0,
                        next_nullifier: Felt252::from_u64(next),
                        state_balance,
                        conceded,
                    }),
                Err(MirrorError::InconsistentConcession { .. })
            ));
        }
    }

    #[test]
    fn apply_event_rejects_gap_and_duplicate_deposit() {
        let mut reference = Reference::new();
        let first = reference.deposit(100);
        let second = reference.deposit(101);

        let mut mirror = TreeMirror::new();
        assert_eq!(
            mirror.apply_event(&second),
            Err(MirrorError::NonContiguousDeposit {
                expected: 0,
                got: 1
            })
        );

        let mut mirror = TreeMirror::new();
        mirror.apply_event(&first).unwrap();
        assert_eq!(
            mirror.apply_event(&first),
            Err(MirrorError::NonContiguousDeposit {
                expected: 1,
                got: 0
            })
        );
    }

    #[test]
    fn every_event_root_must_be_the_mirrored_root() {
        let mut mirror = TreeMirror::new();
        let error = mirror
            .apply_event(&VaultEvent::NoteDeposited {
                note_id: 0,
                commitment: Felt252::from_u64(100),
                amount: 1_000,
                expiry_ts: 1_700_000_000,
                new_root: Felt252::from_u64(1),
            })
            .unwrap_err();
        assert!(matches!(error, MirrorError::RootMismatch { .. }));

        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let [mut escape, _] = reference.escape(0, 900);
        if let VaultEvent::EscapeWithdrawalInitiated { current_root, .. } = &mut escape {
            *current_root = Felt252::from_u64(5);
        }
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();
        assert!(matches!(
            mirror.clone().apply_event(&escape),
            Err(MirrorError::RootMismatch { .. })
        ));
        // An escape's root is the unchanged current root, not a root with the
        // leaf removed.
        let mut removed = TreeMirror::new();
        removed.process_event(&deposit);
        let mut zeroed = removed.clone();
        zeroed.tree.set_leaf(0, Felt252::ZERO);
        if let VaultEvent::EscapeWithdrawalInitiated { current_root, .. } = &mut escape {
            *current_root = zeroed.root();
        }
        assert!(matches!(
            mirror.clone().apply_event(&escape),
            Err(MirrorError::RootMismatch { .. })
        ));
        for event in [
            VaultEvent::ExpiredClaimed {
                note_id: 0,
                deposit_amount: 1_000,
                current_root: Felt252::from_u64(5),
            },
            VaultEvent::ClosedLeafRetired {
                note_id: 0,
                new_root: Felt252::from_u64(5),
            },
        ] {
            let mut closed = mirror.clone();
            if matches!(event, VaultEvent::ClosedLeafRetired { .. }) {
                closed.apply_event(&reference.close(0)).unwrap();
            }
            assert!(matches!(
                closed.apply_event(&event),
                Err(MirrorError::RootMismatch { .. })
            ));
        }
    }

    #[test]
    fn apply_event_rejects_exits_of_a_note_that_is_not_active() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let close = reference.close(0);

        let mut unknown = TreeMirror::new();
        assert_eq!(
            unknown.apply_event(&close),
            Err(MirrorError::UnknownNote { note_id: 0 })
        );

        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit, close.clone()]);
        assert_eq!(
            mirror.clone().apply_event(&close),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
        let escape = VaultEvent::EscapeWithdrawalInitiated {
            note_id: 0,
            nullifier: Felt252::from_u64(1),
            final_balance: 1,
            challenge_deadline: 1,
            current_root: mirror.root(),
        };
        assert_eq!(
            mirror.clone().apply_event(&escape),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
        let claim = VaultEvent::ExpiredClaimed {
            note_id: 0,
            deposit_amount: 1_000,
            current_root: mirror.root(),
        };
        assert_eq!(
            mirror.apply_event(&claim),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );

        // A pending escape is not active either.
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let escape = reference.escape(0, 900);
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit]);
        apply_all(&mut mirror, &escape);
        assert_eq!(
            mirror.apply_event(&VaultEvent::MutualClose {
                note_id: 0,
                nullifier: Felt252::from_u64(1),
                final_balance: 1,
            }),
            Err(MirrorError::NoteNotActive { note_id: 0 })
        );
    }

    #[test]
    fn only_a_closed_note_has_its_leaf_retired() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();
        let retire = VaultEvent::ClosedLeafRetired {
            note_id: 0,
            new_root: TreeMirror::empty_root(),
        };
        assert_eq!(
            mirror.clone().apply_event(&retire),
            Err(MirrorError::NoteNotClosed { note_id: 0 })
        );
        apply_all(&mut mirror, &reference.escape(0, 900));
        assert_eq!(
            mirror.clone().apply_event(&retire),
            Err(MirrorError::NoteNotClosed { note_id: 0 })
        );
        assert_eq!(
            TreeMirror::new().apply_event(&retire),
            Err(MirrorError::UnknownNote { note_id: 0 })
        );
        apply_all(&mut mirror, &[reference.finalize(0, 900)]);
        mirror.apply_event(&reference.retire(0)).unwrap();
        assert_eq!(mirror.root(), TreeMirror::empty_root());
    }

    #[test]
    fn apply_event_rejects_defeat_raise_or_finalize_without_pending_escape() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let mut mirror = TreeMirror::new();
        mirror.apply_event(&deposit).unwrap();

        for event in [
            VaultEvent::EscapeWithdrawalChallenged {
                note_id: 0,
                nullifier: Felt252::from_u64(900),
                current_root: mirror.root(),
            },
            VaultEvent::EscapeWithdrawalFinalized {
                note_id: 0,
                nullifier: Felt252::from_u64(900),
                final_balance: 1,
            },
            VaultEvent::EscapeConcessionRaised {
                note_id: 0,
                nullifier: Felt252::from_u64(900),
                conceded: 2,
                final_balance: 1,
            },
            VaultEvent::EscapeConcessionRecorded {
                note_id: 0,
                next_nullifier: Felt252::from_u64(901),
                state_balance: 3,
                conceded: 2,
            },
        ] {
            assert_eq!(
                mirror.clone().apply_event(&event),
                Err(MirrorError::NoteNotPending { note_id: 0 })
            );
        }
        assert_eq!(
            mirror
                .clone()
                .apply_event(&VaultEvent::EscapeWithdrawalFinalized {
                    note_id: 4,
                    nullifier: Felt252::from_u64(900),
                    final_balance: 1,
                }),
            Err(MirrorError::UnknownNote { note_id: 4 })
        );
    }

    #[test]
    fn apply_event_takes_another_nullifier_as_a_missed_re_escape() {
        let mut reference = Reference::new();
        let deposit = reference.deposit(100);
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &[deposit]);
        apply_all(&mut mirror, &reference.escape(0, 900));
        // The logs miss a defeat of 900 and a re-escape 905 of the note.
        // Neither changes the root, so only the listing is stale.
        reference.challenge(0, 900);
        reference.escape(0, 905);
        assert_eq!(mirror.root(), reference.0.root());
        let missed = |closed_by| MissedReEscape {
            note_id: 0,
            listed_nullifier: Felt252::from_u64(900),
            nullifier: Felt252::from_u64(905),
            closed_by,
        };

        // The vault later finalizes 905: the listed escape closes.
        let mut finalized = mirror.clone();
        let closed = finalized.apply_event(&VaultEvent::EscapeWithdrawalFinalized {
            note_id: 0,
            nullifier: Felt252::from_u64(905),
            final_balance: 1,
        });
        assert_eq!(closed, Ok(Some(missed(EscapeClose::Finalized))));
        assert_eq!(
            closed.unwrap().unwrap().to_string(),
            "note 0 escape 0x389 was finalized while escape 0x384 was listed"
        );
        assert!(finalized.pending_escapes().is_empty());
        assert_eq!(finalized.note_status(0), Some(NoteStatus::Closed));

        // Or defeats it: the note is active again.
        let challenge = reference.challenge(0, 905);
        let mut challenged = mirror.clone();
        assert_eq!(
            challenged.apply_event(&challenge),
            Ok(Some(missed(EscapeClose::Challenged)))
        );
        assert_eq!(challenged.note_status(0), Some(NoteStatus::Active));

        // Or raises it: the listing takes the escape, whose successor is
        // unknown.
        let mut raised = mirror.clone();
        assert_eq!(
            raised.apply_event(&VaultEvent::EscapeConcessionRaised {
                note_id: 0,
                nullifier: Felt252::from_u64(905),
                conceded: 4,
                final_balance: 11,
            }),
            Ok(Some(missed(EscapeClose::Raised)))
        );
        let listed = raised.pending_escapes()[0];
        assert_eq!(listed.withdrawal_nullifier, Felt252::from_u64(905));
        assert_eq!(listed.next_nullifier, None);
        assert_eq!(listed.state_balance, Some(15));

        // The event's root is still checked.
        assert!(matches!(
            mirror.apply_event(&VaultEvent::EscapeWithdrawalChallenged {
                note_id: 0,
                nullifier: Felt252::from_u64(905),
                current_root: Felt252::from_u64(5),
            }),
            Err(MirrorError::RootMismatch { .. })
        ));
    }

    #[test]
    fn snapshot_round_trip_preserves_the_mirror() {
        let mut reference = Reference::new();
        let mut events = vec![
            reference.deposit(100),
            reference.deposit(101),
            reference.deposit(102),
        ];
        events.extend(reference.escape(1, 900));
        events.push(reference.close(2));
        events.push(reference.retire(2));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);

        let restored = TreeMirror::from_snapshot(mirror.snapshot()).unwrap();
        assert_eq!(restored.root(), mirror.root());
        assert_eq!(restored.next_note_id(), 3);
        assert_eq!(restored.get_path(0), mirror.get_path(0));
        assert_eq!(restored.pending_escapes(), mirror.pending_escapes());
        assert_eq!(restored.current_leaves(), mirror.current_leaves());
        assert_eq!(restored.snapshot(), mirror.snapshot());
        for note_id in 0..3 {
            assert_eq!(restored.note_status(note_id), mirror.note_status(note_id));
        }
        assert!(restored.is_published(&Felt252::from_u64(901)));

        let mut restored = restored;
        restored.apply_event(&reference.challenge(1, 900)).unwrap();
        assert_eq!(restored.note_status(1), Some(NoteStatus::Active));
    }

    #[test]
    fn from_snapshot_rejects_inconsistent_state() {
        let mut reference = Reference::new();
        let mut events = vec![reference.deposit(100), reference.deposit(101)];
        events.extend(reference.escape(1, 900));
        let mut mirror = TreeMirror::new();
        apply_all(&mut mirror, &events);
        let snapshot = mirror.snapshot();
        assert!(TreeMirror::from_snapshot(snapshot.clone()).is_ok());

        let rejection = |snapshot: TreeMirrorSnapshot| TreeMirror::from_snapshot(snapshot).err();

        let mut missing = snapshot.clone();
        missing.deposited_leaves.pop();
        assert!(rejection(missing).unwrap().contains("next_note_id"));

        let mut empty_leaf = snapshot.clone();
        empty_leaf.deposited_leaves[0] = Felt252::ZERO;
        assert!(rejection(empty_leaf).is_some());

        let mut active_escape = snapshot.clone();
        active_escape.pending_escapes[0].note_id = 0;
        assert!(rejection(active_escape).unwrap().contains("not pending"));

        let mut orphan_escape = snapshot.clone();
        orphan_escape.pending_escapes[0].note_id = 9;
        assert!(rejection(orphan_escape).is_some());

        let mut dropped_escape = snapshot.clone();
        dropped_escape.pending_escapes.clear();
        assert!(rejection(dropped_escape).is_some());

        let mut retired_active = snapshot.clone();
        retired_active.retired.push(0);
        assert!(rejection(retired_active).unwrap().contains("not closed"));

        let mut unknown_root = snapshot.clone();
        unknown_root
            .known_roots
            .retain(|root| *root != mirror.root());
        assert!(rejection(unknown_root).unwrap().contains("current root"));

        let mut repeated = snapshot;
        let first = repeated.published_nullifiers[0];
        repeated.published_nullifiers.push(first);
        assert!(rejection(repeated).is_some());
    }
}
