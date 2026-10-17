//! The request tree without the operator (design §6.6).
//!
//! A deposit only records its note (`NoteDeposited` carries the note's
//! commitment, amount and expiry); `NotesActivated(first, count, newRoot)`
//! appends the recorded leaves of notes `first .. first + count` as one
//! aligned subtree; `ClosedLeafRetired` zeroes an activated leaf; every other
//! root-bearing event reports the unchanged root. Rebuilding from the vault's
//! logs checks the computed root after every event that reports one.
//!
//! Exits name the note by its stored values and need no path. The tree
//! serves request paths, which must prove membership at the current root,
//! and only a note below the vault's `activationCursor()` has its leaf there
//! ([`note_activation`]).

use std::collections::HashMap;
use std::future::Future;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zkapi_core::v2 as core;
use zkapi_types::{Felt252, MERKLE_DEPTH};

/// `NoteDeposited(uint32 indexed,bytes32 indexed,uint128,uint64)`.
pub const NOTE_DEPOSITED_TOPIC: &str =
    "0x3d5756e39e88718c2260db175f4f454d73fbd02468313b9406bf5c0733481c36";
/// `NotesActivated(uint32 indexed,uint32,uint256,bool)`.
pub const NOTES_ACTIVATED_TOPIC: &str =
    "0x2c5604373c15ade06913903b9f6fffb2f3b0a029d20dac56a6eeb7d8b1c11144";
/// `ClosedLeafRetired(uint32 indexed,uint256)`.
pub const CLOSED_LEAF_RETIRED_TOPIC: &str =
    "0x64572cec8ef079a5baa4f2860f8b65efb52a96f64ee679d315fd2a0541ea28b3";
/// `EscapeWithdrawalInitiated(uint32 indexed,uint256,uint128,address,uint64,uint256)`;
/// data word 4 is the unchanged root.
pub const ESCAPE_INITIATED_TOPIC: &str =
    "0xb0d1eb7131bcf3c6dd53517f6fa90bf7cc94178eb0eb5e0a1f204abe3b839cdf";
/// `EscapeWithdrawalChallenged(uint32 indexed,uint256,uint256)`; data word 1.
pub const ESCAPE_CHALLENGED_TOPIC: &str =
    "0x5cc5343b84cd949969f3ccc4ea44315630280857b9e591cc1ab48dbb9e6a3581";
/// `ExpiredClaimed(uint32 indexed,uint128,uint256)`; data word 1.
pub const EXPIRED_CLAIMED_TOPIC: &str =
    "0x5534ce4a9fb7fe545375064cc186660ac10ba2152cb1592b29b244d2fe169ae4";

/// Every topic the rebuild reads.
pub const TREE_TOPICS: [&str; 6] = [
    NOTE_DEPOSITED_TOPIC,
    NOTES_ACTIVATED_TOPIC,
    CLOSED_LEAF_RETIRED_TOPIC,
    ESCAPE_INITIATED_TOPIC,
    ESCAPE_CHALLENGED_TOPIC,
    EXPIRED_CLAIMED_TOPIC,
];

/// The batch sizes the vault activates notes in.
pub const ACTIVATION_SIZES: [u32; 3] = [1, 4, 16];

/// The first chunk of a log scan, and the smallest it halves to.
pub const LOG_CHUNK_BLOCKS: u64 = 2_000;
pub const MIN_LOG_CHUNK_BLOCKS: u64 = 100;

/// Where a note stands in the vault's activation queue. Notes enter the
/// request tree in id order, so note `note_id` is activated exactly when
/// `note_id < activation_cursor`; until then `note_id - activation_cursor`
/// notes are activated before it. A note can exit either way, but it makes
/// anonymous requests only once activated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NoteActivation {
    pub note_id: u32,
    pub activation_cursor: u32,
    pub activated: bool,
    /// Notes activated before this one (0: it is next); `None` once it is
    /// activated.
    pub queue_position: Option<u32>,
}

/// The activation status of `note_id` under the vault's `activationCursor()`.
pub fn note_activation(note_id: u32, activation_cursor: u32) -> NoteActivation {
    let activated = note_id < activation_cursor;
    NoteActivation {
        note_id,
        activation_cursor,
        activated,
        queue_position: (!activated).then(|| note_id - activation_cursor),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// A log is not a well-formed vault event.
    InvalidLog(String),
    /// The event at `(block, log_index)` cannot follow the events before it
    /// (a note recorded out of order, a misaligned or premature activation, a
    /// retirement of a leaf that is not in the tree).
    InvalidEvent {
        block: u64,
        log_index: u64,
        reason: String,
    },
    /// After the event at `(block, log_index)` the computed root differs
    /// from the root the event reports.
    RootMismatch { block: u64, log_index: u64 },
    /// The note is not activated: its leaf is not in the request tree.
    NotActivated {
        note_id: u32,
        activation_cursor: u32,
    },
    /// The note's leaf in the rebuilt tree is not the expected leaf.
    LeafMismatch(u32),
    /// The log source failed.
    Fetch(String),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLog(message) => write!(f, "invalid vault log: {message}"),
            Self::InvalidEvent {
                block,
                log_index,
                reason,
            } => write!(
                f,
                "the vault event at block {block}, log {log_index} cannot follow the earlier events: {reason}"
            ),
            Self::RootMismatch { block, log_index } => write!(
                f,
                "the rebuilt tree's root differs from the vault's after the event at block {block}, log {log_index}"
            ),
            Self::NotActivated {
                note_id,
                activation_cursor,
            } => write!(
                f,
                "note {note_id} is not activated (the activation cursor is {activation_cursor}); its leaf is not in the request tree"
            ),
            Self::LeafMismatch(note) => {
                write!(f, "the rebuilt tree does not hold note {note}'s leaf")
            }
            Self::Fetch(message) => write!(f, "vault logs could not be read: {message}"),
        }
    }
}

impl std::error::Error for TreeError {}

/// A tree-relevant vault event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEvent {
    /// A note was recorded; the tree is unchanged.
    Deposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
    },
    /// Notes `first_note_id .. first_note_id + count` entered the tree.
    /// `proved` tells a proved batch from the on-chain fallback.
    Activated {
        first_note_id: u32,
        count: u32,
        new_root: Felt252,
        proved: bool,
    },
    Retired {
        note_id: u32,
        new_root: Felt252,
    },
    /// An event that reports the current root without changing it.
    Root {
        root: Felt252,
    },
}

impl TreeEvent {
    /// The root the vault reports after this event, if it reports one.
    pub fn reported_root(&self) -> Option<&Felt252> {
        match self {
            Self::Deposited { .. } => None,
            Self::Activated { new_root, .. } | Self::Retired { new_root, .. } => Some(new_root),
            Self::Root { root } => Some(root),
        }
    }
}

/// A decoded event and its position in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionedEvent {
    pub block: u64,
    pub log_index: u64,
    pub event: TreeEvent,
}

fn quantity(value: &Value, field: &str) -> Result<u64, TreeError> {
    value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| TreeError::InvalidLog(format!("{field} is not a quantity")))
}

fn word(hex: &str) -> Result<[u8; 32], TreeError> {
    let bytes =
        hex::decode(hex).map_err(|_| TreeError::InvalidLog("a word is not hexadecimal".into()))?;
    bytes
        .try_into()
        .map_err(|_| TreeError::InvalidLog("a word is not 32 bytes".into()))
}

fn words(data: &str, count: usize) -> Result<Vec<[u8; 32]>, TreeError> {
    let digits = data
        .strip_prefix("0x")
        .ok_or_else(|| TreeError::InvalidLog("data is not 0x-prefixed".into()))?;
    if digits.len() != count * 64 {
        return Err(TreeError::InvalidLog(format!(
            "data has {} bytes, expected {}",
            digits.len() / 2,
            count * 32
        )));
    }
    (0..count)
        .map(|index| word(&digits[index * 64..(index + 1) * 64]))
        .collect()
}

fn felt(word: &[u8; 32]) -> Felt252 {
    Felt252(*word)
}

fn small(word: &[u8; 32], bytes: usize) -> Result<u128, TreeError> {
    if word[..32 - bytes].iter().any(|byte| *byte != 0) {
        return Err(TreeError::InvalidLog("a word exceeds its type".into()));
    }
    Ok(word[32 - bytes..]
        .iter()
        .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)))
}

fn boolean(word: &[u8; 32]) -> Result<bool, TreeError> {
    match small(word, 1)? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(TreeError::InvalidLog(
            "a bool word is neither 0 nor 1".into(),
        )),
    }
}

fn topic(log: &Value, index: usize) -> Result<[u8; 32], TreeError> {
    log["topics"][index]
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or_else(|| TreeError::InvalidLog(format!("topic {index} is missing")))
        .and_then(word)
}

/// Decode one `eth_getLogs` entry of `vault`. Logs of other addresses, of
/// other events and removed logs decode to `None`.
pub fn decode_log(log: &Value, vault: &[u8; 20]) -> Result<Option<PositionedEvent>, TreeError> {
    if log["removed"] == true {
        return Ok(None);
    }
    let address = log["address"]
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| hex::decode(digits).ok())
        .ok_or_else(|| TreeError::InvalidLog("address is missing".into()))?;
    if address != vault {
        return Ok(None);
    }
    let Some(topic0) = log["topics"][0].as_str() else {
        return Ok(None);
    };
    let block = quantity(&log["blockNumber"], "blockNumber")?;
    let log_index = quantity(&log["logIndex"], "logIndex")?;
    let data = log["data"].as_str().unwrap_or("0x");
    let note_id = || small(&topic(log, 1)?, 4).map(|value| value as u32);
    let event = if topic0.eq_ignore_ascii_case(NOTE_DEPOSITED_TOPIC) {
        let data = words(data, 2)?;
        TreeEvent::Deposited {
            note_id: note_id()?,
            commitment: felt(&topic(log, 2)?),
            amount: small(&data[0], 16)?,
            expiry_ts: small(&data[1], 8)? as u64,
        }
    } else if topic0.eq_ignore_ascii_case(NOTES_ACTIVATED_TOPIC) {
        let data = words(data, 3)?;
        TreeEvent::Activated {
            first_note_id: note_id()?,
            count: small(&data[0], 4)? as u32,
            new_root: felt(&data[1]),
            proved: boolean(&data[2])?,
        }
    } else if topic0.eq_ignore_ascii_case(CLOSED_LEAF_RETIRED_TOPIC) {
        TreeEvent::Retired {
            note_id: note_id()?,
            new_root: felt(&words(data, 1)?[0]),
        }
    } else if topic0.eq_ignore_ascii_case(ESCAPE_INITIATED_TOPIC) {
        TreeEvent::Root {
            root: felt(&words(data, 5)?[4]),
        }
    } else if topic0.eq_ignore_ascii_case(ESCAPE_CHALLENGED_TOPIC)
        || topic0.eq_ignore_ascii_case(EXPIRED_CLAIMED_TOPIC)
    {
        TreeEvent::Root {
            root: felt(&words(data, 2)?[1]),
        }
    } else {
        return Ok(None);
    };
    Ok(Some(PositionedEvent {
        block,
        log_index,
        event,
    }))
}

/// A sparse depth-32 note tree.
#[derive(Debug, Clone)]
pub struct SparseTree {
    /// `(level, index)` → node; level 0 holds the leaves.
    nodes: HashMap<(usize, u64), Felt252>,
    zeros: [Felt252; MERKLE_DEPTH + 1],
}

impl Default for SparseTree {
    fn default() -> Self {
        Self::new()
    }
}

impl SparseTree {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            zeros: core::zero_hashes(),
        }
    }

    fn node(&self, level: usize, index: u64) -> Felt252 {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.zeros[level])
    }

    pub fn root(&self) -> Felt252 {
        self.node(MERKLE_DEPTH, 0)
    }

    pub fn leaf(&self, note_id: u32) -> Felt252 {
        self.node(0, u64::from(note_id))
    }

    pub fn set_leaf(&mut self, note_id: u32, leaf: Felt252) {
        let mut index = u64::from(note_id);
        let mut current = leaf;
        for level in 0..=MERKLE_DEPTH {
            if current == self.zeros[level] {
                self.nodes.remove(&(level, index));
            } else {
                self.nodes.insert((level, index), current);
            }
            if level == MERKLE_DEPTH {
                break;
            }
            let sibling = self.node(level, index ^ 1);
            current = if index & 1 == 0 {
                core::merkle_node(&current, &sibling)
            } else {
                core::merkle_node(&sibling, &current)
            };
            index >>= 1;
        }
    }

    pub fn siblings(&self, note_id: u32) -> [Felt252; MERKLE_DEPTH] {
        let mut siblings = [Felt252::ZERO; MERKLE_DEPTH];
        let mut index = u64::from(note_id);
        for (level, sibling) in siblings.iter_mut().enumerate() {
            *sibling = self.node(level, index ^ 1);
            index >>= 1;
        }
        siblings
    }

    /// The path of `note_id`, checked to hold `expected_leaf`.
    pub fn path(
        &self,
        note_id: u32,
        expected_leaf: &Felt252,
    ) -> Result<(Felt252, Vec<Felt252>), TreeError> {
        if self.leaf(note_id) != *expected_leaf {
            return Err(TreeError::LeafMismatch(note_id));
        }
        Ok((self.root(), self.siblings(note_id).to_vec()))
    }
}

/// The vault's note records and its request tree, as its events build them.
#[derive(Debug, Clone, Default)]
pub struct VaultTree {
    /// The leaves of the activated notes, retired ones zeroed.
    tree: SparseTree,
    /// The leaf of every recorded note, by note id, activated or not.
    recorded: Vec<Felt252>,
    activation_cursor: u32,
}

impl VaultTree {
    pub fn new() -> Self {
        Self::default()
    }

    /// The request tree's root (the vault's `currentRoot()`).
    pub fn root(&self) -> Felt252 {
        self.tree.root()
    }

    /// The request tree itself; [`SparseTree::siblings`] of slot
    /// [`Self::activation_cursor`] is the path `activateNotesOnChain` takes.
    pub fn tree(&self) -> &SparseTree {
        &self.tree
    }

    /// The vault's `nextNoteId()`.
    pub fn next_note_id(&self) -> u32 {
        self.recorded.len() as u32
    }

    /// The vault's `activationCursor()`.
    pub fn activation_cursor(&self) -> u32 {
        self.activation_cursor
    }

    /// The leaf note `note_id` was recorded with, activated or not.
    pub fn recorded_leaf(&self, note_id: u32) -> Option<Felt252> {
        self.recorded.get(note_id as usize).copied()
    }

    /// Apply one event, refusing one that cannot follow the events applied
    /// so far. The caller compares [`TreeEvent::reported_root`] with
    /// [`Self::root`] afterwards.
    pub fn apply(&mut self, event: &TreeEvent) -> Result<(), String> {
        match *event {
            TreeEvent::Deposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
            } => {
                if note_id != self.next_note_id() {
                    return Err(format!(
                        "note {note_id} is recorded out of order (the next note id is {})",
                        self.next_note_id()
                    ));
                }
                self.recorded
                    .push(core::note_leaf(note_id, &commitment, amount, expiry_ts));
            }
            TreeEvent::Activated {
                first_note_id,
                count,
                ..
            } => {
                if !ACTIVATION_SIZES.contains(&count) {
                    return Err(format!(
                        "notes are activated 1, 4 or 16 at a time, not {count}"
                    ));
                }
                if first_note_id != self.activation_cursor {
                    return Err(format!(
                        "the activation starts at note {first_note_id}, not at the cursor {}",
                        self.activation_cursor
                    ));
                }
                let end = u64::from(first_note_id) + u64::from(count);
                if first_note_id % count != 0 || end > u64::from(self.next_note_id()) {
                    return Err(format!(
                        "notes {first_note_id} .. {end} are not an aligned batch of recorded notes ({} recorded)",
                        self.next_note_id()
                    ));
                }
                for note_id in first_note_id..first_note_id + count {
                    self.tree.set_leaf(note_id, self.recorded[note_id as usize]);
                }
                self.activation_cursor = first_note_id + count;
            }
            TreeEvent::Retired { note_id, .. } => {
                if note_id >= self.activation_cursor || self.tree.leaf(note_id).is_zero() {
                    return Err(format!("note {note_id} has no leaf in the tree to retire"));
                }
                self.tree.set_leaf(note_id, Felt252::ZERO);
            }
            TreeEvent::Root { .. } => {}
        }
        Ok(())
    }

    /// The path of an activated note at the current root, checked to hold
    /// `expected_leaf` (a retired note's leaf is zero).
    pub fn path(
        &self,
        note_id: u32,
        expected_leaf: &Felt252,
    ) -> Result<(Felt252, Vec<Felt252>), TreeError> {
        if note_id >= self.activation_cursor {
            return Err(TreeError::NotActivated {
                note_id,
                activation_cursor: self.activation_cursor,
            });
        }
        self.tree.path(note_id, expected_leaf)
    }
}

/// Apply `events` in chain order, requiring the computed root to equal the
/// root of each event that reports one.
pub fn rebuild(events: &[PositionedEvent]) -> Result<VaultTree, TreeError> {
    let mut ordered: Vec<&PositionedEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.block, event.log_index));
    let mut tree = VaultTree::new();
    for positioned in ordered {
        tree.apply(&positioned.event)
            .map_err(|reason| TreeError::InvalidEvent {
                block: positioned.block,
                log_index: positioned.log_index,
                reason,
            })?;
        if positioned
            .event
            .reported_root()
            .is_some_and(|reported| tree.root() != *reported)
        {
            return Err(TreeError::RootMismatch {
                block: positioned.block,
                log_index: positioned.log_index,
            });
        }
    }
    Ok(tree)
}

/// Why one `eth_getLogs` call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFetchError {
    /// The RPC refused the block range or the response size: halve it.
    RangeTooLarge,
    Other(String),
}

/// Read every log in `from..=to` through `fetch(from, to)`, in chunks of
/// `LOG_CHUNK_BLOCKS` blocks that halve (down to `MIN_LOG_CHUNK_BLOCKS`) on
/// a range or size error.
pub async fn collect_logs<F, Fut>(from: u64, to: u64, mut fetch: F) -> Result<Vec<Value>, TreeError>
where
    F: FnMut(u64, u64) -> Fut,
    Fut: Future<Output = Result<Vec<Value>, LogFetchError>>,
{
    let mut logs = Vec::new();
    let mut chunk = LOG_CHUNK_BLOCKS;
    let mut start = from;
    while start <= to {
        let end = to.min(start.saturating_add(chunk - 1));
        match fetch(start, end).await {
            Ok(mut found) => {
                logs.append(&mut found);
                if end == u64::MAX {
                    break;
                }
                start = end + 1;
            }
            Err(LogFetchError::RangeTooLarge) if chunk > MIN_LOG_CHUNK_BLOCKS => {
                chunk = (chunk / 2).max(MIN_LOG_CHUNK_BLOCKS);
            }
            Err(LogFetchError::RangeTooLarge) => {
                return Err(TreeError::Fetch(format!(
                    "the RPC refuses even {MIN_LOG_CHUNK_BLOCKS}-block log ranges"
                )))
            }
            Err(LogFetchError::Other(message)) => return Err(TreeError::Fetch(message)),
        }
    }
    Ok(logs)
}

/// Decode, order and rebuild the vault's records and request tree from
/// `logs`.
pub fn tree_from_logs(logs: &[Value], vault: &[u8; 20]) -> Result<VaultTree, TreeError> {
    let mut events = Vec::new();
    for log in logs {
        if let Some(event) = decode_log(log, vault)? {
            events.push(event);
        }
    }
    rebuild(&events)
}

/// The request path of the activated note `note_id` (whose leaf must be
/// `expected_leaf`) at the root after the last tree event in `logs`.
pub fn path_from_logs(
    logs: &[Value],
    vault: &[u8; 20],
    note_id: u32,
    expected_leaf: &Felt252,
) -> Result<(Felt252, Vec<Felt252>), TreeError> {
    tree_from_logs(logs, vault)?.path(note_id, expected_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_proof::insertion::{insertion_roots, InsertedNote};

    const VAULT: [u8; 20] = [0x42; 20];

    fn hex_word(value: &Felt252) -> String {
        hex::encode(value.0)
    }

    fn log(block: u64, index: u64, topics: Vec<String>, data: String) -> Value {
        serde_json::json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": format!("0x{index:x}"),
            "topics": topics,
            "data": data,
            "removed": false,
        })
    }

    fn note_values(note_id: u32) -> (Felt252, u128, u64) {
        (
            core::registration_commitment(&Felt252::from_u64(1_000 + u64::from(note_id))),
            5_000 + u128::from(note_id),
            2_000_000_000 + 86_400 * u64::from(note_id % 3),
        )
    }

    fn leaf_of(note_id: u32) -> Felt252 {
        let (commitment, amount, expiry) = note_values(note_id);
        core::note_leaf(note_id, &commitment, amount, expiry)
    }

    /// The vault's side: records notes, activates aligned batches (checking
    /// each new root against the insertion statement's own computation) and
    /// retires leaves, emitting the logs a rebuild reads.
    #[derive(Clone)]
    struct Vault {
        logs: Vec<Value>,
        block: u64,
        next_note_id: u32,
        cursor: u32,
        tree: SparseTree,
    }

    impl Vault {
        fn new() -> Self {
            Self {
                logs: Vec::new(),
                block: 10,
                next_note_id: 0,
                cursor: 0,
                tree: SparseTree::new(),
            }
        }

        fn emit(&mut self, topics: Vec<String>, data: String) {
            let index = self.logs.len() as u64 % 3;
            if index == 0 {
                self.block += 1;
            }
            self.logs.push(log(self.block, index, topics, data));
        }

        fn deposit(&mut self) -> u32 {
            let note_id = self.next_note_id;
            let (commitment, amount, expiry) = note_values(note_id);
            self.emit(
                vec![
                    NOTE_DEPOSITED_TOPIC.into(),
                    format!("0x{note_id:064x}"),
                    format!("0x{}", hex_word(&commitment)),
                ],
                format!("0x{amount:064x}{expiry:064x}"),
            );
            self.next_note_id += 1;
            note_id
        }

        fn activate(&mut self, count: u32, proved: bool) {
            let first = self.cursor;
            let notes: Vec<InsertedNote> = (first..first + count)
                .map(|note_id| {
                    let (commitment, amount, expiry) = note_values(note_id);
                    InsertedNote {
                        registration_commitment: core::felt_to_field(&commitment),
                        deposit_amount: amount,
                        expiry,
                    }
                })
                .collect();
            let siblings = self
                .tree
                .siblings(first)
                .map(|sibling| core::felt_to_field(&sibling));
            let (old_root, new_root) = insertion_roots(first, &notes, &siblings);
            assert_eq!(core::field_to_felt(&old_root), self.tree.root());
            for note_id in first..first + count {
                self.tree.set_leaf(note_id, leaf_of(note_id));
            }
            assert_eq!(core::field_to_felt(&new_root), self.tree.root());
            self.cursor += count;
            let root = self.tree.root();
            self.emit(
                vec![NOTES_ACTIVATED_TOPIC.into(), format!("0x{first:064x}")],
                format!("0x{count:064x}{}{:064x}", hex_word(&root), u8::from(proved)),
            );
        }

        fn retire(&mut self, note_id: u32) {
            self.tree.set_leaf(note_id, Felt252::ZERO);
            let root = self.tree.root();
            self.emit(
                vec![
                    CLOSED_LEAF_RETIRED_TOPIC.into(),
                    format!("0x{note_id:064x}"),
                ],
                format!("0x{}", hex_word(&root)),
            );
        }

        /// An escape, reporting the unchanged root.
        fn escape(&mut self, note_id: u32) {
            let root = self.tree.root();
            self.emit(
                vec![ESCAPE_INITIATED_TOPIC.into(), format!("0x{note_id:064x}")],
                format!("0x{}{}", "00".repeat(32 * 4), hex_word(&root)),
            );
        }
    }

    /// Deposits are recorded without touching the root; activations of 1, 4
    /// and 16 notes append exactly the insertion statement's subtree; a
    /// retirement leaves a hole that later activations keep.
    #[test]
    fn rebuild_follows_records_mixed_activations_and_retirements() {
        let mut vault = Vault::new();
        for _ in 0..6 {
            vault.deposit();
        }
        for _ in 0..4 {
            vault.activate(1, true);
        }
        // A note can close and be retired once activated; its slot stays a
        // hole under every later activation.
        vault.retire(1);
        for _ in 6..20 {
            vault.deposit();
        }
        vault.escape(4);
        vault.activate(4, true);
        vault.activate(4, false);
        vault.activate(4, true);
        for _ in 20..33 {
            vault.deposit();
        }
        vault.activate(16, true);
        vault.retire(9);
        vault.activate(1, false);

        let rebuilt = tree_from_logs(&vault.logs, &VAULT).unwrap();
        assert_eq!(rebuilt.root(), vault.tree.root());
        assert_eq!(rebuilt.next_note_id(), 33);
        assert_eq!(rebuilt.activation_cursor(), 33);
        assert_eq!(rebuilt.recorded_leaf(9), Some(leaf_of(9)));
        assert!(rebuilt.tree().leaf(9).is_zero());
        for note_id in [0, 2, 3, 4, 15, 16, 31, 32] {
            let leaf = leaf_of(note_id);
            let (root, siblings) = path_from_logs(&vault.logs, &VAULT, note_id, &leaf).unwrap();
            assert_eq!(root, vault.tree.root());
            assert_eq!(
                core::merkle_root(note_id, &leaf, &siblings.try_into().unwrap()),
                root
            );
        }
        for retired in [1, 9] {
            assert_eq!(
                path_from_logs(&vault.logs, &VAULT, retired, &leaf_of(retired)),
                Err(TreeError::LeafMismatch(retired))
            );
        }

        // Out of order on input: the rebuild sorts by block and log index.
        let mut shuffled = vault.logs.clone();
        shuffled.reverse();
        assert_eq!(
            tree_from_logs(&shuffled, &VAULT).unwrap().root(),
            vault.tree.root()
        );

        // Removed logs and other contracts' logs are ignored.
        let mut noisy = vault.logs.clone();
        let mut removed = noisy[0].clone();
        removed["removed"] = Value::Bool(true);
        removed["data"] = Value::String("0x00".into());
        noisy.push(removed);
        let mut foreign = noisy[1].clone();
        foreign["address"] = Value::String(format!("0x{}", "11".repeat(20)));
        noisy.push(foreign);
        assert_eq!(
            tree_from_logs(&noisy, &VAULT).unwrap().root(),
            vault.tree.root()
        );
    }

    /// A recorded note that is not activated has no request path, while
    /// the notes activated before it do; the slot it will fill is empty.
    #[test]
    fn a_recorded_note_has_no_path_until_it_is_activated() {
        let mut vault = Vault::new();
        for _ in 0..6 {
            vault.deposit();
        }
        vault.activate(4, true);
        let rebuilt = tree_from_logs(&vault.logs, &VAULT).unwrap();
        assert_eq!(
            (rebuilt.next_note_id(), rebuilt.activation_cursor()),
            (6, 4)
        );
        assert_eq!(
            rebuilt.path(4, &leaf_of(4)),
            Err(TreeError::NotActivated {
                note_id: 4,
                activation_cursor: 4
            })
        );
        assert!(matches!(
            rebuilt.path(9, &leaf_of(9)),
            Err(TreeError::NotActivated { note_id: 9, .. })
        ));
        assert!(rebuilt.tree().leaf(4).is_zero());
        assert_eq!(rebuilt.recorded_leaf(5), Some(leaf_of(5)));
        assert_eq!(rebuilt.recorded_leaf(6), None);
        rebuilt.path(3, &leaf_of(3)).unwrap();
        // Deposits alone leave the empty tree.
        let mut fresh = Vault::new();
        fresh.deposit();
        assert_eq!(
            tree_from_logs(&fresh.logs, &VAULT).unwrap().root(),
            SparseTree::new().root()
        );
    }

    #[test]
    fn impossible_events_and_wrong_roots_are_refused() {
        let mut vault = Vault::new();
        for _ in 0..8 {
            vault.deposit();
        }
        vault.activate(1, true);
        vault.activate(1, true);
        let base = vault.logs.clone();
        let next_block = vault.block + 1;
        let activation = |first: u32, count: u32| {
            log(
                next_block,
                0,
                vec![NOTES_ACTIVATED_TOPIC.into(), format!("0x{first:064x}")],
                format!("0x{count:064x}{}{:064x}", "00".repeat(32), 1),
            )
        };
        for (first, count, why) in [
            (2, 2, "not a batch size"),
            (2, 4, "misaligned"),
            (3, 1, "not at the cursor"),
            (0, 1, "already activated"),
            (4, 4, "not at the cursor"),
            (2, 16, "beyond the recorded notes"),
        ] {
            let mut logs = base.clone();
            logs.push(activation(first, count));
            assert!(
                matches!(
                    tree_from_logs(&logs, &VAULT),
                    Err(TreeError::InvalidEvent { block, log_index: 0, .. }) if block == next_block
                ),
                "{why}"
            );
        }
        // A note recorded out of order.
        let mut logs = base.clone();
        let mut skipped = Vault::new();
        skipped.next_note_id = 9;
        skipped.block = next_block - 1;
        skipped.deposit();
        logs.extend(skipped.logs);
        assert!(matches!(
            tree_from_logs(&logs, &VAULT),
            Err(TreeError::InvalidEvent { .. })
        ));
        // A retirement of a recorded but not activated note, and a second
        // retirement of the same leaf.
        let retirement = |block: u64, note_id: u32| {
            log(
                block,
                0,
                vec![
                    CLOSED_LEAF_RETIRED_TOPIC.into(),
                    format!("0x{note_id:064x}"),
                ],
                format!("0x{}", "00".repeat(32)),
            )
        };
        let mut logs = base.clone();
        logs.push(retirement(next_block, 5));
        assert!(matches!(
            tree_from_logs(&logs, &VAULT),
            Err(TreeError::InvalidEvent { block, .. }) if block == next_block
        ));
        let mut retired = vault.clone();
        retired.retire(0);
        tree_from_logs(&retired.logs, &VAULT).unwrap();
        let mut logs = retired.logs.clone();
        logs.push(retirement(retired.block + 1, 0));
        assert!(matches!(
            tree_from_logs(&logs, &VAULT),
            Err(TreeError::InvalidEvent { block, .. }) if block == retired.block + 1
        ));
        // An activation whose root disagrees with the recorded leaves (here:
        // the empty root) is refused at that event.
        let mut logs = base.clone();
        logs.push(activation(2, 1));
        assert_eq!(
            tree_from_logs(&logs, &VAULT).unwrap_err(),
            TreeError::RootMismatch {
                block: next_block,
                log_index: 0
            }
        );
        // So is an unchanged-root report that disagrees.
        let mut logs = base;
        logs.push(log(
            next_block,
            0,
            vec![ESCAPE_CHALLENGED_TOPIC.into(), format!("0x{:064x}", 1)],
            format!("0x{}{}", "00".repeat(32), "11".repeat(32)),
        ));
        assert!(matches!(
            tree_from_logs(&logs, &VAULT),
            Err(TreeError::RootMismatch { .. })
        ));
    }

    #[test]
    fn the_new_events_decode_strictly() {
        let root = Felt252::from_u64(0xabc);
        let activation = |proved: &str, count: &str| {
            log(
                3,
                1,
                vec![NOTES_ACTIVATED_TOPIC.into(), format!("0x{:064x}", 16)],
                format!("0x{count}{}{proved}", hex_word(&root)),
            )
        };
        let one = format!("{:064x}", 1);
        let four = format!("{:064x}", 4);
        assert_eq!(
            decode_log(&activation(&one, &four), &VAULT).unwrap(),
            Some(PositionedEvent {
                block: 3,
                log_index: 1,
                event: TreeEvent::Activated {
                    first_note_id: 16,
                    count: 4,
                    new_root: root,
                    proved: true
                }
            })
        );
        let zero = format!("{:064x}", 0);
        assert!(matches!(
            decode_log(&activation(&zero, &four), &VAULT)
                .unwrap()
                .unwrap()
                .event,
            TreeEvent::Activated { proved: false, .. }
        ));
        let two = format!("{:064x}", 2);
        assert!(decode_log(&activation(&two, &four), &VAULT).is_err());
        let wide = format!("{:064x}", 1u64 << 32);
        assert!(decode_log(&activation(&one, &wide), &VAULT).is_err());
        // NoteDeposited carries two words, and no root.
        let mut vault = Vault::new();
        vault.deposit();
        let deposit = vault.logs[0].clone();
        let (commitment, amount, expiry_ts) = note_values(0);
        let event = decode_log(&deposit, &VAULT).unwrap().unwrap().event;
        assert_eq!(
            event,
            TreeEvent::Deposited {
                note_id: 0,
                commitment,
                amount,
                expiry_ts
            }
        );
        assert_eq!(event.reported_root(), None);
        let mut with_root = deposit;
        with_root["data"] = Value::String(format!(
            "{}{}",
            with_root["data"].as_str().unwrap(),
            "00".repeat(32)
        ));
        assert!(decode_log(&with_root, &VAULT).is_err());
    }

    #[test]
    fn activation_status_is_the_notes_place_behind_the_cursor() {
        assert_eq!(
            note_activation(2, 3),
            NoteActivation {
                note_id: 2,
                activation_cursor: 3,
                activated: true,
                queue_position: None
            }
        );
        assert_eq!(note_activation(3, 3).queue_position, Some(0));
        assert!(!note_activation(3, 3).activated);
        assert_eq!(note_activation(20, 4).queue_position, Some(16));
        assert_eq!(note_activation(u32::MAX, 0).queue_position, Some(u32::MAX));
        assert_eq!(
            serde_json::to_value(note_activation(5, 1)).unwrap(),
            serde_json::json!({"note_id": 5, "activation_cursor": 1, "activated": false, "queue_position": 4})
        );
    }

    #[tokio::test]
    async fn log_scans_halve_their_chunk_on_range_errors() {
        let mut calls = Vec::new();
        let logs = collect_logs(1_000, 5_999, |from, to| {
            calls.push((from, to));
            let refused = to - from + 1 > 500;
            async move {
                if refused {
                    Err(LogFetchError::RangeTooLarge)
                } else {
                    Ok(vec![serde_json::json!({ "from": from })])
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(calls[0], (1_000, 2_999));
        assert_eq!(calls[1], (1_000, 1_999));
        assert_eq!(calls[2], (1_000, 1_499));
        assert_eq!(logs.len(), 10);
        assert_eq!(calls.last(), Some(&(5_500, 5_999)));
        let failed = collect_logs(0, 10, |_, _| async { Err(LogFetchError::RangeTooLarge) }).await;
        assert!(matches!(failed, Err(TreeError::Fetch(_))));
    }
}
