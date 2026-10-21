//! Merkle paths without the operator (design §6.6 and Amendment A1).
//!
//! The vault's note tree is append-only for every note that is not closed:
//! `NoteDeposited` sets a leaf and `ClosedLeafRetired` zeroes one, and every
//! other root-bearing event reports the unchanged root. The vault accepts any
//! root it ever held, so a wallet exits with the path it saved at deposit.
//! Without one, it rebuilds the tree from the vault's logs, checking the
//! computed root after every event.

use std::collections::HashMap;
use std::future::Future;

use serde_json::Value;
use zkapi_core::v2 as core;
use zkapi_types::{Felt252, MERKLE_DEPTH};

/// `NoteDeposited(uint32 indexed,bytes32 indexed,uint128,uint64,uint256)`.
pub const NOTE_DEPOSITED_TOPIC: &str =
    "0x7c83dba8534bea9e30d6444f9ca6462dc906897f9938d220dbbe4358c1f7a063";
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
pub const TREE_TOPICS: [&str; 5] = [
    NOTE_DEPOSITED_TOPIC,
    CLOSED_LEAF_RETIRED_TOPIC,
    ESCAPE_INITIATED_TOPIC,
    ESCAPE_CHALLENGED_TOPIC,
    EXPIRED_CLAIMED_TOPIC,
];

/// The first chunk of a log scan, and the smallest it halves to.
pub const LOG_CHUNK_BLOCKS: u64 = 2_000;
pub const MIN_LOG_CHUNK_BLOCKS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// A log is not a well-formed vault event.
    InvalidLog(String),
    /// After the event at `(block, log_index)` the computed root differs
    /// from the root the event reports.
    RootMismatch { block: u64, log_index: u64 },
    /// The note's leaf in the rebuilt tree is not the expected leaf.
    LeafMismatch(u32),
    /// The log source failed.
    Fetch(String),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLog(message) => write!(f, "invalid vault log: {message}"),
            Self::RootMismatch { block, log_index } => write!(
                f,
                "the rebuilt tree's root differs from the vault's after the event at block {block}, log {log_index}"
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
    Deposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
        new_root: Felt252,
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
        let data = words(data, 3)?;
        TreeEvent::Deposited {
            note_id: note_id()?,
            commitment: felt(&topic(log, 2)?),
            amount: small(&data[0], 16)?,
            expiry_ts: small(&data[1], 8)? as u64,
            new_root: felt(&data[2]),
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

/// Apply `events` in chain order, requiring the computed root to equal each
/// event's root. The final root is the last event's root.
pub fn rebuild(events: &[PositionedEvent]) -> Result<SparseTree, TreeError> {
    let mut ordered: Vec<&PositionedEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.block, event.log_index));
    let mut tree = SparseTree::new();
    for positioned in ordered {
        let reported = match &positioned.event {
            TreeEvent::Deposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
                new_root,
            } => {
                tree.set_leaf(
                    *note_id,
                    core::note_leaf(*note_id, commitment, *amount, *expiry_ts),
                );
                new_root
            }
            TreeEvent::Retired { note_id, new_root } => {
                tree.set_leaf(*note_id, Felt252::ZERO);
                new_root
            }
            TreeEvent::Root { root } => root,
        };
        if tree.root() != *reported {
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

/// Decode, order and rebuild: the path of `note_id` (whose leaf must be
/// `expected_leaf`) at the root of the last tree event in `logs`.
pub fn path_from_logs(
    logs: &[Value],
    vault: &[u8; 20],
    note_id: u32,
    expected_leaf: &Felt252,
) -> Result<(Felt252, Vec<Felt252>), TreeError> {
    let mut events = Vec::new();
    for log in logs {
        if let Some(event) = decode_log(log, vault)? {
            events.push(event);
        }
    }
    rebuild(&events)?.path(note_id, expected_leaf)
}

#[cfg(test)]
mod tests {
    use super::*;

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

    fn deposit_log(
        block: u64,
        index: u64,
        tree: &mut SparseTree,
        note_id: u32,
        secret: u64,
    ) -> Value {
        let commitment = core::registration_commitment(&Felt252::from_u64(secret));
        tree.set_leaf(note_id, core::note_leaf(note_id, &commitment, 1_000, 2_000));
        log(
            block,
            index,
            vec![
                NOTE_DEPOSITED_TOPIC.into(),
                format!("0x{note_id:064x}"),
                format!("0x{}", hex_word(&commitment)),
            ],
            format!(
                "0x{:064x}{:064x}{}",
                1_000u128,
                2_000u64,
                hex_word(&tree.root())
            ),
        )
    }

    #[test]
    fn rebuild_checks_every_root_and_handles_retirements() {
        let mut expected = SparseTree::new();
        let mut logs = vec![
            deposit_log(10, 0, &mut expected, 0, 7),
            deposit_log(10, 1, &mut expected, 1, 8),
            deposit_log(12, 0, &mut expected, 2, 9),
        ];
        // An escape reports the unchanged root.
        logs.push(log(
            13,
            0,
            vec![ESCAPE_INITIATED_TOPIC.into(), format!("0x{:064x}", 1)],
            format!("0x{}{}", "00".repeat(32 * 4), hex_word(&expected.root())),
        ));
        expected.set_leaf(0, Felt252::ZERO);
        logs.push(log(
            14,
            3,
            vec![CLOSED_LEAF_RETIRED_TOPIC.into(), format!("0x{:064x}", 0)],
            format!("0x{}", hex_word(&expected.root())),
        ));
        // Out of order on input: the rebuild sorts by block and log index.
        logs.reverse();
        let leaf = core::note_leaf(
            1,
            &core::registration_commitment(&Felt252::from_u64(8)),
            1_000,
            2_000,
        );
        let (root, siblings) = path_from_logs(&logs, &VAULT, 1, &leaf).unwrap();
        assert_eq!(root, expected.root());
        assert_eq!(
            core::merkle_root(1, &leaf, &siblings.clone().try_into().unwrap()),
            root
        );
        // A retired note has no path.
        assert!(matches!(
            path_from_logs(&logs, &VAULT, 0, &leaf),
            Err(TreeError::LeafMismatch(0))
        ));
        // A root that disagrees with the computed tree is refused.
        let mut lying = logs.clone();
        lying[1]["data"] = Value::String(format!("0x{}{}", "00".repeat(32 * 4), "11".repeat(32)));
        assert!(matches!(
            path_from_logs(&lying, &VAULT, 1, &leaf),
            Err(TreeError::RootMismatch {
                block: 13,
                log_index: 0
            })
        ));
        // Removed logs and other contracts' logs are ignored.
        let mut noisy = logs.clone();
        let mut removed = noisy[0].clone();
        removed["removed"] = Value::Bool(true);
        removed["data"] = Value::String("0x00".into());
        noisy.push(removed);
        let mut foreign = noisy[1].clone();
        foreign["address"] = Value::String(format!("0x{}", "11".repeat(20)));
        noisy.push(foreign);
        assert_eq!(path_from_logs(&noisy, &VAULT, 1, &leaf).unwrap().0, root);
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
