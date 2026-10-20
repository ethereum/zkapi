//! Request paths without the operator (vault revision 4, design C).
//!
//! The note tree serves request paths only. An exit (escape, mutual close,
//! ownership proof) is bound to the leaf the vault stored at deposit and
//! needs no path, root, indexer or log scan.
//!
//! A request proves membership at a root the server admits: one the vault
//! reports through `currentRoot()`. Without the indexer, a client rebuilds
//! the tree itself and checks it against that root:
//!
//! - [`rebuild_from_state`] (primary): `nextNoteId()`, the leaves in
//!   `noteLeaves(start, 2048)` pages and `currentRoot()`, every read pinned
//!   to one block hash (EIP-1898) of a recent `latest` or `safe` block. This
//!   is a read of recent state, not of history: during a finality stall use
//!   `latest`/`safe` rather than `finalized`.
//! - [`rebuild_from_logs`] (fallback): the `NoteDeposited` and
//!   `ClosedLeafRetired` logs up to a pinned block, then one `currentRoot()`
//!   check at that block's hash. No event carries a root since revision 4.
//!
//! [`rebuild_request_tree`] pins a block and tries both in that order.

use std::collections::HashMap;
use std::future::Future;

use serde_json::{json, Value};
use zkapi_core::v2 as core;
use zkapi_types::{Felt252, MERKLE_DEPTH};

/// `NoteDeposited(uint32 indexed noteId, bytes32 indexed commitment, uint128 amount, uint64
/// expiryTs)`: two data words, no root.
pub const NOTE_DEPOSITED_TOPIC: &str =
    "0x3d5756e39e88718c2260db175f4f454d73fbd02468313b9406bf5c0733481c36";
/// `ClosedLeafRetired(uint32 indexed noteId)`: no data.
pub const CLOSED_LEAF_RETIRED_TOPIC: &str =
    "0x733841afe92a19d5b309b7732cf095a30edfae784b7cc5f0a97dec7140fb8e13";

/// Every topic the log rebuild reads: the only events that change a leaf.
pub const TREE_TOPICS: [&str; 2] = [NOTE_DEPOSITED_TOPIC, CLOSED_LEAF_RETIRED_TOPIC];

/// `noteLeaves(uint32 start, uint32 count) → uint256[]`; reverts
/// `InvalidNoteRange` if `start + count > nextNoteId`.
pub const NOTE_LEAVES_SELECTOR: &str = "31749c58";
/// `nextNoteId() → uint32`.
pub const NEXT_NOTE_ID_SELECTOR: &str = "7a2043a3";
/// `currentRoot() → uint256`, computed by the vault from its frontier.
pub const CURRENT_ROOT_SELECTOR: &str = "fdab463d";

/// Leaves per `noteLeaves` call (≈5.2M gas of `eth_call` at 2,048).
pub const NOTE_LEAVES_PAGE: u32 = 2_048;

/// The first chunk of a log scan, and the smallest it halves to.
pub const LOG_CHUNK_BLOCKS: u64 = 2_000;
pub const MIN_LOG_CHUNK_BLOCKS: u64 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeError {
    /// A log is not a well-formed vault event.
    InvalidLog(String),
    /// A vault read at the pinned block is malformed.
    InvalidState(String),
    /// The rebuilt tree's root is not the vault's `currentRoot()` at the
    /// pinned block.
    RootMismatch {
        block: u64,
        vault_root: Felt252,
        computed: Felt252,
    },
    /// The note's leaf in the rebuilt tree is not the expected leaf.
    LeafMismatch(u32),
    /// The chain could not be read.
    Fetch(String),
}

impl std::fmt::Display for TreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLog(message) => write!(f, "invalid vault log: {message}"),
            Self::InvalidState(message) => write!(f, "invalid vault state read: {message}"),
            Self::RootMismatch {
                block,
                vault_root,
                computed,
            } => write!(
                f,
                "the rebuilt tree's root {} differs from the vault's currentRoot() {} at block {block}",
                computed.to_hex(),
                vault_root.to_hex()
            ),
            Self::LeafMismatch(note) => {
                write!(f, "the rebuilt tree does not hold note {note}'s leaf")
            }
            Self::Fetch(message) => write!(f, "the vault could not be read: {message}"),
        }
    }
}

impl std::error::Error for TreeError {}

/// A leaf-changing vault event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeEvent {
    /// Sets leaf `note_id` to `note_leaf(note_id, commitment, amount, expiry_ts)`.
    Deposited {
        note_id: u32,
        commitment: Felt252,
        amount: u128,
        expiry_ts: u64,
    },
    /// Zeroes leaf `note_id` (a Closed note).
    Retired { note_id: u32 },
}

/// A decoded event and its position in the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionedEvent {
    pub block: u64,
    pub log_index: u64,
    pub event: TreeEvent,
}

fn quantity(value: &Value, field: &str) -> Result<u64, String> {
    value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| format!("{field} is not a quantity"))
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

/// The unsigned integer of `bytes` bytes in `word`, or `None` if the word has
/// higher bits set.
fn small(word: &[u8; 32], bytes: usize) -> Option<u128> {
    if word[..32 - bytes].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some(
        word[32 - bytes..]
            .iter()
            .fold(0u128, |value, byte| (value << 8) | u128::from(*byte)),
    )
}

fn log_small(word: &[u8; 32], bytes: usize) -> Result<u128, TreeError> {
    small(word, bytes).ok_or_else(|| TreeError::InvalidLog("a word exceeds its type".into()))
}

fn topic(log: &Value, index: usize) -> Result<[u8; 32], TreeError> {
    log["topics"][index]
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .ok_or_else(|| TreeError::InvalidLog(format!("topic {index} is missing")))
        .and_then(word)
}

/// Decode one `eth_getLogs` entry of `vault`. Logs of other addresses, of
/// other events (including the root-free exit and expiry events, which
/// change no leaf) and removed logs decode to `None`.
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
    let deposited = topic0.eq_ignore_ascii_case(NOTE_DEPOSITED_TOPIC);
    if !deposited && !topic0.eq_ignore_ascii_case(CLOSED_LEAF_RETIRED_TOPIC) {
        return Ok(None);
    }
    let block = quantity(&log["blockNumber"], "blockNumber").map_err(TreeError::InvalidLog)?;
    let log_index = quantity(&log["logIndex"], "logIndex").map_err(TreeError::InvalidLog)?;
    let data = log["data"].as_str().unwrap_or("0x");
    let note_id = log_small(&topic(log, 1)?, 4)? as u32;
    let event = if deposited {
        let data = words(data, 2)?;
        TreeEvent::Deposited {
            note_id,
            commitment: Felt252(topic(log, 2)?),
            amount: log_small(&data[0], 16)?,
            expiry_ts: log_small(&data[1], 8)? as u64,
        }
    } else {
        words(data, 0)?;
        TreeEvent::Retired { note_id }
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
    /// `(level, index)` → node; level 0 holds the leaves. Nodes equal to
    /// their level's zero hash are not stored.
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

    /// The tree whose leaf `i` is `leaves[i]` (zero for a retired note), as
    /// the vault's `noteLeaves` returns them, built level by level: one hash
    /// per non-empty node, about `2 · leaves.len()` in all.
    pub fn from_leaves(leaves: &[Felt252]) -> Self {
        let mut tree = Self::new();
        let mut level_nodes = leaves.to_vec();
        for level in 0..=MERKLE_DEPTH {
            for (index, node) in level_nodes.iter().enumerate() {
                if *node != tree.zeros[level] {
                    tree.nodes.insert((level, index as u64), *node);
                }
            }
            if level == MERKLE_DEPTH {
                break;
            }
            let zero = tree.zeros[level];
            level_nodes = level_nodes
                .chunks(2)
                .map(|pair| {
                    let right = pair.get(1).copied().unwrap_or(zero);
                    if pair[0] == zero && right == zero {
                        tree.zeros[level + 1]
                    } else {
                        core::merkle_node(&pair[0], &right)
                    }
                })
                .collect();
        }
        tree
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

    /// The request path of `note_id`, checked to hold `expected_leaf`: the
    /// tree's root and the note's siblings.
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

/// Apply `events` in chain order. The result is unchecked: compare its root
/// with the vault's `currentRoot()` at the block the events end at (as
/// [`rebuild_from_logs`] does) before any request uses a path of it.
pub fn rebuild(events: &[PositionedEvent]) -> Result<SparseTree, TreeError> {
    let mut ordered: Vec<&PositionedEvent> = events.iter().collect();
    ordered.sort_by_key(|event| (event.block, event.log_index));
    let mut tree = SparseTree::new();
    for positioned in ordered {
        match &positioned.event {
            TreeEvent::Deposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
            } => tree.set_leaf(
                *note_id,
                core::note_leaf(*note_id, commitment, *amount, *expiry_ts),
            ),
            TreeEvent::Retired { note_id } => tree.set_leaf(*note_id, Felt252::ZERO),
        }
    }
    Ok(tree)
}

/// Decode and rebuild `logs` of `vault` (unchecked, see [`rebuild`]), with
/// the number of notes they deposit.
pub fn tree_from_logs(logs: &[Value], vault: &[u8; 20]) -> Result<(SparseTree, u32), TreeError> {
    let mut events = Vec::new();
    let mut next_note_id = 0u32;
    for log in logs {
        if let Some(event) = decode_log(log, vault)? {
            if let TreeEvent::Deposited { note_id, .. } = event.event {
                next_note_id = next_note_id.max(note_id.saturating_add(1));
            }
            events.push(event);
        }
    }
    Ok((rebuild(&events)?, next_note_id))
}

/// Why one `eth_getLogs` call failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LogFetchError {
    /// The RPC refused the block range or the response size: halve it.
    RangeTooLarge,
    Other(String),
}

impl LogFetchError {
    /// Classify an RPC's `eth_getLogs` error message: providers word their
    /// range and response-size limits differently.
    pub fn from_message(message: String) -> Self {
        let lowered = message.to_ascii_lowercase();
        if ["range", "limit", "too many", "too large", "exceed", "size"]
            .iter()
            .any(|needle| lowered.contains(needle))
        {
            Self::RangeTooLarge
        } else {
            Self::Other(message)
        }
    }
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

/// An Ethereum JSON-RPC endpoint the caller trusts for chain state (one the
/// deployment pins or the user configured, never one an operator names).
/// `request` returns the response's `result`, or the error's message.
pub trait JsonRpc {
    fn request(&self, method: &str, params: Value) -> impl Future<Output = Result<Value, String>>;
}

/// A block every read of one rebuild is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedBlock {
    pub number: u64,
    pub hash: [u8; 32],
}

impl PinnedBlock {
    /// The EIP-1898 block parameter for this block: by hash, and refused by
    /// the node once the block is no longer canonical.
    pub fn block_param(&self) -> Value {
        json!({
            "blockHash": format!("0x{}", hex::encode(self.hash)),
            "requireCanonical": true,
        })
    }
}

/// The block `tag` names now (`"latest"` or `"safe"`; `finalized` lags by
/// minutes and stops during a finality stall, and the rebuild reads recent
/// state only).
pub async fn pin_block<R: JsonRpc>(rpc: &R, tag: &str) -> Result<PinnedBlock, TreeError> {
    let block = rpc
        .request("eth_getBlockByNumber", json!([tag, false]))
        .await
        .map_err(TreeError::Fetch)?;
    if block.is_null() {
        return Err(TreeError::Fetch(format!("the RPC has no {tag} block")));
    }
    let number = quantity(&block["number"], "number").map_err(TreeError::InvalidState)?;
    let hash = block["hash"]
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| hex::decode(digits).ok())
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| TreeError::InvalidState("the block has no 32-byte hash".into()))?;
    Ok(PinnedBlock { number, hash })
}

async fn call_at<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
    data: String,
) -> Result<Vec<u8>, TreeError> {
    let result = rpc
        .request(
            "eth_call",
            json!([
                {"to": format!("0x{}", hex::encode(vault)), "data": data},
                block.block_param(),
            ]),
        )
        .await
        .map_err(TreeError::Fetch)?;
    result
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| hex::decode(digits).ok())
        .ok_or_else(|| TreeError::InvalidState("eth_call result is not hex".into()))
}

fn single_word(bytes: &[u8], what: &str) -> Result<[u8; 32], TreeError> {
    bytes
        .try_into()
        .map_err(|_| TreeError::InvalidState(format!("{what} is not one word")))
}

fn field_word(word: [u8; 32], what: &str) -> Result<Felt252, TreeError> {
    Felt252::try_from_bytes_be(word)
        .map_err(|_| TreeError::InvalidState(format!("{what} is not a field element")))
}

/// The vault's `nextNoteId()` at `block`.
pub async fn next_note_id_at<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
) -> Result<u32, TreeError> {
    let bytes = call_at(rpc, vault, block, format!("0x{NEXT_NOTE_ID_SELECTOR}")).await?;
    small(&single_word(&bytes, "nextNoteId()")?, 4)
        .map(|value| value as u32)
        .ok_or_else(|| TreeError::InvalidState("nextNoteId() exceeds uint32".into()))
}

/// The vault's `currentRoot()` at `block`.
pub async fn current_root_at<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
) -> Result<Felt252, TreeError> {
    let bytes = call_at(rpc, vault, block, format!("0x{CURRENT_ROOT_SELECTOR}")).await?;
    field_word(single_word(&bytes, "currentRoot()")?, "currentRoot()")
}

/// The vault's `noteLeaves(start, count)` at `block`: exactly `count`
/// leaves, zero for a retired note.
pub async fn note_leaves_at<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
    start: u32,
    count: u32,
) -> Result<Vec<Felt252>, TreeError> {
    let data = format!("0x{NOTE_LEAVES_SELECTOR}{start:064x}{count:064x}");
    let bytes = call_at(rpc, vault, block, data).await?;
    let malformed =
        || TreeError::InvalidState(format!("noteLeaves({start}, {count}) is malformed"));
    if bytes.len() != 64 + 32 * count as usize {
        return Err(malformed());
    }
    let head: Vec<[u8; 32]> = bytes
        .chunks_exact(32)
        .map(|chunk| chunk.try_into().expect("32-byte chunk"))
        .collect();
    if small(&head[0], 8) != Some(32) || small(&head[1], 8) != Some(u128::from(count)) {
        return Err(malformed());
    }
    head[2..]
        .iter()
        .map(|word| field_word(*word, "a note leaf"))
        .collect()
}

/// The note tree the vault holds at `block`, with that block's root.
#[derive(Debug, Clone)]
pub struct RequestTree {
    pub tree: SparseTree,
    pub block: PinnedBlock,
    /// The vault's `currentRoot()` at `block`, which `tree` reproduces.
    pub root: Felt252,
    pub next_note_id: u32,
}

impl RequestTree {
    /// The request path of `note_id`, whose leaf must be `expected_leaf`.
    pub fn path(
        &self,
        note_id: u32,
        expected_leaf: &Felt252,
    ) -> Result<(Felt252, Vec<Felt252>), TreeError> {
        self.tree.path(note_id, expected_leaf)
    }
}

/// Require `tree`'s root to be the vault's `currentRoot()` at `block`.
async fn checked<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
    tree: SparseTree,
    next_note_id: u32,
) -> Result<RequestTree, TreeError> {
    let vault_root = current_root_at(rpc, vault, block).await?;
    let computed = tree.root();
    if computed != vault_root {
        return Err(TreeError::RootMismatch {
            block: block.number,
            vault_root,
            computed,
        });
    }
    Ok(RequestTree {
        tree,
        block: *block,
        root: vault_root,
        next_note_id,
    })
}

/// Rebuild the tree from the vault's state at `block` (primary):
/// `nextNoteId()`, then its leaves in `noteLeaves` pages of
/// [`NOTE_LEAVES_PAGE`], then `currentRoot()`, every read pinned to
/// `block.hash`, and require the rebuilt root to be the vault's.
pub async fn rebuild_from_state<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    block: &PinnedBlock,
) -> Result<RequestTree, TreeError> {
    // Read first: `noteLeaves` reverts for a range past `nextNoteId`.
    let next_note_id = next_note_id_at(rpc, vault, block).await?;
    let mut leaves = Vec::with_capacity(next_note_id as usize);
    let mut start = 0u32;
    while start < next_note_id {
        let count = (next_note_id - start).min(NOTE_LEAVES_PAGE);
        leaves.extend(note_leaves_at(rpc, vault, block, start, count).await?);
        start += count;
    }
    checked(
        rpc,
        vault,
        block,
        SparseTree::from_leaves(&leaves),
        next_note_id,
    )
    .await
}

/// Rebuild the tree from the vault's logs in `from_block..=block.number`
/// (fallback; `from_block` is the vault's deployment block), then require
/// its root to be the vault's `currentRoot()` at `block.hash`.
pub async fn rebuild_from_logs<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    from_block: u64,
    block: &PinnedBlock,
) -> Result<RequestTree, TreeError> {
    let address = format!("0x{}", hex::encode(vault));
    let logs = collect_logs(from_block, block.number, |start, end| {
        let params = json!([{
            "address": address,
            "fromBlock": format!("0x{start:x}"),
            "toBlock": format!("0x{end:x}"),
            "topics": [TREE_TOPICS],
        }]);
        async move {
            match rpc.request("eth_getLogs", params).await {
                Ok(Value::Array(logs)) => Ok(logs),
                Ok(_) => Err(LogFetchError::Other(
                    "eth_getLogs result is not a list".into(),
                )),
                Err(message) => Err(LogFetchError::from_message(message)),
            }
        }
    })
    .await?;
    let (tree, next_note_id) = tree_from_logs(&logs, vault)?;
    checked(rpc, vault, block, tree, next_note_id).await
}

/// The tree for request paths: pin the `tag` block (`"latest"` or `"safe"`),
/// rebuild from state, and fall back to the logs from `from_block` at the
/// same block when the state reads fail. A root mismatch is not retried: the
/// RPC answered inconsistently for one block hash.
pub async fn rebuild_request_tree<R: JsonRpc>(
    rpc: &R,
    vault: &[u8; 20],
    from_block: u64,
    tag: &str,
) -> Result<RequestTree, TreeError> {
    let block = pin_block(rpc, tag).await?;
    match rebuild_from_state(rpc, vault, &block).await {
        Err(TreeError::Fetch(state) | TreeError::InvalidState(state)) => {
            rebuild_from_logs(rpc, vault, from_block, &block)
                .await
                .map_err(|logs| match logs {
                    TreeError::Fetch(logs) => {
                        TreeError::Fetch(format!("state rebuild: {state}; log rebuild: {logs}"))
                    }
                    other => other,
                })
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use zkapi_core::merkle::MerkleTree;

    const VAULT: [u8; 20] = [0x42; 20];

    fn hex_word(value: &Felt252) -> String {
        hex::encode(value.0)
    }

    fn log(block: u64, index: u64, topics: Vec<String>, data: String) -> Value {
        json!({
            "address": format!("0x{}", hex::encode(VAULT)),
            "blockNumber": format!("0x{block:x}"),
            "logIndex": format!("0x{index:x}"),
            "topics": topics,
            "data": data,
            "removed": false,
        })
    }

    fn commitment(secret: u64) -> Felt252 {
        core::registration_commitment(&Felt252::from_u64(secret))
    }

    fn deposit_log(block: u64, index: u64, note_id: u32, secret: u64) -> Value {
        log(
            block,
            index,
            vec![
                NOTE_DEPOSITED_TOPIC.into(),
                format!("0x{note_id:064x}"),
                format!("0x{}", hex_word(&commitment(secret))),
            ],
            format!("0x{:064x}{:064x}", 1_000u128, 2_000u64),
        )
    }

    fn retire_log(block: u64, index: u64, note_id: u32) -> Value {
        log(
            block,
            index,
            vec![
                CLOSED_LEAF_RETIRED_TOPIC.into(),
                format!("0x{note_id:064x}"),
            ],
            "0x".into(),
        )
    }

    fn leaf(note_id: u32, secret: u64) -> Felt252 {
        core::note_leaf(note_id, &commitment(secret), 1_000, 2_000)
    }

    #[test]
    fn the_topics_are_the_revision_4_events() {
        use zkapi_proof::compact::keccak256;
        for (topic, signature) in [
            (
                NOTE_DEPOSITED_TOPIC,
                "NoteDeposited(uint32,bytes32,uint128,uint64)",
            ),
            (CLOSED_LEAF_RETIRED_TOPIC, "ClosedLeafRetired(uint32)"),
        ] {
            assert_eq!(
                topic,
                format!("0x{}", hex::encode(keccak256(signature.as_bytes())))
            );
        }
        for (selector, signature) in [
            (NOTE_LEAVES_SELECTOR, "noteLeaves(uint32,uint32)"),
            (NEXT_NOTE_ID_SELECTOR, "nextNoteId()"),
            (CURRENT_ROOT_SELECTOR, "currentRoot()"),
        ] {
            assert_eq!(selector, hex::encode(&keccak256(signature.as_bytes())[..4]));
        }
    }

    #[test]
    fn logs_decode_with_the_root_free_layouts() {
        let deposit = decode_log(&deposit_log(10, 2, 5, 7), &VAULT)
            .unwrap()
            .unwrap();
        assert_eq!(
            deposit,
            PositionedEvent {
                block: 10,
                log_index: 2,
                event: TreeEvent::Deposited {
                    note_id: 5,
                    commitment: commitment(7),
                    amount: 1_000,
                    expiry_ts: 2_000,
                },
            }
        );
        assert_eq!(
            decode_log(&retire_log(11, 0, 5), &VAULT)
                .unwrap()
                .unwrap()
                .event,
            TreeEvent::Retired { note_id: 5 }
        );
        // The revision-3 layouts, with a trailing root word, are refused.
        let mut with_root = deposit_log(10, 2, 5, 7);
        with_root["data"] = Value::String(format!(
            "{}{}",
            with_root["data"].as_str().unwrap(),
            "11".repeat(32)
        ));
        assert!(matches!(
            decode_log(&with_root, &VAULT),
            Err(TreeError::InvalidLog(_))
        ));
        let mut retired_with_root = retire_log(11, 0, 5);
        retired_with_root["data"] = Value::String(format!("0x{}", "11".repeat(32)));
        assert!(matches!(
            decode_log(&retired_with_root, &VAULT),
            Err(TreeError::InvalidLog(_))
        ));
        // An amount beyond uint128 is refused.
        let mut wide = deposit_log(10, 2, 5, 7);
        wide["data"] = Value::String(format!("0x{}{:064x}", "01".repeat(32), 2_000u64));
        assert!(matches!(
            decode_log(&wide, &VAULT),
            Err(TreeError::InvalidLog(_))
        ));
        // Removed logs, other contracts' logs, events that change no leaf
        // (escape initiation and challenge, expiry claims) and revision-3
        // topics decode to nothing.
        let mut removed = deposit_log(10, 2, 5, 7);
        removed["removed"] = Value::Bool(true);
        removed["data"] = Value::String("0x00".into());
        let mut foreign = deposit_log(10, 2, 5, 7);
        foreign["address"] = Value::String(format!("0x{}", "11".repeat(20)));
        let initiated = log(
            12,
            0,
            vec![
                "0x5ad24b4d5235cdf161caf23bb21550824a1be902576056f666b56ac6c424f4b1".into(),
                format!("0x{:064x}", 5),
            ],
            format!("0x{}", "00".repeat(32 * 4)),
        );
        let old_deposit = log(
            13,
            0,
            vec![
                "0x7c83dba8534bea9e30d6444f9ca6462dc906897f9938d220dbbe4358c1f7a063".into(),
                format!("0x{:064x}", 6),
                format!("0x{}", hex_word(&commitment(8))),
            ],
            format!("0x{}", "00".repeat(32 * 3)),
        );
        for ignored in [removed, foreign, initiated, old_deposit] {
            assert_eq!(decode_log(&ignored, &VAULT).unwrap(), None, "{ignored}");
        }
    }

    #[test]
    fn rebuild_orders_events_and_handles_retirements() {
        let mut logs = vec![
            deposit_log(10, 0, 0, 7),
            deposit_log(10, 1, 1, 8),
            deposit_log(12, 0, 2, 9),
            retire_log(14, 3, 0),
        ];
        // Out of order on input: the rebuild sorts by block and log index.
        logs.reverse();
        let (tree, next_note_id) = tree_from_logs(&logs, &VAULT).unwrap();
        assert_eq!(next_note_id, 3);
        let expected = MerkleTree::from_leaves(&[Felt252::ZERO, leaf(1, 8), leaf(2, 9)]);
        assert_eq!(tree.root(), expected.root());
        let (root, siblings) = tree.path(1, &leaf(1, 8)).unwrap();
        assert_eq!(root, expected.root());
        assert_eq!(siblings, expected.get_siblings(1).to_vec());
        assert_eq!(
            core::merkle_root(1, &leaf(1, 8), &siblings.try_into().unwrap()),
            root
        );
        // A retired note has no path.
        assert_eq!(tree.path(0, &leaf(0, 7)), Err(TreeError::LeafMismatch(0)));
    }

    #[test]
    fn a_tree_from_leaves_equals_one_built_leaf_by_leaf() {
        for count in [0usize, 1, 2, 3, 7, 64, 129] {
            let leaves: Vec<Felt252> = (0..count)
                .map(|index| {
                    if index % 5 == 3 {
                        Felt252::ZERO
                    } else {
                        leaf(index as u32, index as u64 + 1)
                    }
                })
                .collect();
            let bulk = SparseTree::from_leaves(&leaves);
            let mut incremental = SparseTree::new();
            for (index, value) in leaves.iter().enumerate() {
                incremental.set_leaf(index as u32, *value);
            }
            let reference = MerkleTree::from_leaves(&leaves);
            assert_eq!(bulk.root(), reference.root(), "{count}");
            assert_eq!(bulk.root(), incremental.root(), "{count}");
            for index in 0..count as u32 {
                assert_eq!(bulk.siblings(index), reference.get_siblings(index));
            }
            // Zero nodes are not stored, however the tree was built.
            assert_eq!(bulk.nodes, incremental.nodes, "{count}");
        }
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
                    Ok(vec![json!({ "from": from })])
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
        assert_eq!(
            LogFetchError::from_message("query exceeds max results 10000".into()),
            LogFetchError::RangeTooLarge
        );
        assert_eq!(
            LogFetchError::from_message("connection reset".into()),
            LogFetchError::Other("connection reset".into())
        );
    }

    /// One block of a fake chain: its number, the vault's leaves at it and
    /// the vault's logs up to it.
    #[derive(Clone)]
    struct FakeBlock {
        number: u64,
        hash: [u8; 32],
        leaves: Vec<Felt252>,
    }

    /// A fake JSON-RPC endpoint for a vault: `noteLeaves`, `nextNoteId()` and
    /// `currentRoot()` answer from the block a call is pinned to (by hash
    /// only; a call by number or tag is an error), `currentRoot()` from an
    /// independent tree implementation. Every call is recorded.
    struct FakeRpc {
        blocks: Vec<FakeBlock>,
        logs: Vec<Value>,
        /// Answer `noteLeaves` pages starting at this index from this other
        /// block, as a load balancer ignoring the pin would.
        stray_page: Option<(u32, [u8; 32])>,
        fail_eth_call: bool,
        calls: RefCell<Vec<(String, Value)>>,
    }

    impl FakeRpc {
        fn block(&self, hash: &str) -> Option<&FakeBlock> {
            self.blocks
                .iter()
                .find(|block| format!("0x{}", hex::encode(block.hash)) == hash)
        }

        fn answer(&self, method: &str, params: &Value) -> Result<Value, String> {
            match method {
                "eth_getBlockByNumber" => {
                    let block = match params[0].as_str() {
                        Some("latest") => self.blocks.last(),
                        Some("safe") => self.blocks.iter().rev().nth(1),
                        _ => None,
                    }
                    .ok_or("unknown block")?;
                    Ok(json!({
                        "number": format!("0x{:x}", block.number),
                        "hash": format!("0x{}", hex::encode(block.hash)),
                    }))
                }
                "eth_call" => {
                    if self.fail_eth_call {
                        return Err("execution reverted: out of gas".into());
                    }
                    assert_eq!(params[0]["to"], format!("0x{}", hex::encode(VAULT)));
                    assert_eq!(params[1]["requireCanonical"], true);
                    let hash = params[1]["blockHash"].as_str().ok_or("not pinned")?;
                    let block = self.block(hash).ok_or("unknown block hash")?;
                    let data = params[0]["data"].as_str().unwrap();
                    let words =
                        |from: usize| u32::from_str_radix(&data[from + 56..from + 64], 16).unwrap();
                    match &data[2..10] {
                        NEXT_NOTE_ID_SELECTOR => {
                            Ok(json!(format!("0x{:064x}", block.leaves.len())))
                        }
                        CURRENT_ROOT_SELECTOR => Ok(json!(format!(
                            "0x{}",
                            hex_word(&MerkleTree::from_leaves(&block.leaves).root())
                        ))),
                        NOTE_LEAVES_SELECTOR => {
                            let (start, count) = (words(10), words(74));
                            let source = match self.stray_page {
                                Some((stray, other)) if stray == start => {
                                    self.blocks.iter().find(|b| b.hash == other).unwrap()
                                }
                                _ => block,
                            };
                            let end = start as usize + count as usize;
                            if end > source.leaves.len() {
                                return Err("execution reverted: InvalidNoteRange".into());
                            }
                            let mut out = format!("0x{:064x}{count:064x}", 32);
                            for value in &source.leaves[start as usize..end] {
                                out.push_str(&hex_word(value));
                            }
                            Ok(json!(out))
                        }
                        other => Err(format!("unknown selector {other}")),
                    }
                }
                "eth_getLogs" => {
                    let filter = &params[0];
                    let bound = |field: &str| quantity(&filter[field], field);
                    let (from, to) = (bound("fromBlock")?, bound("toBlock")?);
                    assert_eq!(filter["topics"], json!([TREE_TOPICS]));
                    Ok(Value::Array(
                        self.logs
                            .iter()
                            .filter(|log| {
                                let block = quantity(&log["blockNumber"], "").unwrap();
                                (from..=to).contains(&block)
                            })
                            .cloned()
                            .collect(),
                    ))
                }
                other => Err(format!("unexpected method {other}")),
            }
        }

        fn eth_calls(&self) -> Vec<Value> {
            self.calls
                .borrow()
                .iter()
                .filter(|(method, _)| method == "eth_call")
                .map(|(_, params)| params.clone())
                .collect()
        }
    }

    impl JsonRpc for FakeRpc {
        async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
            self.calls
                .borrow_mut()
                .push((method.to_string(), params.clone()));
            self.answer(method, &params)
        }
    }

    /// A chain of three blocks over a vault with `count` deposits (two
    /// pages and a part), some retired, and its logs: block 100 holds every
    /// deposit but the last, block 101 the last deposit and two
    /// retirements.
    fn fake_chain(count: u32) -> FakeRpc {
        let mut logs = Vec::new();
        let mut leaves = Vec::new();
        for note_id in 0..count {
            let block = if note_id + 1 == count { 101 } else { 100 };
            logs.push(deposit_log(
                block,
                u64::from(note_id),
                note_id,
                1_000 + u64::from(note_id),
            ));
            leaves.push(leaf(note_id, 1_000 + u64::from(note_id)));
        }
        let at_100 = leaves[..leaves.len() - 1].to_vec();
        for retired in [3u32, count - 2] {
            logs.push(retire_log(101, 100_000 + u64::from(retired), retired));
            leaves[retired as usize] = Felt252::ZERO;
        }
        FakeRpc {
            blocks: vec![
                FakeBlock {
                    number: 99,
                    hash: [0x99; 32],
                    leaves: Vec::new(),
                },
                FakeBlock {
                    number: 100,
                    hash: [0xa0; 32],
                    leaves: at_100,
                },
                FakeBlock {
                    number: 101,
                    hash: [0xa1; 32],
                    leaves,
                },
            ],
            logs,
            stray_page: None,
            fail_eth_call: false,
            calls: RefCell::new(Vec::new()),
        }
    }

    const COUNT: u32 = 2 * NOTE_LEAVES_PAGE + 5;

    #[tokio::test]
    async fn the_state_rebuild_equals_the_log_rebuild_at_one_pinned_block() {
        let rpc = fake_chain(COUNT);
        let block = pin_block(&rpc, "latest").await.unwrap();
        assert_eq!(block.number, 101);
        let from_state = rebuild_from_state(&rpc, &VAULT, &block).await.unwrap();
        let state_calls = rpc.eth_calls();
        let from_logs = rebuild_from_logs(&rpc, &VAULT, 0, &block).await.unwrap();

        assert_eq!(from_state.root, from_logs.root);
        assert_eq!(from_state.tree.root(), from_logs.tree.root());
        assert_eq!(
            (from_state.next_note_id, from_logs.next_note_id),
            (COUNT, COUNT)
        );
        for note_id in [0, 1, 2047, 2048, COUNT - 1] {
            let expected = leaf(note_id, 1_000 + u64::from(note_id));
            let path = from_state.path(note_id, &expected).unwrap();
            assert_eq!(path, from_logs.path(note_id, &expected).unwrap());
            assert_eq!(path.0, from_state.root);
        }
        for retired in [3, COUNT - 2] {
            let expected = leaf(retired, 1_000 + u64::from(retired));
            assert_eq!(
                from_state.path(retired, &expected),
                Err(TreeError::LeafMismatch(retired))
            );
        }

        // nextNoteId, three noteLeaves pages within range, currentRoot: all
        // pinned to the one block hash.
        let data: Vec<String> = state_calls
            .iter()
            .map(|params| params[0]["data"].as_str().unwrap()[..10].to_string())
            .collect();
        assert_eq!(
            data,
            [
                format!("0x{NEXT_NOTE_ID_SELECTOR}"),
                format!("0x{NOTE_LEAVES_SELECTOR}"),
                format!("0x{NOTE_LEAVES_SELECTOR}"),
                format!("0x{NOTE_LEAVES_SELECTOR}"),
                format!("0x{CURRENT_ROOT_SELECTOR}"),
            ]
        );
        assert_eq!(
            state_calls[3][0]["data"].as_str().unwrap()[10..],
            format!("{:064x}{:064x}", 2 * NOTE_LEAVES_PAGE, 5)
        );
        for params in rpc.eth_calls() {
            assert_eq!(params[1], block.block_param(), "{params}");
        }

        // The log rebuild's one currentRoot() read is pinned the same way,
        // and its log scan ends at the pinned block.
        let calls = rpc.calls.borrow();
        let scan = calls
            .iter()
            .rev()
            .find(|(method, _)| method == "eth_getLogs")
            .unwrap();
        assert_eq!(scan.1[0]["toBlock"], "0x65");
    }

    #[tokio::test]
    async fn a_page_from_another_block_is_refused() {
        // A safe block (100) and the latest (101) differ in their leaves
        // (note 3 is retired at 101). The first page answered from block 100
        // while pinned to 101 breaks the root.
        let mut rpc = fake_chain(COUNT);
        rpc.stray_page = Some((0, [0xa0; 32]));
        let block = pin_block(&rpc, "latest").await.unwrap();
        let refused = rebuild_from_state(&rpc, &VAULT, &block).await.unwrap_err();
        let TreeError::RootMismatch {
            block: at,
            vault_root,
            computed,
        } = refused
        else {
            panic!("{refused:?}");
        };
        assert_eq!(at, 101);
        assert_ne!(vault_root, computed);
        assert_eq!(
            vault_root,
            MerkleTree::from_leaves(&rpc.blocks[2].leaves).root()
        );
        // The whole rebuild is refused, not repaired from logs.
        let refused = rebuild_request_tree(&rpc, &VAULT, 0, "latest")
            .await
            .unwrap_err();
        assert!(
            matches!(refused, TreeError::RootMismatch { .. }),
            "{refused:?}"
        );

        // At the safe block itself every read agrees.
        rpc.stray_page = None;
        let safe = pin_block(&rpc, "safe").await.unwrap();
        let tree = rebuild_from_state(&rpc, &VAULT, &safe).await.unwrap();
        assert_eq!((tree.block.number, tree.next_note_id), (100, COUNT - 1));
        assert_eq!(
            tree.root,
            MerkleTree::from_leaves(&rpc.blocks[1].leaves).root()
        );
    }

    #[tokio::test]
    async fn the_log_rebuild_is_checked_against_the_current_root() {
        let rpc = fake_chain(40);
        let block = pin_block(&rpc, "latest").await.unwrap();
        assert!(rebuild_from_logs(&rpc, &VAULT, 0, &block).await.is_ok());

        // A missing retirement log leaves a stale leaf: refused.
        let mut lying = fake_chain(40);
        lying
            .logs
            .retain(|log| log["topics"][0] != CLOSED_LEAF_RETIRED_TOPIC);
        let refused = rebuild_from_logs(&lying, &VAULT, 0, &block)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, TreeError::RootMismatch { block: 101, .. }),
            "{refused:?}"
        );

        // Logs that end at an earlier block do not reproduce the pinned root.
        let early = PinnedBlock {
            number: 100,
            hash: block.hash,
        };
        assert!(matches!(
            rebuild_from_logs(&rpc, &VAULT, 0, &early).await,
            Err(TreeError::RootMismatch { .. })
        ));

        // An empty vault has the empty root.
        let before = PinnedBlock {
            number: 99,
            hash: [0x99; 32],
        };
        let empty = rebuild_from_state(&rpc, &VAULT, &before).await.unwrap();
        assert_eq!(empty.root, core::zero_hashes()[MERKLE_DEPTH]);
        assert_eq!(empty.next_note_id, 0);
    }

    #[tokio::test]
    async fn the_request_tree_falls_back_to_logs_when_state_reads_fail() {
        let mut rpc = fake_chain(40);
        let expected = rebuild_from_state(&rpc, &VAULT, &pin_block(&rpc, "latest").await.unwrap())
            .await
            .unwrap();
        rpc.calls.borrow_mut().clear();
        // Every eth_call fails: the log rebuild cannot be checked against
        // currentRoot() either, so the whole rebuild fails, naming both.
        rpc.fail_eth_call = true;
        let failed = rebuild_request_tree(&rpc, &VAULT, 0, "latest")
            .await
            .unwrap_err();
        assert!(
            matches!(&failed, TreeError::Fetch(message) if message.contains("state rebuild") && message.contains("log rebuild")),
            "{failed:?}"
        );
        // A malformed page (an RPC truncating a large eth_call result) falls
        // back to the logs, checked at the same block.
        rpc.fail_eth_call = false;
        struct Truncating(FakeRpc);
        impl JsonRpc for Truncating {
            async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
                let result = self.0.request(method, params.clone()).await?;
                let leaves_call = method == "eth_call"
                    && params[0]["data"].as_str().unwrap()[2..10] == *NOTE_LEAVES_SELECTOR;
                Ok(if leaves_call {
                    json!(&result.as_str().unwrap()[..200])
                } else {
                    result
                })
            }
        }
        let truncating = Truncating(rpc);
        let tree = rebuild_request_tree(&truncating, &VAULT, 0, "latest")
            .await
            .unwrap();
        assert_eq!(tree.root, expected.root);
        assert!(truncating
            .0
            .calls
            .borrow()
            .iter()
            .any(|(method, _)| method == "eth_getLogs"));
    }
}
