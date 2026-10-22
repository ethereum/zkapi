//! Request-tree frontier vectors for the vault's MerkleUpdateLib (append,
//! computed root, sub-path retirement), from `zkapi_core::merkle::Frontier`
//! and checked against the full tree:
//!
//! ```text
//! cargo run -p zkapi-core --example frontier_vectors > \
//!     ../contracts/test/fixtures/frontier-vectors.json
//! ```
//!
//! * `leaves` are note leaves `note_leaf(i, R(i + 1), 1_000_000 + i, 4_000_000_000)`;
//!   `roots` holds the root after appending the first `next` of them, for every
//!   `next` up to 80 and around every 2^k up to 2^10.
//! * `retirements` retire some of those leaves in order (after all are
//!   appended), each with its level and its full path at that moment (a
//!   caller passes `siblings[..level]` and zero-fills the rest), and the root
//!   after it.
//! * `synthetic` states sit at high indices: the vault's storage (`next`,
//!   `filled`, some leaves below `next`) written directly, then appends and a
//!   retirement, each with the root after it.
//!
//! Every list of objects comes with its length (`root_count`, ...), and the
//! synthetic states keep parallel scalar arrays, for Forge's JSON cheatcodes.
use std::collections::BTreeMap;

use serde_json::{json, Value};
use zkapi_core::merkle::{retire_level, Frontier, MerkleTree};
use zkapi_core::v2::{note_leaf, registration_commitment};
use zkapi_types::{Felt252, MERKLE_DEPTH};

fn word(value: &Felt252) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

fn leaf(index: u64) -> Felt252 {
    note_leaf(
        index as u32,
        &registration_commitment(&Felt252::from_u64(index + 1)),
        1_000_000 + index as u128,
        4_000_000_000,
    )
}

fn main() -> anyhow::Result<()> {
    const COUNT: u64 = 1_100;
    let leaves = (0..COUNT).map(leaf).collect::<Vec<_>>();
    let mut checkpoints = (0..=80u32).collect::<Vec<_>>();
    for k in 7..=10u32 {
        for next in [(1u32 << k) - 2, (1 << k) - 1, 1 << k, (1 << k) + 1] {
            checkpoints.push(next);
        }
    }
    checkpoints.push(COUNT as u32);
    checkpoints.sort_unstable();
    checkpoints.dedup();

    let mut frontier = Frontier::new();
    let mut tree = MerkleTree::new();
    let mut roots = Vec::new();
    if checkpoints[0] == 0 {
        roots.push(json!({"next": 0, "root": word(&frontier.root())}));
    }
    for (index, value) in leaves.iter().enumerate() {
        frontier
            .append(*value)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tree.insert(*value);
        let next = index as u32 + 1;
        if checkpoints.contains(&next) {
            anyhow::ensure!(frontier.root() == tree.root(), "root at {next}");
            roots.push(json!({"next": next, "root": word(&frontier.root())}));
        }
    }

    let mut retirements = Vec::new();
    for index in [1_099u32, 1_098, 1_024, 1_023, 777, 512, 3, 0, 2, 1] {
        let siblings = tree.get_siblings(index);
        let level = retire_level(index, frontier.next_index());
        frontier
            .retire(index, &siblings)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tree.set_leaf(index, Felt252::ZERO);
        anyhow::ensure!(frontier.root() == tree.root(), "retire {index}");
        retirements.push(json!({
            "index": index,
            "level": level,
            "siblings": siblings.iter().map(word).collect::<Vec<_>>(),
            "root": word(&frontier.root()),
        }));
    }

    let mut synthetic = Vec::new();
    for start in [
        (1u32 << 20) - 3,
        (1 << 20) + 5,
        (1 << 31) - 2,
        (1 << 31) + 1,
        u32::MAX - 9,
    ] {
        let mut tree = MerkleTree::new();
        let mut stored = BTreeMap::new();
        let mut existing = Vec::new();
        for offset in [1u32, 2, 3, 6, 17, 300, 70_000] {
            let index = start - offset;
            let value = leaf(index as u64);
            tree.set_leaf(index, value);
            stored.insert(index, value);
            existing.push((index, value));
        }
        let mut filled = [Felt252::ZERO; MERKLE_DEPTH];
        for (level, entry) in filled.iter_mut().enumerate().skip(1) {
            if (start >> level) & 1 == 1 {
                *entry = tree.node(level, (start >> level) - 1);
            }
        }
        let mut frontier = Frontier::from_state(start, stored, filled);
        anyhow::ensure!(frontier.root() == tree.root(), "synthetic {start}");
        let initial_root = frontier.root();
        let mut appends = Vec::new();
        let mut next = start;
        for _ in 0..8 {
            if next == u32::MAX {
                break;
            }
            let value = leaf(next as u64);
            frontier
                .append(value)
                .map_err(|e| anyhow::anyhow!("{e:?}"))?;
            tree.set_leaf(next, value);
            next += 1;
            anyhow::ensure!(frontier.root() == tree.root(), "append {next}");
            appends.push((value, frontier.root()));
        }
        let retired = start - 70_000;
        let siblings = tree.get_siblings(retired);
        let level = retire_level(retired, frontier.next_index());
        frontier
            .retire(retired, &siblings)
            .map_err(|e| anyhow::anyhow!("{e:?}"))?;
        tree.set_leaf(retired, Felt252::ZERO);
        anyhow::ensure!(frontier.root() == tree.root(), "synthetic retire");
        synthetic.push(json!({
            "next": start,
            "filled": filled.iter().map(word).collect::<Vec<_>>(),
            "leaf_indices": existing.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            "leaf_values": existing.iter().map(|(_, value)| word(value)).collect::<Vec<_>>(),
            "root": word(&initial_root),
            "append_leaves": appends.iter().map(|(value, _)| word(value)).collect::<Vec<_>>(),
            "append_roots": appends.iter().map(|(_, root)| word(root)).collect::<Vec<_>>(),
            "retire": {
                "index": retired,
                "level": level,
                "siblings": siblings.iter().map(word).collect::<Vec<_>>(),
                "root": word(&frontier.root()),
            },
        }));
    }

    let out: Value = json!({
        "source": "protocol/rust/crates/zkapi-core/examples/frontier_vectors.rs (zkapi_core::merkle::Frontier, checked against MerkleTree)",
        "leaves": leaves.iter().map(word).collect::<Vec<_>>(),
        "root_count": roots.len(),
        "roots": roots,
        "retirement_count": retirements.len(),
        "retirements": retirements,
        "synthetic_count": synthetic.len(),
        "synthetic": synthetic,
    });
    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}
