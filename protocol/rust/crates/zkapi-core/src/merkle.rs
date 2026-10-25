//! Fixed-depth binary Merkle tree using Poseidon.
//!
//! - depth: 32
//! - zero leaf value: 0
//! - node hash: Poseidon(domain("zkapi.v2.node"), left, right)
//!
//! [`MerkleTree`] is the full (sparse) tree that serves request paths;
//! [`Frontier`] is the vault's own model of the same tree (revision 4): the
//! leaves and the frontier of complete left subtrees, from which the vault
//! computes `currentRoot()` and retires a Closed leaf over a sub-path.

use std::collections::BTreeMap;

use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::v2::merkle_node;

/// Compute the zero hashes for each level.
/// zero_hashes[0] = 0 (leaf)
/// zero_hashes[i] = H(domain_node, zero_hashes[i-1], zero_hashes[i-1])
pub fn compute_zero_hashes() -> [Felt252; MERKLE_DEPTH + 1] {
    let mut zeros = [Felt252::ZERO; MERKLE_DEPTH + 1];
    for i in 1..=MERKLE_DEPTH {
        zeros[i] = merkle_node(&zeros[i - 1], &zeros[i - 1]);
    }
    zeros
}

/// Compute the root from a leaf and its sibling path.
///
/// - `index`: leaf index (0-based)
/// - `leaf`: leaf value
/// - `siblings`: sibling hashes from bottom to top, length = MERKLE_DEPTH
pub fn compute_root(index: u32, leaf: &Felt252, siblings: &[Felt252; MERKLE_DEPTH]) -> Felt252 {
    let mut current = *leaf;
    let mut idx = index;
    for sibling in siblings.iter().take(MERKLE_DEPTH) {
        if idx & 1 == 0 {
            current = merkle_node(&current, sibling);
        } else {
            current = merkle_node(sibling, &current);
        }
        idx >>= 1;
    }
    current
}

/// Verify that a leaf is in the tree with the given root.
pub fn verify_membership(
    root: &Felt252,
    index: u32,
    leaf: &Felt252,
    siblings: &[Felt252; MERKLE_DEPTH],
) -> bool {
    compute_root(index, leaf, siblings) == *root
}

/// In-memory Merkle tree for the indexer and testing.
#[derive(Clone)]
pub struct MerkleTree {
    /// Number of leaves inserted so far.
    next_index: u32,
    /// Precomputed zero hashes.
    zero_hashes: [Felt252; MERKLE_DEPTH + 1],
    /// Internal node cache: nodes[level][index] = hash.
    /// Level 0 = leaves, level MERKLE_DEPTH = root.
    nodes: Vec<std::collections::HashMap<u32, Felt252>>,
}

impl MerkleTree {
    /// Create an empty Merkle tree.
    pub fn new() -> Self {
        let zero_hashes = compute_zero_hashes();
        let mut nodes = Vec::with_capacity(MERKLE_DEPTH + 1);
        for _ in 0..=MERKLE_DEPTH {
            nodes.push(std::collections::HashMap::new());
        }
        Self {
            next_index: 0,
            zero_hashes,
            nodes,
        }
    }

    /// The tree whose leaves are `leaves`, at indices `0..leaves.len()` (zero for a retired
    /// leaf): the state-based rebuild from the vault's `noteLeaves` pages.
    pub fn from_leaves(leaves: &[Felt252]) -> Self {
        let mut tree = Self::new();
        for leaf in leaves {
            tree.insert(*leaf);
        }
        tree
    }

    /// Get the current root.
    pub fn root(&self) -> Felt252 {
        self.get_node(MERKLE_DEPTH, 0)
    }

    /// Get the next available leaf index.
    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// Get a leaf value.
    pub fn get_leaf(&self, index: u32) -> Felt252 {
        self.get_node(0, index)
    }

    /// Set a leaf and recompute the path to root. The tree stays sparse: only the leaves set
    /// and their paths are stored, so synthetic states at high indices are cheap.
    pub fn set_leaf(&mut self, index: u32, value: Felt252) {
        self.nodes[0].insert(index, value);

        // Recompute path to root
        let mut idx = index;
        for level in 0..MERKLE_DEPTH {
            let parent_idx = idx / 2;
            let left_idx = parent_idx * 2;
            let right_idx = left_idx + 1;
            let left = self.get_node(level, left_idx);
            let right = self.get_node(level, right_idx);
            let parent = merkle_node(&left, &right);
            self.nodes[level + 1].insert(parent_idx, parent);
            idx = parent_idx;
        }
    }

    /// Insert a leaf at the next available index and return the index.
    pub fn insert(&mut self, value: Felt252) -> u32 {
        let idx = self.next_index;
        self.set_leaf(idx, value);
        self.next_index = idx + 1;
        idx
    }

    /// Get sibling path for a leaf index (bottom to top).
    pub fn get_siblings(&self, index: u32) -> [Felt252; MERKLE_DEPTH] {
        let mut siblings = [Felt252::ZERO; MERKLE_DEPTH];
        let mut idx = index;
        for (level, sibling) in siblings.iter_mut().enumerate().take(MERKLE_DEPTH) {
            let sibling_idx = idx ^ 1;
            *sibling = self.get_node(level, sibling_idx);
            idx /= 2;
        }
        siblings
    }

    /// The node at `level` (0 for a leaf, [`MERKLE_DEPTH`] for the root) and `index` within the
    /// level, the zero hash of the level where nothing was set below it.
    pub fn node(&self, level: usize, index: u32) -> Felt252 {
        self.get_node(level, index)
    }

    /// Get a node value at a given level and index, defaulting to zero hash.
    fn get_node(&self, level: usize, index: u32) -> Felt252 {
        self.nodes[level]
            .get(&index)
            .copied()
            .unwrap_or(self.zero_hashes[level])
    }
}

impl Default for MerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

/// `trailing_ones(index)`: the number of frontier levels an append at `index` hashes through
/// (and the level whose frontier entry it writes).
pub fn trailing_ones(index: u32) -> u32 {
    index.trailing_ones()
}

/// The level whose frontier entry a retirement of `index` rewrites while `next_index` is the
/// next free slot: the highest bit where they differ (`msb(index XOR next_index)`). Below it the
/// retired leaf sits in the complete left subtree `filled[level]`; at 0 the leaf is the vault's
/// last note word and no frontier entry changes.
pub fn retire_level(index: u32, next_index: u32) -> usize {
    debug_assert!(index < next_index);
    (31 - (index ^ next_index).leading_zeros()) as usize
}

/// Why a [`Frontier`] operation failed, as the vault reverts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrontierError {
    /// Every index below `u32::MAX` is taken (the vault's TreeFull).
    TreeFull,
    /// The index is at or above the next free slot.
    UnknownLeaf,
    /// The leaf is already zero, or the siblings do not reproduce the frontier entry (the
    /// vault's StaleRoot).
    StaleRoot,
}

/// The vault's request tree (ZkApiVault revision 4), as the vault keeps it: every leaf by note
/// ID (zero once retired) and the frontier `filled[1..32]`, where `filled[t]` is the complete left
/// subtree of height `t` that the next right subtree at that height is hashed with. `filled[0]`
/// is never stored: the vault reads the left leaf from its note word.
///
/// * [`Frontier::append`] at index `k`: nothing for even `k`; for odd `k`, `trailing_ones(k)`
///   compressions starting from `node(leaf[k-1], leaf)`, written to `filled[trailing_ones(k)]`.
/// * [`Frontier::root`] (`currentRoot()`): at most 32 compressions over `next_index`'s bits.
/// * [`Frontier::retire`] of a leaf `k`: the `retire_level(k, next)`-level sub-path, checked
///   against `filled[level]` and rewritten with the leaf zeroed.
///
/// `filled[t]` is meaningful only where bit `t` of `next_index` is set; the other entries hold
/// subtrees already absorbed into higher ones (the vault's `frontier()` view returns them too).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frontier {
    next_index: u32,
    leaves: BTreeMap<u32, Felt252>,
    filled: [Felt252; MERKLE_DEPTH],
}

impl Frontier {
    pub fn new() -> Self {
        Self {
            next_index: 0,
            leaves: BTreeMap::new(),
            filled: [Felt252::ZERO; MERKLE_DEPTH],
        }
    }

    /// Replays the appends of `leaves` (the vault's `noteLeaves(0, n)`, zero for a retired
    /// leaf). The result has the vault's root; frontier entries at zero bits of `next_index` may
    /// differ from the vault's stale ones.
    pub fn from_leaves(leaves: &[Felt252]) -> Result<Self, FrontierError> {
        let mut frontier = Self::new();
        for leaf in leaves {
            frontier.append(*leaf)?;
        }
        Ok(frontier)
    }

    /// A state given directly (as tests synthesize a vault's storage): `next_index`, the nonzero
    /// leaves, and the frontier.
    pub fn from_state(
        next_index: u32,
        leaves: BTreeMap<u32, Felt252>,
        filled: [Felt252; MERKLE_DEPTH],
    ) -> Self {
        Self {
            next_index,
            leaves,
            filled,
        }
    }

    pub fn next_index(&self) -> u32 {
        self.next_index
    }

    /// The leaf at `index`, zero if never set or retired.
    pub fn leaf(&self, index: u32) -> Felt252 {
        self.leaves.get(&index).copied().unwrap_or(Felt252::ZERO)
    }

    /// The frontier, `filled[0]` always zero (see the type's documentation for stale entries).
    pub fn filled(&self) -> &[Felt252; MERKLE_DEPTH] {
        &self.filled
    }

    /// Appends `leaf` at the next free slot and returns its index.
    pub fn append(&mut self, leaf: Felt252) -> Result<u32, FrontierError> {
        let index = self.next_index;
        if index == u32::MAX {
            return Err(FrontierError::TreeFull);
        }
        if index & 1 == 1 {
            let mut node = crate::v2::merkle_node(&self.leaf(index - 1), &leaf);
            let top = trailing_ones(index) as usize;
            for level in 1..top {
                node = crate::v2::merkle_node(&self.filled[level], &node);
            }
            self.filled[top] = node;
        }
        if !leaf.is_zero() {
            self.leaves.insert(index, leaf);
        }
        self.next_index = index + 1;
        Ok(index)
    }

    /// The root (the vault's computed `currentRoot()`).
    pub fn root(&self) -> Felt252 {
        let zeros = crate::merkle::compute_zero_hashes();
        let next = self.next_index;
        let mut node = Felt252::ZERO;
        let mut empty = true;
        for level in 0..MERKLE_DEPTH {
            if (next >> level) & 1 == 1 {
                let left = if level == 0 {
                    self.leaf(next - 1)
                } else {
                    self.filled[level]
                };
                node = crate::v2::merkle_node(&left, &node);
                empty = false;
            } else if empty {
                node = zeros[level + 1];
            } else {
                node = crate::v2::merkle_node(&node, &zeros[level]);
            }
        }
        node
    }

    /// Sets the leaf at `index` to zero, given its siblings (bottom up; only the first
    /// `retire_level(index, next_index)` are read, as by the vault).
    pub fn retire(
        &mut self,
        index: u32,
        siblings: &[Felt252; MERKLE_DEPTH],
    ) -> Result<(), FrontierError> {
        if index >= self.next_index {
            return Err(FrontierError::UnknownLeaf);
        }
        let old_leaf = self.leaf(index);
        if old_leaf.is_zero() {
            return Err(FrontierError::StaleRoot);
        }
        let level = retire_level(index, self.next_index);
        if level > 0 {
            let mut old_node = old_leaf;
            let mut new_node = Felt252::ZERO;
            for (height, sibling) in siblings.iter().enumerate().take(level) {
                if (index >> height) & 1 == 0 {
                    old_node = crate::v2::merkle_node(&old_node, sibling);
                    new_node = crate::v2::merkle_node(&new_node, sibling);
                } else {
                    old_node = crate::v2::merkle_node(sibling, &old_node);
                    new_node = crate::v2::merkle_node(sibling, &new_node);
                }
            }
            if old_node != self.filled[level] {
                return Err(FrontierError::StaleRoot);
            }
            self.filled[level] = new_node;
        }
        self.leaves.remove(&index);
        Ok(())
    }
}

impl Default for Frontier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_root() {
        let tree = MerkleTree::new();
        let zeros = compute_zero_hashes();
        assert_eq!(tree.root(), zeros[MERKLE_DEPTH]);
    }

    #[test]
    fn test_insert_and_verify() {
        let mut tree = MerkleTree::new();
        let leaf = Felt252::from_u64(42);
        let idx = tree.insert(leaf);
        assert_eq!(idx, 0);

        let siblings = tree.get_siblings(0);
        let root = compute_root(0, &leaf, &siblings);
        assert_eq!(root, tree.root());
        assert!(verify_membership(&tree.root(), 0, &leaf, &siblings));
    }

    #[test]
    fn test_multiple_inserts() {
        let mut tree = MerkleTree::new();
        let leaf0 = Felt252::from_u64(100);
        let leaf1 = Felt252::from_u64(200);
        let leaf2 = Felt252::from_u64(300);

        tree.insert(leaf0);
        tree.insert(leaf1);
        tree.insert(leaf2);

        // Verify all leaves
        for (i, leaf) in [leaf0, leaf1, leaf2].iter().enumerate() {
            let siblings = tree.get_siblings(i as u32);
            assert!(verify_membership(&tree.root(), i as u32, leaf, &siblings));
        }
    }

    #[test]
    fn test_set_leaf_to_zero() {
        let mut tree = MerkleTree::new();
        let leaf = Felt252::from_u64(42);
        tree.insert(leaf);
        let root_with_leaf = tree.root();

        // Zero out the leaf
        tree.set_leaf(0, Felt252::ZERO);
        let root_zeroed = tree.root();

        // Should be back to empty tree root
        let zeros = compute_zero_hashes();
        assert_eq!(root_zeroed, zeros[MERKLE_DEPTH]);
        assert_ne!(root_with_leaf, root_zeroed);
    }

    #[test]
    fn test_update_and_restore() {
        let mut tree = MerkleTree::new();
        let leaf = Felt252::from_u64(42);
        tree.insert(leaf);
        let original_root = tree.root();

        // Zero it
        tree.set_leaf(0, Felt252::ZERO);
        assert_ne!(tree.root(), original_root);

        // Restore it
        tree.set_leaf(0, leaf);
        assert_eq!(tree.root(), original_root);
    }

    /// A deterministic xorshift, so the differential runs are reproducible.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn random_leaf(rng: &mut Rng) -> Felt252 {
        Felt252::from_u64(1 + rng.below(u64::MAX - 1))
    }

    /// The frontier root equals the full tree's after every append and retirement of random
    /// operations, retirements given the full tree's siblings; and siblings above the retirement
    /// level are ignored.
    #[test]
    fn frontier_matches_the_full_tree_over_random_operations() {
        let mut rng = Rng(0x7a6b_6170_6934);
        let mut tree = MerkleTree::new();
        let mut frontier = Frontier::new();
        assert_eq!(frontier.root(), tree.root());
        let mut live: Vec<u32> = Vec::new();
        for step in 0..10_000u32 {
            if live.is_empty() || rng.below(3) != 0 {
                let leaf = random_leaf(&mut rng);
                let index = frontier.append(leaf).unwrap();
                assert_eq!(tree.insert(leaf), index);
                live.push(index);
            } else {
                let index = live.swap_remove(rng.below(live.len() as u64) as usize);
                let mut siblings = tree.get_siblings(index);
                let level = retire_level(index, frontier.next_index());
                if step % 2 == 0 {
                    for sibling in siblings.iter_mut().skip(level) {
                        *sibling = random_leaf(&mut rng);
                    }
                }
                frontier.retire(index, &siblings).unwrap();
                tree.set_leaf(index, Felt252::ZERO);
                assert_eq!(
                    frontier.retire(index, &siblings),
                    Err(FrontierError::StaleRoot)
                );
            }
            if step % 97 == 0 || step < 300 {
                assert_eq!(frontier.root(), tree.root(), "step {step}");
            }
        }
        assert_eq!(frontier.root(), tree.root());
        // The state rebuild (noteLeaves) has the same root.
        let leaves = (0..frontier.next_index())
            .map(|index| frontier.leaf(index))
            .collect::<Vec<_>>();
        assert_eq!(Frontier::from_leaves(&leaves).unwrap().root(), tree.root());
        assert_eq!(MerkleTree::from_leaves(&leaves).root(), tree.root());
    }

    #[test]
    fn retirement_rejects_wrong_siblings_and_unknown_leaves() {
        let mut tree = MerkleTree::new();
        let mut frontier = Frontier::new();
        for value in 1..=6u64 {
            tree.insert(Felt252::from_u64(value));
            frontier.append(Felt252::from_u64(value)).unwrap();
        }
        // Leaf 1 against next index 6: level msb(1 ^ 6) = 2.
        assert_eq!(retire_level(1, 6), 2);
        let mut wrong = tree.get_siblings(1);
        wrong[1] = Felt252::from_u64(99);
        assert_eq!(frontier.retire(1, &wrong), Err(FrontierError::StaleRoot));
        assert_eq!(
            frontier.retire(6, &tree.get_siblings(6)),
            Err(FrontierError::UnknownLeaf)
        );
        // Level 0: the last leaf of an odd count; no siblings are read.
        frontier.append(Felt252::from_u64(7)).unwrap();
        tree.insert(Felt252::from_u64(7));
        assert_eq!(retire_level(6, 7), 0);
        frontier
            .retire(6, &[Felt252::from_u64(5); MERKLE_DEPTH])
            .unwrap();
        tree.set_leaf(6, Felt252::ZERO);
        assert_eq!(frontier.root(), tree.root());
        // A retirement elsewhere in the same block changes filled[level]: the first path is stale.
        let siblings_of_0 = tree.get_siblings(0);
        frontier.retire(1, &tree.get_siblings(1)).unwrap();
        tree.set_leaf(1, Felt252::ZERO);
        assert_eq!(
            frontier.retire(0, &siblings_of_0),
            Err(FrontierError::StaleRoot)
        );
        frontier.retire(0, &tree.get_siblings(0)).unwrap();
        tree.set_leaf(0, Felt252::ZERO);
        assert_eq!(frontier.root(), tree.root());
    }

    /// The vault's frontier written directly at high indices (as Forge tests do with vm.store):
    /// appends and retirements still match the sparse full tree, including the levels a 2^k - 1
    /// index completes.
    #[test]
    fn frontier_matches_the_full_tree_at_synthetic_high_indices() {
        let mut rng = Rng(0x5eed_0001);
        for start in [
            (1u32 << 20) - 3,
            (1 << 20) + 5,
            (1 << 31) - 2,
            (1 << 31) + 1,
            u32::MAX - 40,
        ] {
            let mut tree = MerkleTree::new();
            // A few nonzero leaves just below `start`, spread over levels.
            let mut leaves = BTreeMap::new();
            for offset in [1u32, 2, 3, 6, 17, 300, 70_000] {
                if let Some(index) = start.checked_sub(offset) {
                    let leaf = random_leaf(&mut rng);
                    tree.set_leaf(index, leaf);
                    leaves.insert(index, leaf);
                }
            }
            let mut filled = [Felt252::ZERO; MERKLE_DEPTH];
            for (level, entry) in filled.iter_mut().enumerate().skip(1) {
                if (start >> level) & 1 == 1 {
                    *entry = tree.node(level, (start >> level) - 1);
                }
            }
            let mut frontier = Frontier::from_state(start, leaves.clone(), filled);
            assert_eq!(frontier.root(), tree.root(), "start {start}");
            let mut next = start;
            for _ in 0..32 {
                if next == u32::MAX {
                    assert_eq!(frontier.append(Felt252::ONE), Err(FrontierError::TreeFull));
                    break;
                }
                let leaf = random_leaf(&mut rng);
                assert_eq!(frontier.append(leaf).unwrap(), next);
                tree.set_leaf(next, leaf);
                next += 1;
                assert_eq!(frontier.root(), tree.root(), "append {next}");
            }
            for index in leaves.keys().copied().collect::<Vec<_>>() {
                frontier.retire(index, &tree.get_siblings(index)).unwrap();
                tree.set_leaf(index, Felt252::ZERO);
                assert_eq!(frontier.root(), tree.root(), "retire {index}");
            }
        }
    }

    /// Roots of the frontier at every index up to 1,100, compared with the full tree, including
    /// every 2^k - 1 boundary below it.
    #[test]
    fn frontier_root_at_every_small_index() {
        let mut tree = MerkleTree::new();
        let mut frontier = Frontier::new();
        for value in 0..1_100u64 {
            let leaf = Felt252::from_u64(value * 7 + 3);
            tree.insert(leaf);
            frontier.append(leaf).unwrap();
            assert_eq!(frontier.root(), tree.root(), "{value}");
        }
    }

    #[test]
    fn trailing_ones_and_retire_levels() {
        assert_eq!(trailing_ones(0), 0);
        assert_eq!(trailing_ones(1), 1);
        assert_eq!(trailing_ones(7), 3);
        assert_eq!(trailing_ones(u32::MAX - 1), 0);
        assert_eq!(retire_level(0, 1), 0);
        assert_eq!(retire_level(0, 2), 1);
        assert_eq!(retire_level(3, 4), 2);
        assert_eq!(retire_level(0, 1 << 31), 31);
    }
}
