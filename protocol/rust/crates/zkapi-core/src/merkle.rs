//! Fixed-depth binary Merkle tree using Poseidon.
//!
//! - depth: 32
//! - zero leaf value: 0
//! - node hash: Poseidon(domain("zkapi.v2.node"), left, right)

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
    /// Leaf values by index.
    leaves: Vec<Felt252>,
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
            leaves: Vec::new(),
            zero_hashes,
            nodes,
        }
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

    /// Set a leaf and recompute the path to root.
    pub fn set_leaf(&mut self, index: u32, value: Felt252) {
        // Ensure leaves vec is large enough
        while self.leaves.len() <= index as usize {
            self.leaves.push(Felt252::ZERO);
        }
        self.leaves[index as usize] = value;
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
}
