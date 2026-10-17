//! The insertion statement of `zkapi-v2-concession-v2`: K notes the vault
//! recorded (K = 1, 4 or 16) are appended to the request tree as one aligned
//! subtree, moving the tree from `old_root` to `new_root`.
//!
//! Public inputs, in this order (`3 + 2K`), are exactly what the vault builds
//! from its own state when it activates notes:
//!
//! ```text
//! [old_root, new_root, first_note_id, C_0, M_0, …, C_{K-1}, M_{K-1}]
//! M_j = deposit_amount_j + expiry_j · 2^128
//! ```
//!
//! `old_root` is the vault's current root, `first_note_id` its activation
//! cursor, and `C_j`/`M_j` the registration commitment and packed amount and
//! expiry it stores for note `first_note_id + j`. The circuit constrains:
//!
//! * I1: `first_note_id` is a u32 whose low `log2 K` bits are zero, so the K
//!   indices form one aligned subtree inside the depth-32 tree.
//! * I2: each `M_j` is a u128 amount plus a u64 expiry times 2^128 (unique
//!   below 2^192), and leaf `L_j = H(d_leaf, first_note_id + j, C_j, D_j, e_j)`,
//!   the leaf the request circuit proves membership of.
//! * I3: the K leaves hash to the subtree root with the tree's node hash.
//! * I4: with one private path above the subtree, the EMPTY subtree of height
//!   `log2 K` hashes to `old_root` and the new subtree to `new_root`. So no
//!   occupied leaf is overwritten and every node outside the inserted range,
//!   retired leaves included, is preserved.
//!
//! The statement binds no deployment: it is a fact about two roots and K
//! values, and the vault accepts it only for its own root, cursor and notes.

use ark_bn254::Fr as CircuitField;
use ark_ff::AdditiveGroup;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::prelude::{UInt128, UInt32, UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::groth16::{
    merkle_node, merkle_node_var, note_leaf, note_leaf_var, note_metadata, note_metadata_var,
    REQUEST_MERKLE_DEPTH,
};

/// The batch sizes with a circuit (and a verifying key) of their own.
pub const INSERTION_SIZES: [usize; 3] = [1, 4, 16];

/// Public inputs of the K-note insertion statement.
pub const fn insertion_public_inputs(size: usize) -> usize {
    3 + 2 * size
}

/// Whether `size` is a supported batch size.
pub fn is_insertion_size(size: usize) -> bool {
    INSERTION_SIZES.contains(&size)
}

/// `zero_hash(h)`: the root of an empty subtree of height `h` (0 for a leaf).
pub fn zero_hash(height: usize) -> CircuitField {
    let mut node = CircuitField::ZERO;
    for _ in 0..height {
        node = merkle_node(node, node);
    }
    node
}

/// The values the vault stores for one note, as the insertion statement
/// carries them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InsertedNote {
    pub registration_commitment: CircuitField,
    pub deposit_amount: u128,
    pub expiry: u64,
}

impl InsertedNote {
    /// The note's request-tree leaf at `note_id`.
    pub fn leaf(&self, note_id: u32) -> CircuitField {
        note_leaf(
            note_id,
            self.registration_commitment,
            self.deposit_amount,
            self.expiry,
        )
    }

    pub fn metadata(&self) -> CircuitField {
        note_metadata(self.deposit_amount, self.expiry)
    }
}

#[derive(Clone, Debug)]
pub struct InsertionPublic {
    pub old_root: CircuitField,
    pub new_root: CircuitField,
    pub first_note_id: u32,
    pub notes: Vec<InsertedNote>,
}

impl InsertionPublic {
    pub fn size(&self) -> usize {
        self.notes.len()
    }

    /// The public inputs in statement order.
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        let mut values = vec![
            self.old_root,
            self.new_root,
            CircuitField::from(self.first_note_id),
        ];
        for note in &self.notes {
            values.push(note.registration_commitment);
            values.push(note.metadata());
        }
        values
    }
}

/// The private path above the inserted subtree: `siblings[level]` for
/// `level >= log2 K`, bottom-up, as in a depth-32 Merkle path; the entries
/// below the subtree's height are ignored.
#[derive(Clone, Debug)]
pub struct InsertionWitness {
    pub siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
}

#[derive(Clone, Debug)]
pub struct InsertionCircuit {
    pub public: InsertionPublic,
    pub witness: InsertionWitness,
}

impl InsertionCircuit {
    /// The setup template of the K-note circuit (all values zero; only the
    /// shape matters).
    pub fn template(size: usize) -> Self {
        assert!(is_insertion_size(size), "unsupported insertion size {size}");
        let notes = vec![
            InsertedNote {
                registration_commitment: CircuitField::ZERO,
                deposit_amount: 0,
                expiry: 0,
            };
            size
        ];
        let root = zero_hash(REQUEST_MERKLE_DEPTH);
        Self {
            public: InsertionPublic {
                old_root: root,
                new_root: root,
                first_note_id: 0,
                notes,
            },
            witness: InsertionWitness {
                siblings: [CircuitField::ZERO; REQUEST_MERKLE_DEPTH],
            },
        }
    }
}

/// Subtree height of a K-note batch.
pub fn subtree_height(size: usize) -> usize {
    assert!(is_insertion_size(size), "unsupported insertion size {size}");
    size.trailing_zeros() as usize
}

/// Native root of the K leaves of `notes` starting at `first_note_id`.
pub fn subtree_root(first_note_id: u32, notes: &[InsertedNote]) -> CircuitField {
    let mut level: Vec<CircuitField> = notes
        .iter()
        .enumerate()
        .map(|(offset, note)| note.leaf(first_note_id + offset as u32))
        .collect();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|[left, right]| merkle_node(*left, *right))
            .collect();
    }
    level[0]
}

/// Native `(old_root, new_root)` of the statement: the empty subtree and the
/// subtree of `notes`, each hashed up the path `siblings` above height
/// `log2 K`.
pub fn insertion_roots(
    first_note_id: u32,
    notes: &[InsertedNote],
    siblings: &[CircuitField; REQUEST_MERKLE_DEPTH],
) -> (CircuitField, CircuitField) {
    let height = subtree_height(notes.len());
    let mut old = zero_hash(height);
    let mut new = subtree_root(first_note_id, notes);
    for (level, sibling) in siblings.iter().enumerate().skip(height) {
        if (first_note_id >> level) & 1 == 0 {
            old = merkle_node(old, *sibling);
            new = merkle_node(new, *sibling);
        } else {
            old = merkle_node(*sibling, old);
            new = merkle_node(*sibling, new);
        }
    }
    (old, new)
}

impl ConstraintSynthesizer<CircuitField> for InsertionCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let size = self.public.size();
        if !is_insertion_size(size) {
            return Err(SynthesisError::Unsatisfiable);
        }
        let height = subtree_height(size);
        // Public inputs, in statement order: every input is allocated before
        // any witness so their order is exactly the vault's.
        let old_root = FpVar::new_input(cs.clone(), || Ok(self.public.old_root))?;
        let new_root = FpVar::new_input(cs.clone(), || Ok(self.public.new_root))?;
        let first_input = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.first_note_id))
        })?;
        let mut note_inputs = Vec::with_capacity(size);
        for note in &self.public.notes {
            let commitment = FpVar::new_input(cs.clone(), || Ok(note.registration_commitment))?;
            let metadata = FpVar::new_input(cs.clone(), || Ok(note.metadata()))?;
            note_inputs.push((commitment, metadata));
        }

        // I1: a u32 cursor aligned to K.
        let first = UInt32::new_witness(cs.clone(), || Ok(self.public.first_note_id))?;
        first.to_fp()?.enforce_equal(&first_input)?;
        let bits = first.to_bits_le()?;
        for bit in bits.iter().take(height) {
            bit.enforce_equal(&Boolean::FALSE)?;
        }

        // I2: the leaves of the stored notes.
        let mut level = Vec::with_capacity(size);
        for (offset, (note, (commitment, metadata))) in
            self.public.notes.iter().zip(&note_inputs).enumerate()
        {
            let amount = UInt128::new_witness(cs.clone(), || Ok(note.deposit_amount))?;
            let expiry = UInt64::new_witness(cs.clone(), || Ok(note.expiry))?;
            note_metadata_var(&amount, &expiry)?.enforce_equal(metadata)?;
            // Alignment and the fixed power-of-two K keep first + offset
            // inside the u32 range, so this is the u32 note id.
            let note_id = first_input.clone() + CircuitField::from(offset as u64);
            level.push(note_leaf_var(
                cs.clone(),
                &note_id,
                commitment,
                &amount.to_fp()?,
                &expiry.to_fp()?,
            )?);
        }

        // I3: the subtree root.
        while level.len() > 1 {
            level = level
                .as_chunks::<2>()
                .0
                .iter()
                .map(|[left, right]| merkle_node_var(cs.clone(), left, right))
                .collect::<Result<_, _>>()?;
        }
        let mut new = level.remove(0);

        // I4: the empty subtree and the new one under the same path.
        let mut old = FpVar::Constant(zero_hash(height));
        for (level_index, bit) in bits.iter().enumerate().skip(height) {
            let sibling =
                FpVar::new_witness(cs.clone(), || Ok(self.witness.siblings[level_index]))?;
            let old_left = bit.select(&sibling, &old)?;
            let old_right = bit.select(&old, &sibling)?;
            let new_left = bit.select(&sibling, &new)?;
            let new_right = bit.select(&new, &sibling)?;
            old = merkle_node_var(cs.clone(), &old_left, &old_right)?;
            new = merkle_node_var(cs.clone(), &new_left, &new_right)?;
        }
        old.enforce_equal(&old_root)?;
        new.enforce_equal(&new_root)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::groth16::{registration_commitment, synthesize};
    use ark_ff::Field;
    use ark_relations::r1cs::SynthesisMode;
    use zkapi_core::merkle::MerkleTree;
    use zkapi_types::Felt252;

    fn felt(value: CircuitField) -> Felt252 {
        use ark_ff::{BigInteger, PrimeField};
        let raw = value.into_bigint().to_bytes_be();
        let mut bytes = [0u8; 32];
        bytes[32 - raw.len()..].copy_from_slice(&raw);
        Felt252(bytes)
    }

    fn field(value: &Felt252) -> CircuitField {
        use ark_ff::PrimeField;
        CircuitField::from_be_bytes_mod_order(value.as_bytes())
    }

    fn note(id: u32) -> InsertedNote {
        InsertedNote {
            registration_commitment: registration_commitment(CircuitField::from(100 + id as u64)),
            deposit_amount: 1_000_000 + id as u128,
            expiry: 2_000_000_000 + id as u64,
        }
    }

    /// The batch at `first` over `tree`, with the path read from the tree.
    fn batch(tree: &MerkleTree, first: u32, size: usize) -> InsertionCircuit {
        let notes: Vec<_> = (0..size).map(|j| note(first + j as u32)).collect();
        let siblings = tree.get_siblings(first).map(|value| field(&value));
        let (old_root, new_root) = insertion_roots(first, &notes, &siblings);
        InsertionCircuit {
            public: InsertionPublic {
                old_root,
                new_root,
                first_note_id: first,
                notes,
            },
            witness: InsertionWitness { siblings },
        }
    }

    fn satisfied(circuit: InsertionCircuit) -> bool {
        synthesize(
            circuit,
            SynthesisMode::Prove {
                construct_matrices: true,
            },
        )
        .unwrap()
        .is_satisfied()
        .unwrap()
    }

    #[test]
    fn native_roots_agree_with_the_core_tree() {
        for size in INSERTION_SIZES {
            let mut tree = MerkleTree::new();
            for round in 0..3u32 {
                let first = round * size as u32;
                let circuit = batch(&tree, first, size);
                assert_eq!(circuit.public.old_root, field(&tree.root()), "K={size} old");
                for (offset, inserted) in circuit.public.notes.iter().enumerate() {
                    let id = first + offset as u32;
                    tree.set_leaf(id, felt(inserted.leaf(id)));
                }
                assert_eq!(circuit.public.new_root, field(&tree.root()), "K={size} new");
                assert!(satisfied(circuit), "K={size} round {round}");
            }
        }
    }

    #[test]
    fn every_value_of_the_transition_is_bound() {
        for size in INSERTION_SIZES {
            let tree = MerkleTree::new();
            let good = batch(&tree, 0, size);
            assert!(satisfied(good.clone()));
            let mut bad = good.clone();
            bad.public.old_root += CircuitField::ONE;
            assert!(!satisfied(bad), "K={size} old root");
            let mut bad = good.clone();
            bad.public.new_root += CircuitField::ONE;
            assert!(!satisfied(bad), "K={size} new root");
            let mut bad = good.clone();
            bad.public.notes[size - 1].registration_commitment += CircuitField::ONE;
            assert!(!satisfied(bad), "K={size} commitment");
            let mut bad = good.clone();
            bad.public.notes[0].deposit_amount += 1;
            assert!(!satisfied(bad), "K={size} amount");
            let mut bad = good.clone();
            bad.public.notes[0].expiry += 1;
            assert!(!satisfied(bad), "K={size} expiry");
            let mut bad = good.clone();
            bad.witness.siblings[31] += CircuitField::ONE;
            assert!(!satisfied(bad), "K={size} path");
            let mut bad = good.clone();
            bad.public.first_note_id = size as u32;
            assert!(!satisfied(bad), "K={size} another cursor");
        }
    }

    #[test]
    fn misaligned_or_occupied_destinations_are_unsatisfiable() {
        for size in [4usize, 16] {
            // A cursor off the K alignment (the same values recomputed for it).
            let tree = MerkleTree::new();
            let mut misaligned = batch(&tree, 0, size);
            misaligned.public.first_note_id = 1;
            let (old, new) =
                insertion_roots(1, &misaligned.public.notes, &misaligned.witness.siblings);
            misaligned.public.old_root = old;
            misaligned.public.new_root = new;
            assert!(!satisfied(misaligned), "K={size} misaligned");
        }
        for size in INSERTION_SIZES {
            // The destination already holds a leaf: its root is not the empty
            // subtree's, so no path reproduces old_root from an empty one.
            let mut occupied = MerkleTree::new();
            occupied.set_leaf(size as u32 - 1, felt(note(0).leaf(0)));
            let mut circuit = batch(&occupied, 0, size);
            circuit.public.old_root = field(&occupied.root());
            assert!(!satisfied(circuit), "K={size} occupied");
        }
    }

    #[test]
    fn retired_holes_and_high_indices_are_preserved() {
        for size in INSERTION_SIZES {
            // A retired (zeroed) leaf below the cursor stays zero in new_root.
            let mut tree = MerkleTree::new();
            for id in 0..size as u32 {
                tree.set_leaf(id, felt(note(id).leaf(id)));
            }
            tree.set_leaf(0, Felt252::ZERO);
            let circuit = batch(&tree, size as u32, size);
            let mut expected = tree.clone();
            for (offset, inserted) in circuit.public.notes.iter().enumerate() {
                let id = size as u32 + offset as u32;
                expected.set_leaf(id, felt(inserted.leaf(id)));
            }
            assert_eq!(circuit.public.new_root, field(&expected.root()));
            assert!(satisfied(circuit));
            // The last aligned range of the 32-bit tree.
            let first = u32::MAX - size as u32 + 1;
            let notes: Vec<_> = (0..size).map(|j| note(j as u32)).collect();
            let siblings: [CircuitField; REQUEST_MERKLE_DEPTH] =
                std::array::from_fn(|level| CircuitField::from(800 + level as u64));
            let (old_root, new_root) = insertion_roots(first, &notes, &siblings);
            assert!(satisfied(InsertionCircuit {
                public: InsertionPublic {
                    old_root,
                    new_root,
                    first_note_id: first,
                    notes,
                },
                witness: InsertionWitness { siblings },
            }));
        }
    }

    #[test]
    fn statement_shapes_fit_the_2_15_domain() {
        for size in INSERTION_SIZES {
            let cs = synthesize(InsertionCircuit::template(size), SynthesisMode::Setup).unwrap();
            assert_eq!(
                cs.num_instance_variables() - 1,
                insertion_public_inputs(size)
            );
            let rows = cs.num_constraints() + cs.num_instance_variables();
            assert!(rows <= 1 << 15, "K={size}: {rows} rows");
        }
    }
}
