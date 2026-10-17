//! The note-activation fixtures of `solidity_fixture.rs` and
//! `vault_challenge_fixture.rs`: a proved insertion statement with what a
//! Solidity test needs to activate its notes, with the proof
//! (`activateNotes(first_note_id, count, old_root, new_root, proof)`, or the
//! adapter's `assertValidInsertion(count, inputs, proof)`) or without it
//! (`activateNotesOnChain(first_note_id, count, siblings)`).
use anyhow::{ensure, Context, Result};
use base64::Engine;
use serde::Serialize;
use zkapi_core::v2 as core;
use zkapi_core::MerkleTree;
use zkapi_proof::compact::{InsertionProver, InsertionVerifier};
use zkapi_proof::dev::DevNote;
use zkapi_proof::insertion::{
    insertion_roots, InsertedNote, InsertionPublic, InsertionWitness, INSERTION_SIZES,
};
use zkapi_types::Felt252;

/// A whole 32-byte word: `0x` and 64 hex digits, which Forge's
/// `parseJsonBytes32` and `parseJsonUint` both read.
pub fn word(value: &Felt252) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

/// What the vault stores for a note (`notes(noteId)`), and its leaf.
#[derive(Serialize)]
pub struct StoredNote {
    pub note_id: u32,
    pub registration_commitment: String,
    pub deposit_amount: u128,
    pub expiry: u64,
    /// `deposit_amount + expiry · 2^128`, the statements' packed note values.
    pub metadata: String,
    pub leaf: String,
}

impl StoredNote {
    pub fn of(note: &DevNote) -> Self {
        Self {
            note_id: note.note_id,
            registration_commitment: word(&note.registration()),
            deposit_amount: note.deposit_amount,
            expiry: note.expiry,
            metadata: word(&zkapi_types::inputs::note_metadata(
                note.deposit_amount,
                note.expiry,
            )),
            leaf: word(&note.leaf()),
        }
    }
}

/// One proved activation of `count` notes at cursor `first_note_id`.
#[derive(Serialize)]
pub struct ActivationFixture {
    pub first_note_id: u32,
    pub count: usize,
    pub old_root: String,
    pub new_root: String,
    pub notes: Vec<StoredNote>,
    /// The 32 siblings of slot `first_note_id` in the tree before the
    /// activation, bottom up (those below the batch's subtree are unused).
    pub siblings: Vec<String>,
    /// The `3 + 2K` public inputs, as the vault builds them:
    /// `[old_root, new_root, first_note_id, C_0, M_0, ...]`.
    pub inputs: Vec<String>,
    /// The same inputs as consecutive 32-byte words.
    pub inputs_abi: String,
    pub proof_hex: String,
}

/// The insertion provers and verifiers of a setup, one per batch size.
pub struct Activator {
    keys: Vec<(InsertionProver, InsertionVerifier)>,
}

impl Activator {
    pub fn load(setup: &str) -> Result<Self> {
        let keys = INSERTION_SIZES
            .iter()
            .map(|size| {
                Ok((
                    InsertionProver::load(setup, *size)?,
                    InsertionVerifier::load(setup, *size)?,
                ))
            })
            .collect::<Result<_>>()?;
        Ok(Self { keys })
    }

    /// Prove the activation of `notes` (consecutive ids from the first) in
    /// `tree`, check the proof, and add their leaves to `tree`.
    pub fn activate(&self, tree: &mut MerkleTree, notes: &[DevNote]) -> Result<ActivationFixture> {
        let first_note_id = notes.first().context("no notes to activate")?.note_id;
        let index = INSERTION_SIZES
            .iter()
            .position(|size| *size == notes.len())
            .with_context(|| format!("no insertion circuit for {} notes", notes.len()))?;
        let (prover, verifier) = &self.keys[index];
        let siblings = tree.get_siblings(first_note_id);
        let witness = InsertionWitness {
            siblings: siblings.map(|value| core::felt_to_field(&value)),
        };
        let stored: Vec<InsertedNote> = notes
            .iter()
            .map(|note| InsertedNote {
                registration_commitment: core::felt_to_field(&note.registration()),
                deposit_amount: note.deposit_amount,
                expiry: note.expiry,
            })
            .collect();
        let (old_root, new_root) = insertion_roots(first_note_id, &stored, &witness.siblings);
        let public = InsertionPublic {
            old_root,
            new_root,
            first_note_id,
            notes: stored,
        };
        let proof = prover.prove(&public, &witness)?;
        ensure!(verifier.verify(&public, &proof)?, "insertion proof failed");
        ensure!(
            core::field_to_felt(&old_root) == tree.root(),
            "the empty slots do not hash to the tree's root"
        );
        for note in notes {
            tree.set_leaf(note.note_id, note.leaf());
        }
        ensure!(
            core::field_to_felt(&new_root) == tree.root(),
            "the activation does not reach the tree with the notes"
        );
        let inputs: Vec<Felt252> = public
            .to_field_elements()
            .iter()
            .map(core::field_to_felt)
            .collect();
        let proof = base64::engine::general_purpose::STANDARD
            .decode(&proof.proof)
            .context("decode proof")?;
        Ok(ActivationFixture {
            first_note_id,
            count: notes.len(),
            old_root: word(&core::field_to_felt(&old_root)),
            new_root: word(&core::field_to_felt(&new_root)),
            notes: notes.iter().map(StoredNote::of).collect(),
            siblings: siblings.iter().map(word).collect(),
            inputs: inputs.iter().map(word).collect(),
            inputs_abi: format!(
                "0x{}",
                inputs
                    .iter()
                    .map(|input| hex::encode(input.as_bytes()))
                    .collect::<String>()
            ),
            proof_hex: format!("0x{}", hex::encode(proof)),
        })
    }
}
