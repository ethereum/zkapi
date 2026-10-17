//! Client private state per spec section 5.2.
//!
//! Each active note is represented by a `NoteState` struct that tracks the
//! current balance, blinding factor, commitment, anchor, and server-issued
//! state signature. The state is persisted atomically to disk so that the
//! wallet can always recover to a consistent point after a crash.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use zkapi_types::inputs::note_metadata;
use zkapi_types::{Felt252, SchnorrSignature};

use crate::error::ClientError;

/// Client-side private state for a single note.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NoteState {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    /// Blinding factor serialized as 0x-prefixed lowercase hex.
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    /// The anchor of the state whose request produced this one. The request
    /// circuit checks `current_anchor == next_anchor(nullifier(s, n, prev))`
    /// for every signed state, so a signed state without it cannot prove a
    /// request (`ClientError::PrevAnchorMissing`). Exits never need it.
    /// `None` at genesis and in state files written before it existed.
    #[serde(default)]
    pub prev_anchor: Option<Felt252>,
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
    /// C2 (design §6.2): the one `solvency_bound` every request proof at
    /// this state carries. 0 until the first request proof at the state is
    /// prepared, and reset to 0 by every install. A raise of an escape from
    /// this state can never take more than it.
    #[serde(default)]
    pub bound_at_state: u128,
    /// Installs since the deposit (0 at genesis); an exit kit records the
    /// state it was exported at.
    #[serde(default)]
    pub state_seq: u64,
}

/// What the vault's `notes(noteId)` records for a note, its status aside:
/// the registration commitment `C`, the deposit amount and the expiry. Every
/// exit statement names the note by `C` and the packed amount and expiry
/// ([`RecordedNote::note_metadata`]), and the vault refuses one that differs
/// from its record, so exits need no Merkle path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordedNote {
    pub registration_commitment: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
}

impl RecordedNote {
    /// `deposit_amount + expiry_ts · 2^128`, the vault's packed metadata.
    pub fn note_metadata(&self) -> Felt252 {
        note_metadata(self.deposit_amount, self.expiry_ts)
    }
}

impl NoteState {
    /// Create genesis state after a successful on-chain deposit.
    ///
    /// The initial balance equals the deposit amount, the anchor is 1 (genesis),
    /// and no state signature exists yet.
    #[allow(clippy::too_many_arguments)]
    pub fn new_from_deposit(
        protocol_version: u16,
        chain_id: u64,
        contract_address: Felt252,
        note_id: u32,
        secret_s: Felt252,
        deposit_amount: u128,
        expiry_ts: u64,
        balance_blinding: String,
        commitment_x: Felt252,
        commitment_y: Felt252,
    ) -> Self {
        Self {
            protocol_version,
            chain_id,
            contract_address,
            note_id,
            secret_s,
            deposit_amount,
            expiry_ts,
            current_balance: deposit_amount,
            balance_blinding,
            current_commitment_x: commitment_x,
            current_commitment_y: commitment_y,
            current_anchor: Felt252::ONE, // genesis anchor
            prev_anchor: None,
            is_genesis: true,
            state_signature: None,
            bound_at_state: 0,
            state_seq: 0,
        }
    }

    /// What the vault must record under `note_id` for this note's exits to
    /// verify.
    pub fn recorded_note(&self) -> RecordedNote {
        RecordedNote {
            registration_commitment: zkapi_core::v2::registration_commitment(&self.secret_s),
            deposit_amount: self.deposit_amount,
            expiry_ts: self.expiry_ts,
        }
    }

    /// Compute the solvency bound that the proof must commit to.
    ///
    /// Per spec section 8.2 constraint 9:
    /// - When policy is disabled: `solvency_bound = request_charge_cap`
    /// - When policy is enabled: `solvency_bound = policy_charge_cap`
    pub fn solvency_bound(&self, policy_enabled: bool, charge_cap: u128, policy_cap: u128) -> u128 {
        if policy_enabled {
            policy_cap
        } else {
            charge_cap
        }
    }

    /// Persist the state atomically and durably: it is written and synced
    /// under a temporary name, renamed into the target path, and the rename
    /// is synced before this returns. A crash at any point, including a power
    /// loss, leaves either the old state or the complete new state on disk,
    /// so a request journal cleared afterwards never outlives the state it
    /// was installed into.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| ClientError::Serialization(e.to_string()))?;

        // Ensure parent directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        crate::journal::replace_file_durably(path, json.as_bytes())
    }

    /// Load state from a JSON file on disk.
    pub fn load(path: &Path) -> Result<Self, ClientError> {
        let data = fs::read_to_string(path)?;
        serde_json::from_str(&data).map_err(|e| ClientError::Serialization(e.to_string()))
    }

    /// Archive the state file by moving it into an `archive/` subdirectory
    /// alongside the original path, with a filename that includes the note id.
    /// This is called after a successful close or withdrawal.
    pub fn archive(&self, path: &Path) -> Result<(), ClientError> {
        let parent = path.parent().unwrap_or(Path::new("."));
        let archive_dir = parent.join("archive");
        fs::create_dir_all(&archive_dir)?;
        // The archive directory's entry is durable before the active file
        // can be removed.
        crate::journal::sync_parent(&archive_dir)?;

        let filename = format!("note_{}_closed.json", self.note_id);
        let archive_path = archive_dir.join(filename);

        // Save a copy to the archive, then remove the active state file.
        self.save(&archive_path)?;
        if path.exists() {
            fs::remove_file(path)?;
            crate::journal::sync_parent(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("zkapi_notestate_{}", name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_new_from_deposit_genesis() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            0,
            Felt252::from_u64(42),
            1000,
            1700000000,
            "0x2a".to_string(),
            Felt252::from_u64(1),
            Felt252::from_u64(2),
        );
        assert!(state.is_genesis);
        assert_eq!(state.current_balance, 1000);
        assert_eq!(state.current_anchor, Felt252::ONE);
        assert!(state.prev_anchor.is_none());
        assert!(state.state_signature.is_none());
    }

    /// A state file written before `bound_at_state` and `state_seq` existed
    /// loads with no bound and sequence 0.
    #[test]
    fn a_state_file_without_the_concession_fields_loads_with_defaults() {
        let dir = test_dir("no_concession_fields");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        let mut value = serde_json::to_value(&state).unwrap();
        for field in ["bound_at_state", "state_seq"] {
            value.as_object_mut().unwrap().remove(field);
        }
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.bound_at_state, 0);
        assert_eq!(loaded.state_seq, 0);
    }

    /// A state file (or an exit kit's note) written while exits proved tree
    /// membership still loads: the deposit-time path it carries is ignored,
    /// and saving the state drops it.
    #[test]
    fn a_state_file_with_a_deposit_path_loads_and_drops_it() {
        let dir = test_dir("deposit_path");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        let mut value = serde_json::to_value(&state).unwrap();
        value["deposit_path"] = serde_json::json!({
            "root": "0x5",
            "siblings": vec!["0x0"; zkapi_types::MERKLE_DEPTH],
        });
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.note_id, 7);
        assert_eq!(loaded.recorded_note(), state.recorded_note());
        loaded.save(&path).unwrap();
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        assert!(saved.get("deposit_path").is_none());
    }

    /// The vault's record of a note: `C = H_reg(s)` and the amount and
    /// expiry, packed as the withdrawal statement's input 16.
    #[test]
    fn the_recorded_note_packs_amount_and_expiry() {
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        let recorded = state.recorded_note();
        assert_eq!(
            recorded.registration_commitment,
            zkapi_core::v2::registration_commitment(&Felt252::from_u64(42))
        );
        assert_eq!(
            (recorded.deposit_amount, recorded.expiry_ts),
            (5000, 1700000000)
        );
        let mut packed = [0u8; 32];
        packed[8..16].copy_from_slice(&1700000000u64.to_be_bytes());
        packed[16..32].copy_from_slice(&5000u128.to_be_bytes());
        assert_eq!(recorded.note_metadata(), Felt252(packed));
    }

    /// A state file written before `prev_anchor` existed still loads; its
    /// predecessor anchor is unknown.
    #[test]
    fn a_state_file_without_prev_anchor_loads_with_none() {
        let dir = test_dir("no_prev_anchor");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        let mut value = serde_json::to_value(&state).unwrap();
        value.as_object_mut().unwrap().remove("prev_anchor");
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert!(loaded.prev_anchor.is_none());
        assert_eq!(loaded.note_id, 7);
    }

    #[test]
    fn test_solvency_bound_policy_disabled() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            0,
            Felt252::from_u64(1),
            1000,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        assert_eq!(state.solvency_bound(false, 100, 50), 100);
    }

    #[test]
    fn test_solvency_bound_policy_enabled() {
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            0,
            Felt252::from_u64(1),
            1000,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        assert_eq!(state.solvency_bound(true, 100, 50), 50);
    }

    #[test]
    fn test_save_and_load_roundtrip() {
        let dir = test_dir("save_load");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::from_u64(0xdead),
            7,
            Felt252::from_u64(42),
            5000,
            1700000000,
            "0xff".to_string(),
            Felt252::from_u64(10),
            Felt252::from_u64(20),
        );
        state.save(&path).unwrap();
        let loaded = NoteState::load(&path).unwrap();
        assert_eq!(loaded.note_id, 7);
        assert_eq!(loaded.current_balance, 5000);
        assert_eq!(loaded.balance_blinding, "0xff");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    /// The state's contents and its new name are synced before `save`
    /// returns: a power loss could otherwise leave an empty state file, or
    /// the old state beside a journal already cleared for the new one.
    #[test]
    fn saved_state_is_durable_before_save_returns() {
        let dir = test_dir("durable");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            4,
            Felt252::from_u64(1),
            100,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        crate::journal::durability::take();
        state.save(&path).unwrap();
        assert_eq!(
            crate::journal::durability::take(),
            [("file", dir.join("note_state.tmp")), ("dir", dir.clone())]
        );
        state.archive(&path).unwrap();
        let archive = dir.join("archive");
        assert_eq!(
            crate::journal::durability::take(),
            [
                ("dir", dir.clone()),
                ("file", archive.join("note_4_closed.tmp")),
                ("dir", archive.clone()),
                ("dir", dir.clone())
            ]
        );
    }

    #[test]
    fn test_archive() {
        let dir = test_dir("archive");
        let path = dir.join("note_state.json");
        let state = NoteState::new_from_deposit(
            1,
            1,
            Felt252::ZERO,
            3,
            Felt252::from_u64(1),
            100,
            0,
            "0x0".into(),
            Felt252::ZERO,
            Felt252::ZERO,
        );
        state.save(&path).unwrap();
        assert!(path.exists());

        state.archive(&path).unwrap();
        assert!(!path.exists());
        let archived = dir.join("archive").join("note_3_closed.json");
        assert!(archived.exists());
    }
}
