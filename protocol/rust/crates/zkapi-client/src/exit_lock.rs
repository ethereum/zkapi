//! `exit_lock.json` (design §6.2, §6.3 C3, §6.4 E6).
//!
//! The lock is written durably before any exit proof is generated, and each
//! proof is appended to `released` before it leaves the process. While the
//! lock is held the wallet creates no request proof (C3), and only the
//! lock's own mode's proofs at the lock's state:
//! - `mutual`: at most one live kind-2 ownership proof, plus kind-1 closes;
//! - `escape`: kind-0 escapes conceding at most `bound_at_state`.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use zkapi_types::wire::ClearanceOwnershipProofV2C;
use zkapi_types::Felt252;

use crate::error::ClientError;
use crate::exit_policy::ReleasedExit;

pub const EXIT_LOCK_FILE: &str = "exit_lock.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExitMode {
    Mutual,
    Escape,
}

/// One exit proof that left, or may have left, the process.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleasedProof {
    /// 0 escape, 1 mutual close, 2 ownership proof.
    pub kind: u8,
    pub valid_until: u64,
    pub conceded: u128,
    /// The transaction that carried it, once one is known.
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "txHash")]
    pub tx_hash: Option<String>,
    /// A kind-2 proof is kept so a clearance retry resends the same proof
    /// instead of releasing a second one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership: Option<ClearanceOwnershipProofV2C>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExitLock {
    pub version: u8,
    #[serde(rename = "noteId")]
    pub note_id: u32,
    /// The anchor of the state the lock freezes.
    pub anchor: Felt252,
    pub mode: ExitMode,
    /// When the lock was first set (seconds).
    pub since: u64,
    pub released: Vec<ReleasedProof>,
}

impl ExitLock {
    pub fn new(note_id: u32, anchor: Felt252, mode: ExitMode, since: u64) -> Self {
        Self {
            version: 1,
            note_id,
            anchor,
            mode,
            since,
            released: Vec::new(),
        }
    }

    /// Whether a kind-0 escape or kind-1 close was ever released under it.
    pub fn exit_released(&self) -> bool {
        self.released.iter().any(|proof| proof.kind <= 1)
    }

    /// Whether a kind-0 escape was ever released under it.
    pub fn escape_released(&self) -> bool {
        self.released.iter().any(|proof| proof.kind == 0)
    }

    /// The released proofs as E6 sees them.
    pub fn released_exits(&self) -> Vec<ReleasedExit> {
        self.released
            .iter()
            .map(|proof| ReleasedExit {
                kind: proof.kind,
                valid_until: proof.valid_until,
            })
            .collect()
    }

    /// The kind-2 ownership proof still valid at `now + margin`, if one was
    /// released and kept.
    pub fn live_ownership_proof(
        &self,
        now: u64,
        margin: u64,
    ) -> Option<&ClearanceOwnershipProofV2C> {
        self.released
            .iter()
            .filter(|proof| proof.kind == 2 && proof.valid_until > now.saturating_add(margin))
            .find_map(|proof| proof.ownership.as_ref())
    }

    /// Whether a kind-2 proof released under it may still be accepted at
    /// `now` by the server.
    pub fn ownership_proof_live(&self, now: u64) -> bool {
        self.released
            .iter()
            .any(|proof| proof.kind == 2 && proof.valid_until >= now)
    }

    pub fn load(path: &Path) -> Result<Option<Self>, ClientError> {
        let bytes = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let lock: Self = serde_json::from_slice(&bytes)
            .map_err(|error| ClientError::Serialization(format!("exit_lock.json: {error}")))?;
        if lock.version != 1 {
            return Err(ClientError::Serialization(
                "exit_lock.json has an unknown version".into(),
            ));
        }
        Ok(Some(lock))
    }

    /// Write the lock durably: a crash leaves the old or the new lock.
    pub fn save(&self, path: &Path) -> Result<(), ClientError> {
        let bytes = serde_json::to_vec_pretty(self)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        crate::journal::replace_file_durably(path, &bytes)
    }

    /// Remove the lock durably.
    pub fn remove(path: &Path) -> Result<(), ClientError> {
        crate::journal::remove_file_durably(path)
    }
}
