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

use serde::{Deserialize, Deserializer, Serialize};
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
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "kept_ownership_proof"
    )]
    pub ownership: Option<ClearanceOwnershipProofV2C>,
}

/// A kept ownership proof, or none when it was made for an earlier statement
/// layout (one that proved tree membership at a root): no server accepts it
/// any more, so it is never sent again, while the `valid_until` recorded
/// beside it still holds back a second live proof of the state (C3).
pub(crate) fn kept_ownership_proof<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ClearanceOwnershipProofV2C>, D::Error> {
    Ok(Option::<serde_json::Value>::deserialize(deserializer)?
        .and_then(|kept| serde_json::from_value(kept).ok()))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A lock that kept an ownership proof of the earlier, root-bearing
    /// statement still loads: the proof is dropped, its kind and lifetime
    /// stay for C3 and E6.
    #[test]
    fn a_lock_with_an_earlier_statements_ownership_proof_loads_without_it() {
        let dir = std::env::temp_dir().join(format!("zkapi-exit-lock-{}", uuid::Uuid::new_v4()));
        let path = dir.join(EXIT_LOCK_FILE);
        let rooted = serde_json::json!({
            "public_inputs": {
                "protocol_version": 2, "chain_id": 1, "contract_address": "0x1",
                "active_root": "0x2", "state_signing_key_x": "0x3", "state_signing_key_y": "0x4",
                "clearance_signing_key_x": "0x5", "clearance_signing_key_y": "0x6",
                "note_id": 7, "final_balance": 1000, "destination": vec![0u8; 20],
                "withdrawal_nullifier": "0x7", "kind": 2, "next_nullifier": "0x0",
                "conceded": 0, "valid_until": 2_000_003_600u64
            },
            "proof": {"backend": "groth16_bn254", "proof": "AA=="}
        });
        let lock = serde_json::json!({
            "version": 1, "noteId": 7, "anchor": "0x1", "mode": "mutual", "since": 5,
            "released": [{"kind": 2, "valid_until": 2_000_003_600u64, "conceded": 0, "ownership": rooted}]
        });
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, serde_json::to_vec(&lock).unwrap()).unwrap();
        let loaded = ExitLock::load(&path).unwrap().unwrap();
        assert_eq!(loaded.released.len(), 1);
        assert_eq!(
            (loaded.released[0].kind, loaded.released[0].valid_until),
            (2, 2_000_003_600)
        );
        assert!(loaded.released[0].ownership.is_none());
        assert!(loaded.ownership_proof_live(2_000_000_000));
        assert!(loaded.live_ownership_proof(2_000_000_000, 0).is_none());
        let _ = std::fs::remove_dir_all(dir);
    }
}
