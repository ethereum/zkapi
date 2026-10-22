//! Public input structs for request and withdrawal proofs.
//!
//! Field ordering matches the Groth16 circuits and Solidity Types.sol.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

use crate::Felt252;

/// Public statement verified for every v2 API request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RequestPublicInputsV2 {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub active_root: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: Felt252,
    pub authorization_tag: Felt252,
    pub anonymous_commitment_x: Felt252,
    pub anonymous_commitment_y: Felt252,
}

impl RequestPublicInputsV2 {
    /// Number of public inputs of the request statement.
    pub const NUM_PUBLIC_INPUTS: usize = 12;

    pub fn to_field_elements(&self) -> [Felt252; 12] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key_x,
            self.state_signing_key_y,
            Felt252::from_u64(self.request_time),
            Felt252::from_u128(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment_x,
            self.anonymous_commitment_y,
        ]
    }
}

/// What a withdrawal proof authorizes (public input 12 of the withdrawal
/// statement). The vault accepts only `Escape` in `initiateEscapeWithdrawal`
/// and only `MutualClose` in `mutualClose`; `Ownership` proofs go only to the
/// server's clearance endpoint and are rejected by every vault entry point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WithdrawalKind {
    /// Kind 0: escape. Publishes `next_nullifier` and may concede an amount.
    Escape = 0,
    /// Kind 1: mutual close under a clearance signature. `conceded = 0`.
    MutualClose = 1,
    /// Kind 2: ownership proof for clearance. `destination = 0`, `conceded = 0`.
    Ownership = 2,
}

impl WithdrawalKind {
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Escape),
            1 => Some(Self::MutualClose),
            2 => Some(Self::Ownership),
            _ => None,
        }
    }
}

impl TryFrom<u8> for WithdrawalKind {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::from_u8(value).ok_or_else(|| format!("unknown withdrawal kind {value}"))
    }
}

/// `F = note_id·2^192 + deposit_amount·2^64 + expiry_ts` as a big-endian field element:
/// the withdrawal statement's public input 8 (`noteFields`), which the note leaf binds. Below
/// 2^224, so injective as an integer and as a field element.
pub fn pack_note_fields(note_id: u32, deposit_amount: u128, expiry_ts: u64) -> Felt252 {
    let mut bytes = [0u8; 32];
    bytes[4..8].copy_from_slice(&note_id.to_be_bytes());
    bytes[8..24].copy_from_slice(&deposit_amount.to_be_bytes());
    bytes[24..32].copy_from_slice(&expiry_ts.to_be_bytes());
    Felt252(bytes)
}

/// Public statement of a withdrawal proof for circuit
/// `zkapi-v2-concession-v2`: 16 inputs, in exactly the order of
/// [`Self::to_field_elements`] and of Solidity `Types.WithdrawalPublicInputs`.
///
/// Input 3 is the note's leaf `note_leaf` (the word the vault stores for the note) and input 8
/// is `noteFields` = [`pack_note_fields`]`(note_id, deposit_amount, expiry_ts)`, carried here as
/// its three parts. The proof binds the leaf to the owner's registration and to these fields, and
/// the vault compares the leaf with its own: an exit needs no Merkle path and no root.
///
/// Canonical values: `next_nullifier` is the successor nullifier for kind 0
/// and 0 otherwise; `conceded` is 0 unless kind 0; `destination` is all zero
/// for kind 2. `final_balance + conceded` equals the balance of the state the
/// proof opens. `valid_until` is the last UNIX second at which the vault
/// (kinds 0 and 1) or the server (kind 2) accepts the proof.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WithdrawalPublicInputsV2C {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_leaf: Felt252,
    pub state_signing_key_x: Felt252,
    pub state_signing_key_y: Felt252,
    pub clearance_signing_key_x: Felt252,
    pub clearance_signing_key_y: Felt252,
    pub note_id: u32,
    /// The note's deposit `D` (gwei units), packed into input 8.
    pub deposit_amount: u128,
    /// The note's bucketed expiry `e`, packed into input 8.
    pub expiry_ts: u64,
    pub final_balance: u128,
    pub destination: [u8; 20],
    pub withdrawal_nullifier: Felt252,
    pub kind: u8,
    pub next_nullifier: Felt252,
    pub conceded: u128,
    pub valid_until: u64,
}

impl WithdrawalPublicInputsV2C {
    /// Number of public inputs of the withdrawal statement.
    pub const NUM_PUBLIC_INPUTS: usize = 16;

    /// The 160-bit destination as a field element (left-padded big-endian),
    /// equal to Solidity `uint256(uint160(destination))`.
    pub fn destination_field(&self) -> Felt252 {
        let mut bytes = [0u8; 32];
        bytes[12..].copy_from_slice(&self.destination);
        Felt252(bytes)
    }

    /// Public input 8: `note_id·2^192 + deposit_amount·2^64 + expiry_ts`.
    pub fn note_fields(&self) -> Felt252 {
        pack_note_fields(self.note_id, self.deposit_amount, self.expiry_ts)
    }

    /// The decoded `kind`, or `None` for a value outside {0, 1, 2}.
    pub fn withdrawal_kind(&self) -> Option<WithdrawalKind> {
        WithdrawalKind::from_u8(self.kind)
    }

    /// The public inputs in circuit order (also the ABI word order of the
    /// static Solidity tuple).
    pub fn to_field_elements(&self) -> [Felt252; 16] {
        [
            Felt252::from_u64(self.protocol_version as u64),
            Felt252::from_u64(self.chain_id),
            self.contract_address,
            self.note_leaf,
            self.state_signing_key_x,
            self.state_signing_key_y,
            self.clearance_signing_key_x,
            self.clearance_signing_key_y,
            self.note_fields(),
            Felt252::from_u128(self.final_balance),
            self.destination_field(),
            self.withdrawal_nullifier,
            Felt252::from_u64(self.kind as u64),
            self.next_nullifier,
            Felt252::from_u128(self.conceded),
            Felt252::from_u64(self.valid_until),
        ]
    }
}

/// Hash the exact client request id and payload digest into the private context
/// that the request proof binds through `authorization_tag`.
pub fn canonical_request_context(client_request_id: &str, payload_hash: &Felt252) -> Felt252 {
    let id = client_request_id.as_bytes();
    let mut bytes = Vec::with_capacity(8 + id.len() + 32);
    bytes.extend_from_slice(&(id.len() as u64).to_be_bytes());
    bytes.extend_from_slice(id);
    bytes.extend_from_slice(payload_hash.as_bytes());
    hash_bytes_to_felt(b"zkapi.v2.request-context", &bytes)
}

pub fn canonical_payload_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.payload.v1", payload)
}

pub fn canonical_response_hash(payload: &[u8]) -> Felt252 {
    hash_bytes_to_felt(b"zkapi.response.v1", payload)
}

fn hash_bytes_to_felt(domain: &[u8], payload: &[u8]) -> Felt252 {
    let mut counter = 0u32;
    loop {
        let mut h = Keccak256::new();
        h.update(domain);
        h.update((payload.len() as u64).to_be_bytes());
        h.update(payload);
        h.update(counter.to_be_bytes());
        let digest: [u8; 32] = h.finalize().into();
        if let Ok(felt) = Felt252::try_from_bytes_be(digest) {
            return felt;
        }
        counter = counter
            .checked_add(1)
            .expect("hash-to-felt counter exhausted");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_and_response_hashes_are_domain_separated() {
        let payload = b"{\"ok\":true}";
        assert_eq!(
            canonical_payload_hash(payload),
            canonical_payload_hash(payload)
        );
        assert_eq!(
            canonical_response_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_response_hash(payload)
        );
        assert_ne!(
            canonical_payload_hash(payload),
            canonical_payload_hash(b"other")
        );
    }

    fn sample_withdrawal() -> WithdrawalPublicInputsV2C {
        WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: Felt252::from_u64(1),
            note_leaf: Felt252::from_u64(2),
            state_signing_key_x: Felt252::from_u64(3),
            state_signing_key_y: Felt252::from_u64(4),
            clearance_signing_key_x: Felt252::from_u64(5),
            clearance_signing_key_y: Felt252::from_u64(6),
            note_id: 7,
            deposit_amount: 5_000_000,
            expiry_ts: 4_000_000_000,
            final_balance: 900,
            destination: [0x11; 20],
            withdrawal_nullifier: Felt252::from_u64(8),
            kind: 0,
            next_nullifier: Felt252::from_u64(9),
            conceded: 100,
            valid_until: 2_000_010_800,
        }
    }

    #[test]
    fn withdrawal_field_order_matches_the_statement() {
        let inputs = sample_withdrawal();
        let fields = inputs.to_field_elements();
        assert_eq!(fields.len(), WithdrawalPublicInputsV2C::NUM_PUBLIC_INPUTS);
        assert_eq!(fields[0], Felt252::from_u64(2));
        assert_eq!(fields[3], Felt252::from_u64(2));
        // The design's packing vector (shared with Solidity, JS and Go).
        assert_eq!(
            fields[8],
            Felt252::from_hex("0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800")
                .unwrap()
        );
        assert_eq!(fields[9], Felt252::from_u64(900));
        let mut destination = [0u8; 32];
        destination[12..].fill(0x11);
        assert_eq!(fields[10], Felt252(destination));
        assert_eq!(fields[11], Felt252::from_u64(8));
        assert_eq!(fields[12], Felt252::ZERO);
        assert_eq!(fields[13], Felt252::from_u64(9));
        assert_eq!(fields[14], Felt252::from_u64(100));
        assert_eq!(fields[15], Felt252::from_u64(2_000_010_800));
    }

    #[test]
    fn withdrawal_inputs_are_strict_json() {
        let inputs = sample_withdrawal();
        let value = serde_json::to_value(&inputs).unwrap();
        let keys: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        assert_eq!(keys.len(), 18);
        assert!(keys.contains(&"note_leaf".to_string()));
        assert_eq!(
            serde_json::from_value::<WithdrawalPublicInputsV2C>(value.clone()).unwrap(),
            inputs
        );
        let mut legacy = value.clone();
        legacy["has_clearance"] = false.into();
        assert!(serde_json::from_value::<WithdrawalPublicInputsV2C>(legacy).is_err());
        // A zkapi-v2-concession-v1 statement (active_root, no deposit or expiry) is refused.
        let mut v1 = value.clone();
        let object = v1.as_object_mut().unwrap();
        let leaf = object.remove("note_leaf").unwrap();
        object.insert("active_root".into(), leaf);
        object.remove("deposit_amount");
        object.remove("expiry_ts");
        assert!(serde_json::from_value::<WithdrawalPublicInputsV2C>(v1).is_err());
        let mut both = value.clone();
        both["active_root"] = "0x2".into();
        assert!(serde_json::from_value::<WithdrawalPublicInputsV2C>(both).is_err());
        let mut missing = value;
        missing.as_object_mut().unwrap().remove("valid_until");
        assert!(serde_json::from_value::<WithdrawalPublicInputsV2C>(missing).is_err());
    }

    #[test]
    fn note_fields_pack_without_overlap() {
        let max = pack_note_fields(u32::MAX, u128::MAX, u64::MAX);
        assert_eq!(max.as_bytes()[..4], [0u8; 4]);
        assert!(max.as_bytes()[4..].iter().all(|byte| *byte == 0xff));
        assert_eq!(
            pack_note_fields(1, 0, 0).as_bytes()[7],
            1,
            "note_id starts at bit 192"
        );
        assert_eq!(
            pack_note_fields(0, 1, 0).as_bytes()[23],
            1,
            "deposit at bit 64"
        );
        assert_eq!(
            pack_note_fields(0, 0, 1).as_bytes()[31],
            1,
            "expiry at bit 0"
        );
    }

    #[test]
    fn withdrawal_kinds_round_trip() {
        for kind in [
            WithdrawalKind::Escape,
            WithdrawalKind::MutualClose,
            WithdrawalKind::Ownership,
        ] {
            assert_eq!(WithdrawalKind::try_from(kind.as_u8()), Ok(kind));
        }
        assert!(WithdrawalKind::try_from(3).is_err());
        let mut inputs = sample_withdrawal();
        inputs.kind = 2;
        assert_eq!(inputs.withdrawal_kind(), Some(WithdrawalKind::Ownership));
        inputs.kind = 3;
        assert_eq!(inputs.withdrawal_kind(), None);
    }
}
