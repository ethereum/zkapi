//! Challenge evidence and the vault calls of the concession-exit challenger
//! (§5.4).
//!
//! An escape from state `S_k` names `N = N_k` and `N⁺ = N_{k+1}`. Only a
//! request proof at `N⁺` defeats it (`challengeEscapeWithdrawal`); a request
//! proof at `N` can only raise its concession (`raiseEscapeConcession`) to
//! `min(amount, proof.solvencyBound, stateBalance)`. Evidence is the server's
//! append-only `request_evidence` table: every proof the server accepted,
//! written in the reservation's transaction (O2), whatever became of the
//! lease. Each row is re-verified here (Groth16, nullifier, deployment and
//! state key) before it builds calldata.
//!
//! `Ω(N)`, the amount owed for the request at the escaped nullifier, comes
//! from its `nullifiers` row and lease row (`ChallengeWatcher::owed`):
//!
//! | Row at `N` | Ω |
//! |---|---|
//! | `Finalized` | `charge_applied` |
//! | `exit_deferred`, `ExitedUnsigned`, or `Reserved` with `settled_charge` | `settled_charge` |
//! | `Reserved`, possibly delivered, unsettled | `solvency_bound` (from `deadline − raise_lead`) |
//! | `Reserved`, never issued or delivered; no lease row; `ClearanceReserved`; no row | 0 |

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalPublicInputsV2C, MERKLE_DEPTH};

use crate::error::ServerError;
use crate::nullifier_store::{
    DeploymentBinding, NullifierStatus, NullifierStore, RequestEvidence, TranscriptRecord,
};

/// `challengeEscapeWithdrawal(uint32 noteId, RequestPublicInputs inputs,
/// bytes proof)`: the defeat, by a request proof at the successor nullifier.
pub const DEFEAT_SIGNATURE: &str = "challengeEscapeWithdrawal(uint32,(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256),bytes)";
pub const DEFEAT_SELECTOR: [u8; 4] = [0xda, 0x0c, 0xe4, 0x3d];
/// `raiseEscapeConcession(uint32 noteId, RequestPublicInputs inputs, bytes
/// proof, uint128 amount)`: the raise, by a request proof at the escaped
/// nullifier.
pub const RAISE_SIGNATURE: &str = "raiseEscapeConcession(uint32,(uint16,uint64,address,uint256,uint256,uint256,uint64,uint128,uint256,uint256,uint256,uint256),bytes,uint128)";
pub const RAISE_SELECTOR: [u8; 4] = [0xdd, 0x00, 0x64, 0xba];
/// `retireClosedLeaf(uint32 noteId, uint256[32] siblings)`.
pub const RETIRE_SIGNATURE: &str = "retireClosedLeaf(uint32,uint256[32])";
pub const RETIRE_SELECTOR: [u8; 4] = [0xe4, 0x1f, 0x4c, 0x31];
/// `initiateEscapeWithdrawal(WithdrawalPublicInputs inputs, bytes proof)`.
pub const ESCAPE_SIGNATURE: &str = "initiateEscapeWithdrawal((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64),bytes)";
pub const ESCAPE_SELECTOR: [u8; 4] = [0xa3, 0x8d, 0x62, 0xaa];
/// `mutualClose(WithdrawalPublicInputs inputs, bytes proof)`.
pub const MUTUAL_CLOSE_SIGNATURE: &str = "mutualClose((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64),bytes)";
pub const MUTUAL_CLOSE_SELECTOR: [u8; 4] = [0x72, 0xcd, 0x2e, 0x44];
/// Calldata lengths of the vault calls (§4.2-§4.5).
pub const DEFEAT_CALLDATA_LEN: usize = 740;
pub const RAISE_CALLDATA_LEN: usize = 772;
pub const RETIRE_CALLDATA_LEN: usize = 1_060;
pub const WITHDRAWAL_CALLDATA_LEN: usize = 836;
/// A Groth16 proof: eight big-endian 32-byte coordinates.
pub const PROOF_LEN: usize = 256;

/// Server-written lease errors shown on the operator status are bounded.
const MAX_LAST_ERROR_CHARS: usize = 256;

/// Settlement progress of a Reserved request, for operator status only. It
/// deliberately carries no client request ID: the nullifier already
/// correlates with the server, and status must not link note and request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SettlementProgress {
    pub reservation_kind: String,
    pub reserved_at: u64,
    /// None: there is no lease row, so issuance never completed.
    pub lease_status: Option<String>,
    pub key_issued: bool,
    /// The key was returned to the client, or may have been
    /// (`delivered != Some(false)`).
    #[serde(default)]
    pub possibly_delivered: bool,
    pub key_source: Option<String>,
    pub expires_at: Option<u64>,
    /// Server time at which settlement is next due.
    pub settle_after: Option<u64>,
    /// Write-once server deadline by which the lease's charge is final, at
    /// the worst-case charge if needed; None until the server assigns one.
    #[serde(default)]
    pub settlement_deadline_at: Option<u64>,
    pub last_error: Option<String>,
    /// The lease row exists but could not be read; the server's settlement
    /// scan cannot read it either, so it may never settle.
    pub lease_read_error: Option<String>,
}

impl SettlementProgress {
    /// Latest server time by which the charge is expected to be final: the
    /// write-once settlement deadline when assigned, else the next scheduled
    /// settlement.
    pub fn evidence_expected_by(&self) -> Option<u64> {
        self.settlement_deadline_at.or(self.settle_after)
    }
}

/// The deployment every evidence row must name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EvidenceBinding {
    pub chain_id: u64,
    pub contract_address: Felt252,
    /// The vault's immutable state signing key.
    pub state_key: (Felt252, Felt252),
}

/// A request proof from `request_evidence` that verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvidenceProof {
    pub row_id: i64,
    pub inputs: RequestPublicInputsV2,
    /// The 256-byte Groth16 proof.
    pub proof: Vec<u8>,
    /// Server time of the row (its reservation, or a `--rebind`).
    pub created_at: u64,
    /// "reserve" or "rebind".
    pub source: String,
}

/// The evidence rows at one nullifier.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvidenceSet {
    /// Rows that verified, oldest first.
    pub verified: Vec<EvidenceProof>,
    /// Why the other rows were rejected.
    pub rejected: Vec<String>,
}

impl EvidenceSet {
    /// No row at all at the nullifier.
    pub fn is_empty(&self) -> bool {
        self.verified.is_empty() && self.rejected.is_empty()
    }

    /// The oldest verified row: the defeat evidence, so that every attempt
    /// on a nonce carries the same proof.
    pub fn earliest(&self) -> Option<&EvidenceProof> {
        self.verified.first()
    }

    /// The verified row with the largest solvency bound (the oldest among
    /// equals): the raise evidence, which lets the vault concede the most.
    pub fn max_bound(&self) -> Option<&EvidenceProof> {
        self.verified
            .iter()
            .rev()
            .max_by_key(|evidence| evidence.inputs.solvency_bound)
    }

    /// A verified row existed before `deadline` (server time).
    pub fn existed_before(&self, deadline: u64) -> bool {
        self.verified
            .iter()
            .any(|evidence| evidence.created_at < deadline)
    }
}

/// Why `Ω` is what it is (see the module table).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OwedBasis {
    /// The charge is final: a Finalized transcript's `charge_applied`, or the
    /// `settled_charge` of a settled request whose successor is unsigned
    /// (deferred or `ExitedUnsigned`).
    Settled { charge: u128 },
    /// A request that may have been delivered and has not settled. From
    /// `deadline − raise_lead_seconds`, Ω is its solvency bound.
    Unsettled,
    /// Nothing is owed.
    Nothing(NothingOwed),
}

/// Why nothing is owed at the escaped nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NothingOwed {
    /// No row at the nullifier.
    NoRequest,
    /// Reserved only for a withdrawal clearance.
    Clearance,
    /// A reservation of another kind than a lease.
    NotALease,
    /// A reservation whose lease row was never written.
    NoLeaseRow,
    /// The lease's key was never issued, or never returned to the client.
    NeverDelivered,
}

impl NothingOwed {
    pub fn reason(self) -> &'static str {
        match self {
            Self::NoRequest => "no request at the escaped nullifier",
            Self::Clearance => "the escaped nullifier is reserved only for a withdrawal clearance",
            Self::NotALease => "the reservation at the escaped nullifier has no lease",
            Self::NoLeaseRow => "the reservation has no lease row; issuance never completed",
            Self::NeverDelivered => "the lease's key was never issued or never delivered",
        }
    }
}

/// `Ω(N)` and the settlement it follows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Owed {
    pub basis: OwedBasis,
    pub settlement: Option<SettlementProgress>,
}

/// The kind of a vault call on the challenger's nonce lane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallKind {
    Defeat,
    Raise,
    Retire,
}

impl CallKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Defeat => "defeat",
            Self::Raise => "raise",
            Self::Retire => "retire",
        }
    }
}

/// A vault transaction of the challenger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultCall {
    /// `challengeEscapeWithdrawal(noteId, inputs, proof)` with evidence at
    /// the escape's successor nullifier.
    Defeat {
        note_id: u32,
        inputs: RequestPublicInputsV2,
        proof: Vec<u8>,
    },
    /// `raiseEscapeConcession(noteId, inputs, proof, amount)` with evidence
    /// at the escaped nullifier.
    Raise {
        note_id: u32,
        inputs: RequestPublicInputsV2,
        proof: Vec<u8>,
        amount: u128,
    },
    /// `retireClosedLeaf(noteId, siblings)` after a missed defeat.
    Retire {
        note_id: u32,
        siblings: Box<[Felt252; MERKLE_DEPTH]>,
    },
}

impl VaultCall {
    pub fn kind(&self) -> CallKind {
        match self {
            Self::Defeat { .. } => CallKind::Defeat,
            Self::Raise { .. } => CallKind::Raise,
            Self::Retire { .. } => CallKind::Retire,
        }
    }

    pub fn note_id(&self) -> u32 {
        match self {
            Self::Defeat { note_id, .. }
            | Self::Raise { note_id, .. }
            | Self::Retire { note_id, .. } => *note_id,
        }
    }

    /// The exact calldata, or why it cannot be built.
    pub fn calldata(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Defeat {
                note_id,
                inputs,
                proof,
            } => defeat_calldata(*note_id, inputs, proof),
            Self::Raise {
                note_id,
                inputs,
                proof,
                amount,
            } => raise_calldata(*note_id, inputs, proof, *amount),
            Self::Retire { note_id, siblings } => Ok(retire_calldata(*note_id, siblings)),
        }
    }

    /// What every attempt on one nonce must keep. A defeat's digest is the
    /// pre-concession challenge digest (note, request inputs, proof); a
    /// raise's adds its amount under its own domain; a retirement's names
    /// the note only, since its siblings follow the root.
    pub fn digest(&self) -> String {
        let mut digest = Keccak256::new();
        match self {
            Self::Defeat {
                note_id,
                inputs,
                proof,
            } => {
                digest.update(b"zkapi:v2:challenge-evidence\0");
                digest.update(note_id.to_be_bytes());
                for value in inputs.to_field_elements() {
                    digest.update(value.as_bytes());
                }
                digest.update(proof);
            }
            Self::Raise {
                note_id,
                inputs,
                proof,
                amount,
            } => {
                digest.update(b"zkapi:v2c:raise-evidence\0");
                digest.update(note_id.to_be_bytes());
                for value in inputs.to_field_elements() {
                    digest.update(value.as_bytes());
                }
                digest.update(proof);
                digest.update(amount.to_be_bytes());
            }
            Self::Retire { note_id, .. } => {
                digest.update(b"zkapi:v2c:retire-leaf\0");
                digest.update(note_id.to_be_bytes());
            }
        }
        format!("0x{}", hex::encode(digest.finalize()))
    }
}

fn canonical(value: &Felt252, name: &str) -> Result<(), String> {
    Felt252::try_from_bytes_be(*value.as_bytes())
        .map(|_| ())
        .map_err(|_| format!("{name} is not a BN254 field element"))
}

/// The 20-byte address in a felt, which must have 12 zero high bytes.
fn address_word(value: &Felt252, name: &str) -> Result<(), String> {
    if value.as_bytes()[..12].iter().any(|byte| *byte != 0) {
        return Err(format!("{name} exceeds 20 bytes"));
    }
    Ok(())
}

/// The 12 words of a request tuple, checked: protocol version 2, a 20-byte
/// contract and canonical field elements.
fn request_words(inputs: &RequestPublicInputsV2) -> Result<[Felt252; 12], String> {
    if inputs.protocol_version != 2 {
        return Err("unsupported request protocol version".into());
    }
    address_word(&inputs.contract_address, "request contract address")?;
    for (value, name) in [
        (&inputs.active_root, "active root"),
        (&inputs.state_signing_key_x, "state signing key x"),
        (&inputs.state_signing_key_y, "state signing key y"),
        (&inputs.request_nullifier, "request nullifier"),
        (&inputs.authorization_tag, "authorization tag"),
        (&inputs.anonymous_commitment_x, "anonymous commitment x"),
        (&inputs.anonymous_commitment_y, "anonymous commitment y"),
    ] {
        canonical(value, name)?;
    }
    Ok(inputs.to_field_elements())
}

fn proof_bytes(proof: &[u8]) -> Result<(), String> {
    if proof.len() != PROOF_LEN {
        return Err("a Groth16 proof must contain eight 32-byte coordinates".into());
    }
    Ok(())
}

/// `challengeEscapeWithdrawal` calldata: `selector | noteId | 12 tuple words
/// | offset 0x1c0 | len 256 | 8 proof words`, 740 bytes.
pub fn defeat_calldata(
    note_id: u32,
    inputs: &RequestPublicInputsV2,
    proof: &[u8],
) -> Result<Vec<u8>, String> {
    let words = request_words(inputs)?;
    proof_bytes(proof)?;
    let mut data = Vec::with_capacity(DEFEAT_CALLDATA_LEN);
    data.extend_from_slice(&DEFEAT_SELECTOR);
    data.extend_from_slice(Felt252::from_u64(note_id.into()).as_bytes());
    for word in words {
        data.extend_from_slice(word.as_bytes());
    }
    // The bytes offset after noteId and the static 12-word tuple.
    data.extend_from_slice(Felt252::from_u64(14 * 32).as_bytes());
    data.extend_from_slice(Felt252::from_u64(PROOF_LEN as u64).as_bytes());
    data.extend_from_slice(proof);
    debug_assert_eq!(data.len(), DEFEAT_CALLDATA_LEN);
    Ok(data)
}

/// `raiseEscapeConcession` calldata: `selector | noteId | 12 tuple words |
/// offset 0x1e0 | amount | len 256 | 8 proof words`, 772 bytes.
pub fn raise_calldata(
    note_id: u32,
    inputs: &RequestPublicInputsV2,
    proof: &[u8],
    amount: u128,
) -> Result<Vec<u8>, String> {
    let words = request_words(inputs)?;
    proof_bytes(proof)?;
    let mut data = Vec::with_capacity(RAISE_CALLDATA_LEN);
    data.extend_from_slice(&RAISE_SELECTOR);
    data.extend_from_slice(Felt252::from_u64(note_id.into()).as_bytes());
    for word in words {
        data.extend_from_slice(word.as_bytes());
    }
    // noteId, the tuple, the bytes offset and the static amount precede it.
    data.extend_from_slice(Felt252::from_u64(15 * 32).as_bytes());
    data.extend_from_slice(Felt252::from_u128(amount).as_bytes());
    data.extend_from_slice(Felt252::from_u64(PROOF_LEN as u64).as_bytes());
    data.extend_from_slice(proof);
    debug_assert_eq!(data.len(), RAISE_CALLDATA_LEN);
    Ok(data)
}

/// `retireClosedLeaf` calldata: `selector | noteId | 32 siblings`, 1060
/// bytes.
pub fn retire_calldata(note_id: u32, siblings: &[Felt252; MERKLE_DEPTH]) -> Vec<u8> {
    let mut data = Vec::with_capacity(RETIRE_CALLDATA_LEN);
    data.extend_from_slice(&RETIRE_SELECTOR);
    data.extend_from_slice(Felt252::from_u64(note_id.into()).as_bytes());
    for sibling in siblings {
        data.extend_from_slice(sibling.as_bytes());
    }
    data
}

/// `initiateEscapeWithdrawal` (kind 0) or `mutualClose` (kind 1) calldata:
/// `selector | 16 tuple words | offset 0x220 | len 256 | 8 proof words`,
/// 836 bytes. Refuses an ownership proof (kind 2), which every vault entry
/// point rejects, and a kind-0 statement without a distinct successor
/// nullifier or a kind-1 statement with a successor or a concession.
pub fn withdrawal_calldata(
    inputs: &WithdrawalPublicInputsV2C,
    proof: &[u8],
) -> Result<Vec<u8>, String> {
    if inputs.protocol_version != 2 {
        return Err("unsupported withdrawal protocol version".into());
    }
    address_word(&inputs.contract_address, "withdrawal contract address")?;
    for (value, name) in [
        (&inputs.active_root, "active root"),
        (&inputs.state_signing_key_x, "state signing key x"),
        (&inputs.state_signing_key_y, "state signing key y"),
        (&inputs.clearance_signing_key_x, "clearance signing key x"),
        (&inputs.clearance_signing_key_y, "clearance signing key y"),
        (&inputs.withdrawal_nullifier, "withdrawal nullifier"),
        (&inputs.next_nullifier, "next nullifier"),
    ] {
        canonical(value, name)?;
    }
    let selector = match inputs.kind {
        0 if inputs.next_nullifier.is_zero()
            || inputs.next_nullifier == inputs.withdrawal_nullifier =>
        {
            return Err("an escape needs a successor nullifier distinct from its own".into())
        }
        0 => ESCAPE_SELECTOR,
        1 if !inputs.next_nullifier.is_zero() || inputs.conceded != 0 => {
            return Err("a mutual close has no successor nullifier and concedes nothing".into())
        }
        1 => MUTUAL_CLOSE_SELECTOR,
        kind => return Err(format!("withdrawal kind {kind} is never accepted on chain")),
    };
    proof_bytes(proof)?;
    let mut data = Vec::with_capacity(WITHDRAWAL_CALLDATA_LEN);
    data.extend_from_slice(&selector);
    for word in inputs.to_field_elements() {
        data.extend_from_slice(word.as_bytes());
    }
    // The bytes offset after the static 16-word tuple and itself: 17 words.
    data.extend_from_slice(Felt252::from_u64(17 * 32).as_bytes());
    data.extend_from_slice(Felt252::from_u64(PROOF_LEN as u64).as_bytes());
    data.extend_from_slice(proof);
    debug_assert_eq!(data.len(), WITHDRAWAL_CALLDATA_LEN);
    Ok(data)
}

pub struct ChallengeWatcher {
    store: Arc<NullifierStore>,
}

impl ChallengeWatcher {
    pub fn new(store: Arc<NullifierStore>) -> Self {
        Self { store }
    }

    /// The deployment the server database is bound to.
    pub fn deployment_binding(&self) -> Result<Option<DeploymentBinding>, ServerError> {
        self.store.read_deployment_binding()
    }

    /// The evidence rows at `nullifier`, each re-verified: its Groth16 proof
    /// verifies against its inputs, which name `nullifier`, protocol version
    /// 2, this deployment and the vault's state key. A database or lock
    /// failure is an error, never an empty set: reporting an escape as
    /// unevidenced would silently disable its defeat.
    pub fn verified_evidence(
        &self,
        nullifier: &Felt252,
        verifier: &RequestVerifier,
        binding: &EvidenceBinding,
    ) -> Result<EvidenceSet, ServerError> {
        let mut set = EvidenceSet::default();
        for row in self.store.request_evidence_rows(nullifier)? {
            match row.and_then(|row| check_evidence(row, nullifier, verifier, binding)) {
                Ok(evidence) => set.verified.push(evidence),
                Err(reason) => set.rejected.push(reason),
            }
        }
        Ok(set)
    }

    /// `Ω` for the request at the escaped `nullifier` (see the module table).
    /// A lease row that cannot be read counts as possibly delivered.
    pub fn owed(&self, nullifier: &Felt252) -> Result<Owed, ServerError> {
        let Some(record) = self.store.try_lookup_by_nullifier(nullifier)? else {
            return Ok(Owed {
                basis: OwedBasis::Nothing(NothingOwed::NoRequest),
                settlement: None,
            });
        };
        if record.status == NullifierStatus::ClearanceReserved {
            return Ok(Owed {
                basis: OwedBasis::Nothing(NothingOwed::Clearance),
                settlement: None,
            });
        }
        let settlement = self.settlement_progress(&record);
        let basis = match (record.status, record.charge_applied, record.settled_charge) {
            (NullifierStatus::Finalized, Some(charge), _) => OwedBasis::Settled { charge },
            (_, _, Some(charge)) => OwedBasis::Settled { charge },
            // A Finalized transcript without its charge is corrupt: owed at
            // most its bound, like a request that may have been delivered.
            (NullifierStatus::Finalized | NullifierStatus::ExitedUnsigned, _, None) => {
                OwedBasis::Unsettled
            }
            (_, _, None) if settlement.lease_read_error.is_some() => OwedBasis::Unsettled,
            (_, _, None) if record.reservation_kind != "openrouter_lease" => {
                OwedBasis::Nothing(NothingOwed::NotALease)
            }
            (_, _, None) if settlement.lease_status.is_none() => {
                OwedBasis::Nothing(NothingOwed::NoLeaseRow)
            }
            (_, _, None) if settlement.possibly_delivered => OwedBasis::Unsettled,
            (_, _, None) => OwedBasis::Nothing(NothingOwed::NeverDelivered),
        };
        Ok(Owed {
            basis,
            settlement: Some(settlement),
        })
    }

    fn settlement_progress(&self, record: &TranscriptRecord) -> SettlementProgress {
        let mut progress = SettlementProgress {
            reservation_kind: record.reservation_kind.clone(),
            reserved_at: record.created_at,
            ..Default::default()
        };
        let Some(id) = record
            .client_request_id
            .as_deref()
            .filter(|_| record.reservation_kind == "openrouter_lease")
        else {
            return progress;
        };
        match self.store.try_lookup_openrouter_lease(id) {
            Ok(Some(lease)) if lease.request_nullifier != record.nullifier => {
                progress.lease_read_error =
                    Some("lease row belongs to another nullifier".to_string());
            }
            Ok(Some(lease)) => {
                progress.lease_status = Some(lease.status);
                progress.key_issued = lease.key_hash.is_some();
                progress.possibly_delivered =
                    lease.key_hash.is_some() && lease.delivered != Some(false);
                progress.key_source = Some(lease.key_source);
                progress.expires_at = Some(lease.expires_at);
                progress.settle_after = Some(lease.settle_after);
                progress.settlement_deadline_at = lease.settlement_deadline_at;
                // Upstream errors may echo the key name, which embeds the ID.
                progress.last_error = lease.last_error.as_deref().map(|error| {
                    let mut error = error.replace(id, "[request]");
                    if let Some(oa_id) = lease.oa_client_request_id.as_deref() {
                        error = error.replace(oa_id, "[request]");
                    }
                    bounded(&error)
                });
            }
            Ok(None) => {}
            Err(error) => progress.lease_read_error = Some(bounded(&error.to_string())),
        }
        progress
    }
}

/// Re-verify one evidence row; the reason it is rejected otherwise.
fn check_evidence(
    row: RequestEvidence,
    nullifier: &Felt252,
    verifier: &RequestVerifier,
    binding: &EvidenceBinding,
) -> Result<EvidenceProof, String> {
    let id = row.id;
    let reject = |reason: &str| Err(format!("request_evidence row {id}: {reason}"));
    let inputs = &row.public_inputs;
    if row.nullifier != *nullifier || inputs.request_nullifier != *nullifier {
        return reject("its request nullifier is not the one it is filed under");
    }
    if inputs.solvency_bound != row.solvency_bound {
        return reject("its solvency_bound column differs from its inputs");
    }
    if inputs.protocol_version != 2
        || inputs.chain_id != binding.chain_id
        || inputs.contract_address != binding.contract_address
    {
        return reject("its proof belongs to another deployment");
    }
    if (inputs.state_signing_key_x, inputs.state_signing_key_y) != binding.state_key {
        return reject("its proof names a state key other than the vault's");
    }
    if row.proof.len() != PROOF_LEN {
        return reject("its proof is not 256 bytes");
    }
    if let Err(reason) = request_words(inputs) {
        return reject(&reason);
    }
    let wire = Groth16ProofWire {
        backend: ProofBackendWire::Groth16Bn254,
        proof: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &row.proof),
    };
    match verifier.verify(inputs, &wire) {
        Ok(true) => Ok(EvidenceProof {
            row_id: id,
            inputs: row.public_inputs,
            proof: row.proof,
            created_at: row.created_at,
            source: row.source,
        }),
        Ok(false) => reject("its Groth16 proof does not verify"),
        Err(error) => reject(&format!("its Groth16 proof does not verify: {error}")),
    }
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_LAST_ERROR_CHARS).collect()
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::{config::ServerConfig, processor::RequestProcessor, signer::ServerSigner};
    use base64::Engine;
    use zkapi_types::wire::ApiRequestV2;

    /// Prove a genesis request for note 0 and have the active processor accept
    /// and archive it, rather than hand-constructing a transcript that could
    /// drift from its writer. Each secret yields a distinct nullifier.
    /// The server and wallet of the fixture requests: note 0 of `secret`
    /// with a deposit of 100, at its genesis state.
    fn test_wallet(secret: u64) -> (ServerConfig, crate::test_support::TestNote, u64) {
        let seeds = (Felt252::from_u64(11), Felt252::from_u64(12));
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let test_config = ServerConfig {
            contract_address: Felt252::from_u64(0xdead),
            request_charge_cap: 1,
            proof_setup_dir: crate::test_support::setup_directory(),
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        let deployment = crate::test_support::deployment_of(&test_config, seeds);
        let note = zkapi_proof::dev::DevNote {
            secret: Felt252::from_u64(secret),
            note_id: 0,
            deposit_amount: 100,
            expiry: now + 86_400,
        };
        let wallet = crate::test_support::TestNote {
            deployment,
            state: note.genesis(Felt252::from_u64(17)),
            tree: zkapi_proof::dev::tree_with(&[&note]),
        };
        (test_config, wallet, now)
    }

    /// A request proof of note 0 of `secret` at its genesis state, so at the
    /// nullifier of the fixture request of that secret, with another id and
    /// `solvency_bound`. Nothing is archived.
    pub(crate) fn request_at_genesis(
        secret: u64,
        client_request_id: &str,
        solvency_bound: u128,
    ) -> ApiRequestV2 {
        let (test_config, wallet, now) = test_wallet(secret);
        let payload = crate::test_support::lease_payload(&test_config, now);
        wallet
            .prepare_request(client_request_id, payload, now, solvency_bound)
            .request
    }

    async fn archive_v2_request(
        store: &Arc<NullifierStore>,
        secret: u64,
        client_request_id: &str,
    ) -> ApiRequestV2 {
        let seeds = (Felt252::from_u64(11), Felt252::from_u64(12));
        let signer = Arc::new(ServerSigner::new(&seeds.0, &seeds.1));
        let (test_config, wallet, now) = test_wallet(secret);
        let payload = crate::test_support::lease_payload(&test_config, now);
        let request = wallet
            .prepare_request(client_request_id, payload, now, 1)
            .request;
        let processor =
            RequestProcessor::try_new(test_config, store.clone(), signer, wallet.root()).unwrap();
        processor.update_root(wallet.root());
        processor.finalize_test_lease(&request, 1).unwrap();
        request
    }

    /// A real v2 proof accepted and archived by the active processor.
    pub(crate) async fn finalized_v2_request() -> (Arc<NullifierStore>, ApiRequestV2) {
        static FIXTURE: tokio::sync::OnceCell<(Arc<NullifierStore>, ApiRequestV2)> =
            tokio::sync::OnceCell::const_new();
        FIXTURE
            .get_or_init(|| async {
                let store = Arc::new(NullifierStore::in_memory().unwrap());
                let request = archive_v2_request(&store, 42, "challenge-v2").await;
                (store, request)
            })
            .await
            .clone()
    }

    /// Two finalized requests with distinct nullifiers in one archive, for an
    /// escape at one anchor followed by a re-escape at another.
    pub(crate) async fn two_finalized_v2_requests(
    ) -> (Arc<NullifierStore>, ApiRequestV2, ApiRequestV2) {
        static FIXTURE: tokio::sync::OnceCell<(Arc<NullifierStore>, ApiRequestV2, ApiRequestV2)> =
            tokio::sync::OnceCell::const_new();
        FIXTURE
            .get_or_init(|| async {
                let store = Arc::new(NullifierStore::in_memory().unwrap());
                let first = archive_v2_request(&store, 42, "challenge-v2").await;
                let second = archive_v2_request(&store, 43, "challenge-v2-second").await;
                assert_ne!(
                    first.public_inputs.request_nullifier,
                    second.public_inputs.request_nullifier
                );
                (store, first, second)
            })
            .await
            .clone()
    }

    /// The Finalized transcript bounded settlement writes for this request.
    pub(crate) fn finalized_transcript(request: &ApiRequestV2, charge: u128) -> TranscriptRecord {
        TranscriptRecord {
            nullifier: request.public_inputs.request_nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind: "openrouter_lease".into(),
            client_request_id: Some(request.client_request_id.clone()),
            payload_hash: Some(request.payload_hash),
            charge_applied: Some(charge),
            response_code: Some(200),
            response_payload: Some("{}".into()),
            response_hash: Some(Felt252::from_u64(7)),
            next_commitment_x: None,
            next_commitment_y: None,
            next_anchor: Some(Felt252::from_u64(8)),
            blind_delta_srv: None,
            next_state_sig: None,
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(
                base64::engine::general_purpose::STANDARD
                    .decode(&request.proof.proof)
                    .unwrap(),
            ),
            request_inputs_json: Some(serde_json::to_string(&request.public_inputs).unwrap()),
            api_request_binding: None,
            created_at: 0,
            finalized_at: None,
            settled_charge: None,
            settled_basis: None,
            settled_at: None,
            exit_deferred_since: None,
        }
    }

    /// The deployment the fixtures' requests are bound to.
    pub(crate) fn binding_of(request: &ApiRequestV2) -> EvidenceBinding {
        EvidenceBinding {
            chain_id: request.public_inputs.chain_id,
            contract_address: request.public_inputs.contract_address,
            state_key: (
                request.public_inputs.state_signing_key_x,
                request.public_inputs.state_signing_key_y,
            ),
        }
    }

    pub(crate) fn verifier() -> RequestVerifier {
        RequestVerifier::load(crate::test_support::setup_directory()).unwrap()
    }

    fn proof_of(request: &ApiRequestV2) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD
            .decode(&request.proof.proof)
            .unwrap()
    }

    fn felt(hex: &str) -> Felt252 {
        Felt252::from_hex(hex).unwrap()
    }

    /// The inputs of VaultCalldataGolden.t.sol.
    fn golden_request() -> RequestPublicInputsV2 {
        RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: felt("0x00112233445566778899aabbccddeeff00112233"),
            active_root: felt("0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"),
            state_signing_key_x: felt(
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            ),
            state_signing_key_y: felt(
                "0x2222222222222222222222222222222222222222222222222222222222222222",
            ),
            request_time: 1_767_225_600,
            solvency_bound: u128::MAX,
            request_nullifier: felt(
                "0x0102030405060708091011121314151617181920212223242526272829303132",
            ),
            authorization_tag: felt(
                "0x2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849",
            ),
            anonymous_commitment_x: felt(
                "0x0333333333333333333333333333333333333333333333333333333333333333",
            ),
            anonymous_commitment_y: felt(
                "0x0444444444444444444444444444444444444444444444444444444444444444",
            ),
        }
    }

    fn golden_withdrawal(kind: u8) -> WithdrawalPublicInputsV2C {
        WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 1,
            contract_address: felt("0x00112233445566778899aabbccddeeff00112233"),
            active_root: felt("0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"),
            state_signing_key_x: felt(
                "0x1111111111111111111111111111111111111111111111111111111111111111",
            ),
            state_signing_key_y: felt(
                "0x2222222222222222222222222222222222222222222222222222222222222222",
            ),
            clearance_signing_key_x: felt(
                "0x0555555555555555555555555555555555555555555555555555555555555555",
            ),
            clearance_signing_key_y: felt(
                "0x0666666666666666666666666666666666666666666666666666666666666666",
            ),
            note_id: u32::MAX,
            final_balance: 1_000_000_000_000_000_000,
            destination: [0xff; 20],
            withdrawal_nullifier: felt(
                "0x0102030405060708091011121314151617181920212223242526272829303132",
            ),
            kind,
            next_nullifier: if kind == 0 {
                felt("0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40")
            } else {
                Felt252::ZERO
            },
            conceded: if kind == 0 { 123_456_789 } else { 0 },
            valid_until: u64::MAX,
        }
    }

    fn golden_proof() -> Vec<u8> {
        (1..=256).map(|byte| byte as u8).collect()
    }

    fn golden(name: &str) -> Vec<u8> {
        let vectors: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/vault_calldata_golden.json"))
                .unwrap();
        hex::decode(vectors[name].as_str().unwrap().trim_start_matches("0x")).unwrap()
    }

    #[test]
    fn golden_calldata_matches_forge_abi_encode() {
        let defeat = VaultCall::Defeat {
            note_id: u32::MAX,
            inputs: golden_request(),
            proof: golden_proof(),
        };
        assert_eq!(defeat.calldata().unwrap(), golden("defeat"));
        assert_eq!(golden("defeat").len(), DEFEAT_CALLDATA_LEN);
        let raise = VaultCall::Raise {
            note_id: 7,
            inputs: golden_request(),
            proof: golden_proof(),
            amount: 123_456_789_012_345_678_901_234_567_890,
        };
        assert_eq!(raise.calldata().unwrap(), golden("raise"));
        assert_eq!(golden("raise").len(), RAISE_CALLDATA_LEN);
        assert_eq!(
            withdrawal_calldata(&golden_withdrawal(0), &golden_proof()).unwrap(),
            golden("escape")
        );
        assert_eq!(
            withdrawal_calldata(&golden_withdrawal(1), &golden_proof()).unwrap(),
            golden("close")
        );
        assert_eq!(golden("escape").len(), WITHDRAWAL_CALLDATA_LEN);
        let siblings: [Felt252; MERKLE_DEPTH] =
            std::array::from_fn(|index| Felt252::from_u64((index as u64 + 1) * 0x0101010101010101));
        let retire = VaultCall::Retire {
            note_id: 9,
            siblings: Box::new(siblings),
        };
        assert_eq!(retire.calldata().unwrap(), golden("retire"));
        assert_eq!(golden("retire").len(), RETIRE_CALLDATA_LEN);

        // The selectors are those of the signatures.
        for (signature, selector) in [
            (DEFEAT_SIGNATURE, DEFEAT_SELECTOR),
            (RAISE_SIGNATURE, RAISE_SELECTOR),
            (RETIRE_SIGNATURE, RETIRE_SELECTOR),
            (ESCAPE_SIGNATURE, ESCAPE_SELECTOR),
            (MUTUAL_CLOSE_SIGNATURE, MUTUAL_CLOSE_SELECTOR),
        ] {
            assert_eq!(&Keccak256::digest(signature.as_bytes())[..4], &selector);
        }
        // And those of the real vault (compiled protocol/contracts sources).
        for (name, selector) in [
            ("challengeEscapeWithdrawal", DEFEAT_SELECTOR),
            ("raiseEscapeConcession", RAISE_SELECTOR),
            ("retireClosedLeaf", RETIRE_SELECTOR),
            ("initiateEscapeWithdrawal", ESCAPE_SELECTOR),
            ("mutualClose", MUTUAL_CLOSE_SELECTOR),
        ] {
            assert_eq!(
                crate::test_support::real_selector(name),
                format!("0x{}", hex::encode(selector)),
                "{name}"
            );
        }
    }

    /// The shared withdrawal golden vector (design §11 WP-F): real kind-0
    /// and kind-1 proofs whose calldata Forge pins to abi.encodeCall against
    /// the real vault. With ZKAPI_WITHDRAWAL_GOLDEN_OUT set, the encoder's
    /// output is written there for scripts/check-withdrawal-golden.mjs,
    /// which submits it to a vault on Anvil.
    #[test]
    fn real_proofs_encode_to_the_shared_withdrawal_golden_vector() {
        let golden: serde_json::Value = serde_json::from_str(include_str!(
            "../../../protocol/contracts/test/fixtures/withdrawal-golden.json"
        ))
        .unwrap();
        let mut output = serde_json::Map::new();
        for (name, kind) in [("escape", 0), ("close", 1)] {
            let inputs: WithdrawalPublicInputsV2C =
                serde_json::from_value(golden[name]["public_inputs"].clone()).unwrap();
            assert_eq!(inputs.kind, kind);
            let proof = base64::engine::general_purpose::STANDARD
                .decode(golden[name]["proof"].as_str().unwrap())
                .unwrap();
            let calldata = format!(
                "0x{}",
                hex::encode(withdrawal_calldata(&inputs, &proof).unwrap())
            );
            assert_eq!(
                calldata,
                golden[name]["calldata"].as_str().unwrap(),
                "{name}"
            );
            output.insert(name.into(), calldata.into());
        }
        if let Some(dir) = std::env::var_os("ZKAPI_WITHDRAWAL_GOLDEN_OUT") {
            std::fs::write(
                std::path::Path::new(&dir).join("rust-serverd.json"),
                serde_json::to_vec(&output).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn encoders_refuse_what_the_vault_would_never_accept() {
        let call = |inputs: RequestPublicInputsV2, proof: Vec<u8>| {
            [
                defeat_calldata(1, &inputs, &proof),
                raise_calldata(1, &inputs, &proof, 1),
            ]
        };
        let mut short = golden_proof();
        short.pop();
        let mut version = golden_request();
        version.protocol_version = 3;
        let mut wide = golden_request();
        wide.contract_address = Felt252::from_u64(1);
        wide.contract_address.0[0] = 1;
        let mut outside = golden_request();
        outside.request_nullifier = Felt252([0xff; 32]);
        for (inputs, proof) in [
            (golden_request(), short.clone()),
            (version, golden_proof()),
            (wide, golden_proof()),
            (outside, golden_proof()),
        ] {
            for result in call(inputs, proof) {
                assert!(result.is_err());
            }
        }
        // Ownership proofs, escapes without a distinct successor and closes
        // with a successor or a concession are never encoded.
        let mut ownership = golden_withdrawal(1);
        ownership.kind = 2;
        let mut no_successor = golden_withdrawal(0);
        no_successor.next_nullifier = Felt252::ZERO;
        let mut own_successor = golden_withdrawal(0);
        own_successor.next_nullifier = own_successor.withdrawal_nullifier;
        let mut conceding_close = golden_withdrawal(1);
        conceding_close.conceded = 1;
        for inputs in [ownership, no_successor, own_successor, conceding_close] {
            assert!(withdrawal_calldata(&inputs, &golden_proof()).is_err());
        }
        assert!(withdrawal_calldata(&golden_withdrawal(0), &short).is_err());
    }

    #[test]
    fn digests_pin_the_evidence_and_the_raise_amount() {
        let request = golden_request();
        let defeat = VaultCall::Defeat {
            note_id: 3,
            inputs: request.clone(),
            proof: golden_proof(),
        };
        // The defeat keeps the pre-concession challenge digest.
        let mut expected = Keccak256::new();
        expected.update(b"zkapi:v2:challenge-evidence\0");
        expected.update(3u32.to_be_bytes());
        for value in request.to_field_elements() {
            expected.update(value.as_bytes());
        }
        expected.update(golden_proof());
        assert_eq!(
            defeat.digest(),
            format!("0x{}", hex::encode(expected.finalize()))
        );
        let raise = |amount: u128| VaultCall::Raise {
            note_id: 3,
            inputs: request.clone(),
            proof: golden_proof(),
            amount,
        };
        let mut expected = Keccak256::new();
        expected.update(b"zkapi:v2c:raise-evidence\0");
        expected.update(3u32.to_be_bytes());
        for value in request.to_field_elements() {
            expected.update(value.as_bytes());
        }
        expected.update(golden_proof());
        expected.update(5u128.to_be_bytes());
        assert_eq!(
            raise(5).digest(),
            format!("0x{}", hex::encode(expected.finalize()))
        );
        assert_ne!(raise(5).digest(), raise(6).digest());
        assert_ne!(raise(5).digest(), defeat.digest());
        // A retirement's siblings follow the root; its digest names the note.
        let retire = |sibling: u64| VaultCall::Retire {
            note_id: 3,
            siblings: Box::new([Felt252::from_u64(sibling); MERKLE_DEPTH]),
        };
        assert_eq!(retire(1).digest(), retire(2).digest());
        assert_ne!(retire(1).calldata(), retire(2).calldata());
    }

    #[tokio::test]
    async fn evidence_rows_are_reverified_before_they_build_calldata() {
        let (store, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        let watcher = ChallengeWatcher::new(store);
        let verifier = verifier();
        let set = watcher
            .verified_evidence(&nullifier, &verifier, &binding_of(&request))
            .unwrap();
        assert_eq!(set.verified.len(), 1, "{:?}", set.rejected);
        let evidence = set.earliest().unwrap();
        assert_eq!(evidence.inputs, request.public_inputs);
        assert_eq!(evidence.proof, proof_of(&request));
        assert_eq!(evidence.source, "reserve");
        let call = VaultCall::Defeat {
            note_id: 0,
            inputs: evidence.inputs.clone(),
            proof: evidence.proof.clone(),
        };
        let calldata = call.calldata().unwrap();
        assert_eq!(&calldata[..4], &DEFEAT_SELECTOR);
        assert_eq!(&calldata[4 + 9 * 32..4 + 10 * 32], nullifier.as_bytes());

        // Rows of another deployment or state key are rejected.
        for change in [
            (|binding: &mut EvidenceBinding| binding.chain_id += 1) as fn(&mut EvidenceBinding),
            |binding| binding.contract_address = Felt252::from_u64(0xbeef),
            |binding| binding.state_key.0 = Felt252::from_u64(5),
        ] {
            let mut binding = binding_of(&request);
            change(&mut binding);
            let set = watcher
                .verified_evidence(&nullifier, &verifier, &binding)
                .unwrap();
            assert!(set.verified.is_empty());
            assert_eq!(set.rejected.len(), 1);
            assert!(!set.is_empty());
        }
        // No row at all: an empty set, not an error.
        assert!(watcher
            .verified_evidence(&Felt252::from_u64(77), &verifier, &binding_of(&request))
            .unwrap()
            .is_empty());
    }

    /// Append an evidence row directly (the table refuses only updates and
    /// deletes).
    pub(crate) fn append_raw_evidence(
        store: &NullifierStore,
        nullifier: &Felt252,
        inputs: &str,
        bound: &str,
        proof: &[u8],
        created_at: u64,
    ) {
        store.execute_for_test(
            "INSERT INTO request_evidence (nullifier, client_request_id, solvency_bound,
                request_inputs_json, proof_blob, source, created_at)
             VALUES (?1, 'raw', ?2, ?3, ?4, 'rebind', ?5)",
            rusqlite::params![nullifier.to_hex(), bound, inputs, proof, created_at as i64],
        );
    }

    #[tokio::test]
    async fn a_tampered_or_undecodable_row_never_hides_a_valid_one() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let nullifier = request.public_inputs.request_nullifier;
        let inputs = serde_json::to_string(&request.public_inputs).unwrap();
        let bound = request.public_inputs.solvency_bound.to_string();
        // An earlier tampered proof, and a row that does not decode.
        let mut tampered = proof_of(&request);
        tampered[40] ^= 1;
        append_raw_evidence(&store, &nullifier, &inputs, &bound, &tampered, 1);
        append_raw_evidence(&store, &nullifier, "{}", &bound, &tampered, 2);
        // A row whose bound column disagrees with its inputs.
        append_raw_evidence(&store, &nullifier, &inputs, "7", &proof_of(&request), 3);
        store.reserve_openrouter_lease(&request).unwrap();
        let set = ChallengeWatcher::new(store)
            .verified_evidence(&nullifier, &verifier(), &binding_of(&request))
            .unwrap();
        assert_eq!(set.verified.len(), 1);
        assert_eq!(set.verified[0].source, "reserve");
        assert_eq!(set.rejected.len(), 3, "{:?}", set.rejected);
        assert!(set.rejected[0].contains("does not verify"));
        assert!(set.rejected[1].contains("does not decode"));
        assert!(set.rejected[2].contains("solvency_bound"));
    }

    #[tokio::test]
    async fn the_raise_uses_the_largest_bound_and_evidence_time_is_kept() {
        let (_, request) = finalized_v2_request().await;
        let evidence = |row_id, bound, created_at| {
            let mut inputs = request.public_inputs.clone();
            inputs.solvency_bound = bound;
            EvidenceProof {
                row_id,
                inputs,
                proof: Vec::new(),
                created_at,
                source: "reserve".into(),
            }
        };
        let set = EvidenceSet {
            verified: vec![
                evidence(1, 5, 100),
                evidence(2, 9, 200),
                evidence(3, 9, 300),
                evidence(4, 2, 400),
            ],
            rejected: Vec::new(),
        };
        assert_eq!(set.earliest().unwrap().row_id, 1);
        assert_eq!(set.max_bound().unwrap().row_id, 2);
        assert!(set.existed_before(101));
        assert!(!set.existed_before(100));
        assert!(EvidenceSet::default().max_bound().is_none());
    }

    fn owed(store: &Arc<NullifierStore>, nullifier: &Felt252) -> OwedBasis {
        ChallengeWatcher::new(store.clone())
            .owed(nullifier)
            .unwrap()
            .basis
    }

    #[tokio::test]
    async fn owed_follows_the_omega_table() {
        let (_, request) = finalized_v2_request().await;
        let nullifier = request.public_inputs.request_nullifier;
        let id = request.client_request_id.clone();
        let nothing = |basis: OwedBasis| matches!(basis, OwedBasis::Nothing(_));

        // No row, or a clearance: nothing.
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        assert!(nothing(owed(&store, &nullifier)));
        store
            .reserve_clearance(&nullifier, "ownership_proof")
            .unwrap();
        assert!(nothing(owed(&store, &nullifier)));

        // A reservation without a lease row, or whose key was never issued:
        // nothing.
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        assert!(nothing(owed(&store, &nullifier)));
        store
            .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
            .unwrap();
        assert!(nothing(owed(&store, &nullifier)));
        // Issued but never returned to the client: nothing.
        store.activate_openrouter_lease(&id, "key-hash").unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET delivered = 0 WHERE client_request_id = ?1",
            [&id],
        );
        assert!(nothing(owed(&store, &nullifier)));
        // Possibly delivered and unsettled: its bound, from the raise lead.
        store.execute_for_test(
            "UPDATE openrouter_leases SET delivered = 1 WHERE client_request_id = ?1",
            [&id],
        );
        let owed_now = ChallengeWatcher::new(store.clone())
            .owed(&nullifier)
            .unwrap();
        assert_eq!(owed_now.basis, OwedBasis::Unsettled);
        let settlement = owed_now.settlement.unwrap();
        assert!(settlement.possibly_delivered);
        assert_eq!(settlement.lease_status.as_deref(), Some("active"));
        // Settled (successor deferred or not yet signed): the settled charge.
        store.execute_for_test(
            "UPDATE nullifiers SET settled_charge = 7, settled_basis = 'measured',
                settled_at = 1, exit_deferred_since = 2 WHERE nullifier = ?1",
            [nullifier.to_hex()],
        );
        assert_eq!(owed(&store, &nullifier), OwedBasis::Settled { charge: 7 });
        // ExitedUnsigned keeps it.
        store.execute_for_test(
            "UPDATE nullifiers SET status = 'ExitedUnsigned' WHERE nullifier = ?1",
            [nullifier.to_hex()],
        );
        assert_eq!(owed(&store, &nullifier), OwedBasis::Settled { charge: 7 });

        // Finalized: its charge_applied, zero included.
        for charge in [0, 3] {
            let store = Arc::new(NullifierStore::in_memory().unwrap());
            store.reserve_openrouter_lease(&request).unwrap();
            store
                .finalize(&nullifier, &finalized_transcript(&request, charge))
                .unwrap();
            assert_eq!(owed(&store, &nullifier), OwedBasis::Settled { charge });
        }
    }

    #[tokio::test]
    async fn an_unreadable_lease_row_counts_as_possibly_delivered() {
        let (_, request) = finalized_v2_request().await;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let server = NullifierStore::new(&path).unwrap();
        server.reserve_openrouter_lease(&request).unwrap();
        server
            .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
            .unwrap();
        let store = Arc::new(NullifierStore::open_read_only(&path).unwrap());
        let nullifier = request.public_inputs.request_nullifier;
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("UPDATE openrouter_leases SET api_request_json = 'not json';")
            .unwrap();
        let owed = ChallengeWatcher::new(store.clone())
            .owed(&nullifier)
            .unwrap();
        assert_eq!(owed.basis, OwedBasis::Unsettled);
        assert!(owed.settlement.unwrap().lease_read_error.is_some());

        // A failed read is an error, never "nothing owed" or "no evidence".
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TABLE nullifiers;")
            .unwrap();
        let watcher = ChallengeWatcher::new(store);
        assert!(watcher.owed(&nullifier).is_err());
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch("DROP TRIGGER request_evidence_no_delete; DROP TABLE request_evidence;")
            .unwrap();
        assert!(watcher
            .verified_evidence(&nullifier, &verifier(), &binding_of(&request))
            .is_err());
    }

    #[tokio::test]
    async fn issued_lease_reports_redacted_settlement_progress() {
        let (_, request) = finalized_v2_request().await;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 1, 2, 3, 1.0)
            .unwrap();
        // Status never links a note to its request: the ID is redacted.
        store
            .record_openrouter_lease_error(
                &request.client_request_id,
                &format!("upstream rejected key zkapi-{}", request.client_request_id),
            )
            .unwrap();
        let progress = ChallengeWatcher::new(store)
            .owed(&request.public_inputs.request_nullifier)
            .unwrap()
            .settlement
            .unwrap();
        assert_eq!(
            progress.last_error.as_deref(),
            Some("upstream rejected key zkapi-[request]")
        );
        assert_eq!(progress.lease_status.as_deref(), Some("provisioning"));
        assert_eq!(progress.expires_at, Some(2));
        assert_eq!(progress.settle_after, Some(3));
        assert_eq!(progress.evidence_expected_by(), Some(3));
        assert_eq!(progress.reservation_kind, "openrouter_lease");
    }
}
