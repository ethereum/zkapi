//! Browser-safe zkAPI wallet operations for circuit `zkapi-v2-concession-v1`.
//!
//! This crate deliberately owns neither storage nor transport. Every operation
//! accepts an immutable state snapshot and returns the complete next snapshot,
//! allowing the JavaScript host to commit state and its write-ahead journal in
//! one IndexedDB transaction before any network request is made.
//!
//! Refusals are errors whose message starts with a stable code followed by
//! `": "` (for example `invalid_successor: S4 ...`), so the host can tell a
//! signed but unusable successor from a transport problem. The codes are the
//! `pub const` strings of [`codes`].
//!
//! What the crate enforces (design §6.1–§6.5):
//! * **S1–S6** before a successor installs ([`complete_response`]): identity,
//!   payload hash, the state signature, the charge against the state's one
//!   bound, the derived anchor `next_anchor(N)` and the commitment algebra.
//!   A correctly signed response that fails S3, S4 or S5 is refused with
//!   [`codes::INVALID_SUCCESSOR`].
//! * **C2**: every request proof at a state carries the same solvency bound,
//!   recorded in the returned state as `bound_at_state` ([`prepare_request`]).
//! * **Q6a**: a signed state proves requests only with its `prev_anchor`.
//!   Exits never need it.
//! * Withdrawal kinds: an escape (kind 0) concedes at most `bound_at_state`;
//!   a mutual close (kind 1) and an ownership proof (kind 2) concede nothing,
//!   and an ownership proof has no destination ([`prepare_withdrawal`]).
//! * Lost ε: a finalized response whose journal is lost is checked against
//!   S1, S2, S4 and S6 ([`check_unrecoverable_response`]) before its charge
//!   may lower an escape's concession.
//! * A saved deposit-time path is kept only if it leads to its root
//!   ([`note_path_matches`]); the vault accepts any root it ever held.

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Deserializer, Serialize};
use zkapi_core::merkle::MerkleTree;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, dev_setup_build, random_field, random_scalar, rerandomize,
    server_update, verify_signature, withdrawal_public_inputs, RequestProver, RequestVerifier,
    RequestWitnessData, WithdrawalProver, WithdrawalStatementParams, WithdrawalWitnessData,
    CEREMONY_SETUP_ID, CIRCUIT_ID, DEV_SETUP_ID,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceResponseV2, CurvePointWire, Groth16ProofWire, ProofBackendWire,
    RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, SchnorrSignature, WithdrawalKind, WithdrawalPublicInputsV2C,
    MERKLE_DEPTH,
};

/// Stable refusal codes (the prefix of an error message, before `": "`).
pub mod codes {
    /// The bundle and a key file belong to different setups.
    pub const SETUP_MISMATCH: &str = "setup_mismatch";
    /// The note state belongs to another deployment or is inconsistent.
    pub const STATE_INVALID: &str = "state_invalid";
    /// C2: a request proof at this state already used another bound.
    pub const BOUND_FIXED_AT_STATE: &str = "bound_fixed_at_state";
    /// A signed state without its predecessor's anchor cannot prove requests.
    pub const PREV_ANCHOR_MISSING: &str = "prev_anchor_missing";
    /// The Merkle path does not lead from the note's leaf to the given root.
    pub const MERKLE_PATH_MISMATCH: &str = "merkle_path_mismatch";
    /// The state holds less than the requested solvency bound.
    pub const INSUFFICIENT_BALANCE: &str = "insufficient_balance";
    /// S1: the response or journal names another request or state.
    pub const RESPONSE_IDENTITY_MISMATCH: &str = "response_identity_mismatch";
    /// S1: the journal was not made at this state.
    pub const JOURNAL_STATE_MISMATCH: &str = "journal_state_mismatch";
    /// S2: the response payload does not hash to `response_hash`.
    pub const RESPONSE_HASH_MISMATCH: &str = "response_hash_mismatch";
    /// S6: the successor is not signed by the build-pinned state key.
    pub const SUCCESSOR_SIGNATURE_INVALID: &str = "successor_signature_invalid";
    /// S3, S4 or S5 failed on a correctly signed successor: treat it exactly
    /// like a withheld successor (archive disposition `invalid_successor`).
    pub const INVALID_SUCCESSOR: &str = "invalid_successor";
    /// A withdrawal argument is not allowed for its mode.
    pub const WITHDRAWAL_ARGS: &str = "invalid_withdrawal_args";
    /// C3: an escape may concede at most the state's bound.
    pub const CONCEDED_EXCEEDS_BOUND: &str = "conceded_exceeds_bound";
    /// The mutual-close clearance is missing or not valid for this state.
    pub const CLEARANCE_INVALID: &str = "clearance_invalid";
    /// A tree event is out of order or names an impossible leaf change.
    pub const TREE_EVENT_INVALID: &str = "tree_event_invalid";
}

fn refusal(code: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("{code}: {detail}")
}

/// The setup this bundle proves with: `dev` when built with the `dev-setup`
/// feature, otherwise the ceremony setup `mpc-1`. Keys of any other setup are
/// refused, even ones the underlying proof library would accept.
pub fn bundle_setup_id() -> &'static str {
    if dev_setup_build() {
        DEV_SETUP_ID
    } else {
        CEREMONY_SETUP_ID
    }
}

fn require_bundle_setup(setup_id: &str, what: &str) -> Result<()> {
    let expected = bundle_setup_id();
    if setup_id != expected {
        return Err(refusal(
            codes::SETUP_MISMATCH,
            format!("the {what} belongs to setup {setup_id:?}; this {CIRCUIT_ID} bundle is built for setup {expected:?}"),
        ));
    }
    Ok(())
}

/// Decode a request proving key of this bundle's setup.
pub fn load_request_prover(bytes: &[u8]) -> Result<RequestProver> {
    let prover = RequestProver::from_bytes(bytes)?;
    require_bundle_setup(prover.setup_id(), "request proving key")?;
    Ok(prover)
}

/// Decode a withdrawal proving key of this bundle's setup.
pub fn load_withdrawal_prover(bytes: &[u8]) -> Result<WithdrawalProver> {
    let prover = WithdrawalProver::from_bytes(bytes)?;
    require_bundle_setup(prover.setup_id(), "withdrawal proving key")?;
    Ok(prover)
}

/// Decode a request verifying key (`request.vk`) of this bundle's setup.
pub fn load_request_verifier(bytes: &[u8]) -> Result<RequestVerifier> {
    let verifier = RequestVerifier::from_bytes(bytes)?;
    require_bundle_setup(verifier.setup_id(), "request verifying key")?;
    Ok(verifier)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BrowserWalletConfig {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub request_charge_cap: u128,
    pub policy_charge_cap: u128,
    pub policy_enabled: bool,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteState {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub note_id: u32,
    pub secret_s: Felt252,
    pub deposit_amount: u128,
    pub expiry_ts: u64,
    pub current_balance: u128,
    pub balance_blinding: String,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub current_anchor: Felt252,
    /// `current_anchor == 1`; kept for the host's status display.
    pub is_genesis: bool,
    pub state_signature: Option<SchnorrSignature>,
    /// The anchor of the state whose request produced this one (`None` at
    /// genesis). A signed state without it cannot prove requests
    /// (`prev_anchor_missing`) but can always exit.
    #[serde(default)]
    pub prev_anchor: Option<Felt252>,
    /// The solvency bound of every request proof made at this state (C2);
    /// 0 while no request proof was made. Reset to 0 by an install.
    #[serde(default)]
    pub bound_at_state: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingRequestJournal {
    pub exists: bool,
    pub client_request_id: String,
    pub nullifier: Felt252,
    pub payload_hash: Felt252,
    pub user_rerandomization: Felt252,
    pub created_at_ms: u64,
    pub prepared_request: ApiRequestV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DepositParams {
    pub secret: Felt252,
    pub registration_commitment: Felt252,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmDepositArgs {
    pub secret: Felt252,
    pub note_id: u32,
    pub amount: u128,
    pub expiry_ts: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareRequestArgs {
    pub payload: String,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    pub client_request_id: String,
    pub request_time: u64,
    pub created_at_ms: u64,
}

/// A prepared request. The host commits `state` (which records the bound,
/// C2), `journal` and the archive record in one transaction before the
/// request leaves the device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedRequest {
    pub request: ApiRequestV2,
    pub journal: PendingRequestJournal,
    pub state: BrowserNoteState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompleteResponseArgs {
    pub state: BrowserNoteState,
    pub journal: PendingRequestJournal,
    pub response: RequestResponseV2,
}

/// Arguments of [`prepare_withdrawal`].
///
/// * `escape` (kind 0): `destination` and `conceded` are required, and
///   `conceded <= bound_at_state`. No clearance.
/// * `mutual` (kind 1): `destination` and the server `clearance` are
///   required; `conceded` must be absent or 0.
/// * `ownership` (kind 2): no destination (absent or the zero address), no
///   clearance, `conceded` absent or 0.
///
/// `valid_until` is the last second at which the vault (kinds 0 and 1) or
/// the server (kind 2) accepts the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareWithdrawalArgs {
    pub mode: String,
    #[serde(default)]
    pub destination: Option<String>,
    #[serde(default)]
    pub conceded: Option<u128>,
    pub valid_until: u64,
    pub active_root: Felt252,
    pub merkle_siblings: Vec<Felt252>,
    #[serde(default)]
    pub clearance: Option<ClearanceResponseV2>,
}

/// A withdrawal proof. Exits do no Merkle work on chain, so the plan carries
/// no path: the calldata is the 16-word statement and the proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WithdrawalPlan {
    pub mode: String,
    pub public_inputs: WithdrawalPublicInputsV2C,
    pub proof: Groth16ProofWire,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserNoteStatus {
    pub note_id: u32,
    pub deposit_amount: u128,
    pub current_balance: u128,
    pub expiry_ts: u64,
    pub is_genesis: bool,
    pub current_anchor: Felt252,
    pub current_commitment_x: Felt252,
    pub current_commitment_y: Felt252,
    pub bound_at_state: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserWalletStatus {
    pub has_note: bool,
    pub pending_request: bool,
    pub note: Option<BrowserNoteStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TreeSnapshot {
    pub root: Felt252,
    pub next_note_id: u32,
    pub leaves: Vec<Felt252>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BrowserTreePath {
    pub active_root: Felt252,
    pub note_id: u32,
    pub siblings: Vec<Felt252>,
}

/// Derive a path from the indexer's privacy-safe whole-tree snapshot and
/// verify the advertised root before any proof uses it.
pub fn tree_path(
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
) -> Result<BrowserTreePath> {
    if snapshot.leaves.len() != snapshot.next_note_id as usize {
        anyhow::bail!("tree snapshot leaf count does not match next_note_id");
    }
    if (require_existing && note_id >= snapshot.next_note_id)
        || (!require_existing && note_id != snapshot.next_note_id)
    {
        anyhow::bail!("requested note index is inconsistent with the tree snapshot");
    }
    let mut tree = MerkleTree::new();
    for (index, leaf) in snapshot.leaves.into_iter().enumerate() {
        tree.set_leaf(index as u32, leaf);
    }
    if tree.root() != snapshot.root {
        anyhow::bail!("tree snapshot root verification failed");
    }
    Ok(BrowserTreePath {
        active_root: snapshot.root,
        note_id,
        siblings: tree.get_siblings(note_id).to_vec(),
    })
}

/// The path of `note_id` in the tree whose leaf `i` is `leaves[i]` (zero for
/// a retired leaf), and that tree's root. The note's leaf must be present.
pub fn tree_path_from_leaves(leaves: Vec<Felt252>, note_id: u32) -> Result<BrowserTreePath> {
    let leaf = leaves.get(note_id as usize).copied().ok_or_else(|| {
        refusal(
            codes::TREE_EVENT_INVALID,
            format!("note {note_id} is not among the {} leaves", leaves.len()),
        )
    })?;
    if leaf.is_zero() {
        return Err(refusal(
            codes::TREE_EVENT_INVALID,
            format!("note {note_id} has no leaf"),
        ));
    }
    let mut tree = MerkleTree::new();
    for (index, value) in leaves.into_iter().enumerate() {
        if !value.is_zero() {
            tree.set_leaf(index as u32, value);
        }
    }
    Ok(BrowserTreePath {
        active_root: tree.root(),
        note_id,
        siblings: tree.get_siblings(note_id).to_vec(),
    })
}

fn deserialize_u128_text<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u128, D::Error> {
    let text = String::deserialize(deserializer)?;
    let parsed = match text.strip_prefix("0x") {
        Some(hex) => u128::from_str_radix(hex, 16),
        None => text.parse::<u128>(),
    };
    parsed.map_err(|_| serde::de::Error::custom("expected a decimal or 0x-hex u128 string"))
}

/// One leaf-changing vault event, in the vault's log order (§6.6). Amounts
/// travel as strings because JavaScript numbers lose precision above 2^53.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
pub enum TreeEvent {
    /// `NoteDeposited(noteId, commitment, amount, expiryTs, newRoot)` sets
    /// leaf `note_id` to `note_leaf(note_id, commitment, amount, expiry_ts)`.
    NoteDeposited {
        note_id: u32,
        commitment: Felt252,
        #[serde(deserialize_with = "deserialize_u128_text")]
        amount: u128,
        expiry_ts: u64,
    },
    /// `ClosedLeafRetired(noteId, newRoot)` zeroes leaf `note_id`.
    ClosedLeafRetired { note_id: u32 },
}

/// The vault's note tree rebuilt from its logs. Deposits take consecutive
/// note ids from 0; a retirement zeroes a deposited, not yet retired leaf.
/// Each [`NoteTree::apply`] returns the new root, which the caller compares
/// with the event's own root.
#[derive(Clone)]
pub struct NoteTree {
    tree: MerkleTree,
    next_note_id: u32,
    retired: std::collections::BTreeSet<u32>,
}

impl Default for NoteTree {
    fn default() -> Self {
        Self::new()
    }
}

impl NoteTree {
    pub fn new() -> Self {
        Self {
            tree: MerkleTree::new(),
            next_note_id: 0,
            retired: Default::default(),
        }
    }

    pub fn root(&self) -> Felt252 {
        self.tree.root()
    }

    pub fn next_note_id(&self) -> u32 {
        self.next_note_id
    }

    pub fn apply(&mut self, event: &TreeEvent) -> Result<Felt252> {
        match *event {
            TreeEvent::NoteDeposited {
                note_id,
                commitment,
                amount,
                expiry_ts,
            } => {
                if note_id != self.next_note_id {
                    return Err(refusal(
                        codes::TREE_EVENT_INVALID,
                        format!(
                            "deposit of note {note_id} out of order (next note id {})",
                            self.next_note_id
                        ),
                    ));
                }
                self.tree.set_leaf(
                    note_id,
                    core::note_leaf(note_id, &commitment, amount, expiry_ts),
                );
                self.next_note_id = self
                    .next_note_id
                    .checked_add(1)
                    .ok_or_else(|| refusal(codes::TREE_EVENT_INVALID, "note ids exhausted"))?;
            }
            TreeEvent::ClosedLeafRetired { note_id } => {
                if note_id >= self.next_note_id || !self.retired.insert(note_id) {
                    return Err(refusal(
                        codes::TREE_EVENT_INVALID,
                        format!("note {note_id} has no leaf to retire"),
                    ));
                }
                self.tree.set_leaf(note_id, Felt252::ZERO);
            }
        }
        Ok(self.tree.root())
    }

    /// The path of a deposited, not retired note at the current root.
    pub fn path(&self, note_id: u32) -> Result<BrowserTreePath> {
        if note_id >= self.next_note_id || self.retired.contains(&note_id) {
            return Err(refusal(
                codes::TREE_EVENT_INVALID,
                format!("note {note_id} has no leaf in the rebuilt tree"),
            ));
        }
        Ok(BrowserTreePath {
            active_root: self.tree.root(),
            note_id,
            siblings: self.tree.get_siblings(note_id).to_vec(),
        })
    }
}

pub fn generate_deposit_params() -> DepositParams {
    loop {
        let secret = random_field();
        if !secret.is_zero() {
            return DepositParams {
                registration_commitment: core::registration_commitment(&secret),
                secret,
            };
        }
    }
}

pub fn confirm_deposit(
    config: &BrowserWalletConfig,
    args: ConfirmDepositArgs,
) -> Result<BrowserNoteState> {
    validate_state_identity(config, args.secret, args.amount)?;
    let blinding = random_scalar();
    let commitment = balance_commitment(
        args.amount,
        &blinding,
        &core::note_leaf(
            args.note_id,
            &core::registration_commitment(&args.secret),
            args.amount,
            args.expiry_ts,
        ),
    );
    Ok(BrowserNoteState {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        note_id: args.note_id,
        secret_s: args.secret,
        deposit_amount: args.amount,
        expiry_ts: args.expiry_ts,
        current_balance: args.amount,
        balance_blinding: blinding.to_hex(),
        current_commitment_x: commitment.x,
        current_commitment_y: commitment.y,
        current_anchor: core::GENESIS_ANCHOR,
        is_genesis: true,
        state_signature: None,
        prev_anchor: None,
        bound_at_state: 0,
    })
}

pub fn wallet_status(
    state: Option<&BrowserNoteState>,
    journal: Option<&PendingRequestJournal>,
) -> BrowserWalletStatus {
    BrowserWalletStatus {
        has_note: state.is_some(),
        pending_request: journal.is_some_and(|entry| entry.exists),
        note: state.map(|state| BrowserNoteStatus {
            note_id: state.note_id,
            deposit_amount: state.deposit_amount,
            current_balance: state.current_balance,
            expiry_ts: state.expiry_ts,
            is_genesis: state.is_genesis,
            current_anchor: state.current_anchor,
            current_commitment_x: state.current_commitment_x,
            current_commitment_y: state.current_commitment_y,
            bound_at_state: state.bound_at_state,
        }),
    }
}

/// `N(τ) = H(d_null', s, note_id, τ)` of the state: the nullifier its
/// requests spend and its exits publish.
pub fn withdrawal_nullifier(state: &BrowserNoteState) -> Felt252 {
    core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
}

/// `N(succ(N(τ)))`: the nullifier of the state's honest successor, which an
/// escape from this state publishes and only a request from that successor
/// spends (the evidence that defeats a stale escape).
pub fn successor_nullifier(state: &BrowserNoteState) -> Felt252 {
    core::successor_nullifier(&state.secret_s, state.note_id, &state.current_anchor)
}

pub fn prepare_request(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    proving_key: &[u8],
) -> Result<PreparedRequest> {
    let prover = load_request_prover(proving_key)?;
    prepare_request_with_prover(config, state, args, &prover)
}

/// Prove one request at `state`. The returned state records the request's
/// solvency bound as `bound_at_state` (C2): the first request proof at a state
/// fixes it, and a later one with another bound is refused with
/// [`codes::BOUND_FIXED_AT_STATE`] before any proof is made.
pub fn prepare_request_with_prover(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareRequestArgs,
    prover: &RequestProver,
) -> Result<PreparedRequest> {
    validate_state(config, state)?;
    require_bundle_setup(prover.setup_id(), "request proving key")?;
    if args.client_request_id.trim().is_empty() {
        anyhow::bail!("client_request_id is required");
    }
    let solvency_bound = if config.policy_enabled {
        config.policy_charge_cap
    } else {
        config.request_charge_cap
    };
    // 0 means "no request proof yet" in bound_at_state, so it can never be
    // a bound itself.
    if solvency_bound == 0 {
        anyhow::bail!("the solvency bound must be positive");
    }
    if state.bound_at_state != 0 && state.bound_at_state != solvency_bound {
        return Err(refusal(
            codes::BOUND_FIXED_AT_STATE,
            format!(
                "request proofs at this state use the bound {}; refusing a proof with bound {solvency_bound}",
                state.bound_at_state
            ),
        ));
    }
    if state.current_balance < solvency_bound {
        return Err(refusal(
            codes::INSUFFICIENT_BALANCE,
            format!("need {solvency_bound}, have {}", state.current_balance),
        ));
    }
    if !state.is_genesis && state.prev_anchor.is_none() {
        return Err(refusal(
            codes::PREV_ANCHOR_MISSING,
            "this signed state was saved without its predecessor's anchor; it can exit but not make requests",
        ));
    }
    let siblings = siblings_array(args.merkle_siblings)?;
    require_path(state, &args.active_root, &siblings)?;
    let payload_hash = canonical_payload_hash(args.payload.as_bytes());
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = stored_commitment(state, &current_blinding)?;
    let rerandomization = random_scalar();
    let anonymous = rerandomize(&current, &rerandomization)?;
    let nullifier = withdrawal_nullifier(state);
    let request_context = canonical_request_context(&args.client_request_id, &payload_hash);
    let public_inputs = RequestPublicInputsV2 {
        protocol_version: state.protocol_version,
        chain_id: state.chain_id,
        contract_address: state.contract_address,
        active_root: args.active_root,
        state_signing_key_x: config.state_signing_key.x,
        state_signing_key_y: config.state_signing_key.y,
        request_time: args.request_time,
        solvency_bound,
        request_nullifier: nullifier,
        authorization_tag: core::authorization_tag(&nullifier, &request_context),
        anonymous_commitment_x: anonymous.x,
        anonymous_commitment_y: anonymous.y,
    };
    let proof = prover
        .prove(
            &public_inputs,
            RequestWitnessData {
                secret: state.secret_s,
                request_context,
                note_id: state.note_id,
                deposit_amount: state.deposit_amount,
                expiry: state.expiry_ts,
                merkle_siblings: siblings,
                current_balance: state.current_balance,
                current_blinding,
                rerandomization,
                current_anchor: state.current_anchor,
                prev_anchor: state.prev_anchor,
                state_signature: state.state_signature,
            },
        )
        .context("generate request proof")?;
    let request = ApiRequestV2 {
        client_request_id: args.client_request_id.clone(),
        payload: args.payload,
        payload_hash,
        public_inputs,
        proof,
    };
    let journal = PendingRequestJournal {
        exists: true,
        client_request_id: args.client_request_id,
        nullifier,
        payload_hash,
        user_rerandomization: rerandomization,
        created_at_ms: args.created_at_ms,
        prepared_request: request.clone(),
    };
    let mut next = state.clone();
    next.bound_at_state = solvency_bound;
    Ok(PreparedRequest {
        request,
        journal,
        state: next,
    })
}

fn invalid_successor(check: &str, detail: impl std::fmt::Display) -> anyhow::Error {
    refusal(codes::INVALID_SUCCESSOR, format!("{check}: {detail}"))
}

/// Check a server response against S1–S6 and return the installed successor.
///
/// * S1: the response names the journal's request and nullifier, and the
///   journal was made at this state (`N(s, note_id, τ)`).
/// * S2: the payload hashes to `response_hash`.
/// * S6: the build-pinned state key signs `(next_commitment, next_anchor)`.
/// * S3: `charge <= bound_at_state`, and the journal's bound is that bound.
/// * S4: `next_anchor == next_anchor(N)`.
/// * S5: `server_update(C + ε·H, charge, δ) == next_commitment`.
///
/// A signed response that fails S3, S4 or S5 is refused with
/// [`codes::INVALID_SUCCESSOR`]. The successor has `prev_anchor = τ` and
/// `bound_at_state = 0`.
pub fn complete_response(
    config: &BrowserWalletConfig,
    args: CompleteResponseArgs,
) -> Result<BrowserNoteState> {
    let CompleteResponseArgs {
        state,
        journal,
        response,
    } = args;
    validate_state(config, &state)?;
    let current_blinding = parse_scalar(&state.balance_blinding)?;
    let current = stored_commitment(&state, &current_blinding)?;

    // S1
    if !journal.exists
        || response.client_request_id != journal.client_request_id
        || response.request_nullifier != journal.nullifier
    {
        return Err(refusal(
            codes::RESPONSE_IDENTITY_MISMATCH,
            "the response names another request or nullifier than the journal",
        ));
    }
    let nullifier = withdrawal_nullifier(&state);
    let proven = &journal.prepared_request.public_inputs;
    if journal.nullifier != nullifier
        || proven.request_nullifier != nullifier
        || proven.protocol_version != state.protocol_version
        || proven.chain_id != state.chain_id
        || proven.contract_address != state.contract_address
        || journal.prepared_request.client_request_id != journal.client_request_id
    {
        return Err(refusal(
            codes::JOURNAL_STATE_MISMATCH,
            "the journal was not made at this note state",
        ));
    }
    // S2
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        return Err(refusal(
            codes::RESPONSE_HASH_MISMATCH,
            "the response payload does not hash to response_hash",
        ));
    }
    // S6
    let message = core::state_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    if !verify_signature(
        &config.state_signing_key,
        &message,
        &response.next_state_signature,
    )? {
        return Err(refusal(
            codes::SUCCESSOR_SIGNATURE_INVALID,
            "the successor is not signed by the pinned state key",
        ));
    }
    // S3
    if state.bound_at_state == 0 || proven.solvency_bound != state.bound_at_state {
        return Err(invalid_successor(
            "S3",
            format!(
                "the journal's solvency bound {} is not this state's bound {}",
                proven.solvency_bound, state.bound_at_state
            ),
        ));
    }
    if response.charge_applied > state.bound_at_state {
        return Err(invalid_successor(
            "S3",
            format!(
                "charge {} exceeds the state's bound {}",
                response.charge_applied, state.bound_at_state
            ),
        ));
    }
    // S4
    let expected_anchor = core::next_anchor(&nullifier);
    if response.next_anchor != expected_anchor
        || response.next_anchor.is_zero()
        || response.next_anchor == core::GENESIS_ANCHOR
    {
        return Err(invalid_successor(
            "S4",
            "the successor is not at the derived anchor next_anchor(N)",
        ));
    }
    // S5
    let anonymous = rerandomize(&current, &journal.user_rerandomization)?;
    let expected = server_update(
        &anonymous,
        response.charge_applied,
        &response.blind_delta_srv,
    )?;
    if expected != response.next_commitment {
        return Err(invalid_successor(
            "S5",
            "the successor commitment is not C + ε·H − charge·G + δ·H",
        ));
    }
    let next_blinding = add_blindings(
        &add_blindings(&current_blinding, &journal.user_rerandomization),
        &response.blind_delta_srv,
    );
    let mut next = state;
    next.prev_anchor = Some(next.current_anchor);
    next.current_balance = next
        .current_balance
        .checked_sub(response.charge_applied)
        .ok_or_else(|| invalid_successor("S3", "charge exceeds balance"))?;
    next.balance_blinding = next_blinding.to_hex();
    next.current_commitment_x = response.next_commitment.x;
    next.current_commitment_y = response.next_commitment.y;
    next.current_anchor = response.next_anchor;
    next.is_genesis = false;
    next.state_signature = Some(response.next_state_signature);
    next.bound_at_state = 0;
    Ok(next)
}

/// What a finalized response proves about a state whose request journal (or
/// its rerandomization ε) is lost: the response passes S1, S2, S4 and S6
/// ([`check_unrecoverable_response`]), so its charge may lower an escape's
/// concession to `min(charge, bound_at_state)` (design §6.4 E3, lost ε).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UnrecoverableResponse {
    pub charge_applied: u128,
    pub next_anchor: Felt252,
}

/// Check a finalized response at `state` that cannot be installed because
/// its journal is lost: S1 (it names this state's nullifier `N(s, note_id,
/// τ)`), S2 (payload hash), S6 (the pinned state key signs the successor) and
/// S4 (the successor is at `next_anchor(N)`). S3 and S5 need the journal.
pub fn check_unrecoverable_response(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    response: &RequestResponseV2,
) -> Result<UnrecoverableResponse> {
    validate_state(config, state)?;
    let nullifier = withdrawal_nullifier(state);
    // S1
    if response.request_nullifier != nullifier {
        return Err(refusal(
            codes::RESPONSE_IDENTITY_MISMATCH,
            "the response names another nullifier than this state's",
        ));
    }
    // S2
    if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
        return Err(refusal(
            codes::RESPONSE_HASH_MISMATCH,
            "the response payload does not hash to response_hash",
        ));
    }
    // S6
    let message = core::state_message(
        state.protocol_version,
        state.chain_id,
        &state.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    if !verify_signature(
        &config.state_signing_key,
        &message,
        &response.next_state_signature,
    )? {
        return Err(refusal(
            codes::SUCCESSOR_SIGNATURE_INVALID,
            "the successor is not signed by the pinned state key",
        ));
    }
    // S4
    if response.next_anchor != core::next_anchor(&nullifier) {
        return Err(invalid_successor(
            "S4",
            "the successor is not at the derived anchor next_anchor(N)",
        ));
    }
    Ok(UnrecoverableResponse {
        charge_applied: response.charge_applied,
        next_anchor: response.next_anchor,
    })
}

/// A Merkle path to check against a note ([`note_path_matches`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NotePathArgs {
    pub active_root: Felt252,
    pub siblings: Vec<Felt252>,
}

/// Whether `siblings` lead from `state`'s leaf to `active_root`. The wallet
/// keeps a deposit-time path only when it does: the vault accepts any root it
/// ever held, so that path proves exits for the note's whole life
/// (Amendment A1).
pub fn note_path_matches(state: &BrowserNoteState, args: NotePathArgs) -> Result<bool> {
    let siblings = siblings_array(args.siblings)?;
    Ok(core::merkle_root(state.note_id, &state_note_leaf(state), &siblings) == args.active_root)
}

enum WithdrawalMode {
    Escape {
        destination: [u8; 20],
        conceded: u128,
    },
    Mutual {
        destination: [u8; 20],
    },
    Ownership,
}

impl WithdrawalMode {
    fn kind(&self) -> WithdrawalKind {
        match self {
            Self::Escape { .. } => WithdrawalKind::Escape,
            Self::Mutual { .. } => WithdrawalKind::MutualClose,
            Self::Ownership => WithdrawalKind::Ownership,
        }
    }
}

fn parse_withdrawal_mode(
    args: &PrepareWithdrawalArgs,
    state: &BrowserNoteState,
) -> Result<WithdrawalMode> {
    let destination = args.destination.as_deref().map(parse_address).transpose()?;
    let payout_destination = || {
        destination
            .filter(|address| *address != [0u8; 20])
            .ok_or_else(|| {
                refusal(
                    codes::WITHDRAWAL_ARGS,
                    format!("a {} withdrawal needs a nonzero destination", args.mode),
                )
            })
    };
    let no_concession = || match args.conceded {
        None | Some(0) => Ok(()),
        Some(_) => Err(refusal(
            codes::WITHDRAWAL_ARGS,
            format!(
                "only an escape may concede; a {} proof concedes 0",
                args.mode
            ),
        )),
    };
    let no_clearance = || match args.clearance {
        None => Ok(()),
        Some(_) => Err(refusal(
            codes::WITHDRAWAL_ARGS,
            format!("a {} proof takes no clearance", args.mode),
        )),
    };
    if args.valid_until == 0 {
        return Err(refusal(codes::WITHDRAWAL_ARGS, "valid_until must be set"));
    }
    match args.mode.as_str() {
        "escape" => {
            no_clearance()?;
            let conceded = args.conceded.ok_or_else(|| {
                refusal(
                    codes::WITHDRAWAL_ARGS,
                    "an escape needs an explicit conceded amount",
                )
            })?;
            if conceded > state.bound_at_state {
                return Err(refusal(
                    codes::CONCEDED_EXCEEDS_BOUND,
                    format!(
                        "conceded {conceded} exceeds the state's bound {}",
                        state.bound_at_state
                    ),
                ));
            }
            Ok(WithdrawalMode::Escape {
                destination: payout_destination()?,
                conceded,
            })
        }
        "mutual" => {
            no_concession()?;
            Ok(WithdrawalMode::Mutual {
                destination: payout_destination()?,
            })
        }
        "ownership" => {
            no_concession()?;
            no_clearance()?;
            if destination.is_some_and(|address| address != [0u8; 20]) {
                return Err(refusal(
                    codes::WITHDRAWAL_ARGS,
                    "an ownership proof has no destination",
                ));
            }
            Ok(WithdrawalMode::Ownership)
        }
        other => Err(refusal(
            codes::WITHDRAWAL_ARGS,
            format!("withdrawal mode must be escape, mutual or ownership, not {other:?}"),
        )),
    }
}

pub fn prepare_withdrawal(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareWithdrawalArgs,
    proving_key: &[u8],
) -> Result<WithdrawalPlan> {
    let prover = load_withdrawal_prover(proving_key)?;
    prepare_withdrawal_with_prover(config, state, args, &prover)
}

/// Prove an exit from `state`: kind 0 (`escape`), 1 (`mutual`) or 2
/// (`ownership`), see [`PrepareWithdrawalArgs`]. The statement carries the
/// canonical `withdrawal_nullifier`, `next_nullifier` (the successor
/// nullifier for an escape, 0 otherwise), `final_balance = B − conceded` and
/// `valid_until`. Exits never need `prev_anchor`.
pub fn prepare_withdrawal_with_prover(
    config: &BrowserWalletConfig,
    state: &BrowserNoteState,
    args: PrepareWithdrawalArgs,
    prover: &WithdrawalProver,
) -> Result<WithdrawalPlan> {
    validate_state(config, state)?;
    require_bundle_setup(prover.setup_id(), "withdrawal proving key")?;
    let mode = parse_withdrawal_mode(&args, state)?;
    let siblings = siblings_array(args.merkle_siblings)?;
    require_path(state, &args.active_root, &siblings)?;
    let state_blinding = parse_scalar(&state.balance_blinding)?;
    stored_commitment(state, &state_blinding)?;
    let nullifier = withdrawal_nullifier(state);
    let clearance_signature = match &mode {
        WithdrawalMode::Mutual { .. } => {
            let clearance = args.clearance.as_ref().ok_or_else(|| {
                refusal(
                    codes::CLEARANCE_INVALID,
                    "a mutual close needs the server clearance",
                )
            })?;
            if clearance.withdrawal_nullifier != nullifier {
                return Err(refusal(
                    codes::CLEARANCE_INVALID,
                    "the clearance names another nullifier",
                ));
            }
            let message = core::clearance_message(
                state.protocol_version,
                state.chain_id,
                &state.contract_address,
                &nullifier,
            );
            if !verify_signature(
                &config.clearance_signing_key,
                &message,
                &clearance.signature,
            )? {
                return Err(refusal(
                    codes::CLEARANCE_INVALID,
                    "the clearance is not signed by the pinned clearance key",
                ));
            }
            Some(clearance.signature)
        }
        WithdrawalMode::Escape { .. } | WithdrawalMode::Ownership => None,
    };
    let (destination, conceded) = match mode {
        WithdrawalMode::Escape {
            destination,
            conceded,
        } => (destination, conceded),
        WithdrawalMode::Mutual { destination } => (destination, 0),
        WithdrawalMode::Ownership => ([0u8; 20], 0),
    };
    let witness = WithdrawalWitnessData {
        secret: state.secret_s,
        deposit_amount: state.deposit_amount,
        expiry: state.expiry_ts,
        merkle_siblings: siblings,
        state_balance: state.current_balance,
        state_blinding,
        current_anchor: state.current_anchor,
        kind: mode.kind(),
        conceded,
        valid_until: args.valid_until,
        state_signature: state.state_signature,
        clearance_signature,
    };
    let public_inputs = withdrawal_public_inputs(
        &WithdrawalStatementParams {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root: args.active_root,
            state_signing_key: config.state_signing_key.clone(),
            clearance_signing_key: config.clearance_signing_key.clone(),
            note_id: state.note_id,
            destination,
        },
        &witness,
    )?;
    let proof = prover
        .prove(&public_inputs, witness)
        .context("generate withdrawal proof")?;
    Ok(WithdrawalPlan {
        mode: args.mode,
        public_inputs,
        proof,
    })
}

/// Verify a request proof (base64 of its 256 bytes) under a request
/// verifying key file of this bundle's setup: the stale-device pre-check
/// (§6.4 E4) checks the operator's evidence at `N⁺` with it.
pub fn verify_request(
    public_inputs: &RequestPublicInputsV2,
    proof_base64: &str,
    verifying_key: &[u8],
) -> Result<bool> {
    let verifier = load_request_verifier(verifying_key)?;
    verifier.verify(
        public_inputs,
        &Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: proof_base64.to_string(),
        },
    )
}

fn validate_state_identity(
    config: &BrowserWalletConfig,
    secret: Felt252,
    amount: u128,
) -> Result<()> {
    if config.protocol_version != 2 {
        anyhow::bail!("unsupported protocol version {}", config.protocol_version);
    }
    if config.contract_address.is_zero() || secret.is_zero() || amount == 0 {
        anyhow::bail!("deposit identity contains a zero value");
    }
    Ok(())
}

fn validate_state(config: &BrowserWalletConfig, state: &BrowserNoteState) -> Result<()> {
    if state.protocol_version != config.protocol_version
        || state.chain_id != config.chain_id
        || state.contract_address != config.contract_address
    {
        return Err(refusal(
            codes::STATE_INVALID,
            "wallet state belongs to a different zkAPI deployment",
        ));
    }
    validate_state_identity(config, state.secret_s, state.deposit_amount)?;
    let genesis = state.current_anchor == core::GENESIS_ANCHOR;
    if state.is_genesis != genesis
        || (genesis
            && (state.state_signature.is_some()
                || state.prev_anchor.is_some()
                || state.current_balance != state.deposit_amount))
        || (!genesis && state.state_signature.is_none())
        || state.current_balance > state.deposit_amount
        || state.bound_at_state > state.current_balance
    {
        return Err(refusal(
            codes::STATE_INVALID,
            "the note state is inconsistent (genesis flag, signature, balance or bound)",
        ));
    }
    Ok(())
}

fn stored_commitment(state: &BrowserNoteState, blinding: &Felt252) -> Result<CurvePointWire> {
    let commitment = balance_commitment(state.current_balance, blinding, &state_note_leaf(state));
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        return Err(refusal(
            codes::STATE_INVALID,
            "persisted balance commitment is inconsistent",
        ));
    }
    Ok(commitment)
}

fn require_path(
    state: &BrowserNoteState,
    active_root: &Felt252,
    siblings: &[Felt252; MERKLE_DEPTH],
) -> Result<()> {
    if core::merkle_root(state.note_id, &state_note_leaf(state), siblings) != *active_root {
        return Err(refusal(
            codes::MERKLE_PATH_MISMATCH,
            "the Merkle path does not lead from this note's leaf to active_root",
        ));
    }
    Ok(())
}

fn parse_scalar(value: &str) -> Result<Felt252> {
    Felt252::from_hex(value).map_err(|error| anyhow!("invalid balance blinding: {error}"))
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH]> {
    let count = values.len();
    values
        .try_into()
        .map_err(|_| anyhow!("expected {MERKLE_DEPTH} Merkle siblings, got {count}"))
}

fn parse_address(value: &str) -> Result<[u8; 20]> {
    let raw = value.strip_prefix("0x").unwrap_or(value);
    if raw.len() != 40 {
        anyhow::bail!("destination must be a 20-byte hex address");
    }
    let mut address = [0u8; 20];
    for (index, chunk) in raw.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        address[index] = u8::from_str_radix(
            std::str::from_utf8(chunk).context("address is not UTF-8")?,
            16,
        )
        .context("address contains non-hex characters")?;
    }
    Ok(address)
}

fn state_note_leaf(state: &BrowserNoteState) -> Felt252 {
    core::note_leaf(
        state.note_id,
        &core::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    )
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use super::*;
    use wasm_bindgen::prelude::*;

    fn encode<T: Serialize>(value: &T) -> std::result::Result<String, JsValue> {
        serde_json::to_string(value).map_err(js_error)
    }

    fn decode<T: for<'de> Deserialize<'de>>(value: &str) -> std::result::Result<T, JsValue> {
        serde_json::from_str(value).map_err(js_error)
    }

    fn js_error(error: impl std::fmt::Display) -> JsValue {
        JsValue::from_str(&error.to_string())
    }

    fn js_anyhow(error: anyhow::Error) -> JsValue {
        // `{:#}` keeps the code prefix and appends the causes.
        JsValue::from_str(&format!("{error:#}"))
    }

    #[wasm_bindgen(start)]
    pub fn start() {
        console_error_panic_hook::set_once();
    }

    #[wasm_bindgen]
    pub fn browser_circuit_id() -> String {
        CIRCUIT_ID.to_owned()
    }

    /// The setup this bundle loads keys of: "dev" or "mpc-1".
    #[wasm_bindgen]
    pub fn browser_setup_id() -> String {
        bundle_setup_id().to_owned()
    }

    #[wasm_bindgen]
    pub fn browser_generate_deposit() -> std::result::Result<String, JsValue> {
        encode(&generate_deposit_params())
    }

    #[wasm_bindgen]
    pub fn browser_confirm_deposit(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&confirm_deposit(&decode(config_json)?, decode(args_json)?).map_err(js_anyhow)?)
    }

    #[wasm_bindgen]
    pub fn browser_wallet_status(
        state_json: Option<String>,
        journal_json: Option<String>,
    ) -> std::result::Result<String, JsValue> {
        let state = state_json.as_deref().map(decode).transpose()?;
        let journal = journal_json.as_deref().map(decode).transpose()?;
        encode(&wallet_status(state.as_ref(), journal.as_ref()))
    }

    #[wasm_bindgen]
    pub fn browser_prepare_request(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_request(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_anyhow)?,
        )
    }

    #[wasm_bindgen]
    pub struct BrowserRequestProver {
        prover: RequestProver,
    }

    #[wasm_bindgen]
    impl BrowserRequestProver {
        #[wasm_bindgen(constructor)]
        pub fn new(proving_key: &[u8]) -> std::result::Result<BrowserRequestProver, JsValue> {
            Ok(Self {
                prover: load_request_prover(proving_key).map_err(js_anyhow)?,
            })
        }

        pub fn prepare_request(
            &self,
            config_json: &str,
            state_json: &str,
            args_json: &str,
        ) -> std::result::Result<String, JsValue> {
            encode(
                &prepare_request_with_prover(
                    &decode(config_json)?,
                    &decode(state_json)?,
                    decode(args_json)?,
                    &self.prover,
                )
                .map_err(js_anyhow)?,
            )
        }
    }

    #[wasm_bindgen]
    pub fn browser_complete_response(
        config_json: &str,
        args_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(&complete_response(&decode(config_json)?, decode(args_json)?).map_err(js_anyhow)?)
    }

    /// S1, S2, S4 and S6 of a response whose journal is lost; returns
    /// `{charge_applied, next_anchor}` (JSON).
    #[wasm_bindgen]
    pub fn browser_check_unrecoverable_response(
        config_json: &str,
        state_json: &str,
        response_json: &str,
    ) -> std::result::Result<String, JsValue> {
        encode(
            &check_unrecoverable_response(
                &decode(config_json)?,
                &decode(state_json)?,
                &decode(response_json)?,
            )
            .map_err(js_anyhow)?,
        )
    }

    /// Whether `{active_root, siblings}` (JSON) is a path of the state's note.
    #[wasm_bindgen]
    pub fn browser_note_path_matches(
        state_json: &str,
        path_json: &str,
    ) -> std::result::Result<bool, JsValue> {
        note_path_matches(&decode(state_json)?, decode(path_json)?).map_err(js_anyhow)
    }

    #[wasm_bindgen]
    pub fn browser_withdrawal_nullifier(state_json: &str) -> std::result::Result<String, JsValue> {
        encode(&withdrawal_nullifier(&decode(state_json)?))
    }

    #[wasm_bindgen]
    pub fn browser_successor_nullifier(state_json: &str) -> std::result::Result<String, JsValue> {
        encode(&successor_nullifier(&decode(state_json)?))
    }

    #[wasm_bindgen]
    pub fn browser_tree_path(
        snapshot_json: &str,
        note_id: u32,
        require_existing: bool,
    ) -> std::result::Result<String, JsValue> {
        encode(&tree_path(decode(snapshot_json)?, note_id, require_existing).map_err(js_anyhow)?)
    }

    #[wasm_bindgen]
    pub fn browser_tree_path_from_leaves(
        leaves_json: &str,
        note_id: u32,
    ) -> std::result::Result<String, JsValue> {
        encode(&tree_path_from_leaves(decode(leaves_json)?, note_id).map_err(js_anyhow)?)
    }

    /// The note tree rebuilt from vault logs (§6.6): `apply` one event, in log
    /// order, and compare the returned root with the event's.
    #[wasm_bindgen]
    pub struct BrowserNoteTree {
        tree: NoteTree,
    }

    #[wasm_bindgen]
    impl BrowserNoteTree {
        #[wasm_bindgen(constructor)]
        #[allow(clippy::new_without_default)]
        pub fn new() -> BrowserNoteTree {
            Self {
                tree: NoteTree::new(),
            }
        }

        /// Apply one `TreeEvent` (JSON) and return the new root (JSON felt).
        pub fn apply(&mut self, event_json: &str) -> std::result::Result<String, JsValue> {
            encode(&self.tree.apply(&decode(event_json)?).map_err(js_anyhow)?)
        }

        pub fn root(&self) -> std::result::Result<String, JsValue> {
            encode(&self.tree.root())
        }

        pub fn next_note_id(&self) -> u32 {
            self.tree.next_note_id()
        }

        pub fn path(&self, note_id: u32) -> std::result::Result<String, JsValue> {
            encode(&self.tree.path(note_id).map_err(js_anyhow)?)
        }
    }

    #[wasm_bindgen]
    pub fn browser_prepare_withdrawal(
        config_json: &str,
        state_json: &str,
        args_json: &str,
        proving_key: &[u8],
    ) -> std::result::Result<String, JsValue> {
        encode(
            &prepare_withdrawal(
                &decode(config_json)?,
                &decode(state_json)?,
                decode(args_json)?,
                proving_key,
            )
            .map_err(js_anyhow)?,
        )
    }

    /// `true` iff the proof verifies for the statement under the request
    /// verifying key file `verifying_key`; an error for malformed input.
    #[wasm_bindgen]
    pub fn browser_verify_request(
        public_json: &str,
        proof_base64: &str,
        verifying_key: &[u8],
    ) -> std::result::Result<bool, JsValue> {
        verify_request(&decode(public_json)?, proof_base64, verifying_key).map_err(js_anyhow)
    }
}

#[cfg(test)]
mod tests;
