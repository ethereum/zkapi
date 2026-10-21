//! zkAPI v2 wallet for circuit `zkapi-v2-concession-v1`: compact Groth16
//! proofs, note-bound nullifiers, derived successor anchors and the three
//! withdrawal kinds (escape, mutual close, ownership proof).
//!
//! The client rules of design §6.1–§6.3 live here:
//! - S1–S6 before a successor is installed, with S3 against
//!   `bound_at_state`; a correctly signed successor failing S3, S4 or S5 is
//!   archived as `invalid_successor`, one arriving after an exit proof was
//!   released as `late_successor`;
//! - C2 (one bound per state), C3 (no request proof while `exit_lock.json`
//!   is held, and only the lock mode's exit proofs), C4 (near expiry) and C5
//!   (no request from a state whose ownership proof was sent);
//! - the §6.2 write orders: a request writes the bound, then the journal,
//!   and only then may it be transmitted; an install writes the new state,
//!   then the archive disposition, then removes the journal; an exit proof is
//!   generated only under a durable lock and recorded as released before it
//!   is returned.
//!
//! C1 (one lock around all of this) is the caller's: the companion's
//! process-wide `WalletLock`.

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_field, random_scalar, rerandomize, server_update,
    verify_signature, withdrawal_public_inputs, RequestProver, RequestWitnessData,
    WithdrawalProver, WithdrawalStatementParams, WithdrawalWitnessData,
};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProofV2C, ClearanceRequestV2C, ClearanceResponseV2,
    CurvePointWire, ErrorResponse, Groth16ProofWire, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2, WithdrawalKind, WithdrawalPublicInputsV2C, MERKLE_DEPTH,
};

use crate::config::{ClientConfig, ClientProofMode};
use crate::error::ClientError;
use crate::exit_lock::{ExitLock, ExitMode, ReleasedProof, EXIT_LOCK_FILE};
use crate::exit_policy::{self, disposition, NoteChainStatus};
use crate::journal::{
    archive_request, latest_records, read_archive, ArchiveListing, ArchivedRequest,
    PendingRequestJournal,
};
use crate::note_state::{DepositPath, NoteState};

/// Delays before resending the identical clearance body after a retriable
/// `stale_root` (the server has not yet observed the indexer's root) or
/// `capacity_exhausted` answer.
#[cfg(not(test))]
const CLEARANCE_RETRY_DELAYS_MS: [u64; 4] = [1_000, 2_000, 4_000, 8_000];
#[cfg(test)]
const CLEARANCE_RETRY_DELAYS_MS: [u64; 4] = [1, 2, 4, 8];

/// Lifetime of an escape (kind 0) or mutual-close (kind 1) proof: the vault
/// refuses it after `valid_until = now + 10,800`.
pub const EXIT_PROOF_VALIDITY_SECONDS: u64 = 10_800;
/// Lifetime of an ownership proof (kind 2). The server accepts one with
/// `now <= valid_until <= now + 3,600` by its own clock.
pub const OWNERSHIP_PROOF_VALIDITY_SECONDS: u64 = 3_600;
/// How far ahead of the server's clock this device's clock may run before an
/// ownership proof's `valid_until` exceeds the server's 3,600-second window.
pub const OWNERSHIP_CLOCK_SKEW_MARGIN_SECONDS: u64 = 300;
#[cfg(test)]
use crate::exit_policy::OWNERSHIP_RESEND_MARGIN_SECONDS;

/// C5's record (§6.2 "ownership-proof-sent flag"): the note state whose
/// ownership proof was sent, or may have been. No request proof is made from
/// that state afterwards.
pub const OWNERSHIP_PROOF_MARKER_FILE: &str = "oa-ownership-proof-sent.json";

fn ownership_proof_still_valid() -> ClientError {
    ClientError::ExitLockConflict(
        "an ownership proof of this state is still valid; another is made only after it expires"
            .into(),
    )
}

#[derive(Serialize, Deserialize)]
struct OwnershipProofMarker {
    version: u8,
    note_id: u32,
    nullifier: Felt252,
    /// The proof sent and its `valid_until` (0 and none in markers of
    /// earlier builds): C3's one live ownership proof of the state outlives
    /// the lock it was made under, which the user may cancel (E6).
    #[serde(default)]
    valid_until: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ownership: Option<ClearanceOwnershipProofV2C>,
}

pub struct Wallet {
    config: ClientConfig,
    state: Option<NoteState>,
    state_path: PathBuf,
    journal_path: PathBuf,
    archive_dir: PathBuf,
    exit_lock_path: PathBuf,
    ownership_marker_path: PathBuf,
    /// E0: the bound on each operator call while exiting.
    call_timeout: Option<std::time::Duration>,
}

impl Wallet {
    pub fn new(config: ClientConfig) -> Result<Self, ClientError> {
        let state_dir = PathBuf::from(&config.state_dir);
        std::fs::create_dir_all(&state_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&state_dir, std::fs::Permissions::from_mode(0o700))?;
        }
        let state_path = state_dir.join("note_state.json");
        let journal_path = state_dir.join("pending_journal.json");
        let archive_dir = state_dir.join("request_archive");
        let state = state_path
            .exists()
            .then(|| NoteState::load(&state_path))
            .transpose()?;
        Ok(Self {
            config,
            state,
            state_path,
            journal_path,
            archive_dir,
            exit_lock_path: state_dir.join(EXIT_LOCK_FILE),
            ownership_marker_path: state_dir.join(OWNERSHIP_PROOF_MARKER_FILE),
            call_timeout: None,
        })
    }

    /// Bound every later operator call (recovery and clearance) by `timeout`,
    /// connect and full body included (E0's `CALL_TIMEOUT` in exit mode).
    pub fn set_call_timeout(&mut self, timeout: Option<std::time::Duration>) {
        self.call_timeout = timeout;
    }

    fn operator_request(
        &self,
        method: reqwest::Method,
        target: String,
    ) -> Result<reqwest::RequestBuilder, ClientError> {
        let request = crate::testnet_auth::request(
            self.config.chain_id,
            &self.config.server_url,
            method,
            target,
        )?;
        Ok(match self.call_timeout {
            Some(timeout) => request.timeout(timeout),
            None => request,
        })
    }

    pub fn state(&self) -> Option<&NoteState> {
        self.state.as_ref()
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub fn has_pending_request(&self) -> bool {
        PendingRequestJournal::read(&self.journal_path)
            .ok()
            .flatten()
            .is_some()
    }

    pub fn get_pending_journal(&self) -> Result<Option<PendingRequestJournal>, ClientError> {
        PendingRequestJournal::read(&self.journal_path)
    }

    /// Return the durable, already-proved request for an idempotent transport
    /// retry. Older journals may not contain the full request.
    pub fn pending_api_request(&self) -> Result<Option<ApiRequestV2>, ClientError> {
        Ok(PendingRequestJournal::read(&self.journal_path)?
            .and_then(|journal| journal.prepared_request))
    }

    pub fn generate_deposit_params(&self) -> (Felt252, Felt252) {
        loop {
            let secret = random_field();
            if !secret.is_zero() {
                return (secret, core::registration_commitment(&secret));
            }
        }
    }

    pub fn confirm_deposit(
        &mut self,
        secret: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry: u64,
    ) -> Result<(), ClientError> {
        self.confirm_deposit_with_path(secret, note_id, deposit_amount, expiry, None)
    }

    /// Install the genesis state of a deposit, keeping its Merkle path at the
    /// root the deposit set (Amendment A1) when the caller has it: the vault
    /// accepts that root for every later exit. The path must prove the note's
    /// leaf at that root.
    pub fn confirm_deposit_with_path(
        &mut self,
        secret: Felt252,
        note_id: u32,
        deposit_amount: u128,
        expiry: u64,
        deposit_path: Option<DepositPath>,
    ) -> Result<(), ClientError> {
        if self.state.is_some() {
            return Err(ClientError::NoteAlreadyExists);
        }
        let leaf = core::note_leaf(
            note_id,
            &core::registration_commitment(&secret),
            deposit_amount,
            expiry,
        );
        if let Some(path) = &deposit_path {
            check_path(note_id, &leaf, path)?;
        }
        let blinding = random_scalar();
        let commitment = balance_commitment(deposit_amount, &blinding, &leaf);
        let mut state = NoteState::new_from_deposit(
            self.config.protocol_version,
            self.config.chain_id,
            self.config.contract_address,
            note_id,
            secret,
            deposit_amount,
            expiry,
            blinding.to_hex(),
            commitment.x,
            commitment.y,
        );
        state.deposit_path = deposit_path;
        state.save(&self.state_path)?;
        self.state = Some(state);
        Ok(())
    }

    /// Save a Merkle path of the note at a root the vault held (Amendment
    /// A1), for a note confirmed without one. The path must prove the note's
    /// leaf at `path.root`; the caller checks that the vault knows the root.
    pub fn save_deposit_path(&mut self, path: DepositPath) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        check_path(state.note_id, &state_note_leaf(state), &path)?;
        let mut next = state.clone();
        next.deposit_path = Some(path);
        self.persist_state(next)
    }

    /// The note's saved Merkle path (Amendment A1), if any.
    pub fn deposit_path(&self) -> Option<&DepositPath> {
        self.state
            .as_ref()
            .and_then(|state| state.deposit_path.as_ref())
    }

    pub async fn request_flow(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<RequestResponseV2, ClientError> {
        let request = self.prepare_request(payload, payload_hash, active_root, merkle_siblings)?;
        let response = crate::testnet_auth::request(
            self.config.chain_id,
            &self.config.server_url,
            reqwest::Method::POST,
            format!(
                "{}/v2/requests",
                self.config.server_url.trim_end_matches('/')
            ),
        )?
        .json(&request)
        .send()
        .await
        .map_err(|error| ClientError::ServerError(error.to_string()))?;
        let response = crate::testnet_auth::check_response(response)?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|error| ClientError::ServerError(error.to_string()))?;
        if !status.is_success() {
            if let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) {
                if error.error_code == "stale_root" {
                    // Unsigned: kept in the archive, where a later receipt
                    // can still be installed from it.
                    self.archive_pending_request(disposition::DISCARDED_STALE_ROOT)?;
                    return Err(ClientError::StaleRoot);
                }
                return Err(ClientError::ServerError(format!(
                    "{}: {}",
                    error.error_code, error.error_message
                )));
            }
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
        let response: RequestResponseV2 = serde_json::from_str(&body)
            .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
        self.complete_pending_response(&response)?;
        Ok(response)
    }

    /// The solvency bound the wallet's configuration asks for.
    pub fn configured_solvency_bound(&self) -> u128 {
        if self.config.policy_enabled {
            self.config.policy_charge_cap
        } else {
            self.config.request_charge_cap
        }
    }

    /// Generate and durably journal one zkAPI request without submitting it,
    /// with the configured solvency bound.
    pub fn prepare_request(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<ApiRequestV2, ClientError> {
        let bound = self.configured_solvency_bound();
        self.prepare_request_with_bound(payload, payload_hash, active_root, merkle_siblings, bound)
    }

    /// Whether a request proof could be prepared from the current state now:
    /// the refusals of C3, C4 and C5, before any proof work.
    pub fn check_request_allowed(&self) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        // C3: no request proof while an exit of this note is in progress.
        if self
            .exit_lock()?
            .is_some_and(|lock| lock.note_id == state.note_id)
        {
            return Err(ClientError::ExitLocked);
        }
        // C5: never from a state whose ownership proof was sent.
        if self.ownership_proof_sent_at_current_state()? {
            return Err(ClientError::OwnershipProofSent);
        }
        // C4: leave room for settlement before the latest exit start.
        let must_initiate_by = exit_policy::must_initiate_by(state.expiry_ts);
        if exit_policy::note_near_expiry(
            now_seconds(),
            self.config.settlement_window_seconds,
            must_initiate_by,
        ) {
            return Err(ClientError::NoteNearExpiry);
        }
        Ok(())
    }

    /// Generate and durably journal one zkAPI request at `solvency_bound`
    /// without submitting it. The write order is §6.2's: (1) the state with
    /// `bound_at_state`, (2) the journal; the caller transmits only after
    /// this returns. Every request proof at a state carries the same bound
    /// (C2): a different one is refused with `bound_fixed_at_state`.
    pub fn prepare_request_with_bound(
        &mut self,
        payload: &str,
        payload_hash: Felt252,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        solvency_bound: u128,
    ) -> Result<ApiRequestV2, ClientError> {
        if self.has_pending_request() {
            return Err(ClientError::PendingRequest);
        }
        if canonical_payload_hash(payload.as_bytes()) != payload_hash {
            return Err(ClientError::InvalidResponse(
                "payload_hash does not match payload bytes".to_string(),
            ));
        }
        self.check_request_allowed()?;
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        if state.current_balance < solvency_bound {
            return Err(ClientError::InsufficientBalance {
                needed: solvency_bound,
                available: state.current_balance,
            });
        }
        // C2: one bound per state.
        if state.bound_at_state != 0 && state.bound_at_state != solvency_bound {
            return Err(ClientError::BoundFixedAtState {
                bound: state.bound_at_state,
                requested: solvency_bound,
            });
        }

        let siblings = siblings_array(merkle_siblings)?;
        let current_blinding = parse_scalar(&state.balance_blinding)?;
        let expected_current = balance_commitment(
            state.current_balance,
            &current_blinding,
            &state_note_leaf(state),
        );
        ensure_stored_commitment(state, &expected_current)?;
        // The request circuit checks a signed state's anchor against its
        // predecessor's nullifier. Without the predecessor anchor no request
        // can be proved from this state (exits do not need it).
        let prev_anchor = if state.current_anchor == core::GENESIS_ANCHOR {
            None
        } else {
            Some(state.prev_anchor.ok_or(ClientError::PrevAnchorMissing)?)
        };
        // Write order step 1: the bound is durable before any proof exists.
        if state.bound_at_state == 0 {
            let mut bound = state.clone();
            bound.bound_at_state = solvency_bound;
            self.persist_state(bound)?;
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let rerandomization = random_scalar();
        let anonymous = rerandomize(&expected_current, &rerandomization)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let nullifier = state_nullifier(state);
        let client_request_id = uuid::Uuid::new_v4().to_string();
        let request_context = canonical_request_context(&client_request_id, &payload_hash);
        let public_inputs = RequestPublicInputsV2 {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key_x: self.config.state_signing_key.x,
            state_signing_key_y: self.config.state_signing_key.y,
            request_time: now_seconds(),
            solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let prover = RequestProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
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
                    prev_anchor,
                    state_signature: state.state_signature,
                },
            )
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;

        let request = ApiRequestV2 {
            client_request_id: client_request_id.clone(),
            payload: payload.to_string(),
            payload_hash,
            public_inputs,
            proof,
        };
        // Write order step 2: the journal, before the request can leave.
        PendingRequestJournal::write(
            &self.journal_path,
            &PendingRequestJournal {
                exists: true,
                client_request_id,
                nullifier,
                payload_hash,
                user_rerandomization: rerandomization,
                created_at_ms: now_ms(),
                prepared_request: Some(request.clone()),
            },
        )?;
        Ok(request)
    }

    /// Verify a finalized response for the currently journaled request (S1–
    /// S6), persist the next note state, and clear the journal after the
    /// state is safe on disk.
    ///
    /// A correctly signed response that fails S3, S4 or S5 archives the
    /// journal as `invalid_successor` (§6.1). A valid response arriving after
    /// an exit proof of this state was released archives it as
    /// `late_successor` (§6.4 E4 step 6); E6 installs it later.
    pub fn complete_pending_response(
        &mut self,
        response: &RequestResponseV2,
    ) -> Result<(), ClientError> {
        let journal =
            PendingRequestJournal::read(&self.journal_path)?.ok_or(ClientError::PendingRequest)?;
        match self.verified_successor(&journal, response) {
            Ok(next) => {
                if self.lock_blocks_install()? {
                    PendingRequestJournal::archive_with_response(
                        &self.journal_path,
                        &self.archive_dir,
                        disposition::LATE_SUCCESSOR,
                        Some(response),
                    )?;
                    return Err(ClientError::LateSuccessor);
                }
                self.install(next, None)
            }
            Err(ClientError::InvalidSuccessor(reason)) => {
                PendingRequestJournal::archive_with_response(
                    &self.journal_path,
                    &self.archive_dir,
                    disposition::INVALID_SUCCESSOR,
                    Some(response),
                )?;
                Err(ClientError::InvalidSuccessor(reason))
            }
            Err(error) => Err(error),
        }
    }

    /// Install `next`, the verified successor of the current state, in §6.2
    /// order: (1) the new state (bound 0, `prev_anchor` set), (2) the archive
    /// disposition `installed`, (3) the journal's removal. `archived` names
    /// a request installed from the archive instead of the journal. An exit
    /// lock that released no exit proof moves to the new state.
    fn install(
        &mut self,
        mut next: NoteState,
        archived: Option<&PendingRequestJournal>,
    ) -> Result<(), ClientError> {
        next.bound_at_state = 0;
        next.state_seq = next.state_seq.saturating_add(1);
        self.persist_state(next)?;
        match archived {
            None => PendingRequestJournal::archive(
                &self.journal_path,
                &self.archive_dir,
                disposition::INSTALLED,
            )?,
            Some(journal) => {
                archive_request(&self.archive_dir, journal, disposition::INSTALLED)?;
            }
        }
        self.move_exit_lock_to_current_state()
    }

    /// Whether an exit lock of the current state released a kind-0 or kind-1
    /// proof, so no successor may be installed until E6 releases it.
    fn lock_blocks_install(&self) -> Result<bool, ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(false);
        };
        Ok(self.exit_lock()?.is_some_and(|lock| {
            lock.note_id == state.note_id
                && lock.anchor == state.current_anchor
                && lock.exit_released()
        }))
    }

    /// E3 step 2 and E4 step 3: a successor installed while the lock had
    /// released no exit proof moves the lock to the new state, where the
    /// decision restarts at E2 (mode `mutual`).
    fn move_exit_lock_to_current_state(&self) -> Result<(), ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        let Some(mut lock) = self.exit_lock()? else {
            return Ok(());
        };
        if lock.note_id != state.note_id
            || lock.anchor == state.current_anchor
            || lock.exit_released()
        {
            return Ok(());
        }
        lock.anchor = state.current_anchor;
        lock.mode = ExitMode::Mutual;
        lock.released.clear();
        lock.save(&self.exit_lock_path)
    }

    /// Verify `response` for `journal`'s request at the current state and
    /// return the next note state, without persisting anything.
    fn verified_successor(
        &self,
        journal: &PendingRequestJournal,
        response: &RequestResponseV2,
    ) -> Result<NoteState, ClientError> {
        if let Some(prepared) = &journal.prepared_request {
            let request_payload = serde_json::from_str::<serde_json::Value>(&prepared.payload).ok();
            if let Some(quote) = request_payload
                .as_ref()
                .and_then(|payload| payload.get("billing_quote"))
            {
                let settled: serde_json::Value = serde_json::from_str(&response.response_payload)
                    .map_err(|_| {
                    ClientError::VerificationFailed("invalid native settlement payload".into())
                })?;
                if settled.get("billing_quote") != Some(quote) {
                    return Err(ClientError::VerificationFailed(
                        "native settlement changed the authorized quote".into(),
                    ));
                }
            }
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        // S1: the journaled request was made at the current state.
        if journal.nullifier != state_nullifier(state) {
            return Err(ClientError::VerificationFailed(
                "the request was not made at the note's current state".to_string(),
            ));
        }
        let current = balance_commitment(
            state.current_balance,
            &parse_scalar(&state.balance_blinding)?,
            &state_note_leaf(state),
        );
        ensure_stored_commitment(state, &current)?;
        let anonymous = rerandomize(&current, &journal.user_rerandomization)
            .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
        self.successor_state(response, journal, &anonymous)
    }

    fn persist_state(&mut self, next: NoteState) -> Result<(), ClientError> {
        next.save(&self.state_path)?;
        self.state = Some(next);
        Ok(())
    }

    /// Set aside the pending request without installing a response. Its
    /// journal moves into the append-only request archive, where `recover`
    /// can still install a later finalized receipt for it.
    pub fn clear_pending_request(&self) -> Result<(), ClientError> {
        self.archive_pending_request("discarded")
    }

    /// Like `clear_pending_request`, recording why the journal was set aside.
    pub fn archive_pending_request(&self, disposition: &str) -> Result<(), ClientError> {
        PendingRequestJournal::archive(&self.journal_path, &self.archive_dir, disposition)
    }

    /// The archive of the current note state: requests transmitted from it
    /// share its nullifier. A record that cannot be read is listed as
    /// unreadable, so callers can still tell that something was archived.
    pub fn archive_at_current_state(&self) -> Result<ArchiveListing, ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(ArchiveListing::default());
        };
        read_archive(&self.archive_dir, &state_nullifier(state))
    }

    /// The readable archived requests of the current note state.
    pub fn archived_requests_at_current_state(&self) -> Result<Vec<ArchivedRequest>, ClientError> {
        Ok(self.archive_at_current_state()?.records)
    }

    /// Every request released at the current state, as the exit decision
    /// sees it: the pending journal (`pending`) and each archived request's
    /// latest record. An unreadable archive record counts as an unresolved
    /// release made now. `reading` is the latest server reading of the
    /// state's nullifier, if one was taken.
    pub fn released_records(
        &self,
        reading: Option<exit_policy::Reading>,
    ) -> Result<Vec<exit_policy::ReleasedRecord>, ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(Vec::new());
        };
        let nullifier = state_nullifier(state);
        let view = |disposition: &str, journal: &PendingRequestJournal| {
            let created_at = journal.created_at_ms / 1_000;
            exit_policy::ReleasedRecord {
                disposition: disposition.to_string(),
                request_time: journal
                    .prepared_request
                    .as_ref()
                    .map_or(created_at, |request| request.public_inputs.request_time),
                created_at,
                reading,
            }
        };
        let mut records = Vec::new();
        let pending = self
            .get_pending_journal()?
            .filter(|journal| journal.nullifier == nullifier);
        if let Some(journal) = &pending {
            records.push(view(disposition::PENDING, journal));
        }
        let listing = read_archive(&self.archive_dir, &nullifier)?;
        for record in latest_records(&listing) {
            if pending.as_ref().is_some_and(|journal| {
                journal.client_request_id == record.journal.client_request_id
            }) {
                continue;
            }
            records.push(view(&record.disposition, &record.journal));
        }
        // An unreadable record may be a released request. It was archived
        // after its request was sent, so its file's modification time bounds
        // the request's time from above; without one it counts as old.
        for path in &listing.unreadable {
            let modified = std::fs::metadata(path)
                .and_then(|metadata| metadata.modified())
                .ok()
                .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                .map_or(0, |elapsed| elapsed.as_secs());
            records.push(exit_policy::ReleasedRecord {
                disposition: "unreadable".into(),
                request_time: modified,
                created_at: modified,
                reading,
            });
        }
        Ok(records)
    }

    /// Install a finalized response for the pending request, or else for a
    /// request archived at the current state.
    pub async fn recover(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        if let Some(response) = self.recover_pending().await? {
            return Ok(Some(response));
        }
        self.recover_archived().await
    }

    /// Install a finalized response for the pending request only. Unlike
    /// `recover`, this sends nothing when no request is pending, so it suits
    /// background polling.
    pub async fn recover_pending(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        self.archive_stale_pending_request()?;
        if let Some(journal) = PendingRequestJournal::read(&self.journal_path)? {
            let response = self
                .operator_request(
                    reqwest::Method::GET,
                    format!(
                        "{}/v2/requests/{}",
                        self.config.server_url.trim_end_matches('/'),
                        journal.client_request_id
                    ),
                )?
                .send()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            let response = crate::testnet_auth::check_response(response)?;
            if response.status() != reqwest::StatusCode::NOT_FOUND {
                let recovery: RecoveryResponseV2 = response
                    .error_for_status()
                    .map_err(|error| ClientError::ServerError(error.to_string()))?
                    .json()
                    .await
                    .map_err(|error| ClientError::InvalidResponse(error.to_string()))?;
                if let Some(response) = recovery.request_response {
                    self.complete_pending_response(&response)?;
                    return Ok(Some(response));
                }
            }
        }
        Ok(None)
    }

    /// A pending journal whose nullifier is not the current state's was
    /// proved at an earlier state, which has since been settled: its own
    /// response was installed (a crash between the install's archive record
    /// and the journal's removal leaves an `installed` record: the journal is
    /// then only removed), or another request's was. It can never be
    /// installed or admitted at this state, so it moves into the archive as
    /// superseded.
    fn archive_stale_pending_request(&self) -> Result<(), ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(());
        };
        let current = state_nullifier(state);
        let Some(pending) = PendingRequestJournal::read(&self.journal_path)? else {
            return Ok(());
        };
        if pending.nullifier == current {
            return Ok(());
        }
        let installed = read_archive(&self.archive_dir, &pending.nullifier)?
            .records
            .iter()
            .any(|record| {
                record.disposition == disposition::INSTALLED
                    && record.journal.client_request_id == pending.client_request_id
            });
        if installed {
            PendingRequestJournal::clear(&self.journal_path)
        } else {
            self.archive_pending_request(disposition::SUPERSEDED)
        }
    }

    /// One read of the server's record for the current state's nullifier,
    /// made only when requests were archived at this state. A finalized
    /// response for one of them is installed when it verifies; the pending
    /// request at this state, if any, can then never be admitted and is
    /// archived as superseded. Failures and unverifiable claims change
    /// nothing.
    async fn recover_archived(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        if let Some(response) = self.install_late_successors()? {
            return Ok(Some(response));
        }
        let archived = match self.archive_at_current_state() {
            Ok(listing) => {
                // A damaged record cannot be installed, but it must not stop
                // the readable ones from being installed.
                for path in &listing.unreadable {
                    tracing::warn!(path = %path.display(), "skipping an unreadable request archive record");
                }
                listing.records
            }
            Err(error) => {
                tracing::warn!(%error, "the request archive could not be read");
                return Ok(None);
            }
        };
        if archived.is_empty() {
            return Ok(None);
        }
        let nullifier = archived[0].journal.nullifier;
        let Ok(response) = self.operator_request(
            reqwest::Method::GET,
            format!(
                "{}/v2/nullifiers/{}",
                self.config.server_url.trim_end_matches('/'),
                nullifier
            ),
        ) else {
            return Ok(None);
        };
        let Ok(response) = response.send().await else {
            return Ok(None);
        };
        let response = crate::testnet_auth::check_response(response)?;
        if !response.status().is_success() {
            return Ok(None);
        }
        let Ok(recovery) = response.json::<RecoveryResponseV2>().await else {
            return Ok(None);
        };
        let Some(response) = recovery.request_response else {
            return Ok(None);
        };
        self.install_archived_response(&archived, &response)
    }

    /// Install `response` for the matching archived request at the current
    /// state, if it verifies and no released exit proof blocks it.
    fn install_archived_response(
        &mut self,
        archived: &[ArchivedRequest],
        response: &RequestResponseV2,
    ) -> Result<Option<RequestResponseV2>, ClientError> {
        let Some(record) = archived
            .iter()
            .rev()
            .find(|record| record.journal.client_request_id == response.client_request_id)
        else {
            return Ok(None);
        };
        let journal = record.journal.clone();
        let Ok(next) = self.verified_successor(&journal, response) else {
            return Ok(None);
        };
        if self.lock_blocks_install()? {
            return Ok(None);
        }
        // The pending retry at this state can never be admitted once the
        // archived request owns its nullifier. Archive it before the next
        // state is saved: a crash in between leaves both requests archived
        // at this state, where the next recovery installs the same receipt,
        // never a saved successor beside a journal of the old state.
        if PendingRequestJournal::read(&self.journal_path)?
            .is_some_and(|pending| pending.nullifier == journal.nullifier)
        {
            self.archive_pending_request(disposition::SUPERSEDED)?;
        }
        self.install(next, Some(&journal))?;
        Ok(Some(response.clone()))
    }

    /// Install a `late_successor` kept at the current state once no exit
    /// lock blocks it (E6: on release, rerun S1–S6 and install).
    pub fn install_late_successors(&mut self) -> Result<Option<RequestResponseV2>, ClientError> {
        if self.state.is_none() || self.lock_blocks_install()? {
            return Ok(None);
        }
        let listing = self.archive_at_current_state()?;
        let late: Vec<ArchivedRequest> = latest_records(&listing)
            .into_iter()
            .filter(|record| {
                record.disposition == disposition::LATE_SUCCESSOR && record.response.is_some()
            })
            .cloned()
            .collect();
        for record in &late {
            let response = record.response.clone().expect("filtered on a response");
            if let Some(installed) = self.install_archived_response(&late, &response)? {
                return Ok(Some(installed));
            }
        }
        Ok(None)
    }

    // ----- exit lock (§6.2, C3, E6) -----

    /// The exit lock, if one is held.
    pub fn exit_lock(&self) -> Result<Option<ExitLock>, ClientError> {
        ExitLock::load(&self.exit_lock_path)
    }

    /// Hold the exit lock at the current state in `mode`, durably, before any
    /// exit decision or proof. A lock already held at this state may switch
    /// from `mutual` to `escape` (E2 step 5), and back only while no escape
    /// was released. A lock of another note is stale (that note closed or
    /// was reset) and is replaced; a lock of another state of this note is
    /// replaced only while it released no exit proof.
    pub fn set_exit_lock(&self, mode: ExitMode) -> Result<ExitLock, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let fresh = ExitLock::new(state.note_id, state.current_anchor, mode, now_seconds());
        let lock = match self.exit_lock()? {
            None => fresh,
            Some(lock) if lock.note_id != state.note_id => fresh,
            Some(lock) if lock.anchor != state.current_anchor => {
                if lock.exit_released() {
                    return Err(ClientError::ExitLockConflict(
                        "an exit proof of an earlier state of this note was released; it must be dead before another exit starts".into(),
                    ));
                }
                fresh
            }
            Some(lock) if lock.mode == mode => return Ok(lock),
            Some(mut lock) => {
                if lock.mode == ExitMode::Escape && lock.escape_released() {
                    return Err(ClientError::ExitLockConflict(
                        "an escape proof of this state was released; the exit stays in escape mode"
                            .into(),
                    ));
                }
                lock.mode = mode;
                lock
            }
        };
        lock.save(&self.exit_lock_path)?;
        Ok(lock)
    }

    /// E6: the user cancels an exit that released no kind-0 or kind-1 proof.
    /// An ownership proof sent under it still keeps the state request-free
    /// (C5), and stays the state's one live ownership proof (C3): C5's
    /// marker keeps it for the next lock.
    pub fn cancel_exit_lock(&mut self) -> Result<(), ClientError> {
        let Some(lock) = self.exit_lock()? else {
            return Ok(());
        };
        if !exit_policy::lock_releasable(
            &lock.released_exits(),
            true,
            NoteChainStatus::Active,
            None,
            now_seconds(),
            false,
        ) {
            return Err(ClientError::ExitLockConflict(
                "an exit proof was released; the lock is held until it is dead or the note closes"
                    .into(),
            ));
        }
        ExitLock::remove(&self.exit_lock_path)?;
        self.install_late_successors()?;
        Ok(())
    }

    /// E6: release the lock once the note is closed, or once every released
    /// kind-0 and kind-1 proof is dead (`finalized_block_timestamp` and this
    /// device's clock `now` both past each `valid_until + 900`, the note
    /// `Active` with no pending exit), then install any late successor.
    /// `status_trusted` marks a reading from the owner's exit RPC: only such
    /// a `Closed` reading releases a lock whose proof may still land.
    /// Returns whether the lock was released.
    pub fn release_exit_lock(
        &mut self,
        note: NoteChainStatus,
        finalized_block_timestamp: Option<u64>,
        now: u64,
        status_trusted: bool,
    ) -> Result<bool, ClientError> {
        let Some(lock) = self.exit_lock()? else {
            return Ok(true);
        };
        if !exit_policy::lock_releasable(
            &lock.released_exits(),
            false,
            note,
            finalized_block_timestamp,
            now,
            status_trusted,
        ) {
            return Ok(false);
        }
        ExitLock::remove(&self.exit_lock_path)?;
        if note != NoteChainStatus::Closed {
            self.install_late_successors()?;
        }
        Ok(true)
    }

    /// Record the transaction that carried the released proof at `index`.
    pub fn record_exit_transaction(&self, index: usize, tx_hash: &str) -> Result<(), ClientError> {
        let mut lock = self
            .exit_lock()?
            .ok_or_else(|| ClientError::ExitLockConflict("no exit lock is held".into()))?;
        let proof = lock
            .released
            .get_mut(index)
            .ok_or_else(|| ClientError::ExitLockConflict("no such released proof".into()))?;
        proof.tx_hash = Some(tx_hash.to_ascii_lowercase());
        lock.save(&self.exit_lock_path)
    }

    /// The lock that allows an exit proof of `mode` at the current state.
    fn lock_for_proof(&self, mode: ExitMode) -> Result<ExitLock, ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let lock = self.exit_lock()?.ok_or_else(|| {
            ClientError::ExitLockConflict(
                "the exit lock must be held before an exit proof is generated".into(),
            )
        })?;
        if lock.note_id != state.note_id || lock.anchor != state.current_anchor {
            return Err(ClientError::ExitLockConflict(
                "the exit lock is held for another note state".into(),
            ));
        }
        if lock.mode != mode {
            return Err(ClientError::ExitLockConflict(format!(
                "the exit lock is in {} mode",
                match lock.mode {
                    ExitMode::Mutual => "mutual",
                    ExitMode::Escape => "escape",
                }
            )));
        }
        Ok(lock)
    }

    /// Append a released proof to `lock`, durably, before it is returned.
    fn record_release(&self, mut lock: ExitLock, proof: ReleasedProof) -> Result<(), ClientError> {
        lock.released.push(proof);
        lock.save(&self.exit_lock_path)
    }

    // ----- C5 -----

    /// Whether an ownership proof of the current state was sent, or may have
    /// been (C5).
    pub fn ownership_proof_sent_at_current_state(&self) -> Result<bool, ClientError> {
        Ok(self.ownership_marker_at_current_state()?.is_some())
    }

    /// C5's marker, when it names the current state.
    fn ownership_marker_at_current_state(
        &self,
    ) -> Result<Option<OwnershipProofMarker>, ClientError> {
        let Some(state) = self.state.as_ref() else {
            return Ok(None);
        };
        let bytes = match std::fs::read(&self.ownership_marker_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let marker: OwnershipProofMarker = serde_json::from_slice(&bytes)
            .map_err(|error| ClientError::Serialization(format!("ownership marker: {error}")))?;
        if marker.version != 1 {
            return Err(ClientError::Serialization(
                "ownership marker has an unknown version".into(),
            ));
        }
        Ok(
            (marker.note_id == state.note_id && marker.nullifier == state_nullifier(state))
                .then_some(marker),
        )
    }

    fn record_ownership_marker(
        &self,
        ownership: &ClearanceOwnershipProofV2C,
        valid_until: u64,
    ) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let marker = OwnershipProofMarker {
            version: 1,
            note_id: state.note_id,
            nullifier: state_nullifier(state),
            valid_until,
            ownership: Some(ownership.clone()),
        };
        let bytes = serde_json::to_vec(&marker)
            .map_err(|error| ClientError::Serialization(error.to_string()))?;
        crate::journal::replace_file_durably(&self.ownership_marker_path, &bytes)
    }

    // ----- exits -----

    /// Obtain the server's clearance and build the mutual-close (kind 1)
    /// proof. The clearance request carries an ownership proof (kind 2) for
    /// the same state and nullifier: it has no destination, concedes nothing,
    /// publishes no successor nullifier and is refused by every vault entry
    /// point. Needs the exit lock in `mutual` mode.
    pub async fn withdrawal_mutual_close(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        self.withdrawal_mutual_close_recorded(destination, active_root, merkle_siblings, || Ok(()))
            .await
    }

    /// Like `withdrawal_mutual_close`, but calls `before_send` once the
    /// ownership proof is built (and recorded as released) and before the
    /// clearance request carrying it is sent. An error from it sends nothing.
    pub async fn withdrawal_mutual_close_recorded(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        before_send: impl FnOnce() -> Result<(), ClientError>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        self.withdrawal_mutual_close_cleared(destination, active_root, merkle_siblings, before_send)
            .await
            .map(|(public, proof, _)| (public, proof))
    }

    /// Like `withdrawal_mutual_close_recorded`, and also returns the verified
    /// clearance signature, so the close can be proved again with a later
    /// `valid_until` (`mutual_close_from_clearance`) without another
    /// ownership proof or clearance request.
    pub async fn withdrawal_mutual_close_cleared(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        before_send: impl FnOnce() -> Result<(), ClientError>,
    ) -> Result<
        (
            WithdrawalPublicInputsV2C,
            Groth16ProofWire,
            zkapi_types::SchnorrSignature,
        ),
        ClientError,
    > {
        check_payout_destination(&destination)?;
        self.lock_for_proof(ExitMode::Mutual)?;
        let ownership = self.ownership_proof(active_root, merkle_siblings.clone())?;
        before_send()?;
        self.mutual_close_with_clearance(destination, active_root, merkle_siblings, ownership)
            .await
    }

    /// A fresh mutual close (kind 1) of the current state from a clearance
    /// signature obtained earlier: the vault refuses a close after its
    /// `valid_until` (L6), and the clearance signs only the nullifier, so an
    /// expired close is proved again with a new lifetime, at the same root
    /// and path (any root the vault ever held stays known, Amendment A1).
    /// Needs the exit lock in `mutual` mode; recorded as released before it
    /// is returned.
    pub fn mutual_close_from_clearance(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        clearance_signature: &zkapi_types::SchnorrSignature,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        check_payout_destination(&destination)?;
        let lock = self.lock_for_proof(ExitMode::Mutual)?;
        self.check_clearance_signature(clearance_signature)?;
        let valid_until = now_seconds() + EXIT_PROOF_VALIDITY_SECONDS;
        let built = self.build_withdrawal(
            WithdrawalKind::MutualClose,
            destination,
            0,
            valid_until,
            active_root,
            merkle_siblings,
            Some(*clearance_signature),
        )?;
        self.record_release(
            lock,
            ReleasedProof {
                kind: 1,
                valid_until,
                conceded: 0,
                tx_hash: None,
                ownership: None,
            },
        )?;
        Ok(built)
    }

    /// The clearance key's signature over the current state's nullifier.
    fn check_clearance_signature(
        &self,
        signature: &zkapi_types::SchnorrSignature,
    ) -> Result<(), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &state_nullifier(state),
        );
        if !verify_signature(&self.config.clearance_signing_key, &message, signature)
            .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
        {
            return Err(ClientError::VerificationFailed(
                "invalid clearance signature".to_string(),
            ));
        }
        Ok(())
    }

    /// The ownership proof (kind 2) a clearance request carries for the
    /// current state, valid for `OWNERSHIP_PROOF_VALIDITY_SECONDS` less a
    /// clock-skew margin. At most one is live per state (C3), across locks:
    /// while the one released earlier is valid it is returned again, so a
    /// retry resends the same proof, also under a new lock after the user
    /// cancelled the one it was made under (E6). Recorded as released, and
    /// the state marked for C5 with the proof, before it is returned.
    pub fn ownership_proof(
        &self,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<ClearanceOwnershipProofV2C, ClientError> {
        let lock = self.lock_for_proof(ExitMode::Mutual)?;
        let now = now_seconds();
        // The state's newest ownership proof: one released under this lock,
        // or the one C5's marker keeps (made under an earlier lock).
        let mut newest: Option<(u64, Option<ClearanceOwnershipProofV2C>, bool)> = None;
        for proof in lock.released.iter().filter(|proof| proof.kind == 2) {
            if newest
                .as_ref()
                .is_none_or(|(valid_until, ..)| proof.valid_until > *valid_until)
            {
                newest = Some((proof.valid_until, proof.ownership.clone(), true));
            }
        }
        if let Some(marker) = self.ownership_marker_at_current_state()? {
            if newest
                .as_ref()
                .is_none_or(|(valid_until, ..)| marker.valid_until > *valid_until)
            {
                newest = Some((marker.valid_until, marker.ownership, false));
            }
        }
        match exit_policy::ownership_proof_action(newest.as_ref().map(|(at, ..)| *at), now) {
            exit_policy::OwnershipProofAction::New => {}
            exit_policy::OwnershipProofAction::Resend => {
                if let Some((valid_until, Some(kept), in_lock)) = newest {
                    if !in_lock {
                        self.record_release(
                            lock,
                            ReleasedProof {
                                kind: 2,
                                valid_until,
                                conceded: 0,
                                tx_hash: None,
                                ownership: Some(kept.clone()),
                            },
                        )?;
                    }
                    return Ok(kept);
                }
                return Err(ownership_proof_still_valid());
            }
            exit_policy::OwnershipProofAction::Wait => return Err(ownership_proof_still_valid()),
        }
        let valid_until = now
            + OWNERSHIP_PROOF_VALIDITY_SECONDS.saturating_sub(OWNERSHIP_CLOCK_SKEW_MARGIN_SECONDS);
        let (public_inputs, proof) = self.build_withdrawal(
            WithdrawalKind::Ownership,
            [0; 20],
            0,
            valid_until,
            active_root,
            merkle_siblings,
            None,
        )?;
        let ownership = ClearanceOwnershipProofV2C {
            public_inputs,
            proof,
        };
        self.record_ownership_marker(&ownership, valid_until)?;
        self.record_release(
            lock,
            ReleasedProof {
                kind: 2,
                valid_until,
                conceded: 0,
                tx_hash: None,
                ownership: Some(ownership.clone()),
            },
        )?;
        Ok(ownership)
    }

    async fn mutual_close_with_clearance(
        &self,
        destination: [u8; 20],
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        ownership: ClearanceOwnershipProofV2C,
    ) -> Result<
        (
            WithdrawalPublicInputsV2C,
            Groth16ProofWire,
            zkapi_types::SchnorrSignature,
        ),
        ClientError,
    > {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let nullifier = state_nullifier(state);
        let clearance = self.request_clearance(&nullifier, ownership).await?;
        let (public, proof) = self.mutual_close_from_clearance(
            destination,
            active_root,
            merkle_siblings,
            &clearance.signature,
        )?;
        Ok((public, proof, clearance.signature))
    }

    /// An escape (kind 0) from the current state that pays
    /// `current_balance - conceded` to `destination` and publishes the
    /// successor nullifier. The vault accepts it until
    /// `now + EXIT_PROOF_VALIDITY_SECONDS`. Needs the exit lock in `escape`
    /// mode, and concedes at most `bound_at_state` (C3). Recorded as
    /// released before it is returned.
    pub fn withdrawal_escape_hatch(
        &self,
        destination: [u8; 20],
        conceded: u128,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        check_payout_destination(&destination)?;
        let lock = self.lock_for_proof(ExitMode::Escape)?;
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        if !exit_policy::concession_allowed(conceded, state.bound_at_state) {
            return Err(ClientError::ConcessionAboveBound {
                conceded,
                bound: state.bound_at_state,
            });
        }
        let valid_until = now_seconds() + EXIT_PROOF_VALIDITY_SECONDS;
        let built = self.build_withdrawal(
            WithdrawalKind::Escape,
            destination,
            conceded,
            valid_until,
            active_root,
            merkle_siblings,
            None,
        )?;
        self.record_release(
            lock,
            ReleasedProof {
                kind: 0,
                valid_until,
                conceded,
                tx_hash: None,
                ownership: None,
            },
        )?;
        Ok(built)
    }

    /// Close the wallet's note: archive its state, remove the exit lock (the
    /// note is closed, E6) and set aside any pending request.
    pub fn archive_note(&mut self) -> Result<(), ClientError> {
        if let Some(state) = &self.state {
            state.archive(&self.state_path)?;
        }
        self.state = None;
        ExitLock::remove(&self.exit_lock_path)?;
        self.archive_pending_request("note_archived")?;
        Ok(())
    }

    /// The nullifier of the current state, `N(s, note_id, τ)`.
    pub fn current_nullifier(&self) -> Option<Felt252> {
        self.state.as_ref().map(state_nullifier)
    }

    /// The nullifier an escape from the current state publishes as
    /// `next_nullifier`: that of the state's only valid successor.
    pub fn current_successor_nullifier(&self) -> Option<Felt252> {
        self.state.as_ref().map(|state| {
            core::successor_nullifier(&state.secret_s, state.note_id, &state.current_anchor)
        })
    }

    /// The current state's note leaf.
    pub fn current_note_leaf(&self) -> Option<Felt252> {
        self.state.as_ref().map(state_note_leaf)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_withdrawal(
        &self,
        kind: WithdrawalKind,
        destination: [u8; 20],
        conceded: u128,
        valid_until: u64,
        active_root: Felt252,
        merkle_siblings: Vec<Felt252>,
        clearance_signature: Option<zkapi_types::SchnorrSignature>,
    ) -> Result<(WithdrawalPublicInputsV2C, Groth16ProofWire), ClientError> {
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        let params = WithdrawalStatementParams {
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root,
            state_signing_key: self.config.state_signing_key.clone(),
            clearance_signing_key: self.config.clearance_signing_key.clone(),
            note_id: state.note_id,
            destination,
        };
        let witness = WithdrawalWitnessData {
            secret: state.secret_s,
            deposit_amount: state.deposit_amount,
            expiry: state.expiry_ts,
            merkle_siblings: siblings_array(merkle_siblings)?,
            state_balance: state.current_balance,
            state_blinding: parse_scalar(&state.balance_blinding)?,
            current_anchor: state.current_anchor,
            kind,
            conceded,
            valid_until,
            state_signature: state.state_signature,
            clearance_signature,
        };
        let public = withdrawal_public_inputs(&params, &witness)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let prover = WithdrawalProver::load(self.setup_dir())
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        let proof = prover
            .prove(&public, witness)
            .map_err(|error| ClientError::ProofGeneration(error.to_string()))?;
        Ok((public, proof))
    }

    async fn request_clearance(
        &self,
        nullifier: &Felt252,
        ownership: ClearanceOwnershipProofV2C,
    ) -> Result<ClearanceResponseV2, ClientError> {
        let request = ClearanceRequestV2C {
            withdrawal_nullifier: *nullifier,
            ownership_proof: ownership,
        };
        let url = format!(
            "{}/v2/withdraw/clearance",
            self.config.server_url.trim_end_matches('/')
        );
        let mut delays = CLEARANCE_RETRY_DELAYS_MS.iter();
        loop {
            let response = self
                .operator_request(reqwest::Method::POST, url.clone())?
                .timeout(std::time::Duration::from_secs(
                    exit_policy::CALL_TIMEOUT_SECONDS,
                ))
                .json(&request)
                .send()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            let response = crate::testnet_auth::check_response(response)?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| ClientError::ServerError(error.to_string()))?;
            if status.is_success() {
                return serde_json::from_str(&body)
                    .map_err(|error| ClientError::InvalidResponse(error.to_string()));
            }
            let code = serde_json::from_str::<ErrorResponse>(&body)
                .map(|error| error.error_code)
                .unwrap_or_default();
            let stale_root = status == reqwest::StatusCode::CONFLICT && code == "stale_root";
            let saturated =
                status == reqwest::StatusCode::SERVICE_UNAVAILABLE && code == "capacity_exhausted";
            if stale_root || saturated {
                if let Some(delay) = delays.next() {
                    tokio::time::sleep(std::time::Duration::from_millis(*delay)).await;
                    continue;
                }
                if stale_root {
                    return Err(ClientError::StaleRoot);
                }
            }
            if (status == reqwest::StatusCode::BAD_REQUEST
                && code == "clearance_ownership_required")
                || (status == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    && code == "legacy_clearance_capacity")
                || (status == reqwest::StatusCode::CONFLICT && code == "nullifier_used")
            {
                return Err(ClientError::ClearanceRefused(code));
            }
            return Err(ClientError::ServerError(format!("HTTP {status}: {body}")));
        }
    }

    /// S1–S6 for `response` to `journal`'s request, whose rerandomized
    /// commitment is `anonymous`. A response that fails S3, S4 or S5 but is
    /// correctly signed (S6) is `InvalidSuccessor`.
    fn successor_state(
        &self,
        response: &RequestResponseV2,
        journal: &PendingRequestJournal,
        anonymous: &CurvePointWire,
    ) -> Result<NoteState, ClientError> {
        // S1.
        if response.client_request_id != journal.client_request_id
            || response.request_nullifier != journal.nullifier
        {
            return Err(ClientError::VerificationFailed(
                "response request identity mismatch".to_string(),
            ));
        }
        // S2.
        if canonical_response_hash(response.response_payload.as_bytes()) != response.response_hash {
            return Err(ClientError::VerificationFailed(
                "response payload hash mismatch".to_string(),
            ));
        }
        let state = self.state.as_ref().ok_or(ClientError::NoActiveNote)?;
        // S6, first: only a correctly signed successor can be an invalid one.
        let message = core::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &response.next_commitment.x,
            &response.next_commitment.y,
            &response.next_anchor,
        );
        if !verify_signature(
            &self.config.state_signing_key,
            &message,
            &response.next_state_signature,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?
        {
            return Err(ClientError::VerificationFailed(
                "invalid next-state signature".to_string(),
            ));
        }
        // S3: the charge is at most the state's one bound, and the journaled
        // request carries that bound. A state saved before `bound_at_state`
        // existed has none recorded; its request's own bound applies.
        let journal_bound = journal
            .prepared_request
            .as_ref()
            .map(|request| request.public_inputs.solvency_bound);
        let bound = if state.bound_at_state != 0 {
            if journal_bound.is_some_and(|bound| bound != state.bound_at_state) {
                return Err(ClientError::InvalidSuccessor(
                    "the request's solvency bound is not the state's bound".to_string(),
                ));
            }
            state.bound_at_state
        } else {
            journal_bound.unwrap_or_else(|| self.configured_solvency_bound())
        };
        if response.charge_applied > bound {
            return Err(ClientError::InvalidSuccessor(
                "the charge exceeds the state's solvency bound".to_string(),
            ));
        }
        // S4: the only successor the request circuit can spend, and the only
        // one whose nullifier an escape from this state publishes, sits at
        // `next_anchor(N)`. Any other anchor (0, 1, reused, random) is
        // treated like a withheld successor.
        if response.next_anchor != core::next_anchor(&journal.nullifier) {
            return Err(ClientError::InvalidSuccessor(
                "the successor anchor is not derived from the request nullifier".to_string(),
            ));
        }
        // S5.
        let expected = server_update(
            anonymous,
            response.charge_applied,
            &response.blind_delta_srv,
        )
        .map_err(|error| ClientError::VerificationFailed(error.to_string()))?;
        if expected != response.next_commitment {
            return Err(ClientError::InvalidSuccessor(
                "next commitment algebra mismatch".to_string(),
            ));
        }

        let current_blinding = parse_scalar(&state.balance_blinding)?;
        let next_blinding = add_blindings(
            &add_blindings(&current_blinding, &journal.user_rerandomization),
            &response.blind_delta_srv,
        );
        let mut next = state.clone();
        next.current_balance = next
            .current_balance
            .checked_sub(response.charge_applied)
            .ok_or_else(|| ClientError::InvalidSuccessor("charge exceeds balance".to_string()))?;
        next.balance_blinding = next_blinding.to_hex();
        next.current_commitment_x = response.next_commitment.x;
        next.current_commitment_y = response.next_commitment.y;
        next.prev_anchor = Some(state.current_anchor);
        next.current_anchor = response.next_anchor;
        next.is_genesis = false;
        next.state_signature = Some(response.next_state_signature);
        Ok(next)
    }

    /// E3 "lost ε": the charge of a `Finalized` response at the current
    /// state's nullifier that passes S1 (as far as it can without a journal:
    /// the nullifier), S2, S4 and S6 but matches no request this wallet can
    /// install. `None` when the response does not pass those checks.
    pub fn uninstallable_finalized_charge(&self, response: &RequestResponseV2) -> Option<u128> {
        let state = self.state.as_ref()?;
        let nullifier = state_nullifier(state);
        let message = core::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &response.next_commitment.x,
            &response.next_commitment.y,
            &response.next_anchor,
        );
        (response.request_nullifier == nullifier
            && canonical_response_hash(response.response_payload.as_bytes())
                == response.response_hash
            && response.next_anchor == core::next_anchor(&nullifier)
            && verify_signature(
                &self.config.state_signing_key,
                &message,
                &response.next_state_signature,
            )
            .unwrap_or(false))
        .then_some(response.charge_applied)
    }

    fn setup_dir(&self) -> &str {
        match &self.config.proof_mode {
            ClientProofMode::Groth16 { setup_dir } => setup_dir,
        }
    }
}

/// Check that `path` proves `leaf` at note `note_id` under `path.root`.
fn check_path(note_id: u32, leaf: &Felt252, path: &DepositPath) -> Result<(), ClientError> {
    let siblings = siblings_array(path.siblings.clone())?;
    if core::merkle_root(note_id, leaf, &siblings) != path.root {
        return Err(ClientError::VerificationFailed(
            "the Merkle path does not prove the note's leaf at its root".to_string(),
        ));
    }
    Ok(())
}

/// Refuse a payout to the zero address for escapes and mutual closes. Only
/// an ownership proof has no destination.
fn check_payout_destination(destination: &[u8; 20]) -> Result<(), ClientError> {
    if *destination == [0; 20] {
        return Err(ClientError::ProofGeneration(
            "withdrawal destination cannot be the zero address".to_string(),
        ));
    }
    Ok(())
}

fn state_nullifier(state: &NoteState) -> Felt252 {
    core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
}

fn ensure_stored_commitment(
    state: &NoteState,
    commitment: &CurvePointWire,
) -> Result<(), ClientError> {
    if commitment.x != state.current_commitment_x || commitment.y != state.current_commitment_y {
        return Err(ClientError::VerificationFailed(
            "persisted balance commitment is inconsistent".to_string(),
        ));
    }
    Ok(())
}

fn parse_scalar(value: &str) -> Result<Felt252, ClientError> {
    Felt252::from_hex(value).map_err(ClientError::Serialization)
}

fn siblings_array(values: Vec<Felt252>) -> Result<[Felt252; MERKLE_DEPTH], ClientError> {
    values.try_into().map_err(|values: Vec<Felt252>| {
        ClientError::ProofGeneration(format!(
            "expected {MERKLE_DEPTH} Merkle siblings, got {}",
            values.len()
        ))
    })
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_ms() -> u64 {
    now_seconds().saturating_mul(1_000)
}

fn state_note_leaf(state: &NoteState) -> Felt252 {
    core::note_leaf(
        state.note_id,
        &core::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    )
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use zkapi_proof::compact::{CompactSigner, RequestVerifier, WithdrawalVerifier};

    use super::*;
    use crate::journal::{crash, durability};

    /// The committed development setup (loaded with the `dev-setup` feature).
    const SETUP_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../setup/v2-concession-dev"
    );
    const DESTINATION: [u8; 20] = [0x11; 20];
    const NOTE_ID: u32 = 5;

    type Replies = Arc<Mutex<VecDeque<(u16, String)>>>;
    type Calls = Arc<Mutex<Vec<(String, Vec<u8>)>>>;

    /// Minimal HTTP/1.1 server: records each request path and body and answers
    /// with the next scripted (status, body) reply.
    struct MockServer {
        url: String,
        replies: Replies,
        calls: Calls,
    }

    impl MockServer {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let replies = Replies::default();
            let calls = Calls::default();
            let (queued, recorded) = (replies.clone(), calls.clone());
            tokio::spawn(async move {
                while let Ok((mut socket, _)) = listener.accept().await {
                    let mut request = Vec::new();
                    let mut buffer = [0u8; 8192];
                    let header_end = loop {
                        let read = socket.read(&mut buffer).await.unwrap();
                        assert!(read > 0, "truncated request");
                        request.extend_from_slice(&buffer[..read]);
                        if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                            break end + 4;
                        }
                    };
                    let head = String::from_utf8_lossy(&request[..header_end]).to_string();
                    let length = head
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap_or(0);
                    while request.len() < header_end + length {
                        let read = socket.read(&mut buffer).await.unwrap();
                        assert!(read > 0, "truncated body");
                        request.extend_from_slice(&buffer[..read]);
                    }
                    let path = head.split_whitespace().nth(1).unwrap_or_default();
                    recorded
                        .lock()
                        .unwrap()
                        .push((path.to_string(), request[header_end..].to_vec()));
                    let (status, body) = queued
                        .lock()
                        .unwrap()
                        .pop_front()
                        .unwrap_or((500, "{}".to_string()));
                    let response = format!(
                        "HTTP/1.1 {status} Mock\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    socket.write_all(response.as_bytes()).await.unwrap();
                    let _ = socket.shutdown().await;
                }
            });
            Self {
                url,
                replies,
                calls,
            }
        }

        fn reply(&self, status: u16, body: String) {
            self.replies.lock().unwrap().push_back((status, body));
        }

        fn calls(&self) -> Vec<(String, Vec<u8>)> {
            self.calls.lock().unwrap().clone()
        }
    }

    struct Fixture {
        wallet: Wallet,
        state_signer: CompactSigner,
        clearance_signer: CompactSigner,
        root: Felt252,
        siblings: Vec<Felt252>,
        state_dir: PathBuf,
        server_url: String,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.state_dir);
        }
    }

    impl Fixture {
        /// The same state directory opened again, as after a restart.
        fn reopen(&mut self) {
            self.wallet = Wallet::new(config(&self.server_url, &self.state_dir)).unwrap();
        }

        fn state(&self) -> NoteState {
            self.wallet.state().unwrap().clone()
        }
    }

    fn config(server_url: &str, state_dir: &std::path::Path) -> ClientConfig {
        ClientConfig {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(0x1234),
            request_charge_cap: 1_000,
            policy_charge_cap: 1_000,
            policy_enabled: false,
            server_url: server_url.to_string(),
            state_dir: state_dir.to_string_lossy().into_owned(),
            proof_mode: ClientProofMode::Groth16 {
                setup_dir: SETUP_DIR.to_string(),
            },
            state_signing_key: CompactSigner::from_seed(&Felt252::from_u64(11)).public_key(),
            clearance_signing_key: CompactSigner::from_seed(&Felt252::from_u64(12)).public_key(),
            settlement_window_seconds: 21_905,
        }
    }

    /// A genesis note alone in an otherwise empty tree.
    fn fixture(server_url: &str) -> Fixture {
        fixture_expiring(server_url, 4_000_000_000)
    }

    fn fixture_expiring(server_url: &str, expiry: u64) -> Fixture {
        let state_dir =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        let mut wallet = Wallet::new(config(server_url, &state_dir)).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), NOTE_ID, 2_000_000, expiry)
            .unwrap();
        let siblings = core::zero_hashes()[..MERKLE_DEPTH].to_vec();
        let state = wallet.state().unwrap();
        let root = core::merkle_root(
            state.note_id,
            &state_note_leaf(state),
            &siblings_array(siblings.clone()).unwrap(),
        );
        Fixture {
            wallet,
            state_signer: CompactSigner::from_seed(&Felt252::from_u64(11)),
            clearance_signer: CompactSigner::from_seed(&Felt252::from_u64(12)),
            root,
            siblings,
            state_dir,
            server_url: server_url.to_string(),
        }
    }

    /// A copy of the fixture's state directory opened as a second wallet.
    fn copy_of(fixture: &Fixture) -> (Wallet, PathBuf) {
        let copy =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&copy).unwrap();
        for entry in std::fs::read_dir(&fixture.state_dir).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_file() {
                std::fs::copy(entry.path(), copy.join(entry.file_name())).unwrap();
            }
        }
        (
            Wallet::new(config(&fixture.server_url, &copy)).unwrap(),
            copy,
        )
    }

    fn nullifier(fixture: &Fixture) -> Felt252 {
        let state = fixture.wallet.state().unwrap();
        core::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
    }

    fn clearance(fixture: &Fixture) -> String {
        let state = fixture.wallet.state().unwrap();
        let nullifier = nullifier(fixture);
        let message = core::clearance_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &nullifier,
        );
        serde_json::to_string(&ClearanceResponseV2 {
            status: "ok".to_string(),
            withdrawal_nullifier: nullifier,
            signature: fixture.clearance_signer.sign(&message),
        })
        .unwrap()
    }

    fn error(code: &str, retriable: bool) -> String {
        serde_json::json!({"status": "error", "client_request_id": "", "error_code": code,
            "error_message": "mock", "retriable": retriable, "latest_root": "0x7"})
        .to_string()
    }

    /// The server's finalized response to `request`, signed by the state key
    /// at `anchor` (the derived anchor unless a test overrides it).
    fn signed_response(
        fixture: &Fixture,
        request: &ApiRequestV2,
        charge: u128,
        anchor: Option<Felt252>,
    ) -> RequestResponseV2 {
        let state = fixture.wallet.state().unwrap();
        let anonymous = CurvePointWire {
            x: request.public_inputs.anonymous_commitment_x,
            y: request.public_inputs.anonymous_commitment_y,
        };
        let delta = random_scalar();
        let next = server_update(&anonymous, charge, &delta).unwrap();
        let next_anchor =
            anchor.unwrap_or_else(|| core::next_anchor(&request.public_inputs.request_nullifier));
        let message = core::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &next.x,
            &next.y,
            &next_anchor,
        );
        let payload = "{\"ok\":true}".to_string();
        RequestResponseV2 {
            status: "ok".into(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            response_code: 200,
            response_hash: canonical_response_hash(payload.as_bytes()),
            response_payload: payload,
            charge_applied: charge,
            next_commitment: next,
            next_anchor,
            blind_delta_srv: delta,
            next_state_signature: fixture.state_signer.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        }
    }

    fn prepare(fixture: &mut Fixture) -> ApiRequestV2 {
        prepare_with_bound(fixture, 1_000).unwrap()
    }

    fn prepare_with_bound(fixture: &mut Fixture, bound: u128) -> Result<ApiRequestV2, ClientError> {
        let payload = "{\"model\":\"m\"}";
        fixture.wallet.prepare_request_with_bound(
            payload,
            canonical_payload_hash(payload.as_bytes()),
            fixture.root,
            fixture.siblings.clone(),
            bound,
        )
    }

    fn archive_dispositions(fixture: &Fixture, nullifier: &Felt252) -> Vec<String> {
        read_archive(&fixture.state_dir.join("request_archive"), nullifier)
            .unwrap()
            .records
            .into_iter()
            .map(|record| record.disposition)
            .collect()
    }

    #[tokio::test]
    async fn mutual_close_sends_a_verifiable_ownership_proof_without_a_destination() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        server.reply(409, error("stale_root", true));
        server.reply(503, error("capacity_exhausted", true));
        server.reply(200, clearance(&fixture));

        let before = now_seconds();
        let (public, proof) = fixture
            .wallet
            .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
            .await
            .unwrap();

        // Retriable answers resend the byte-identical body without re-proving.
        let calls = server.calls();
        assert_eq!(calls.len(), 3);
        assert!(calls
            .iter()
            .all(|(path, _)| path == "/v2/withdraw/clearance"));
        assert!(calls.iter().all(|(_, body)| *body == calls[0].1));
        let body: serde_json::Value = serde_json::from_slice(&calls[0].1).unwrap();
        assert_eq!(body.as_object().unwrap().len(), 2);
        for request_field in ["request_nullifier", "authorization_tag", "solvency_bound"] {
            assert!(body["ownership_proof"]["public_inputs"]
                .get(request_field)
                .is_none());
        }
        let request: ClearanceRequestV2C = serde_json::from_slice(&calls[0].1).unwrap();
        let ownership = request.ownership_proof;
        assert_eq!(request.withdrawal_nullifier, nullifier(&fixture));

        // The ownership proof (kind 2): same state, nullifier, root, keys and
        // balance, but no destination, no successor nullifier, no concession
        // and a valid_until inside the server's one-hour window.
        let owned = &ownership.public_inputs;
        assert_eq!(owned.withdrawal_kind(), Some(WithdrawalKind::Ownership));
        assert_eq!(owned.destination, [0; 20]);
        assert_eq!(owned.next_nullifier, Felt252::ZERO);
        assert_eq!(owned.conceded, 0);
        assert_eq!(owned.withdrawal_nullifier, request.withdrawal_nullifier);
        assert_eq!(owned.final_balance, 2_000_000);
        assert_eq!(owned.active_root, fixture.root);
        assert!(owned.valid_until > before);
        assert!(owned.valid_until <= now_seconds() + OWNERSHIP_PROOF_VALIDITY_SECONDS);

        // The close (kind 1) pays the real destination the whole balance.
        assert_eq!(public.withdrawal_kind(), Some(WithdrawalKind::MutualClose));
        assert_eq!(public.destination, DESTINATION);
        assert_eq!(public.withdrawal_nullifier, request.withdrawal_nullifier);
        assert_eq!(public.final_balance, 2_000_000);
        assert_eq!(public.next_nullifier, Felt252::ZERO);
        assert_eq!(public.conceded, 0);
        assert!(public.valid_until >= before + EXIT_PROOF_VALIDITY_SECONDS);
        assert!(public.valid_until <= now_seconds() + EXIT_PROOF_VALIDITY_SECONDS);
        assert_eq!(
            ownership.proof.backend,
            zkapi_types::wire::ProofBackendWire::Groth16Bn254
        );
        assert_ne!(ownership.proof, proof);

        // Both proofs verify under the deployment's withdrawal verifying key.
        let verifier = WithdrawalVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier.verify(owned, &ownership.proof).unwrap());
        assert!(verifier.verify(&public, &proof).unwrap());

        // Both were recorded as released, in order, under the mutual lock.
        let lock = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(lock.mode, ExitMode::Mutual);
        assert_eq!(
            lock.released
                .iter()
                .map(|proof| (proof.kind, proof.valid_until))
                .collect::<Vec<_>>(),
            [(2, owned.valid_until), (1, public.valid_until)]
        );
    }

    #[tokio::test]
    async fn persistent_stale_root_resends_one_ownership_proof() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        for _ in 0..=CLEARANCE_RETRY_DELAYS_MS.len() {
            server.reply(409, error("stale_root", true));
        }
        let result = fixture
            .wallet
            .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
            .await;
        assert!(matches!(result, Err(ClientError::StaleRoot)), "{result:?}");
        let calls = server.calls();
        assert_eq!(calls.len(), CLEARANCE_RETRY_DELAYS_MS.len() + 1);
        assert!(calls.iter().all(|(_, body)| *body == calls[0].1));
        // A later retry resends the same, still valid, ownership proof: at
        // most one is live per lock (C3).
        server.reply(200, clearance(&fixture));
        fixture
            .wallet
            .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
            .await
            .unwrap();
        let calls = server.calls();
        assert_eq!(calls.last().unwrap().1, calls[0].1);
        let lock = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(lock.released.iter().filter(|p| p.kind == 2).count(), 1);
    }

    #[tokio::test]
    async fn rejected_clearance_is_not_retried() {
        for (status, code) in [(400, "invalid_proof"), (409, "nullifier_used")] {
            let server = MockServer::start().await;
            let fixture = fixture(&server.url);
            fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
            server.reply(status, error(code, false));
            let result = fixture
                .wallet
                .withdrawal_mutual_close(DESTINATION, fixture.root, fixture.siblings.clone())
                .await;
            let refused =
                matches!(&result, Err(ClientError::ClearanceRefused(refused)) if refused == code);
            let failed =
                matches!(&result, Err(ClientError::ServerError(message)) if message.contains(code));
            assert!(
                if code == "nullifier_used" {
                    refused
                } else {
                    failed
                },
                "{result:?}"
            );
            assert_eq!(server.calls().len(), 1, "{code}");
        }
    }

    #[tokio::test]
    async fn invalid_ownership_witness_or_destination_sends_no_clearance_request() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        let mut wrong_path = fixture.siblings.clone();
        wrong_path[3] = Felt252::from_u64(9);
        for (destination, root, siblings) in [
            (DESTINATION, Felt252::from_u64(7), fixture.siblings.clone()),
            (DESTINATION, fixture.root, wrong_path),
            (DESTINATION, fixture.root, fixture.siblings[1..].to_vec()),
            ([0; 20], fixture.root, fixture.siblings.clone()),
        ] {
            let result = fixture
                .wallet
                .withdrawal_mutual_close(destination, root, siblings)
                .await;
            assert!(
                matches!(result, Err(ClientError::ProofGeneration(_))),
                "{result:?}"
            );
        }
        assert!(server.calls().is_empty());
        // Nothing that failed to build was recorded as released.
        assert!(fixture
            .wallet
            .exit_lock()
            .unwrap()
            .unwrap()
            .released
            .is_empty());
        assert!(fixture
            .wallet
            .withdrawal_escape_hatch([0; 20], 0, fixture.root, fixture.siblings.clone())
            .is_err());
    }

    /// The ownership proof is recorded as released, and the state marked for
    /// C5, after the proof is built and before the request carrying it is
    /// sent, so the record covers every answer, including none: a gateway's
    /// 429 here. A proof that cannot be built records nothing, and a failed
    /// caller record sends nothing.
    #[tokio::test]
    async fn the_ownership_proof_is_recorded_before_its_clearance_request_leaves() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        server.reply(
            429,
            serde_json::json!({"error": {"code": "gateway_rate_limited"}}).to_string(),
        );
        let mut recorded = Vec::new();
        let result = fixture
            .wallet
            .withdrawal_mutual_close_recorded(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                || {
                    recorded.push((
                        server.calls().len(),
                        fixture.wallet.exit_lock().unwrap().unwrap().released.len(),
                        fixture
                            .wallet
                            .ownership_proof_sent_at_current_state()
                            .unwrap(),
                    ));
                    Ok(())
                },
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::ServerError(_))),
            "{result:?}"
        );
        assert_eq!(
            recorded,
            [(0, 1, true)],
            "recorded once, before any request"
        );
        assert_eq!(server.calls().len(), 1);

        let result = fixture
            .wallet
            .withdrawal_mutual_close_recorded(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                || Err(ClientError::Serialization("storage unavailable".into())),
            )
            .await;
        assert!(
            matches!(result, Err(ClientError::Serialization(_))),
            "{result:?}"
        );
        assert_eq!(server.calls().len(), 1, "a failed record sends nothing");

        let other = MockServer::start().await;
        let fresh = fixture_expiring(&other.url, 4_000_000_000);
        fresh.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        let mut wrong_path = fresh.siblings.clone();
        wrong_path[3] = Felt252::from_u64(9);
        let result = fresh
            .wallet
            .withdrawal_mutual_close_recorded(DESTINATION, fresh.root, wrong_path, || {
                panic!("recorded a proof that was never built")
            })
            .await;
        assert!(
            matches!(result, Err(ClientError::ProofGeneration(_))),
            "{result:?}"
        );
        assert!(!fresh
            .wallet
            .ownership_proof_sent_at_current_state()
            .unwrap());
    }

    /// An escape (kind 0) publishes the state's nullifier and that of its
    /// derived successor, and pays the balance less the concession, which is
    /// at most the state's bound (C3).
    #[test]
    fn escape_publishes_the_successor_nullifier_and_pays_balance_less_concession() {
        let mut fixture = fixture("http://127.0.0.1:1");
        prepare(&mut fixture);
        assert_eq!(fixture.state().bound_at_state, 1_000);
        fixture.wallet.set_exit_lock(ExitMode::Escape).unwrap();
        assert!(matches!(
            fixture.wallet.withdrawal_escape_hatch(
                DESTINATION,
                1_001,
                fixture.root,
                fixture.siblings.clone()
            ),
            Err(ClientError::ConcessionAboveBound {
                conceded: 1_001,
                bound: 1_000
            })
        ));
        let before = now_seconds();
        let (public, proof) = fixture
            .wallet
            .withdrawal_escape_hatch(DESTINATION, 1_000, fixture.root, fixture.siblings.clone())
            .unwrap();
        let state = fixture.wallet.state().unwrap();
        assert_eq!(public.withdrawal_kind(), Some(WithdrawalKind::Escape));
        assert_eq!(public.withdrawal_nullifier, nullifier(&fixture));
        assert_eq!(
            Some(public.withdrawal_nullifier),
            fixture.wallet.current_nullifier()
        );
        let successor = core::nullifier(
            &state.secret_s,
            state.note_id,
            &core::next_anchor(&public.withdrawal_nullifier),
        );
        assert_eq!(public.next_nullifier, successor);
        assert_eq!(
            Some(public.next_nullifier),
            fixture.wallet.current_successor_nullifier()
        );
        assert_eq!(public.conceded, 1_000);
        assert_eq!(public.final_balance, 2_000_000 - 1_000);
        assert_eq!(public.destination, DESTINATION);
        assert!(public.valid_until >= before + EXIT_PROOF_VALIDITY_SECONDS);
        let verifier = WithdrawalVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier.verify(&public, &proof).unwrap());
        // Released before it was returned, with its concession.
        let lock = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(lock.released.len(), 1);
        assert_eq!(
            (
                lock.released[0].kind,
                lock.released[0].valid_until,
                lock.released[0].conceded
            ),
            (0, public.valid_until, 1_000)
        );
    }

    /// A request from the installed successor proves the anchor chain with
    /// the predecessor's anchor, and its nullifier is exactly the
    /// `next_nullifier` an escape from the predecessor publishes.
    #[test]
    fn the_successor_records_its_predecessor_anchor_and_proves_the_next_request() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let genesis = fixture.state();
        // The escape is proved from a copy of the genesis state, so the
        // original wallet holds no exit lock.
        let (copy, copy_dir) = copy_of(&fixture);
        copy.set_exit_lock(ExitMode::Escape).unwrap();
        let (escape, _) = copy
            .withdrawal_escape_hatch(DESTINATION, 0, fixture.root, fixture.siblings.clone())
            .unwrap();
        let _ = std::fs::remove_dir_all(copy_dir);
        let request = prepare(&mut fixture);
        let verifier = RequestVerifier::load(SETUP_DIR).unwrap();
        assert!(verifier
            .verify(&request.public_inputs, &request.proof)
            .unwrap());
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();

        let next = fixture.state();
        assert_eq!(next.prev_anchor, Some(genesis.current_anchor));
        assert_eq!(
            next.current_anchor,
            core::next_anchor(&request.public_inputs.request_nullifier)
        );
        assert!(!next.is_genesis);
        assert_eq!(next.current_balance, 2_000_000 - 400);
        assert_eq!(next.bound_at_state, 0, "the install resets the bound");
        assert_eq!(next.state_seq, 1);
        // Persisted with the predecessor anchor.
        let reloaded = NoteState::load(&fixture.state_dir.join("note_state.json")).unwrap();
        assert_eq!(reloaded.prev_anchor, Some(genesis.current_anchor));
        // The install's archive disposition was written.
        assert_eq!(
            archive_dispositions(&fixture, &request.public_inputs.request_nullifier),
            ["installed"]
        );

        let second = prepare_with_bound(&mut fixture, 700).unwrap();
        assert!(verifier
            .verify(&second.public_inputs, &second.proof)
            .unwrap());
        assert_eq!(
            second.public_inputs.request_nullifier,
            escape.next_nullifier
        );
    }

    /// S4: a correctly signed successor at any anchor but `next_anchor(N)` is
    /// refused, nothing is installed, and the request is archived as
    /// `invalid_successor` with the response (it is treated like a withheld
    /// successor).
    #[test]
    fn a_successor_at_a_non_derived_anchor_is_an_invalid_successor() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let genesis = fixture.state();
        let nullifier = request.public_inputs.request_nullifier;
        let journal = fixture.wallet.get_pending_journal().unwrap().unwrap();
        let journal_path = fixture.state_dir.join("pending_journal.json");
        let anchors = [
            Felt252::ZERO,
            Felt252::ONE,
            genesis.current_anchor,
            Felt252::from_u64(0xdead_beef),
            // The derived anchor of another note's nullifier at this anchor.
            core::next_anchor(&core::nullifier(
                &genesis.secret_s,
                genesis.note_id + 1,
                &genesis.current_anchor,
            )),
            // The old (pre-concession) style: any server-chosen anchor.
            nullifier,
        ];
        for (index, anchor) in anchors.iter().enumerate() {
            let response = signed_response(&fixture, &request, 400, Some(*anchor));
            let result = fixture.wallet.complete_pending_response(&response);
            assert!(
                matches!(&result, Err(ClientError::InvalidSuccessor(message))
                    if message.contains("not derived")),
                "{anchor:?}: {result:?}"
            );
            assert_eq!(fixture.state().current_anchor, genesis.current_anchor);
            assert!(!fixture.wallet.has_pending_request());
            let records = read_archive(&fixture.state_dir.join("request_archive"), &nullifier)
                .unwrap()
                .records;
            assert_eq!(records.len(), index + 1);
            assert_eq!(records[index].disposition, "invalid_successor");
            assert_eq!(
                serde_json::to_value(records[index].response.as_ref()).unwrap(),
                serde_json::to_value(Some(&response)).unwrap()
            );
            // Put the same journal back to try the next anchor.
            PendingRequestJournal::write(&journal_path, &journal).unwrap();
        }
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        assert!(!fixture.wallet.has_pending_request());
    }

    /// S3 and S5: an overcharge above the state's bound and a phantom
    /// commitment are invalid successors; an unsigned response is merely
    /// rejected and keeps the journal.
    #[test]
    fn overcharges_and_phantom_commitments_are_invalid_and_unsigned_answers_are_rejected() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let journal = fixture.wallet.get_pending_journal().unwrap().unwrap();
        let journal_path = fixture.state_dir.join("pending_journal.json");

        let overcharge = signed_response(&fixture, &request, 1_001, None);
        let result = fixture.wallet.complete_pending_response(&overcharge);
        assert!(
            matches!(&result, Err(ClientError::InvalidSuccessor(m)) if m.contains("bound")),
            "{result:?}"
        );
        PendingRequestJournal::write(&journal_path, &journal).unwrap();

        let mut phantom = signed_response(&fixture, &request, 400, None);
        phantom.blind_delta_srv = random_scalar();
        let state = fixture.state();
        let message = core::state_message(
            2,
            1,
            &state.contract_address,
            &phantom.next_commitment.x,
            &phantom.next_commitment.y,
            &phantom.next_anchor,
        );
        phantom.next_state_signature = fixture.state_signer.sign(&message);
        let result = fixture.wallet.complete_pending_response(&phantom);
        assert!(
            matches!(&result, Err(ClientError::InvalidSuccessor(m)) if m.contains("commitment")),
            "{result:?}"
        );
        PendingRequestJournal::write(&journal_path, &journal).unwrap();

        let mut unsigned = signed_response(&fixture, &request, 400, None);
        unsigned.next_state_signature = fixture.clearance_signer.sign(&Felt252::from_u64(1));
        let result = fixture.wallet.complete_pending_response(&unsigned);
        assert!(
            matches!(&result, Err(ClientError::VerificationFailed(_))),
            "{result:?}"
        );
        assert!(
            fixture.wallet.has_pending_request(),
            "S6 failures keep the journal"
        );
        assert_eq!(
            archive_dispositions(&fixture, &request.public_inputs.request_nullifier),
            ["invalid_successor", "invalid_successor"]
        );
    }

    /// C2: every request proof at a state carries one bound, fixed by the
    /// first; it survives a restart and resets at the next install.
    #[test]
    fn one_bound_per_state() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let first = prepare_with_bound(&mut fixture, 1_000).unwrap();
        assert_eq!(fixture.state().bound_at_state, 1_000);
        fixture
            .wallet
            .archive_pending_request("discarded_stale_root")
            .unwrap();
        fixture.reopen();
        let refused = prepare_with_bound(&mut fixture, 2_000);
        assert!(
            matches!(
                refused,
                Err(ClientError::BoundFixedAtState {
                    bound: 1_000,
                    requested: 2_000
                })
            ),
            "{refused:?}"
        );
        assert!(refused
            .unwrap_err()
            .to_string()
            .starts_with("bound_fixed_at_state"));
        let second = prepare_with_bound(&mut fixture, 1_000).unwrap();
        assert_eq!(
            second.public_inputs.request_nullifier,
            first.public_inputs.request_nullifier
        );
        let response = signed_response(&fixture, &second, 10, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        assert_eq!(fixture.state().bound_at_state, 0);
        prepare_with_bound(&mut fixture, 3_000).unwrap();
        assert_eq!(fixture.state().bound_at_state, 3_000);
    }

    /// §6.2 request write order: the state with `bound_at_state` is synced
    /// before the journal, and a crash at each step leaves a consistent
    /// wallet: before the bound nothing changed; after the bound and before
    /// the journal nothing was sent, and only that bound can follow.
    #[test]
    fn the_request_write_order_survives_a_crash_at_every_step() {
        let mut fixture = fixture("http://127.0.0.1:1");
        durability::take();
        prepare(&mut fixture);
        let synced: Vec<String> = durability::take()
            .into_iter()
            .filter(|(kind, _)| *kind == "file")
            .map(|(_, path)| path.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(synced, ["note_state.tmp", "pending_journal.tmp"]);

        // Crash before the bound is written.
        let mut fixture = fixture_expiring("http://127.0.0.1:1", 4_000_000_000);
        crash::after(0);
        assert!(prepare_with_bound(&mut fixture, 1_000).is_err());
        crash::disarm();
        fixture.reopen();
        assert_eq!(fixture.state().bound_at_state, 0);
        assert!(!fixture.wallet.has_pending_request());

        // Crash after the bound, before the journal: nothing can have been
        // transmitted, and the bound is fixed.
        crash::after(1);
        assert!(prepare_with_bound(&mut fixture, 1_000).is_err());
        crash::disarm();
        fixture.reopen();
        assert_eq!(fixture.state().bound_at_state, 1_000);
        assert!(!fixture.wallet.has_pending_request());
        assert!(matches!(
            prepare_with_bound(&mut fixture, 999),
            Err(ClientError::BoundFixedAtState { .. })
        ));
        let request = prepare_with_bound(&mut fixture, 1_000).unwrap();
        assert_eq!(
            fixture
                .wallet
                .get_pending_journal()
                .unwrap()
                .unwrap()
                .client_request_id,
            request.client_request_id
        );
    }

    /// §6.2 install write order: (1) the new state, (2) the archive
    /// disposition, (3) the journal's removal. A crash after any step leaves
    /// a wallet whose recovery reaches the same final state.
    #[tokio::test]
    async fn the_install_write_order_survives_a_crash_at_every_step() {
        for steps in 0..3 {
            let mut fixture = fixture("http://127.0.0.1:1");
            let request = prepare(&mut fixture);
            let response = signed_response(&fixture, &request, 400, None);
            durability::take();
            crash::after(steps);
            let result = fixture.wallet.complete_pending_response(&response);
            crash::disarm();
            assert!(result.is_err(), "step {steps}");
            fixture.reopen();
            let nullifier = request.public_inputs.request_nullifier;
            match steps {
                0 => {
                    // Nothing was written: the request is still pending and
                    // installs normally.
                    assert_eq!(fixture.state().state_seq, 0);
                    assert!(fixture.wallet.has_pending_request());
                    fixture.wallet.complete_pending_response(&response).unwrap();
                }
                1 => {
                    // The state advanced (bound reset) but the journal of the
                    // old state is still there: recovery sets it aside.
                    assert_eq!(fixture.state().state_seq, 1);
                    assert_eq!(fixture.state().bound_at_state, 0);
                    assert!(fixture.wallet.has_pending_request());
                    fixture.wallet.archive_stale_pending_request().unwrap();
                    assert_eq!(archive_dispositions(&fixture, &nullifier), ["superseded"]);
                }
                _ => {
                    // The `installed` record exists; recovery only removes
                    // the journal and records nothing twice.
                    assert!(fixture.wallet.has_pending_request());
                    fixture.wallet.archive_stale_pending_request().unwrap();
                    assert_eq!(archive_dispositions(&fixture, &nullifier), ["installed"]);
                }
            }
            assert!(!fixture.wallet.has_pending_request());
            assert_eq!(fixture.state().current_balance, 2_000_000 - 400);
            assert_eq!(fixture.state().prev_anchor, Some(Felt252::ONE));
        }
    }

    /// §6.2 exit write order: the lock is durable before any exit proof is
    /// generated, and each proof is recorded as released before it is
    /// returned; a crash before the record returns no proof.
    #[test]
    fn exit_proofs_are_released_only_under_a_durable_lock() {
        let fixture = fixture("http://127.0.0.1:1");
        let escape = |wallet: &Wallet| {
            wallet.withdrawal_escape_hatch(DESTINATION, 0, fixture.root, fixture.siblings.clone())
        };
        assert!(matches!(
            escape(&fixture.wallet),
            Err(ClientError::ExitLockConflict(_))
        ));
        crash::after(0);
        assert!(fixture.wallet.set_exit_lock(ExitMode::Escape).is_err());
        crash::disarm();
        assert!(fixture.wallet.exit_lock().unwrap().is_none());
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        assert!(matches!(
            escape(&fixture.wallet),
            Err(ClientError::ExitLockConflict(m)) if m.contains("mutual")
        ));
        fixture.wallet.set_exit_lock(ExitMode::Escape).unwrap();
        // The release record fails: the proof never leaves.
        crash::after(0);
        assert!(escape(&fixture.wallet).is_err());
        crash::disarm();
        assert!(fixture
            .wallet
            .exit_lock()
            .unwrap()
            .unwrap()
            .released
            .is_empty());
        let (public, _) = escape(&fixture.wallet).unwrap();
        let lock = ExitLock::load(&fixture.state_dir.join("exit_lock.json"))
            .unwrap()
            .unwrap();
        assert_eq!(lock.released[0].valid_until, public.valid_until);
        // An escape that was released keeps the lock in escape mode.
        assert!(matches!(
            fixture.wallet.set_exit_lock(ExitMode::Mutual),
            Err(ClientError::ExitLockConflict(_))
        ));
    }

    /// C3: no request proof while the lock is held; a successor of a request
    /// made before the lock installs and moves the lock when no exit proof
    /// was released, and is kept as `late_successor` when one was. E6 then
    /// installs it once every released proof is dead.
    #[test]
    fn requests_freeze_under_the_lock_and_late_successors_wait_for_its_release() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let lock = fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        assert!(matches!(
            fixture.wallet.check_request_allowed(),
            Err(ClientError::ExitLocked)
        ));
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        let moved = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(moved.anchor, fixture.state().current_anchor);
        assert_ne!(moved.anchor, lock.anchor);
        assert_eq!(moved.mode, ExitMode::Mutual);
        fixture.wallet.cancel_exit_lock().unwrap();

        // Now an escape is released before the next successor arrives.
        let second = prepare_with_bound(&mut fixture, 900).unwrap();
        fixture.wallet.set_exit_lock(ExitMode::Escape).unwrap();
        let (escape, _) = fixture
            .wallet
            .withdrawal_escape_hatch(DESTINATION, 900, fixture.root, fixture.siblings.clone())
            .unwrap();
        let before = fixture.state();
        let late = signed_response(&fixture, &second, 300, None);
        assert!(matches!(
            fixture.wallet.complete_pending_response(&late),
            Err(ClientError::LateSuccessor)
        ));
        assert_eq!(fixture.state().current_anchor, before.current_anchor);
        assert_eq!(
            archive_dispositions(&fixture, &second.public_inputs.request_nullifier),
            ["late_successor"]
        );
        // The user cannot cancel a lock with a released escape.
        assert!(fixture.wallet.cancel_exit_lock().is_err());
        let dead = escape.valid_until + 901;
        // Not dead yet: the finalized block is not past valid_until + 900.
        assert!(!fixture
            .wallet
            .release_exit_lock(
                NoteChainStatus::Active,
                Some(escape.valid_until + 900),
                dead,
                false
            )
            .unwrap());
        assert!(!fixture
            .wallet
            .release_exit_lock(
                NoteChainStatus::PendingWithdrawal,
                Some(u64::MAX),
                dead,
                true
            )
            .unwrap());
        // A chain that reports a finalized block far ahead (an RPC the
        // operator influences) releases nothing while this device's clock
        // says the escape can still land, and no untrusted Closed reading
        // does either: the late successor stays archived.
        for (note, trusted) in [
            (NoteChainStatus::Active, false),
            (NoteChainStatus::Active, true),
            (NoteChainStatus::Closed, false),
        ] {
            assert!(!fixture
                .wallet
                .release_exit_lock(note, Some(u64::MAX), now_seconds(), trusted)
                .unwrap());
        }
        assert_eq!(
            archive_dispositions(&fixture, &second.public_inputs.request_nullifier),
            ["late_successor"]
        );
        assert!(fixture
            .wallet
            .release_exit_lock(NoteChainStatus::Active, Some(dead), dead, false)
            .unwrap());
        assert!(fixture.wallet.exit_lock().unwrap().is_none());
        let after = fixture.state();
        assert_eq!(after.current_balance, before.current_balance - 300);
        assert_eq!(after.prev_anchor, Some(before.current_anchor));
        assert_eq!(
            archive_dispositions(&fixture, &second.public_inputs.request_nullifier),
            ["late_successor", "installed"]
        );
    }

    /// C5: after an ownership proof of a state left, no request is made from
    /// that state, even once the lock is cancelled.
    #[tokio::test]
    async fn no_request_from_a_state_whose_ownership_proof_was_sent() {
        let server = MockServer::start().await;
        let mut fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        fixture.wallet.cancel_exit_lock().unwrap();
        let refused = prepare_with_bound(&mut fixture, 1_000);
        assert!(
            matches!(refused, Err(ClientError::OwnershipProofSent)),
            "{refused:?}"
        );
    }

    /// C4: a note too close to its latest exit start refuses new requests.
    #[test]
    fn requests_near_expiry_are_refused() {
        let now = now_seconds();
        let expiry = now + exit_policy::INITIATE_MARGIN_SECONDS + 21_905 + 4_000;
        let mut fixture = fixture_expiring("http://127.0.0.1:1", expiry);
        let refused = prepare_with_bound(&mut fixture, 1_000);
        assert!(
            matches!(refused, Err(ClientError::NoteNearExpiry)),
            "{refused:?}"
        );
        assert_eq!(fixture.state().bound_at_state, 0);
    }

    /// Amendment A1: the deposit-time path is checked and kept, and an escape
    /// proves membership with it.
    #[test]
    fn the_deposit_path_is_checked_saved_and_proves_exits() {
        let state_dir =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        let mut wallet = Wallet::new(config("http://127.0.0.1:1", &state_dir)).unwrap();
        let secret = Felt252::from_u64(42);
        let leaf = core::note_leaf(
            3,
            &core::registration_commitment(&secret),
            2_000_000,
            4_000_000_000,
        );
        // A neighbour at note 2 makes the path non-trivial.
        let mut tree = crate::tree::SparseTree::new();
        tree.set_leaf(2, Felt252::from_u64(77));
        tree.set_leaf(3, leaf);
        let path = DepositPath {
            root: tree.root(),
            siblings: tree.siblings(3).to_vec(),
        };
        let mut wrong = path.clone();
        wrong.root = Felt252::from_u64(5);
        assert!(wallet
            .confirm_deposit_with_path(secret, 3, 2_000_000, 4_000_000_000, Some(wrong))
            .is_err());
        assert!(wallet.state().is_none());
        wallet
            .confirm_deposit_with_path(secret, 3, 2_000_000, 4_000_000_000, Some(path.clone()))
            .unwrap();
        let reopened = Wallet::new(config("http://127.0.0.1:1", &state_dir)).unwrap();
        assert_eq!(reopened.deposit_path(), Some(&path));
        reopened.set_exit_lock(ExitMode::Escape).unwrap();
        let (public, proof) = reopened
            .withdrawal_escape_hatch(DESTINATION, 0, path.root, path.siblings.clone())
            .unwrap();
        assert_eq!(public.active_root, path.root);
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&public, &proof)
            .unwrap());
        let _ = std::fs::remove_dir_all(state_dir);
    }

    /// The exit decision's view of the released records: the journal and the
    /// latest record of each archived request at the state.
    #[test]
    fn released_records_list_the_journal_and_each_requests_latest_record() {
        let mut fixture = fixture("http://127.0.0.1:1");
        prepare(&mut fixture);
        fixture
            .wallet
            .archive_pending_request("discarded_stale_root")
            .unwrap();
        let pending = prepare(&mut fixture);
        let records = fixture.wallet.released_records(None).unwrap();
        assert_eq!(
            records
                .iter()
                .map(|record| record.disposition.as_str())
                .collect::<Vec<_>>(),
            ["pending", "discarded_stale_root"]
        );
        assert_eq!(records[0].request_time, pending.public_inputs.request_time);
        assert!(!exit_policy::state_is_fresh(1_000, &records));
    }

    /// A signed state saved before `prev_anchor` existed proves no request,
    /// but still exits.
    #[test]
    fn a_signed_state_without_its_predecessor_anchor_refuses_requests_but_exits() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let response = signed_response(&fixture, &request, 400, None);
        fixture.wallet.complete_pending_response(&response).unwrap();
        let path = fixture.state_dir.join("note_state.json");
        let mut legacy = NoteState::load(&path).unwrap();
        legacy.prev_anchor = None;
        legacy.save(&path).unwrap();
        let mut wallet = Wallet::new(config("http://127.0.0.1:1", &fixture.state_dir)).unwrap();
        let payload = "{}";
        let refused = wallet.prepare_request(
            payload,
            canonical_payload_hash(payload.as_bytes()),
            fixture.root,
            fixture.siblings.clone(),
        );
        assert!(
            matches!(refused, Err(ClientError::PrevAnchorMissing)),
            "{refused:?}"
        );
        assert!(!wallet.has_pending_request());
        wallet.set_exit_lock(ExitMode::Escape).unwrap();
        let (escape, proof) = wallet
            .withdrawal_escape_hatch(DESTINATION, 0, fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_eq!(escape.final_balance, 2_000_000 - 400);
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&escape, &proof)
            .unwrap());
    }

    /// The nullifier is bound to the note: the same secret at the same
    /// anchor in another note has another nullifier.
    #[test]
    fn requests_from_notes_sharing_a_secret_have_distinct_nullifiers() {
        let mut first = fixture("http://127.0.0.1:1");
        let state_dir =
            std::env::temp_dir().join(format!("zkapi-client-wallet-{}", uuid::Uuid::new_v4()));
        let mut other = Wallet::new(config("http://127.0.0.1:1", &state_dir)).unwrap();
        other
            .confirm_deposit(Felt252::from_u64(42), NOTE_ID + 1, 2_000_000, 4_000_000_000)
            .unwrap();
        let request = prepare(&mut first);
        assert_ne!(
            Some(request.public_inputs.request_nullifier),
            other.current_nullifier()
        );
        let _ = std::fs::remove_dir_all(state_dir);
    }

    /// L6 and §3.3: a close expires, and the clearance signs only the
    /// nullifier, so an expired close is proved again from the kept
    /// signature with a new lifetime, at the same root and path, without a
    /// second ownership proof or clearance request. A signature that does
    /// not verify proves nothing, and only the mutual lock allows it.
    #[tokio::test]
    async fn an_expired_close_is_proved_again_from_its_clearance() {
        let server = MockServer::start().await;
        let fixture = fixture(&server.url);
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        server.reply(200, clearance(&fixture));
        let (first, _, signature) = fixture
            .wallet
            .withdrawal_mutual_close_cleared(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                || Ok(()),
            )
            .await
            .unwrap();
        let forged = fixture.state_signer.sign(&core::clearance_message(
            2,
            1,
            &Felt252::from_u64(0x1234),
            &nullifier(&fixture),
        ));
        assert!(matches!(
            fixture.wallet.mutual_close_from_clearance(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                &forged
            ),
            Err(ClientError::VerificationFailed(_))
        ));
        std::thread::sleep(std::time::Duration::from_millis(1_100));
        let (again, proof) = fixture
            .wallet
            .mutual_close_from_clearance(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                &signature,
            )
            .unwrap();
        assert!(again.valid_until > first.valid_until);
        assert_eq!(again.withdrawal_kind(), Some(WithdrawalKind::MutualClose));
        assert_eq!(
            (
                again.withdrawal_nullifier,
                again.final_balance,
                again.destination
            ),
            (
                first.withdrawal_nullifier,
                first.final_balance,
                first.destination
            )
        );
        assert!(WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&again, &proof)
            .unwrap());
        assert_eq!(server.calls().len(), 1, "no second clearance request");
        let lock = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(
            lock.released
                .iter()
                .map(|proof| (proof.kind, proof.valid_until))
                .collect::<Vec<_>>()[1..],
            [(1, first.valid_until), (1, again.valid_until)]
        );
        assert_eq!(lock.released.iter().filter(|p| p.kind == 2).count(), 1);
        // Only under the mutual lock.
        fixture.wallet.set_exit_lock(ExitMode::Escape).unwrap();
        assert!(matches!(
            fixture.wallet.mutual_close_from_clearance(
                DESTINATION,
                fixture.root,
                fixture.siblings.clone(),
                &signature
            ),
            Err(ClientError::ExitLockConflict(_))
        ));
    }

    /// C3, mode mutual: at most one live ownership proof. Within the resend
    /// margin the kept proof is no longer resent, and no second one is made
    /// until it has expired; then one more is.
    #[test]
    fn a_second_ownership_proof_waits_until_the_first_expires() {
        let fixture = fixture("http://127.0.0.1:1");
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        let first = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        let resent = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_eq!(resent.proof, first.proof);
        let path = fixture.state_dir.join(EXIT_LOCK_FILE);
        let marker = fixture.state_dir.join(OWNERSHIP_PROOF_MARKER_FILE);
        // The proof's lifetime, in the lock and in C5's marker alike.
        let set_valid_until = |valid_until: u64| {
            let mut lock = ExitLock::load(&path).unwrap().unwrap();
            lock.released[0].valid_until = valid_until;
            lock.save(&path).unwrap();
            let mut saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
            saved["valid_until"] = serde_json::json!(valid_until);
            std::fs::write(&marker, serde_json::to_vec(&saved).unwrap()).unwrap();
        };
        // Still accepted by the server, too close to expiry to resend.
        set_valid_until(now_seconds() + OWNERSHIP_RESEND_MARGIN_SECONDS - 1);
        assert!(matches!(
            fixture
                .wallet
                .ownership_proof(fixture.root, fixture.siblings.clone()),
            Err(ClientError::ExitLockConflict(_))
        ));
        assert_eq!(
            fixture.wallet.exit_lock().unwrap().unwrap().released.len(),
            1
        );
        set_valid_until(now_seconds() - 1);
        let second = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_ne!(second.proof, first.proof);
        assert_eq!(
            fixture.wallet.exit_lock().unwrap().unwrap().released.len(),
            2
        );
    }

    /// C3 across locks: cancelling the lock an ownership proof was made
    /// under (E6 allows it, no kind-0 or kind-1 proof was released) does not
    /// let a new lock make a second live one. The kept proof is sent again
    /// and recorded under the new lock; near its expiry none is made, and
    /// after it one more is.
    #[test]
    fn a_cancelled_lock_makes_no_second_live_ownership_proof() {
        let mut fixture = fixture("http://127.0.0.1:1");
        fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        let first = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        let relock = |fixture: &mut Fixture| {
            fixture.wallet.cancel_exit_lock().unwrap();
            assert!(fixture.wallet.exit_lock().unwrap().is_none());
            fixture.wallet.set_exit_lock(ExitMode::Mutual).unwrap();
        };
        relock(&mut fixture);
        let again = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_eq!(again.proof, first.proof);
        let lock = fixture.wallet.exit_lock().unwrap().unwrap();
        assert_eq!(
            (lock.released.len(), lock.released[0].kind),
            (1, 2),
            "the resent proof is recorded under the new lock"
        );
        let marker = fixture.state_dir.join(OWNERSHIP_PROOF_MARKER_FILE);
        let set_valid_until = |valid_until: u64| {
            let mut saved: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&marker).unwrap()).unwrap();
            saved["valid_until"] = serde_json::json!(valid_until);
            std::fs::write(&marker, serde_json::to_vec(&saved).unwrap()).unwrap();
        };
        set_valid_until(now_seconds() + OWNERSHIP_RESEND_MARGIN_SECONDS - 1);
        relock(&mut fixture);
        assert!(matches!(
            fixture
                .wallet
                .ownership_proof(fixture.root, fixture.siblings.clone()),
            Err(ClientError::ExitLockConflict(_))
        ));
        set_valid_until(now_seconds() - 1);
        relock(&mut fixture);
        let second = fixture
            .wallet
            .ownership_proof(fixture.root, fixture.siblings.clone())
            .unwrap();
        assert_ne!(second.proof, first.proof);
        assert!(fixture
            .wallet
            .ownership_proof_sent_at_current_state()
            .unwrap());
    }

    /// E3 "lost ε" takes a finalized response's charge only when it passes
    /// S1 (the nullifier), S2, S4 and S6: a response at a non-derived anchor
    /// or signed by another key concedes nothing on its word.
    #[test]
    fn a_lost_epsilon_charge_needs_the_derived_anchor_and_the_state_key() {
        let mut fixture = fixture("http://127.0.0.1:1");
        let request = prepare(&mut fixture);
        let valid = signed_response(&fixture, &request, 400, None);
        assert_eq!(
            fixture.wallet.uninstallable_finalized_charge(&valid),
            Some(400)
        );
        for anchor in [Felt252::ONE, Felt252::ZERO, Felt252::from_u64(77)] {
            let response = signed_response(&fixture, &request, 400, Some(anchor));
            assert_eq!(
                fixture.wallet.uninstallable_finalized_charge(&response),
                None
            );
        }
        let mut unsigned = valid.clone();
        unsigned.next_state_signature = fixture.clearance_signer.sign(&Felt252::ONE);
        assert_eq!(
            fixture.wallet.uninstallable_finalized_charge(&unsigned),
            None
        );
        let mut other_state = valid.clone();
        other_state.request_nullifier = Felt252::from_u64(3);
        assert_eq!(
            fixture.wallet.uninstallable_finalized_charge(&other_state),
            None
        );
        let mut rehashed = valid;
        rehashed.response_payload = "{}".into();
        assert_eq!(
            fixture.wallet.uninstallable_finalized_charge(&rehashed),
            None
        );
    }
}
