//! The activation worker of vault revision 4 (`zkapi-activated`): appends
//! the notes the vault recorded to its request tree in proved batches.
//!
//! A deposit only records a note. The note can exit at once, but it makes
//! anonymous requests only once it is activated: appended to the request
//! tree, whose root the request statement proves membership under. Each poll
//! reads, at one block, the vault's `nextNoteId()`, `activationCursor()`,
//! `currentRoot()` and `paused()`; the notes from the cursor up to
//! `nextNoteId` are recorded and wait.
//!
//! **Batch size.** The largest of 16, 4 and 1 that is aligned at the cursor
//! (`cursor % K == 0`) and recorded. While a larger aligned batch is still
//! filling, the worker waits, but no longer than
//! `max_activation_wait_seconds` after it first saw the oldest pending note:
//! at low volume every deposit gets a singleton proof within that bound, and
//! the worker never waits for 16 deposits nor falls back to the on-chain path.
//!
//! **Batch.** The statement's notes are read from the vault itself
//! (`notes(id)`: the commitment and the packed amount and expiry the vault
//! feeds its verifier). The siblings of the cursor's slot come from the
//! indexer (`/v1/tree/notes/{cursor}/path`) and are checked locally: the empty
//! subtree with those siblings must hash to the vault's `currentRoot()`. The
//! insertion proof uses the setup's proving key of size K, whose verifying
//! key the adapter pins (`INSERTION{K}_VK_HASH`, checked at startup, and the
//! keys load only under this build's setup policy). It is sent as
//! `activateNotes(cursor, K, root, newRoot, proof)`.
//!
//! **Races.** The vault accepts the call only at its cursor and root:
//! another activation (another worker, or anyone's `activateNotesOnChain`) or
//! a leaf retirement landing first makes it revert `StaleActivation()` before
//! any verification, while deposits landing meanwhile change nothing (the
//! batch is a prefix of the recorded notes). A batch whose cursor or root
//! moved while it was proved is never sent: it is rebuilt from fresh state.
//! An obsolete pending transaction is replaced on its nonce by the fresh
//! batch, or left to revert cheaply when nothing is left to activate.
//!
//! **Transactions.** One dedicated sender, one nonce at a time, EIP-1559
//! fees within the caps and the transaction fee ceiling (`tx_lane`). The
//! call, its proof, fees and nonce are written ahead of every send, so a
//! restart resumes the nonce with the same call (a dropped transaction is
//! re-sent without proving again), and the nonce is held until its
//! transaction is `confirmations` deep: a reorganization is followed, not
//! assumed away. A persisted call is sent again only while it is still the
//! batch at the vault's state of the poll (cursor, root, `nextNoteId` and the
//! batch's notes, which a reorganization can drop or replace); otherwise it
//! is replaced on its nonce by a fresh batch. Nothing else is persisted;
//! every decision is made from the chain.

use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, ensure, Context};
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_proof::compact::{hex32, InsertionProver};
use zkapi_proof::insertion::{
    insertion_roots, is_insertion_size, InsertedNote, InsertionPublic, InsertionWitness,
    INSERTION_SIZES,
};
use zkapi_types::{Felt252, MERKLE_DEPTH};

use crate::{
    activation_status::{
        ActivationAlarmPolicy, ActivationBlocked, ActivationChainStatus, ActivationSenderStatus,
        ActivationStatus, ActivationStatusHandle, BatchOutcome, BatchRecord, NextBatchStatus,
        PendingCallStatus, WorkerState,
    },
    challenge_service::DeploymentCheckError,
    challenge_status::unix_now,
    deployment::{
        insertion_vk_hash_selector, probe_deployment, ContractReader, DeploymentManifest,
        ProbeError,
    },
    native_billing::{VaultNote, NOTE_STATUS_UNINITIALIZED},
    nullifier_store::StatementIdentity,
    tx_lane::{
        classify_send_error, felt_u64, headroom, parse_hex_u128, plan_fees, push_superseded,
        quantity, quantity_u128, refusal_reason, refused_tx_fee, refused_tx_fee_cap, revert_name,
        rpc_request, selector, transaction_fees, words, write_json_atomically, FeePlan, FeePolicy,
        Fees, RpcError, RpcReader, SendFailure, SEND_TIMEOUT,
    },
    watcher::PROOF_LEN,
};

/// `activateNotes(uint32 firstNoteId, uint256 count, uint256 expectedRoot,
/// uint256 newRoot, bytes proof)`.
pub const ACTIVATE_SIGNATURE: &str = "activateNotes(uint32,uint256,uint256,uint256,bytes)";
pub const ACTIVATE_SELECTOR: [u8; 4] = [0xa2, 0xb2, 0xc7, 0x15];
/// `selector | firstNoteId | count | expectedRoot | newRoot | offset 0xa0 |
/// len 256 | 8 proof words`.
pub const ACTIVATE_CALLDATA_LEN: usize = 452;
/// How long the worker waits for a larger aligned batch to fill.
pub const DEFAULT_MAX_ACTIVATION_WAIT_SECONDS: u64 = 30;
/// Gas assumed before any estimate, for the balance alarm and replacement
/// planning: the gas limit of a 16-note activation (about 600,000 gas on the
/// revision-4 vault, plus 20%).
pub const DEFAULT_ACTIVATION_GAS: u64 = 720_000;
const NOTES_ACTIVATED_EVENT: &str = "NotesActivated(uint32,uint32,uint256,bool)";
/// The vault's reverts an activation simulation is classified by.
const ACTIVATION_REVERTS: [&str; 4] = [
    "StaleActivation()",
    "InvalidActivation()",
    "InvalidProof()",
    "Paused()",
];
const INDEXER_TIMEOUT: Duration = Duration::from_secs(10);
/// Sender balance and signer fee cap observations run at most this often.
const OBSERVE_INTERVAL_SECONDS: u64 = 15;
const MAX_ERROR_CHARS: usize = 512;
const CHECKPOINT_VERSION: u32 = 1;

#[derive(Clone, Debug)]
pub struct ActivationServiceConfig {
    /// Operator-controlled RPC supporting `eth_sendTransaction` for `sender`.
    pub rpc_url: String,
    pub indexer_url: String,
    /// The worker's dedicated sender; nobody else may send from it.
    pub sender: String,
    pub contract_address: Felt252,
    pub chain_id: u64,
    /// The worker's nonce is held until its transaction is this deep.
    pub confirmations: u64,
    pub checkpoint: PathBuf,
    pub proof_setup_dir: PathBuf,
    pub fee: FeePolicy,
    pub alarms: ActivationAlarmPolicy,
    pub max_activation_wait_seconds: u64,
    /// Build, prove and simulate batches, but never send.
    pub dry_run: bool,
}

/// What to do with the recorded notes from the cursor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchChoice {
    /// Every recorded note is activated.
    Idle,
    /// Activate this many notes from the cursor now.
    Activate(usize),
    /// The largest batch aligned at the cursor (`aligned` notes) is still
    /// filling: activate the `size` recorded ones at `until` unless it fills.
    Wait {
        size: usize,
        aligned: usize,
        until: u64,
    },
}

/// The largest batch size aligned at `cursor` (16, 4 or 1).
pub fn largest_aligned(cursor: u32) -> usize {
    INSERTION_SIZES
        .iter()
        .rev()
        .copied()
        .find(|size| (cursor as usize).is_multiple_of(*size))
        .unwrap_or(1)
}

/// The batch to activate at `cursor` with notes up to `next_note_id`
/// recorded, the oldest pending one first seen at `oldest_seen_at`: the
/// largest aligned recorded batch, at once if it is the largest aligned at
/// the cursor, else once `max_wait` seconds have passed since then.
pub fn choose_batch(
    cursor: u32,
    next_note_id: u32,
    oldest_seen_at: u64,
    now: u64,
    max_wait: u64,
) -> BatchChoice {
    let pending = next_note_id.saturating_sub(cursor) as usize;
    if pending == 0 {
        return BatchChoice::Idle;
    }
    let aligned = largest_aligned(cursor);
    let size = INSERTION_SIZES
        .iter()
        .rev()
        .copied()
        .find(|size| *size <= aligned && *size <= pending)
        .unwrap_or(1);
    let until = oldest_seen_at.saturating_add(max_wait);
    if size == aligned || now >= until {
        BatchChoice::Activate(size)
    } else {
        BatchChoice::Wait {
            size,
            aligned,
            until,
        }
    }
}

/// `activateNotes` calldata, refusing what the vault never accepts: an
/// unsupported or misaligned batch, roots that are not field elements, or a
/// proof that is not eight 32-byte coordinates.
pub fn activate_calldata(
    first_note_id: u32,
    count: usize,
    expected_root: &Felt252,
    new_root: &Felt252,
    proof: &[u8],
) -> Result<Vec<u8>, String> {
    if !is_insertion_size(count) || !(first_note_id as usize).is_multiple_of(count) {
        return Err(format!(
            "an activation of {count} notes at {first_note_id} is not an aligned batch of 1, 4 or 16"
        ));
    }
    for (value, name) in [(expected_root, "expected root"), (new_root, "new root")] {
        Felt252::try_from_bytes_be(*value.as_bytes())
            .map_err(|_| format!("{name} is not a BN254 field element"))?;
    }
    if proof.len() != PROOF_LEN {
        return Err("a Groth16 proof must contain eight 32-byte coordinates".into());
    }
    let mut data = Vec::with_capacity(ACTIVATE_CALLDATA_LEN);
    data.extend_from_slice(&ACTIVATE_SELECTOR);
    data.extend_from_slice(Felt252::from_u64(first_note_id.into()).as_bytes());
    data.extend_from_slice(Felt252::from_u64(count as u64).as_bytes());
    data.extend_from_slice(expected_root.as_bytes());
    data.extend_from_slice(new_root.as_bytes());
    // The bytes offset after the four static words and itself.
    data.extend_from_slice(Felt252::from_u64(5 * 32).as_bytes());
    data.extend_from_slice(Felt252::from_u64(PROOF_LEN as u64).as_bytes());
    data.extend_from_slice(proof);
    debug_assert_eq!(data.len(), ACTIVATE_CALLDATA_LEN);
    Ok(data)
}

/// When the worker first saw recorded notes: `(n, t)` means notes below `n`
/// were seen by unix time `t`. Only the entries above the cursor are kept.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Observations(Vec<(u32, u64)>);

impl Observations {
    /// Record `next_note_id` seen at `now` with the cursor at `cursor`.
    /// Returns whether anything changed.
    fn observe(&mut self, cursor: u32, next_note_id: u32, now: u64) -> bool {
        let before = self.0.clone();
        // A reorganization can remove deposits; they count as new if they
        // come back.
        self.0.retain(|(next, _)| *next <= next_note_id);
        if self.0.last().is_none_or(|(next, _)| *next < next_note_id) {
            self.0.push((next_note_id, now));
        }
        let first_pending = self
            .0
            .iter()
            .position(|(next, _)| *next > cursor)
            .unwrap_or(self.0.len());
        self.0.drain(..first_pending);
        self.0 != before
    }

    /// When note `note_id` was first seen recorded.
    fn seen_at(&self, note_id: u32) -> Option<u64> {
        self.0
            .iter()
            .find(|(next, _)| *next > note_id)
            .map(|(_, at)| *at)
    }
}

/// A prepared `activateNotes` call: the batch and its proof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct ActivationCall {
    first_note_id: u32,
    count: u32,
    old_root: Felt252,
    new_root: Felt252,
    /// The 256-byte Groth16 proof, 0x-hex.
    proof: String,
    proving_ms: u64,
    /// `notes_digest` of the batch's notes as the vault held them when it
    /// was proved.
    #[serde(default)]
    notes_digest: Option<String>,
}

impl ActivationCall {
    fn calldata(&self) -> anyhow::Result<Vec<u8>> {
        let proof = hex::decode(self.proof.trim_start_matches("0x"))
            .context("persisted activation proof is not hex")?;
        activate_calldata(
            self.first_note_id,
            self.count as usize,
            &self.old_root,
            &self.new_root,
            &proof,
        )
        .map_err(anyhow::Error::msg)
    }

    /// Whether the vault would still accept the batch at this cursor, root
    /// and `nextNoteId` (a reorganization can drop a recorded note). The
    /// notes themselves are compared by `notes_digest`.
    fn valid_at(&self, state: &VaultState) -> bool {
        self.first_note_id == state.cursor
            && self.old_root == state.root
            && self.first_note_id.saturating_add(self.count) <= state.next_note_id
    }
}

/// The digest of a batch's notes as the vault feeds them to its verifier:
/// each note's commitment, amount and expiry, in order.
fn notes_digest(notes: &[VaultNote]) -> String {
    let mut hasher = Keccak256::new();
    for note in notes {
        hasher.update(note.commitment.as_bytes());
        hasher.update(note.deposit_amount.to_be_bytes());
        hasher.update(note.expiry.to_be_bytes());
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// The worker's reserved nonce and the attempts on it. Every field is
/// written before a send, so a crash or an ambiguous result never loses what
/// may have been broadcast.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingActivation {
    nonce: u64,
    /// The call of the latest attempt. A replacement may change the call
    /// (a fresh batch replaces an obsolete one).
    call: ActivationCall,
    #[serde(default)]
    transaction_hash: Option<String>,
    /// Earlier candidate hashes on the nonce, oldest first; any may mine.
    #[serde(default)]
    superseded_hashes: Vec<String>,
    /// Fees (0x-hex wei) and gas limit of the latest attempt.
    #[serde(default)]
    max_fee_per_gas: Option<String>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<String>,
    #[serde(default)]
    gas_limit: Option<u64>,
    #[serde(default)]
    submitted_block: Option<u64>,
    #[serde(default)]
    attempts: u32,
    /// An attempt may hold the nonce without a known hash, so a re-send must
    /// be a valid replacement of the persisted fees.
    #[serde(default)]
    unknown_attempt: bool,
    /// The call failed simulation as overtaken or with a refused proof: it
    /// is replaced by a fresh batch, never sent again.
    #[serde(default)]
    obsolete: bool,
}

impl PendingActivation {
    fn fees(&self) -> Option<Fees> {
        Some(Fees {
            max_fee: parse_hex_u128(self.max_fee_per_gas.as_deref()?)?,
            tip: parse_hex_u128(self.max_priority_fee_per_gas.as_deref()?)?,
        })
    }

    /// Every attempt on the nonce was a definite non-broadcast.
    fn never_broadcast(&self) -> bool {
        self.transaction_hash.is_none()
            && self.superseded_hashes.is_empty()
            && !self.unknown_attempt
            && self.attempts > 0
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Checkpoint {
    version: u32,
    sender: String,
    chain_id: u64,
    contract_address: Felt252,
    #[serde(default)]
    pending: Option<PendingActivation>,
    #[serde(default)]
    observed: Observations,
    #[serde(default)]
    totals: crate::activation_status::ActivationTotals,
    #[serde(default)]
    last_batch: Option<BatchRecord>,
}

/// The vault's activation state at one block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct VaultState {
    root: Felt252,
    cursor: u32,
    next_note_id: u32,
    paused: bool,
}

#[derive(Clone, Debug)]
struct HeadInfo {
    number: u64,
    hash: Option<String>,
    timestamp: u64,
    base_fee: Option<u128>,
}

/// The state of the worker's nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LaneState {
    /// No nonce is reserved.
    Free,
    /// Reserved, and no attempt is known to occupy it.
    Reserved,
    /// Reserved and possibly held by an attempt without a known hash.
    Held,
    /// An attempt is in the pool.
    Pending,
    /// Consumed, not yet at confirmation depth.
    Mined,
}

#[derive(Deserialize)]
struct PathResponse {
    note_id: u32,
    siblings: Vec<Felt252>,
    #[serde(default)]
    root: Option<Felt252>,
    #[serde(default)]
    block_number: Option<u64>,
}

pub struct ActivationService {
    config: ActivationServiceConfig,
    client: reqwest::Client,
    /// The insertion provers, by `INSERTION_SIZES` position.
    provers: Vec<Arc<InsertionProver>>,
    /// The statement of the setup's request and withdrawal keys, which the
    /// startup probes compare with the adapter.
    identity: StatementIdentity,
    checkpoint: Checkpoint,
    status: ActivationStatusHandle,
    snapshot: ActivationStatus,
    sender_balance: Option<u128>,
    signer_tx_fee_cap: Option<u128>,
    /// The lowest transaction fee the signer's node refused as above its RPC
    /// fee cap; kept until restart.
    node_refused_tx_fee: Option<u128>,
    last_observed_at: Option<u64>,
    last_gas: Option<u64>,
    /// Fees read from the pending transaction.
    observed_fees: Option<Fees>,
    /// `--dry-run`: the last simulated call, reused while still valid.
    dry_run_call: Option<ActivationCall>,
    /// The head block hash and notes digest the pending call's notes were
    /// last found unchanged at.
    notes_checked: Option<(String, String)>,
}

impl ActivationService {
    /// Load the insertion proving keys (under this build's setup policy) and
    /// the checkpoint, which must belong to this sender, chain and vault.
    pub fn new(config: ActivationServiceConfig) -> anyhow::Result<Self> {
        ensure!(
            config.contract_address.as_bytes()[..12]
                .iter()
                .all(|byte| *byte == 0),
            "vault address exceeds 20 bytes"
        );
        let sender = config
            .sender
            .strip_prefix("0x")
            .context("sender must be a 0x-prefixed address")?;
        ensure!(
            hex::decode(sender)?.len() == 20,
            "sender must be a 20-byte address"
        );
        config.fee.validate()?;
        config.alarms.validate().map_err(anyhow::Error::msg)?;
        let provers = INSERTION_SIZES
            .iter()
            .map(|size| {
                InsertionProver::load(&config.proof_setup_dir, *size)
                    .map(Arc::new)
                    .with_context(|| format!("load the {size}-note insertion proving key"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let identity = StatementIdentity::load(&config.proof_setup_dir.display().to_string())?;
        let checkpoint: Checkpoint = if config.checkpoint.exists() {
            serde_json::from_slice(&std::fs::read(&config.checkpoint)?)
                .context("unreadable activation checkpoint")?
        } else {
            Checkpoint {
                version: CHECKPOINT_VERSION,
                sender: config.sender.to_ascii_lowercase(),
                chain_id: config.chain_id,
                contract_address: config.contract_address,
                pending: None,
                observed: Observations::default(),
                totals: Default::default(),
                last_batch: None,
            }
        };
        ensure!(
            checkpoint.version == CHECKPOINT_VERSION,
            "activation checkpoint version {} is not {CHECKPOINT_VERSION}",
            checkpoint.version
        );
        ensure!(
            checkpoint.sender == config.sender.to_ascii_lowercase()
                && checkpoint.chain_id == config.chain_id
                && checkpoint.contract_address == config.contract_address,
            "activation checkpoint belongs to another sender or deployment"
        );
        let started_at = unix_now();
        let mut snapshot = ActivationStatus::initial(
            ActivationChainStatus {
                chain_id: config.chain_id,
                vault: format!(
                    "0x{}",
                    hex::encode(&config.contract_address.as_bytes()[12..])
                ),
                confirmations: config.confirmations,
                ..Default::default()
            },
            ActivationSenderStatus {
                address: config.sender.to_ascii_lowercase(),
                min_balance_wei: config
                    .alarms
                    .min_sender_balance_wei
                    .unwrap_or(
                        u128::from(DEFAULT_ACTIVATION_GAS)
                            .saturating_mul(config.fee.max_fee_per_gas)
                            .min(config.fee.tx_fee_cap_wei),
                    )
                    .to_string(),
                max_fee_per_gas_wei: config.fee.max_fee_per_gas.to_string(),
                max_priority_fee_per_gas_wei: config.fee.max_priority_fee_per_gas.to_string(),
                tx_fee_cap_wei: config.fee.tx_fee_cap_wei.to_string(),
                ..Default::default()
            },
            started_at,
        );
        if config.dry_run {
            snapshot
                .config_warnings
                .push("--dry-run: activations are simulated, never sent".into());
        }
        snapshot.totals = checkpoint.totals.clone();
        snapshot.last_batch = checkpoint.last_batch.clone();
        let status = Arc::new(RwLock::new(snapshot.clone()));
        let mut service = Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .build()?,
            provers,
            identity,
            checkpoint,
            status,
            snapshot,
            sender_balance: None,
            signer_tx_fee_cap: None,
            node_refused_tx_fee: None,
            last_observed_at: None,
            last_gas: None,
            observed_fees: None,
            dry_run_call: None,
            notes_checked: None,
            config,
        };
        service.publish();
        Ok(service)
    }

    /// Shared handle for the status listener.
    pub fn status_handle(&self) -> ActivationStatusHandle {
        self.status.clone()
    }

    /// The status as the listener would serve it now.
    pub fn status(&self) -> ActivationStatus {
        crate::activation_status::evaluate(&self.snapshot, &self.config.alarms, unix_now())
    }

    /// The startup checks: the manifest is this vault's, the RPC serves its
    /// chain, the vault and adapter pass the startup probes (revision 4, the
    /// adapter's circuit and request and withdrawal verifying keys equal to
    /// the setup's, the three runtime codehashes the manifest pins), and the
    /// adapter's `INSERTION{K}_VK_HASH` is the verifying key of each proving
    /// key, of the manifest's setup.
    pub async fn verify_deployment(
        &mut self,
        manifest: &DeploymentManifest,
    ) -> Result<(), DeploymentCheckError> {
        let result = self.check_deployment(manifest).await;
        self.snapshot
            .config_warnings
            .retain(|warning| !warning.starts_with("deployment not verified"));
        if let Err(error) = &result {
            self.snapshot
                .config_warnings
                .push(format!("deployment not verified: {error}"));
        }
        self.publish();
        result
    }

    async fn check_deployment(
        &mut self,
        manifest: &DeploymentManifest,
    ) -> Result<(), DeploymentCheckError> {
        let vault = self.vault_address();
        if manifest.chain_id != self.config.chain_id || manifest.contract_address != vault {
            return Err(DeploymentCheckError::Mismatch(format!(
                "the deployment manifest is for vault {} on chain {}, not vault {vault} on chain {}",
                manifest.contract_address, manifest.chain_id, self.config.chain_id
            )));
        }
        let chain = self
            .rpc("eth_chainId", json!([]))
            .await
            .and_then(|value| quantity(&value))
            .map_err(DeploymentCheckError::Unavailable)?;
        if chain != self.config.chain_id {
            return Err(DeploymentCheckError::Mismatch(
                "RPC chain ID does not match the activation deployment".into(),
            ));
        }
        let reader = RpcReader {
            client: self.client.clone(),
            url: self.config.rpc_url.clone(),
        };
        let report = probe_deployment(&reader, manifest, &self.identity)
            .await
            .map_err(|error| match error {
                ProbeError::Mismatch(message) => DeploymentCheckError::Mismatch(message),
                ProbeError::Unavailable(message) => {
                    DeploymentCheckError::Unavailable(anyhow!(message))
                }
            })?;
        for prover in &self.provers {
            let size = prover.size();
            if prover.setup_id() != manifest.setup_id {
                return Err(DeploymentCheckError::Mismatch(format!(
                    "the {size}-note insertion proving key is of setup {:?}, but the deployment \
                     manifest pins setup {:?}",
                    prover.setup_id(),
                    manifest.setup_id
                )));
            }
            let selector = insertion_vk_hash_selector(size).expect("an insertion size");
            let pinned = reader
                .contract_word(&report.proof_adapter_address, selector)
                .await
                .map_err(|error| {
                    DeploymentCheckError::Unavailable(anyhow!(
                        "adapter INSERTION{size}_VK_HASH() at {}: {error}",
                        report.proof_adapter_address
                    ))
                })?;
            let loaded = prover.verifying_key_keccak256();
            if pinned != loaded {
                return Err(DeploymentCheckError::Mismatch(format!(
                    "adapter INSERTION{size}_VK_HASH() is {}, but the {size}-note insertion \
                     proving key's verifying key is {}",
                    hex32(&pinned),
                    hex32(&loaded)
                )));
            }
        }
        Ok(())
    }

    /// One poll: reconcile the nonce, read the vault, then keep, re-send,
    /// replace or prepare an activation. Errors leave the durable record
    /// intact for the next poll or restart.
    pub async fn poll_once(&mut self) -> anyhow::Result<()> {
        self.snapshot.poll.last_started_at = Some(unix_now());
        self.publish();
        let result = self.poll_inner().await;
        let now = unix_now();
        let poll = &mut self.snapshot.poll;
        poll.last_completed_at = Some(now);
        match &result {
            Ok(()) => {
                poll.last_success_at = Some(now);
                poll.consecutive_failures = 0;
                poll.last_error = None;
            }
            Err(error) => {
                poll.consecutive_failures = poll.consecutive_failures.saturating_add(1);
                poll.last_error = Some(bounded(&format!("{error:#}")));
            }
        }
        self.publish();
        result
    }

    async fn poll_inner(&mut self) -> anyhow::Result<()> {
        let chain = match self
            .rpc("eth_chainId", json!([]))
            .await
            .and_then(|value| quantity(&value))
        {
            Ok(chain) => chain,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        if chain != self.config.chain_id {
            return Err(self.blocked(
                ActivationBlocked::RpcError,
                anyhow!("RPC chain ID does not match the activation deployment"),
            ));
        }
        let head = match self.fetch_head().await {
            Ok(head) => head,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        self.observe_sender().await;
        let lane = match self.reconcile_nonce(&head).await {
            Ok(lane) => lane,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        let state = match self
            .vault_state(json!(format!("0x{:x}", head.number)))
            .await
        {
            Ok(state) => state,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        let now = unix_now();
        if self
            .checkpoint
            .observed
            .observe(state.cursor, state.next_note_id, now)
        {
            self.persist()?;
        }
        self.observe_queue(&state);
        if lane == LaneState::Mined {
            let nonce = self
                .checkpoint
                .pending
                .as_ref()
                .map(|pending| pending.nonce);
            self.set_state(
                WorkerState::Confirming,
                format!(
                    "nonce {} mined; held until {} confirmations",
                    nonce.unwrap_or_default(),
                    self.config.confirmations
                ),
            );
            return Ok(());
        }
        if state.paused {
            self.set_state(
                WorkerState::Paused,
                "the vault is paused: activation reverts until it is unpaused".to_string(),
            );
            return Ok(());
        }
        let pending = self.checkpoint.pending.clone();
        if let Some(pending) = &pending {
            if self.still_valid(pending, &state, &head).await? {
                return self.keep_or_resend(lane, pending, &head).await;
            }
        }
        let oldest = self
            .checkpoint
            .observed
            .seen_at(state.cursor)
            .unwrap_or(now);
        let choice = choose_batch(
            state.cursor,
            state.next_note_id,
            oldest,
            now,
            self.config.max_activation_wait_seconds,
        );
        let size = match choice {
            BatchChoice::Idle => {
                self.snapshot.next_batch = None;
                self.hold_obsolete(
                    pending.as_ref(),
                    WorkerState::Idle,
                    "every recorded note is activated".into(),
                );
                return Ok(());
            }
            BatchChoice::Wait {
                size,
                aligned,
                until,
            } => {
                self.snapshot.next_batch = Some(NextBatchStatus {
                    first_note_id: state.cursor,
                    size,
                    aligned_size: aligned,
                    activate_by: Some(until),
                });
                self.hold_obsolete(
                    pending.as_ref(),
                    WorkerState::Waiting,
                    format!(
                        "{} recorded notes pending; waiting until {until} for a full batch of {aligned}",
                        state.next_note_id - state.cursor
                    ),
                );
                return Ok(());
            }
            BatchChoice::Activate(size) => size,
        };
        self.snapshot.next_batch = Some(NextBatchStatus {
            first_note_id: state.cursor,
            size,
            aligned_size: largest_aligned(state.cursor),
            activate_by: None,
        });
        let plan = match (lane, pending.as_ref()) {
            (LaneState::Free, _) | (_, None) => FeePlan::First,
            (LaneState::Reserved, Some(pending)) => {
                pending.fees().map_or(FeePlan::First, FeePlan::Resend)
            }
            // An obsolete attempt holds the nonce: the fresh batch replaces
            // it, if it can be outbid, before any proving.
            (_, Some(pending)) => match self.replacement_plan(pending, head.base_fee) {
                Some(plan) => plan,
                None => return Ok(()),
            },
        };
        let Some(call) = self.prepare(state, size, head.number).await? else {
            return Ok(());
        };
        self.submit(call, plan, &head).await
    }

    /// Whether the persisted call is still the batch at the vault's state:
    /// not obsolete, valid at the cursor, root and `nextNoteId`, and proved
    /// for the notes the vault holds at the poll's block (a reorganization
    /// can replace a deposit under an unchanged cursor and root). The notes
    /// are read again whenever the head block changed.
    async fn still_valid(
        &mut self,
        pending: &PendingActivation,
        state: &VaultState,
        head: &HeadInfo,
    ) -> anyhow::Result<bool> {
        let call = &pending.call;
        if pending.obsolete || !call.valid_at(state) {
            return Ok(false);
        }
        let Some(digest) = &call.notes_digest else {
            return Ok(true);
        };
        let checked = head.hash.clone().map(|hash| (hash, digest.clone()));
        if checked.is_some() && checked == self.notes_checked {
            return Ok(true);
        }
        let block = json!(format!("0x{:x}", head.number));
        let notes = match self.batch_notes(call, block).await {
            Ok(notes) => notes,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        if notes_digest(&notes) != *digest {
            tracing::info!(
                nonce = pending.nonce,
                first_note_id = call.first_note_id,
                batch_size = call.count,
                "a reorganization replaced a note of the pending activation; rebuilding it"
            );
            self.notes_checked = None;
            return Ok(false);
        }
        self.notes_checked = checked;
        Ok(true)
    }

    /// A pending call that is still valid: wait for it, outbid it on its
    /// nonce once it has waited `bump_after_blocks` or the base fee passed
    /// its fee cap, or re-send it when no attempt holds the nonce.
    async fn keep_or_resend(
        &mut self,
        lane: LaneState,
        pending: &PendingActivation,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let waiting = format!(
            "activation of notes {}..{} pending on nonce {}",
            pending.call.first_note_id,
            pending.call.first_note_id + pending.call.count,
            pending.nonce
        );
        let old = pending.fees().or(self.observed_fees);
        match (lane, old) {
            (LaneState::Reserved, _) => {
                let plan = old.map_or(FeePlan::First, FeePlan::Resend);
                self.submit(pending.call.clone(), plan, head).await
            }
            (LaneState::Held, None) => {
                self.submit(pending.call.clone(), FeePlan::First, head)
                    .await
            }
            (_, None) => {
                self.set_state(
                    WorkerState::Submitted,
                    format!("{waiting} with unknown fees; not replaceable"),
                );
                Ok(())
            }
            (_, Some(old)) => {
                let waited = pending.submitted_block.is_none_or(|block| {
                    head.number.saturating_sub(block) >= self.config.fee.bump_after_blocks
                });
                let base_above = head.base_fee.is_some_and(|base| base > old.max_fee);
                if !(waited || base_above) {
                    self.set_state(WorkerState::Submitted, waiting);
                    return Ok(());
                }
                match self.bump_viability(old, pending, head.base_fee) {
                    Ok(true) => {
                        self.submit(pending.call.clone(), FeePlan::Bump(old), head)
                            .await
                    }
                    Ok(false) => {
                        self.set_state(
                            WorkerState::Submitted,
                            format!(
                                "{waiting}; the remaining fee headroom is reserved until the oldest pending note is critical"
                            ),
                        );
                        Ok(())
                    }
                    Err(reason) => {
                        self.block(
                            ActivationBlocked::from_lane(reason),
                            format!(
                                "{waiting} at max fee {} and tip {} wei; no valid replacement within the caps",
                                old.max_fee, old.tip
                            ),
                        );
                        Ok(())
                    }
                }
            }
        }
    }

    /// The plan replacing an obsolete attempt on the nonce with a fresh
    /// batch, if it can be outbid. Otherwise the state says why, and the
    /// obsolete attempt is left to revert or drop.
    fn replacement_plan(
        &mut self,
        pending: &PendingActivation,
        base_fee: Option<u128>,
    ) -> Option<FeePlan> {
        let obsolete = format!(
            "obsolete activation of notes {}..{} on nonce {}",
            pending.call.first_note_id,
            pending.call.first_note_id + pending.call.count,
            pending.nonce
        );
        let Some(old) = pending.fees().or(self.observed_fees) else {
            self.set_state(
                WorkerState::Submitted,
                format!("{obsolete} with unknown fees; it reverts StaleActivation() if mined"),
            );
            return None;
        };
        match self.bump_viability(old, pending, base_fee) {
            Ok(true) => Some(FeePlan::Bump(old)),
            Ok(false) => {
                self.set_state(
                    WorkerState::Submitted,
                    format!(
                        "{obsolete}; the remaining fee headroom is reserved, so it is left to revert StaleActivation() if mined"
                    ),
                );
                None
            }
            Err(reason) => {
                self.block(
                    ActivationBlocked::from_lane(reason),
                    format!("{obsolete} cannot be outbid within the caps"),
                );
                None
            }
        }
    }

    /// Whether a valid same-nonce replacement of `old` exists within the caps
    /// and the transaction fee ceiling at the latest gas limit (within the
    /// reserve's limit until the oldest pending note is critical).
    fn bump_viability(
        &self,
        old: Fees,
        pending: &PendingActivation,
        base_fee: Option<u128>,
    ) -> Result<bool, crate::challenge_status::BlockedReason> {
        let gas = pending
            .gas_limit
            .or(self.last_gas)
            .unwrap_or(DEFAULT_ACTIVATION_GAS);
        plan_fees(
            &self.config.fee,
            FeePlan::Bump(old),
            base_fee,
            self.critical(),
            Some(self.tx_fee_limit(gas)),
            None,
        )
        .map(|fees| fees.is_some())
    }

    /// The oldest pending note waited past the critical alarm threshold:
    /// replacements spend the two kept in reserve (as the challenger's do at
    /// its deadlines), so a held nonce is outbid up to the caps.
    fn critical(&self) -> bool {
        let queue = &self.snapshot.queue;
        queue.pending_notes > 0
            && queue.oldest_pending_seen_at.is_some_and(|seen| {
                unix_now().saturating_sub(seen) > self.config.alarms.pending_critical_seconds
            })
    }

    /// No batch is due: an obsolete attempt that still holds the nonce is
    /// reported, else `state`.
    fn hold_obsolete(
        &mut self,
        pending: Option<&PendingActivation>,
        state: WorkerState,
        detail: String,
    ) {
        match pending {
            Some(pending) => self.set_state(
                WorkerState::Submitted,
                format!(
                    "{detail}; the obsolete activation of notes {}..{} on nonce {} reverts \
                     StaleActivation() if mined",
                    pending.call.first_note_id,
                    pending.call.first_note_id + pending.call.count,
                    pending.nonce
                ),
            ),
            None => self.set_state(state, detail),
        }
    }

    /// Build and prove the batch of `size` notes at the cursor of `state`,
    /// read at `block`. None when it cannot be built now (the state says
    /// why) or the cursor or root moved while it was proved.
    async fn prepare(
        &mut self,
        state: VaultState,
        size: usize,
        block: u64,
    ) -> anyhow::Result<Option<ActivationCall>> {
        let first = state.cursor;
        let block = json!(format!("0x{block:x}"));
        let mut recorded = Vec::with_capacity(size);
        for offset in 0..size as u32 {
            let note = match self.vault_note(first + offset, block.clone()).await {
                Ok(note) => note,
                Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
            };
            if note.status == NOTE_STATUS_UNINITIALIZED {
                self.block(
                    ActivationBlocked::VaultInconsistent,
                    format!(
                        "note {} below nextNoteId {} reads unrecorded; retrying",
                        first + offset,
                        state.next_note_id
                    ),
                );
                return Ok(None);
            }
            recorded.push(note);
        }
        let digest = notes_digest(&recorded);
        if let Some(call) = self.dry_run_call.clone().filter(|call| {
            call.valid_at(&state)
                && call.count as usize == size
                && call.notes_digest.as_ref() == Some(&digest)
        }) {
            return Ok(Some(call));
        }
        let notes: Vec<InsertedNote> = recorded
            .iter()
            .map(|note| InsertedNote {
                registration_commitment: zkapi_core::v2::felt_to_field(&note.commitment),
                deposit_amount: note.deposit_amount,
                expiry: note.expiry,
            })
            .collect();
        let path = match self
            .indexer_get::<PathResponse>(&format!("/v1/tree/notes/{first}/path"))
            .await
        {
            Ok(path) => path,
            Err(error) => {
                self.block(
                    ActivationBlocked::IndexerUnavailable,
                    format!("indexer path request failed: {error:#}"),
                );
                return Ok(None);
            }
        };
        let siblings: [Felt252; MERKLE_DEPTH] =
            match <[Felt252; MERKLE_DEPTH]>::try_from(path.siblings) {
                Ok(siblings) if path.note_id == first => siblings,
                _ => {
                    self.block(
                        ActivationBlocked::IndexerInvalidResponse,
                        format!("the indexer path of slot {first} is not 32 siblings of that slot"),
                    );
                    return Ok(None);
                }
            };
        let siblings = siblings.map(|sibling| zkapi_core::v2::felt_to_field(&sibling));
        let (old_root, new_root) = insertion_roots(first, &notes, &siblings);
        if zkapi_core::v2::field_to_felt(&old_root) != state.root {
            self.block(
                ActivationBlocked::IndexerPathBehind,
                format!(
                    "the indexer's siblings of slot {first} (its root {}, block {}) do not hash \
                     the empty subtree to the vault's currentRoot() {}",
                    path.root
                        .map(|root| root.to_hex())
                        .unwrap_or_else(|| "unknown".into()),
                    path.block_number
                        .map(|block| block.to_string())
                        .unwrap_or_else(|| "unknown".into()),
                    state.root.to_hex()
                ),
            );
            return Ok(None);
        }
        self.set_state(
            WorkerState::Proving,
            format!(
                "proving the activation of notes {first}..{}",
                first + size as u32
            ),
        );
        self.publish();
        let prover = self.prover(size);
        let public = InsertionPublic {
            old_root,
            new_root,
            first_note_id: first,
            notes,
        };
        let started = Instant::now();
        let proved = tokio::task::spawn_blocking(move || {
            prover.prove(&public, &InsertionWitness { siblings })
        })
        .await
        .map_err(|error| anyhow!("the proving task failed: {error}"))
        .and_then(|proof| proof);
        let proving_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let proof = match proved.and_then(|wire| {
            base64::engine::general_purpose::STANDARD
                .decode(&wire.proof)
                .context("undecodable proof")
        }) {
            Ok(proof) if proof.len() == PROOF_LEN => proof,
            Ok(_) => {
                return Err(self.blocked(
                    ActivationBlocked::ProvingFailed,
                    anyhow!("the prover returned a proof of the wrong length"),
                ))
            }
            Err(error) => return Err(self.blocked(ActivationBlocked::ProvingFailed, error)),
        };
        let totals = &mut self.checkpoint.totals;
        totals.proofs_total = totals.proofs_total.saturating_add(1);
        totals.proving_ms_total = totals.proving_ms_total.saturating_add(proving_ms);
        tracing::info!(
            first_note_id = first,
            batch_size = size,
            proving_ms,
            "proved an activation batch"
        );
        let call = ActivationCall {
            first_note_id: first,
            count: size as u32,
            old_root: state.root,
            new_root: zkapi_core::v2::field_to_felt(&new_root),
            proof: format!("0x{}", hex::encode(proof)),
            proving_ms,
            notes_digest: Some(digest),
        };
        // Another activation or a retirement may have landed while proving;
        // deposits change nothing.
        let fresh = match self.vault_state(json!("latest")).await {
            Ok(fresh) => fresh,
            Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
        };
        if !call.valid_at(&fresh) {
            self.stale(format!(
                "the cursor or root moved while notes {first}..{} were proved (cursor {}, root {})",
                first + size as u32,
                fresh.cursor,
                fresh.root.to_hex()
            ))?;
            return Ok(None);
        }
        self.persist()?;
        Ok(Some(call))
    }

    /// Simulate, plan fees, write ahead and send `call` on the reserved
    /// nonce or the next one.
    async fn submit(
        &mut self,
        call: ActivationCall,
        plan: FeePlan,
        head: &HeadInfo,
    ) -> anyhow::Result<()> {
        let calldata = call.calldata()?;
        let mut transaction = json!({
            "from": self.config.sender,
            "to": self.vault_address(),
            "data": format!("0x{}", hex::encode(calldata)),
        });
        if let Err(error) = self.rpc("eth_call", json!([transaction, "latest"])).await {
            return self.simulation_failed(error, &call).await;
        }
        let estimated = match self
            .rpc("eth_estimateGas", json!([transaction]))
            .await
            .and_then(|value| quantity(&value))
        {
            Ok(gas) => gas,
            Err(error) => return self.simulation_failed(error, &call).await,
        };
        let gas = estimated
            .checked_add(estimated / 5)
            .context("activation gas estimate overflow")?;
        self.last_gas = Some(gas);
        let previous = self.checkpoint.pending.clone();
        let nonce = match &previous {
            Some(pending) => pending.nonce,
            None => match self.transaction_count("pending").await {
                Ok(nonce) => nonce,
                Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
            },
        };
        let affordable = self
            .sender_balance
            .map(|balance| balance / u128::from(gas).max(1));
        let tx_fee_limit = self.tx_fee_limit(gas);
        let fees = match plan_fees(
            &self.config.fee,
            plan,
            head.base_fee,
            matches!(plan, FeePlan::Bump(_)) && self.critical(),
            Some(tx_fee_limit),
            affordable,
        ) {
            Ok(Some(fees)) => fees,
            Ok(None) => {
                self.block(
                    ActivationBlocked::FeeReserveHeld,
                    format!("nonce {nonce} is held; the remaining fee headroom is reserved"),
                );
                return Ok(());
            }
            Err(reason) => {
                if self.release_if_never_broadcast().await {
                    self.persist()?;
                }
                self.block(
                    ActivationBlocked::from_lane(reason),
                    format!(
                        "no fees within the caps at {gas} gas (base fee {} wei, transaction fee ceiling {} wei)",
                        head.base_fee.unwrap_or_default(),
                        self.tx_fee_cap()
                    ),
                );
                return Ok(());
            }
        };
        if self.config.dry_run {
            let detail = format!(
                "would send the activation of notes {}..{} (gas {gas}, max fee {} wei, tip {} wei)",
                call.first_note_id,
                call.first_note_id + call.count,
                fees.max_fee,
                fees.tip
            );
            tracing::info!(
                first_note_id = call.first_note_id,
                batch_size = call.count,
                gas,
                "dry run: activation simulated, not sent"
            );
            self.dry_run_call = Some(call);
            self.set_state(WorkerState::DryRun, detail);
            return Ok(());
        }
        // Write ahead: a crash or ambiguous result after this point never
        // loses the reservation, the fees that may be in a pool, or the call.
        let mut entry = previous.clone().unwrap_or(PendingActivation {
            nonce,
            call: call.clone(),
            transaction_hash: None,
            superseded_hashes: Vec::new(),
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            gas_limit: None,
            submitted_block: None,
            attempts: 0,
            unknown_attempt: false,
            obsolete: false,
        });
        if let Some(hash) = entry.transaction_hash.take() {
            push_superseded(&mut entry.superseded_hashes, hash);
        }
        entry.call = call.clone();
        entry.obsolete = false;
        entry.max_fee_per_gas = Some(format!("0x{:x}", fees.max_fee));
        entry.max_priority_fee_per_gas = Some(format!("0x{:x}", fees.tip));
        entry.gas_limit = Some(gas);
        entry.submitted_block = Some(head.number);
        entry.attempts = entry.attempts.saturating_add(1);
        entry.unknown_attempt = true;
        self.checkpoint.pending = Some(entry);
        self.persist()?;
        transaction["gas"] = json!(format!("0x{gas:x}"));
        transaction["nonce"] = json!(format!("0x{nonce:x}"));
        transaction["maxFeePerGas"] = json!(format!("0x{:x}", fees.max_fee));
        transaction["maxPriorityFeePerGas"] = json!(format!("0x{:x}", fees.tip));
        let sent = self
            .rpc_with_timeout(
                "eth_sendTransaction",
                json!([transaction]),
                Some(SEND_TIMEOUT),
            )
            .await
            .and_then(|hash| {
                hash.as_str()
                    .map(str::to_owned)
                    .context("transaction response lacks hash")
            });
        match sent {
            Ok(hash) => {
                let entry = self.checkpoint.pending.as_mut().expect("written ahead");
                entry.transaction_hash = Some(hash.clone());
                entry.unknown_attempt = false;
                self.persist()?;
                tracing::info!(
                    nonce,
                    first_note_id = call.first_note_id,
                    batch_size = call.count,
                    transaction_hash = %hash,
                    gas,
                    max_fee_per_gas = fees.max_fee,
                    max_priority_fee_per_gas = fees.tip,
                    "submitted activation"
                );
                self.set_state(
                    WorkerState::Submitted,
                    format!(
                        "activation of notes {}..{} pending on nonce {nonce}",
                        call.first_note_id,
                        call.first_note_id + call.count
                    ),
                );
                Ok(())
            }
            Err(error) => {
                self.send_failed(nonce, (gas, fees.max_fee), previous, error)
                    .await
            }
        }
    }

    /// `sent` is the gas limit and maxFeePerGas of the failed send.
    async fn send_failed(
        &mut self,
        nonce: u64,
        sent: (u64, u128),
        previous: Option<PendingActivation>,
        error: anyhow::Error,
    ) -> anyhow::Result<()> {
        let (gas, max_fee) = sent;
        let reason = match classify_send_error(&error) {
            SendFailure::Refused(reason) => {
                self.roll_back_unsent(previous).await;
                if reason.as_deref() == Some("tx_fee_above_cap") {
                    if let Some(cap) = refused_tx_fee_cap(&error, gas) {
                        self.signer_tx_fee_cap = Some(cap);
                    }
                }
                if reason.as_deref() == Some("upstream_tx_fee_cap") {
                    let refused = refused_tx_fee(&error, gas, max_fee);
                    self.node_refused_tx_fee = Some(
                        self.node_refused_tx_fee
                            .map_or(refused, |lowest| lowest.min(refused)),
                    );
                    tracing::warn!(
                        refused_tx_fee_wei = refused,
                        "the signer's node refused the transaction fee as above its RPC fee cap; later bids stay within 10/11 of the lowest refused fee until restart"
                    );
                }
                refusal_reason(reason.as_deref())
            }
            SendFailure::NotBroadcast(reason) => {
                self.roll_back_unsent(previous).await;
                reason
            }
            SendFailure::Ambiguous(hash) => {
                // Keep the write-ahead record; a candidate hash lets the next
                // poll find the transaction, otherwise re-sends must outbid.
                if let Some(hash) = hash {
                    let entry = self.checkpoint.pending.as_mut().expect("written ahead");
                    entry.transaction_hash = Some(hash);
                    entry.unknown_attempt = false;
                }
                crate::challenge_status::BlockedReason::SendAmbiguous
            }
        };
        self.persist()?;
        tracing::warn!(nonce, error = %error, "activation send failed");
        Err(self.blocked(ActivationBlocked::from_lane(reason), error))
    }

    /// Nothing was broadcast: restore the nonce's earlier record (counting
    /// the attempt), and release the nonce when no attempt can occupy it.
    /// The caller persists.
    async fn roll_back_unsent(&mut self, previous: Option<PendingActivation>) {
        let attempts = self
            .checkpoint
            .pending
            .as_ref()
            .map_or(0, |pending| pending.attempts);
        // A nonce allocated for this send (no earlier record): nothing ever
        // occupied it.
        self.checkpoint.pending = previous.map(|previous| PendingActivation {
            attempts,
            ..previous
        });
        self.release_if_never_broadcast().await;
    }

    /// Release the reserved nonce when no attempt on it was broadcast and
    /// neither the latest nor the pending count has passed it. The caller
    /// persists.
    async fn release_if_never_broadcast(&mut self) -> bool {
        let Some(nonce) = self
            .checkpoint
            .pending
            .as_ref()
            .filter(|pending| pending.never_broadcast())
            .map(|pending| pending.nonce)
        else {
            return false;
        };
        let unused = self
            .transaction_count("latest")
            .await
            .is_ok_and(|count| count <= nonce)
            && self
                .transaction_count("pending")
                .await
                .is_ok_and(|count| count <= nonce);
        if !unused {
            return false;
        }
        self.checkpoint.pending = None;
        self.observed_fees = None;
        tracing::info!(
            nonce,
            "released a reserved nonce that no attempt was broadcast on"
        );
        true
    }

    async fn simulation_failed(
        &mut self,
        error: anyhow::Error,
        call: &ActivationCall,
    ) -> anyhow::Result<()> {
        let revert = revert_name(&error, &ACTIVATION_REVERTS);
        // The persisted call reverting so is obsolete (a reorganization can
        // drop or replace its notes): it is never sent again, and the next
        // poll replaces it on its nonce by a fresh batch.
        let persisted = matches!(
            revert,
            Some("StaleActivation()" | "InvalidActivation()" | "InvalidProof()")
        ) && self
            .checkpoint
            .pending
            .as_ref()
            .is_some_and(|pending| pending.call == *call);
        if persisted {
            self.checkpoint.pending.as_mut().expect("pending").obsolete = true;
        }
        match revert {
            Some("StaleActivation()" | "InvalidActivation()") => {
                self.stale(format!(
                    "simulation of the activation of notes {}..{} reverted {}: the cursor, root \
                     or recorded notes moved",
                    call.first_note_id,
                    call.first_note_id + call.count,
                    revert.unwrap_or_default()
                ))?;
                Ok(())
            }
            Some("Paused()") => {
                self.set_state(
                    WorkerState::Paused,
                    "the vault is paused: activation reverts until it is unpaused".to_string(),
                );
                Ok(())
            }
            Some("InvalidProof()") if persisted => {
                self.stale(format!(
                    "simulation of the persisted activation of notes {}..{} reverted \
                     InvalidProof(): the recorded notes moved",
                    call.first_note_id,
                    call.first_note_id + call.count
                ))?;
                Ok(())
            }
            Some("InvalidProof()") => {
                self.dry_run_call = None;
                // A reorganization while the batch was proved can replace or
                // reorder its notes under an unchanged cursor, root and
                // nextNoteId: the batch is rebuilt. Only a proof of the notes
                // the vault still holds is rejected.
                if let Some(digest) = &call.notes_digest {
                    let notes = match self.batch_notes(call, json!("latest")).await {
                        Ok(notes) => notes,
                        Err(error) => return Err(self.blocked(ActivationBlocked::RpcError, error)),
                    };
                    if notes
                        .iter()
                        .any(|note| note.status == NOTE_STATUS_UNINITIALIZED)
                        || notes_digest(&notes) != *digest
                    {
                        self.stale(format!(
                            "simulation of the activation of notes {}..{} reverted \
                             InvalidProof(): a reorganization moved the batch's notes while it \
                             was proved",
                            call.first_note_id,
                            call.first_note_id + call.count
                        ))?;
                        return Ok(());
                    }
                }
                Err(self.blocked(
                    ActivationBlocked::ProofRejected,
                    anyhow!("the adapter rejected the insertion proof (InvalidProof()): {error}"),
                ))
            }
            _ if error.downcast_ref::<RpcError>().is_some() => Err(self.blocked(
                ActivationBlocked::SimulationReverted,
                anyhow!("activation simulation reverted: {error}"),
            )),
            _ => Err(self.blocked(ActivationBlocked::RpcError, error)),
        }
    }

    /// A prepared batch was overtaken: counted, and rebuilt from fresh state
    /// by the next poll.
    fn stale(&mut self, detail: String) -> anyhow::Result<()> {
        let totals = &mut self.checkpoint.totals;
        totals.stale_rebuilds_total = totals.stale_rebuilds_total.saturating_add(1);
        self.dry_run_call = None;
        self.persist()?;
        tracing::info!(detail = %detail, "activation batch overtaken; rebuilding from fresh state");
        self.set_state(WorkerState::Rebuilding, detail);
        Ok(())
    }

    async fn reconcile_nonce(&mut self, head: &HeadInfo) -> anyhow::Result<LaneState> {
        let Some(pending) = self.checkpoint.pending.clone() else {
            return Ok(LaneState::Free);
        };
        let (latest, confirmed) = self.nonce_counts().await?;
        if confirmed > pending.nonce {
            self.finish_mined(&pending).await?;
            return Ok(LaneState::Free);
        }
        if latest > pending.nonce {
            // Held until enough confirmations have passed to protect against
            // a tip reorganization.
            return Ok(LaneState::Mined);
        }
        // Probe only the current and the most recent superseded candidate.
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.superseded_hashes.last())
        {
            let transaction = self.rpc("eth_getTransactionByHash", json!([hash])).await?;
            if !transaction.is_null() {
                self.observed_fees = transaction_fees(&transaction);
                return Ok(LaneState::Pending);
            }
        }
        if let Some(hash) = pending.transaction_hash {
            // Unknown to the RPC (dropped, or not propagated): it may still
            // mine, so it is kept until the nonce is consumed.
            let entry = self.checkpoint.pending.as_mut().expect("pending");
            entry.transaction_hash = None;
            push_superseded(&mut entry.superseded_hashes, hash);
            self.persist()?;
        }
        // The sender is dedicated, so a pending count past this unmined nonce
        // means an attempt without a known hash occupies it.
        if self.transaction_count("pending").await? > pending.nonce {
            return Ok(LaneState::Held);
        }
        // An ambiguous send without a hash may sit in a pool this RPC does
        // not see: it holds the nonce for `bump_after_blocks`. Nothing having
        // appeared by then, the nonce is re-sent at the persisted fees (only
        // one attempt on it can mine), so a send that never left cannot hold
        // it for ever.
        if pending.unknown_attempt
            && pending.submitted_block.is_some_and(|block| {
                head.number.saturating_sub(block) < self.config.fee.bump_after_blocks
            })
        {
            return Ok(LaneState::Held);
        }
        Ok(LaneState::Reserved)
    }

    /// The nonce is consumed at confirmation depth: record how its
    /// transaction ended and release it.
    async fn finish_mined(&mut self, pending: &PendingActivation) -> anyhow::Result<()> {
        let mut receipt = None;
        for hash in pending
            .transaction_hash
            .iter()
            .chain(pending.superseded_hashes.iter().rev())
        {
            let found = self.rpc("eth_getTransactionReceipt", json!([hash])).await?;
            if !found.is_null() {
                receipt = Some((hash.clone(), found));
                break;
            }
        }
        let vault = self.vault_address();
        let confirmed_at = unix_now();
        let record = match receipt {
            Some((hash, receipt)) => {
                let succeeded = receipt.get("status").and_then(Value::as_str) == Some("0x1");
                let activated = succeeded
                    .then(|| notes_activated(&receipt, &vault))
                    .flatten();
                let (first, size) =
                    activated.unwrap_or((pending.call.first_note_id, pending.call.count));
                BatchRecord {
                    first_note_id: first,
                    size,
                    outcome: if activated.is_some() {
                        BatchOutcome::Activated
                    } else {
                        BatchOutcome::Reverted
                    },
                    proving_ms: if (first, size) == (pending.call.first_note_id, pending.call.count)
                    {
                        pending.call.proving_ms
                    } else {
                        0
                    },
                    gas_used: receipt.get("gasUsed").and_then(|gas| quantity(gas).ok()),
                    transaction_hash: Some(hash),
                    block: receipt
                        .get("blockNumber")
                        .and_then(|block| quantity(block).ok()),
                    confirmed_at,
                }
            }
            None => BatchRecord {
                first_note_id: pending.call.first_note_id,
                size: pending.call.count,
                outcome: BatchOutcome::Unknown,
                proving_ms: pending.call.proving_ms,
                gas_used: None,
                transaction_hash: None,
                block: None,
                confirmed_at,
            },
        };
        let totals = &mut self.checkpoint.totals;
        match record.outcome {
            BatchOutcome::Activated => {
                totals.batches_activated_total = totals.batches_activated_total.saturating_add(1);
                totals.notes_activated_total = totals
                    .notes_activated_total
                    .saturating_add(record.size.into());
                let by_size = match record.size {
                    1 => &mut totals.batches_1_total,
                    4 => &mut totals.batches_4_total,
                    _ => &mut totals.batches_16_total,
                };
                *by_size = by_size.saturating_add(1);
            }
            BatchOutcome::Reverted => {
                totals.reverted_total = totals.reverted_total.saturating_add(1)
            }
            BatchOutcome::Unknown => {}
        }
        totals.gas_used_total = totals
            .gas_used_total
            .saturating_add(record.gas_used.unwrap_or_default());
        match record.outcome {
            BatchOutcome::Activated => tracing::info!(
                nonce = pending.nonce,
                first_note_id = record.first_note_id,
                batch_size = record.size,
                gas_used = record.gas_used,
                proving_ms = record.proving_ms,
                transaction_hash = record.transaction_hash.as_deref().unwrap_or_default(),
                "activation confirmed"
            ),
            BatchOutcome::Reverted => tracing::warn!(
                nonce = pending.nonce,
                first_note_id = record.first_note_id,
                batch_size = record.size,
                gas_used = record.gas_used,
                "the worker's activation mined and reverted: another activation or a retirement landed first"
            ),
            BatchOutcome::Unknown => tracing::warn!(
                nonce = pending.nonce,
                "the worker's nonce was consumed by an attempt without a known receipt"
            ),
        }
        self.checkpoint.last_batch = Some(record);
        self.checkpoint.pending = None;
        self.observed_fees = None;
        self.persist()
    }

    async fn nonce_counts(&mut self) -> anyhow::Result<(u64, u64)> {
        let head = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        let latest = self.transaction_count("latest").await?;
        let confirmed = match head.checked_sub(self.config.confirmations) {
            Some(block) => self.transaction_count(&format!("0x{block:x}")).await?,
            None => 0,
        };
        // A reorganization or a newly mined block may race the reads: never
        // release a reservation whose consumption the latest read did not see.
        Ok((latest, confirmed.min(latest)))
    }

    async fn transaction_count(&self, tag: &str) -> anyhow::Result<u64> {
        quantity(
            &self
                .rpc("eth_getTransactionCount", json!([self.config.sender, tag]))
                .await?,
        )
    }

    async fn fetch_head(&mut self) -> anyhow::Result<HeadInfo> {
        let block = self
            .rpc("eth_getBlockByNumber", json!(["latest", false]))
            .await?;
        let head = HeadInfo {
            number: quantity(&block["number"]).context("latest block lacks a number")?,
            hash: block.get("hash").and_then(Value::as_str).map(str::to_owned),
            timestamp: quantity(&block["timestamp"]).context("latest block lacks a timestamp")?,
            base_fee: block
                .get("baseFeePerGas")
                .filter(|value| !value.is_null())
                .map(quantity_u128)
                .transpose()?,
        };
        let chain = &mut self.snapshot.chain;
        chain.latest_block = Some(head.number);
        chain.latest_block_timestamp = Some(head.timestamp);
        chain.base_fee_per_gas_wei = head.base_fee.map(|fee| fee.to_string());
        Ok(head)
    }

    /// `currentRoot()`, `activationCursor()`, `nextNoteId()` and `paused()`
    /// at `block`.
    async fn vault_state(&mut self, block: Value) -> anyhow::Result<VaultState> {
        let word = |words: Vec<Felt252>, name: &str| -> anyhow::Result<Felt252> {
            ensure!(words.len() == 1, "malformed {name} response");
            Ok(words[0])
        };
        let root = word(
            self.call_at("currentRoot()", block.clone()).await?,
            "currentRoot",
        )?;
        let cursor = felt_u64(&word(
            self.call_at("activationCursor()", block.clone()).await?,
            "activationCursor",
        )?)?;
        let next = felt_u64(&word(
            self.call_at("nextNoteId()", block.clone()).await?,
            "nextNoteId",
        )?)?;
        let paused = match felt_u64(&word(self.call_at("paused()", block).await?, "paused")?)? {
            0 => false,
            1 => true,
            _ => bail!("malformed paused response"),
        };
        let state = VaultState {
            root,
            cursor: u32::try_from(cursor).context("activation cursor exceeds uint32")?,
            next_note_id: u32::try_from(next).context("next note ID exceeds uint32")?,
            paused,
        };
        ensure!(
            state.cursor <= state.next_note_id,
            "vault activation cursor {} is past nextNoteId {}",
            state.cursor,
            state.next_note_id
        );
        self.snapshot.chain.current_root = Some(state.root);
        self.snapshot.chain.paused = Some(state.paused);
        Ok(state)
    }

    async fn vault_note(&self, note_id: u32, block: Value) -> anyhow::Result<VaultNote> {
        let mut data = selector("notes(uint32)");
        data.extend_from_slice(Felt252::from_u64(note_id.into()).as_bytes());
        let raw = self
            .rpc(
                "eth_call",
                json!([{ "to": self.vault_address(), "data": format!("0x{}", hex::encode(data)) }, block]),
            )
            .await?;
        VaultNote::decode(raw.as_str().context("malformed notes response")?)
            .map_err(|error| anyhow!("note {note_id}: {error}"))
    }

    /// The vault's notes of `call`'s batch at `block`.
    async fn batch_notes(
        &self,
        call: &ActivationCall,
        block: Value,
    ) -> anyhow::Result<Vec<VaultNote>> {
        let mut notes = Vec::with_capacity(call.count as usize);
        for note_id in call.first_note_id..call.first_note_id + call.count {
            notes.push(self.vault_note(note_id, block.clone()).await?);
        }
        Ok(notes)
    }

    async fn call_at(&self, signature: &str, block: Value) -> anyhow::Result<Vec<Felt252>> {
        words(
            &self
                .rpc(
                    "eth_call",
                    json!([{
                        "to": self.vault_address(),
                        "data": format!("0x{}", hex::encode(selector(signature))),
                    }, block]),
                )
                .await?,
        )
    }

    /// The sender's balance and the signer's transaction fee cap, at most
    /// every `OBSERVE_INTERVAL_SECONDS`.
    async fn observe_sender(&mut self) {
        let now = unix_now();
        if self
            .last_observed_at
            .is_some_and(|at| now.saturating_sub(at) < OBSERVE_INTERVAL_SECONDS)
        {
            return;
        }
        self.last_observed_at = Some(now);
        if let Ok(balance) = self
            .rpc("eth_getBalance", json!([self.config.sender, "latest"]))
            .await
            .and_then(|value| quantity_u128(&value))
        {
            self.sender_balance = Some(balance);
            self.snapshot.sender.balance_wei = Some(balance.to_string());
            self.snapshot.sender.balance_observed_at = Some(now);
        }
        // The bundled signer reports its cap; without a report, a cap learned
        // from a refusal stays in force.
        if let Ok(Some(cap)) = self
            .rpc("zkapi_signerStatus", json!([]))
            .await
            .and_then(|status| {
                status
                    .get("tx_fee_cap_wei")
                    .filter(|value| !value.is_null())
                    .map(quantity_u128)
                    .transpose()
            })
        {
            if cap > 0 {
                self.signer_tx_fee_cap = Some(cap);
            }
        }
        self.snapshot.sender.signer_tx_fee_cap_wei =
            self.signer_tx_fee_cap.map(|cap| cap.to_string());
    }

    /// The transaction fee ceiling in force: the lowest of the worker's, the
    /// signer's and 10/11 of the lowest fee its node refused.
    fn tx_fee_cap(&self) -> u128 {
        self.config
            .fee
            .tx_fee_cap_wei
            .min(self.signer_tx_fee_cap.unwrap_or(u128::MAX))
            .min(
                self.node_refused_tx_fee
                    .map(headroom)
                    .filter(|bound| *bound > 0)
                    .unwrap_or(u128::MAX),
            )
    }

    /// The highest maxFeePerGas the ceiling allows at `gas`.
    fn tx_fee_limit(&self, gas: u64) -> u128 {
        self.tx_fee_cap() / u128::from(gas).max(1)
    }

    fn prover(&self, size: usize) -> Arc<InsertionProver> {
        let index = INSERTION_SIZES
            .iter()
            .position(|candidate| *candidate == size)
            .expect("an insertion size");
        self.provers[index].clone()
    }

    fn observe_queue(&mut self, state: &VaultState) {
        let queue = &mut self.snapshot.queue;
        queue.activation_cursor = Some(state.cursor);
        queue.next_note_id = Some(state.next_note_id);
        queue.pending_notes = u64::from(state.next_note_id - state.cursor);
        queue.oldest_pending_seen_at = self.checkpoint.observed.seen_at(state.cursor);
    }

    fn set_state(&mut self, state: WorkerState, detail: String) {
        self.snapshot.state = state;
        self.snapshot.detail = Some(detail);
        self.snapshot.blocked_reason = None;
        self.snapshot.blocked_since = None;
    }

    fn block(&mut self, reason: ActivationBlocked, detail: String) {
        if self.snapshot.blocked_since.is_none() {
            self.snapshot.blocked_since = Some(unix_now());
        }
        self.snapshot.state = WorkerState::Blocked;
        self.snapshot.blocked_reason = Some(reason);
        self.snapshot.detail = Some(bounded(&detail));
    }

    /// Record `error` as blocking and return it.
    fn blocked(&mut self, reason: ActivationBlocked, error: anyhow::Error) -> anyhow::Error {
        self.block(reason, format!("{error:#}"));
        error
    }

    fn publish(&mut self) {
        self.snapshot.totals = self.checkpoint.totals.clone();
        self.snapshot.last_batch = self.checkpoint.last_batch.clone();
        self.snapshot.pending_call =
            self.checkpoint
                .pending
                .as_ref()
                .map(|pending| PendingCallStatus {
                    nonce: pending.nonce,
                    first_note_id: pending.call.first_note_id,
                    size: pending.call.count,
                    transaction_hash: pending.transaction_hash.clone(),
                    attempts: pending.attempts,
                    max_fee_per_gas_wei: pending.fees().map(|fees| fees.max_fee.to_string()),
                    max_priority_fee_per_gas_wei: pending.fees().map(|fees| fees.tip.to_string()),
                    gas_limit: pending.gas_limit,
                    submitted_block: pending.submitted_block,
                });
        let snapshot = self.snapshot.clone();
        match self.status.write() {
            Ok(mut status) => *status = snapshot,
            Err(poisoned) => *poisoned.into_inner() = snapshot,
        }
    }

    fn vault_address(&self) -> String {
        format!(
            "0x{}",
            hex::encode(&self.config.contract_address.as_bytes()[12..])
        )
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        self.rpc_with_timeout(method, params, None).await
    }

    async fn rpc_with_timeout(
        &self,
        method: &str,
        params: Value,
        timeout: Option<Duration>,
    ) -> anyhow::Result<Value> {
        rpc_request(&self.client, &self.config.rpc_url, method, params, timeout).await
    }

    async fn indexer_get<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let response = self
            .client
            .get(format!(
                "{}{path}",
                self.config.indexer_url.trim_end_matches('/')
            ))
            .timeout(INDEXER_TIMEOUT)
            .send()
            .await
            .map_err(|error| anyhow!(error.without_url().to_string()))?;
        if !response.status().is_success() {
            bail!("HTTP {}", response.status().as_u16());
        }
        response
            .json()
            .await
            .map_err(|error| anyhow!(error.without_url().to_string()))
    }

    fn persist(&self) -> anyhow::Result<()> {
        write_json_atomically(&self.config.checkpoint, &self.checkpoint)
    }
}

/// The batch a receipt's `NotesActivated` log of `vault` activated.
fn notes_activated(receipt: &Value, vault: &str) -> Option<(u32, u32)> {
    let topic0 = format!(
        "0x{}",
        hex::encode(Keccak256::digest(NOTES_ACTIVATED_EVENT.as_bytes()))
    );
    receipt.get("logs")?.as_array()?.iter().find_map(|log| {
        let topics = log.get("topics")?.as_array()?;
        if !log.get("address")?.as_str()?.eq_ignore_ascii_case(vault)
            || !topics.first()?.as_str()?.eq_ignore_ascii_case(&topic0)
            || topics.len() != 2
        {
            return None;
        }
        let first = u32::try_from(quantity(&topics[1]).ok()?).ok()?;
        let data = words(log.get("data")?).ok()?;
        let count = u32::try_from(felt_u64(data.first()?).ok()?).ok()?;
        (data.len() == 3).then_some((first, count))
    })
}

fn bounded(text: &str) -> String {
    text.chars().take(MAX_ERROR_CHARS).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_lane::GWEI;
    use axum::{
        extract::{Path, State},
        routing::{get, post},
        Json, Router,
    };
    use std::{
        collections::BTreeMap,
        sync::{Mutex, OnceLock},
    };
    use zkapi_core::MerkleTree;
    use zkapi_proof::compact::InsertionVerifier;

    const SENDER: &str = "0x00000000000000000000000000000000000000a1";
    const VAULT: u64 = 0xdead;

    #[test]
    fn batches_are_the_largest_aligned_recorded_size_with_a_bounded_wait() {
        let now = 1_000;
        // Nothing recorded waits.
        assert_eq!(choose_batch(7, 7, now, now, 30), BatchChoice::Idle);
        // Low volume: one deposit at a 16-aligned cursor waits for the
        // larger batch, then is activated alone at the bound.
        assert_eq!(
            choose_batch(0, 1, now, now + 29, 30),
            BatchChoice::Wait {
                size: 1,
                aligned: 16,
                until: now + 30
            }
        );
        assert_eq!(
            choose_batch(0, 1, now, now + 30, 30),
            BatchChoice::Activate(1)
        );
        // Without a wait, the largest available aligned size at once.
        assert_eq!(choose_batch(0, 1, now, now, 0), BatchChoice::Activate(1));
        assert_eq!(choose_batch(0, 5, now, now, 0), BatchChoice::Activate(4));
        // A full aligned batch never waits.
        assert_eq!(
            choose_batch(0, 16, now, now, 3_600),
            BatchChoice::Activate(16)
        );
        assert_eq!(
            choose_batch(32, 100, now, now, 3_600),
            BatchChoice::Activate(16)
        );
        // At a cursor aligned to 4 but not 16, 4 is the largest batch: no
        // wait for it, and a backlog catches up 4 at a time to alignment.
        assert_eq!(
            choose_batch(4, 30, now, now, 3_600),
            BatchChoice::Activate(4)
        );
        assert_eq!(
            choose_batch(20, 22, now, now, 3_600),
            BatchChoice::Wait {
                size: 1,
                aligned: 4,
                until: now + 3_600
            }
        );
        // At an odd cursor only singletons exist.
        assert_eq!(
            choose_batch(5, 30, now, now, 3_600),
            BatchChoice::Activate(1)
        );
        assert_eq!(largest_aligned(0), 16);
        assert_eq!(largest_aligned(8), 4);
        assert_eq!(largest_aligned(6), 1);
        assert_eq!(largest_aligned(48), 16);
    }

    #[test]
    fn observations_date_pending_notes_from_their_first_sighting() {
        let mut seen = Observations::default();
        assert!(seen.observe(0, 3, 100));
        assert!(!seen.observe(0, 3, 105));
        assert!(seen.observe(0, 5, 110));
        assert_eq!(seen.seen_at(0), Some(100));
        assert_eq!(seen.seen_at(2), Some(100));
        assert_eq!(seen.seen_at(3), Some(110));
        assert_eq!(seen.seen_at(5), None);
        // Activated notes are forgotten; the rest keep their first sighting.
        assert!(seen.observe(3, 5, 120));
        assert_eq!(seen.0, vec![(5, 110)]);
        assert_eq!(seen.seen_at(3), Some(110));
        // A reorganization that removes deposits forgets them; they are new
        // if they come back.
        assert!(seen.observe(3, 4, 130));
        assert_eq!(seen.seen_at(3), Some(130));
        // Everything activated: nothing is kept.
        assert!(seen.observe(4, 4, 140));
        assert!(seen.0.is_empty());
    }

    #[test]
    fn activation_calldata_matches_forge_abi_encode() {
        let root =
            Felt252::from_hex("0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9")
                .unwrap();
        let new_root =
            Felt252::from_hex("0x1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a")
                .unwrap();
        let proof: Vec<u8> = (1..=256).map(|byte| byte as u8).collect();
        let golden = crate::test_support::real_vault_layout()["activate"]
            .as_str()
            .unwrap()
            .to_string();
        let calldata = activate_calldata(8, 4, &root, &new_root, &proof).unwrap();
        assert_eq!(format!("0x{}", hex::encode(&calldata)), golden);
        assert_eq!(calldata.len(), ACTIVATE_CALLDATA_LEN);
        assert_eq!(
            &Keccak256::digest(ACTIVATE_SIGNATURE.as_bytes())[..4],
            &ACTIVATE_SELECTOR
        );
        assert_eq!(
            crate::test_support::real_selector("activateNotes"),
            format!("0x{}", hex::encode(ACTIVATE_SELECTOR))
        );
        // The getters, the event and the reverts are the real vault's.
        for (name, signature) in [
            ("activationCursor", "activationCursor()"),
            ("nextNoteId", "nextNoteId()"),
            ("currentRoot", "currentRoot()"),
            ("paused", "paused()"),
            ("notes", "notes(uint32)"),
        ] {
            assert_eq!(
                crate::test_support::real_selector(name),
                format!("0x{}", hex::encode(selector(signature))),
                "{name}"
            );
        }
        let (topics, data) = crate::test_support::real_event("NotesActivated");
        assert_eq!(
            topics[0],
            format!(
                "0x{}",
                hex::encode(Keccak256::digest(NOTES_ACTIVATED_EVENT.as_bytes()))
            )
        );
        // emit NotesActivated(4, 4, 0x0d0d, true).
        let vault = "0x00000000000000000000000000000000000000aa";
        let receipt = json!({ "logs": [{ "address": vault, "topics": topics, "data": data }] });
        assert_eq!(notes_activated(&receipt, vault), Some((4, 4)));
        assert_eq!(notes_activated(&receipt, SENDER), None);
        for (signature, selector_hex) in [
            ("StaleActivation()", "9c9413a1"),
            ("InvalidActivation()", "e72f8984"),
            ("InvalidProof()", "09bde339"),
            ("Paused()", "9e87fac8"),
        ] {
            assert_eq!(
                hex::encode(selector(signature)),
                selector_hex,
                "{signature}"
            );
        }
        // What the vault never accepts is never encoded.
        for (first, count) in [(8, 3), (6, 4), (16, 32), (0, 0)] {
            assert!(activate_calldata(first, count, &root, &new_root, &proof).is_err());
        }
        assert!(activate_calldata(8, 4, &Felt252([0xff; 32]), &new_root, &proof).is_err());
        assert!(activate_calldata(8, 4, &root, &new_root, &proof[1..]).is_err());
    }

    // ---- A mock vault, signer RPC and indexer ------------------------------

    /// What the mock applies when the worker first asks the indexer for a
    /// path: between its state read and its send, i.e. while it proves.
    enum Hook {
        Deposit(u32),
        CompetingActivation(u32),
        /// A shallow reorganization re-includes these two recorded deposits
        /// in the other order: cursor, root and nextNoteId are unchanged.
        Reorder(u32, u32),
    }

    #[derive(Clone)]
    struct MockNote {
        commitment: Felt252,
        amount: u128,
        expiry: u64,
        status: u8,
    }

    #[derive(Clone)]
    struct PoolTx {
        hash: String,
        data: String,
        max_fee: u128,
        tip: u128,
        gas: u64,
    }

    /// The chain at one point, which `MockVault::reorg_to` returns to.
    #[derive(Clone)]
    struct ChainSnapshot {
        notes: Vec<MockNote>,
        tree: MerkleTree,
        cursor: u32,
        head: u64,
        timestamp: u64,
        mined: usize,
    }

    struct MockVault {
        notes: Vec<MockNote>,
        tree: MerkleTree,
        cursor: u32,
        paused: bool,
        head: u64,
        timestamp: u64,
        base_fee: u128,
        /// Reorganizations so far: part of the block hash.
        reorgs: u64,
        /// Part of the commitment of every later deposit, so a deposit after
        /// a reorganization can record another note at the same ID.
        fork: u64,
        /// The next this many sends fail ambiguously (no hash) without
        /// reaching the pool.
        ambiguous_sends: u32,
        /// The sender's mined transactions, in nonce order: (block, tx).
        mined: Vec<(u64, PoolTx)>,
        pool: BTreeMap<u64, PoolTx>,
        receipts: BTreeMap<String, Value>,
        sends: Vec<Value>,
        /// The indexer serves this tree instead of the vault's (it lags).
        indexer_tree: Option<MerkleTree>,
        hook: Option<Hook>,
        /// The adapter refuses every proof (its keys are not the worker's).
        reject_proofs: bool,
        /// Answers of the startup probes: getter selector -> word.
        probe_words: BTreeMap<String, String>,
        code: BTreeMap<String, String>,
    }

    impl MockVault {
        fn new() -> Self {
            Self {
                notes: Vec::new(),
                tree: MerkleTree::new(),
                cursor: 0,
                paused: false,
                head: 10,
                timestamp: unix_now(),
                base_fee: GWEI,
                reorgs: 0,
                fork: 0,
                ambiguous_sends: 0,
                mined: Vec::new(),
                pool: BTreeMap::new(),
                receipts: BTreeMap::new(),
                sends: Vec::new(),
                indexer_tree: None,
                hook: None,
                reject_proofs: false,
                probe_words: BTreeMap::new(),
                code: BTreeMap::new(),
            }
        }

        fn deposit(&mut self, count: u32) {
            for _ in 0..count {
                let id = self.notes.len() as u64;
                self.notes.push(MockNote {
                    commitment: Felt252::from_u64(0xc000 + id + (self.fork << 32)),
                    amount: 1_000_000 + u128::from(id),
                    expiry: 4_000_000_000,
                    status: crate::native_billing::NOTE_STATUS_ACTIVE,
                });
            }
        }

        fn leaf(&self, id: u32) -> Felt252 {
            let note = &self.notes[id as usize];
            zkapi_core::v2::note_leaf(id, &note.commitment, note.amount, note.expiry)
        }

        /// Append `count` recorded notes at the cursor, as either entry
        /// point does.
        fn activate(&mut self, count: u32) {
            for id in self.cursor..self.cursor + count {
                let leaf = self.leaf(id);
                self.tree.set_leaf(id, leaf);
            }
            self.cursor += count;
        }

        /// Someone else's `activateNotesOnChain` lands in a new block.
        fn activate_on_chain(&mut self, count: u32) {
            self.activate(count);
            self.head += 1;
        }

        /// The challenger's `retireClosedLeaf` of an activated closed note.
        fn retire(&mut self, id: u32) {
            self.notes[id as usize].status = crate::native_billing::NOTE_STATUS_CLOSED;
            self.tree.set_leaf(id, Felt252::ZERO);
            self.head += 1;
        }

        fn latest_count(&self) -> u64 {
            self.mined.len() as u64
        }

        fn snapshot(&self) -> ChainSnapshot {
            ChainSnapshot {
                notes: self.notes.clone(),
                tree: self.tree.clone(),
                cursor: self.cursor,
                head: self.head,
                timestamp: self.timestamp,
                mined: self.mined.len(),
            }
        }

        /// A reorganization back to `snapshot`, as Anvil's `evm_revert`: the
        /// later blocks, their deposits, activations and receipts are gone.
        /// The sender's transactions in them return to the pool when the
        /// node re-injects them (`reinject`), else they are dropped.
        fn reorg_to(&mut self, snapshot: ChainSnapshot, reinject: bool) {
            let undone = self.mined.split_off(snapshot.mined);
            for (nonce, (_, tx)) in (snapshot.mined as u64..).zip(undone) {
                self.receipts.remove(&tx.hash);
                if reinject {
                    self.pool.insert(nonce, tx);
                }
            }
            self.notes = snapshot.notes;
            self.tree = snapshot.tree;
            self.cursor = snapshot.cursor;
            self.head = snapshot.head;
            self.timestamp = snapshot.timestamp;
            self.reorgs += 1;
        }

        /// Blocks without the sender's pending transaction (it is not
        /// included).
        fn advance(&mut self, blocks: u64) {
            self.head += blocks;
            self.timestamp += 12 * blocks;
        }

        /// Why `activateNotes` reverts at the current state, if it does.
        fn check_activation(&self, data: &str) -> Result<(u32, u32, Felt252), &'static str> {
            let bytes = hex::decode(data.trim_start_matches("0x")).unwrap();
            assert_eq!(&bytes[..4], &ACTIVATE_SELECTOR, "only activations are sent");
            let word =
                |index: usize| Felt252(bytes[4 + 32 * index..36 + 32 * index].try_into().unwrap());
            let first = word(0).to_u64().unwrap() as u32;
            let count = word(1).to_u64().unwrap() as u32;
            let (expected, new_root) = (word(2), word(3));
            if self.paused {
                return Err("9e87fac8");
            }
            if !is_insertion_size(count as usize) {
                return Err("e72f8984");
            }
            if first != self.cursor {
                return Err("9c9413a1");
            }
            if !first.is_multiple_of(count) || (first + count) as usize > self.notes.len() {
                return Err("e72f8984");
            }
            if expected != self.tree.root() {
                return Err("9c9413a1");
            }
            let public = InsertionPublic {
                old_root: zkapi_core::v2::felt_to_field(&expected),
                new_root: zkapi_core::v2::felt_to_field(&new_root),
                first_note_id: first,
                notes: (first..first + count)
                    .map(|id| {
                        let note = &self.notes[id as usize];
                        InsertedNote {
                            registration_commitment: zkapi_core::v2::felt_to_field(
                                &note.commitment,
                            ),
                            deposit_amount: note.amount,
                            expiry: note.expiry,
                        }
                    })
                    .collect(),
            };
            let proof = zkapi_types::wire::Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD.encode(&bytes[196..452]),
            };
            if self.reject_proofs || !verifier(count as usize).verify(&public, &proof).unwrap() {
                return Err("09bde339");
            }
            Ok((first, count, new_root))
        }

        /// Mine a block with the sender's next pool transaction, if any.
        fn mine(&mut self) {
            self.head += 1;
            self.timestamp += 12;
            let nonce = self.latest_count();
            let Some(tx) = self.pool.remove(&nonce) else {
                return;
            };
            let (status, logs) = match self.check_activation(&tx.data) {
                Ok((first, count, new_root)) => {
                    self.activate(count);
                    assert_eq!(
                        self.tree.root(),
                        new_root,
                        "the proved new root is the tree's"
                    );
                    let log = json!({
                        "address": format!("0x{VAULT:040x}"),
                        "topics": [
                            format!("0x{}", hex::encode(Keccak256::digest(NOTES_ACTIVATED_EVENT.as_bytes()))),
                            format!("0x{first:064x}"),
                        ],
                        "data": format!("0x{count:064x}{}{:064x}", hex::encode(new_root.as_bytes()), 1),
                    });
                    ("0x1", vec![log])
                }
                Err(_) => ("0x0", vec![]),
            };
            self.receipts.insert(
                tx.hash.clone(),
                json!({
                    "transactionHash": tx.hash,
                    "status": status,
                    "gasUsed": format!("0x{:x}", tx.gas * 5 / 6),
                    "blockNumber": format!("0x{:x}", self.head),
                    "logs": logs,
                }),
            );
            self.mined.push((self.head, tx));
        }
    }

    fn verifier(size: usize) -> &'static InsertionVerifier {
        static VERIFIERS: OnceLock<Vec<InsertionVerifier>> = OnceLock::new();
        let verifiers = VERIFIERS.get_or_init(|| {
            INSERTION_SIZES
                .iter()
                .map(|size| {
                    InsertionVerifier::load(crate::test_support::setup_directory(), *size).unwrap()
                })
                .collect()
        });
        &verifiers[INSERTION_SIZES.iter().position(|s| *s == size).unwrap()]
    }

    type Shared = Arc<Mutex<MockVault>>;

    fn word_hex(value: u64) -> String {
        format!("0x{value:064x}")
    }

    fn revert(selector_hex: &str) -> Value {
        json!({ "code": 3, "message": "execution reverted", "data": format!("0x{selector_hex}") })
    }

    async fn rpc(State(vault): State<Shared>, Json(request): Json<Value>) -> Json<Value> {
        let mut vault = vault.lock().unwrap();
        let params = &request["params"];
        let result: Result<Value, Value> = match request["method"].as_str().unwrap() {
            "eth_chainId" => Ok(json!("0x1")),
            "eth_blockNumber" => Ok(json!(format!("0x{:x}", vault.head))),
            "eth_getBlockByNumber" => Ok(json!({
                "number": format!("0x{:x}", vault.head),
                "hash": format!("0x{:032x}{:032x}", vault.reorgs, vault.head),
                "timestamp": format!("0x{:x}", vault.timestamp),
                "baseFeePerGas": format!("0x{:x}", vault.base_fee),
            })),
            "eth_getBalance" => Ok(json!(format!("0x{:x}", 1_000u128 * GWEI * GWEI))),
            "zkapi_signerStatus" => Err(json!({ "code": -32601, "message": "method not found" })),
            "eth_getCode" => Ok(json!(vault
                .code
                .get(params[0].as_str().unwrap())
                .cloned()
                .unwrap_or_else(|| "0x".into()))),
            "eth_getTransactionCount" => {
                let latest = vault.latest_count();
                Ok(json!(format!(
                    "0x{:x}",
                    match params[1].as_str().unwrap() {
                        "latest" => latest,
                        "pending" => latest + vault.pool.len() as u64,
                        block => {
                            let block = u64::from_str_radix(&block[2..], 16).unwrap();
                            vault.mined.iter().filter(|(at, _)| *at <= block).count() as u64
                        }
                    }
                )))
            }
            "eth_getTransactionByHash" => {
                let hash = params[0].as_str().unwrap();
                Ok(vault
                    .pool
                    .values()
                    .find(|tx| tx.hash == hash)
                    .map(|tx| {
                        json!({
                            "hash": tx.hash,
                            "maxFeePerGas": format!("0x{:x}", tx.max_fee),
                            "maxPriorityFeePerGas": format!("0x{:x}", tx.tip),
                        })
                    })
                    .unwrap_or(Value::Null))
            }
            "eth_getTransactionReceipt" => Ok(vault
                .receipts
                .get(params[0].as_str().unwrap())
                .cloned()
                .unwrap_or(Value::Null)),
            "eth_estimateGas" => {
                match vault.check_activation(params[0]["data"].as_str().unwrap()) {
                    Ok((_, count, _)) => Ok(json!(format!(
                        "0x{:x}",
                        250_000 + 20_000 * u64::from(count)
                    ))),
                    Err(selector_hex) => Err(revert(selector_hex)),
                }
            }
            "eth_call" => {
                let data = params[0]["data"].as_str().unwrap().to_string();
                let call = |signature: &str| format!("0x{}", hex::encode(selector(signature)));
                if let Some(word) = vault.probe_words.get(&data) {
                    Ok(json!(word))
                } else if data == call("currentRoot()") {
                    Ok(json!(format!(
                        "0x{}",
                        hex::encode(vault.tree.root().as_bytes())
                    )))
                } else if data == call("activationCursor()") {
                    Ok(json!(word_hex(vault.cursor.into())))
                } else if data == call("nextNoteId()") {
                    Ok(json!(word_hex(vault.notes.len() as u64)))
                } else if data == call("paused()") {
                    Ok(json!(word_hex(vault.paused as u64)))
                } else if let Some(id) = data.strip_prefix(&call("notes(uint32)")) {
                    let id = u32::from_str_radix(id, 16).unwrap() as usize;
                    Ok(json!(match vault.notes.get(id) {
                        Some(note) => format!(
                            "0x{}{:064x}{:064x}{:064x}",
                            hex::encode(note.commitment.as_bytes()),
                            note.amount,
                            note.expiry,
                            note.status
                        ),
                        None => format!("0x{}", "0".repeat(256)),
                    }))
                } else {
                    match vault.check_activation(&data) {
                        Ok(_) => Ok(json!("0x")),
                        Err(selector_hex) => Err(revert(selector_hex)),
                    }
                }
            }
            "eth_sendTransaction" => {
                let tx = &params[0];
                vault.sends.push(tx.clone());
                let quantity = |name: &str| {
                    u128::from_str_radix(&tx[name].as_str().unwrap()[2..], 16).unwrap()
                };
                let nonce = quantity("nonce") as u64;
                let hash = format!(
                    "0x{}",
                    hex::encode(Keccak256::digest(tx.to_string().as_bytes()))
                );
                let replaced = vault.pool.get(&nonce).cloned();
                if vault.ambiguous_sends > 0 {
                    vault.ambiguous_sends -= 1;
                    Err(json!({ "code": -32000, "message": "upstream request timed out" }))
                } else if nonce < vault.latest_count() {
                    Err(json!({ "code": -32000, "message": "nonce too low" }))
                } else if replaced.is_some_and(|old| {
                    quantity("maxFeePerGas") < old.max_fee * 11 / 10
                        || quantity("maxPriorityFeePerGas") < old.tip * 11 / 10
                }) {
                    Err(json!({ "code": -32000, "message": "replacement transaction underpriced" }))
                } else {
                    vault.pool.insert(
                        nonce,
                        PoolTx {
                            hash: hash.clone(),
                            data: tx["data"].as_str().unwrap().into(),
                            max_fee: quantity("maxFeePerGas"),
                            tip: quantity("maxPriorityFeePerGas"),
                            gas: quantity("gas") as u64,
                        },
                    );
                    Ok(json!(hash))
                }
            }
            method => panic!("unexpected RPC method {method}"),
        };
        Json(match result {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
            Err(error) => json!({ "jsonrpc": "2.0", "id": 1, "error": error }),
        })
    }

    async fn path(State(vault): State<Shared>, Path(id): Path<u32>) -> Json<Value> {
        let mut vault = vault.lock().unwrap();
        match vault.hook.take() {
            Some(Hook::Deposit(count)) => vault.deposit(count),
            Some(Hook::CompetingActivation(count)) => vault.activate_on_chain(count),
            Some(Hook::Reorder(a, b)) => {
                vault.notes.swap(a as usize, b as usize);
                vault.reorgs += 1;
            }
            None => {}
        }
        let tree = vault
            .indexer_tree
            .clone()
            .unwrap_or_else(|| vault.tree.clone());
        Json(json!({
            "note_id": id,
            "leaf": tree.get_leaf(id),
            "siblings": tree.get_siblings(id).to_vec(),
            "root": tree.root(),
            "block_number": vault.head,
            "block_hash": format!("0x{:064x}", vault.head),
            "activated": id < vault.cursor,
            "activation_cursor": vault.cursor,
        }))
    }

    struct Fixture {
        vault: Shared,
        config: ActivationServiceConfig,
        server: tokio::task::JoinHandle<()>,
        _directory: tempfile::TempDir,
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Fixture {
        async fn new(max_wait: u64) -> Self {
            let vault = Arc::new(Mutex::new(MockVault::new()));
            let app = Router::new()
                .route("/", post(rpc))
                .route("/v1/tree/notes/{id}/path", get(path))
                .with_state(vault.clone());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let directory = tempfile::tempdir().unwrap();
            let config = ActivationServiceConfig {
                rpc_url: url.clone(),
                indexer_url: url,
                sender: SENDER.into(),
                contract_address: Felt252::from_u64(VAULT),
                chain_id: 1,
                confirmations: 1,
                checkpoint: directory.path().join("activation.json"),
                proof_setup_dir: PathBuf::from(crate::test_support::setup_directory()),
                fee: FeePolicy::new(100 * GWEI, 10 * GWEI),
                alarms: ActivationAlarmPolicy::default(),
                max_activation_wait_seconds: max_wait,
                dry_run: false,
            };
            Self {
                vault,
                config,
                server,
                _directory: directory,
            }
        }

        fn service(&self) -> ActivationService {
            ActivationService::new(self.config.clone()).unwrap()
        }

        fn vault(&self) -> std::sync::MutexGuard<'_, MockVault> {
            self.vault.lock().unwrap()
        }

        /// The (first note, size) of every activation sent, in order.
        fn sent_batches(&self) -> Vec<(u32, u32)> {
            self.vault()
                .sends
                .iter()
                .map(|tx| {
                    let data = hex::decode(&tx["data"].as_str().unwrap()[2..]).unwrap();
                    let word = |index: usize| {
                        Felt252(data[4 + 32 * index..36 + 32 * index].try_into().unwrap())
                            .to_u64()
                            .unwrap() as u32
                    };
                    (word(0), word(1))
                })
                .collect()
        }

        fn nonces(&self) -> Vec<u64> {
            self.vault()
                .sends
                .iter()
                .map(|tx| u64::from_str_radix(&tx["nonce"].as_str().unwrap()[2..], 16).unwrap())
                .collect()
        }

        /// Mine the pending activation and confirm it (one more block).
        async fn mine_and_confirm(&self, service: &mut ActivationService) {
            self.vault().mine();
            service.poll_once().await.unwrap();
            assert_eq!(service.status().state, WorkerState::Confirming);
            self.vault().mine();
        }
    }

    /// Low volume: one deposit at a 16-aligned cursor waits for a larger
    /// batch at most `max_activation_wait_seconds`, then is activated alone
    /// with a singleton proof; nothing is sent while it waits.
    #[tokio::test]
    async fn a_lone_deposit_is_activated_alone_after_the_bounded_wait() {
        let fixture = Fixture::new(1).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Waiting);
        let next = status.next_batch.unwrap();
        assert_eq!(
            (next.first_note_id, next.size, next.aligned_size),
            (0, 1, 16)
        );
        assert!(next.activate_by.is_some());
        assert_eq!(status.queue.pending_notes, 1);
        assert!(fixture.vault().sends.is_empty());
        tokio::time::sleep(Duration::from_millis(1_100)).await;
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Idle);
        assert_eq!(fixture.vault().cursor, 1);
        assert!(status.pending_call.is_none());
        assert_eq!(status.totals.batches_1_total, 1);
        assert_eq!(status.totals.notes_activated_total, 1);
        let last = status.last_batch.unwrap();
        assert_eq!(last.outcome, BatchOutcome::Activated);
        assert_eq!((last.first_note_id, last.size), (0, 1));
        assert!(last.gas_used.unwrap() > 0);
        assert!(status.totals.proving_ms_total >= last.proving_ms);
    }

    /// Full aligned batches are proved as soon as they are recorded: 16 at
    /// a 16-aligned cursor, then 4 at a cursor aligned to 4 only; a partial
    /// batch at a 16-aligned cursor waits until the bound.
    #[tokio::test]
    async fn full_aligned_batches_of_16_and_4_are_activated_at_once() {
        let fixture = Fixture::new(3_600).await;
        fixture.vault().deposit(16);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 16)]);
        fixture.mine_and_confirm(&mut service).await;
        fixture.vault().deposit(4);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 16);
        assert_eq!(service.status().state, WorkerState::Waiting);
        assert_eq!(fixture.sent_batches(), [(0, 16)]);
        // The bound passes: the 4 recorded notes go as one batch.
        service.config.max_activation_wait_seconds = 0;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 16), (16, 4)]);
        fixture.mine_and_confirm(&mut service).await;
        service.config.max_activation_wait_seconds = 3_600;
        fixture.vault().deposit(4);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 16), (16, 4), (20, 4)]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 24);
        assert_eq!(status.state, WorkerState::Idle);
        assert_eq!(
            (
                status.totals.batches_16_total,
                status.totals.batches_4_total,
                status.totals.notes_activated_total
            ),
            (1, 2, 24)
        );
        assert_eq!(fixture.nonces(), [0, 1, 2]);
    }

    /// A deposit that lands while a batch is proved leaves the batch valid
    /// (it is a prefix of the recorded notes): it is sent and activated, and
    /// the new note waits for the next batch.
    #[tokio::test]
    async fn a_deposit_landing_while_proving_leaves_the_batch_valid() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        fixture.vault().hook = Some(Hook::Deposit(1));
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        assert_eq!(fixture.vault().notes.len(), 2);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(fixture.sent_batches(), [(0, 1), (1, 1)]);
        assert_eq!(service.status().totals.stale_rebuilds_total, 0);
    }

    /// A competing activation (anyone's activateNotesOnChain) lands while
    /// the worker proves: the batch is never sent, and the next poll
    /// rebuilds it from fresh state.
    #[tokio::test]
    async fn a_competing_activation_while_proving_discards_the_batch() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(2);
        fixture.vault().hook = Some(Hook::CompetingActivation(1));
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Rebuilding);
        assert_eq!(status.totals.stale_rebuilds_total, 1);
        assert!(fixture.vault().sends.is_empty());
        assert!(service.checkpoint.pending.is_none());
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(1, 1)]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 2);
    }

    /// A shallow reorganization while the worker proves re-includes the
    /// batch's deposits in another order: cursor, root and nextNoteId are
    /// unchanged, so the batch is simulated and reverts InvalidProof(). Its
    /// notes moved: it is rebuilt from fresh state, not reported as
    /// `proof_rejected`.
    #[tokio::test]
    async fn a_reorg_reordering_the_batch_while_proving_rebuilds_it() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(4);
        fixture.vault().hook = Some(Hook::Reorder(2, 3));
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Rebuilding);
        assert_eq!(status.blocked_reason, None);
        assert_eq!(status.totals.stale_rebuilds_total, 1);
        assert!(fixture.vault().sends.is_empty());
        assert!(service.checkpoint.pending.is_none());
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 4)]);
        assert_eq!(service.status().totals.proofs_total, 2);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 4);
        let vault = fixture.vault();
        assert_eq!(vault.tree.get_leaf(2), vault.leaf(2));
    }

    /// The adapter refuses a fresh proof of the notes the vault still
    /// holds: `proof_rejected` (critical at once), and nothing is sent.
    #[tokio::test]
    async fn a_refused_proof_of_unmoved_notes_is_proof_rejected() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        fixture.vault().reject_proofs = true;
        let mut service = fixture.service();
        let error = service.poll_once().await.unwrap_err();
        assert!(format!("{error:#}").contains("InvalidProof()"));
        let status = service.status();
        assert_eq!(status.state, WorkerState::Blocked);
        assert_eq!(
            status.blocked_reason,
            Some(ActivationBlocked::ProofRejected)
        );
        assert!(status
            .blocked_reason
            .is_some_and(ActivationBlocked::is_immediately_critical));
        assert_eq!(status.totals.stale_rebuilds_total, 0);
        assert!(fixture.vault().sends.is_empty());
    }

    /// A competing activation lands while the worker's is pending: the
    /// obsolete transaction is replaced on its nonce by the fresh batch
    /// (outbidding it), so it never mines to revert.
    #[tokio::test]
    async fn a_competing_activation_makes_the_pending_one_obsolete_and_it_is_replaced() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(2);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        fixture.vault().activate_on_chain(1);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1), (1, 1)]);
        assert_eq!(fixture.nonces(), [0, 0]);
        let sends = fixture.vault().sends.clone();
        let fee = |tx: &Value, name: &str| {
            u128::from_str_radix(&tx[name].as_str().unwrap()[2..], 16).unwrap()
        };
        for name in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(fee(&sends[1], name) >= crate::tx_lane::min_bump(fee(&sends[0], name)));
        }
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 2);
        assert_eq!(status.totals.batches_activated_total, 1);
        assert_eq!(status.totals.reverted_total, 0);
        assert_eq!(status.last_batch.unwrap().first_note_id, 1);
    }

    /// When nothing is left to activate, an obsolete pending activation is
    /// left to mine: it reverts StaleActivation() (cheaply, before any
    /// verification) and is counted as reverted, nothing more.
    #[tokio::test]
    async fn an_obsolete_activation_with_nothing_left_reverts_and_is_counted() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        fixture.vault().activate_on_chain(1);
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Submitted);
        assert!(status.detail.unwrap().contains("obsolete"));
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Idle);
        assert_eq!(status.totals.reverted_total, 1);
        assert_eq!(status.totals.batches_activated_total, 0);
        assert_eq!(status.last_batch.unwrap().outcome, BatchOutcome::Reverted);
    }

    /// A leaf retirement (the challenger's retireClosedLeaf) lands before
    /// the worker's activation: the root moved, so the pending activation is
    /// rebuilt against the new root and replaces the obsolete one.
    #[tokio::test]
    async fn a_retirement_landing_first_moves_the_root_and_the_batch_is_rebuilt() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(2);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1), (1, 1)]);
        let stale_root = fixture.vault().tree.root();
        fixture.vault().retire(0);
        assert_ne!(fixture.vault().tree.root(), stale_root);
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1), (1, 1), (1, 1)]);
        assert_eq!(fixture.nonces(), [0, 1, 1]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 2);
        // The retired leaf stays retired; the activated one is the note's.
        let vault = fixture.vault();
        assert!(vault.tree.get_leaf(0).is_zero());
        assert_eq!(vault.tree.get_leaf(1), vault.leaf(1));
        drop(vault);
        assert_eq!(service.status().totals.batches_activated_total, 2);
    }

    /// A restart with a pending call resumes it: the same nonce is followed
    /// to confirmation, no new batch is proved or sent meanwhile.
    #[tokio::test]
    async fn a_restart_resumes_the_pending_call_on_its_nonce() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().totals.proofs_total, 1);
        drop(service);
        let mut restarted = fixture.service();
        assert_eq!(restarted.status().pending_call.unwrap().nonce, 0);
        restarted.poll_once().await.unwrap();
        assert_eq!(restarted.status().state, WorkerState::Submitted);
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        assert_eq!(restarted.status().totals.proofs_total, 1);
        fixture.mine_and_confirm(&mut restarted).await;
        restarted.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(restarted.status().totals.batches_activated_total, 1);
        assert_eq!(fixture.vault().sends.len(), 1);
    }

    /// A dropped transaction (gone from every pool, its nonce unconsumed) is
    /// re-sent on its nonce with the persisted call, without proving again.
    #[tokio::test]
    async fn a_dropped_transaction_is_resent_on_its_nonce_without_proving_again() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        fixture.vault().pool.clear();
        service.poll_once().await.unwrap();
        let sends = fixture.vault().sends.clone();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["data"], sends[1]["data"]);
        assert_eq!(fixture.nonces(), [0, 0]);
        let status = service.status();
        assert_eq!(status.totals.proofs_total, 1);
        assert_eq!(status.pending_call.unwrap().attempts, 2);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(service.status().totals.batches_activated_total, 1);
    }

    /// A reorganization undoes the worker's activation before it is
    /// confirmed: the nonce stays held, a transaction the node returns to
    /// its pool is waited on, and a dropped one is re-sent on its nonce with
    /// the persisted call, without proving again. The batch counts once.
    #[tokio::test]
    async fn a_shallow_reorg_of_the_mined_activation_is_followed_on_its_nonce() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let before = fixture.vault().snapshot();
        fixture.vault().mine();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Confirming);
        fixture.vault().reorg_to(before.clone(), true);
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Submitted);
        assert_eq!(status.pending_call.unwrap().nonce, 0);
        assert_eq!(status.totals.batches_activated_total, 0);
        assert_eq!(fixture.vault().sends.len(), 1);
        fixture.vault().mine();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Confirming);
        fixture.vault().reorg_to(before, false);
        service.poll_once().await.unwrap();
        let sends = fixture.vault().sends.clone();
        assert_eq!(sends.len(), 2);
        assert_eq!(sends[0]["data"], sends[1]["data"]);
        assert_eq!(fixture.nonces(), [0, 0]);
        assert_eq!(service.status().totals.proofs_total, 1);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(status.state, WorkerState::Idle);
        assert_eq!(status.totals.batches_activated_total, 1);
        assert_eq!(status.totals.reverted_total, 0);
    }

    /// A reorganization drops the worker's activation and the last deposit
    /// of its batch: cursor and root are unchanged, but the persisted batch
    /// of 4 would revert InvalidActivation() for ever. It is rebuilt on its
    /// nonce from the notes still recorded.
    #[tokio::test]
    async fn a_reorg_dropping_a_batch_deposit_rebuilds_the_batch_on_its_nonce() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(3);
        let before = fixture.vault().snapshot();
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 4)]);
        fixture.vault().mine();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Confirming);
        fixture.vault().reorg_to(before, false);
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.sent_batches(), [(0, 4), (0, 1)]);
        assert_eq!(fixture.nonces(), [0, 0]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(status.totals.batches_activated_total, 1);
        assert_eq!(status.totals.reverted_total, 0);
        // The next batch goes on the next nonce.
        assert_eq!(fixture.sent_batches().last(), Some(&(1, 1)));
        assert_eq!(fixture.nonces().last(), Some(&1));
    }

    /// While the worker's activation is pending, a reorganization records
    /// another note at its batch's ID: cursor, root and nextNoteId are
    /// unchanged, but the pending proof is of the replaced note (it would
    /// revert InvalidProof()). It is replaced on its nonce by a fresh batch.
    #[tokio::test]
    async fn a_pending_call_proved_for_a_reorged_note_is_replaced() {
        let fixture = Fixture::new(0).await;
        let before = fixture.vault().snapshot();
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        {
            let mut vault = fixture.vault();
            vault.reorg_to(before, false);
            vault.fork = 1;
            vault.deposit(1);
        }
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1), (0, 1)]);
        assert_eq!(fixture.nonces(), [0, 0]);
        assert_eq!(service.status().totals.proofs_total, 2);
        let sends = fixture.vault().sends.clone();
        let fee = |tx: &Value, name: &str| {
            u128::from_str_radix(&tx[name].as_str().unwrap()[2..], 16).unwrap()
        };
        for name in ["maxFeePerGas", "maxPriorityFeePerGas"] {
            assert!(fee(&sends[1], name) >= crate::tx_lane::min_bump(fee(&sends[0], name)));
        }
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(status.totals.batches_activated_total, 1);
        assert_eq!(status.totals.reverted_total, 0);
        let vault = fixture.vault();
        assert_eq!(vault.tree.get_leaf(0), vault.leaf(0));
    }

    /// A persisted call whose simulation reverts as overtaken or with a
    /// refused proof (here: a checkpoint without the notes digest, after a
    /// reorganization replaced its note) is marked obsolete and replaced on
    /// its nonce, never re-sent; it is not reported as `proof_rejected`.
    #[tokio::test]
    async fn a_persisted_call_failing_simulation_is_replaced_not_resent() {
        let fixture = Fixture::new(0).await;
        let before = fixture.vault().snapshot();
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let pending = service.checkpoint.pending.as_mut().unwrap();
        pending.call.notes_digest = None;
        {
            let mut vault = fixture.vault();
            vault.reorg_to(before, false);
            vault.pool.clear();
            vault.fork = 1;
            vault.deposit(1);
        }
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Rebuilding);
        assert_eq!(status.totals.stale_rebuilds_total, 1);
        assert!(service.checkpoint.pending.as_ref().unwrap().obsolete);
        assert_eq!(fixture.vault().sends.len(), 1);
        drop(service);
        // The mark is durable: a restart replaces the call too.
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(fixture.nonces(), [0, 0]);
        assert_eq!(service.status().totals.proofs_total, 2);
        assert!(!service.checkpoint.pending.as_ref().unwrap().obsolete);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(service.status().totals.batches_activated_total, 1);
    }

    /// A reorganization deeper than the confirmations undoes an activation
    /// already counted: the worker reads the rolled-back cursor and root and
    /// activates the note again on the freed nonce.
    #[tokio::test]
    async fn a_reorg_past_the_confirmations_is_activated_again_from_the_chain() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let before = fixture.vault().snapshot();
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Idle);
        assert!(service.checkpoint.pending.is_none());
        fixture.vault().reorg_to(before, false);
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.sent_batches(), [(0, 1), (0, 1)]);
        assert_eq!(fixture.nonces(), [0, 0]);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(status.state, WorkerState::Idle);
        assert_eq!(status.totals.batches_activated_total, 2);
    }

    /// The worker restarts after a reorganization that undid its mined
    /// activation and replaced the batch's note: the persisted proof is
    /// re-checked against the vault, discarded, and a fresh batch is sent
    /// on the persisted nonce.
    #[tokio::test]
    async fn a_restart_after_a_reorg_resumes_from_the_chain() {
        let fixture = Fixture::new(0).await;
        let before = fixture.vault().snapshot();
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        fixture.vault().mine();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Confirming);
        drop(service);
        {
            let mut vault = fixture.vault();
            vault.reorg_to(before, false);
            vault.fork = 1;
            vault.deposit(1);
        }
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.nonces(), [0, 0]);
        let sends = fixture.vault().sends.clone();
        assert_ne!(sends[0]["data"], sends[1]["data"]);
        assert_eq!(service.status().totals.proofs_total, 2);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(status.totals.batches_activated_total, 1);
        assert_eq!(status.totals.reverted_total, 0);
    }

    /// An ambiguous send without a hash that never reached a pool, at fees
    /// leaving only the reserve: once nothing appeared on the nonce within
    /// `bump_after_blocks`, it is re-sent at its fees on its nonce instead
    /// of holding the nonce for ever.
    #[tokio::test]
    async fn an_ambiguous_send_that_never_left_is_resent_after_the_bump_interval() {
        let fixture = Fixture::new(0).await;
        {
            let mut vault = fixture.vault();
            // The first bid is already at the non-critical limit.
            vault.base_fee = 45 * GWEI;
            vault.ambiguous_sends = 1;
            vault.deposit(1);
        }
        let mut service = fixture.service();
        assert!(service.poll_once().await.is_err());
        assert_eq!(
            service.status().blocked_reason,
            Some(ActivationBlocked::SendAmbiguous)
        );
        let pending = service.checkpoint.pending.clone().unwrap();
        assert!(pending.unknown_attempt && pending.transaction_hash.is_none());
        let fees = pending.fees().unwrap();
        assert_eq!(
            service.bump_viability(fees, &pending, Some(45 * GWEI)),
            Ok(false)
        );
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.vault().sends.len(), 1);
        let bump_after = service.config.fee.bump_after_blocks;
        fixture.vault().advance(bump_after);
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Submitted);
        assert_eq!(fixture.nonces(), [0, 0]);
        assert_eq!(fixture.vault().pool.len(), 1);
        let resent = service.checkpoint.pending.clone().unwrap();
        assert!(!resent.unknown_attempt && resent.transaction_hash.is_some());
        assert_eq!(resent.fees(), Some(fees));
        assert_eq!(service.status().totals.proofs_total, 1);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(service.status().totals.batches_activated_total, 1);
    }

    /// A pending activation not included at fees leaving only the reserve is
    /// kept; once the oldest pending note passes the critical alarm
    /// threshold the reserve is spent: 10/11 of the caps, then the caps.
    #[tokio::test]
    async fn the_replacement_reserve_is_spent_once_the_oldest_note_is_critical() {
        let fixture = Fixture::new(0).await;
        fixture.vault().base_fee = 45 * GWEI;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        let bump_after = service.config.fee.bump_after_blocks;
        fixture.vault().advance(bump_after);
        service.poll_once().await.unwrap();
        assert!(service.status().detail.unwrap().contains("reserved"));
        assert_eq!(fixture.vault().sends.len(), 1);
        let waited = service.config.alarms.pending_critical_seconds + 1;
        service.checkpoint.observed = Observations(vec![(1, unix_now() - waited)]);
        service.poll_once().await.unwrap();
        fixture.vault().advance(bump_after);
        service.poll_once().await.unwrap();
        let fee = |tx: &Value, name: &str| {
            u128::from_str_radix(&tx[name].as_str().unwrap()[2..], 16).unwrap()
        };
        let fees = |tx: &Value| (fee(tx, "maxFeePerGas"), fee(tx, "maxPriorityFeePerGas"));
        let sends = fixture.vault().sends.clone();
        let caps = (100 * GWEI, 10 * GWEI);
        let reserve = (headroom(caps.0), headroom(caps.1));
        assert_eq!(
            sends.iter().skip(1).map(fees).collect::<Vec<_>>(),
            [reserve, caps]
        );
        assert_eq!(fixture.nonces(), [0, 0, 0]);
        // At the caps no replacement is left.
        fixture.vault().advance(bump_after);
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Blocked);
        assert_eq!(fixture.vault().sends.len(), 3);
        fixture.mine_and_confirm(&mut service).await;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.vault().cursor, 1);
        assert_eq!(service.status().totals.batches_activated_total, 1);
    }

    /// The indexer's siblings must hash the empty subtree to the vault's
    /// root: a lagging indexer blocks the batch before any proving.
    #[tokio::test]
    async fn a_lagging_indexer_path_is_refused_before_proving() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(2);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        fixture.mine_and_confirm(&mut service).await;
        // The indexer still serves the tree before note 0's activation.
        fixture.vault().indexer_tree = Some(MerkleTree::new());
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::Blocked);
        assert_eq!(
            status.blocked_reason,
            Some(ActivationBlocked::IndexerPathBehind)
        );
        assert_eq!(status.totals.proofs_total, 1);
        assert_eq!(fixture.sent_batches(), [(0, 1)]);
        fixture.vault().indexer_tree = None;
        service.poll_once().await.unwrap();
        assert_eq!(fixture.sent_batches(), [(0, 1), (1, 1)]);
    }

    /// --dry-run proves and simulates the batch, never sends it, and does
    /// not prove it again while it stays valid; a paused vault is waited on.
    #[tokio::test]
    async fn dry_run_simulates_without_sending_and_a_paused_vault_waits() {
        let mut fixture = Fixture::new(0).await;
        fixture.config.dry_run = true;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        service.poll_once().await.unwrap();
        let status = service.status();
        assert_eq!(status.state, WorkerState::DryRun);
        assert_eq!(status.totals.proofs_total, 1);
        assert!(status
            .config_warnings
            .iter()
            .any(|w| w.contains("--dry-run")));
        assert!(fixture.vault().sends.is_empty());
        assert!(service.checkpoint.pending.is_none());
        fixture.vault().paused = true;
        service.poll_once().await.unwrap();
        assert_eq!(service.status().state, WorkerState::Paused);
    }

    /// Startup: the deployment probes, then each insertion proving key's
    /// verifying key against the adapter's INSERTION{K}_VK_HASH.
    #[tokio::test]
    async fn startup_pins_the_insertion_keys_to_the_adapter() {
        use crate::deployment::*;
        let fixture = Fixture::new(0).await;
        let mut service = fixture.service();
        let identity = crate::deployment::tests::dev_identity();
        let keys = crate::native_billing::VaultSigningKeys {
            state: zkapi_types::wire::CurvePointWire {
                x: Felt252::from_u64(1),
                y: Felt252::from_u64(2),
            },
            clearance: zkapi_types::wire::CurvePointWire {
                x: Felt252::from_u64(3),
                y: Felt252::from_u64(4),
            },
        };
        let manifest = DeploymentManifest::parse(
            &crate::deployment::tests::manifest_json(&format!("0x{VAULT:040x}"), &keys, &identity)
                .to_string(),
        )
        .unwrap();
        let padded = |hex: &str| format!("0x{:0>64}", hex.trim_start_matches("0x"));
        {
            let mut vault = fixture.vault();
            for (selector, value) in [
                (CONCESSION_ESCAPE_VERSION_SELECTOR, word_hex(1)),
                (NOTE_BOUND_EXIT_VERSION_SELECTOR, word_hex(1)),
                (
                    PROOF_ADAPTER_SELECTOR,
                    padded(&manifest.proof_adapter_address),
                ),
                (
                    CIRCUIT_ID_HASH_SELECTOR,
                    hex32(&zkapi_proof::compact::CIRCUIT_ID_HASH),
                ),
                (
                    REQUEST_VK_HASH_SELECTOR,
                    identity.request_vk_keccak256.clone(),
                ),
                (
                    WITHDRAWAL_VK_HASH_SELECTOR,
                    identity.withdrawal_vk_keccak256.clone(),
                ),
            ] {
                vault.probe_words.insert(selector.into(), value);
            }
            for prover in &service.provers {
                vault.probe_words.insert(
                    insertion_vk_hash_selector(prover.size()).unwrap().into(),
                    hex32(&prover.verifying_key_keccak256()),
                );
            }
            for (address, code) in [
                (&manifest.contract_address, "vault code"),
                (&manifest.proof_adapter_address, "adapter code"),
                (&manifest.poseidon_library_address, "poseidon code"),
            ] {
                vault
                    .code
                    .insert(address.clone(), format!("0x{}", hex::encode(code)));
            }
        }
        service.verify_deployment(&manifest).await.unwrap();
        // The adapter pins another 4-note verifying key.
        fixture
            .vault()
            .probe_words
            .insert(INSERTION4_VK_HASH_SELECTOR.into(), hex32(&[7; 32]));
        let error = service.verify_deployment(&manifest).await.unwrap_err();
        assert!(
            matches!(&error, DeploymentCheckError::Mismatch(message) if message.contains("INSERTION4_VK_HASH")),
            "{error}"
        );
        assert!(service
            .status()
            .config_warnings
            .iter()
            .any(|warning| warning.starts_with("deployment not verified")));
        // A vault without note-bound exits is refused.
        fixture
            .vault()
            .probe_words
            .insert(NOTE_BOUND_EXIT_VERSION_SELECTOR.into(), word_hex(0));
        let error = service.verify_deployment(&manifest).await.unwrap_err();
        assert!(
            matches!(&error, DeploymentCheckError::Mismatch(message) if message.contains("NOTE_BOUND_EXIT_VERSION")),
            "{error}"
        );
    }

    /// A checkpoint of another sender or vault is refused.
    #[tokio::test]
    async fn a_checkpoint_of_another_deployment_is_refused() {
        let fixture = Fixture::new(0).await;
        fixture.vault().deposit(1);
        let mut service = fixture.service();
        service.poll_once().await.unwrap();
        drop(service);
        let mut other = fixture.config.clone();
        other.sender = "0x00000000000000000000000000000000000000a2".into();
        let error = ActivationService::new(other).err().unwrap();
        assert!(error.to_string().contains("another sender"), "{error}");
        let mut vault = fixture.config.clone();
        vault.contract_address = Felt252::from_u64(0xbeef);
        assert!(ActivationService::new(vault).is_err());
    }
}
