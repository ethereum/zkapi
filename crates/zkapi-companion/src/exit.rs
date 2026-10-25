//! The companion's exits (design §6.4 E0–E6 and §6.7): the escape routes
//! `/oa/v1/withdraw/escape/{prepare,submit,status,finalize}` and the exit
//! decision the mutual close shares.
//!
//! Every decision runs under the process-wide `WalletLock` (C1): the exit
//! lock is set, the request journal and archive are read and the server is
//! asked, with no request preparation in between. Operator calls are bounded
//! (E0: 20 s each, 120 s per recovery pass, none after `must_initiate_by`);
//! the escape needs no operator at all, and since vault revision 4 no Merkle
//! path, root, indexer or log scan either: the proof carries the note's leaf
//! and fields, and the vault compares them with the leaf it stored at
//! deposit.

use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkapi_client::exit_lock::ExitMode;
use zkapi_client::exit_policy::{
    self, EarlyExit, ExitDecision, ExitFacts, MutualOutcome, NoteChainStatus, PayoutMatch, Reading,
    ServerReading,
};
use zkapi_client::wallet::Wallet;
use zkapi_proof::compact::RequestVerifier;
use zkapi_types::wire::{Groth16ProofWire, RecoveryResponseV2};
use zkapi_types::{Felt252, RequestPublicInputsV2, WithdrawalPublicInputsV2C};

use super::{
    acquire_wallet_lock, current_thread_runtime, load_wallet, now_seconds, spawn_blocking,
    AuthService,
};
use crate::chain::{self, Rpc};
use crate::config::AuthConfig;
use crate::error::AuthError;

pub(crate) const ESCAPE_RECORD_FILE: &str = "escape_withdrawal.json";

/// E0's `CALL_TIMEOUT` and `RECOVERY_BUDGET` (shortened in tests).
#[cfg(not(test))]
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_secs(exit_policy::CALL_TIMEOUT_SECONDS);
#[cfg(test)]
pub(crate) const CALL_TIMEOUT: Duration = Duration::from_millis(1_500);
#[cfg(not(test))]
pub(crate) const RECOVERY_BUDGET: Duration =
    Duration::from_secs(exit_policy::RECOVERY_BUDGET_SECONDS);
#[cfg(test)]
pub(crate) const RECOVERY_BUDGET: Duration = Duration::from_secs(3);

/// A prepared plan (an escape, or a mutual close) is handed out again only
/// while it stays valid this long; a plan closer to its `valid_until` is
/// proved again.
pub(crate) const PLAN_REUSE_MARGIN_SECONDS: u64 = 1_800;
/// How often a recovery install may restart the decision at a new state.
const MAX_STATE_RESTARTS: usize = 3;

/// The withdrawal record of an escape (§6.2 "withdrawal record"):
/// `{noteId, stateBalance B, concededAtInit c, boundAtState b, destination,
/// validUntil, startBlock}`, the plan, and its progress.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EscapeRecord {
    pub version: u8,
    pub note_id: u32,
    pub withdrawal_nullifier: Felt252,
    pub next_nullifier: Felt252,
    /// B, decimal.
    pub state_balance: String,
    /// c at initiation, decimal.
    pub conceded_at_init: String,
    /// b, decimal.
    pub bound_at_state: String,
    pub destination: String,
    pub valid_until: u64,
    /// A block at or before the proof was made: raises are scanned from it.
    pub start_block: u64,
    /// Why the escape concedes `conceded_at_init`.
    pub reason: String,
    pub public_inputs: WithdrawalPublicInputsV2C,
    pub proof: Groth16ProofWire,
    /// `prepared`, `submitted`, `complete`, `defeated` or `expired`.
    pub phase: String,
    #[serde(default)]
    pub initiate_transactions: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalize_transaction: Option<String>,
    /// The payout the vault made (or credited), decimal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payout: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conceded_final: Option<String>,
    #[serde(default)]
    pub payout_credited: bool,
    /// E5's alert: the payout is below `B − bound_at_state`.
    #[serde(default)]
    pub concession_exceeded_bound: bool,
}

impl EscapeRecord {
    fn amount(value: &str) -> u128 {
        value.parse().unwrap_or_default()
    }
    pub fn state_balance(&self) -> u128 {
        Self::amount(&self.state_balance)
    }
    pub fn conceded_at_init(&self) -> u128 {
        Self::amount(&self.conceded_at_init)
    }
    pub fn bound(&self) -> u128 {
        Self::amount(&self.bound_at_state)
    }
}

pub(crate) fn load_record(config: &AuthConfig) -> Result<Option<EscapeRecord>, AuthError> {
    let path = config.state_dir.join(ESCAPE_RECORD_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| AuthError::Wallet("the escape record is unreadable; preserve it".into())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(AuthError::Wallet("the escape record is unreadable".into())),
    }
}

pub(crate) fn save_record(config: &AuthConfig, record: &EscapeRecord) -> Result<(), AuthError> {
    let bytes = serde_json::to_vec_pretty(record)
        .map_err(|error| AuthError::Serialization(error.to_string()))?;
    crate::oa_withdrawal::write_private_durably(&config.state_dir.join(ESCAPE_RECORD_FILE), &bytes)
}

/// The owner's request to `/oa/v1/withdraw/escape/prepare`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EscapePrepareRequest {
    pub destination: String,
    /// The concession the owner confirmed, decimal. Without it the route
    /// only reports the decision; nothing is proved or released.
    #[serde(default)]
    pub conceded: Option<String>,
    /// Exit before `T` (E3 "forced early exit").
    #[serde(default)]
    pub early_exit: Option<EarlyExit>,
}

/// What one decision found.
#[derive(Debug, Clone)]
pub(crate) struct Decided {
    pub decision: ExitDecision,
    pub facts: ExitFacts,
    pub state_balance: u128,
    pub note_id: u32,
    /// The response E1 installed, if it installed one.
    pub installed: Option<zkapi_types::wire::RequestResponseV2>,
}

impl Decided {
    pub fn to_json(&self) -> Value {
        let mut value = json!({
            "note_id": self.note_id,
            "state_balance": self.state_balance.to_string(),
            "bound_at_state": self.facts.bound_at_state.to_string(),
            "must_initiate_by": self.facts.must_initiate_by,
            "now": self.facts.now,
        });
        match self.decision {
            ExitDecision::Mutual => value["action"] = json!("mutual"),
            ExitDecision::Wait { until } => {
                value["action"] = json!("wait");
                value["wait_until"] = json!(until);
            }
            ExitDecision::Escape { conceded, reason } => {
                value["action"] = json!("escape");
                value["conceded"] = json!(conceded.to_string());
                value["payout"] = json!(self.state_balance.saturating_sub(conceded).to_string());
                value["reason"] = serde_json::to_value(reason).unwrap_or_default();
            }
        }
        value
    }
}

/// E0: an operator call in exit mode: 20 s, and any failure (timeout, 5xx,
/// 429, an invalid answer) counts as unreachable. `Retry-After` is ignored.
async fn exit_get(config: &AuthConfig, path: String) -> Option<reqwest::Response> {
    let url = format!("{}{path}", config.protocol_server_url.trim_end_matches('/'));
    let request = zkapi_client::testnet_auth::request(
        config.chain_id,
        &config.protocol_server_url,
        reqwest::Method::GET,
        url,
    )
    .ok()?
    .timeout(CALL_TIMEOUT);
    request.send().await.ok()
}

/// The server's record of `nullifier`, or `None` when it is unreachable.
async fn read_nullifier(config: &AuthConfig, nullifier: &Felt252) -> Option<RecoveryResponseV2> {
    let response = exit_get(config, format!("/v2/nullifiers/{nullifier}")).await?;
    if !response.status().is_success() {
        return None;
    }
    tokio::time::timeout(CALL_TIMEOUT, response.json::<RecoveryResponseV2>())
        .await
        .ok()?
        .ok()
}

/// What an E1 pass did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Recovered {
    Nothing,
    /// A successor installed: the state changed.
    Installed,
    /// A valid successor arrived after an exit proof was released.
    Late,
}

/// E1: one bounded recovery pass (skipped once `must_initiate_by` passed).
pub(crate) async fn recovery_pass(wallet: &mut Wallet, must_initiate_by: u64) -> Recovered {
    recovery_pass_with_response(wallet, must_initiate_by)
        .await
        .0
}

/// `recovery_pass`, with the installed response.
pub(crate) async fn recovery_pass_with_response(
    wallet: &mut Wallet,
    must_initiate_by: u64,
) -> (Recovered, Option<zkapi_types::wire::RequestResponseV2>) {
    if now_seconds() >= must_initiate_by {
        return (Recovered::Nothing, None);
    }
    wallet.set_call_timeout(Some(CALL_TIMEOUT));
    let result = tokio::time::timeout(RECOVERY_BUDGET, wallet.recover()).await;
    wallet.set_call_timeout(None);
    match result {
        Ok(Ok(Some(response))) => (Recovered::Installed, Some(response)),
        Ok(Err(zkapi_client::error::ClientError::LateSuccessor)) => (Recovered::Late, None),
        Ok(Err(error)) => {
            tracing::debug!(%error, "exit recovery pass found nothing installable");
            (Recovered::Nothing, None)
        }
        Ok(Ok(None)) | Err(_) => (Recovered::Nothing, None),
    }
}

/// E0's `E_low`, reading `effectiveExpiry(noteId, commitment, amount,
/// expiryTs)` through the pinned RPC and the user's exit RPC when one is
/// configured; any failure, or a 0 for a preimage that does not reproduce the
/// stored leaf, leaves `expiry_ts`.
async fn e_low(
    config: &AuthConfig,
    note_id: u32,
    commitment: Felt252,
    amount: u128,
    expiry_ts: u64,
) -> u64 {
    let Some(exit_url) = config.exit_rpc_url.as_deref() else {
        return expiry_ts;
    };
    let Ok(vault) = chain::vault_address(&config.contract_address) else {
        return expiry_ts;
    };
    let read = |url: Option<&str>| {
        let url = url.map(str::to_string);
        async move {
            let rpc = Rpc::new(url.as_deref()?).ok()?.on_chain(config.chain_id);
            chain::effective_expiry(&rpc, &vault, note_id, &commitment, amount, expiry_ts)
                .await
                .ok()
        }
    };
    let (pinned, exit) = tokio::join!(read(config.demo_rpc_url.as_deref()), read(Some(exit_url)));
    exit_policy::e_low(expiry_ts, pinned, exit)
}

/// The RPC an escape reads the chain through: the owner's exit RPC when one
/// is configured, otherwise the pinned RPC (§1.2(6), §6.7). The pinned RPC is
/// operator-influenced (§2.1), so when the owner named an RPC of their own it
/// is never asked in its place, even when that one fails: what it answered
/// would decide what is proved and signed (the start block) or the
/// escape's state (pending, closed, defeated), and the lock's release (E5,
/// E6). A failing exit RPC is reported; the owner retries or names another.
/// Every reading must come from the deployment's chain: an RPC on another
/// chain fails each call (WP-D's eth_chainId check, as in the SDK).
pub(crate) fn deciding_rpc(config: &AuthConfig) -> Result<Rpc, AuthError> {
    let url = config
        .exit_rpc_url
        .as_deref()
        .or(config.demo_rpc_url.as_deref())
        .ok_or_else(|| {
            AuthError::InvalidInput("the deployment names no RPC to confirm the exit".into())
        })?;
    Ok(Rpc::new(url)?.on_chain(config.chain_id))
}

/// A lock this exit call holds at the end with nothing released under it
/// (a decision only, an E3 wait, a refusal or a failure before any proof)
/// is removed: no proof left, so nothing on chain needs it (E6 "no kind-0 or
/// kind-1 proof was released"), and the decision that needed it for C1 is
/// over. Requests resume, as the SDK does. A lock that released any proof,
/// an ownership proof included, stays.
pub(crate) fn drop_unused_lock(wallet: &mut Wallet) -> Result<(), AuthError> {
    if wallet
        .exit_lock()?
        .is_some_and(|lock| lock.released.is_empty())
    {
        wallet.cancel_exit_lock()?;
    }
    Ok(())
}

/// E1 then E2/E3 for the wallet's current state. Sets nothing; the caller
/// holds the exit lock.
pub(crate) async fn decide(
    config: &AuthConfig,
    wallet: &mut Wallet,
    mutual_outcome: Option<MutualOutcome>,
    early_exit: Option<EarlyExit>,
    recover: bool,
) -> Result<Decided, AuthError> {
    let state = wallet.state().ok_or(AuthError::NoActiveNote)?.clone();
    let must_initiate_by = exit_policy::must_initiate_by(
        e_low(
            config,
            state.note_id,
            zkapi_core::v2::registration_commitment(&state.secret_s),
            state.deposit_amount,
            state.expiry_ts,
        )
        .await,
    );
    let installed = if recover {
        recovery_pass_with_response(wallet, must_initiate_by)
            .await
            .1
    } else {
        None
    };
    let state = wallet.state().ok_or(AuthError::NoActiveNote)?.clone();
    let nullifier = wallet.current_nullifier().ok_or(AuthError::NoActiveNote)?;
    let now = now_seconds();
    // One reading of the state's nullifier, unless the decision is already
    // forced: past must_initiate_by no operator call is made.
    let recovery = if now < must_initiate_by {
        read_nullifier(config, &nullifier).await
    } else {
        None
    };
    let reading = Reading {
        status: recovery
            .as_ref()
            .map_or(ServerReading::Unavailable, |recovery| {
                ServerReading::from_nullifier_status(&recovery.nullifier_status)
            }),
        observed_at: now,
    };
    let records = wallet.released_records(Some(reading))?;
    // E3 "lost ε": the server finalized this state for a request this wallet
    // cannot install (no journal or archive record of it).
    let lost_epsilon_charge = recovery
        .as_ref()
        .and_then(|recovery| recovery.request_response.as_ref())
        .filter(|response| {
            !wallet_holds_request(wallet, &response.client_request_id).unwrap_or(true)
        })
        .and_then(|response| wallet.uninstallable_finalized_charge(response));
    let facts = ExitFacts {
        now,
        must_initiate_by,
        settlement_window: config.settlement_window_seconds,
        unsettled_escape_after: exit_policy::unsettled_escape_after(
            config.unsettled_request_escape_after_seconds,
        ),
        bound_at_state: state.bound_at_state,
        records,
        settlement_deadline_reported: recovery.as_ref().and_then(|r| r.settlement_deadline),
        lost_epsilon_charge,
        mutual_outcome,
        early_exit,
    };
    Ok(Decided {
        decision: exit_policy::decide(&facts),
        facts,
        state_balance: state.current_balance,
        note_id: state.note_id,
        installed,
    })
}

/// Whether the journal or the archive at the current state holds the request
/// `client_request_id`.
fn wallet_holds_request(wallet: &Wallet, client_request_id: &str) -> Result<bool, AuthError> {
    if wallet
        .get_pending_journal()?
        .is_some_and(|journal| journal.client_request_id == client_request_id)
    {
        return Ok(true);
    }
    let listing = wallet.archive_at_current_state()?;
    if !listing.unreadable.is_empty() {
        return Ok(true);
    }
    Ok(listing
        .records
        .iter()
        .any(|record| record.journal.client_request_id == client_request_id))
}

/// E4 step 2: the stale-device pre-check. A request proof at `N⁺` that
/// verifies under the pinned request key means another device spent this
/// state; anything else (errors, refusals, unverifiable answers) is ignored.
pub(crate) async fn stale_device_check(
    config: &AuthConfig,
    successor_nullifier: &Felt252,
) -> Result<(), AuthError> {
    #[derive(Deserialize)]
    struct Evidence {
        public_inputs: RequestPublicInputsV2,
        proof: Groth16ProofWire,
    }
    let Some(response) = exit_get(
        config,
        format!("/v2/nullifiers/{successor_nullifier}/evidence"),
    )
    .await
    else {
        return Ok(());
    };
    if !response.status().is_success() {
        return Ok(());
    }
    let Ok(Ok(evidence)) = tokio::time::timeout(CALL_TIMEOUT, response.json::<Evidence>()).await
    else {
        return Ok(());
    };
    if evidence.public_inputs.request_nullifier != *successor_nullifier {
        return Ok(());
    }
    let setup_dir = config.proof_setup_dir.clone();
    let verified = tokio::task::spawn_blocking(move || {
        RequestVerifier::load(&setup_dir)
            .and_then(|verifier| verifier.verify(&evidence.public_inputs, &evidence.proof))
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false);
    if verified {
        return Err(AuthError::DeviceNotNewest);
    }
    Ok(())
}

/// E4 step 5: advisory reads. They never block the escape.
async fn advisory_warnings(
    config: &AuthConfig,
    nullifier: &Felt252,
    successor: &Felt252,
) -> Vec<String> {
    let mut warnings = Vec::new();
    let Ok(vault) = chain::vault_address(&config.contract_address) else {
        return warnings;
    };
    for url in [
        config.demo_rpc_url.as_deref(),
        config.exit_rpc_url.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let Ok(rpc) = Rpc::new(url).map(|rpc| rpc.on_chain(config.chain_id)) else {
            continue;
        };
        for (label, value) in [("nullifier", nullifier), ("successor nullifier", successor)] {
            match chain::challenged(&rpc, &vault, value, "latest").await {
                Ok(true) => warnings.push(format!(
                    "{} reports this state's {label} as challenged; the escape may revert",
                    rpc.url()
                )),
                Ok(false) => {}
                Err(error) => warnings.push(format!("advisory read failed: {error}")),
            }
        }
    }
    warnings
}

/// The concessions the decision allows for an escape the owner asks for.
fn allowed_concession(decided: &Decided) -> Option<(u128, &'static str)> {
    match decided.decision {
        // The owner chose an escape over a mutual close at a fresh state.
        ExitDecision::Mutual => Some((0, "requested")),
        ExitDecision::Escape { conceded, reason } => Some((
            conceded,
            match reason {
                exit_policy::EscapeReason::MutualCutoff => "mutual_cutoff",
                exit_policy::EscapeReason::MutualRefused => "mutual_refused",
                exit_policy::EscapeReason::LostEpsilon => "lost_epsilon",
                exit_policy::EscapeReason::AtDeadline => "at_deadline",
                exit_policy::EscapeReason::ForcedEarly => "forced_early",
            },
        )),
        ExitDecision::Wait { .. } => None,
    }
}

fn plan_json(record: &EscapeRecord, config: &AuthConfig, warnings: &[String]) -> Value {
    let calldata =
        chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &record.public_inputs, &record.proof)
            .unwrap_or_default();
    json!({
        "status": "prepared",
        "mode": "escape",
        "note_id": record.note_id,
        "destination": record.destination,
        "state_balance": record.state_balance,
        "conceded": record.conceded_at_init,
        "bound_at_state": record.bound_at_state,
        "payout": record.public_inputs.final_balance.to_string(),
        "valid_until": record.valid_until,
        "reason": record.reason,
        "withdrawal_nullifier": record.withdrawal_nullifier,
        "next_nullifier": record.next_nullifier,
        "public_inputs": record.public_inputs,
        "proof": record.proof,
        "vault": format!("0x{}", hex::encode(chain::vault_address(&config.contract_address).unwrap_or([0; 20]))),
        "calldata": calldata,
        "phase": record.phase,
        "warnings": warnings,
    })
}

fn parse_conceded(value: &str) -> Result<u128, AuthError> {
    value
        .parse::<u128>()
        .map_err(|_| AuthError::InvalidInput("conceded must be a decimal amount".into()))
}

impl AuthService {
    /// `POST /oa/v1/withdraw/escape/prepare`.
    pub async fn oa_escape_prepare(
        &self,
        request: EscapePrepareRequest,
    ) -> Result<Value, AuthError> {
        let destination = crate::oa_withdrawal::destination(&request.destination)?;
        crate::oa_withdrawal::check_destination(&self.config, &destination)?;
        let confirmed = request
            .conceded
            .as_deref()
            .map(parse_conceded)
            .transpose()?;
        // A live key would let a chat race the decision; it is retired first,
        // within one E1 budget (E0): the retirement and recovery calls go to
        // the operator, which may stall them.
        if self.direct_lease.lock().await.is_some() {
            match tokio::time::timeout(RECOVERY_BUDGET, self.settle_for_withdrawal()).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    tracing::debug!(%error, "the live lease did not settle before the escape decision");
                }
                Err(_) => {
                    tracing::warn!(
                        "the live lease did not settle within the exit's recovery budget"
                    );
                }
            }
        }
        let mut lease = self.direct_lease.lock().await;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let early_exit = request.early_exit;
        let result = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            current_thread_runtime()?.block_on(prepare_escape_locked(
                &config,
                &mut wallet,
                destination,
                confirmed,
                early_exit,
            ))
        })
        .await;
        if result.is_ok() {
            *lease = None;
        }
        result
    }

    /// `POST /oa/v1/withdraw/escape/submit`: the transaction that carries
    /// the prepared escape.
    pub async fn oa_escape_submit(&self, transaction_hash: String) -> Result<Value, AuthError> {
        crate::oa_withdrawal::transaction_hash(&transaction_hash)?;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            let mut record = load_record(&config)?.ok_or(AuthError::WithdrawalConflict)?;
            if record.phase == "complete" {
                return Err(AuthError::WithdrawalConflict);
            }
            let hash = transaction_hash.to_ascii_lowercase();
            if !record.initiate_transactions.contains(&hash) {
                record.initiate_transactions.push(hash.clone());
            }
            if record.phase == "prepared" {
                record.phase = "submitted".into();
            }
            if let Some(lock) = wallet.exit_lock()? {
                if let Some(index) = lock
                    .released
                    .iter()
                    .rposition(|proof| proof.kind == 0 && proof.valid_until == record.valid_until)
                {
                    wallet.record_exit_transaction(index, &hash)?;
                }
            }
            save_record(&config, &record)?;
            Ok(
                json!({"status": "submitted", "phase": record.phase, "note_id": record.note_id,
                "transaction_hash": hash}),
            )
        })
        .await
    }

    /// `GET /oa/v1/withdraw/escape/status`: the escape record, the exit lock
    /// and the vault's view of the note. A dead lock (E6) is released here.
    pub async fn oa_escape_status(&self) -> Result<Value, AuthError> {
        self.escape_status_at(None).await
    }

    /// The status with this device's clock read as `clock` (tests), or the
    /// system clock.
    pub(crate) async fn escape_status_at(&self, clock: Option<u64>) -> Result<Value, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            let now = clock.unwrap_or_else(now_seconds);
            current_thread_runtime()?.block_on(escape_status_locked(&config, &mut wallet, now))
        })
        .await
    }

    /// `POST /oa/v1/withdraw/escape/cancel`: E6 "no kind-0 or kind-1 proof
    /// was released and the user cancels". Removes the exit lock, so
    /// requests resume (except from a state whose ownership proof left,
    /// C5). Refused with `exit_lock_conflict` while a released escape or
    /// close may still land: such a lock is released only once the note
    /// closes or every released proof is dead (the status route).
    pub async fn oa_escape_cancel(&self) -> Result<Value, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            let lock = wallet.exit_lock()?;
            wallet.cancel_exit_lock()?;
            Ok(json!({
                "status": "cancelled",
                "had_lock": lock.is_some(),
                "ownership_proof_sent": wallet.ownership_proof_sent_at_current_state()?,
            }))
        })
        .await
    }

    /// `POST /oa/v1/withdraw/escape/finalize`: check a finalized
    /// `finalizeEscapeWithdrawal` (anyone's) and close the note.
    pub async fn oa_escape_finalize(&self, transaction_hash: String) -> Result<Value, AuthError> {
        crate::oa_withdrawal::transaction_hash(&transaction_hash)?;
        let mut lease = self.direct_lease.lock().await;
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let result = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            current_thread_runtime()?.block_on(finalize_escape_locked(
                &config,
                &mut wallet,
                &transaction_hash.to_ascii_lowercase(),
            ))
        })
        .await;
        if result.is_ok() {
            *lease = None;
        }
        result
    }
}

async fn prepare_escape_locked(
    config: &AuthConfig,
    wallet: &mut Wallet,
    destination: [u8; 20],
    confirmed: Option<u128>,
    early_exit: Option<EarlyExit>,
) -> Result<Value, AuthError> {
    let destination_hex = format!("0x{}", hex::encode(destination));
    let state = wallet.state().ok_or(AuthError::NoActiveNote)?.clone();
    // A plan already prepared for this state is handed out again while it
    // stays valid: it was released, and another could land beside it.
    if let Some(record) = load_record(config)? {
        let same_state = Some(record.withdrawal_nullifier) == wallet.current_nullifier()
            && record.note_id == state.note_id;
        let live = record.valid_until > now_seconds() + PLAN_REUSE_MARGIN_SECONDS;
        if same_state && matches!(record.phase.as_str(), "prepared" | "submitted") && live {
            if !record.destination.eq_ignore_ascii_case(&destination_hex) {
                return Err(AuthError::WithdrawalConflict);
            }
            if confirmed.is_some_and(|conceded| conceded != record.conceded_at_init()) {
                return Err(AuthError::ConcededMismatch(json!({
                    "conceded": record.conceded_at_init,
                    "reason": record.reason,
                })));
            }
            return Ok(plan_json(&record, config, &[]));
        }
    }
    let result = decide_and_prove_escape(
        config,
        wallet,
        destination,
        destination_hex,
        confirmed,
        early_exit,
    )
    .await;
    // Only a prepared escape released a proof; anything else leaves no lock
    // behind unless an earlier proof (an ownership proof) needs it.
    if !result
        .as_ref()
        .is_ok_and(|value| value["status"] == "prepared")
    {
        drop_unused_lock(wallet)?;
    }
    result
}

async fn decide_and_prove_escape(
    config: &AuthConfig,
    wallet: &mut Wallet,
    destination: [u8; 20],
    destination_hex: String,
    confirmed: Option<u128>,
    early_exit: Option<EarlyExit>,
) -> Result<Value, AuthError> {
    // How the mutual close of this very state ended, if one was tried. A
    // reservation of an earlier state of the note says nothing about this
    // one.
    let current = wallet.current_nullifier();
    let mutual_outcome = crate::oa_withdrawal::load(config)?
        .filter(|reservation| Some(reservation.nullifier) == current)
        .and_then(|reservation| reservation.clearance_outcome);
    for _ in 0..MAX_STATE_RESTARTS {
        // E2 step 1: the lock before E1. A lock that already released an
        // escape stays in escape mode.
        let mode = match wallet.exit_lock()? {
            Some(lock) if Some(lock.anchor) == wallet.state().map(|state| state.current_anchor) => {
                lock.mode
            }
            _ => ExitMode::Mutual,
        };
        wallet.set_exit_lock(mode)?;
        let decided = decide(config, wallet, mutual_outcome, early_exit, true).await?;
        let Some((conceded, reason)) = allowed_concession(&decided) else {
            let mut value = decided.to_json();
            value["status"] = json!("wait");
            return Ok(value);
        };
        let Some(confirmed) = confirmed else {
            let mut value = decided.to_json();
            value["status"] = json!("decision");
            value["action"] = json!("escape");
            value["conceded"] = json!(conceded.to_string());
            value["payout"] = json!(decided.state_balance.saturating_sub(conceded).to_string());
            value["reason"] = json!(reason);
            return Ok(value);
        };
        if confirmed != conceded {
            let mut value = decided.to_json();
            value["conceded"] = json!(conceded.to_string());
            value["reason"] = json!(reason);
            return Err(AuthError::ConcededMismatch(value));
        }
        wallet.set_exit_lock(ExitMode::Escape)?;
        let successor = wallet
            .current_successor_nullifier()
            .ok_or(AuthError::NoActiveNote)?;
        if now_seconds() < decided.facts.must_initiate_by {
            stale_device_check(config, &successor).await?;
        }
        // E4 step 3: a successor installed now moves the exit to it.
        if recovery_pass(wallet, decided.facts.must_initiate_by).await == Recovered::Installed {
            continue;
        }
        let mut start_block = config.deploy_block;
        if let Ok(rpc) = deciding_rpc(config) {
            if let Ok((number, _)) = rpc.block("latest").await {
                start_block = number;
            }
        }
        let bound = wallet.state().map_or(0, |state| state.bound_at_state);
        let (public_inputs, proof) = wallet.withdrawal_escape_hatch(destination, conceded)?;
        let mut warnings = advisory_warnings(
            config,
            &public_inputs.withdrawal_nullifier,
            &public_inputs.next_nullifier,
        )
        .await;
        // E4 step 6: a successor arriving now is archived as late.
        if recovery_pass(wallet, decided.facts.must_initiate_by).await == Recovered::Late {
            warnings.push(
                "a successor of this state arrived after the escape proof was made; it is kept and installed only if this escape never lands".into(),
            );
        }
        let record = EscapeRecord {
            version: 1,
            note_id: public_inputs.note_id,
            withdrawal_nullifier: public_inputs.withdrawal_nullifier,
            next_nullifier: public_inputs.next_nullifier,
            state_balance: (public_inputs.final_balance + public_inputs.conceded).to_string(),
            conceded_at_init: public_inputs.conceded.to_string(),
            bound_at_state: bound.to_string(),
            destination: destination_hex.clone(),
            valid_until: public_inputs.valid_until,
            start_block,
            reason: reason.into(),
            public_inputs,
            proof,
            phase: "prepared".into(),
            initiate_transactions: Vec::new(),
            finalize_transaction: None,
            payout: None,
            conceded_final: None,
            payout_credited: false,
            concession_exceeded_bound: false,
        };
        save_record(config, &record)?;
        let mut plan = plan_json(&record, config, &warnings);
        plan["must_initiate_by"] = json!(decided.facts.must_initiate_by);
        return Ok(plan);
    }
    Err(AuthError::Wallet(
        "the note state kept changing during the escape decision; retry".into(),
    ))
}

async fn escape_status_locked(
    config: &AuthConfig,
    wallet: &mut Wallet,
    now: u64,
) -> Result<Value, AuthError> {
    let record = load_record(config)?;
    let lock = wallet.exit_lock()?;
    let mut status = json!({
        "record": record,
        "exit_lock": lock.as_ref().map(|lock| json!({
            "note_id": lock.note_id, "mode": lock.mode, "since": lock.since,
            "released": lock.released.iter().map(|proof| json!({
                "kind": proof.kind, "valid_until": proof.valid_until,
                "conceded": proof.conceded.to_string(), "txHash": proof.tx_hash,
            })).collect::<Vec<_>>(),
        })),
    });
    let Some(record) = record else {
        status["phase"] = json!("none");
        return Ok(status);
    };
    status["phase"] = json!(record.phase);
    if record.phase == "complete" {
        return Ok(status);
    }
    let vault = chain::vault_address(&config.contract_address)?;
    // What is shown comes from the escape's RPC alone (deciding_rpc): the
    // caller acts on it (finalizes after a pending deadline, records a
    // defeat), so a pinned RPC never answers for a failing exit RPC.
    let read = match deciding_rpc(config) {
        Ok(rpc) => match chain::read_note(&rpc, &vault, record.note_id, "latest").await {
            Ok(view) => Some((rpc, view)),
            Err(_) => None,
        },
        Err(_) => None,
    };
    let Some((rpc, view)) = read else {
        status["chain"] = json!("unavailable");
        status["trusted"] = json!(false);
        return Ok(status);
    };
    // Only the owner's exit RPC is a source the operator does not control
    // (§2.1). Without one, every reading here is the pinned RPC's: the caller
    // must treat it as advisory and ask again (a defeat it reports is not
    // final), and E6 never releases a live lock on it.
    let trusted = config.exit_rpc_url.as_deref() == Some(rpc.url());
    status["chain_rpc"] = json!(if trusted { "exit" } else { "pinned" });
    status["trusted"] = json!(trusted);
    match view.pending {
        Some(pending) if pending.nullifier == record.withdrawal_nullifier => {
            status["phase"] = json!("pending");
            status["payout"] = json!(pending.final_balance.to_string());
            status["conceded"] = json!(pending.conceded.to_string());
            status["challenge_deadline"] = json!(pending.deadline);
            status["finalize_calldata"] = json!(chain::finalize_calldata(record.note_id));
            status["finalizable"] = json!(now > pending.deadline);
        }
        Some(_) => status["phase"] = json!("other_exit_pending"),
        None if view.status == 3 => status["phase"] = json!("closed"),
        None if view.status == 1 => {
            // Defeated (another device spent the successor) or never landed.
            // Both are read at a finalized block, where the note must be
            // Active with no pending exit: a defeat counts only from an
            // EscapeWithdrawalChallenged of this escape's nullifier in a
            // finalized block, never from a flag at the latest block.
            // `defeat` is what those logs show, None when they were not
            // read: logs that fail to load never count as "no defeat".
            let mut defeat: Option<Option<String>> = None;
            let mut logs_failed = false;
            let mut settled_at = None;
            if let Ok((block, finalized_ts)) = rpc.block("finalized").await {
                let tag = format!("0x{block:x}");
                if chain::read_note(&rpc, &vault, record.note_id, &tag)
                    .await
                    .is_ok_and(|view| view.status == 1 && view.pending.is_none())
                {
                    settled_at = Some(finalized_ts);
                    match chain::escape_defeat(
                        &rpc,
                        &vault,
                        record.note_id,
                        &record.withdrawal_nullifier,
                        record.start_block,
                        block,
                    )
                    .await
                    {
                        Ok(found) => defeat = Some(found),
                        Err(_) => logs_failed = true,
                    }
                }
            }
            status["defeat_checked"] = json!(defeat.is_some());
            if logs_failed {
                // Whether the escape was defeated is unknown: nothing is
                // decided from this reading, so the caller must not act on it.
                status["trusted"] = json!(false);
                status["defeat_logs"] = json!("unavailable");
            }
            // E6: release the lock once every released proof is dead: at a
            // finalized block past each valid_until + 900, the note Active
            // with no pending exit, and on this device's clock too. No RPC
            // answer alone releases it: a lock released on a false answer
            // would let a late successor install while the escape can still
            // land.
            let released = match settled_at {
                Some(finalized_ts) => wallet.release_exit_lock(
                    NoteChainStatus::Active,
                    Some(finalized_ts),
                    now,
                    trusted,
                )?,
                None => false,
            };
            if released {
                status["exit_lock"] = Value::Null;
            }
            // Only the defeat logs this reading read settle the escape: with
            // no lock left, one the chain shows neither pending nor defeated
            // never landed (a saved defeat an earlier reading reported is
            // corrected). Without them (unread or failing logs), or when
            // they settle nothing, a record an earlier reading settled as
            // defeated or expired is reported as unknown and kept as it is:
            // never expired, and a saved defeat is never overwritten.
            let settled_before = matches!(record.phase.as_str(), "defeated" | "expired");
            match &defeat {
                Some(Some(hash)) => {
                    status["phase"] = json!("defeated");
                    status["error"] = json!("device_not_newest");
                    status["defeat_transaction"] = json!(hash);
                }
                Some(None) if released => status["phase"] = json!("expired"),
                _ if logs_failed || settled_before => status["phase"] = json!("unknown"),
                _ => {}
            }
            let unlocked = released || wallet.exit_lock()?.is_none();
            let phase = status["phase"].as_str().unwrap_or("").to_string();
            if unlocked && matches!(phase.as_str(), "defeated" | "expired") && phase != record.phase
            {
                let mut settled = record.clone();
                settled.phase = phase;
                save_record(config, &settled)?;
            }
        }
        None => {}
    }
    Ok(status)
}

/// E5: the payout of a finalized escape of `record` in `receipt`, matched
/// against B, the initial and every raised concession, and the bound.
pub(crate) async fn match_finalized_escape(
    config: &AuthConfig,
    record: &EscapeRecord,
    receipt: &Value,
    rpc: &Rpc,
) -> Result<(u128, PayoutMatch, bool), AuthError> {
    let vault = chain::vault_address(&config.contract_address)?;
    let vault_hex = format!("0x{}", hex::encode(vault));
    let note_topic = format!("0x{}", chain::word_u64(record.note_id.into()));
    let finalized_topic = chain::escape_finalized_topic();
    let deferred_topic = chain::escape_payout_deferred_topic();
    let destination = crate::oa_withdrawal::destination(&record.destination)?;
    let destination_topic = format!("0x{}", chain::word_address(&destination));
    let logs = receipt["logs"]
        .as_array()
        .ok_or_else(|| AuthError::InvalidInput("the receipt has no logs".into()))?;
    let ours = |log: &&Value| {
        log["removed"] != true
            && log["address"]
                .as_str()
                .is_some_and(|address| address.eq_ignore_ascii_case(&vault_hex))
    };
    let mut paid = None;
    for log in logs.iter().filter(ours) {
        let topics = log["topics"].as_array().cloned().unwrap_or_default();
        let topic = |index: usize| topics.get(index).and_then(Value::as_str).unwrap_or("");
        if topics.len() == 2
            && topic(0).eq_ignore_ascii_case(&finalized_topic)
            && topic(1).eq_ignore_ascii_case(&note_topic)
        {
            let data = log["data"].as_str().unwrap_or("");
            let words = data
                .strip_prefix("0x")
                .filter(|digits| digits.len() == 3 * 64);
            let Some(words) = words else { continue };
            if words[..64].eq_ignore_ascii_case(&chain::word_felt(&record.withdrawal_nullifier))
                && words[128..].eq_ignore_ascii_case(&chain::word_address(&destination))
                && words[64..96].bytes().all(|byte| byte == b'0')
            {
                if paid.is_some() {
                    return Err(AuthError::InvalidInput(
                        "the receipt finalizes this escape twice".into(),
                    ));
                }
                paid = u128::from_str_radix(&words[96..128], 16).ok();
            }
        }
    }
    let paid = paid.ok_or_else(|| {
        AuthError::InvalidInput(
            "the receipt has no EscapeWithdrawalFinalized for this note, nullifier and destination"
                .into(),
        )
    })?;
    let credited = logs.iter().filter(ours).any(|log| {
        let topics = log["topics"].as_array().cloned().unwrap_or_default();
        topics.len() == 3
            && [&deferred_topic, &note_topic, &destination_topic]
                .iter()
                .zip(&topics)
                .all(|(expected, topic)| {
                    topic
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
                })
    });
    let block = chain::quantity(&receipt["blockNumber"])?;
    let raises = chain::raised_concessions(
        rpc,
        &vault,
        record.note_id,
        &record.withdrawal_nullifier,
        record.start_block,
        block,
    )
    .await?;
    let matched = exit_policy::match_escape_payout(
        paid,
        record.state_balance(),
        record.conceded_at_init(),
        &raises,
        Some(record.bound()),
    );
    Ok((paid, matched, credited))
}

async fn finalize_escape_locked(
    config: &AuthConfig,
    wallet: &mut Wallet,
    hash: &str,
) -> Result<Value, AuthError> {
    let mut record = load_record(config)?.ok_or(AuthError::WithdrawalConflict)?;
    if record.phase == "complete" {
        if record.finalize_transaction.as_deref() == Some(hash) {
            return Ok(json!({"status": "complete", "record": record}));
        }
        return Err(AuthError::WithdrawalConflict);
    }
    // The payout closes the note: the owner's exit RPC decides when one is
    // configured, so a pinned RPC that is down or lies neither blocks nor
    // forges the close.
    let rpc = deciding_rpc(config)?;
    let receipt = rpc
        .receipt(hash)
        .await?
        .ok_or(AuthError::OaWithdrawalPending)?;
    if receipt["status"] != "0x1" {
        return Err(AuthError::InvalidInput(
            "the finalize transaction did not succeed".into(),
        ));
    }
    let (finalized, _) = rpc.block("finalized").await?;
    if chain::quantity(&receipt["blockNumber"])? > finalized {
        return Err(AuthError::OaWithdrawalPending);
    }
    let (paid, matched, credited) = match_finalized_escape(config, &record, &receipt, &rpc).await?;
    let PayoutMatch::Matches {
        conceded_final,
        concession_exceeded_bound,
    } = matched
    else {
        return Err(AuthError::InvalidInput(format!(
            "the payout {paid} matches neither the escape's balance less its concession nor any recorded raise"
        )));
    };
    if concession_exceeded_bound {
        tracing::warn!(
            note_id = record.note_id,
            paid,
            "concession_exceeded_bound: the escape paid less than the state balance less this state's bound"
        );
    }
    let vault = chain::vault_address(&config.contract_address)?;
    let view = chain::read_note(&rpc, &vault, record.note_id, "finalized").await?;
    if view.status != 3 {
        return Err(AuthError::OaWithdrawalPending);
    }
    record.phase = "complete".into();
    record.finalize_transaction = Some(hash.to_string());
    record.payout = Some(paid.to_string());
    record.conceded_final = Some(conceded_final.to_string());
    record.payout_credited = credited;
    record.concession_exceeded_bound = concession_exceeded_bound;
    save_record(config, &record)?;
    // The note is closed (E6): archive it, which releases the exit lock.
    if wallet
        .state()
        .is_some_and(|state| state.note_id == record.note_id)
    {
        wallet.archive_note()?;
    }
    crate::oa_withdrawal::complete_for_escape(config, &record, hash)?;
    Ok(json!({
        "status": "complete",
        "note_id": record.note_id,
        "payout": record.payout,
        "conceded_final": record.conceded_final,
        "payout_credited": credited,
        "concession_exceeded_bound": concession_exceeded_bound,
        "claim_calldata": credited.then(|| chain::claim_calldata(&crate::oa_withdrawal::destination(&record.destination).unwrap_or([0; 20]))),
        "record": record,
    }))
}

#[cfg(test)]
#[path = "exit_tests.rs"]
mod tests;
