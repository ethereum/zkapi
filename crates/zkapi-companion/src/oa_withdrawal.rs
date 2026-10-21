//! Durable OA withdrawal reservation. Every call runs under the wallet lock.
//! The snapshot is local recovery material and is never returned over HTTP.
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_client::note_state::NoteState;
use zkapi_core::v2;
use zkapi_types::Felt252;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::indexer::IndexerClient;
use crate::service::{WithdrawalMode, WithdrawalPlan};

const FILE: &str = "oa-withdrawal.json";

#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct Reservation {
    version: u8,
    pub snapshot: NoteState,
    pub destination: [u8; 20],
    pub nullifier: Felt252,
    pub plan: Option<WithdrawalPlan>,
    pub complete: bool,
    pub transaction_hash: Option<String>,
    /// Written by earlier builds: the owner acknowledged sending an ownership
    /// proof from an expired note's unsettled state on a legacy vault. Kept
    /// so such a reservation still loads; every clearance request of a
    /// `zkapi-v2-concession-v1` companion carries the ownership proof.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub unsettled_request_risk_accepted: bool,
    /// Whether a clearance request carrying this state's ownership proof may
    /// have left the companion. It is saved as `true` once the proof is built
    /// and before the request is sent, whatever answer (a gateway 429, a 5xx,
    /// none) follows: whoever saw the request may hold the proof, which is a
    /// submittable escape at this nullifier. `None` in a reservation saved
    /// before this field existed; see `ownership_proof_may_have_left`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ownership_proof_sent: Option<bool>,
    /// The confirmed payout is a finalized escape that the vault could not
    /// push to the destination: it credited the balance to
    /// `escapePayoutCredits(destination)` (`EscapePayoutDeferred`), and only
    /// `claimEscapePayout(destination)` delivers it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub escape_payout_credited: bool,
    /// How the clearance of this reservation was refused, if it was (E2
    /// steps 4 and 5): the exit decision then waits (E3) or escapes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearance_outcome: Option<zkapi_client::exit_policy::MutualOutcome>,
    /// The verified clearance signature of this reservation's nullifier.
    /// It signs only the nullifier, not the close's `valid_until`, so a
    /// close that expired (L6) is proved again from it without another
    /// ownership proof or clearance request. `None` before the clearance,
    /// and in a reservation saved before this field existed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clearance_signature: Option<zkapi_types::SchnorrSignature>,
}

impl Reservation {
    /// Whether this reservation's ownership proof may have left the
    /// companion. A reservation saved before `ownership_proof_sent` existed
    /// does not say. No build could send a proof it could not build, and
    /// building one needs the reserved state's note leaf in the vault's tree
    /// at its note id (`leaf_in_tree`, asked only for such a reservation).
    /// A wrongly bound note, the case release exists for, fails that, so its
    /// reservation releases whichever build saved it.
    pub(crate) fn ownership_proof_may_have_left(
        &self,
        leaf_in_tree: impl FnOnce() -> Result<bool, AuthError>,
    ) -> Result<bool, AuthError> {
        match self.ownership_proof_sent {
            Some(sent) => Ok(sent),
            None => leaf_in_tree(),
        }
    }
}

/// Whether `state`'s note leaf is in the vault's tree at its note id, as the
/// indexer reports it. Every withdrawal or request proof from the state
/// proves exactly that membership: without it no ownership proof was ever
/// built from the state, and no request proof can be built from it either.
pub(crate) async fn note_leaf_in_tree(
    indexer: &IndexerClient,
    state: &NoteState,
) -> Result<bool, AuthError> {
    let leaf = v2::note_leaf(
        state.note_id,
        &v2::registration_commitment(&state.secret_s),
        state.deposit_amount,
        state.expiry_ts,
    );
    Ok(indexer.note_leaf(state.note_id).await? == leaf)
}

/// Recorded, before the request leaves, that a clearance request carrying
/// this reservation's ownership proof is about to be sent. The reservation
/// then stays until the note closes: it is never released, and no request
/// proof is made at its nullifier (C5).
pub(crate) fn record_ownership_proof_sent(
    config: &AuthConfig,
    record: &mut Reservation,
) -> Result<(), AuthError> {
    if record.ownership_proof_sent != Some(true) {
        record.ownership_proof_sent = Some(true);
        save(config, record)?;
    }
    Ok(())
}

fn storage_error() -> AuthError {
    AuthError::Wallet(
        "withdrawal recovery storage is unavailable or invalid; preserve its files".into(),
    )
}

pub(crate) fn destination(value: &str) -> Result<[u8; 20], AuthError> {
    let bytes = hex_bytes(value, 20)?;
    let mut result = [0; 20];
    result.copy_from_slice(&bytes);
    if result == [0; 20] {
        return Err(AuthError::InvalidInput(
            "withdrawal destination cannot be the zero address".into(),
        ));
    }
    Ok(result)
}

/// A withdrawal destination the vault can pay: neither the zero address nor
/// the vault itself. A vault with `vault_revision` 2 refuses its own address
/// (`InvalidDestination`), and a legacy vault cannot receive the payout, so
/// every close to it reverts. Checked before any note is reserved or any
/// clearance is requested: a clearance is permanent, and the reservation
/// pins its destination.
pub(crate) fn check_destination(
    config: &AuthConfig,
    destination: &[u8; 20],
) -> Result<(), AuthError> {
    if *destination == [0; 20] {
        return Err(AuthError::InvalidInput(
            "withdrawal destination cannot be the zero address".into(),
        ));
    }
    if zkapi_types::serialization::address_to_felt(destination) == config.contract_address {
        return Err(AuthError::InvalidInput(
            "withdrawal destination cannot be the vault contract, which cannot pay itself".into(),
        ));
    }
    Ok(())
}

fn hex_bytes(value: &str, size: usize) -> Result<Vec<u8>, AuthError> {
    if !value.starts_with("0x")
        || value.len() != 2 + size * 2
        || !value[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(AuthError::InvalidInput(
            "invalid withdrawal hexadecimal value".into(),
        ));
    }
    (2..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| AuthError::InvalidInput("invalid withdrawal hexadecimal value".into()))
        })
        .collect()
}

fn hex(value: &[u8]) -> String {
    format!(
        "0x{}",
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn same_state(left: &NoteState, right: &NoteState) -> bool {
    matches!((serde_json::to_value(left), serde_json::to_value(right)), (Ok(left), Ok(right)) if left == right)
}

pub(crate) fn load(config: &AuthConfig) -> Result<Option<Reservation>, AuthError> {
    let path = config.state_dir.join(FILE);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(storage_error()),
    };
    if !metadata.is_file() || metadata.len() > 1 << 20 {
        return Err(storage_error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err(storage_error());
        }
    }
    let record: Reservation = serde_json::from_slice(&fs::read(path).map_err(|_| storage_error())?)
        .map_err(|_| storage_error())?;
    if record.version != 1
        || record.snapshot.protocol_version != config.protocol_version
        || record.snapshot.chain_id != config.chain_id
        || record.snapshot.contract_address != config.contract_address
        || record.destination == [0; 20]
        || record.nullifier
            != v2::nullifier(
                &record.snapshot.secret_s,
                record.snapshot.note_id,
                &record.snapshot.current_anchor,
            )
        || (record.complete && record.transaction_hash.is_none())
    {
        return Err(storage_error());
    }
    if let Some(plan) = &record.plan {
        validate_plan(&record, plan)?;
    }
    if let Some(hash) = &record.transaction_hash {
        hex_bytes(hash, 32)?;
    }
    Ok(Some(record))
}

/// Whether `reserve` would refuse `state` and `destination` with a
/// conflict, without changing anything: checked before any operator call,
/// so a conflicting request fails the same way whatever the operator does.
pub(crate) fn check_reservable(
    config: &AuthConfig,
    state: &NoteState,
    destination: [u8; 20],
) -> Result<(), AuthError> {
    if let Some(previous) = load(config)? {
        let replaced = (previous.complete && previous.snapshot.note_id != state.note_id)
            || superseded(&previous, state, crate::service::now_seconds());
        if !replaced
            && (previous.destination != destination || !same_state(&previous.snapshot, state))
        {
            return Err(AuthError::WithdrawalConflict);
        }
    }
    Ok(())
}

pub(crate) fn reserve(
    config: &AuthConfig,
    state: &NoteState,
    destination: [u8; 20],
) -> Result<Reservation, AuthError> {
    if state.protocol_version != config.protocol_version
        || state.chain_id != config.chain_id
        || state.contract_address != config.contract_address
        || destination == [0; 20]
    {
        return Err(AuthError::WithdrawalConflict);
    }
    if let Some(previous) = load(config)? {
        if previous.complete && previous.snapshot.note_id != state.note_id {
            archive(
                config,
                &previous,
                "reservation",
                &serde_json::to_vec(&previous).map_err(|_| storage_error())?,
            )?;
        } else if superseded(&previous, state, crate::service::now_seconds()) {
            archive(
                config,
                &previous,
                "superseded",
                &serde_json::to_vec(&previous).map_err(|_| storage_error())?,
            )?;
        } else {
            if previous.destination != destination || !same_state(&previous.snapshot, state) {
                return Err(AuthError::WithdrawalConflict);
            }
            return Ok(previous);
        }
    }
    let record = Reservation {
        version: 1,
        snapshot: state.clone(),
        destination,
        nullifier: v2::nullifier(&state.secret_s, state.note_id, &state.current_anchor),
        plan: None,
        complete: false,
        transaction_hash: None,
        unsettled_request_risk_accepted: false,
        ownership_proof_sent: Some(false),
        escape_payout_credited: false,
        clearance_outcome: None,
        clearance_signature: None,
    };
    save(config, &record)?;
    Ok(record)
}

/// Whether `previous`, an incomplete reservation, belongs to an earlier
/// state of the note `state` now holds, and no close it may hold can still
/// land. A successor installs only after every released close of its state
/// is dead (E6), so such a reservation's clearance can never pay again: it
/// says nothing about the newer state, whose own mutual close it must not
/// block. Its ownership proof stays recorded (C5 is per nullifier).
fn superseded(previous: &Reservation, state: &NoteState, now: u64) -> bool {
    !previous.complete
        && previous.snapshot.note_id == state.note_id
        && state.state_seq > previous.snapshot.state_seq
        && previous.nullifier
            != v2::nullifier(&state.secret_s, state.note_id, &state.current_anchor)
        && previous.plan.as_ref().is_none_or(|plan| {
            plan.public_inputs
                .valid_until
                .saturating_add(zkapi_client::exit_policy::LOCK_RELEASE_MARGIN_SECONDS)
                < now
        })
}

pub(crate) fn save(config: &AuthConfig, record: &Reservation) -> Result<(), AuthError> {
    atomic_write(
        &config.state_dir.join(FILE),
        &serde_json::to_vec(record).map_err(|_| storage_error())?,
    )
}

pub(crate) fn check_spending(config: &AuthConfig, note_id: Option<u32>) -> Result<(), AuthError> {
    if let Some(record) = load(config)? {
        if !record.complete || note_id == Some(record.snapshot.note_id) {
            return Err(AuthError::WithdrawalConflict);
        }
    }
    Ok(())
}

pub(crate) fn validate_plan(record: &Reservation, plan: &WithdrawalPlan) -> Result<(), AuthError> {
    let inputs = &plan.public_inputs;
    if plan.mode != WithdrawalMode::Mutual
        || inputs.withdrawal_kind() != Some(zkapi_types::WithdrawalKind::MutualClose)
        || inputs.next_nullifier != Felt252::ZERO
        || inputs.conceded != 0
        || inputs.protocol_version != record.snapshot.protocol_version
        || inputs.chain_id != record.snapshot.chain_id
        || inputs.contract_address != record.snapshot.contract_address
        || inputs.note_id != record.snapshot.note_id
        || inputs.final_balance != record.snapshot.current_balance
        || inputs.destination != record.destination
        || inputs.withdrawal_nullifier != record.nullifier
        || plan.siblings.len() != 32
    {
        return Err(AuthError::WithdrawalConflict);
    }
    Ok(())
}

pub(crate) fn public_status(record: Option<&Reservation>) -> Value {
    match record {
        None => json!({"phase": "none"}),
        Some(record) => {
            let mut status = json!({"phase": if record.complete {"complete"} else {"reserved"},
                "note_id": record.snapshot.note_id, "destination": hex(&record.destination),
                "final_balance": record.snapshot.current_balance.to_string(), "withdrawal_nullifier": hex(record.nullifier.as_bytes())});
            if let Some(hash) = &record.transaction_hash {
                status["transaction_hash"] = json!(hash);
            }
            if record.escape_payout_credited {
                status["escape_payout_credited"] = json!(true);
            }
            status
        }
    }
}

/// Write a private (0600) file durably: synced, renamed and the rename synced.
pub(crate) fn write_private_durably(path: &Path, bytes: &[u8]) -> Result<(), AuthError> {
    atomic_write(path, bytes)
}

/// Check a 32-byte `0x` transaction hash.
pub(crate) fn transaction_hash(value: &str) -> Result<(), AuthError> {
    hex_bytes(value, 32).map(|_| ())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), AuthError> {
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let temporary = path.with_extension("tmp");
    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&temporary).map_err(|_| storage_error())?;
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| storage_error())?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| storage_error())?;
    fs::rename(&temporary, path).map_err(|_| storage_error())?;
    File::open(path.parent().ok_or_else(storage_error)?)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage_error())
}

fn archive(
    config: &AuthConfig,
    record: &Reservation,
    label: &str,
    bytes: &[u8],
) -> Result<(), AuthError> {
    let directory = config.state_dir.join("archive");
    fs::create_dir_all(&directory).map_err(|_| storage_error())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| storage_error())?;
    }
    File::open(&config.state_dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage_error())?;
    atomic_write(
        &directory.join(format!(
            "oa-withdrawal-{}-{}-{label}.json",
            record.snapshot.note_id,
            record.nullifier.to_hex()
        )),
        bytes,
    )
}

/// Only an incomplete reservation without a plan, for the unchanged active
/// note, may be released: it never produced a mutual-close proof. It also
/// must not have sent an ownership proof (C5): no request is made from a
/// state whose ownership proof left, so releasing it would gain nothing.
/// `leaf_in_tree` is `note_leaf_in_tree` for the active note (see
/// `Reservation::ownership_proof_may_have_left`).
pub(crate) fn check_release(
    config: &AuthConfig,
    record: &Reservation,
    active: &NoteState,
    leaf_in_tree: impl FnOnce() -> Result<bool, AuthError>,
) -> Result<(), AuthError> {
    if record.complete || record.plan.is_some() || !same_state(active, &record.snapshot) {
        return Err(AuthError::WithdrawalConflict);
    }
    let _ = config;
    if record.ownership_proof_may_have_left(leaf_in_tree)? {
        return Err(AuthError::OwnershipProofSent);
    }
    Ok(())
}

/// Remove such a reservation, keeping an archived copy. Call under the wallet
/// lock, only after the server reported the nullifier unknown, so that no
/// clearance or mutual close can exist for it.
pub(crate) fn release(
    config: &AuthConfig,
    record: &Reservation,
    active: &NoteState,
    leaf_in_tree: impl FnOnce() -> Result<bool, AuthError>,
) -> Result<(), AuthError> {
    check_release(config, record, active, leaf_in_tree)?;
    archive(
        config,
        record,
        "released",
        &serde_json::to_vec(record).map_err(|_| storage_error())?,
    )?;
    match fs::remove_file(config.state_dir.join(FILE)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(storage_error()),
    }
    File::open(&config.state_dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage_error())
}

// Called only after independently checking canonical finalized payout evidence.
pub(crate) fn complete(
    config: &AuthConfig,
    record: &mut Reservation,
    hash: &str,
) -> Result<(), AuthError> {
    let active_path = config.state_dir.join("note_state.json");
    if active_path.exists() {
        let active = NoteState::load(&active_path).map_err(|_| storage_error())?;
        if !same_state(&active, &record.snapshot) {
            return Err(AuthError::WithdrawalConflict);
        }
    }
    if zkapi_client::journal::PendingRequestJournal::read(
        &config.state_dir.join("pending_journal.json"),
    )?
    .is_some()
    {
        return Err(AuthError::PendingSettlement);
    }
    archive(
        config,
        record,
        "note",
        &serde_json::to_vec(&record.snapshot).map_err(|_| storage_error())?,
    )?;
    record.transaction_hash = Some(hash.to_lowercase());
    save(config, record)?;
    match fs::remove_file(&active_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(storage_error()),
    }
    File::open(&config.state_dir)
        .and_then(|f| f.sync_all())
        .map_err(|_| storage_error())?;
    record.complete = true;
    save(config, record)
}

/// The reservation of a note an escape closed (`exit::finalize`): mark it
/// complete with the finalize transaction. The note was archived already.
pub(crate) fn complete_for_escape(
    config: &AuthConfig,
    escape: &crate::service::exit::EscapeRecord,
    hash: &str,
) -> Result<(), AuthError> {
    let Some(mut record) = load(config)? else {
        return Ok(());
    };
    if record.complete || record.snapshot.note_id != escape.note_id {
        return Ok(());
    }
    record.escape_payout_credited = escape.payout_credited;
    complete(config, &mut record, hash)
}

/// Complete with the evidence `confirm_receipt` returned. A finalized escape
/// whose payout the vault credited closed the note too; the status then
/// reports the credit instead of a paid close.
pub(crate) fn complete_confirmed(
    config: &AuthConfig,
    record: &mut Reservation,
    hash: &str,
    evidence: CloseEvidence,
) -> Result<(), AuthError> {
    record.escape_payout_credited = evidence.escape_payout_credited;
    complete(config, record, hash)
}

async fn rpc(config: &AuthConfig, method: &str, params: Value) -> Result<Value, AuthError> {
    let failure = || {
        AuthError::Wallet("withdrawal RPC unavailable or invalid; preserve saved progress".into())
    };
    let url = config.demo_rpc_url.as_deref().ok_or_else(failure)?;
    let parsed = reqwest::Url::parse(url).map_err(|_| failure())?;
    // The escape's rule (chain::rpc_url_allowed): HTTPS, or plain HTTP to a
    // node on this machine, so a close confirms on every RPC an escape may
    // use.
    if !crate::chain::rpc_url_allowed(&parsed) {
        return Err(failure());
    }
    // New clients inherit the daemon's authenticated local CONNECT proxy,
    // using direct TCP or Wisp with no fallback or account authorization header.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| failure())?;
    let mut response = client
        .post(url)
        .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
        .send()
        .await
        .map_err(|_| failure())?;
    if !response.status().is_success() {
        return Err(failure());
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| failure())? {
        if bytes.len() + chunk.len() > 1 << 20 {
            return Err(failure());
        }
        bytes.extend_from_slice(&chunk);
    }
    let response: Value = serde_json::from_slice(&bytes).map_err(|_| failure())?;
    if response["id"] != 1
        || response["jsonrpc"] != "2.0"
        || response.get("error").is_some()
        || response.get("result").is_none()
    {
        return Err(failure());
    }
    Ok(response["result"].clone())
}

fn quantity(value: &Value) -> Result<u64, AuthError> {
    let text = value.as_str().ok_or_else(storage_error)?;
    u64::from_str_radix(text.strip_prefix("0x").ok_or_else(storage_error)?, 16)
        .map_err(|_| storage_error())
}

/// What a matching payout receipt shows.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CloseEvidence {
    /// The receipt's escape closed the note, but the vault could not push the
    /// balance to the destination and credited it to
    /// `escapePayoutCredits(destination)`: `EscapePayoutDeferred` for this
    /// note and destination precedes `EscapeWithdrawalFinalized`. Nothing has
    /// reached the destination until `claimEscapePayout(destination)`.
    pub escape_payout_credited: bool,
    /// The receipt is a finalized escape of the reserved state that paid
    /// this amount, which a raise may have lowered below the snapshot
    /// balance: `confirm_receipt` matches it against the escape record (E5).
    pub escape_paid: Option<u128>,
}

pub(crate) fn validate_close_event(
    record: &Reservation,
    receipt: &Value,
    hash: &str,
) -> Result<CloseEvidence, AuthError> {
    if receipt["status"] != "0x1"
        || !receipt["transactionHash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(hash))
    {
        return Err(AuthError::InvalidInput(
            "withdrawal receipt is not a successful matching transaction".into(),
        ));
    }
    // A finalized escape of the reserved state is the only other payout of
    // this note. It pays B − c_final, which a concession or a raise may set
    // below the snapshot balance; `confirm_receipt` matches the amount (E5).
    let topics = [
        b"MutualClose(uint32,uint256,uint128,address)".as_slice(),
        b"EscapeWithdrawalFinalized(uint32,uint256,uint128,address)".as_slice(),
    ]
    .map(|signature| format!("0x{:x}", Keccak256::digest(signature)));
    let vault = hex(&record.snapshot.contract_address.as_bytes()[12..]);
    let note_topic = format!("0x{:064x}", record.snapshot.note_id);
    let nullifier_word = &hex(record.nullifier.as_bytes())[2..];
    let destination_word = format!("{}{}", "0".repeat(24), &hex(&record.destination)[2..]);
    let mut escape_paid = None;
    let matches: Vec<&Value> = receipt["logs"]
        .as_array()
        .ok_or_else(storage_error)?
        .iter()
        .filter(|log| {
            if log["removed"] == true
                || !log["address"]
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case(&vault))
            {
                return false;
            }
            let Some(log_topics) = log["topics"].as_array().filter(|topics| topics.len() == 2)
            else {
                return false;
            };
            if !log_topics[1]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&note_topic))
            {
                return false;
            }
            let escape = log_topics[0]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&topics[1]));
            let mutual = log_topics[0]
                .as_str()
                .is_some_and(|value| value.eq_ignore_ascii_case(&topics[0]));
            let Some(data) = log["data"]
                .as_str()
                .and_then(|value| value.strip_prefix("0x"))
                .filter(|value| value.len() == 192)
            else {
                return false;
            };
            if !data[..64].eq_ignore_ascii_case(nullifier_word)
                || !data[128..].eq_ignore_ascii_case(&destination_word)
                || !data[64..96].bytes().all(|byte| byte == b'0')
            {
                return false;
            }
            let Ok(paid) = u128::from_str_radix(&data[96..128], 16) else {
                return false;
            };
            if mutual {
                paid == record.snapshot.current_balance
            } else if escape && paid <= record.snapshot.current_balance {
                escape_paid = Some(paid);
                true
            } else {
                false
            }
        })
        .collect();
    if matches.len() != 1 {
        return Err(AuthError::InvalidInput(
            "withdrawal receipt has no unique matching MutualClose or EscapeWithdrawalFinalized payout event".into(),
        ));
    }
    // A vault with vault_revision 2 credits an escape payout that the
    // destination rejects, or that needs more than 100,000 gas to receive.
    // Whatever amount it names, a deferral for this note and destination
    // means the destination was not paid. A mutual close pays in full or
    // reverts, so only an escape can be credited.
    let escape = matches[0]["topics"][0]
        .as_str()
        .is_some_and(|value| value.eq_ignore_ascii_case(&topics[1]));
    let deferred = format!(
        "0x{:x}",
        Keccak256::digest(b"EscapePayoutDeferred(uint32,address,uint128)")
    );
    let destination_topic = format!("0x{}{}", "0".repeat(24), &hex(&record.destination)[2..]);
    let escape_payout_credited = escape
        && receipt["logs"]
            .as_array()
            .ok_or_else(storage_error)?
            .iter()
            .any(|log| {
                log["removed"] != true
                    && log["address"]
                        .as_str()
                        .is_some_and(|value| value.eq_ignore_ascii_case(&vault))
                    && log["topics"].as_array().is_some_and(|log_topics| {
                        log_topics.len() == 3
                            && [&deferred, &note_topic, &destination_topic]
                                .iter()
                                .zip(log_topics)
                                .all(|(expected, topic)| {
                                    topic
                                        .as_str()
                                        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
                                })
                    })
            });
    Ok(CloseEvidence {
        escape_payout_credited,
        escape_paid: escape.then_some(escape_paid).flatten(),
    })
}

pub(crate) async fn confirm_receipt(
    config: &AuthConfig,
    record: &Reservation,
    hash: &str,
) -> Result<CloseEvidence, AuthError> {
    confirm_receipt_using(config, record, hash, |method, params| {
        rpc(config, method, params)
    })
    .await
}

async fn confirm_receipt_using<F, Fut>(
    config: &AuthConfig,
    record: &Reservation,
    hash: &str,
    mut request: F,
) -> Result<CloseEvidence, AuthError>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, AuthError>>,
{
    hex_bytes(hash, 32)?;
    if quantity(&request("eth_chainId", json!([])).await?)? != config.chain_id {
        return Err(AuthError::WithdrawalConflict);
    }
    let receipt = request("eth_getTransactionReceipt", json!([hash])).await?;
    if receipt.is_null() {
        return Err(AuthError::OaWithdrawalPending);
    }
    let evidence = validate_close_event(record, &receipt, hash)?;
    let number = quantity(&receipt["blockNumber"])?;
    if let Some(paid) = evidence.escape_paid {
        check_escape_payout(config, record, paid, number, &mut request).await?;
    }
    let hash = receipt["blockHash"].as_str().ok_or_else(storage_error)?;
    hex_bytes(hash, 32)?;
    let finalized = request("eth_getBlockByNumber", json!(["finalized", false])).await?;
    if quantity(&finalized["number"])? < number {
        return Err(AuthError::OaWithdrawalPending);
    }
    let canonical = request(
        "eth_getBlockByNumber",
        json!([receipt["blockNumber"], false]),
    )
    .await?;
    if quantity(&canonical["number"])? != number
        || !canonical["hash"]
            .as_str()
            .is_some_and(|value| value.eq_ignore_ascii_case(hash))
    {
        return Err(AuthError::OaWithdrawalPending);
    }
    if quantity(&request("eth_chainId", json!([])).await?)? != config.chain_id {
        return Err(AuthError::WithdrawalConflict);
    }
    Ok(evidence)
}

/// E5 for a reservation closed by an escape: `paid` must be `B − c_final`,
/// with `c_final` the largest of the initial concession and every
/// `EscapeConcessionRaised` since. B and the initial concession come from
/// the escape record, or, for an escape this companion did not prepare,
/// from the note's latest `EscapeConcessionRecorded`.
async fn check_escape_payout<F, Fut>(
    config: &AuthConfig,
    record: &Reservation,
    paid: u128,
    block: u64,
    request: &mut F,
) -> Result<(), AuthError>
where
    F: FnMut(&'static str, Value) -> Fut,
    Fut: std::future::Future<Output = Result<Value, AuthError>>,
{
    let mismatch = || {
        AuthError::InvalidInput(
            "the escape payout matches neither the reserved balance nor the escape's balance less its concessions".into(),
        )
    };
    let escape = crate::service::exit::load_record(config)?.filter(|escape| {
        escape.note_id == record.snapshot.note_id && escape.withdrawal_nullifier == record.nullifier
    });
    let vault = hex(&record.snapshot.contract_address.as_bytes()[12..]);
    let note_topic = format!("0x{:064x}", record.snapshot.note_id);
    // Without an escape record of the reserved state (another device or an
    // exit kit escaped), the latest EscapeConcessionRecorded of the note gives
    // the state balance, which must be the reserved one, and the initial
    // concession.
    let (state_balance, conceded_at_init, from_block, bound) = match escape {
        Some(escape) => (
            escape.state_balance(),
            escape.conceded_at_init(),
            escape.start_block,
            Some(escape.bound()),
        ),
        None => {
            if paid == record.snapshot.current_balance {
                return Ok(());
            }
            let recorded = request(
                "eth_getLogs",
                json!([{
                    "address": vault,
                    "fromBlock": format!("0x{:x}", config.deploy_block),
                    "toBlock": format!("0x{block:x}"),
                    "topics": [crate::chain::topic("EscapeConcessionRecorded(uint32,uint256,uint128,uint128)"), note_topic],
                }]),
            )
            .await?;
            let latest = recorded
                .as_array()
                .ok_or_else(storage_error)?
                .iter()
                .rev()
                .filter(|log| log["removed"] != true)
                .filter_map(|log| {
                    log["data"]
                        .as_str()
                        .and_then(|value| value.strip_prefix("0x"))
                        .filter(|value| value.len() == 192)
                        .map(str::to_string)
                })
                .next()
                .ok_or_else(mismatch)?;
            let word = |range: std::ops::Range<usize>| {
                latest[range.clone()][..32]
                    .bytes()
                    .all(|byte| byte == b'0')
                    .then(|| u128::from_str_radix(&latest[range][32..], 16).ok())
                    .flatten()
            };
            let (Some(state_balance), Some(conceded)) = (word(64..128), word(128..192)) else {
                return Err(mismatch());
            };
            if state_balance != record.snapshot.current_balance {
                return Err(mismatch());
            }
            (state_balance, conceded, config.deploy_block, None)
        }
    };
    let logs = request(
        "eth_getLogs",
        json!([{
            "address": vault,
            "fromBlock": format!("0x{from_block:x}"),
            "toBlock": format!("0x{block:x}"),
            "topics": [crate::chain::escape_concession_raised_topic(), note_topic],
        }]),
    )
    .await?;
    let nullifier_word = &hex(record.nullifier.as_bytes())[2..];
    let mut raises = Vec::new();
    for log in logs.as_array().ok_or_else(storage_error)? {
        if log["removed"] == true {
            continue;
        }
        let data = log["data"]
            .as_str()
            .and_then(|value| value.strip_prefix("0x"))
            .filter(|value| value.len() == 192)
            .ok_or_else(storage_error)?;
        if data[..64].eq_ignore_ascii_case(nullifier_word)
            && data[64..96].bytes().all(|b| b == b'0')
        {
            raises.push(u128::from_str_radix(&data[96..128], 16).map_err(|_| storage_error())?);
        }
    }
    match zkapi_client::exit_policy::match_escape_payout(
        paid,
        state_balance,
        conceded_at_init,
        &raises,
        bound,
    ) {
        zkapi_client::exit_policy::PayoutMatch::Matches { .. } => Ok(()),
        zkapi_client::exit_policy::PayoutMatch::Mismatch => Err(mismatch()),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn fixture() -> (tempfile::TempDir, AuthConfig, NoteState) {
        let directory = tempfile::tempdir().unwrap();
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            chain_id: 11_155_111,
            contract_address: Felt252::from_u64(0x12345),
            indexer_url: "http://127.0.0.1:1".into(),
            protocol_server_url: "http://127.0.0.1:1".into(),
            ..Default::default()
        };
        let note = NoteState::new_from_deposit(
            2,
            config.chain_id,
            config.contract_address,
            7,
            Felt252::from_u64(42),
            1_500_000,
            4_000_000_000,
            "0x1".into(),
            Felt252::ONE,
            Felt252::ONE,
        );
        note.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        (directory, config, note)
    }

    pub(crate) fn plan(record: &Reservation) -> WithdrawalPlan {
        WithdrawalPlan {
            mode: WithdrawalMode::Mutual,
            siblings: vec![Felt252::ZERO; 32],
            public_inputs: zkapi_types::WithdrawalPublicInputsV2C {
                protocol_version: 2,
                chain_id: record.snapshot.chain_id,
                contract_address: record.snapshot.contract_address,
                active_root: Felt252::ONE,
                state_signing_key_x: Felt252::ZERO,
                state_signing_key_y: Felt252::ONE,
                clearance_signing_key_x: Felt252::ZERO,
                clearance_signing_key_y: Felt252::ONE,
                note_id: record.snapshot.note_id,
                final_balance: record.snapshot.current_balance,
                destination: record.destination,
                withdrawal_nullifier: record.nullifier,
                kind: zkapi_types::WithdrawalKind::MutualClose.as_u8(),
                next_nullifier: Felt252::ZERO,
                conceded: 0,
                valid_until: 4_000_000_000,
            },
            proof: zkapi_types::wire::Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "test-proof".into(),
            },
        }
    }

    /// A reservation of an earlier state of the note (a successor installed
    /// since, which E6 allows only once its closes are dead) gives way to the
    /// current state's own mutual close; one of a state that is not older,
    /// or whose close may still land, still conflicts.
    #[test]
    fn a_reservation_of_an_earlier_state_gives_way_to_the_current_state() {
        let (_directory, config, note) = fixture();
        let mut first = reserve(&config, &note, [1; 20]).unwrap();
        first.ownership_proof_sent = Some(true);
        save(&config, &first).unwrap();
        let mut next = note.clone();
        next.current_anchor = Felt252::from_u64(0x55);
        next.state_seq += 1;
        next.current_balance -= 10;
        // A close of the earlier state that may still land conflicts.
        first.plan = Some(plan(&first));
        save(&config, &first).unwrap();
        assert!(matches!(
            check_reservable(&config, &next, [2; 20]),
            Err(AuthError::WithdrawalConflict)
        ));
        assert!(matches!(
            reserve(&config, &next, [2; 20]),
            Err(AuthError::WithdrawalConflict)
        ));
        // Dead (valid_until + 900 passed): the earlier reservation is
        // archived and the current state reserved.
        if let Some(plan) = first.plan.as_mut() {
            plan.public_inputs.valid_until = crate::service::now_seconds() - 1_000;
        }
        save(&config, &first).unwrap();
        check_reservable(&config, &next, [2; 20]).unwrap();
        let replaced = reserve(&config, &next, [2; 20]).unwrap();
        assert_eq!(replaced.snapshot.current_anchor, next.current_anchor);
        assert_eq!(replaced.destination, [2; 20]);
        assert!(std::fs::read_dir(config.state_dir.join("archive"))
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .ends_with("-superseded.json")));
        // A state that is not newer than the reserved one conflicts.
        let mut sideways = note.clone();
        sideways.current_anchor = Felt252::from_u64(0x66);
        sideways.state_seq = next.state_seq;
        assert!(matches!(
            reserve(&config, &sideways, [2; 20]),
            Err(AuthError::WithdrawalConflict)
        ));
    }

    pub(crate) fn receipt(record: &Reservation, hash: &str) -> Value {
        json!({"status":"0x1","transactionHash":hash,"blockNumber":"0x64","blockHash":hex(&[3;32]),
            "logs":[{"address":hex(&record.snapshot.contract_address.as_bytes()[12..]),
                "topics":[format!("0x{:x}",Keccak256::digest(b"MutualClose(uint32,uint256,uint128,address)")),format!("0x{:064x}",record.snapshot.note_id)],
                "data":format!("{}{:064x}{}{}",hex(record.nullifier.as_bytes()),record.snapshot.current_balance,"0".repeat(24),&hex(&record.destination)[2..])}]})
    }

    #[test]
    fn reservation_survives_restart_and_freezes_private_state() {
        let (_directory, config, note) = fixture();
        let record = reserve(&config, &note, [1; 20]).unwrap();
        let restored = load(&config).unwrap().unwrap();
        assert!(same_state(&restored.snapshot, &note));
        assert!(check_spending(&config, Some(note.note_id)).is_err());
        assert!(check_spending(&config, None).is_err());
        assert!(reserve(&config, &note, [2; 20]).is_err());
        let mut changed = note.clone();
        changed.current_balance -= 1;
        assert!(reserve(&config, &changed, [1; 20]).is_err());
        let public = public_status(Some(&record));
        assert_eq!(public["phase"], "reserved");
        assert_eq!(public["final_balance"], "1500000");
        assert_eq!(public["withdrawal_nullifier"].as_str().unwrap().len(), 66);
        for secret_field in [
            "snapshot",
            "secret_s",
            "current_anchor",
            "balance_blinding",
            "state_signature",
            "plan",
        ] {
            assert!(public.get(secret_field).is_none());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(config.state_dir.join(FILE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let mut wrong_chain = config.clone();
        wrong_chain.chain_id += 1;
        assert!(load(&wrong_chain).is_err());
        let mut wrong_vault = config.clone();
        wrong_vault.contract_address = Felt252::ONE;
        assert!(load(&wrong_vault).is_err());
        fs::write(config.state_dir.join(FILE), "broken").unwrap();
        assert!(check_spending(&config, Some(note.note_id)).is_err());
    }

    #[test]
    fn durable_close_retains_archive_and_allows_only_distinct_new_note() {
        let (_directory, config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        record.plan = Some(plan(&record));
        save(&config, &record).unwrap();
        let hash = hex(&[4; 32]);
        // Reproduce a crash after the old note was removed, before complete saved.
        record.transaction_hash = Some(hash.clone());
        save(&config, &record).unwrap();
        fs::remove_file(config.state_dir.join("note_state.json")).unwrap();
        complete(&config, &mut record, &hash).unwrap();
        assert!(load(&config).unwrap().unwrap().complete);
        assert!(check_spending(&config, Some(note.note_id)).is_err());
        assert!(check_spending(&config, None).is_ok());
        let mut next = note.clone();
        next.note_id += 1;
        next.save(&config.state_dir.join("note_state.json"))
            .unwrap();
        assert!(check_spending(&config, Some(next.note_id)).is_ok());
        assert!(
            complete(&config, &mut record, &hash).is_err(),
            "must not delete a newer note"
        );
        let next_record = reserve(&config, &next, [2; 20]).unwrap();
        assert_eq!(next_record.snapshot.note_id, next.note_id);
        assert!(!next_record.complete);
        let archived: Vec<_> = fs::read_dir(config.state_dir.join("archive"))
            .unwrap()
            .collect();
        assert_eq!(
            archived.len(),
            2,
            "both the closed note and prior reservation must survive"
        );
    }

    #[test]
    fn close_fails_closed_for_pending_or_corrupt_settlement_journal() {
        let (_directory, config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        fs::write(config.state_dir.join("pending_journal.json"), "corrupt").unwrap();
        assert!(complete(&config, &mut record, &hex(&[4; 32])).is_err());
        assert!(config.state_dir.join("note_state.json").exists());
        assert!(!load(&config).unwrap().unwrap().complete);
    }

    #[test]
    fn payout_requires_exact_unique_event_not_just_closed_note_status() {
        let (_directory, config, note) = fixture();
        let record = reserve(&config, &note, [1; 20]).unwrap();
        let hash = hex(&[4; 32]);
        let valid = receipt(&record, &hash);
        validate_close_event(&record, &valid, &hash).unwrap();
        for field in ["address", "data"] {
            let mut bad = valid.clone();
            bad["logs"][0][field] = json!("0x00");
            assert!(
                validate_close_event(&record, &bad, &hash).is_err(),
                "{field}"
            );
        }
        for topic in 0..2 {
            let mut bad = valid.clone();
            bad["logs"][0]["topics"][topic] = json!(hex(&[0; 32]));
            assert!(validate_close_event(&record, &bad, &hash).is_err());
        }
        let mut bad = valid.clone();
        bad["logs"][0]["removed"] = json!(true);
        assert!(validate_close_event(&record, &bad, &hash).is_err());
        let mut bad = valid.clone();
        bad["status"] = json!("0x0");
        assert!(validate_close_event(&record, &bad, &hash).is_err());
        let mut bad = valid.clone();
        bad["logs"] = json!([valid["logs"][0], valid["logs"][0]]);
        assert!(validate_close_event(&record, &bad, &hash).is_err());
        assert!(validate_close_event(&record, &valid, &hex(&[5; 32])).is_err());
    }

    #[tokio::test]
    async fn confirmation_requires_finalized_canonical_block_and_stable_chain() {
        let (_directory, config, note) = fixture();
        let record = reserve(&config, &note, [1; 20]).unwrap();
        let hash = hex(&[4; 32]);
        for case in [
            "valid",
            "pending",
            "unfinalized",
            "reorg",
            "wrong_chain",
            "changed_chain",
        ] {
            let mut chain_reads = 0;
            let outcome = confirm_receipt_using(&config, &record, &hash, |method, _params| {
                std::future::ready(Ok(match method {
                    "eth_chainId" => {
                        chain_reads += 1;
                        json!(format!(
                            "0x{:x}",
                            if case == "wrong_chain"
                                || (case == "changed_chain" && chain_reads == 2)
                            {
                                1
                            } else {
                                config.chain_id
                            }
                        ))
                    }
                    "eth_getTransactionReceipt" => {
                        if case == "pending" {
                            Value::Null
                        } else {
                            receipt(&record, &hash)
                        }
                    }
                    "eth_getBlockByNumber" if _params[0] == "finalized" => {
                        json!({"number":if case == "unfinalized" {"0x63"} else {"0x64"}})
                    }
                    "eth_getBlockByNumber" => {
                        json!({"number":"0x64","hash":hex(&[if case == "reorg" {7} else {3};32])})
                    }
                    _ => panic!("unexpected RPC"),
                }))
            })
            .await;
            assert_eq!(outcome.is_ok(), case == "valid", "{case}");
            assert!(
                config.state_dir.join("note_state.json").exists(),
                "checking evidence alone must never remove private state"
            );
        }
    }

    pub(crate) fn escape_finalized(record: &Reservation, hash: &str) -> Value {
        let mut escape = receipt(record, hash);
        escape["logs"][0]["topics"][0] = json!(format!(
            "0x{:x}",
            Keccak256::digest(b"EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")
        ));
        escape
    }

    #[tokio::test]
    async fn finalized_escape_of_the_reserved_payout_is_alternate_evidence() {
        let (_directory, config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        let hash = hex(&[4; 32]);
        let valid = escape_finalized(&record, &hash);
        validate_close_event(&record, &valid, &hash).unwrap();
        // The nullifier, final balance and destination words must all match.
        let data = valid["logs"][0]["data"].as_str().unwrap().to_string();
        for last_digit in [65, 129, 193] {
            let mut changed = data.clone().into_bytes();
            changed[last_digit] = if changed[last_digit] == b'0' {
                b'1'
            } else {
                b'0'
            };
            let mut bad = valid.clone();
            bad["logs"][0]["data"] = json!(String::from_utf8(changed).unwrap());
            assert!(validate_close_event(&record, &bad, &hash).is_err());
        }
        let mut other_note = valid.clone();
        other_note["logs"][0]["topics"][1] = json!(format!("0x{:064x}", note.note_id + 1));
        assert!(validate_close_event(&record, &other_note, &hash).is_err());
        // An initiated or challenged escape has not paid anything.
        for event in [
            b"EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64,uint256)".as_slice(),
            b"EscapeWithdrawalChallenged(uint32,uint256,uint256)".as_slice(),
        ] {
            let mut bad = valid.clone();
            bad["logs"][0]["topics"][0] = json!(format!("0x{:x}", Keccak256::digest(event)));
            assert!(validate_close_event(&record, &bad, &hash).is_err());
        }
        let mut both = valid.clone();
        both["logs"] = json!([valid["logs"][0], receipt(&record, &hash)["logs"][0]]);
        assert!(validate_close_event(&record, &both, &hash).is_err());

        // Finality is still required, after which the plan-less reservation completes.
        for finalized in ["0x63", "0x64"] {
            let outcome = confirm_receipt_using(&config, &record, &hash, |method, params| {
                std::future::ready(Ok(match method {
                    "eth_chainId" => json!(format!("0x{:x}", config.chain_id)),
                    "eth_getTransactionReceipt" => valid.clone(),
                    "eth_getBlockByNumber" if params[0] == "finalized" => {
                        json!({"number": finalized})
                    }
                    "eth_getBlockByNumber" => json!({"number":"0x64","hash":hex(&[3; 32])}),
                    _ => panic!("unexpected RPC"),
                }))
            })
            .await;
            assert_eq!(outcome.is_ok(), finalized == "0x64", "{finalized}");
        }
        assert!(record.plan.is_none());
        complete(&config, &mut record, &hash).unwrap();
        let status = public_status(load(&config).unwrap().as_ref());
        assert_eq!(status["phase"], "complete");
        assert_eq!(status["transaction_hash"], hash);
        assert!(!config.state_dir.join("note_state.json").exists());
    }

    /// E5 for an escape of the reserved state that this companion did not
    /// prepare (an exit kit, another device): the payout must be the
    /// reserved balance less the concession recorded at initiation, raised
    /// to its largest raise; anything else is refused.
    #[tokio::test]
    async fn an_escape_payout_after_a_raise_matches_the_recorded_concession() {
        let (_directory, config, note) = fixture();
        let record = reserve(&config, &note, [1; 20]).unwrap();
        let hash = hex(&[4; 32]);
        let balance = record.snapshot.current_balance;
        for (paid, accepted) in [
            (balance - 900, true),
            (balance - 901, false),
            (balance, true),
        ] {
            let mut receipt = escape_finalized(&record, &hash);
            receipt["logs"][0]["data"] = json!(format!(
                "{}{:064x}{}{}",
                hex(record.nullifier.as_bytes()),
                paid,
                "0".repeat(24),
                &hex(&record.destination)[2..]
            ));
            let outcome = confirm_receipt_using(&config, &record, &hash, |method, params| {
                let receipt = receipt.clone();
                let recorded = crate::chain::topic("EscapeConcessionRecorded(uint32,uint256,uint128,uint128)");
                std::future::ready(Ok(match method {
                    "eth_chainId" => json!(format!("0x{:x}", config.chain_id)),
                    "eth_getTransactionReceipt" => receipt,
                    "eth_getLogs" if params[0]["topics"][0] == recorded => json!([{
                        "data": format!("0x{}{:064x}{:064x}", "00".repeat(32), balance, 100),
                    }]),
                    "eth_getLogs" => json!([{
                        "data": format!("{}{:064x}{:064x}", hex(record.nullifier.as_bytes()), 900, balance - 900),
                    }]),
                    "eth_getBlockByNumber" if params[0] == "finalized" => json!({"number": "0x64"}),
                    "eth_getBlockByNumber" => json!({"number": "0x64", "hash": hex(&[3; 32])}),
                    other => panic!("unexpected RPC {other}"),
                }))
            })
            .await;
            assert_eq!(outcome.is_ok(), accepted, "{paid}: {outcome:?}");
        }
    }

    pub(crate) fn escape_payout_deferred(record: &Reservation) -> Value {
        json!({"address": hex(&record.snapshot.contract_address.as_bytes()[12..]),
            "topics": [
                format!("0x{:x}", Keccak256::digest(b"EscapePayoutDeferred(uint32,address,uint128)")),
                format!("0x{:064x}", record.snapshot.note_id),
                format!("0x{}{}", "0".repeat(24), &hex(&record.destination)[2..]),
            ],
            "data": format!("0x{:064x}", record.snapshot.current_balance)})
    }

    /// contracts cross-component request 3: on a vault_revision 2 vault an
    /// escape whose push to the destination fails still finalizes, but the
    /// balance is only credited to escapePayoutCredits(destination), with
    /// EscapePayoutDeferred before EscapeWithdrawalFinalized. The note is
    /// closed, so the reservation completes, but its status reports the
    /// credit and never a paid close.
    #[tokio::test]
    async fn a_credited_escape_payout_completes_the_close_but_is_reported_as_credited() {
        assert_eq!(
            format!(
                "0x{:x}",
                Keccak256::digest(b"EscapePayoutDeferred(uint32,address,uint128)")
            ),
            "0x1bd006afb1f419c06bdcfcba16d47a9c4c8569f843228da165bdaec644bfa942"
        );
        let (_directory, config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        let hash = hex(&[4; 32]);
        let paid = escape_finalized(&record, &hash);
        assert!(
            !validate_close_event(&record, &paid, &hash)
                .unwrap()
                .escape_payout_credited
        );
        let mut credited = paid.clone();
        credited["logs"] = json!([escape_payout_deferred(&record), paid["logs"][0]]);
        assert!(
            validate_close_event(&record, &credited, &hash)
                .unwrap()
                .escape_payout_credited
        );
        // Only a deferral of this note to this destination, from the vault,
        // that is still canonical counts.
        for (field, value) in [
            ("address", json!(hex(&[9; 20]))),
            ("removed", json!(true)),
            ("topic1", json!(format!("0x{:064x}", note.note_id + 1))),
            (
                "topic2",
                json!(format!("0x{}{}", "0".repeat(24), &hex(&[2; 20])[2..])),
            ),
        ] {
            let mut other = credited.clone();
            match field {
                "topic1" => other["logs"][0]["topics"][1] = value,
                "topic2" => other["logs"][0]["topics"][2] = value,
                _ => other["logs"][0][field] = value,
            }
            assert!(
                !validate_close_event(&record, &other, &hash)
                    .unwrap()
                    .escape_payout_credited,
                "{field}"
            );
        }
        // Exactly the deferral's three topics: not two (no destination), not
        // four, and not another event's topic0 such as EscapePayoutClaimed.
        let deferral = credited["logs"][0]["topics"].clone();
        let claimed = format!(
            "0x{:x}",
            Keccak256::digest(b"EscapePayoutClaimed(address,uint128)")
        );
        for (case, topics) in [
            ("two topics", json!([deferral[0], deferral[1]])),
            (
                "four topics",
                json!([deferral[0], deferral[1], deferral[2], deferral[2]]),
            ),
            ("claimed topic0", json!([claimed, deferral[1], deferral[2]])),
            ("one topic", json!([deferral[0]])),
            ("no topics", json!([])),
        ] {
            let mut other = credited.clone();
            other["logs"][0]["topics"] = topics;
            assert!(
                !validate_close_event(&record, &other, &hash)
                    .unwrap()
                    .escape_payout_credited,
                "{case}"
            );
        }
        // A mutual close is never credited, and a deferral never stands in
        // for the payout event itself.
        let mut mutual = credited.clone();
        mutual["logs"][1] = receipt(&record, &hash)["logs"][0].clone();
        assert!(
            !validate_close_event(&record, &mutual, &hash)
                .unwrap()
                .escape_payout_credited
        );
        let mut alone = credited.clone();
        alone["logs"] = json!([escape_payout_deferred(&record)]);
        assert!(validate_close_event(&record, &alone, &hash).is_err());

        let evidence = confirm_receipt_using(&config, &record, &hash, |method, params| {
            std::future::ready(Ok(match method {
                "eth_chainId" => json!(format!("0x{:x}", config.chain_id)),
                "eth_getTransactionReceipt" => credited.clone(),
                "eth_getBlockByNumber" if params[0] == "finalized" => json!({"number": "0x64"}),
                "eth_getBlockByNumber" => json!({"number":"0x64","hash":hex(&[3; 32])}),
                _ => panic!("unexpected RPC"),
            }))
        })
        .await
        .unwrap();
        assert!(evidence.escape_payout_credited);
        complete_confirmed(&config, &mut record, &hash, evidence).unwrap();
        let status = public_status(load(&config).unwrap().as_ref());
        assert_eq!(status["phase"], "complete");
        assert_eq!(status["escape_payout_credited"], true);
        // A reservation saved before the field existed reads as not credited.
        let mut legacy = serde_json::to_value(&record).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("escape_payout_credited");
        let legacy: Reservation = serde_json::from_value(legacy).unwrap();
        assert!(public_status(Some(&legacy))
            .get("escape_payout_credited")
            .is_none());
    }

    /// Release is refused, on every vault (C5), for a reservation whose
    /// ownership proof may have left. A reservation saved before
    /// `ownership_proof_sent` existed says nothing: builds sent one only when
    /// they could build it, which needs the state's note leaf in the vault's
    /// tree.
    #[test]
    fn release_is_refused_once_the_ownership_proof_may_have_left() {
        let (_directory, mut config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        assert_eq!(record.ownership_proof_sent, Some(false));
        let unasked = || -> Result<bool, AuthError> { panic!("the note leaf is not asked") };
        check_release(&config, &record, &note, unasked).unwrap();
        record_ownership_proof_sent(&config, &mut record).unwrap();
        let saved = load(&config).unwrap().unwrap();
        assert_eq!(saved.ownership_proof_sent, Some(true));
        assert!(matches!(
            check_release(&config, &saved, &note, unasked),
            Err(AuthError::OwnershipProofSent)
        ));
        assert!(matches!(
            release(&config, &saved, &note, unasked),
            Err(AuthError::OwnershipProofSent)
        ));
        assert!(load(&config).unwrap().is_some(), "the reservation stays");
        assert!(check_spending(&config, Some(note.note_id)).is_err());

        // Saved without the field, as zkapi-clientd 0.1.6 and the
        // development builds before it did.
        let mut legacy = serde_json::to_value(&saved).unwrap();
        legacy
            .as_object_mut()
            .unwrap()
            .remove("ownership_proof_sent");
        assert!(legacy.get("ownership_proof_sent").is_none());
        fs::write(
            config.state_dir.join(FILE),
            serde_json::to_vec(&legacy).unwrap(),
        )
        .unwrap();
        let legacy = load(&config).unwrap().unwrap();
        assert_eq!(legacy.ownership_proof_sent, None);
        // The note leaf decides: in the tree, a proof could have been built
        // and sent; not in it (a wrongly bound note), none ever was.
        assert!(matches!(
            check_release(&config, &legacy, &note, || Ok(true)),
            Err(AuthError::OwnershipProofSent)
        ));
        check_release(&config, &legacy, &note, || Ok(false)).unwrap();
        // A leaf that cannot be read releases nothing.
        assert!(matches!(
            check_release(&config, &legacy, &note, || Err(AuthError::Indexer(
                "down".into()
            ))),
            Err(AuthError::Indexer(_))
        ));

        // C5 holds on every vault revision: earlier builds released such a
        // reservation on a vault with vault_revision 2.
        for revision in [2, 3] {
            config.vault_revision = revision;
            assert!(matches!(
                check_release(&config, &saved, &note, unasked),
                Err(AuthError::OwnershipProofSent)
            ));
        }
    }

    #[test]
    fn release_needs_an_unplanned_incomplete_reservation_of_the_active_note() {
        let (_directory, config, note) = fixture();
        let mut record = reserve(&config, &note, [1; 20]).unwrap();
        let mut changed = note.clone();
        changed.current_balance -= 1;
        let unasked = || -> Result<bool, AuthError> { panic!("the note leaf is not asked") };
        assert!(release(&config, &record, &changed, unasked).is_err());
        record.plan = Some(plan(&record));
        assert!(release(&config, &record, &note, unasked).is_err());
        record.plan = None;
        release(&config, &record, &note, unasked).unwrap();
        assert!(load(&config).unwrap().is_none());
        assert!(check_spending(&config, Some(note.note_id)).is_ok());
        let archived = config.state_dir.join("archive").join(format!(
            "oa-withdrawal-{}-{}-released.json",
            note.note_id,
            record.nullifier.to_hex()
        ));
        assert!(archived.exists());
        let mut completed = reserve(&config, &note, [1; 20]).unwrap();
        completed.plan = Some(plan(&completed));
        complete(&config, &mut completed, &hex(&[4; 32])).unwrap();
        assert!(release(&config, &completed, &note, unasked).is_err());
    }

    /// A saved mutual plan is a kind-1 close of the reserved state: no other
    /// kind, no concession and no successor nullifier.
    #[test]
    fn a_plan_must_be_the_reserved_states_mutual_close() {
        let (_directory, config, note) = fixture();
        let record = reserve(&config, &note, [1; 20]).unwrap();
        validate_plan(&record, &plan(&record)).unwrap();
        type Mutation = (&'static str, fn(&mut WithdrawalPlan));
        let mutations: [Mutation; 7] = [
            ("escape kind", |plan| plan.public_inputs.kind = 0),
            ("ownership kind", |plan| plan.public_inputs.kind = 2),
            ("unknown kind", |plan| plan.public_inputs.kind = 3),
            ("conceded", |plan| plan.public_inputs.conceded = 1),
            ("next nullifier", |plan| {
                plan.public_inputs.next_nullifier = Felt252::ONE
            }),
            ("balance", |plan| plan.public_inputs.final_balance -= 1),
            ("destination", |plan| {
                plan.public_inputs.destination = [2; 20]
            }),
        ];
        for (case, mutate) in mutations {
            let mut changed = plan(&record);
            mutate(&mut changed);
            assert!(
                matches!(
                    validate_plan(&record, &changed),
                    Err(AuthError::WithdrawalConflict)
                ),
                "{case}"
            );
        }
    }

    #[test]
    fn destination_is_an_explicit_nonzero_evm_address() {
        let (_directory, config, _note) = fixture();
        assert!(check_destination(&config, &[1; 20]).is_ok());
        let vault = zkapi_types::serialization::felt_to_address(&config.contract_address).unwrap();
        for refused in [[0; 20], vault] {
            assert!(matches!(
                check_destination(&config, &refused),
                Err(AuthError::InvalidInput(_))
            ));
        }
        assert_eq!(destination(&hex(&[1; 20])).unwrap(), [1; 20]);
        for bad in [
            hex(&[0; 20]),
            hex(&[1; 32]),
            "11".repeat(20),
            "0xwrong".into(),
        ] {
            assert!(destination(&bad).is_err());
        }
    }
}
