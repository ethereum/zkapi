//! The operator's close relay, from the wallet's side (serverd's
//! `close_relay`): pay the relay fee as one metered request at the current
//! state, then hand the prepared cooperative close to the relay and read its
//! status. All protocol traffic goes to the configured protocol server
//! through the companion's own transport (the authenticated CONNECT proxy,
//! Tor when the client routes the server over Tor).
//!
//! The fee request is an ordinary request proof: the companion journals it
//! like any request before it leaves, and an answer lost in transit is
//! recovered like any request (`/wallet/settle`, `GET /v2/requests/{id}`).
//! Its successor carries the fee as spent; the withdrawal prepared afterwards
//! (`/oa/v1/withdraw/prepare`) is cleared and proved at that successor, so
//! the fee sits in the close's treasury share. The ticket secret is saved
//! (`close-relay-ticket.json`, mode 0600) before the request is proved, and
//! only its hash is in the request; the secret goes only with the relay
//! submission. The relay never holds the client's funds: the close's proof
//! binds its destination and amount, and the client keeps the proof and
//! submits it itself if the relay does not land it in time.
//!
//! Routes (bridge-authenticated like every `/oa/v1` route):
//! * `POST /oa/v1/withdraw/relay/fee`: pay (or resume paying) the fee;
//! * `POST /oa/v1/withdraw/relay/submit`: queue the reserved close;
//! * `GET /oa/v1/withdraw/relay/status`: the relay's view of it.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkapi_types::wire::{
    CloseRelayFeeAuthorization, CloseRelayStatusResponse, CloseRelaySubmissionV2C,
    CloseRelayTermsResponse, ErrorResponse, RequestResponseV2,
};
use zkapi_types::Felt252;

use super::{
    acquire_wallet_lock, compute_payload_hash, current_thread_runtime, load_wallet, spawn_blocking,
    state_solvency_bound, AuthService,
};
use crate::config::AuthConfig;
use crate::error::AuthError;

const TICKET_FILE: &str = "close-relay-ticket.json";
/// The server admits a request only within 300 s of its request_time (plus
/// 30 s of skew): a fee request older than this that the server does not
/// hold never will be.
const RELAY_FEE_UNADMITTABLE_AFTER_SECONDS: u64 = 600;
const MAX_BODY_BYTES: usize = 65_536;

/// A relay ticket of the current note (`close-relay-ticket.json`).
#[derive(Clone, Serialize, Deserialize)]
pub(crate) struct RelayTicket {
    version: u8,
    note_id: u32,
    /// The ticket secret, `0x` and 64 hex digits; sent only with the close.
    secret: String,
    fee_units: u128,
    /// The nullifier of the state the fee request is made at.
    request_nullifier: Felt252,
    /// Set once the fee request is journaled.
    client_request_id: Option<String>,
    /// "pending" until the fee request's successor is installed, then "paid".
    status: String,
}

impl RelayTicket {
    fn secret_bytes(&self) -> Result<[u8; 32], AuthError> {
        let bytes = self
            .secret
            .strip_prefix("0x")
            .and_then(|hex_digits| hex::decode(hex_digits).ok())
            .ok_or_else(storage_error)?;
        bytes.try_into().map_err(|_| storage_error())
    }

    fn public(&self) -> Value {
        let ticket_hash = self
            .secret_bytes()
            .map(|secret| {
                format!(
                    "0x{}",
                    hex::encode(zkapi_types::wire::close_relay_ticket_hash(&secret))
                )
            })
            .unwrap_or_default();
        json!({
            "status": self.status,
            "note_id": self.note_id,
            "fee_units": self.fee_units.to_string(),
            "ticket_hash": ticket_hash,
        })
    }
}

fn storage_error() -> AuthError {
    AuthError::Wallet(
        "close relay ticket storage is unavailable or invalid; preserve its file".into(),
    )
}

fn load_ticket(config: &AuthConfig) -> Result<Option<RelayTicket>, AuthError> {
    let path = config.state_dir.join(TICKET_FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| storage_error()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(storage_error()),
    }
}

fn save_ticket(config: &AuthConfig, ticket: &RelayTicket) -> Result<(), AuthError> {
    crate::oa_withdrawal::write_private_durably(
        &config.state_dir.join(TICKET_FILE),
        &serde_json::to_vec(ticket).map_err(|_| storage_error())?,
    )
}

/// Whether `payload` is a close-relay fee authorization (a pending request a
/// native wallet holds besides its leases).
pub(crate) fn is_fee_payload(payload: &str) -> bool {
    serde_json::from_str::<CloseRelayFeeAuthorization>(payload)
        .is_ok_and(|authorization| authorization.mode == zkapi_types::wire::CLOSE_RELAY_FEE_MODE)
}

/// A bounded JSON body from the protocol server.
async fn read_body(mut response: reqwest::Response) -> Result<Vec<u8>, AuthError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AuthError::Wallet("protocol server request failed".into()))?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err(AuthError::Wallet(
                "protocol server response is too large".into(),
            ));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// A protocol server refusal, with its error code kept for the caller.
fn server_refusal(status: reqwest::StatusCode, body: &[u8]) -> AuthError {
    let message = serde_json::from_slice::<ErrorResponse>(body)
        .map(|error| format!("{}: {}", error.error_code, error.error_message))
        .unwrap_or_else(|_| format!("HTTP {status}"));
    AuthError::UpstreamResponse {
        status: axum::http::StatusCode::from_u16(status.as_u16())
            .unwrap_or(axum::http::StatusCode::BAD_GATEWAY),
        message,
    }
}

async fn server(
    config: &AuthConfig,
    method: reqwest::Method,
    path: &str,
    body: Option<Value>,
) -> Result<(reqwest::StatusCode, Vec<u8>), AuthError> {
    let mut request = zkapi_client::testnet_auth::request(
        config.chain_id,
        &config.protocol_server_url,
        method,
        format!("{}{path}", config.protocol_server_url.trim_end_matches('/')),
    )?;
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request
        .send()
        .await
        .map_err(|_| AuthError::Wallet("protocol server request failed".into()))?;
    let response = zkapi_client::testnet_auth::check_response(response)?;
    let status = response.status();
    Ok((status, read_body(response).await?))
}

async fn relay_terms(config: &AuthConfig) -> Result<CloseRelayTermsResponse, AuthError> {
    let (status, body) = server(
        config,
        reqwest::Method::GET,
        "/v2/withdraw/relay/terms",
        None,
    )
    .await?;
    if !status.is_success() {
        return Err(server_refusal(status, &body));
    }
    serde_json::from_slice(&body).map_err(|error| AuthError::Serialization(error.to_string()))
}

impl AuthService {
    /// The protocol server's relay terms (`{"enabled": false}` without a
    /// relay), read through the companion's transport.
    pub async fn close_relay_terms(&self) -> Result<Value, AuthError> {
        let terms = relay_terms(&self.config).await?;
        serde_json::to_value(terms).map_err(|error| AuthError::Serialization(error.to_string()))
    }

    /// Pay the relay fee at the current state, or resume a fee request
    /// already journaled. Idempotent: a paid ticket of the current note is
    /// returned as it is. Refused once the withdrawal is reserved (the fee
    /// is paid before the close is prepared), while another request is
    /// pending, and when the server does not relay.
    pub async fn close_relay_fee(&self) -> Result<Value, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let indexer = self.indexer.clone();
        // The live lease (if any) stays as it is: a pending lease request
        // refuses the fee below until it settles.
        let _lease = self.direct_lease.lock().await;
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            let state = wallet.state().ok_or(AuthError::NoActiveNote)?.clone();
            let runtime = current_thread_runtime()?;
            let existing = load_ticket(&config)?.filter(|ticket| ticket.note_id == state.note_id);
            if let Some(ticket) = existing.as_ref().filter(|ticket| ticket.status == "paid") {
                return Ok(ticket.public());
            }
            let current = wallet.current_nullifier().ok_or(AuthError::NoActiveNote)?;
            let mut ticket = match existing {
                // Journaled: resend the very request (the server answers an
                // exact retry with its signed successor).
                Some(ticket)
                    if ticket.client_request_id.is_some()
                        && wallet
                            .get_pending_journal()?
                            .is_some_and(|journal| {
                                Some(journal.client_request_id) == ticket.client_request_id
                            }) =>
                {
                    ticket
                }
                // Installed meanwhile (by recovery): the state moved to the
                // successor of the fee request.
                Some(mut ticket)
                    if state.current_anchor
                        == zkapi_core::v2::next_anchor(&ticket.request_nullifier) =>
                {
                    ticket.status = "paid".into();
                    save_ticket(&config, &ticket)?;
                    return Ok(ticket.public());
                }
                // Not journaled, or set aside: a fresh ticket below.
                _ => {
                    if crate::oa_withdrawal::load(&config)?
                        .is_some_and(|record| !record.complete)
                    {
                        return Err(AuthError::InvalidInput(
                            "the relay fee is paid before the withdrawal is prepared; this withdrawal is already reserved, so submit its close yourself".into(),
                        ));
                    }
                    if wallet.has_pending_request() {
                        return Err(AuthError::PendingSettlement);
                    }
                    wallet.check_request_allowed()?;
                    let terms = runtime.block_on(relay_terms(&config))?;
                    let fee_units = match (terms.enabled, terms.fee_units.as_deref()) {
                        (true, Some(fee)) => fee
                            .parse::<u128>()
                            .ok()
                            .filter(|fee| *fee > 0)
                            .ok_or_else(|| {
                                AuthError::Wallet("the relay's terms name no valid fee".into())
                            })?,
                        _ => {
                            return Err(AuthError::InvalidInput(
                                "this protocol server does not relay closes; submit the close yourself".into(),
                            ))
                        }
                    };
                    if state.current_balance < fee_units {
                        return Err(AuthError::InsufficientBalance);
                    }
                    let ticket = RelayTicket {
                        version: 1,
                        note_id: state.note_id,
                        secret: format!(
                            "0x{}",
                            hex::encode(zkapi_proof::compact::random_scalar().0)
                        ),
                        fee_units,
                        request_nullifier: current,
                        client_request_id: None,
                        status: "pending".into(),
                    };
                    // The secret is durable before its hash can leave.
                    save_ticket(&config, &ticket)?;
                    ticket
                }
            };
            let request = if ticket.client_request_id.is_some() {
                let request = wallet
                    .pending_api_request()?
                    .ok_or(AuthError::PendingRequest)?;
                // The server admits an exact retry only while its
                // request_time is fresh. An older one is installed if the
                // server holds it, and set aside if it never will.
                if super::now_seconds()
                    > request
                        .public_inputs
                        .request_time
                        .saturating_add(RELAY_FEE_UNADMITTABLE_AFTER_SECONDS)
                {
                    let recovery = runtime.block_on(super::nullifier_recovery(
                        &config,
                        &request.public_inputs.request_nullifier,
                    ))?;
                    if let Some(response) = recovery.request_response {
                        wallet.complete_pending_response(&response)?;
                        ticket.status = "paid".into();
                        save_ticket(&config, &ticket)?;
                        return Ok(ticket.public());
                    }
                    if recovery.status == "not_found" && recovery.nullifier_status == "unknown" {
                        wallet.archive_pending_request("discarded_expired_unaccepted")?;
                        std::fs::remove_file(config.state_dir.join(TICKET_FILE))
                            .map_err(|_| storage_error())?;
                        return Err(AuthError::Wallet(
                            "the relay fee request was never admitted and is now too old; pay the fee again".into(),
                        ));
                    }
                    return Err(AuthError::PendingSettlement);
                }
                request
            } else {
                let payload = serde_json::to_string(&CloseRelayFeeAuthorization::new(
                    ticket.fee_units,
                    &ticket.secret_bytes()?,
                ))
                .map_err(|error| AuthError::Serialization(error.to_string()))?;
                let note_id = state.note_id;
                let (root, siblings) =
                    runtime.block_on(async { indexer.root_and_path(note_id).await })?;
                let bound = state_solvency_bound(state.bound_at_state, ticket.fee_units)?;
                let request = wallet.prepare_request_with_bound(
                    &payload,
                    compute_payload_hash(payload.as_bytes()),
                    root,
                    siblings,
                    bound,
                )?;
                ticket.client_request_id = Some(request.client_request_id.clone());
                save_ticket(&config, &ticket)?;
                request
            };
            let (status, body) = runtime.block_on(server(
                &config,
                reqwest::Method::POST,
                "/v2/withdraw/relay/fee",
                Some(serde_json::to_value(&request).map_err(|error| {
                    AuthError::Serialization(error.to_string())
                })?),
            ))?;
            if !status.is_success() {
                let error = serde_json::from_slice::<ErrorResponse>(&body).ok();
                if error.as_ref().is_some_and(|error| {
                    error.error_code == "stale_root" || error.error_code == "relay_fee_changed"
                }) {
                    // Never admitted: set aside (a later receipt still
                    // installs from the archive) and start over next time.
                    wallet.archive_pending_request(zkapi_client::exit_policy::disposition::DISCARDED_STALE_ROOT)?;
                    std::fs::remove_file(config.state_dir.join(TICKET_FILE))
                        .map_err(|_| storage_error())?;
                }
                return Err(server_refusal(status, &body));
            }
            let response: RequestResponseV2 = serde_json::from_slice(&body)
                .map_err(|error| AuthError::Serialization(error.to_string()))?;
            if response.charge_applied != ticket.fee_units {
                tracing::warn!(
                    charged = response.charge_applied,
                    fee = ticket.fee_units,
                    "the relay fee request was charged another amount than its terms"
                );
            }
            wallet.complete_pending_response(&response)?;
            ticket.status = "paid".into();
            save_ticket(&config, &ticket)?;
            Ok(ticket.public())
        })
        .await
    }

    /// Hand the reserved cooperative close to the relay with the paid
    /// ticket. Idempotent on the server: the same close returns its status.
    pub async fn close_relay_submit(&self) -> Result<Value, AuthError> {
        let (ticket, plan) = self.relay_close().await?;
        let submission = CloseRelaySubmissionV2C {
            public_inputs: plan.public_inputs,
            proof: plan.proof,
            ticket_secret: ticket.secret.clone(),
        };
        let (status, body) = server(
            &self.config,
            reqwest::Method::POST,
            "/v2/withdraw/relay",
            Some(
                serde_json::to_value(&submission)
                    .map_err(|error| AuthError::Serialization(error.to_string()))?,
            ),
        )
        .await?;
        if !status.is_success() {
            return Err(server_refusal(status, &body));
        }
        let relayed: CloseRelayStatusResponse = serde_json::from_slice(&body)
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        serde_json::to_value(relayed).map_err(|error| AuthError::Serialization(error.to_string()))
    }

    /// The relay's view of the reserved close: its status response, or
    /// `{"status":"unknown"}` when the relay holds none.
    pub async fn close_relay_status(&self) -> Result<Value, AuthError> {
        let (_, plan) = self.relay_close().await?;
        let (status, body) = server(
            &self.config,
            reqwest::Method::GET,
            &format!(
                "/v2/withdraw/relay/{}",
                plan.public_inputs.withdrawal_nullifier
            ),
            None,
        )
        .await?;
        if status == reqwest::StatusCode::NOT_FOUND
            && serde_json::from_slice::<Value>(&body)
                .is_ok_and(|value| value["status"] == "not_found")
        {
            return Ok(json!({"status": "unknown"}));
        }
        if !status.is_success() {
            return Err(server_refusal(status, &body));
        }
        let relayed: CloseRelayStatusResponse = serde_json::from_slice(&body)
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        serde_json::to_value(relayed).map_err(|error| AuthError::Serialization(error.to_string()))
    }

    /// The paid ticket and the reserved close of its note.
    async fn relay_close(&self) -> Result<(RelayTicket, super::WithdrawalPlan), AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|_| AuthError::Wallet("wallet lock unavailable".into()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let record = crate::oa_withdrawal::load(&config)?.ok_or_else(|| {
                AuthError::InvalidInput("no withdrawal is reserved; prepare it first".into())
            })?;
            let plan = record.plan.clone().ok_or_else(|| {
                AuthError::InvalidInput("the reserved withdrawal has no close yet".into())
            })?;
            crate::oa_withdrawal::validate_plan(&record, &plan)?;
            let ticket = load_ticket(&config)?
                .filter(|ticket| {
                    ticket.status == "paid" && ticket.note_id == record.snapshot.note_id
                })
                .ok_or_else(|| {
                    AuthError::InvalidInput("no relay fee is paid for this note".into())
                })?;
            Ok((ticket, plan))
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only a strict fee authorization counts as the relay's pending
    /// request; a lease payload or anything else does not.
    #[test]
    fn fee_payloads_are_told_from_leases() {
        let fee = serde_json::to_string(&CloseRelayFeeAuthorization::new(5, &[1; 32])).unwrap();
        assert!(is_fee_payload(&fee));
        assert!(!is_fee_payload(
            r#"{"mode":"openrouter_ephemeral_lease","version":1}"#
        ));
        assert!(!is_fee_payload(&fee.replace("}", ",\"x\":1}")));
        assert!(!is_fee_payload("{}"));
    }
}
