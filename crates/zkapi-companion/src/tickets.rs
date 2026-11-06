//! Fixed-price tickets (`POST /oa/v1/ticket`).
//!
//! A ticket buys one OA-org runtime key with a tier's allowance and lifetime
//! at the tier's set price. The purchase proof binds the tier's terms, the
//! frozen quote and the price in gwei; the server settles the request at
//! exactly that price and returns the signed successor with the key, which is
//! verified and installed before the key is handed out. The wallet is free for
//! the next purchase at once, so keys from several tickets can serve requests
//! at the same time. Only the purchase itself (proof, POST, install) holds the
//! wallet; inference never does.

use super::*;
use zkapi_types::wire::{
    TicketAuthorization, TicketCatalogResponse, TicketTermsV1, TICKET_MODE, TICKET_SETTLEMENT_TYPE,
};

/// How often one purchase re-sends or re-proves after a recoverable refusal.
const TICKET_PURCHASE_ATTEMPTS: usize = 4;
/// The paid tickets this wallet holds, with their keys (mode 0600).
const INVENTORY_FILE: &str = "ticket-inventory.json";
const INVENTORY_VERSION: u16 = 2;
/// A ticket is handed out only with at least this much lifetime left.
const MIN_HANDOUT_LIFETIME_SECONDS: u64 = 90;
/// A consumed or expired claim is remembered this long after the key's
/// expiry, so a retried purchase ID never buys again.
const TOMBSTONE_SECONDS: u64 = 86_400;

/// A ticket handed to a caller: its runtime key and what was paid for it.
/// Debug never prints the key.
#[derive(Clone, Serialize)]
pub struct TicketPurchase {
    pub client_request_id: String,
    /// The caller's idempotency key this ticket is claimed for.
    pub purchase_id: String,
    pub tier: TicketTermsV1,
    /// The fixed charge, in gwei, of the installed successor.
    pub price_units: u64,
    pub api_key: String,
    pub base_url: String,
    pub expires_at: u64,
    /// When the ticket was bought (and its successor installed).
    pub bought_at: u64,
    pub verified: bool,
    pub verification_status: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_detail: Option<String>,
}

impl std::fmt::Debug for TicketPurchase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TicketPurchase")
            .field("client_request_id", &self.client_request_id)
            .field("purchase_id", &self.purchase_id)
            .field("tier", &self.tier.tier_id)
            .field("price_units", &self.price_units)
            .field("api_key", &"[redacted]")
            .field("expires_at", &self.expires_at)
            .field("verified", &self.verified)
            .finish()
    }
}

/// Where a paid ticket is in its local life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    /// Stored from a checked purchase reply before its successor is
    /// installed. Never handed out: it becomes ready only once the wallet
    /// verified and installed the successor (from the pending journal, or
    /// found it installed in the request archive after a crash).
    Provisional,
    /// The successor is installed: the key may be handed out.
    Ready,
    /// Its successor failed the wallet's checks (S1–S6 or the ticket's
    /// fixed price and terms): never handed out.
    Refused,
    /// Its key failed OA verification: never handed out.
    Rejected,
    /// Used for a request (or expired while claimed). The key is erased;
    /// the claim is kept so that its purchase ID never buys again.
    Consumed,
}

/// A paid ticket in the local inventory, stored before the purchase's
/// successor is installed (which removes the pending journal), so neither a
/// crash nor a lost local reply loses a paid key; and handed out only once
/// it is ready.
#[derive(Clone, Serialize, Deserialize)]
struct InventoryEntry {
    client_request_id: String,
    request_nullifier: Felt252,
    tier: TicketTermsV1,
    price_units: u64,
    api_key: String,
    base_url: String,
    expires_at: u64,
    evidence: OaKeyVerificationEvidence,
    bought_at: u64,
    phase: Phase,
    #[serde(default)]
    claimed_by: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Inventory {
    version: u16,
    entries: Vec<InventoryEntry>,
}

impl Default for Inventory {
    fn default() -> Self {
        Self {
            version: INVENTORY_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Inventory {
    /// Expired keys are erased. An unclaimed one is forgotten; a claimed
    /// one stays as a consumed claim for a day.
    fn prune(&mut self, now: u64) {
        for entry in &mut self.entries {
            if entry.expires_at <= now && entry.phase != Phase::Consumed {
                entry.phase = Phase::Consumed;
                entry.api_key.clear();
            }
        }
        self.entries.retain(|entry| {
            entry.expires_at > now
                || (entry.claimed_by.is_some()
                    && entry.expires_at.saturating_add(TOMBSTONE_SECONDS) > now)
        });
    }
}

/// Non-secret inventory metadata (`GET /oa/v1/tickets`).
#[derive(Debug, Clone, Serialize)]
pub struct InventorySummary {
    pub client_request_id: String,
    pub tier: TicketTermsV1,
    pub expires_at: u64,
    pub phase: &'static str,
    pub claimed: bool,
}

fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Provisional => "provisional",
        Phase::Ready => "ready",
        Phase::Refused => "refused",
        Phase::Rejected => "rejected",
        Phase::Consumed => "consumed",
    }
}

fn inventory_path(state_dir: &Path) -> PathBuf {
    state_dir.join(INVENTORY_FILE)
}

fn read_inventory(state_dir: &Path) -> Result<Inventory, AuthError> {
    match std::fs::read(inventory_path(state_dir)) {
        Ok(bytes) => {
            let inventory: Inventory = serde_json::from_slice(&bytes).map_err(|_| {
                AuthError::Wallet(
                    "the ticket inventory cannot be read; it is left unchanged".into(),
                )
            })?;
            if inventory.version != INVENTORY_VERSION {
                return Err(AuthError::Wallet(
                    "the ticket inventory has an unsupported version".into(),
                ));
            }
            Ok(inventory)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Inventory::default()),
        Err(error) => Err(AuthError::Wallet(error.to_string())),
    }
}

fn write_inventory(state_dir: &Path, inventory: &Inventory) -> Result<(), AuthError> {
    let bytes = serde_json::to_vec(inventory)
        .map_err(|error| AuthError::Serialization(error.to_string()))?;
    crate::oa_withdrawal::write_private_durably(&inventory_path(state_dir), &bytes)
}

fn valid_purchase_id(purchase_id: &str) -> bool {
    (8..=128).contains(&purchase_id.len())
        && purchase_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// What a claim found in the inventory.
enum Claim {
    Ticket(InventoryEntry),
    /// The ticket claimed for this purchase ID is unusable.
    Unusable(&'static str),
    None,
}

/// Claim for `purchase_id`: the ticket it already holds, or an unclaimed,
/// ready ticket of exactly `terms`.
fn claim(inventory: &mut Inventory, terms: &TicketTermsV1, purchase_id: &str, now: u64) -> Claim {
    inventory.prune(now);
    if let Some(entry) = inventory
        .entries
        .iter()
        .find(|entry| entry.claimed_by.as_deref() == Some(purchase_id))
    {
        return match entry.phase {
            Phase::Ready => Claim::Ticket(entry.clone()),
            Phase::Consumed => Claim::Unusable("the ticket of this purchase was used or expired"),
            Phase::Rejected => Claim::Unusable("the ticket's key failed verification"),
            Phase::Refused | Phase::Provisional => {
                Claim::Unusable("the ticket's settlement was not installed")
            }
        };
    }
    match inventory.entries.iter_mut().find(|entry| {
        entry.claimed_by.is_none()
            && entry.phase == Phase::Ready
            && entry.tier == *terms
            && entry.expires_at > now.saturating_add(MIN_HANDOUT_LIFETIME_SECONDS)
    }) {
        Some(entry) => {
            entry.claimed_by = Some(purchase_id.to_string());
            Claim::Ticket(entry.clone())
        }
        None => Claim::None,
    }
}

#[derive(Deserialize)]
struct TicketPurchaseResponse {
    #[serde(flatten)]
    lease: OpenRouterLeaseResponse,
    key_source: String,
    #[serde(default)]
    verification: Option<OaKeyVerificationEvidence>,
    billing_quote: Option<crate::oa_native::Quote>,
    ticket: Option<TicketTermsV1>,
    request_response: Option<RequestResponseV2>,
}

/// The ticket authorization of a saved request, or None for any other mode.
pub(crate) fn saved_ticket(payload: &str) -> Option<TicketAuthorization> {
    let mut value: Value = serde_json::from_str(payload).ok()?;
    if value.get("mode").and_then(Value::as_str) != Some(TICKET_MODE) {
        return None;
    }
    value.as_object_mut()?.remove("billing_quote");
    serde_json::from_value(value).ok()
}

/// The purchase payload: the terms, the price at `quote` and the quote.
pub(crate) fn ticket_payload(
    terms: &TicketTermsV1,
    quote: &crate::oa_native::Quote,
) -> Result<(String, u64), AuthError> {
    let price_units = u64::try_from(quote.charge_units(u128::from(terms.price_micro_usd))?)
        .map_err(|_| AuthError::Wallet("ticket price overflows".into()))?;
    let mut payload = serde_json::to_value(TicketAuthorization {
        mode: TICKET_MODE.into(),
        version: 1,
        ticket: terms.clone(),
        price_units,
    })
    .map_err(|error| AuthError::Serialization(error.to_string()))?;
    payload["billing_quote"] =
        serde_json::to_value(quote).map_err(|error| AuthError::Serialization(error.to_string()))?;
    Ok((payload.to_string(), price_units))
}

/// The checks of a purchase response before anything is installed: the
/// key is for this request and its terms, from the OA org, at the bound
/// quote, and the signed successor charges exactly the ticket's price and
/// echoes the request's terms. The cryptographic successor checks (S1–S6)
/// follow in the wallet's install.
fn check_purchase(
    config: &AuthConfig,
    request: &ApiRequestV2,
    ticket: &TicketAuthorization,
    response: &TicketPurchaseResponse,
) -> Result<(), AuthError> {
    let mismatch = |detail: &str| Err(AuthError::KeyVerification(format!("ticket {detail}")));
    let quote = crate::oa_native::saved_quote(config, &request.payload)?;
    if response.lease.client_request_id != request.client_request_id
        || response.ticket.as_ref() != Some(&ticket.ticket)
        || response.billing_quote != quote
    {
        return mismatch("response is for another request, tier or quote");
    }
    if response.key_source != "oa_org" || response.verification.is_none() {
        return mismatch("key is not an OA org key with verification evidence");
    }
    let expected_limit = ticket.ticket.credit_limit_micro_usd as f64 / 1_000_000.0;
    if response.lease.api_key.is_empty()
        || response.lease.spending_limit_usd != expected_limit
        || response.lease.expires_at <= now_seconds()
        || response.lease.expires_at
            > now_seconds().saturating_add(ticket.ticket.duration_seconds + 60)
    {
        return mismatch("key has another allowance or lifetime");
    }
    if !matches_trusted_url(
        &response.lease.openrouter_api_base,
        &config.openrouter_inference_base,
    ) {
        return mismatch("key's inference origin is not the trusted origin");
    }
    let successor = response.request_response.as_ref().ok_or_else(|| {
        AuthError::KeyVerification("ticket purchase omitted its successor".into())
    })?;
    if successor.client_request_id != request.client_request_id
        || successor.request_nullifier != request.public_inputs.request_nullifier
        || successor.charge_applied != u128::from(ticket.price_units)
    {
        return mismatch("successor does not charge exactly the ticket's price");
    }
    let settled: Value = serde_json::from_str(&successor.response_payload)
        .map_err(|_| AuthError::KeyVerification("invalid ticket settlement payload".into()))?;
    if settled.get("type").and_then(Value::as_str) != Some(TICKET_SETTLEMENT_TYPE)
        || settled.get("ticket") != serde_json::to_value(&ticket.ticket).ok().as_ref()
        || settled.get("price_units").and_then(Value::as_str)
            != Some(ticket.price_units.to_string().as_str())
    {
        return mismatch("settlement does not repeat the bought terms");
    }
    Ok(())
}

impl AuthService {
    /// The tiers the protocol server sells (`GET /v2/tickets`).
    pub async fn ticket_catalog(&self) -> Result<TicketCatalogResponse, AuthError> {
        let response = zkapi_client::testnet_auth::request(
            self.config.chain_id,
            &self.config.protocol_server_url,
            reqwest::Method::GET,
            format!(
                "{}/v2/tickets",
                self.config.protocol_server_url.trim_end_matches('/')
            ),
        )?
        .send()
        .await
        .map_err(|error| AuthError::Wallet(error.to_string()))?;
        let response = zkapi_client::testnet_auth::check_response(response)?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(AuthError::TicketsUnavailable);
        }
        if !response.status().is_success() {
            return Err(AuthError::Wallet(format!(
                "ticket catalog returned HTTP {}",
                response.status()
            )));
        }
        let catalog: TicketCatalogResponse = response
            .json()
            .await
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        if catalog.version != 1 || catalog.key_source != "oa_org" || catalog.tiers.is_empty() {
            return Err(AuthError::TicketsUnavailable);
        }
        Ok(catalog)
    }

    /// Hand out a ticket of exactly `terms` for `purchase_id`, buying one
    /// only when the inventory holds no ready one. Idempotent per purchase
    /// ID: a retry after a lost reply returns the same ticket and never buys
    /// again. A ticket purchase whose server reply was lost is finished
    /// first, and every stored ticket is handed out only after its successor
    /// is verified and installed. Terms that are no longer on sale fail with
    /// `ticket_terms_changed`.
    pub async fn buy_ticket(
        &self,
        terms: &TicketTermsV1,
        purchase_id: &str,
    ) -> Result<TicketPurchase, AuthError> {
        if !valid_purchase_id(purchase_id) {
            return Err(AuthError::InvalidInput(
                "purchase_id must be 8 to 128 characters of [A-Za-z0-9._:-]".into(),
            ));
        }
        self.require_ticket_mode()?;
        let _purchase = self.ticket_mutex.lock().await;
        for _ in 0..TICKET_PURCHASE_ATTEMPTS {
            self.settle_stored_tickets().await?;
            match self.claim_inventory(terms, purchase_id).await? {
                Claim::Ticket(entry) => return self.hand_out(entry, purchase_id).await,
                Claim::Unusable(reason) => {
                    return Err(AuthError::KeyVerification(reason.to_string()))
                }
                Claim::None => {}
            }
            self.ensure_scheme_agreement().await?;
            self.oa_check_spending().await?;
            self.ticket_purchase(Some(terms)).await?;
        }
        Err(AuthError::LeasePending(
            "no ticket of this tier could be handed out".into(),
        ))
    }

    /// Finish a pending ticket purchase, if the journal holds one, into the
    /// inventory. Nothing new is bought and no paid key is dropped.
    pub(crate) async fn finish_pending_ticket(&self) -> Result<bool, AuthError> {
        self.require_ticket_mode()?;
        let _purchase = self.ticket_mutex.lock().await;
        let finished = self.ticket_purchase(None).await?;
        self.settle_stored_tickets().await?;
        Ok(finished)
    }

    /// Bring every stored ticket to a settled phase before any claim: finish
    /// a pending ticket purchase (its replayed reply is checked again and its
    /// successor installed), then promote a provisional ticket only when the
    /// request archive shows its successor installed. A provisional ticket
    /// whose request was set aside otherwise is refused, never handed out,
    /// and no further ticket is bought until it is resolved.
    async fn settle_stored_tickets(&self) -> Result<(), AuthError> {
        if self.pending_ticket().await? {
            self.ticket_purchase(None).await?;
        }
        let archive_dir = self.config.state_dir.join("request_archive");
        let unresolved = self
            .update_inventory(move |inventory| {
                let mut unresolved = false;
                for entry in &mut inventory.entries {
                    if entry.phase != Phase::Provisional {
                        continue;
                    }
                    let records = zkapi_client::journal::archived_requests(
                        &archive_dir,
                        &entry.request_nullifier,
                    )
                    .unwrap_or_default();
                    let mine = records.iter().filter(|record| {
                        record.journal.client_request_id == entry.client_request_id
                    });
                    let mut installed = false;
                    let mut set_aside = false;
                    for record in mine {
                        installed |= record.disposition == "installed";
                        set_aside |= record.disposition != "installed";
                    }
                    if installed {
                        entry.phase = Phase::Ready;
                    } else if set_aside {
                        entry.phase = Phase::Refused;
                        entry.api_key.clear();
                        unresolved = true;
                    } else {
                        unresolved = true;
                    }
                }
                Ok(unresolved)
            })
            .await?;
        if unresolved {
            return Err(AuthError::LeasePending(
                "a bought ticket's settlement was not installed; recover the wallet before buying again".into(),
            ));
        }
        Ok(())
    }

    /// Return a handed-out ticket after its request. By default a ticket
    /// serves one request: `consume` erases its key (keeping the claim, so
    /// its purchase ID never buys again). Without `consume` it returns to
    /// the inventory for a later request of the same terms.
    pub async fn release_ticket(
        &self,
        client_request_id: &str,
        purchase_id: &str,
        consume: bool,
    ) -> Result<(), AuthError> {
        let _purchase = self.ticket_mutex.lock().await;
        let client_request_id = client_request_id.to_string();
        let purchase_id = purchase_id.to_string();
        self.update_inventory(move |inventory| {
            let entry = inventory
                .entries
                .iter_mut()
                .find(|entry| {
                    entry.client_request_id == client_request_id
                        && entry.claimed_by.as_deref() == Some(purchase_id.as_str())
                })
                .ok_or_else(|| {
                    AuthError::InvalidInput("no ticket is claimed for this purchase".into())
                })?;
            if consume || entry.phase != Phase::Ready {
                entry.phase = Phase::Consumed;
                entry.api_key.clear();
            } else {
                entry.claimed_by = None;
            }
            Ok(())
        })
        .await
    }

    /// Return the claims of an earlier run of the local client, which no
    /// request of its uses any more: a ready ticket that was handed out but
    /// whose request never released it goes back to the inventory. The
    /// client calls this once at startup, before its first claim.
    pub async fn release_all_tickets(&self) -> Result<usize, AuthError> {
        let _purchase = self.ticket_mutex.lock().await;
        self.update_inventory(|inventory| {
            let mut released = 0;
            for entry in &mut inventory.entries {
                if entry.phase == Phase::Ready && entry.claimed_by.take().is_some() {
                    released += 1;
                }
            }
            Ok(released)
        })
        .await
    }

    pub async fn ticket_inventory(&self) -> Result<Vec<InventorySummary>, AuthError> {
        let now = now_seconds();
        self.update_inventory(move |inventory| {
            inventory.prune(now);
            Ok(inventory
                .entries
                .iter()
                .map(|entry| InventorySummary {
                    client_request_id: entry.client_request_id.clone(),
                    tier: entry.tier.clone(),
                    expires_at: entry.expires_at,
                    phase: phase_name(entry.phase),
                    claimed: entry.claimed_by.is_some(),
                })
                .collect())
        })
        .await
    }

    fn require_ticket_mode(&self) -> Result<(), AuthError> {
        if self.config.request_mode != RequestMode::DirectOpenrouter
            || self.config.billing_asset != "native_eth"
        {
            return Err(AuthError::KeyVerification(
                "tickets need native ETH direct mode".into(),
            ));
        }
        Ok(())
    }

    /// Read, change and durably write the inventory under the wallet locks.
    async fn update_inventory<R: Send + 'static>(
        &self,
        change: impl FnOnce(&mut Inventory) -> Result<R, AuthError> + Send + 'static,
    ) -> Result<R, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut inventory = read_inventory(&config.state_dir)?;
            let result = change(&mut inventory)?;
            write_inventory(&config.state_dir, &inventory)?;
            Ok(result)
        })
        .await
    }

    async fn claim_inventory(
        &self,
        terms: &TicketTermsV1,
        purchase_id: &str,
    ) -> Result<Claim, AuthError> {
        let purchase_id = purchase_id.to_string();
        let terms = terms.clone();
        let now = now_seconds();
        self.update_inventory(move |inventory| Ok(claim(inventory, &terms, &purchase_id, now)))
            .await
    }

    /// Verify a claimed ticket's key with the OA verifier and return it. A
    /// key that fails verification is marked and never handed out again; a
    /// verifier outage only marks it unverified, as for a metered OA key.
    async fn hand_out(
        &self,
        entry: InventoryEntry,
        purchase_id: &str,
    ) -> Result<TicketPurchase, AuthError> {
        match self
            .verify_oa_key(&entry.api_key, entry.expires_at, &entry.evidence)
            .await
        {
            Ok(outcome) => Ok(TicketPurchase {
                client_request_id: entry.client_request_id,
                purchase_id: purchase_id.to_string(),
                tier: entry.tier,
                price_units: entry.price_units,
                api_key: entry.api_key,
                base_url: entry.base_url,
                expires_at: entry.expires_at,
                bought_at: entry.bought_at,
                verified: outcome.verified,
                verification_status: if outcome.verified {
                    "verified"
                } else {
                    "verifier-unavailable"
                },
                verification_detail: outcome.detail.map(str::to_string),
            }),
            Err(error) => {
                let id = entry.client_request_id.clone();
                self.update_inventory(move |inventory| {
                    for entry in &mut inventory.entries {
                        if entry.client_request_id == id {
                            entry.phase = Phase::Rejected;
                            entry.api_key.clear();
                        }
                    }
                    Ok(())
                })
                .await?;
                Err(error)
            }
        }
    }

    /// One purchase into the inventory: the pending ticket request if the
    /// journal holds one, else (with `tier_id`) a new one. False when nothing
    /// was bought. The caller holds the purchase lock: purchases are
    /// sequential (each spends the state the previous one installed), while
    /// inference with bought keys is not serialized at all.
    async fn ticket_purchase(&self, wanted: Option<&TicketTermsV1>) -> Result<bool, AuthError> {
        let mut catalog = None;
        let mut refreshed_quote = false;
        let mut cleared_stale = false;
        for _ in 0..TICKET_PURCHASE_ATTEMPTS {
            let pending = self.pending_request_payload().await?;
            let terms = match (pending.as_deref().map(saved_ticket), wanted) {
                (Some(Some(_)), _) => None,
                (Some(None), _) => {
                    // A metered lease holds this state. Retire it (after its
                    // in-flight requests) so that its successor is installed.
                    if wanted.is_none() {
                        return Ok(false);
                    }
                    self.settle_metered_for_withdrawal().await?;
                    continue;
                }
                (None, None) => return Ok(false),
                (None, Some(wanted)) => {
                    if catalog.is_none() {
                        catalog = Some(self.ticket_catalog().await?);
                    }
                    let on_sale = catalog.as_ref().and_then(|catalog| {
                        catalog
                            .tiers
                            .iter()
                            .find(|tier| tier.tier_id == wanted.tier_id)
                    });
                    match on_sale {
                        Some(on_sale) if on_sale == wanted => Some(wanted.clone()),
                        Some(_) => return Err(AuthError::TicketTermsChanged(wanted.tier_id)),
                        None => return Err(AuthError::TicketTierUnavailable(wanted.tier_id)),
                    }
                }
            };
            let request = self.prepare_ticket_request(terms).await?;
            let ticket = saved_ticket(&request.payload)
                .ok_or_else(|| AuthError::Wallet("the saved request is not a ticket".into()))?;
            let response = zkapi_client::testnet_auth::request(
                self.config.chain_id,
                &self.config.protocol_server_url,
                reqwest::Method::POST,
                format!(
                    "{}/v2/openrouter/leases",
                    self.config.protocol_server_url.trim_end_matches('/')
                ),
            )?
            .json(&request)
            .send()
            .await
            .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let response = zkapi_client::testnet_auth::check_response(response)?;
            let status = response.status();
            let body = response
                .text()
                .await
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            if status.is_success() {
                self.complete_ticket_purchase(&request, &ticket, &body)
                    .await?;
                return Ok(true);
            }
            let Ok(error) = serde_json::from_str::<ErrorResponse>(&body) else {
                return Err(AuthError::Wallet(format!("HTTP {status}")));
            };
            match error.error_code.as_str() {
                "native_quote_expired" | "native_quote_superseded" if !refreshed_quote => {
                    // Retired only on the server's acknowledgement that it
                    // never accepted the request.
                    self.refresh_unaccepted_native_request(request).await?;
                    refreshed_quote = true;
                }
                "stale_root" | "ticket_terms_mismatch" if !cleared_stale => {
                    // Set aside only when the server holds no record of the
                    // nullifier; then prove again from fresh terms.
                    if error.error_code == "stale_root"
                        && self.vault_current_root().await? == request.public_inputs.active_root
                    {
                        return Err(AuthError::LeasePending(format!(
                            "ticket request {} was refused as stale while the vault still has its root; the saved request is preserved",
                            request.client_request_id
                        )));
                    }
                    self.clear_unadmitted_request(&request).await?;
                    cleared_stale = true;
                    catalog = None;
                }
                // Settled at zero (never issued), or paid but its key
                // lapsed: only the signed successor advances the wallet.
                "ticket_unissued" | "oa_key_policy_rejected" | "ticket_key_expired" | "replay" => {
                    self.recover().await?;
                    return Err(AuthError::Wallet(format!(
                        "{}: {}",
                        error.error_code, error.error_message
                    )));
                }
                _ => {
                    return Err(AuthError::Wallet(format!(
                        "{}: {}",
                        error.error_code, error.error_message
                    )))
                }
            }
        }
        Err(AuthError::LeasePending(
            "the ticket purchase did not complete; the saved request is preserved".into(),
        ))
    }

    pub(crate) async fn pending_ticket(&self) -> Result<bool, AuthError> {
        Ok(self
            .pending_request_payload()
            .await?
            .is_some_and(|payload| saved_ticket(&payload).is_some()))
    }

    async fn pending_request_payload(&self) -> Result<Option<String>, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let wallet = load_wallet(&config)?;
            if !wallet.has_pending_request() {
                return Ok(None);
            }
            Ok(Some(
                wallet
                    .pending_api_request()?
                    .ok_or_else(|| {
                        AuthError::LeasePending(
                            "an older pending request has no retryable request body".into(),
                        )
                    })?
                    .payload,
            ))
        })
        .await
    }

    /// The saved ticket request, or a new proof for `terms` at a verified
    /// quote, with a solvency bound covering the price.
    async fn prepare_ticket_request(
        &self,
        terms: Option<TicketTermsV1>,
    ) -> Result<ApiRequestV2, AuthError> {
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let paths = self.paths.clone();
        spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut wallet = load_wallet(&config)?;
            crate::oa_withdrawal::check_spending(
                &config,
                wallet.state().map(|state| state.note_id),
            )?;
            if wallet.has_pending_request() {
                let request = wallet
                    .pending_api_request()?
                    .ok_or(AuthError::PendingRequest)?;
                if saved_ticket(&request.payload).is_none() {
                    return Err(AuthError::PendingRequest);
                }
                return Ok(request);
            }
            let terms = terms.ok_or(AuthError::PendingRequest)?;
            wallet.check_request_allowed()?;
            let state = wallet.state().ok_or(AuthError::NoActiveNote)?;
            let note_id = state.note_id;
            let bound_at_state = state.bound_at_state;
            let runtime = current_thread_runtime()?;
            let leaf = wallet.current_note_leaf().ok_or(AuthError::NoActiveNote)?;
            let (active_root, siblings) =
                runtime.block_on(async move { paths.path(note_id, &leaf).await })?;
            let quote = runtime.block_on(crate::oa_native::verified_quote(&config))?;
            let (payload, price_units) = ticket_payload(&terms, &quote)?;
            let bound = state_solvency_bound(
                bound_at_state,
                u128::from(price_units).max(config.request_charge_cap),
            )?;
            if wallet
                .state()
                .is_some_and(|state| state.current_balance < bound)
            {
                return Err(AuthError::InsufficientBalance);
            }
            let payload_hash = compute_payload_hash(payload.as_bytes());
            wallet
                .prepare_request_with_bound(&payload, payload_hash, active_root, siblings, bound)
                .map_err(Into::into)
        })
        .await
    }

    /// Store a checked purchase reply in the inventory as provisional,
    /// install its successor (which the wallet verifies again, including the
    /// ticket's fixed price and terms, and which removes the pending
    /// journal), and only then mark the ticket ready. Before the store the
    /// journal replays the purchase; after it the inventory keeps the key;
    /// a successor the wallet refuses leaves the ticket refused, never
    /// handed out.
    async fn complete_ticket_purchase(
        &self,
        request: &ApiRequestV2,
        ticket: &TicketAuthorization,
        body: &str,
    ) -> Result<(), AuthError> {
        let response: TicketPurchaseResponse = serde_json::from_str(body)
            .map_err(|error| AuthError::Serialization(error.to_string()))?;
        if let Err(error) = check_purchase(&self.config, request, ticket, &response) {
            // A mismatched reply never advances the wallet; only signed
            // recovery may, and the journal keeps the request.
            let _ = self.recover().await;
            return Err(error);
        }
        let successor = response
            .request_response
            .clone()
            .ok_or_else(|| AuthError::KeyVerification("missing successor".into()))?;
        let evidence = response
            .verification
            .clone()
            .ok_or_else(|| AuthError::KeyVerification("missing OA key evidence".into()))?;
        let entry = InventoryEntry {
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            tier: ticket.ticket.clone(),
            price_units: ticket.price_units,
            api_key: response.lease.api_key,
            base_url: response.lease.openrouter_api_base,
            expires_at: response.lease.expires_at,
            evidence,
            bought_at: now_seconds(),
            phase: Phase::Provisional,
            claimed_by: None,
        };
        let id = entry.client_request_id.clone();
        let config = self.config.clone();
        let wallet_mutex = self.wallet_mutex.clone();
        let session_events = self.oa_session_events.clone();
        let installed = spawn_blocking(move || {
            let _guard = wallet_mutex
                .lock()
                .map_err(|error| AuthError::Wallet(error.to_string()))?;
            let _lockfile = acquire_wallet_lock(&config.state_dir)?;
            let mut inventory = read_inventory(&config.state_dir)?;
            // A replayed purchase (the earlier reply was lost after this
            // store) carries the same key: keep one entry.
            if !inventory
                .entries
                .iter()
                .any(|existing| existing.client_request_id == entry.client_request_id)
            {
                inventory.entries.push(entry);
                write_inventory(&config.state_dir, &inventory)?;
            }
            let mut wallet = load_wallet(&config)?;
            let installed = wallet.complete_pending_response(&successor);
            let phase = match &installed {
                Ok(()) => Some(Phase::Ready),
                Err(zkapi_client::error::ClientError::InvalidSuccessor(_)) => Some(Phase::Refused),
                // A late successor (an exit proof was released) or another
                // error: the ticket stays provisional until recovery shows
                // its successor installed.
                Err(_) => None,
            };
            if let Some(phase) = phase {
                let mut inventory = read_inventory(&config.state_dir)?;
                for stored in &mut inventory.entries {
                    if stored.client_request_id == id && stored.phase == Phase::Provisional {
                        stored.phase = phase;
                        if phase == Phase::Refused {
                            stored.api_key.clear();
                        }
                    }
                }
                write_inventory(&config.state_dir, &inventory)?;
            }
            if installed.is_ok() {
                session_events.settled(
                    &successor,
                    wallet.state().map(|state| state.current_balance),
                );
            }
            installed.map_err(AuthError::from)
        })
        .await;
        installed?;
        tracing::info!(
            client_request_id = %request.client_request_id,
            tier = ticket.ticket.tier_id,
            price_units = ticket.price_units,
            "ticket bought; successor installed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn terms() -> TicketTermsV1 {
        TicketTermsV1 {
            tier_id: 1,
            tier_name: "Instant".into(),
            oa_tickets: 4,
            price_micro_usd: 560_000,
            credit_limit_micro_usd: 3_000_000,
            duration_seconds: 3_600,
        }
    }

    fn quote(answer: &str) -> crate::oa_native::Quote {
        crate::oa_native::Quote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 11155111,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "7".into(),
            answer: answer.into(),
            decimals: 8,
            updated_at: 1_700_000_000,
            expires_at: 1_700_004_500,
        }
    }

    #[test]
    fn the_payload_binds_terms_price_and_quote_and_parses_back() {
        // $2,500/ETH: $0.56 is 224,000 gwei.
        let (payload, price) = ticket_payload(&terms(), &quote("250000000000")).unwrap();
        assert_eq!(price, 224_000);
        let ticket = saved_ticket(&payload).unwrap();
        assert_eq!(ticket.ticket, terms());
        assert_eq!(ticket.price_units, 224_000);
        let value: Value = serde_json::from_str(&payload).unwrap();
        assert_eq!(value["billing_quote"]["answer"], "250000000000");
        // Rounded up, as every native charge: $0.56 at $3,000/ETH.
        let (_, price) = ticket_payload(&terms(), &quote("300000000000")).unwrap();
        assert_eq!(price, 186_667);
    }

    #[test]
    fn only_ticket_payloads_are_tickets() {
        let metered = json!({"mode":"openrouter_ephemeral_lease","version":1,
            "billing_quote": quote("250000000000")})
        .to_string();
        assert!(saved_ticket(&metered).is_none());
        let (payload, _) = ticket_payload(&terms(), &quote("250000000000")).unwrap();
        let mut extra: Value = serde_json::from_str(&payload).unwrap();
        extra["prompt"] = "hello".into();
        assert!(saved_ticket(&extra.to_string()).is_none());
    }

    // ---- purchase lifecycle against a mock protocol server ----

    use axum::{
        extract::State,
        routing::{get, post},
        Json, Router,
    };
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use zkapi_client::journal::PendingRequestJournal;
    use zkapi_proof::compact::{rerandomize, server_update, CompactSigner};
    use zkapi_types::wire::CurvePointWire;

    const DEPOSIT: u128 = 1_500_000;
    const PRICE: u64 = 224_000;

    struct Server {
        request: Value,
        reply: Value,
        /// What `GET /v2/requests/ticket-request` serves, if anything.
        recovery: Option<Value>,
        verifier_valid: bool,
        /// The server's purchase reply is lost after it charged.
        lose_reply: bool,
        events: Vec<&'static str>,
    }

    /// Signs successors of the fixture's request at any charge and payload.
    struct Successors {
        signer: CompactSigner,
        anonymous: CurvePointWire,
        nullifier: Felt252,
        deployment: (u16, u64, Felt252),
        quote: crate::oa_native::Quote,
    }

    impl Successors {
        fn settled(&self, charge: u64, ticket: TicketTermsV1) -> RequestResponseV2 {
            let payload = json!({"type": TICKET_SETTLEMENT_TYPE, "issued": true,
                "delivered": true, "ticket": ticket, "price_units": PRICE.to_string(),
                "charge_basis": "ticket", "billing_quote": self.quote})
            .to_string();
            self.signed(u128::from(charge), payload)
        }

        fn signed(&self, charge: u128, payload: String) -> RequestResponseV2 {
            let next_commitment = server_update(&self.anonymous, charge, &Felt252::ONE).unwrap();
            let next_anchor = core_v2::next_anchor(&self.nullifier);
            let (version, chain_id, contract) = self.deployment;
            let message = core_v2::state_message(
                version,
                chain_id,
                &contract,
                &next_commitment.x,
                &next_commitment.y,
                &next_anchor,
            );
            RequestResponseV2 {
                status: "finalized".into(),
                client_request_id: "ticket-request".into(),
                request_nullifier: self.nullifier,
                response_code: 200,
                response_hash: zkapi_types::canonical_response_hash(payload.as_bytes()),
                response_payload: payload,
                charge_applied: charge,
                next_commitment,
                next_anchor,
                blind_delta_srv: Felt252::ONE,
                next_state_signature: self.signer.sign(&message),
                policy_reason_code: None,
                policy_evidence_hash: None,
            }
        }
    }

    struct Fixture {
        directory: tempfile::TempDir,
        config: AuthConfig,
        server: Arc<Mutex<Server>>,
        successors: Successors,
        _handle: tokio::task::JoinHandle<()>,
    }

    /// A funded wallet whose ticket purchase was proved and transmitted (the
    /// pending journal), and a server that sells it at its fixed price.
    async fn fixture() -> Fixture {
        let directory = tempfile::tempdir().unwrap();
        let signer = CompactSigner::from_seed(&Felt252::from_u64(99));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config = AuthConfig {
            state_dir: directory.path().to_path_buf(),
            protocol_version: 2,
            chain_id: 1,
            request_charge_cap: 100_000,
            state_signing_key: signer.public_key(),
            protocol_server_url: url.clone(),
            oa_verifier_url: url.clone(),
            openrouter_inference_base: "https://openrouter.ai/api/v1".into(),
            request_mode: RequestMode::DirectOpenrouter,
            require_oa_org_key_source: true,
            billing_asset: "native_eth".into(),
            billing_unit: "gwei".into(),
            native_asset_wei_per_unit: "1000000000".into(),
            native_price_feed_address: format!("0x{}", "12".repeat(20)),
            ..Default::default()
        };
        let mut wallet = load_wallet(&config).unwrap();
        wallet
            .confirm_deposit(Felt252::from_u64(42), 7, DEPOSIT, 4_000_000_000)
            .unwrap();
        let note = wallet.state().unwrap();
        let nullifier = core_v2::nullifier(&note.secret_s, note.note_id, &note.current_anchor);
        let anonymous = rerandomize(
            &CurvePointWire {
                x: note.current_commitment_x,
                y: note.current_commitment_y,
            },
            &Felt252::ONE,
        )
        .unwrap();
        let quote: crate::oa_native::Quote = serde_json::from_value(json!({
            "asset":"native_eth","units_per_eth":1_000_000_000,"chain_id":1,
            "feed_address":config.native_price_feed_address,"round_id":"123",
            "answer":"250000000000","decimals":8,"updated_at":1,"expires_at":3601}))
        .unwrap();
        let (payload, price) = ticket_payload(&terms(), &quote).unwrap();
        assert_eq!(price, PRICE);
        let request = ApiRequestV2 {
            client_request_id: "ticket-request".into(),
            payload_hash: compute_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: zkapi_types::RequestPublicInputsV2 {
                protocol_version: 2,
                chain_id: 1,
                contract_address: config.contract_address,
                active_root: Felt252::ZERO,
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1,
                // The solvency bound is the price: no successor may charge more.
                solvency_bound: u128::from(PRICE),
                request_nullifier: nullifier,
                authorization_tag: Felt252::ONE,
                anonymous_commitment_x: anonymous.x,
                anonymous_commitment_y: anonymous.y,
            },
            proof: Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: "saved-proof-only".into(),
            },
        };
        PendingRequestJournal::write(
            &config.state_dir.join("pending_journal.json"),
            &PendingRequestJournal {
                exists: true,
                client_request_id: request.client_request_id.clone(),
                nullifier,
                payload_hash: request.payload_hash,
                user_rerandomization: Felt252::ONE,
                created_at_ms: 1,
                prepared_request: Some(request.clone()),
            },
        )
        .unwrap();
        let successors = Successors {
            signer,
            anonymous,
            nullifier,
            deployment: (note.protocol_version, note.chain_id, note.contract_address),
            quote: quote.clone(),
        };
        let expires = now_seconds() + 3_570;
        let reply = json!({"status":"active","client_request_id":"ticket-request",
            "api_key":"private-ticket-key","openrouter_api_base":config.openrouter_inference_base,
            "issued_at":1,"expires_at":expires,"valid_for_seconds":3_570,"settle_after":1,
            "spending_limit_usd":3.0,"key_source":"oa_org","billing_quote":quote,
            "verification":{"station_id":"test-station","key_valid_till":expires,
                "station_signature":"synthetic-signature","org_signature":"synthetic-org-signature",
                "verifier_url":url},
            "ticket": terms(), "request_response": successors.settled(PRICE, terms())});
        let server = Arc::new(Mutex::new(Server {
            request: serde_json::to_value(&request).unwrap(),
            reply,
            recovery: None,
            verifier_valid: true,
            lose_reply: false,
            events: Vec::new(),
        }));
        let router = Router::new()
            .route("/v2/openrouter/leases", post(|State(server): State<Arc<Mutex<Server>>>, Json(body): Json<Value>| async move {
                let mut server = server.lock().unwrap();
                assert_eq!(body, server.request, "only the exact saved request is sent");
                server.events.push("purchase");
                if server.lose_reply {
                    server.lose_reply = false;
                    return (axum::http::StatusCode::BAD_GATEWAY, Json(json!({})));
                }
                (axum::http::StatusCode::CREATED, Json(server.reply.clone()))
            }))
            .route("/v2/requests/ticket-request", get(|State(server): State<Arc<Mutex<Server>>>| async move {
                let mut server = server.lock().unwrap();
                server.events.push("recover");
                Json(match &server.recovery {
                    Some(response) => json!({"status":"finalized","nullifier_status":"finalized","request_response":response}),
                    None => json!({"status":"pending","nullifier_status":"reserved"}),
                })
            }))
            .route("/submit_key", post(|State(server): State<Arc<Mutex<Server>>>, Json(body): Json<Value>| async move {
                let mut server = server.lock().unwrap();
                server.events.push("verify");
                assert_eq!(body["api_key"], "private-ticket-key");
                let hash = format!("{:x}", Sha256::digest(b"private-ticket-key"));
                Json(json!({"status":"verified","station_id":"test-station",
                    "key_hash": if server.verifier_valid { hash[..16].to_string() } else { "00".repeat(8) }}))
            }))
            .with_state(server.clone());
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        Fixture {
            directory,
            config,
            server,
            successors,
            _handle: handle,
        }
    }

    impl Fixture {
        fn service(&self) -> Arc<AuthService> {
            AuthService::new(self.config.clone()).unwrap()
        }

        fn purchases(&self) -> usize {
            let server = self.server.lock().unwrap();
            server
                .events
                .iter()
                .filter(|event| **event == "purchase")
                .count()
        }

        fn verifications(&self) -> usize {
            let server = self.server.lock().unwrap();
            server
                .events
                .iter()
                .filter(|event| **event == "verify")
                .count()
        }

        async fn balance(&self, service: &AuthService) -> u128 {
            service
                .status()
                .await
                .unwrap()
                .note
                .unwrap()
                .current_balance
        }

        fn inventory(&self) -> Inventory {
            read_inventory(self.directory.path()).unwrap()
        }

        fn journal_pending(&self) -> bool {
            self.directory.path().join("pending_journal.json").exists()
        }

        /// No stored copy of the key outside the inventory, which erases it
        /// once it may no longer be handed out.
        fn key_stored(&self) -> bool {
            std::fs::read_to_string(inventory_path(self.directory.path()))
                .is_ok_and(|text| text.contains("private-ticket-key"))
        }
    }

    #[tokio::test]
    async fn a_lost_server_reply_is_finished_once_and_handed_out_idempotently() {
        let fixture = fixture().await;
        let service = fixture.service();
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.api_key, "private-ticket-key");
        assert_eq!(ticket.price_units, PRICE);
        assert_eq!(ticket.tier, terms());
        assert!(ticket.verified);
        assert!(!format!("{ticket:?}").contains("private-ticket-key"));
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
        assert!(!fixture.journal_pending());
        // The local reply is lost: the same purchase ID gets the same ticket,
        // with no second purchase.
        let again = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(again.client_request_id, ticket.client_request_id);
        // Restart: the inventory survives, the same claim answers.
        drop(service);
        let restarted = fixture.service();
        let after_restart = restarted
            .buy_ticket(&terms(), "purchase-0001")
            .await
            .unwrap();
        assert_eq!(after_restart.api_key, "private-ticket-key");
        assert_eq!(fixture.purchases(), 1);
        assert_eq!(
            fixture.balance(&restarted).await,
            DEPOSIT - u128::from(PRICE)
        );
        // The inventory file is private.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(inventory_path(fixture.directory.path()))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o077, 0);
        }
        // Used for its request, the ticket is consumed: its key is erased and
        // a retry of the purchase ID answers without buying again.
        restarted
            .release_ticket("ticket-request", "purchase-0001", true)
            .await
            .unwrap();
        assert!(!fixture.key_stored());
        assert!(matches!(
            restarted.buy_ticket(&terms(), "purchase-0001").await,
            Err(AuthError::KeyVerification(_))
        ));
        assert_eq!(fixture.purchases(), 1);
        assert_eq!(fixture.inventory().entries[0].phase, Phase::Consumed);
    }

    /// Deliberate reuse: a ticket returned unconsumed serves a later purchase
    /// of exactly its terms, never another tier's.
    #[tokio::test]
    async fn an_unconsumed_ticket_serves_only_its_exact_terms() {
        let fixture = fixture().await;
        let service = fixture.service();
        service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        service
            .release_ticket("ticket-request", "purchase-0001", false)
            .await
            .unwrap();
        let reused = service.buy_ticket(&terms(), "purchase-0002").await.unwrap();
        assert_eq!(reused.client_request_id, "ticket-request");
        assert_eq!(fixture.purchases(), 1);
        service
            .release_ticket("ticket-request", "purchase-0002", false)
            .await
            .unwrap();
        // Other terms of the same tier (a repriced catalog) are not served
        // by it, and the server does not sell them: nothing is bought.
        let repriced = TicketTermsV1 {
            price_micro_usd: 600_000,
            ..terms()
        };
        assert!(service
            .buy_ticket(&repriced, "purchase-0003")
            .await
            .is_err());
        assert_eq!(fixture.purchases(), 1);
        assert!(fixture.inventory().entries[0].claimed_by.is_none());
    }

    #[tokio::test]
    async fn a_key_failing_verification_after_install_is_kept_paid_and_never_rebought() {
        let fixture = fixture().await;
        fixture.server.lock().unwrap().verifier_valid = false;
        let service = fixture.service();
        assert!(service.buy_ticket(&terms(), "purchase-0001").await.is_err());
        // Charged once and installed; the paid ticket is recorded, rejected,
        // and its key erased.
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
        let inventory = fixture.inventory();
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].phase, Phase::Rejected);
        assert!(!fixture.key_stored());
        // A retry answers from the inventory: no second purchase.
        assert!(matches!(
            service.buy_ticket(&terms(), "purchase-0001").await,
            Err(AuthError::KeyVerification(_))
        ));
        assert_eq!(fixture.purchases(), 1);
    }

    #[tokio::test]
    async fn an_ambiguous_server_reply_keeps_the_journal_and_the_retry_pays_once() {
        let fixture = fixture().await;
        fixture.server.lock().unwrap().lose_reply = true;
        let service = fixture.service();
        assert!(service.buy_ticket(&terms(), "purchase-0001").await.is_err());
        assert!(fixture.journal_pending());
        assert_eq!(fixture.balance(&service).await, DEPOSIT);
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.api_key, "private-ticket-key");
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
        assert_eq!(fixture.purchases(), 2);
    }

    fn provisional_entry(fixture: &Fixture, claimed_by: Option<&str>) -> InventoryEntry {
        let reply = fixture.server.lock().unwrap().reply.clone();
        InventoryEntry {
            client_request_id: "ticket-request".into(),
            request_nullifier: fixture.successors.nullifier,
            tier: terms(),
            price_units: PRICE,
            api_key: "private-ticket-key".into(),
            base_url: "https://openrouter.ai/api/v1".into(),
            expires_at: reply["expires_at"].as_u64().unwrap(),
            evidence: serde_json::from_value(reply["verification"].clone()).unwrap(),
            bought_at: 1,
            phase: Phase::Provisional,
            claimed_by: claimed_by.map(str::to_string),
        }
    }

    /// A crash after the store and before the install: the retry replays
    /// the journal (the server returns the same key), installs the verified
    /// successor, and only then hands out the ticket.
    #[tokio::test]
    async fn a_crash_before_install_is_installed_before_any_hand_out() {
        let fixture = fixture().await;
        write_inventory(
            fixture.directory.path(),
            &Inventory {
                version: INVENTORY_VERSION,
                entries: vec![provisional_entry(&fixture, None)],
            },
        )
        .unwrap();
        let service = fixture.service();
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.client_request_id, "ticket-request");
        // Installed before the hand-out, from the replayed purchase.
        assert!(!fixture.journal_pending());
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
        assert_eq!(fixture.purchases(), 1);
        let inventory = fixture.inventory();
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].phase, Phase::Ready);
    }

    /// A crash after the install and before the ticket was marked ready:
    /// the request archive shows the successor installed, so it is promoted
    /// without any server call.
    #[tokio::test]
    async fn a_crash_after_install_is_promoted_from_the_archive() {
        let fixture = fixture().await;
        let mut wallet = load_wallet(&fixture.config).unwrap();
        wallet
            .complete_pending_response(&fixture.successors.settled(PRICE, terms()))
            .unwrap();
        drop(wallet);
        write_inventory(
            fixture.directory.path(),
            &Inventory {
                version: INVENTORY_VERSION,
                entries: vec![provisional_entry(&fixture, None)],
            },
        )
        .unwrap();
        let service = fixture.service();
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.api_key, "private-ticket-key");
        assert_eq!(fixture.purchases(), 0);
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
    }

    /// A reply with valid-looking metadata but a successor the wallet cannot
    /// verify: the key is never handed out, no other ticket is bought, also
    /// after a restart, and the purchase stays recoverable.
    #[tokio::test]
    async fn an_unverifiable_successor_never_exposes_the_key_or_buys_again() {
        let fixture = fixture().await;
        {
            let mut server = fixture.server.lock().unwrap();
            let mut forged = fixture.successors.settled(PRICE, terms());
            forged.next_state_signature =
                CompactSigner::from_seed(&Felt252::from_u64(7)).sign(&Felt252::ONE);
            server.reply["request_response"] = serde_json::to_value(forged).unwrap();
        }
        for attempt in 0..2 {
            let service = fixture.service();
            assert!(service.buy_ticket(&terms(), "purchase-0001").await.is_err());
            assert!(service.buy_ticket(&terms(), "purchase-0002").await.is_err());
            assert_eq!(
                fixture.balance(&service).await,
                DEPOSIT,
                "attempt {attempt}"
            );
            assert_eq!(fixture.verifications(), 0, "a key went to the verifier");
            let inventory = fixture.inventory();
            assert_eq!(inventory.entries.len(), 1);
            assert_eq!(inventory.entries[0].phase, Phase::Provisional);
            assert!(inventory.entries[0].claimed_by.is_none());
            // Only the exact saved request is replayed: never a new proof.
            assert!(fixture.journal_pending());
        }
        // The server serves the valid successor: the next retry installs it
        // and the paid key is handed out at last.
        fixture.server.lock().unwrap().reply["request_response"] =
            serde_json::to_value(fixture.successors.settled(PRICE, terms())).unwrap();
        let service = fixture.service();
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.api_key, "private-ticket-key");
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
    }

    /// Generic recovery (`GET /v2/requests`) of a ticket request goes through
    /// the wallet's ticket check: a validly signed successor that charges
    /// other than the fixed price is refused, not installed, and the stored
    /// ticket is refused too.
    #[tokio::test]
    async fn recovery_refuses_a_signed_ticket_successor_at_another_charge() {
        let fixture = fixture().await;
        write_inventory(
            fixture.directory.path(),
            &Inventory {
                version: INVENTORY_VERSION,
                entries: vec![provisional_entry(&fixture, None)],
            },
        )
        .unwrap();
        let cheaper_terms = TicketTermsV1 {
            credit_limit_micro_usd: 1,
            ..terms()
        };
        for (charge, ticket) in [(PRICE - 1, terms()), (PRICE, cheaper_terms)] {
            fixture.server.lock().unwrap().recovery =
                Some(serde_json::to_value(fixture.successors.settled(charge, ticket)).unwrap());
            let service = fixture.service();
            let _ = service.recover().await;
            assert_eq!(fixture.balance(&service).await, DEPOSIT);
        }
        let service = fixture.service();
        assert!(service.buy_ticket(&terms(), "purchase-0001").await.is_err());
        assert_eq!(fixture.inventory().entries[0].phase, Phase::Refused);
        assert!(!fixture.key_stored());
        assert_eq!(fixture.verifications(), 0);
        assert_eq!(fixture.purchases(), 0);
    }

    #[tokio::test]
    async fn withdrawal_settlement_finishes_a_paid_ticket_into_the_inventory() {
        let fixture = fixture().await;
        let service = fixture.service();
        let status = service.settle_for_withdrawal().await.unwrap();
        assert!(!status.pending_request);
        assert_eq!(fixture.balance(&service).await, DEPOSIT - u128::from(PRICE));
        let inventory = fixture.inventory();
        assert_eq!(inventory.entries.len(), 1);
        assert_eq!(inventory.entries[0].phase, Phase::Ready);
        assert!(inventory.entries[0].claimed_by.is_none());
        // The paid key is still handed out afterwards, without a purchase.
        let ticket = service.buy_ticket(&terms(), "purchase-0001").await.unwrap();
        assert_eq!(ticket.api_key, "private-ticket-key");
        assert_eq!(fixture.purchases(), 1);
        // release-all after a client restart frees the ready claim.
        assert_eq!(service.release_all_tickets().await.unwrap(), 1);
        assert!(fixture.inventory().entries[0].claimed_by.is_none());
    }

    #[test]
    fn claims_are_exclusive_and_only_of_ready_tickets_of_exact_terms() {
        let entry = |id: &str, tier: TicketTermsV1, expires_at: u64, phase: Phase| InventoryEntry {
            client_request_id: id.into(),
            request_nullifier: Felt252::ONE,
            tier,
            price_units: 1,
            api_key: format!("key-{id}"),
            base_url: "https://openrouter.ai/api/v1".into(),
            expires_at,
            evidence: serde_json::from_value(json!({"verifier_url":"https://v.example",
                "station_id":"s","key_valid_till":expires_at,"station_signature":"a",
                "org_signature":"b"}))
            .unwrap(),
            bought_at: 1,
            phase,
            claimed_by: None,
        };
        let other_tier = TicketTermsV1 {
            tier_id: 2,
            ..terms()
        };
        let repriced = TicketTermsV1 {
            price_micro_usd: 1,
            ..terms()
        };
        let mut inventory = Inventory {
            version: INVENTORY_VERSION,
            entries: vec![
                entry("expired", terms(), 100, Phase::Ready),
                entry("short", terms(), 1_050, Phase::Ready),
                entry("provisional", terms(), 10_000, Phase::Provisional),
                entry("refused", terms(), 10_000, Phase::Refused),
                entry("repriced", repriced, 10_000, Phase::Ready),
                entry("other-tier", other_tier.clone(), 10_000, Phase::Ready),
                entry("good", terms(), 10_000, Phase::Ready),
            ],
        };
        let now = 1_000;
        let Claim::Ticket(first) = claim(&mut inventory, &terms(), "p1", now) else {
            panic!("a usable ticket")
        };
        assert_eq!(first.client_request_id, "good");
        assert!(inventory
            .entries
            .iter()
            .all(|e| e.client_request_id != "expired"));
        let Claim::Ticket(again) = claim(&mut inventory, &terms(), "p1", now) else {
            panic!("the same ticket")
        };
        assert_eq!(again.client_request_id, "good");
        assert!(matches!(
            claim(&mut inventory, &terms(), "p2", now),
            Claim::None
        ));
        let Claim::Ticket(other) = claim(&mut inventory, &other_tier, "p3", now) else {
            panic!("tier 2")
        };
        assert_eq!(other.client_request_id, "other-tier");
        // A claimed key that expires becomes a consumed tombstone for a day.
        inventory.prune(20_000);
        assert!(inventory
            .entries
            .iter()
            .all(|e| e.claimed_by.is_some() && e.phase == Phase::Consumed && e.api_key.is_empty()));
        assert!(matches!(
            claim(&mut inventory, &terms(), "p1", 20_000),
            Claim::Unusable(_)
        ));
        inventory.prune(10_000 + TOMBSTONE_SECONDS + 1);
        assert!(inventory.entries.is_empty());
        assert!(!valid_purchase_id("short"));
        assert!(!valid_purchase_id("has space here"));
        assert!(valid_purchase_id("purchase-0001"));
    }
}
