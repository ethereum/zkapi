//! zkAPI v2 request processor.

use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha3::{Digest, Keccak256};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{random_field, random_scalar, server_update, RequestVerifier};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceRequest, ClearanceResponseV2, CurvePointWire,
    OpenRouterLeaseAuthorization, OpenRouterLeaseResponse, OpenRouterLeaseStatusResponse,
    RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    NullifierStatus,
};

use crate::config::{OpenRouterLeaseSourceConfig, ServerConfig};
use crate::dashboard::{redact_secrets, DashboardEvent, DashboardHub};
use crate::error::ServerError;
use crate::native_billing::{NativeBillingOracle, NativeBillingQuote};
use crate::nullifier_store::{
    api_request_binding, NullifierStore, OaProvisioningOutcome, OpenRouterLeaseRecord,
    TranscriptRecord,
};
use crate::oa_org::{IssuedOpenRouterLease, OaOrgProvisioner, OaOrgUsage, OaOrgUsageExpectation};
use crate::openrouter::OpenRouterProvisioner;
use crate::pricing;
use crate::settlement::{SettlementResult, UsageInfo};
use crate::signer::ServerSigner;

const MAX_REQUEST_AGE_SECONDS: u64 = 300;
const MAX_FUTURE_SKEW_SECONDS: u64 = 30;
// OA's signed validity is an upstream upper bound, not a guarantee that the
// child key remains usable until the final second. Stop advertising it as the
// usable lease end and leave room for clock skew and in-flight requests.
const OA_LEASE_EXPIRY_SAFETY_SECONDS: u64 = 30;

/// Response body of the additive `GET /v2/time` endpoint.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ServerTimeResponse {
    pub server_time_ms: u64,
    pub protocol_version: u16,
    pub chain_id: u64,
    pub max_request_age_seconds: u64,
    pub max_future_skew_seconds: u64,
}

/// A request older than the admission window can never be admitted again:
/// admission refuses it before any reservation, and its age only grows.
/// Future-dated requests are deliberately excluded; they can become valid.
fn request_time_irrevocably_expired(request_time: u64, now: u64) -> bool {
    request_time.saturating_add(MAX_REQUEST_AGE_SECONDS) < now
}

pub struct RequestProcessor {
    config: ServerConfig,
    store: Arc<NullifierStore>,
    signer: Arc<ServerSigner>,
    verifier: RequestVerifier,
    current_root: Arc<RwLock<Felt252>>,
    dashboard: Option<Arc<DashboardHub>>,
    openrouter: Option<Arc<OpenRouterProvisioner>>,
    oa_org: Option<Arc<OaOrgProvisioner>>,
    native_oracle: NativeBillingOracle,
    lease_issue_lock: tokio::sync::Mutex<()>,
    lease_settlement_lock: tokio::sync::Mutex<()>,
    // Keep the database exclusive for this processor's full lifetime, including
    // background tasks that may outlive an HTTP listener.
    _writer_lock: Option<crate::writer_lock::ServerWriterLock>,
}

impl RequestProcessor {
    pub fn try_new(
        config: ServerConfig,
        store: Arc<NullifierStore>,
        signer: Arc<ServerSigner>,
        current_root: Felt252,
    ) -> anyhow::Result<Self> {
        config.validate_native_mode()?;
        let writer_lock = store.acquire_writer_lock()?;
        if let Some(lease) = config.openrouter_leases.as_ref() {
            anyhow::ensure!(
                lease.ttl_seconds > 0,
                "OpenRouter lease TTL must be positive"
            );
            match &lease.source {
                OpenRouterLeaseSourceConfig::OpenRouter { management_key, .. } => {
                    anyhow::ensure!(
                        !management_key.is_empty(),
                        "OpenRouter management key cannot be empty"
                    );
                }
                OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url,
                    shared_secret,
                } => {
                    anyhow::ensure!(!org_base_url.is_empty(), "OA org URL cannot be empty");
                    anyhow::ensure!(
                        !shared_secret.is_empty(),
                        "OA org shared secret cannot be empty"
                    );
                    anyhow::ensure!(
                        lease.ttl_seconds.is_multiple_of(60),
                        "OA org lease TTL must be a whole number of minutes"
                    );
                }
            }
        }
        let native = config
            .native_billing
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native ETH billing configuration is required"))?;
        let address = config.contract_address.to_hex();
        let body = address.strip_prefix("0x").unwrap_or(&address);
        let native_oracle =
            NativeBillingOracle::new(native, config.chain_id, format!("0x{:0>40}", body))?;
        let verifier = RequestVerifier::load(&config.proof_setup_dir)?;
        let openrouter = config
            .openrouter_leases
            .as_ref()
            .and_then(|lease| match &lease.source {
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key,
                    api_base,
                } => Some(
                    OpenRouterProvisioner::new(management_key.clone(), api_base.clone())
                        .map(Arc::new),
                ),
                OpenRouterLeaseSourceConfig::OaOrg { .. } => None,
            })
            .transpose()?;
        let oa_org = config
            .openrouter_leases
            .as_ref()
            .and_then(|lease| match &lease.source {
                OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url,
                    shared_secret,
                } => Some(
                    OaOrgProvisioner::new(org_base_url.clone(), shared_secret.clone())
                        .map(Arc::new),
                ),
                OpenRouterLeaseSourceConfig::OpenRouter { .. } => None,
            })
            .transpose()?;
        Ok(Self {
            native_oracle,
            config,
            store,
            signer,
            verifier,
            current_root: Arc::new(RwLock::new(current_root)),
            dashboard: None,
            openrouter,
            oa_org,
            lease_issue_lock: tokio::sync::Mutex::new(()),
            lease_settlement_lock: tokio::sync::Mutex::new(()),
            _writer_lock: writer_lock,
        })
    }

    #[cfg(test)]
    pub(crate) fn finalize_test_lease(
        &self,
        request: &ApiRequestV2,
        charge_gwei: u128,
    ) -> Result<RequestResponseV2, ServerError> {
        if let Some(response) = self.validate_and_reserve(request)? {
            return Ok(response);
        }
        self.finalize_request(
            request,
            SettlementResult {
                status_code: 200,
                payload: self
                    .settlement_payload(request, serde_json::json!({"status":"finalized"}))?,
                charge_applied: charge_gwei,
                usage: None,
                billing_label: "native-test".into(),
            },
            0,
            0,
        )
    }

    pub fn with_dashboard(mut self, dashboard: Arc<DashboardHub>) -> Self {
        self.dashboard = Some(dashboard);
        self
    }

    pub fn dashboard(&self) -> Option<&Arc<DashboardHub>> {
        self.dashboard.as_ref()
    }

    pub fn update_root(&self, new_root: Felt252) {
        if let Ok(mut root) = self.current_root.write() {
            *root = new_root;
        }
    }

    pub fn current_root(&self) -> Felt252 {
        self.current_root
            .read()
            .map(|value| *value)
            .unwrap_or(Felt252::ZERO)
    }

    pub fn state_signing_key(&self) -> CurvePointWire {
        self.signer.state_public_key()
    }

    pub fn clearance_signing_key(&self) -> CurvePointWire {
        self.signer.clearance_public_key()
    }

    /// Public, read-only freshness context for `GET /v2/time`. It reports only
    /// this deployment's clock and the existing fixed admission window; it
    /// reads no request, wallet, nullifier or user state and creates none.
    pub fn server_time(&self) -> ServerTimeResponse {
        ServerTimeResponse {
            server_time_ms: current_timestamp_ms(),
            protocol_version: self.config.protocol_version,
            chain_id: self.config.chain_id,
            max_request_age_seconds: MAX_REQUEST_AGE_SECONDS,
            max_future_skew_seconds: MAX_FUTURE_SKEW_SECONDS,
        }
    }

    pub async fn native_billing_quote(&self) -> Result<NativeBillingQuote, ServerError> {
        self.native_oracle.quote(current_timestamp()).await
    }

    fn lease_authorization(
        &self,
        request: &ApiRequestV2,
    ) -> Result<(OpenRouterLeaseAuthorization, NativeBillingQuote), ServerError> {
        let mut payload: serde_json::Value = serde_json::from_str(&request.payload)
            .map_err(|_| ServerError::InvalidRequest("invalid lease authorization".into()))?;
        let object = payload.as_object_mut().ok_or_else(|| {
            ServerError::InvalidRequest("invalid lease authorization object".into())
        })?;
        let quote = object.remove("billing_quote").ok_or_else(|| {
            ServerError::InvalidRequest("native ETH lease requires a bound billing quote".into())
        })?;
        let quote: NativeBillingQuote = serde_json::from_value(quote)
            .map_err(|_| ServerError::InvalidRequest("invalid native billing quote".into()))?;
        let config = self.config.native_billing.as_ref().ok_or_else(|| {
            ServerError::InvalidRequest("native ETH billing configuration is required".into())
        })?;
        quote.validate_identity(config, self.config.chain_id)?;
        let authorization = serde_json::from_value(payload).map_err(|_| {
            ServerError::InvalidRequest("invalid prompt-free lease authorization".into())
        })?;
        Ok((authorization, quote))
    }

    fn lease_limit_micro_usd(&self, request: &ApiRequestV2) -> Result<u128, ServerError> {
        self.lease_authorization(request)?
            .1
            .limit_micro_usd(request.public_inputs.solvency_bound)
    }

    fn settlement_payload(
        &self,
        request: &ApiRequestV2,
        mut payload: serde_json::Value,
    ) -> Result<String, ServerError> {
        let quote = self.lease_authorization(request)?.1;
        payload
            .as_object_mut()
            .ok_or_else(|| ServerError::Internal("settlement payload is not an object".into()))?
            .insert(
                "billing_quote".into(),
                serde_json::to_value(quote).map_err(|_| {
                    ServerError::Internal("could not encode native billing quote".into())
                })?,
            );
        Ok(payload.to_string())
    }

    fn lease_charge_units(
        &self,
        request: &ApiRequestV2,
        micro_usd: u128,
    ) -> Result<u128, ServerError> {
        self.lease_authorization(request)?.1.charge_units(micro_usd)
    }

    fn native_oa_request_id(request: &ApiRequestV2) -> Result<String, ServerError> {
        let binding = api_request_binding(request)?;
        let mut hash = Keccak256::new();
        hash.update(b"zkapi:oa-org-request:v1\0");
        hash.update(binding.as_bytes());
        Ok(format!("zkapi-v2-{}", hex::encode(hash.finalize())))
    }

    fn persisted_oa_request_id(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
    ) -> Result<String, ServerError> {
        let expected = Self::native_oa_request_id(&lease.api_request)?;
        if lease.oa_client_request_id.as_deref() != Some(expected.as_str()) {
            return Err(ServerError::Internal(
                "native OA lease is missing its bound upstream request ID".into(),
            ));
        }
        Ok(expected)
    }

    /// Reserve one prompt-free zkAPI request and mint its bounded OpenRouter
    /// runtime key using its frozen native ETH price quote.
    pub async fn issue_openrouter_lease(
        &self,
        request: &ApiRequestV2,
    ) -> Result<IssuedOpenRouterLease, ServerError> {
        let (authorization, billing_quote) = self.lease_authorization(request)?;
        if authorization != OpenRouterLeaseAuthorization::default() {
            return Err(ServerError::InvalidRequest(
                "unsupported OpenRouter lease authorization".to_string(),
            ));
        }
        let lease_config = self.config.openrouter_leases.as_ref().ok_or_else(|| {
            ServerError::InvalidRequest(
                "prompt-private OpenRouter leases are not enabled on this server".to_string(),
            )
        })?;
        // Validate native integer bounds before reserving a nullifier. An
        // unrepresentable budget must never strand otherwise unused state.
        let limit_micro_usd = self.lease_limit_micro_usd(request)?;
        let _issue_guard = self.lease_issue_lock.lock().await;
        let oa_request_id = if matches!(
            lease_config.source,
            OpenRouterLeaseSourceConfig::OaOrg { .. }
        ) {
            Some(Self::native_oa_request_id(request)?)
        } else {
            None
        };

        // A persisted request already froze its quote before external issuance.
        // Matching retries remain valid after the oracle round ages out.
        let existing_lease = self
            .store
            .lookup_openrouter_lease(&request.client_request_id);
        let existing_reservation = self
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier);
        if let Some(existing) = existing_lease.as_ref() {
            if api_request_binding(&existing.api_request)? != api_request_binding(request)? {
                return Err(ServerError::Replay);
            }
        }
        if existing_reservation.is_none() {
            self.native_oracle
                .validate(&billing_quote, current_timestamp())
                .await?;
            // Oracle reads may span expiry; no await may separate this check
            // from the synchronous proof validation and reservation below.
            self.native_oracle
                .assert_fresh(&billing_quote, current_timestamp())?;
        }
        if self.validate_and_reserve(request)?.is_some() {
            return Err(ServerError::Replay);
        }
        let key_name = format!("zkapi-{}", request.client_request_id);
        // The verified proof may expose a coarse solvency tier above the
        // deployment's minimum request cap. Bind that exact tier to the child
        // key's cumulative USD budget for this chat.
        let mut spending_limit_usd = pricing::micro_usd_to_usd(limit_micro_usd);
        if !spending_limit_usd.is_finite() || spending_limit_usd <= 0.0 {
            return Err(ServerError::InvalidRequest(
                "lease spending limit must be positive".to_string(),
            ));
        }
        let mut resume_provisioning = false;
        let mut issued_at = current_timestamp();
        let existing = self
            .store
            .lookup_openrouter_lease(&request.client_request_id);
        if let Some(existing) = existing.as_ref() {
            let persisted_binding = api_request_binding(&existing.api_request)?;
            if existing.request_nullifier != request.public_inputs.request_nullifier
                || persisted_binding != api_request_binding(request)?
            {
                return Err(ServerError::Internal(
                    "pending lease request does not match its nullifier reservation".to_string(),
                ));
            }
            if existing.key_source != lease_config.source.label() {
                return Err(ServerError::Internal(format!(
                    "pending lease source {} does not match configured source {}",
                    existing.key_source,
                    lease_config.source.label()
                )));
            }
            if existing.status != "provisioning" || existing.key_hash.is_some() {
                return Err(ServerError::LeasePending);
            }
            if existing.key_source == "oa_org"
                && existing.oa_provisioning_outcome == OaProvisioningOutcome::ConfirmedUnissued
            {
                // A definitive rejection is terminal. Never mint another key
                // while recovering a crash between its evidence and signature.
                self.finalize_unissued_oa_lease(existing).await?;
                return Err(ServerError::OaKeyPolicyRejected);
            }
        }
        // A reservation preserves the accepted request, not permission to mint
        // new access after its collateral has entered an escape or been paid
        // out. Check immediately before provider I/O, including OA retries
        // that might be the first successful upstream issuance.
        self.native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await?;
        if let Some(existing) = existing {
            match &lease_config.source {
                OpenRouterLeaseSourceConfig::OpenRouter { .. } => {
                    let provisioner = self.openrouter.as_ref().ok_or_else(|| {
                        ServerError::Internal(
                            "OpenRouter lease provider is unavailable".to_string(),
                        )
                    })?;
                    provisioner.delete_keys_named(&key_name).await?;
                    self.store
                        .remove_failed_openrouter_lease(&request.client_request_id)?;
                }
                OpenRouterLeaseSourceConfig::OaOrg { .. } => {
                    // OA station issuance is replay-safe. Retain the durable
                    // reservation and ask for the same one-show key again. The
                    // persisted limit, not any retry input, is authoritative.
                    let persisted_limit = pricing::micro_usd_to_usd(
                        self.lease_limit_micro_usd(&existing.api_request)?,
                    );
                    if existing.spending_limit_usd.to_bits() != persisted_limit.to_bits()
                        || !persisted_limit.is_finite()
                        || persisted_limit <= 0.0
                    {
                        return Err(ServerError::Internal(
                            "pending lease spending limit does not match its bound request"
                                .to_string(),
                        ));
                    }
                    self.persisted_oa_request_id(&existing)?;
                    spending_limit_usd = existing.spending_limit_usd;
                    resume_provisioning = true;
                    issued_at = existing.issued_at;
                }
            }
        }
        let requested_expires_at = current_timestamp().saturating_add(lease_config.ttl_seconds);
        if !resume_provisioning {
            self.store.create_openrouter_lease_with_oa_id(
                request,
                lease_config.source.label(),
                issued_at,
                requested_expires_at,
                requested_expires_at.saturating_add(lease_config.settlement_grace_seconds),
                spending_limit_usd,
                oa_request_id.as_deref(),
            )?;
        }
        let (api_key, key_hash, openrouter_api_base, expires_at, verification) = match &lease_config
            .source
        {
            OpenRouterLeaseSourceConfig::OpenRouter { .. } => {
                let provisioner = self.openrouter.as_ref().ok_or_else(|| {
                    ServerError::Internal("OpenRouter lease provider is unavailable".to_string())
                })?;
                match provisioner
                    .create_key(&key_name, spending_limit_usd, requested_expires_at)
                    .await
                {
                    Ok(created) => (
                        created.key,
                        created.hash,
                        provisioner.inference_base(),
                        requested_expires_at,
                        None,
                    ),
                    Err(error) => {
                        let _ = self
                            .store
                            .remove_failed_openrouter_lease(&request.client_request_id);
                        return Err(error);
                    }
                }
            }
            OpenRouterLeaseSourceConfig::OaOrg { .. } => {
                let provisioner = self.oa_org.as_ref().ok_or_else(|| {
                    ServerError::Internal("OA org lease provider is unavailable".to_string())
                })?;
                // Commit uncertainty before any external side effect. A crash
                // or timeout can never later be mistaken for nonissuance.
                let first_attempt = self.store.begin_oa_issuance(&request.client_request_id)?;
                let created = provisioner
                    .create_key(
                        oa_request_id
                            .as_deref()
                            .unwrap_or(&request.client_request_id),
                        spending_limit_usd,
                        limit_micro_usd,
                        lease_config.ttl_seconds,
                    )
                    .await;
                let created = match created {
                    Ok(created) => created,
                    Err(ServerError::OaKeyPolicyRejected) if first_attempt => {
                        self.store.confirm_oa_unissued(&request.client_request_id)?;
                        let rejected = self
                            .store
                            .lookup_openrouter_lease(&request.client_request_id)
                            .ok_or_else(|| {
                                ServerError::Internal("rejected lease disappeared".into())
                            })?;
                        self.finalize_unissued_oa_lease(&rejected).await?;
                        return Err(ServerError::OaKeyPolicyRejected);
                    }
                    Err(error) => return Err(error),
                };
                let usable_expires_at = created
                    .expires_at
                    .saturating_sub(OA_LEASE_EXPIRY_SAFETY_SECONDS);
                if usable_expires_at <= current_timestamp() {
                    return Err(ServerError::Internal(
                        "OA org key has no safe usable lifetime".to_string(),
                    ));
                }
                (
                    created.key,
                    created.hash,
                    created.openrouter_api_base,
                    usable_expires_at,
                    Some(created.verification),
                )
            }
        };
        let settle_after = expires_at.saturating_add(lease_config.settlement_grace_seconds);
        self.store.update_openrouter_lease_timing(
            &request.client_request_id,
            expires_at,
            settle_after,
        )?;
        if let Err(error) = self
            .store
            .activate_openrouter_lease(&request.client_request_id, &key_hash)
        {
            if let (Some(provisioner), OpenRouterLeaseSourceConfig::OpenRouter { .. }) =
                (&self.openrouter, &lease_config.source)
            {
                let _ = provisioner.delete_key(&key_hash).await;
            }
            return Err(error);
        }
        // The chain may have consumed this nullifier during provider I/O.
        // Persist activation first so challenge evidence and settlement survive
        // either a consumed nullifier or an unavailable RPC, but never expose
        // the runtime key unless its authorization is still unspent.
        self.native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await?;
        Ok(IssuedOpenRouterLease {
            lease: OpenRouterLeaseResponse {
                status: "active".to_string(),
                client_request_id: request.client_request_id.clone(),
                api_key,
                openrouter_api_base,
                issued_at,
                expires_at,
                valid_for_seconds: expires_at.saturating_sub(issued_at),
                settle_after,
                spending_limit_usd,
            },
            key_source: lease_config.source.label().to_string(),
            verification,
            billing_quote,
        })
    }

    /// Read-only expiration handshake. It serializes behind in-flight issuance
    /// without provisioning a key or mutating the wallet/nullifier database.
    pub async fn expire_unaccepted_native_lease(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<serde_json::Value, ServerError> {
        let (authorization, quote) = self.lease_authorization(request)?;
        if authorization != OpenRouterLeaseAuthorization::default()
            || request.client_request_id != client_request_id
            || canonical_payload_hash(request.payload.as_bytes()) != request.payload_hash
        {
            return Err(ServerError::InvalidRequest(
                "native expiry check does not match the exact request".into(),
            ));
        }
        if request.public_inputs.protocol_version != self.config.protocol_version
            || request.public_inputs.chain_id != self.config.chain_id
            || request.public_inputs.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "native expiry check deployment mismatch".into(),
            ));
        }
        let _guard = self.lease_issue_lock.lock().await;
        if self
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_some()
            || self
                .store
                .lookup_openrouter_lease(client_request_id)
                .is_some()
            || self.store.lookup_by_client_id(client_request_id).is_some()
        {
            return Err(ServerError::LeasePending);
        }
        // Still under the issuance lock with no reservation for this exact
        // request: the same age rule admission applies is final here.
        let status = if quote.expires_at <= current_timestamp()
            || request_time_irrevocably_expired(
                request.public_inputs.request_time,
                current_timestamp(),
            ) {
            "expired_unaccepted"
        } else {
            let oracle = &self.native_oracle;
            match oracle.validate(&quote, current_timestamp()).await {
                Err(ServerError::NativeQuoteSuperseded) => "superseded_unaccepted",
                Err(ServerError::NativeQuoteExpired) if quote.expires_at <= current_timestamp() => {
                    "expired_unaccepted"
                }
                Err(error) => return Err(error),
                Ok(()) if quote.expires_at <= current_timestamp() => "expired_unaccepted",
                Ok(()) => return Err(ServerError::LeasePending),
            }
        };
        Ok(serde_json::json!({
            "status":status, "client_request_id":client_request_id,
            "request_nullifier":request.public_inputs.request_nullifier,
            "payload_hash":request.payload_hash, "server_time_ms":current_timestamp().saturating_mul(1000),
        }))
    }

    /// Settle every expired lease from OpenRouter's authoritative aggregate
    /// usage. Failures are retained and retried by the next background scan.
    pub async fn settle_due_openrouter_leases(&self) {
        let _settlement_guard = self.lease_settlement_lock.lock().await;
        for lease in self.store.due_openrouter_leases(current_timestamp()) {
            let result = match lease.key_source.as_str() {
                "openrouter" => match &self.openrouter {
                    Some(provisioner) => self.settle_openrouter_lease(&lease, provisioner).await,
                    None => Err(ServerError::Internal(
                        "direct OpenRouter settlement credential is unavailable".to_string(),
                    )),
                },
                "oa_org" if lease.status == "provisioning" => {
                    self.settle_provisioning_oa_lease(&lease).await
                }
                "oa_org" => self.settle_oa_org_lease(&lease).await,
                source => Err(ServerError::Internal(format!(
                    "unsupported lease key source {source}"
                ))),
            };
            if let Err(error) = result {
                tracing::warn!(
                    client_request_id = %lease.client_request_id,
                    error = %error,
                    "OpenRouter lease settlement will be retried"
                );
                let _ = self
                    .store
                    .record_openrouter_lease_error(&lease.client_request_id, &error.to_string());
            }
        }
    }

    /// Retire a key that the upstream rejected before its advertised lease
    /// end. Requiring the original prompt-free proof prevents lease IDs alone
    /// from acting as unauthenticated denial-of-service capabilities.
    pub async fn retire_openrouter_lease(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<OpenRouterLeaseStatusResponse, ServerError> {
        let _settlement_guard = self.lease_settlement_lock.lock().await;
        let lease = self
            .store
            .lookup_openrouter_lease(client_request_id)
            .ok_or_else(|| ServerError::InvalidRequest("unknown OpenRouter lease".to_string()))?;
        let request_matches = serde_json::to_value(request)
            .and_then(|request| {
                serde_json::to_value(&lease.api_request).map(|issued| request == issued)
            })
            .map_err(|error| {
                ServerError::Internal(format!("failed to compare lease retirement proof: {error}"))
            })?;
        if request.client_request_id != client_request_id || !request_matches {
            return Err(ServerError::InvalidRequest(
                "lease retirement proof does not match the issued lease".to_string(),
            ));
        }
        match lease.status.as_str() {
            "finalized" => {}
            "provisioning" if lease.key_source == "oa_org" => {
                self.settle_provisioning_oa_lease(&lease).await?;
            }
            "active" | "retiring" | "disabled" | "revoking" => match lease.key_source.as_str() {
                "openrouter" => {
                    let provisioner = self.openrouter.as_ref().ok_or_else(|| {
                        ServerError::Internal(
                            "direct OpenRouter settlement credential is unavailable".to_string(),
                        )
                    })?;
                    if let Err(error) = self.settle_openrouter_lease(&lease, provisioner).await {
                        self.store
                            .record_openrouter_lease_error(client_request_id, &error.to_string())?;
                        return Err(error);
                    }
                }
                "oa_org" => self.settle_oa_org_lease(&lease).await?,
                source => {
                    return Err(ServerError::Internal(format!(
                        "unsupported lease key source {source}"
                    )))
                }
            },
            _ => return Err(ServerError::LeasePending),
        }
        self.openrouter_lease_status(client_request_id)
            .ok_or_else(|| ServerError::Internal("retired lease disappeared".to_string()))
    }

    /// Recover only metadata already persisted by the issuer, then use normal
    /// signed usage settlement. A missing binding never authorizes a refund.
    /// Callers hold the settlement lock; issuer reads do not block new keys.
    async fn settle_provisioning_oa_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
    ) -> Result<(), ServerError> {
        if lease.status != "provisioning" || lease.key_source != "oa_org" {
            return Err(ServerError::LeasePending);
        }
        if lease.oa_provisioning_outcome != OaProvisioningOutcome::MayHaveIssued {
            let _issue_guard = self.lease_issue_lock.lock().await;
            let current = self
                .store
                .lookup_openrouter_lease(&lease.client_request_id)
                .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
            return if current.status == "finalized" {
                Ok(())
            } else {
                self.finalize_unissued_oa_lease(&current).await
            };
        }
        let record = self.validate_oa_lease_binding(lease)?;
        if record.status == NullifierStatus::Finalized {
            return self.settle_oa_org_lease(lease).await;
        }
        let config = self.config.openrouter_leases.as_ref().ok_or_else(|| {
            ServerError::Internal("OA org lease configuration is unavailable".into())
        })?;
        if config.ttl_seconds == 0 || !config.ttl_seconds.is_multiple_of(60) {
            return Err(ServerError::Internal("invalid OA lease duration".into()));
        }
        let provider = self
            .oa_org
            .as_ref()
            .ok_or_else(|| ServerError::Internal("OA org lease provider is unavailable".into()))?;
        let binding = provider
            .reconcile_key(
                &self.persisted_oa_request_id(lease)?,
                OaOrgUsageExpectation {
                    credit_limit_usd: lease.spending_limit_usd,
                    duration_minutes: config.ttl_seconds / 60,
                    limit_credits: self.lease_limit_micro_usd(&lease.api_request)?,
                    minimum_expires_at: lease
                        .issued_at
                        .saturating_add(config.ttl_seconds)
                        .saturating_sub(OA_LEASE_EXPIRY_SAFETY_SECONDS),
                    maximum_expires_at: current_timestamp()
                        .saturating_add(config.ttl_seconds)
                        .saturating_add(OA_LEASE_EXPIRY_SAFETY_SECONDS),
                },
            )
            .await?;
        let Some(binding) = binding else {
            return Err(ServerError::LeasePending);
        };
        // Re-read after I/O under issuance exclusion. The original issuance
        // may have completed while reconciliation was reading its binding.
        let current = {
            let _issue_guard = self.lease_issue_lock.lock().await;
            let current = self
                .store
                .lookup_openrouter_lease(&lease.client_request_id)
                .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
            self.validate_oa_lease_binding(&current)?;
            if current.status == "provisioning" {
                let expires_at = binding
                    .expires_at
                    .saturating_sub(OA_LEASE_EXPIRY_SAFETY_SECONDS);
                self.store.reconcile_oa_lease(
                    &current.client_request_id,
                    &binding.key_hash,
                    expires_at,
                    expires_at.saturating_add(config.settlement_grace_seconds),
                )?;
            } else if current.status != "finalized"
                && current.key_hash.as_deref() != Some(binding.key_hash.as_str())
            {
                return Err(ServerError::Internal(
                    "OA reconciliation raced a different key".into(),
                ));
            }
            self.store
                .lookup_openrouter_lease(&lease.client_request_id)
                .ok_or_else(|| ServerError::Internal("reconciled lease disappeared".into()))?
        };
        if current.status == "finalized" {
            return Ok(());
        }
        self.settle_oa_org_lease(&current).await
    }

    fn validate_oa_lease_binding(
        &self,
        lease: &OpenRouterLeaseRecord,
    ) -> Result<TranscriptRecord, ServerError> {
        let request = &lease.api_request;
        let binding = api_request_binding(request)?;
        let record = self
            .store
            .lookup_by_nullifier(&lease.request_nullifier)
            .ok_or_else(|| ServerError::Internal("OA lease has no reservation".into()))?;
        let public = &request.public_inputs;
        let signing_key = self.state_signing_key();
        if lease.client_request_id != request.client_request_id
            || lease.request_nullifier != public.request_nullifier
            || record.reservation_kind != "openrouter_lease"
            || record.client_request_id.as_deref() != Some(request.client_request_id.as_str())
            || record.payload_hash != Some(request.payload_hash)
            || record.api_request_binding.as_deref() != Some(binding.as_str())
            || canonical_payload_hash(request.payload.as_bytes()) != request.payload_hash
            || public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
            || public.state_signing_key_x != signing_key.x
            || public.state_signing_key_y != signing_key.y
            || self.lease_authorization(request)?.0 != OpenRouterLeaseAuthorization::default()
            || lease.spending_limit_usd.to_bits()
                != pricing::micro_usd_to_usd(self.lease_limit_micro_usd(request)?).to_bits()
        {
            return Err(ServerError::Internal("OA lease binding mismatch".into()));
        }
        self.persisted_oa_request_id(lease)?;
        if !matches!(
            record.status,
            NullifierStatus::Reserved | NullifierStatus::Finalized
        ) {
            return Err(ServerError::LeasePending);
        }
        Ok(record)
    }

    /// Consume an accepted authorization without charge only when durable
    /// evidence excludes upstream issuance. Callers hold lease_issue_lock.
    /// Expiry, a missing key, and a later rejection after a lost reply do not
    /// establish this condition. Historical rows remain MayHaveIssued.
    async fn finalize_unissued_oa_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
    ) -> Result<(), ServerError> {
        if lease.status != "provisioning"
            || lease.key_source != "oa_org"
            || lease.key_hash.is_some()
            || !matches!(
                lease.oa_provisioning_outcome,
                OaProvisioningOutcome::NotStarted | OaProvisioningOutcome::ConfirmedUnissued
            )
        {
            return Err(ServerError::LeasePending);
        }
        let request = &lease.api_request;
        let record = self.validate_oa_lease_binding(lease)?;
        if record.status == NullifierStatus::Finalized {
            // The transcript was committed before the lease row. Reuse that
            // exact signed successor; a retry must never sign another balance.
            let payload = record
                .response_payload
                .as_deref()
                .and_then(|value| serde_json::from_str::<serde_json::Value>(value).ok());
            if record.charge_applied != Some(0)
                || record.next_state_sig.is_none()
                || payload.as_ref().and_then(|p| p["type"].as_str())
                    != Some("oa_org_unissued_lease_cancellation")
            {
                return Err(ServerError::Internal(
                    "unexpected unissued lease transcript".into(),
                ));
            }
        } else if record.status == NullifierStatus::Reserved {
            self.native_oracle
                .assert_request_unspent(&lease.request_nullifier)
                .await?;
            let payload = self.settlement_payload(
                request,
                serde_json::json!({
                    "type": "oa_org_unissued_lease_cancellation",
                    "issued": false,
                    "usage_credits": 0,
                    "usage_usd": 0,
                    "reason": match lease.oa_provisioning_outcome {
                        OaProvisioningOutcome::NotStarted => "issuance_not_started",
                        _ => "issuer_policy_rejected",
                    },
                }),
            )?;
            self.finalize_request(
                request,
                SettlementResult {
                    status_code: 200,
                    payload,
                    charge_applied: 0,
                    usage: None,
                    billing_label: "direct:oa-org-unissued".into(),
                },
                0,
                0,
            )?;
        } else {
            return Err(ServerError::LeasePending);
        }
        self.store
            .finalize_openrouter_lease(&lease.client_request_id, 0.0, 0)
    }

    /// Ask the OA org for the station-signed final child-key usage. Pending or
    /// unavailable receipts are retried; the reserved cap is never substituted.
    async fn settle_oa_org_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
    ) -> Result<(), ServerError> {
        if let Some(record) = self
            .store
            .lookup_by_nullifier(&lease.request_nullifier)
            .filter(|record| record.status == NullifierStatus::Finalized)
        {
            let usage_credits = record
                .response_payload
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .and_then(|payload| payload["usage_credits"].as_u64())
                .map(u128::from)
                .unwrap_or_default();
            self.store.finalize_openrouter_lease(
                &lease.client_request_id,
                pricing::micro_usd_to_usd(usage_credits),
                record.charge_applied.unwrap_or_default(),
            )?;
            return Ok(());
        }
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OA org lease has no key hash".to_string())
        })?;
        let provisioner = self.oa_org.as_ref().ok_or_else(|| {
            ServerError::Internal("OA org lease provider is unavailable".to_string())
        })?;
        let lease_config = self.config.openrouter_leases.as_ref().ok_or_else(|| {
            ServerError::Internal("OA org lease configuration is unavailable".to_string())
        })?;
        if lease_config.ttl_seconds == 0 || !lease_config.ttl_seconds.is_multiple_of(60) {
            return Err(ServerError::Internal(
                "OA org lease duration is not a positive whole number of minutes".to_string(),
            ));
        }
        let duration_minutes = lease_config.ttl_seconds / 60;
        let expected_limit_credits = self.lease_limit_micro_usd(&lease.api_request)?;
        let oa_request_id = self.persisted_oa_request_id(lease)?;
        let receipt = provisioner
            .get_key_usage(
                &oa_request_id,
                key_hash,
                OaOrgUsageExpectation {
                    credit_limit_usd: lease.spending_limit_usd,
                    duration_minutes,
                    limit_credits: expected_limit_credits,
                    minimum_expires_at: lease.expires_at,
                    maximum_expires_at: lease
                        .expires_at
                        .saturating_add(OA_LEASE_EXPIRY_SAFETY_SECONDS),
                },
            )
            .await?;
        let receipt = match receipt {
            OaOrgUsage::Finalized(receipt) => receipt,
            OaOrgUsage::Pending {
                retry_after_seconds,
            } => {
                return Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds,
                })
            }
        };
        if receipt.closed_at < lease.issued_at {
            return Err(ServerError::Internal(
                "OA org usage receipt predates the issued lease".to_string(),
            ));
        }
        let charge = self.lease_charge_units(&lease.api_request, receipt.usage_credits)?;
        let usage_usd = pricing::micro_usd_to_usd(receipt.usage_credits);
        let payload = self.settlement_payload(
            &lease.api_request,
            serde_json::json!({
                "type": "oa_org_ephemeral_lease_settlement",
                "issued_at": lease.issued_at,
                "expires_at": lease.expires_at,
                "usage_credits": receipt.usage_credits,
                "usage_usd": usage_usd,
                "usage_receipt_expires_at": receipt.expires_at,
                "usage_receipt_closed_at": receipt.closed_at,
                "usage_finalized_at": receipt.finalized_at,
                "station_id": receipt.station_id,
                "station_signature": receipt.station_signature,
                "org_signature": receipt.org_signature,
            }),
        )?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "oa_org_signed_usage_receipt".to_string(),
            }),
            billing_label: "direct:oa-org-ephemeral".to_string(),
        };
        self.finalize_request(&lease.api_request, provider_response, 0, 0)?;
        self.store
            .finalize_openrouter_lease(&lease.client_request_id, usage_usd, charge)
    }

    async fn settle_openrouter_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
        provisioner: &OpenRouterProvisioner,
    ) -> Result<(), ServerError> {
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OpenRouter lease has no key hash".to_string())
        })?;
        if let Some(record) = self
            .store
            .lookup_by_nullifier(&lease.request_nullifier)
            .filter(|record| record.status == NullifierStatus::Finalized)
        {
            let usage_usd = record
                .response_payload
                .as_deref()
                .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
                .and_then(|payload| payload["usage_usd"].as_f64())
                .unwrap_or_default();
            // Also reconcile a legacy/crash-window finalized transcript before
            // retiring its lease record. Never abandon a failed revocation.
            provisioner.delete_key(key_hash).await?;
            self.store.finalize_openrouter_lease(
                &lease.client_request_id,
                usage_usd,
                record.charge_applied.unwrap_or_default(),
            )?;
            return Ok(());
        }
        let mut phase = lease.status.as_str();
        let mut settle_after = lease.settle_after;
        if phase == "active" {
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "active",
                "retiring",
                current_timestamp(),
                None,
            )?;
            phase = "retiring";
        }
        if phase == "retiring" {
            provisioner.disable_key(key_hash).await?;
            // OpenRouter does not issue a finalized receipt. Its aggregate
            // accounting requires the configured drain/reconciliation interval
            // after disabling, including when retiring a key before expiry.
            let grace = self
                .config
                .openrouter_leases
                .as_ref()
                .ok_or_else(|| {
                    ServerError::Internal(
                        "OpenRouter lease configuration is unavailable".to_string(),
                    )
                })?
                .settlement_grace_seconds;
            settle_after = current_timestamp().saturating_add(grace);
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "retiring",
                "disabled",
                settle_after,
                None,
            )?;
            phase = "disabled";
        }
        let usage_usd = if phase == "disabled" {
            let now = current_timestamp();
            if now < settle_after {
                return Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds: settle_after - now,
                });
            }
            let usage = provisioner.get_key_usage(key_hash).await?;
            if !usage.disabled {
                self.store.advance_openrouter_retirement(
                    &lease.client_request_id,
                    "disabled",
                    "retiring",
                    now,
                    None,
                )?;
                return Err(ServerError::Internal(
                    "OpenRouter settlement key is still enabled".to_string(),
                ));
            }
            // Capture usage durably before deletion makes it unavailable.
            self.store.advance_openrouter_retirement(
                &lease.client_request_id,
                "disabled",
                "revoking",
                now,
                Some(usage.usage_usd),
            )?;
            usage.usage_usd
        } else if phase == "revoking" {
            lease.usage_usd.ok_or_else(|| {
                ServerError::Internal("OpenRouter revocation has no persisted usage".to_string())
            })?
        } else {
            return Err(ServerError::LeasePending);
        };
        // Fail closed. A 503 or ambiguous DELETE leaves the nullifier reserved
        // and the revoking lease visible to the background retry scanner.
        provisioner.delete_key(key_hash).await?;
        let raw_charge =
            self.lease_charge_units(&lease.api_request, pricing::usd_to_micro_usd(usage_usd))?;
        let lease_charge_cap = lease.api_request.public_inputs.solvency_bound;
        let charge = raw_charge.min(lease_charge_cap);
        if charge != raw_charge {
            tracing::warn!(
                client_request_id = %lease.client_request_id,
                raw_charge,
                charge,
                "OpenRouter usage exceeded the proof-bound lease limit; clamped charge"
            );
        }
        let payload = self.settlement_payload(
            &lease.api_request,
            serde_json::json!({
                "type": "openrouter_ephemeral_lease_settlement",
                "issued_at": lease.issued_at,
                "expires_at": lease.expires_at,
                "usage_usd": usage_usd,
            }),
        )?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "openrouter_key_aggregate".to_string(),
            }),
            billing_label: "direct:openrouter-ephemeral".to_string(),
        };
        self.finalize_request(&lease.api_request, provider_response, 0, 0)?;
        self.store
            .finalize_openrouter_lease(&lease.client_request_id, usage_usd, charge)?;
        Ok(())
    }

    /// Validate proof/deployment bindings and reserve the request nullifier.
    /// Returns a prior finalized response for an idempotent replay.
    fn validate_and_reserve(
        &self,
        request: &ApiRequestV2,
    ) -> Result<Option<RequestResponseV2>, ServerError> {
        let public = &request.public_inputs;
        let payload_hash = canonical_payload_hash(request.payload.as_bytes());
        if payload_hash != request.payload_hash {
            return Err(ServerError::InvalidRequest(
                "payload_hash does not match payload bytes".to_string(),
            ));
        }
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "version, chain, or contract mismatch".to_string(),
            ));
        }
        let request_binding = api_request_binding(request)?;
        // A byte-identical request already reserved by this endpoint passed
        // all checks on its first attempt. Resume it before root/freshness
        // checks so a transport retry remains possible after those values move.
        // A different endpoint kind can never claim the reservation.
        if let Some(existing) = self.store.lookup_by_nullifier(&public.request_nullifier) {
            let same_request = existing.client_request_id.as_deref()
                == Some(&request.client_request_id)
                && existing.payload_hash == Some(request.payload_hash)
                && existing.reservation_kind == "openrouter_lease"
                && existing.api_request_binding.as_deref() == Some(request_binding.as_str());
            if !same_request {
                return Err(ServerError::Replay);
            }
            return match existing.status {
                NullifierStatus::Finalized => {
                    response_from_record(&existing, &request.client_request_id).map(Some)
                }
                NullifierStatus::Reserved => Ok(None),
                NullifierStatus::ClearanceReserved => Err(ServerError::Replay),
            };
        }
        let root = self.current_root();
        if public.active_root != root {
            return Err(ServerError::StaleRoot {
                latest_root: root.to_hex(),
            });
        }
        let state_key = self.state_signing_key();
        if public.state_signing_key_x != state_key.x || public.state_signing_key_y != state_key.y {
            return Err(ServerError::InvalidRequest(
                "state signing key does not match this deployment".to_string(),
            ));
        }
        let now = current_timestamp();
        if request_time_irrevocably_expired(public.request_time, now)
            || public.request_time > now.saturating_add(MAX_FUTURE_SKEW_SECONDS)
        {
            return Err(ServerError::InvalidRequest(
                "request_time is outside the accepted freshness window".to_string(),
            ));
        }
        let required_solvency = self.config.request_charge_cap;
        if public.solvency_bound < required_solvency {
            return Err(ServerError::InvalidRequest(format!(
                "solvency_bound {} is below required {}",
                public.solvency_bound, required_solvency
            )));
        }
        let context = canonical_request_context(&request.client_request_id, &payload_hash);
        if core::authorization_tag(&public.request_nullifier, &context) != public.authorization_tag
        {
            return Err(ServerError::InvalidProof(
                "proof authorization tag does not bind this request id and payload".to_string(),
            ));
        }
        if !self
            .verifier
            .verify(public, &request.proof)
            .map_err(|error| ServerError::InvalidProof(error.to_string()))?
        {
            return Err(ServerError::InvalidProof(
                "Groth16 verification returned false".to_string(),
            ));
        }

        // Proof verification is synchronous but can be slow. Recheck at the
        // actual reservation boundary, while issue_openrouter_lease retains
        // its serialization lock. A matching existing reservation returned
        // above and keeps its original quote even after expiration.
        self.native_oracle
            .assert_fresh(&self.lease_authorization(request)?.1, current_timestamp())?;
        self.store.reserve_openrouter_lease(request)?;
        Ok(None)
    }

    fn finalize_request(
        &self,
        request: &ApiRequestV2,
        provider_response: SettlementResult,
        upstream_ms: u64,
        total_ms: u64,
    ) -> Result<RequestResponseV2, ServerError> {
        let public = &request.public_inputs;
        let reservation_kind = self
            .store
            .lookup_by_nullifier(&public.request_nullifier)
            .ok_or_else(|| {
                ServerError::Internal("request nullifier is no longer reserved".to_string())
            })?
            .reservation_kind;
        if reservation_kind != "openrouter_lease" {
            return Err(ServerError::InvalidRequest(
                "only native lease reservations can settle".into(),
            ));
        }
        let charge_cap = public.solvency_bound;
        if provider_response.charge_applied > charge_cap {
            return Err(ServerError::Internal(format!(
                "provider charge {} exceeds cap {}",
                provider_response.charge_applied, charge_cap
            )));
        }

        let anonymous = CurvePointWire {
            x: public.anonymous_commitment_x,
            y: public.anonymous_commitment_y,
        };
        let blind_delta = random_scalar();
        let next_commitment =
            server_update(&anonymous, provider_response.charge_applied, &blind_delta)
                .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
        let next_anchor = core::next_anchor(
            &random_field(),
            &public.request_nullifier,
            &next_commitment.x,
            &next_commitment.y,
        );
        let state_message = core::state_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let state_signature = self.signer.sign_state(&state_message);
        let response_hash = canonical_response_hash(provider_response.payload.as_bytes());
        let proof_bytes = base64::engine::general_purpose::STANDARD
            .decode(&request.proof.proof)
            .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
        let transcript = TranscriptRecord {
            nullifier: public.request_nullifier,
            status: NullifierStatus::Finalized,
            reservation_kind,
            client_request_id: Some(request.client_request_id.clone()),
            payload_hash: Some(request.payload_hash),
            charge_applied: Some(provider_response.charge_applied),
            response_code: Some(provider_response.status_code),
            response_payload: Some(provider_response.payload.clone()),
            response_hash: Some(response_hash),
            next_commitment_x: Some(next_commitment.x),
            next_commitment_y: Some(next_commitment.y),
            next_anchor: Some(next_anchor),
            blind_delta_srv: Some(blind_delta),
            next_state_sig: Some(state_signature),
            policy_reason_code: None,
            policy_evidence_hash: None,
            proof_blob: Some(proof_bytes.clone()),
            request_inputs_json: serde_json::to_string(public).ok(),
            api_request_binding: Some(api_request_binding(request)?),
            created_at: current_timestamp(),
            finalized_at: Some(current_timestamp()),
        };
        self.store
            .finalize(&public.request_nullifier, &transcript)?;

        if let Some(hub) = &self.dashboard {
            hub.record(DashboardEvent {
                seq: hub.next_seq(),
                ts_ms: current_timestamp_ms(),
                client_request_id: request.client_request_id.clone(),
                billing_label: provider_response.billing_label.clone(),
                request_nullifier: public.request_nullifier,
                active_root: public.active_root,
                anon_commitment: anonymous,
                solvency_bound: public.solvency_bound,
                solvency_bound_usd: pricing::micro_usd_to_usd(self.lease_limit_micro_usd(request)?),
                proof_backend: "groth16_bn254".to_string(),
                proof_public_output_hash: public.authorization_tag,
                proof_size_bytes: proof_bytes.len(),
                request_raw: redact_secrets(&request.payload),
                response_code: provider_response.status_code,
                response_text: redact_secrets(&provider_response.payload),
                response_hash,
                usage: provider_response.usage.clone(),
                charge_applied: provider_response.charge_applied,
                charge_usd: provider_response
                    .usage
                    .as_ref()
                    .map(|usage| usage.cost_usd)
                    .unwrap_or(0.0),
                next_commitment: next_commitment.clone(),
                next_anchor,
                blind_delta_srv: blind_delta,
                upstream_ms,
                total_ms,
            });
        }

        Ok(RequestResponseV2 {
            status: "ok".to_string(),
            client_request_id: request.client_request_id.clone(),
            request_nullifier: public.request_nullifier,
            response_code: provider_response.status_code,
            response_payload: provider_response.payload,
            response_hash,
            charge_applied: provider_response.charge_applied,
            next_commitment,
            next_anchor,
            blind_delta_srv: blind_delta,
            next_state_signature: state_signature,
            policy_reason_code: None,
            policy_evidence_hash: None,
        })
    }

    pub fn openrouter_leases_enabled(&self) -> bool {
        self.config.openrouter_leases.is_some()
    }

    pub fn openrouter_lease_status(
        &self,
        client_request_id: &str,
    ) -> Option<OpenRouterLeaseStatusResponse> {
        self.store
            .lookup_openrouter_lease(client_request_id)
            .map(|lease| OpenRouterLeaseStatusResponse {
                status: lease.status,
                client_request_id: lease.client_request_id,
                issued_at: lease.issued_at,
                expires_at: lease.expires_at,
                settle_after: lease.settle_after,
                spending_limit_usd: lease.spending_limit_usd,
                usage_usd: lease.usage_usd,
                charge_applied: lease.charge_applied,
                last_error: lease.last_error,
            })
    }

    pub fn process_clearance(
        &self,
        request: &ClearanceRequest,
    ) -> Result<ClearanceResponseV2, ServerError> {
        let already_reserved = match self
            .store
            .lookup_by_nullifier(&request.withdrawal_nullifier)
        {
            Some(record) if record.status == NullifierStatus::ClearanceReserved => true,
            Some(_) => return Err(ServerError::NullifierUsed),
            None => false,
        };
        let message = core::clearance_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            &request.withdrawal_nullifier,
        );
        let signature = self.signer.sign_clearance(&message);
        if !already_reserved {
            self.store
                .reserve_clearance(&request.withdrawal_nullifier)?;
        }
        Ok(ClearanceResponseV2 {
            status: "ok".to_string(),
            withdrawal_nullifier: request.withdrawal_nullifier,
            signature,
        })
    }

    pub fn recover_by_client_id(
        &self,
        client_request_id: &str,
    ) -> Result<RecoveryResponseV2, ServerError> {
        Ok(self
            .store
            .lookup_by_client_id(client_request_id)
            .map(|record| recovery_from_record(&record))
            .unwrap_or_else(not_found_recovery))
    }

    pub fn recover_by_nullifier(
        &self,
        nullifier: &Felt252,
    ) -> Result<RecoveryResponseV2, ServerError> {
        Ok(self
            .store
            .lookup_by_nullifier(nullifier)
            .map(|record| recovery_from_record(&record))
            .unwrap_or_else(not_found_recovery))
    }

    pub fn config(&self) -> &ServerConfig {
        &self.config
    }

    pub fn store(&self) -> &Arc<NullifierStore> {
        &self.store
    }
}

fn response_from_record(
    record: &TranscriptRecord,
    client_request_id: &str,
) -> Result<RequestResponseV2, ServerError> {
    Ok(RequestResponseV2 {
        status: "ok".to_string(),
        client_request_id: client_request_id.to_string(),
        request_nullifier: record.nullifier,
        response_code: record.response_code.unwrap_or(200),
        response_payload: record.response_payload.clone().unwrap_or_default(),
        response_hash: record.response_hash.unwrap_or(Felt252::ZERO),
        charge_applied: record.charge_applied.unwrap_or(0),
        next_commitment: CurvePointWire {
            x: record.next_commitment_x.unwrap_or(Felt252::ZERO),
            y: record.next_commitment_y.unwrap_or(Felt252::ZERO),
        },
        next_anchor: record.next_anchor.unwrap_or(Felt252::ZERO),
        blind_delta_srv: record.blind_delta_srv.unwrap_or(Felt252::ZERO),
        next_state_signature: record
            .next_state_sig
            .ok_or_else(|| ServerError::Internal("stored response lacks signature".to_string()))?,
        policy_reason_code: record.policy_reason_code,
        policy_evidence_hash: record.policy_evidence_hash,
    })
}

fn recovery_from_record(record: &TranscriptRecord) -> RecoveryResponseV2 {
    let status = match record.status {
        NullifierStatus::Reserved => "reserved",
        NullifierStatus::Finalized => "finalized",
        NullifierStatus::ClearanceReserved => "clearance_reserved",
    };
    RecoveryResponseV2 {
        status: "ok".to_string(),
        nullifier_status: status.to_string(),
        request_response: (record.status == NullifierStatus::Finalized)
            .then(|| {
                response_from_record(record, record.client_request_id.as_deref().unwrap_or(""))
            })
            .transpose()
            .ok()
            .flatten(),
    }
}

fn not_found_recovery() -> RecoveryResponseV2 {
    RecoveryResponseV2 {
        status: "not_found".to_string(),
        nullifier_status: "unknown".to_string(),
        request_response: None,
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::path::PathBuf;

    use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
    use zkapi_types::RequestPublicInputsV2;

    use crate::config::OpenRouterLeaseConfig;

    fn setup_directory() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/setup/v2")
            .canonicalize()
            .unwrap()
            .to_string_lossy()
            .to_string()
    }

    fn oa_lease_processor(store: Arc<NullifierStore>) -> RequestProcessor {
        let state_seed = Felt252::from_u64(11);
        let clear_seed = Felt252::from_u64(12);
        let signer = Arc::new(ServerSigner::new(&state_seed, &clear_seed));
        RequestProcessor::try_new(
            ServerConfig {
                request_charge_cap: 1,
                contract_address: Felt252::from_u64(1),
                native_billing: Some(crate::test_support::native_config()),
                proof_setup_dir: setup_directory(),
                openrouter_leases: Some(OpenRouterLeaseConfig {
                    source: OpenRouterLeaseSourceConfig::OaOrg {
                        // No request should reach this address in the mutation
                        // tests: the bound-retry check must reject first.
                        org_base_url: "http://127.0.0.1:9".to_string(),
                        shared_secret: "test-secret".to_string(),
                    },
                    ttl_seconds: 300,
                    settlement_grace_seconds: 0,
                    settlement_poll_seconds: 1,
                }),
                ..Default::default()
            },
            store,
            signer,
            Felt252::ZERO,
        )
        .unwrap()
    }

    fn unverified_lease_request(processor: &RequestProcessor) -> ApiRequestV2 {
        let payload = crate::test_support::lease_payload(&processor.config, current_timestamp());
        let state_key = processor.state_signing_key();
        ApiRequestV2 {
            client_request_id: "pre-oa-failure-request".to_string(),
            payload_hash: canonical_payload_hash(payload.as_bytes()),
            payload,
            public_inputs: RequestPublicInputsV2 {
                protocol_version: processor.config.protocol_version,
                chain_id: processor.config.chain_id,
                contract_address: processor.config.contract_address,
                active_root: Felt252::ZERO,
                state_signing_key_x: state_key.x,
                state_signing_key_y: state_key.y,
                request_time: current_timestamp(),
                solvency_bound: 3_000_000,
                request_nullifier: Felt252::from_u64(77),
                authorization_tag: Felt252::from_u64(78),
                anonymous_commitment_x: Felt252::from_u64(79),
                anonymous_commitment_y: Felt252::from_u64(80),
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: "original-proof-that-was-verified-before-reservation".to_string(),
            },
        }
    }

    fn mutated_request(
        request: &ApiRequestV2,
        mutate: impl FnOnce(&mut ApiRequestV2),
    ) -> ApiRequestV2 {
        let mut mutation = request.clone();
        mutate(&mut mutation);
        mutation
    }

    // These lifecycle tests start at the durable boundary immediately after
    // proof verification. Proof/circuit tests separately cover admission.
    fn reserved_request(processor: &RequestProcessor) -> ApiRequestV2 {
        let mut request = unverified_lease_request(processor);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"verified-proof");
        processor.store.reserve_openrouter_lease(&request).unwrap();
        request
    }

    #[derive(Default)]
    struct IssuanceMock {
        spent: bool,
        consume_on_create: bool,
        fail_create: bool,
        policy_reject: bool,
        fail_rpc_after_create: bool,
        creates: usize,
        provider_calls: usize,
        nullifier_reads: usize,
    }

    type IssuanceMockState = Arc<std::sync::Mutex<IssuanceMock>>;

    async fn issuance_rpc(
        axum::extract::State(state): axum::extract::State<IssuanceMockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
        let mut state = state.lock().unwrap();
        if state.fail_rpc_after_create && state.creates > 0 {
            return Err(axum::http::StatusCode::SERVICE_UNAVAILABLE);
        }
        let result = if body["method"] == "eth_chainId" {
            "0x1".to_string()
        } else {
            assert_eq!(body["method"], "eth_call");
            assert_eq!(body["params"][1], "latest");
            assert_eq!(
                body["params"][0]["to"],
                "0x0000000000000000000000000000000000000001"
            );
            let selector = Keccak256::digest(b"usedNullifiers(uint256)");
            assert_eq!(
                body["params"][0]["data"],
                format!("0x{}{:064x}", hex::encode(&selector[..4]), 77)
            );
            state.nullifier_reads += 1;
            format!("0x{:064x}", u8::from(state.spent))
        };
        Ok(axum::Json(
            serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}),
        ))
    }

    fn configure_issuance_rpc(processor: &mut RequestProcessor, url: String) {
        let config = processor.config.native_billing.as_mut().unwrap();
        config.rpc_url = url;
        processor.native_oracle = NativeBillingOracle::new(
            config.clone(),
            processor.config.chain_id,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
    }

    async fn unspent_rpc(processor: &mut RequestProcessor) -> tokio::task::JoinHandle<()> {
        let app = axum::Router::new()
            .route("/", axum::routing::post(issuance_rpc))
            .with_state(Arc::new(std::sync::Mutex::new(IssuanceMock::default())));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() })
    }

    async fn issuance_processor(
        oa: bool,
        state: IssuanceMockState,
    ) -> (RequestProcessor, ApiRequestV2, tokio::task::JoinHandle<()>) {
        use axum::{
            extract::State,
            http::StatusCode,
            routing::{get, post},
            Json, Router,
        };
        use serde_json::{json, Value};
        async fn create(
            State(state): State<IssuanceMockState>,
            Json(body): Json<Value>,
        ) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            state.creates += 1;
            if state.fail_create {
                state.fail_create = false;
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"detail":"unavailable"})),
                ));
            }
            if state.policy_reject {
                return Err((
                    StatusCode::BAD_REQUEST,
                    Json(json!({"detail":"credit_limit exceeds zkAPI policy"})),
                ));
            }
            state.spent |= state.consume_on_create;
            let response = if body.get("credit_limit").is_some() {
                json!({"source":"oa_org", "key":"runtime-key", "key_hash":"test-hash",
                    "credit_limit":body["credit_limit"], "duration_minutes":body["duration_minutes"],
                    "expires_at_unix":current_timestamp()+300,
                    "station_id":"station", "station_recently_attested":true,
                    "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64),
                    "verifier_url":"https://verifier.example", "openrouter_api_base":"https://openrouter.ai/api/v1"})
            } else {
                json!({"key":"runtime-key", "data":{"hash":"test-hash", "name":body["name"],
                    "limit":body["limit"], "expires_at":body["expires_at"], "include_byok_in_limit":true}})
            };
            Ok(Json(response))
        }
        async fn list(State(state): State<IssuanceMockState>) -> Json<Value> {
            state.lock().unwrap().provider_calls += 1;
            Json(json!({"data":[]}))
        }
        let app = Router::new()
            .route("/rpc", post(issuance_rpc))
            .route("/v1/keys", get(list).post(create))
            .route("/api/zkapi/request_key", post(create))
            .route(
                "/api/zkapi/reconcile_key",
                post(|Json(body): Json<Value>| async move {
                    Json(json!({"source":"oa_org", "version":1, "status":"unknown",
                    "client_request_id":body["client_request_id"]}))
                }),
            )
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        configure_issuance_rpc(&mut processor, format!("{url}/rpc"));
        if oa {
            processor.oa_org = Some(Arc::new(
                OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
            ));
        } else {
            processor.config.openrouter_leases.as_mut().unwrap().source =
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "test-secret".into(),
                    api_base: url.clone(),
                };
            processor.openrouter = Some(Arc::new(
                OpenRouterProvisioner::new("test-secret".into(), url).unwrap(),
            ));
            processor.oa_org = None;
        }
        // Resume at the durable verified boundary, with a frozen quote and
        // request that have aged out. The admission proof tests are separate.
        let mut request = unverified_lease_request(&processor);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.payload = crate::test_support::lease_payload(&processor.config, 100);
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.request_time = 100;
        request.proof.proof = base64::engine::general_purpose::STANDARD.encode(b"verified-proof");
        store.reserve_openrouter_lease(&request).unwrap();
        let id = oa.then(|| RequestProcessor::native_oa_request_id(&request).unwrap());
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                if oa { "oa_org" } else { "openrouter" },
                100,
                400,
                400,
                3.0,
                id.as_deref(),
            )
            .unwrap();
        (processor, request, server)
    }

    #[tokio::test]
    async fn expired_issued_provisioning_recovers_metadata_and_charges_actual_usage() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, old_server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        let expected_id = RequestProcessor::native_oa_request_id(&request).unwrap();
        let expected_cap = processor.lease_limit_micro_usd(&request).unwrap();
        let expected_usd = pricing::micro_usd_to_usd(expected_cap);
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let reconciliation_seen = seen.clone();
        let usage_seen = seen.clone();
        let reconciliation_id = expected_id.clone();
        let app = Router::new()
            .route("/api/zkapi/reconcile_key", post(move |headers: axum::http::HeaderMap, Json(body): Json<Value>| {
                let seen = reconciliation_seen.clone();
                let expected_id = reconciliation_id.clone();
                async move {
                    assert_eq!(headers["authorization"], "Bearer test-secret");
                    assert_eq!(body["client_request_id"], expected_id);
                    assert_eq!(body["credit_limit_credits"], json!(expected_cap));
                    assert_eq!(body["credit_limit"], expected_usd);
                    assert_eq!(body["duration_minutes"], 5);
                    seen.lock().unwrap().push("reconcile".into());
                    Json(json!({"source":"oa_org", "version":1, "status":"issued",
                        "client_request_id":body["client_request_id"], "station_request_id":crate::oa_org::station_request_id(body["client_request_id"].as_str().unwrap()),
                        "key_hash":"recovered-hash", "credit_limit":body["credit_limit"],
                        "credit_limit_credits":body["credit_limit_credits"], "duration_minutes":5,
                        "expires_at_unix":600, "station_id":"saved-station"}))
                }
            }))
            .route("/api/zkapi/key_usage", post(move |Json(body): Json<Value>| {
                let seen = usage_seen.clone();
                async move {
                    assert_eq!(body["key_hash"], "recovered-hash");
                    assert_eq!(body["expires_at_unix"], 600);
                    let first_usage = {
                        let mut calls = seen.lock().unwrap();
                        let first = !calls.iter().any(|call| call == "usage");
                        calls.push("usage".into());
                        first
                    };
                    if first_usage {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            Json(json!({"detail":"usage temporarily unavailable"})));
                    }
                    (axum::http::StatusCode::OK, Json(json!({"source":"oa_org", "version":1, "status":"finalized",
                        "client_request_id":body["client_request_id"], "station_request_id":"ab".repeat(32),
                        "key_hash":"recovered-hash", "usage_credits":1_000_000,
                        "credit_limit_credits":body["credit_limit_credits"], "expires_at_unix":600,
                        "closed_at_unix":550, "finalized_at_unix":601, "station_id":"saved-station",
                        "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64)})))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-secret".into(),
            )
            .unwrap(),
        ));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        processor.settle_due_openrouter_leases().await;
        let interrupted = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(interrupted.status, "active");
        assert_eq!(interrupted.key_hash.as_deref(), Some("recovered-hash"));
        assert_eq!(interrupted.expires_at, 570);
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        // Resume from the durable metadata boundary without reconciliation,
        // replaying issuance, or changing the original quote.
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.key_hash.as_deref(), Some("recovered-hash"));
        assert_eq!(lease.expires_at, 570);
        let expected_charge = processor.lease_charge_units(&request, 1_000_000).unwrap();
        assert!(expected_charge > 0);
        assert_eq!(lease.charge_applied, Some(expected_charge));
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert!(record.next_state_sig.is_some());
        let payload: Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["type"], "oa_org_ephemeral_lease_settlement");
        assert_eq!(payload["usage_credits"], 1_000_000);
        assert_eq!(
            payload["billing_quote"],
            serde_json::from_str::<Value>(&request.payload).unwrap()["billing_quote"]
        );
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(*seen.lock().unwrap(), vec!["reconcile", "usage", "usage"]);
        assert_eq!(state.lock().unwrap().creates, 0);
        old_server.abort();
        server.abort();
    }

    #[tokio::test]
    async fn unknown_issuer_binding_retains_ambiguous_reservation_without_reissuing() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert!(lease.key_hash.is_none());
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(record.next_state_sig.is_none());
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn definitive_first_rejection_finalizes_zero_charge_and_never_reissues() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            policy_reject: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_ref().unwrap()).unwrap();
        assert_eq!(payload["type"], "oa_org_unissued_lease_cancellation");
        assert_eq!(payload["issued"], false);
        assert_eq!(
            payload["billing_quote"],
            serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
        );
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        let again = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(again.next_state_sig, record.next_state_sig);
        assert_eq!(state.lock().unwrap().creates, 1);
        server.abort();
    }

    #[tokio::test]
    async fn later_policy_rejection_cannot_erase_earlier_issuance_uncertainty() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            policy_reject: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.status, "provisioning");
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        assert_eq!(state.lock().unwrap().creates, 2);
        server.abort();
    }

    #[tokio::test]
    async fn confirmed_rejection_survives_failed_finalization_then_background_recovers() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            policy_reject: true,
            fail_rpc_after_create: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(processor.issue_openrouter_lease(&request).await.is_err());
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert_eq!(lease.status, "provisioning");
        state.lock().unwrap().fail_rpc_after_create = false;
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 1);
        server.abort();
    }

    #[tokio::test]
    async fn unstarted_retirement_preserves_exact_binding_and_waits_for_issuance_lock() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        let mut changed = request.clone();
        changed.proof.proof.push('x');
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &changed)
                .await,
            Err(ServerError::InvalidRequest(_))
        ));
        let guard = processor.lease_issue_lock.lock().await;
        assert!(tokio::time::timeout(
            std::time::Duration::from_millis(20),
            processor.retire_openrouter_lease(&request.client_request_id, &request)
        )
        .await
        .is_err());
        drop(guard);
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_reconciles_existing_signed_transcript_after_crash() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap());
        processor
            .store
            .confirm_oa_unissued(&request.client_request_id)
            .unwrap();
        let signed = processor.finalize_request(&request, SettlementResult {
            status_code: 200,
            payload: processor.settlement_payload(&request, serde_json::json!({
                "type":"oa_org_unissued_lease_cancellation", "issued":false, "usage_credits":0
            })).unwrap(),
            charge_applied: 0, usage: None, billing_label: "test".into(),
        }, 0, 0).unwrap();
        processor.settle_due_openrouter_leases().await;
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.next_state_sig, Some(signed.next_state_signature));
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn stalled_active_usage_does_not_block_new_issuance() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc_server) = issuance_processor(true, state).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "issued-hash")
            .unwrap();
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        let started_handler = started.clone();
        let release_handler = release.clone();
        let app = axum::Router::new().route(
            "/api/zkapi/key_usage",
            axum::routing::post(move || {
                let started = started_handler.clone();
                let release = release_handler.clone();
                async move {
                    started.notify_one();
                    release.notified().await;
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(
                format!("http://{}", listener.local_addr().unwrap()),
                "test-secret".into(),
            )
            .unwrap(),
        ));
        let usage_server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let processor = Arc::new(processor);
        let scanning = processor.clone();
        let scan = tokio::spawn(async move {
            scanning.settle_due_openrouter_leases().await;
        });
        tokio::time::timeout(std::time::Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        let guard = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            processor.lease_issue_lock.lock(),
        )
        .await
        .expect("active usage blocked issuance");
        drop(guard);
        release.notify_one();
        scan.await.unwrap();
        rpc_server.abort();
        usage_server.abort();
    }

    #[tokio::test]
    async fn failed_issuance_cannot_retry_after_withdrawal_consumes_its_nullifier() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
                fail_create: true,
                ..Default::default()
            }));
            let (processor, request, server) = issuance_processor(oa, state.clone()).await;
            assert!(matches!(
                processor.issue_openrouter_lease(&request).await,
                Err(ServerError::Internal(_))
            ));
            let provider_calls = {
                let mut state = state.lock().unwrap();
                assert_eq!(state.creates, 1);
                state.spent = true;
                state.provider_calls
            };
            assert!(matches!(
                processor.issue_openrouter_lease(&request).await,
                Err(ServerError::NullifierUsed)
            ));
            assert_eq!(state.lock().unwrap().provider_calls, provider_calls);
            let reserved = processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap();
            assert_eq!(reserved.status, NullifierStatus::Reserved);
            assert_eq!(
                reserved.api_request_binding.as_deref(),
                Some(api_request_binding(&request).unwrap().as_str())
            );
            assert!(
                crate::watcher::ChallengeWatcher::new(processor.store.clone())
                    .challenge_transcript(&request.public_inputs.request_nullifier)
                    .is_none()
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn collateral_change_during_issuance_never_exposes_key_and_retains_evidence() {
        for oa in [false, true] {
            for rpc_failure in [false, true] {
                let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
                    consume_on_create: !rpc_failure,
                    fail_rpc_after_create: rpc_failure,
                    ..Default::default()
                }));
                let (processor, request, server) = issuance_processor(oa, state.clone()).await;
                let result = processor.issue_openrouter_lease(&request).await;
                if rpc_failure {
                    assert!(matches!(result, Err(ServerError::Internal(_))));
                } else {
                    assert!(matches!(result, Err(ServerError::NullifierUsed)));
                }
                assert_eq!(state.lock().unwrap().creates, 1);
                let lease = processor
                    .store
                    .lookup_openrouter_lease(&request.client_request_id)
                    .unwrap();
                assert_eq!(lease.status, "active");
                assert_eq!(lease.key_hash.as_deref(), Some("test-hash"));
                assert_eq!(
                    api_request_binding(&lease.api_request).unwrap(),
                    api_request_binding(&request).unwrap()
                );
                assert!(
                    crate::watcher::ChallengeWatcher::new(processor.store.clone())
                        .challenge_transcript(&request.public_inputs.request_nullifier)
                        .is_some()
                );
                // Recovery of already activated access needs no fresh chain
                // read and cannot repeat provider issuance after either error.
                assert!(matches!(
                    processor.issue_openrouter_lease(&request).await,
                    Err(ServerError::LeasePending)
                ));
                assert_eq!(state.lock().unwrap().creates, 1);
                server.abort();
            }
        }
    }

    #[tokio::test]
    async fn unspent_reserved_retry_keeps_frozen_quote_after_unrelated_root_change() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
            let (processor, request, server) = issuance_processor(oa, state.clone()).await;
            processor.update_root(Felt252::from_u64(999));
            let quote = processor.lease_authorization(&request).unwrap().1;
            assert!(quote.expires_at < current_timestamp());
            let issued = processor.issue_openrouter_lease(&request).await.unwrap();
            assert_eq!(issued.lease.api_key, "runtime-key");
            assert_eq!(issued.billing_quote, quote);
            assert_eq!(issued.lease.spending_limit_usd, 3.0);
            let state = state.lock().unwrap();
            assert_eq!(state.creates, 1);
            assert_eq!(state.nullifier_reads, 2);
            server.abort();
        }
    }

    #[derive(Default)]
    struct RetirementMock {
        disabled: bool,
        deleted: bool,
        fail_disable: bool,
        fail_delete: bool,
        lose_delete_response: bool,
        fail_usage: bool,
        usage: f64,
        events: Vec<&'static str>,
    }

    async fn retirement_processor(
        state: Arc<std::sync::Mutex<RetirementMock>>,
        grace: u64,
        database_path: Option<&std::path::Path>,
    ) -> (RequestProcessor, ApiRequestV2, tokio::task::JoinHandle<()>) {
        use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
        type MockState = Arc<std::sync::Mutex<RetirementMock>>;
        async fn disable(
            State(state): State<MockState>,
            Json(body): Json<serde_json::Value>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            assert_eq!(body["disabled"], true);
            let mut state = state.lock().unwrap();
            state.events.push("disable");
            if state.fail_disable {
                state.fail_disable = false;
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            state.disabled = true;
            Ok(Json(serde_json::json!({"data": {"disabled": true}})))
        }
        async fn usage(
            State(state): State<MockState>,
        ) -> Result<Json<serde_json::Value>, StatusCode> {
            let mut state = state.lock().unwrap();
            state.events.push("usage");
            assert!(state.disabled, "usage must be read after spending stops");
            assert!(!state.deleted, "usage is unavailable after deletion");
            if state.fail_usage {
                state.fail_usage = false;
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            Ok(Json(
                serde_json::json!({"data": {"disabled": state.disabled, "usage": state.usage, "byok_usage": 0.0}}),
            ))
        }
        async fn delete(State(state): State<MockState>) -> StatusCode {
            let mut state = state.lock().unwrap();
            state.events.push("delete");
            assert!(state.disabled);
            if state.fail_delete {
                state.fail_delete = false;
                state.deleted = state.lose_delete_response;
                return StatusCode::SERVICE_UNAVAILABLE;
            }
            if state.deleted {
                return StatusCode::NOT_FOUND;
            }
            state.deleted = true;
            StatusCode::NO_CONTENT
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route(
                "/v1/keys/test-hash",
                get(usage).patch(disable).delete(delete),
            )
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let store = Arc::new(match database_path {
            Some(path) => NullifierStore::new(path).unwrap(),
            None => NullifierStore::in_memory().unwrap(),
        });
        let mut processor = oa_lease_processor(store.clone());
        let config = processor.config.openrouter_leases.as_mut().unwrap();
        config.source = OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: "test".to_string(),
            api_base: url.clone(),
        };
        config.settlement_grace_seconds = grace;
        processor.openrouter = Some(Arc::new(
            OpenRouterProvisioner::new("test".to_string(), url).unwrap(),
        ));
        processor.oa_org = None;
        let request = reserved_request(&processor);
        let now = current_timestamp();
        store
            .create_openrouter_lease(
                &request,
                "openrouter",
                now,
                now + 300,
                now + 300 + grace,
                3.0,
            )
            .unwrap();
        store
            .activate_openrouter_lease(&request.client_request_id, "test-hash")
            .unwrap();
        (processor, request, server)
    }

    #[tokio::test]
    async fn failed_key_deletion_never_signs_and_background_retry_recovers() {
        for lose_delete_response in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(RetirementMock {
                usage: 0.000002,
                fail_delete: true,
                lose_delete_response,
                ..Default::default()
            }));
            let db_path =
                std::env::temp_dir().join(format!("zkapi-retirement-{}.db", uuid::Uuid::new_v4()));
            let (processor, request, server) =
                retirement_processor(state.clone(), 0, Some(&db_path)).await;
            assert!(processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .is_err());
            let store = &processor.store;
            assert_eq!(
                store
                    .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                    .unwrap()
                    .status,
                NullifierStatus::Reserved
            );
            let lease = store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "revoking");
            assert_eq!(lease.usage_usd, Some(0.000002));
            assert!(lease.last_error.is_some());
            assert_eq!(store.due_openrouter_leases(current_timestamp()).len(), 1);
            assert!(state.lock().unwrap().disabled);
            assert_eq!(state.lock().unwrap().deleted, lose_delete_response);
            // Reopen SQLite with a fresh processor: both a still-existing key
            // and a lost successful DELETE must resume from durable usage.
            let config = processor.config.clone();
            let signer = processor.signer.clone();
            drop(processor);
            let store = Arc::new(NullifierStore::new(&db_path).unwrap());
            let processor =
                RequestProcessor::try_new(config, store.clone(), signer, Felt252::ZERO).unwrap();
            processor.settle_due_openrouter_leases().await;
            let response = processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .unwrap();
            assert_eq!(response.status, "finalized");
            assert_eq!(
                store
                    .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                    .unwrap()
                    .charge_applied,
                Some(2)
            );
            assert_eq!(
                state.lock().unwrap().events,
                ["disable", "usage", "delete", "delete"]
            );
            server.abort();
            drop(processor);
            drop(store);
            std::fs::remove_file(db_path).unwrap();
        }
    }

    #[tokio::test]
    async fn retirement_disable_and_usage_failures_remain_retryable() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000003,
            fail_disable: true,
            fail_usage: true,
            ..Default::default()
        }));
        let (processor, request, server) = retirement_processor(state.clone(), 0, None).await;
        assert!(processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .is_err());
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "retiring"
        );
        assert!(!state.lock().unwrap().disabled);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "disabled"
        );
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(
            state.lock().unwrap().events,
            ["disable", "disable", "usage", "usage", "delete"]
        );
        server.abort();
    }

    #[tokio::test]
    async fn early_retirement_waits_for_usage_reconciliation_after_disabling() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, request, server) = retirement_processor(state.clone(), 60, None).await;
        assert!(matches!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeaseSettlementPending { .. })
        ));
        assert_eq!(state.lock().unwrap().events, ["disable"]);
        assert!(processor
            .store
            .due_openrouter_leases(current_timestamp())
            .is_empty());
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        // Simulate delayed billing becoming visible during the drain interval.
        state.lock().unwrap().usage = 0.000005;
        processor
            .store
            .advance_openrouter_retirement(
                &request.client_request_id,
                "disabled",
                "disabled",
                0,
                None,
            )
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .charge_applied,
            Some(5)
        );
        assert_eq!(state.lock().unwrap().events, ["disable", "usage", "delete"]);
        server.abort();
    }

    #[test]
    fn removed_proof_backends_are_rejected_on_the_wire() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let mut request = serde_json::to_value(unverified_lease_request(&processor)).unwrap();
        request["proof"]["backend"] = "stwo_cairo".into();
        assert!(serde_json::from_value::<ApiRequestV2>(request).is_err());
    }

    #[tokio::test]
    async fn pre_oa_failure_rejects_every_mutated_reserved_retry() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = oa_lease_processor(store.clone());
        let request = unverified_lease_request(&processor);
        let original_limit =
            pricing::micro_usd_to_usd(processor.lease_limit_micro_usd(&request).unwrap());

        // This is the durable state left after proof verification and lease
        // reservation but before OA successfully returns a key.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease(&request, "oa_org", 100, 400, 400, original_limit)
            .unwrap();

        // A byte-identical transport retry remains resumable even though its
        // proof is not verified a second time.
        assert!(processor.validate_and_reserve(&request).unwrap().is_none());

        let changed_payload = format!(" {}", request.payload);
        let binding_replay_mutations = vec![
            (
                "client_request_id",
                mutated_request(&request, |value| {
                    value.client_request_id = "different-request-id".to_string()
                }),
            ),
            (
                "payload_and_payload_hash",
                mutated_request(&request, |value| {
                    value.payload = changed_payload.to_string();
                    value.payload_hash = canonical_payload_hash(changed_payload.as_bytes());
                }),
            ),
            (
                "active_root",
                mutated_request(&request, |value| {
                    value.public_inputs.active_root = Felt252::from_u64(901)
                }),
            ),
            (
                "state_signing_key_x",
                mutated_request(&request, |value| {
                    value.public_inputs.state_signing_key_x = Felt252::from_u64(902)
                }),
            ),
            (
                "state_signing_key_y",
                mutated_request(&request, |value| {
                    value.public_inputs.state_signing_key_y = Felt252::from_u64(903)
                }),
            ),
            (
                "request_time",
                mutated_request(&request, |value| value.public_inputs.request_time = 1),
            ),
            (
                "solvency_bound",
                mutated_request(&request, |value| {
                    value.public_inputs.solvency_bound = u128::MAX
                }),
            ),
            (
                "authorization_tag",
                mutated_request(&request, |value| {
                    value.public_inputs.authorization_tag = Felt252::from_u64(904)
                }),
            ),
            (
                "anonymous_commitment_x",
                mutated_request(&request, |value| {
                    value.public_inputs.anonymous_commitment_x = Felt252::from_u64(905)
                }),
            ),
            (
                "anonymous_commitment_y",
                mutated_request(&request, |value| {
                    value.public_inputs.anonymous_commitment_y = Felt252::from_u64(906)
                }),
            ),
            (
                "proof_string",
                mutated_request(&request, |value| {
                    value.proof.proof = "garbage-not-a-proof".to_string()
                }),
            ),
        ];
        let original_binding = api_request_binding(&request).unwrap();
        for (field, mutation) in binding_replay_mutations {
            assert_ne!(
                api_request_binding(&mutation).unwrap(),
                original_binding,
                "{field} was not covered by the complete request binding"
            );
            let result = processor.issue_openrouter_lease(&mutation).await;
            assert!(
                matches!(
                    &result,
                    Err(ServerError::Replay | ServerError::InvalidRequest(_))
                ),
                "reserved retry mutation in {field} was not rejected: {}",
                result
                    .err()
                    .map(|error| error.to_string())
                    .unwrap_or_else(|| "unexpected success".to_string())
            );
        }

        for (field, mutation) in [
            (
                "protocol_version",
                mutated_request(&request, |value| value.public_inputs.protocol_version += 1),
            ),
            (
                "chain_id",
                mutated_request(&request, |value| value.public_inputs.chain_id += 1),
            ),
            (
                "contract_address",
                mutated_request(&request, |value| {
                    value.public_inputs.contract_address = Felt252::from_u64(907)
                }),
            ),
        ] {
            assert_ne!(api_request_binding(&mutation).unwrap(), original_binding);
            let error = processor
                .issue_openrouter_lease(&mutation)
                .await
                .err()
                .unwrap_or_else(|| panic!("{field} mutation unexpectedly succeeded"));
            assert!(
                matches!(
                    &error,
                    ServerError::ProtocolMismatch(_) | ServerError::Replay
                ),
                "{field} mutation returned {error}"
            );
        }

        let payload_only = mutated_request(&request, |value| {
            value.payload = changed_payload.to_string()
        });
        let payload_hash_only = mutated_request(&request, |value| {
            value.payload_hash = Felt252::from_u64(908)
        });
        for (field, mutation) in [
            ("payload", payload_only),
            ("payload_hash", payload_hash_only),
        ] {
            assert_ne!(api_request_binding(&mutation).unwrap(), original_binding);
            let error = processor
                .issue_openrouter_lease(&mutation)
                .await
                .err()
                .unwrap_or_else(|| panic!("{field} mutation unexpectedly succeeded"));
            assert!(
                matches!(&error, ServerError::InvalidRequest(_) | ServerError::Replay),
                "{field} mutation returned {error}"
            );
        }

        let changed_nullifier = mutated_request(&request, |value| {
            value.public_inputs.request_nullifier = Felt252::from_u64(909)
        });
        assert_ne!(
            api_request_binding(&changed_nullifier).unwrap(),
            original_binding
        );
        let error = processor
            .issue_openrouter_lease(&changed_nullifier)
            .await
            .err()
            .expect("request_nullifier mutation unexpectedly succeeded");
        assert!(
            matches!(&error, ServerError::Replay),
            "request_nullifier mutation returned {error}"
        );

        let lease = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.api_request.public_inputs.solvency_bound,
            request.public_inputs.solvency_bound
        );
        assert_eq!(lease.spending_limit_usd.to_bits(), original_limit.to_bits());
        assert_eq!(lease.status, "provisioning");
        assert!(lease.key_hash.is_none());
    }
    #[test]
    fn native_oa_namespace_is_deployment_and_full_request_bound_and_persisted() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        let request = unverified_lease_request(&processor);
        let id = RequestProcessor::native_oa_request_id(&request).unwrap();
        assert_eq!(
            id,
            RequestProcessor::native_oa_request_id(&request.clone()).unwrap()
        );
        assert_eq!(id.len(), 73);
        for mutate in [
            (|r: &mut ApiRequestV2| r.public_inputs.chain_id += 1) as fn(&mut ApiRequestV2),
            |r| r.public_inputs.contract_address = Felt252::from_u64(999),
            |r| r.public_inputs.request_nullifier = Felt252::from_u64(998),
            |r| r.proof.proof.push('x'),
            |r| r.client_request_id.push('x'),
        ] {
            let mut different = request.clone();
            mutate(&mut different);
            assert_ne!(
                id,
                RequestProcessor::native_oa_request_id(&different).unwrap()
            );
        }
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(&request, "oa_org", 1, 2, 3, 1.0, Some(&id))
            .unwrap();
        let saved = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(saved.oa_client_request_id.as_deref(), Some(id.as_str()));
        assert_eq!(saved.client_request_id, request.client_request_id);
        assert_eq!(processor.persisted_oa_request_id(&saved).unwrap(), id);
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        });
        assert_eq!(processor.persisted_oa_request_id(&saved).unwrap(), id);
        let mut corrupted = saved.clone();
        corrupted.oa_client_request_id = None;
        assert!(processor.persisted_oa_request_id(&corrupted).is_err());
        corrupted.oa_client_request_id = Some("different-deployment".into());
        assert!(processor.persisted_oa_request_id(&corrupted).is_err());
    }

    #[tokio::test]
    async fn native_oa_issuance_and_usage_use_same_persisted_upstream_namespace() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let seen = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let issuance_seen = seen.clone();
        let usage_seen = seen.clone();
        let now = current_timestamp();
        let app = Router::new()
            .route("/api/zkapi/request_key", post(move |Json(body): Json<Value>| {
                let seen = issuance_seen.clone();
                async move {
                    seen.lock().unwrap().push(body["client_request_id"].as_str().unwrap().into());
                    Json(json!({"source":"oa_org", "key":"runtime-key", "key_hash":"key-hash",
                        "credit_limit":1.0, "duration_minutes":5, "expires_at_unix":now+300,
                        "station_id":"station", "station_recently_attested":true,
                        "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64),
                        "verifier_url":"https://verifier.example", "openrouter_api_base":"https://openrouter.ai/api/v1"}))
                }
            }))
            .route("/api/zkapi/key_usage", post(move |Json(body): Json<Value>| {
                let seen = usage_seen.clone();
                async move {
                    seen.lock().unwrap().push(body["client_request_id"].as_str().unwrap().into());
                    Json(json!({"source":"oa_org", "version":1, "status":"pending",
                        "client_request_id":body["client_request_id"], "key_hash":"key-hash",
                        "station_request_id":"ab".repeat(32), "retry_after_seconds":1}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        });
        let chain_server = unspent_rpc(&mut processor).await;
        let mut request = unverified_lease_request(&processor);
        request.payload = json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
            "asset":"native_eth","units_per_eth":1_000_000_000,"chain_id":1,
            "feed_address":"0x694aa1769357215de4fac081bf1f309adc325306","round_id":"123",
            "answer":"250000000000","decimals":8,"updated_at":now,"expires_at":now+4500
        }})
        .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        let id = RequestProcessor::native_oa_request_id(&request).unwrap();
        // Resume at the already-verified durable boundary, avoiding mock proofs
        // at admission; the real-proof tests separately cover that boundary.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                now,
                now + 300,
                now + 300,
                1.0,
                Some(&id),
            )
            .unwrap();
        let issued = processor.issue_openrouter_lease(&request).await.unwrap();
        assert_eq!(issued.lease.client_request_id, request.client_request_id);
        let saved = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert!(matches!(
            processor.settle_oa_org_lease(&saved).await,
            Err(ServerError::LeaseSettlementPending { .. })
        ));
        assert_eq!(*seen.lock().unwrap(), vec![id.clone(), id]);
        assert_eq!(
            store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "active"
        );
        server.abort();
        chain_server.abort();
    }

    #[tokio::test]
    async fn native_lease_persists_frozen_quote_and_rejects_missing_or_changed_quotes() {
        use crate::native_billing::NativeBillingConfig;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let chain_server = unspent_rpc(&mut processor).await;
        let mut request = unverified_lease_request(&processor);
        request.payload = serde_json::to_string(&OpenRouterLeaseAuthorization::default()).unwrap();
        assert!(processor.lease_authorization(&request).is_err());
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at: 100,
            expires_at: 3700,
        };
        request.payload = serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote}).to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        assert_eq!(
            processor.lease_limit_micro_usd(&request).unwrap(),
            1_000_000
        );
        assert_eq!(
            processor.lease_charge_units(&request, 123_456).unwrap(),
            49_383
        );
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteExpired)
        ));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        let expired = processor
            .expire_unaccepted_native_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(expired["status"], "expired_unaccepted");
        assert_eq!(
            expired["payload_hash"],
            serde_json::to_value(request.payload_hash).unwrap()
        );
        assert_eq!(
            expired["request_nullifier"],
            serde_json::to_value(request.public_inputs.request_nullifier).unwrap()
        );
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        // An expiry check must wait behind in-flight issuance. Simulate that
        // issuer accepting the request before it releases the shared lock.
        let issuance_guard = processor.lease_issue_lock.lock().await;
        let expiry_check =
            processor.expire_unaccepted_native_lease(&request.client_request_id, &request);
        tokio::pin!(expiry_check);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut expiry_check)
                .await
                .is_err()
        );
        store.reserve_openrouter_lease(&request).unwrap();
        drop(issuance_guard);
        assert!(matches!(expiry_check.await, Err(ServerError::LeasePending)));
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                100,
                400,
                400,
                1.0,
                Some(&RequestProcessor::native_oa_request_id(&request).unwrap()),
            )
            .unwrap();
        let restored = store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            processor
                .lease_authorization(&restored.api_request)
                .unwrap()
                .1,
            quote.clone()
        );
        // Retry must reach the unavailable issuer, not fetch/reprice an expired
        // round. This confirms that a restarted lease uses its persisted quote.
        let error = processor
            .issue_openrouter_lease(&restored.api_request)
            .await
            .err()
            .unwrap();
        assert!(
            !error.to_string().contains("stale") && !error.to_string().contains("oracle"),
            "{error}"
        );
        let mut collision = restored.api_request.clone();
        collision.public_inputs.request_nullifier = Felt252::from_u64(999);
        assert!(matches!(
            processor.issue_openrouter_lease(&collision).await,
            Err(ServerError::Replay)
        ));
        assert!(store
            .lookup_by_nullifier(&collision.public_inputs.request_nullifier)
            .is_none());
        let mut mutation = restored.api_request.clone();
        let mut payload: serde_json::Value = serde_json::from_str(&mutation.payload).unwrap();
        payload["billing_quote"]["answer"] = "500000000000".into();
        mutation.payload = payload.to_string();
        mutation.payload_hash = canonical_payload_hash(mutation.payload.as_bytes());
        assert!(matches!(
            processor.issue_openrouter_lease(&mutation).await,
            Err(ServerError::Replay)
        ));
        let mut missing_config = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        missing_config.config.native_billing = None;
        assert!(missing_config.lease_authorization(&request).is_err());
        chain_server.abort();
    }
    #[tokio::test]
    async fn native_issuance_rechecks_expiry_after_delayed_oracle_read() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::time::Duration;
        use tokio::sync::Notify;

        let expires_at = current_timestamp() + 5;
        let updated_at = expires_at - 3600;
        let oracle_read_started = Arc::new(Notify::new());
        let finish_oracle_read = Arc::new(Notify::new());
        let started = oracle_read_started.clone();
        let finish = finish_oracle_read.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let started = started.clone();
                let finish = finish.clone();
                async move {
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else {
                        assert_eq!(request["params"][1], "finalized");
                        if data.starts_with("0x9a6fc8f5") {
                            started.notify_one();
                            finish.notified().await;
                        } else {
                            assert_eq!(data, "0xfeaf968c");
                        }
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            123, 250_000_000_000u64, updated_at, updated_at, 123
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let processor = Arc::new(processor);
        let mut request = unverified_lease_request(&processor);
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at,
            expires_at,
        };
        request.payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        let issuer = processor.clone();
        let issued_request = request.clone();
        let issuance =
            tokio::spawn(async move { issuer.issue_openrouter_lease(&issued_request).await });
        tokio::time::timeout(Duration::from_secs(10), oracle_read_started.notified())
            .await
            .unwrap();
        while current_timestamp() < expires_at {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        finish_oracle_read.notify_one();
        let result = tokio::time::timeout(Duration::from_secs(5), issuance)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(ServerError::NativeQuoteExpired)));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert!(store
            .lookup_openrouter_lease(&request.client_request_id)
            .is_none());
        assert_eq!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await
                .unwrap()["status"],
            "expired_unaccepted"
        );
        server.abort();
    }
    #[tokio::test]
    async fn native_issuance_uses_latest_finalized_round_and_recovers_superseded_request() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::sync::atomic::{AtomicU64, Ordering};

        let updated_at = current_timestamp() - 30;
        let finalized_round = Arc::new(AtomicU64::new(123));
        let head_round = Arc::new(AtomicU64::new(124));
        let rpc_finalized = finalized_round.clone();
        let rpc_head = head_round.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let finalized = rpc_finalized.clone();
                let head = rpc_head.clone();
                async move {
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else if data.starts_with("0xaad24061") {
                        assert_eq!(request["params"][1], "latest");
                        format!("0x{:064x}", 0)
                    } else {
                        let latest = if request["params"][1] == "finalized" {
                            finalized.load(Ordering::SeqCst)
                        } else {
                            head.load(Ordering::SeqCst)
                        };
                        let round = if data == "0xfeaf968c" {
                            latest
                        } else {
                            assert!(data.starts_with("0x9a6fc8f5"));
                            let round = u64::from_str_radix(&data[10..], 16).unwrap();
                            assert!(round <= latest);
                            round
                        };
                        let price = if round == 123 {
                            250_000_000_000u64
                        } else {
                            200_000_000_000u64
                        };
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            round, price, updated_at, updated_at, round
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store.clone());
        processor.config.contract_address = Felt252::from_u64(1);
        let config = NativeBillingConfig {
            rpc_url,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 4500,
        };
        processor.config.native_billing = Some(config.clone());
        processor.native_oracle = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        let oracle = &processor.native_oracle;
        let quote = oracle.quote(current_timestamp()).await.unwrap();
        assert_eq!(
            quote.round_id, "123",
            "head-only round must not influence pricing"
        );
        oracle.validate(&quote, current_timestamp()).await.unwrap();
        let mut request = unverified_lease_request(&processor);
        request.payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.solvency_bound = 400_000;
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        // Proof construction used round123. Once round124 finalizes, a new
        // issuance cannot choose the more favorable historical price123.
        finalized_round.store(124, Ordering::SeqCst);
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteSuperseded)
        ));
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        let ack = processor
            .expire_unaccepted_native_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(ack["status"], "superseded_unaccepted");
        assert_eq!(
            ack["payload_hash"],
            serde_json::to_value(request.payload_hash).unwrap()
        );
        assert_eq!(
            ack["request_nullifier"],
            serde_json::to_value(request.public_inputs.request_nullifier).unwrap()
        );
        // A normal head reorg cannot revive an acknowledged old finalized quote.
        head_round.store(123, Ordering::SeqCst);
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NativeQuoteSuperseded)
        ));
        // Simulate a previously accepted request from before finality advanced:
        // recovery never discards it and measured usage uses its frozen price.
        store.reserve_openrouter_lease(&request).unwrap();
        store
            .create_openrouter_lease_with_oa_id(
                &request,
                "oa_org",
                updated_at,
                updated_at + 300,
                updated_at + 300,
                1.0,
                Some(&RequestProcessor::native_oa_request_id(&request).unwrap()),
            )
            .unwrap();
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await,
            Err(ServerError::LeasePending)
        ));
        assert_eq!(
            processor.lease_charge_units(&request, 123_456).unwrap(),
            49_383
        );
        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(!matches!(
            error,
            ServerError::NativeQuoteSuperseded | ServerError::NativeQuoteExpired
        ));
        server.abort();
    }
    #[test]
    fn native_quote_is_bound_by_real_browser_proof_and_settles_in_gwei() {
        use zkapi_browser::{
            BrowserWalletConfig, CompleteResponseArgs, ConfirmDepositArgs, PrepareRequestArgs,
        };
        use zkapi_core::merkle::MerkleTree;
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store);
        processor.config.contract_address = Felt252::from_u64(1);
        processor.config.request_charge_cap = 400_000;
        processor.config.native_billing = Some(crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            decimals: 8,
            max_age_seconds: 3600,
        });
        let config = BrowserWalletConfig {
            protocol_version: 2,
            chain_id: 1,
            contract_address: processor.config.contract_address,
            request_charge_cap: 400_000,
            policy_charge_cap: 400_000,
            policy_enabled: false,
            state_signing_key: processor.state_signing_key(),
            clearance_signing_key: processor.clearance_signing_key(),
        };
        let params = zkapi_browser::generate_deposit_params();
        let state = zkapi_browser::confirm_deposit(
            &config,
            ConfirmDepositArgs {
                secret: params.secret,
                note_id: 0,
                amount: 2_000_000,
                expiry_ts: 4_000_000_000,
            },
        )
        .unwrap();
        let mut tree = MerkleTree::new();
        tree.set_leaf(
            0,
            core::note_leaf(0, &params.registration_commitment, 2_000_000, 4_000_000_000),
        );
        processor.update_root(tree.root());
        let now = current_timestamp();
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at: now,
            expires_at: now + 3600,
        };
        let payload=serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote}).to_string();
        let key =
            std::fs::read(std::path::Path::new(&setup_directory()).join("request.pk")).unwrap();
        let prepared = zkapi_browser::prepare_request(
            &config,
            &state,
            PrepareRequestArgs {
                payload: payload.clone(),
                active_root: tree.root(),
                merkle_siblings: tree.get_siblings(0).to_vec(),
                client_request_id: "native-real-proof".into(),
                request_time: now,
                created_at_ms: now * 1000,
            },
            &key,
        )
        .unwrap();
        assert_eq!(prepared.request.payload, payload);
        let serialized = serde_json::to_string(&prepared.journal).unwrap();
        let journal: zkapi_browser::PendingRequestJournal =
            serde_json::from_str(&serialized).unwrap();
        assert_eq!(journal.prepared_request.payload, payload);
        let mut changed = prepared.request.clone();
        let mut changed_payload: serde_json::Value = serde_json::from_str(&payload).unwrap();
        changed_payload["billing_quote"]["answer"] = "500000000000".into();
        changed.payload = changed_payload.to_string();
        changed.payload_hash = canonical_payload_hash(changed.payload.as_bytes());
        assert!(matches!(
            processor.validate_and_reserve(&changed),
            Err(ServerError::InvalidProof(_))
        ));
        let context = canonical_request_context(&changed.client_request_id, &changed.payload_hash);
        changed.public_inputs.authorization_tag =
            core::authorization_tag(&changed.public_inputs.request_nullifier, &context);
        assert!(matches!(
            processor.validate_and_reserve(&changed),
            Err(ServerError::InvalidProof(_))
        ));
        assert!(processor
            .validate_and_reserve(&prepared.request)
            .unwrap()
            .is_none());
        let charge = processor
            .lease_charge_units(&prepared.request, 123_456)
            .unwrap();
        assert_eq!(charge, 49_383);
        let response = processor
            .finalize_request(
                &prepared.request,
                SettlementResult {
                    status_code: 200,
                    payload: serde_json::json!({"billing_quote":quote,"usage_credits":123456})
                        .to_string(),
                    charge_applied: charge,
                    usage: None,
                    billing_label: "native-test".into(),
                },
                0,
                0,
            )
            .unwrap();
        let next = zkapi_browser::complete_response(
            &config,
            CompleteResponseArgs {
                state,
                journal,
                response,
            },
        )
        .unwrap();
        assert_eq!(next.current_balance, 2_000_000 - charge);
    }

    #[test]
    fn server_time_reports_only_clock_and_existing_fixed_window() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let before = current_timestamp_ms();
        let time = processor.server_time();
        let after = current_timestamp_ms();
        assert!(before <= time.server_time_ms && time.server_time_ms <= after);
        assert_eq!(time.max_request_age_seconds, 300);
        assert_eq!(time.max_future_skew_seconds, 30);
        let body = serde_json::to_value(&time).unwrap();
        let mut keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        assert_eq!(
            keys,
            [
                "chain_id",
                "max_future_skew_seconds",
                "max_request_age_seconds",
                "protocol_version",
                "server_time_ms"
            ]
        );
    }

    #[test]
    fn legacy_admission_freshness_window_is_unchanged() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        for (offset, admitted_by_freshness) in [
            (-301i64, false),
            (-299, true),
            (0, true),
            (29, true),
            (31, false),
        ] {
            let mut request = unverified_lease_request(&processor);
            request.public_inputs.request_time = (now as i64 + offset) as u64;
            let error = processor.validate_and_reserve(&request).unwrap_err();
            let freshness = error
                .to_string()
                .contains("request_time is outside the accepted freshness window");
            assert_eq!(
                freshness, !admitted_by_freshness,
                "offset {offset}: {error}"
            );
            assert!(processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .is_none());
        }
        assert!(!request_time_irrevocably_expired(now - 300, now));
        assert!(request_time_irrevocably_expired(now - 301, now));
        assert!(!request_time_irrevocably_expired(now + 86_400, now));
    }

    #[tokio::test]
    async fn expire_declares_only_aged_unaccepted_exact_requests_expired() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = oa_lease_processor(store.clone());
        let now = current_timestamp();
        // The bound quote is still live, so the legacy quote rule alone would
        // answer LeasePending (after an oracle read) forever.
        let mut aged = unverified_lease_request(&processor);
        aged.public_inputs.request_time = now - 301;
        let ack = processor
            .expire_unaccepted_native_lease(&aged.client_request_id, &aged)
            .await
            .unwrap();
        assert_eq!(ack["status"], "expired_unaccepted");
        assert_eq!(ack["client_request_id"], aged.client_request_id);
        assert_eq!(
            ack["request_nullifier"],
            serde_json::to_value(aged.public_inputs.request_nullifier).unwrap()
        );
        assert_eq!(
            ack["payload_hash"],
            serde_json::to_value(aged.payload_hash).unwrap()
        );
        assert!(store
            .lookup_by_nullifier(&aged.public_inputs.request_nullifier)
            .is_none());
        assert!(store
            .lookup_openrouter_lease(&aged.client_request_id)
            .is_none());

        // Exact request binding still applies before any age answer.
        let other_id = processor
            .expire_unaccepted_native_lease("another-request", &aged)
            .await;
        assert!(matches!(other_id, Err(ServerError::InvalidRequest(_))));
        let mut tampered = aged.clone();
        tampered.payload_hash = Felt252::from_u64(1);
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&tampered.client_request_id, &tampered)
                .await,
            Err(ServerError::InvalidRequest(_))
        ));
        let mut foreign = aged.clone();
        foreign.public_inputs.chain_id = 999;
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&foreign.client_request_id, &foreign)
                .await,
            Err(ServerError::ProtocolMismatch(_))
        ));

        // Fresh and future-dated requests can still be admitted: they are not
        // discarded by age and fall through to the unchanged quote rule (the
        // unreachable fixture oracle makes that an error, never an expiry).
        for offset in [-299i64, 0, 31, 86_400] {
            let mut request = unverified_lease_request(&processor);
            request.public_inputs.request_time = (now as i64 + offset) as u64;
            let result = processor
                .expire_unaccepted_native_lease(&request.client_request_id, &request)
                .await;
            assert!(
                result.is_err(),
                "offset {offset} must not be expired: {result:?}"
            );
        }

        // An accepted (reserved) aged request is never declared expired, and
        // the age answer serializes behind in-flight issuance.
        let guard = processor.lease_issue_lock.lock().await;
        let check = processor.expire_unaccepted_native_lease(&aged.client_request_id, &aged);
        tokio::pin!(check);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(25), &mut check)
                .await
                .is_err()
        );
        store.reserve_openrouter_lease(&aged).unwrap();
        drop(guard);
        assert!(matches!(check.await, Err(ServerError::LeasePending)));
    }
}
