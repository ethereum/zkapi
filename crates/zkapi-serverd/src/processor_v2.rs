//! zkAPI v2 request processor.
//!
//! Lease settlement always terminates. A lease whose runtime key was never
//! returned to the client finalizes at zero. A lease that may have been
//! delivered finalizes at its measured usage, clamped to the proof-bound
//! budget before conversion; transient failures retry until the lease's
//! write-once settlement deadline, after which it finalizes without provider
//! I/O at the solvency bound (or at captured usage when only key deletion
//! failed), with an operator-visible review. Settlement never re-validates the
//! frozen quote against live configuration. A corrupt binding is cancelled
//! and never signed, until the operator repairs and reopens it; a possibly
//! delivered direct key's usage is captured before the cancellation, and a
//! reopened lease's saved request is verified again before anything is
//! signed for it.
//!
//! A zero settlement of a never-delivered lease holds the issuance lock, so
//! it never overlaps an issuance that may still deliver the key, and it
//! fences the row before signing: a key is only ever returned for a lease
//! that settles from usage.
//!
//! Settling and signing are separate steps (§5.1, O7). Settlement fixes a
//! request's charge by its deadline and persists it on the reservation
//! (`settled_charge`), finalizing the lease row in the same transaction. The
//! successor is then signed, at the derived anchor `succ(N)` only
//! (`crate::successor`), and only while the request's nullifier is unspent on
//! chain: a nullifier an exit consumed defers the signature (`exit_deferred`)
//! until the exit is defeated, or, once `challengePeriod + 3600` s have
//! passed, makes the request ExitedUnsigned, never signed. Every accepted
//! lease reaches a signed transcript or ExitedUnsigned.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::Engine;
use sha3::{Digest, Keccak256};
use zkapi_core::v2 as core;
use zkapi_proof::compact::{RequestVerifier, WithdrawalVerifier};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProofV2C, ClearanceRequestV2C, ClearanceResponseV2,
    CurvePointWire, Groth16ProofWire, OpenRouterLeaseAuthorization, OpenRouterLeaseResponse,
    OpenRouterLeaseStatusResponse, ProofBackendWire, RecoveryResponseV2, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, Felt252, RequestPublicInputsV2,
    WithdrawalKind,
};

use crate::config::{
    OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig, EXIT_DEFERRAL_SLACK_SECONDS,
    MIN_SETTLEMENT_RETRY_WINDOW_SECONDS,
};
use crate::dashboard::{
    redact_secrets, DashboardEvent, DashboardHub, PendingLeaseView, SettlementCounts,
    SettlementOverview, SettlementReviewView,
};
use crate::error::ServerError;
use crate::native_billing::{NativeBillingOracle, NativeBillingQuote};
use crate::nullifier_store::{
    api_request_binding, lease_binding_mismatch, saved_request_mismatch, FinalizeGuard, KeyCleanup,
    LeaseFinalization, NewOpenRouterLease, NullifierStatus, NullifierStore, OaProvisioningOutcome,
    OpenRouterLeaseRecord, SettleOutcome, SettledCharge, SettledScanKey, SettlementReview,
    SignatureDeferral, TranscriptRecord,
};
use crate::oa_org::{IssuedOpenRouterLease, OaOrgProvisioner, OaOrgUsage, OaOrgUsageExpectation};
use crate::openrouter::OpenRouterProvisioner;
use crate::pricing;
use crate::settlement::{SettlementResult, UsageInfo};
use crate::signer::ServerSigner;
use crate::successor::{build_signed_successor, check_signable};

const MAX_REQUEST_AGE_SECONDS: u64 = 300;
const MAX_FUTURE_SKEW_SECONDS: u64 = 30;
// OA's signed validity is an upstream upper bound, not a guarantee that the
// child key remains usable until the final second. Stop advertising it as the
// usable lease end and leave room for clock skew and in-flight requests.
const OA_LEASE_EXPIRY_SAFETY_SECONDS: u64 = 30;
/// Concurrent clearance ownership-proof verifications.
const CLEARANCE_VERIFY_PERMITS: usize = 4;
const CLEARANCE_PERMIT_TIMEOUT: Duration = Duration::from_secs(2);
const RECENT_ROOTS_CAPACITY: usize = 1024;
const REJECTED_CLEARANCE_CAPACITY: usize = 4096;
const KNOWN_ROOTS_CAPACITY: usize = 4096;
const KEY_CLEANUP_BATCH: usize = 50;
const KEY_CLEANUP_MAX_BACKOFF_SECONDS: u64 = 3_600;
/// Longest wait honoured from an org's retry-after for a pending receipt, or
/// for a rate-limited (429) usage read.
const MAX_PENDING_SETTLEMENT_DEFERRAL_SECONDS: u64 = 300;
/// Settled requests whose successors one sweep tries to sign.
const SIGN_BATCH: usize = 200;
/// A kind-2 ownership proof's `valid_until` may lie at most this far ahead
/// (§5.3): `now <= valid_until <= now + 3600`.
const OWNERSHIP_PROOF_MAX_VALIDITY_SECONDS: u64 = 3_600;
/// How long a nullifier found unpublished stays cached as such. A published
/// one stays published (its events are permanent) and is cached for good.
const PUBLICATION_CACHE_TTL_SECONDS: u64 = 5;
const PUBLICATION_CACHE_CAPACITY: usize = 4096;
/// Without the indexer's published-nullifier table (unreadable, or no
/// indexer configured), the vault's `EscapeConcessionRecorded` logs are
/// scanned from this long before a request was reserved
/// (`RequestProcessor::read_publication`).
const PUBLICATION_SCAN_SLACK_SECONDS: u64 = 3_600;
/// The longest such scan, in blocks (about a week of 12-second blocks): an
/// older reservation fails closed.
const PUBLICATION_SCAN_MAX_BLOCKS: u64 = 50_000;

/// Latency bounds of the settler. Every settlement step persists its phase
/// before its external side effect, so cancelling an attempt is safe.
#[derive(Debug, Clone, Copy)]
struct SettlementTiming {
    /// Stop starting provider-I/O attempts after this much of a tick.
    tick_budget: Duration,
    /// One provider-I/O settlement attempt.
    attempt_timeout: Duration,
    /// Client retirement waits this long for its lease's lock...
    retire_lock_timeout: Duration,
    /// ...and this long for its settlement attempt.
    retire_timeout: Duration,
    /// A tick waits this long for the issuance lock to finalize never
    /// delivered leases past their deadline.
    issue_lock_timeout: Duration,
    /// Background provider-key cleanup per tick and per key.
    cleanup_budget: Duration,
    cleanup_attempt_timeout: Duration,
    /// Single-flight cache of the vault's currentRoot() for clearance.
    vault_root_ttl: Duration,
}

impl Default for SettlementTiming {
    fn default() -> Self {
        // Issuance-lock wait + tick budget + attempt timeout + cleanup stays
        // well inside config::SETTLEMENT_SWEEP_SLACK_SECONDS (600). The
        // sweep never waits for a lease's lock: a lease an owner's
        // retirement holds (at most retire_lock_timeout waiting, then
        // retire_timeout) is left to it.
        Self {
            tick_budget: Duration::from_secs(120),
            attempt_timeout: Duration::from_secs(150),
            retire_lock_timeout: Duration::from_secs(10),
            retire_timeout: Duration::from_secs(45),
            issue_lock_timeout: Duration::from_secs(30),
            cleanup_budget: Duration::from_secs(30),
            cleanup_attempt_timeout: Duration::from_secs(30),
            vault_root_ttl: Duration::from_secs(3),
        }
    }
}

/// Roots the server observed (indexer polls and vault reads), each with the
/// time it was last seen.
#[derive(Default)]
struct RecentRoots {
    entries: VecDeque<(Felt252, u64)>,
}

impl RecentRoots {
    fn observe(&mut self, root: Felt252, now: u64, window: u64) {
        match self.entries.iter_mut().find(|(seen, _)| *seen == root) {
            Some(entry) => entry.1 = entry.1.max(now),
            None => {
                self.entries.push_back((root, now));
                if self.entries.len() > RECENT_ROOTS_CAPACITY {
                    self.entries.pop_front();
                }
            }
        }
        self.entries
            .retain(|(_, seen)| seen.saturating_add(window) >= now);
    }

    fn contains(&self, root: &Felt252, now: u64, window: u64) -> bool {
        self.entries
            .iter()
            .any(|(seen, at)| seen == root && at.saturating_add(window) >= now)
    }
}

/// The vault's answers to `knownRoots(root)` (Amendment A1). A root it set
/// stays known; one it never set is cached as unknown only while the vault's
/// current root is the one read with the answer, since a root becomes known
/// only by becoming the current root.
#[derive(Default)]
struct KnownRoots {
    known: std::collections::HashSet<Felt252>,
    /// The vault root under which `unknown` was read.
    unknown_under: Felt252,
    unknown: std::collections::HashSet<Felt252>,
}

impl KnownRoots {
    fn lookup(&self, root: &Felt252, vault_root: &Felt252) -> Option<bool> {
        if self.known.contains(root) {
            Some(true)
        } else if self.unknown_under == *vault_root && self.unknown.contains(root) {
            Some(false)
        } else {
            None
        }
    }

    fn record(&mut self, root: Felt252, vault_root: Felt252, known: bool) {
        if known {
            if self.known.len() >= KNOWN_ROOTS_CAPACITY {
                self.known.clear();
            }
            self.known.insert(root);
            return;
        }
        if self.unknown_under != vault_root || self.unknown.len() >= KNOWN_ROOTS_CAPACITY {
            self.unknown.clear();
            self.unknown_under = vault_root;
        }
        self.unknown.insert(root);
    }
}

/// Per-lease settlement locks. Settling, retiring or finalizing a lease
/// excludes every other settlement of that lease, and of no other: an owner's
/// retirements of one lease never queue ahead of the sweep's work on the
/// others. A lock lives while someone holds or awaits it.
#[derive(Default)]
struct LeaseLocks {
    table: Mutex<LeaseLockTable>,
}

#[derive(Default)]
struct LeaseLockTable {
    locks: std::collections::HashMap<String, std::sync::Weak<tokio::sync::Mutex<()>>>,
    /// Size at which entries nobody holds or awaits are dropped.
    prune_at: usize,
}

impl LeaseLocks {
    const MIN_PRUNE_AT: usize = 64;

    fn lock_of(&self, client_request_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        let mut table = self
            .table
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(lock) = table
            .locks
            .get(client_request_id)
            .and_then(std::sync::Weak::upgrade)
        {
            return lock;
        }
        if table.locks.len() >= table.prune_at.max(Self::MIN_PRUNE_AT) {
            table.locks.retain(|_, lock| lock.strong_count() > 0);
            table.prune_at = table.locks.len().saturating_mul(2);
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        table
            .locks
            .insert(client_request_id.to_owned(), Arc::downgrade(&lock));
        lock
    }

    /// The lease's lock, unless someone holds or awaits it.
    fn try_lock(&self, client_request_id: &str) -> Option<tokio::sync::OwnedMutexGuard<()>> {
        self.lock_of(client_request_id).try_lock_owned().ok()
    }

    /// The lease's lock, after those who await it already (FIFO).
    async fn lock(&self, client_request_id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        self.lock_of(client_request_id).lock_owned().await
    }
}

/// O5: the Merkle root admission accepts, and when the indexer and the
/// vault last agreed on it.
#[derive(Debug, Default, Clone, Copy)]
struct RootAgreement {
    /// The last refresh at which the indexer root equalled the vault's
    /// currentRoot() (or a root an embedder set with `update_root`).
    agreed_at: Option<u64>,
    /// The last refresh found the two roots different.
    disagreeing: bool,
}

/// Nullifiers found published (consumed or challenged on chain, or in a vault
/// event) for good, and nullifiers found unpublished, with an expiry.
#[derive(Default)]
struct PublicationCache {
    published: std::collections::HashSet<Felt252>,
    unpublished: VecDeque<(Felt252, u64)>,
}

impl PublicationCache {
    fn lookup(&self, nullifier: &Felt252, now: u64) -> Option<bool> {
        if self.published.contains(nullifier) {
            return Some(true);
        }
        self.unpublished
            .iter()
            .any(|(cached, expires)| cached == nullifier && *expires > now)
            .then_some(false)
    }

    fn record(&mut self, nullifier: Felt252, published: bool, now: u64) {
        self.unpublished
            .retain(|(cached, expires)| *cached != nullifier && *expires > now);
        if published {
            if self.published.len() >= PUBLICATION_CACHE_CAPACITY {
                self.published.clear();
            }
            self.published.insert(nullifier);
        } else {
            self.unpublished
                .push_back((nullifier, now.saturating_add(PUBLICATION_CACHE_TTL_SECONDS)));
            if self.unpublished.len() > PUBLICATION_CACHE_CAPACITY {
                self.unpublished.pop_front();
            }
        }
    }
}

/// The lease row a new reservation is written with.
struct IssuanceLease<'a> {
    lease_config: &'a OpenRouterLeaseConfig,
    spending_limit_usd: f64,
    oa_request_id: Option<&'a str>,
}

/// What signing a settled request's successor did (`sign_successor`).
#[derive(Debug, Clone)]
pub enum SignOutcome {
    Signed(Box<RequestResponseV2>),
    /// The nullifier is consumed on chain: not signed (O7), retried each sweep.
    Deferred {
        since: u64,
    },
    /// Terminal: no successor is ever signed for this request.
    ExitedUnsigned,
}

/// A lease status at which settlement has nothing more to do: finalized
/// (signed or settled), cancelled, or settled and deferred or ended by O7.
pub(crate) fn lease_terminal(status: &str) -> bool {
    matches!(
        status,
        "finalized" | "cancelled" | "exit_deferred" | "exited_unsigned"
    )
}

/// (root, nullifier) pairs whose verified ownership proof used a root the
/// vault did not have, with the vault root read and an expiry. While the
/// (cached, single-flight) vault root is unchanged, replays are answered from
/// here without a pairing check.
#[derive(Default)]
struct RejectedClearances {
    entries: VecDeque<(Felt252, Felt252, Felt252, u64)>,
}

impl RejectedClearances {
    fn lookup(&self, root: &Felt252, nullifier: &Felt252, now: u64) -> Option<Felt252> {
        self.entries
            .iter()
            .find(|(r, n, _, expires)| r == root && n == nullifier && *expires > now)
            .map(|(_, _, vault_root, _)| *vault_root)
    }

    fn insert(&mut self, root: Felt252, nullifier: Felt252, vault_root: Felt252, expires: u64) {
        self.entries
            .retain(|(r, n, _, _)| !(*r == root && *n == nullifier));
        self.entries
            .push_back((root, nullifier, vault_root, expires));
        if self.entries.len() > REJECTED_CLEARANCE_CAPACITY {
            self.entries.pop_front();
        }
    }
}

/// Why a possibly delivered lease is finalized without measured usage.
#[derive(Debug, Clone)]
enum FallbackCause {
    Deadline,
    Unsettleable(String),
}

/// The integrity of a lease row against its nullifier reservation.
enum LeaseBinding {
    Valid(Box<TranscriptRecord>),
    /// Never signed: the lease is cancelled with a binding_corrupt review.
    Corrupt(String),
}

pub struct RequestProcessor {
    config: ServerConfig,
    store: Arc<NullifierStore>,
    signer: Arc<ServerSigner>,
    verifier: RequestVerifier,
    withdrawal_verifier: WithdrawalVerifier,
    current_root: Arc<RwLock<Felt252>>,
    recent_roots: Mutex<RecentRoots>,
    rejected_clearances: Mutex<RejectedClearances>,
    clearance_permits: tokio::sync::Semaphore,
    /// The last vault currentRoot() read (or its failure) and when.
    vault_root_cache: tokio::sync::Mutex<Option<(Result<Felt252, String>, Instant)>>,
    /// The vault's knownRoots answers; held across a read (single flight).
    vault_known_roots: tokio::sync::Mutex<KnownRoots>,
    /// O5: when the indexer and the vault last agreed on `current_root`.
    root_agreement: Mutex<RootAgreement>,
    /// Which nullifiers are published on chain (`nullifier_published`).
    publication: Mutex<PublicationCache>,
    /// Where the signing pass's next pages start, for requests never found
    /// consumed and for deferred ones (`sign_settled_successors`).
    signing_cursors: Mutex<[Option<SettledScanKey>; 2]>,
    timing: SettlementTiming,
    dashboard: Option<Arc<DashboardHub>>,
    openrouter: Option<Arc<OpenRouterProvisioner>>,
    oa_org: Option<Arc<OaOrgProvisioner>>,
    native_oracle: NativeBillingOracle,
    lease_issue_lock: tokio::sync::Mutex<()>,
    lease_locks: LeaseLocks,
    /// Unix time before which no OA usage read is started, because the org
    /// answered one with 429 (`oa_usage_rate_limited`). In memory only.
    oa_usage_backoff_until: AtomicU64,
    /// Tests: the nullifiers the chain reports consumed, instead of the
    /// vault RPC, for the signing gate (O7) and the publication check.
    #[cfg(test)]
    pub(crate) test_chain: Option<Arc<Mutex<TestChain>>>,
    /// Drill builds: how this server misbehaves (`zkapi --adversary`).
    #[cfg(feature = "adversary")]
    adversary: Option<crate::adversary::AdversaryMode>,
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
        // Library embeddings can bypass run_server's full seed policy; never
        // serve the published development keys or one key for both roles.
        signer.ensure_serving_keys()?;
        let writer_lock = store.acquire_writer_lock()?;
        if let Some(lease) = config.openrouter_leases.as_ref() {
            anyhow::ensure!(
                lease.ttl_seconds > 0,
                "OpenRouter lease TTL must be positive"
            );
            // Sanity only: run_server enforces the full bound against the
            // vault's challengePeriod().
            anyhow::ensure!(
                lease.settlement_deadline_seconds > lease.settlement_grace_seconds,
                "OpenRouter settlement deadline must exceed the settlement grace"
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
        // The successor signing path, anchor assertion included, with an
        // ephemeral key; the production signer is never invoked.
        crate::successor::self_test(&config.successor_deployment())
            .map_err(|error| anyhow::anyhow!("refusing to start: {error}"))?;
        let native_oracle = NativeBillingOracle::for_server(&config)?;
        let verifier = RequestVerifier::load(&config.proof_setup_dir)?;
        let withdrawal_verifier = WithdrawalVerifier::load(&config.proof_setup_dir)?;
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
        let mut recent_roots = RecentRoots::default();
        recent_roots.observe(
            current_root,
            current_timestamp(),
            config.clearance_root_window_seconds,
        );
        Ok(Self {
            native_oracle,
            config,
            store,
            signer,
            verifier,
            withdrawal_verifier,
            current_root: Arc::new(RwLock::new(current_root)),
            recent_roots: Mutex::new(recent_roots),
            rejected_clearances: Mutex::new(RejectedClearances::default()),
            clearance_permits: tokio::sync::Semaphore::new(CLEARANCE_VERIFY_PERMITS),
            vault_root_cache: tokio::sync::Mutex::new(None),
            vault_known_roots: tokio::sync::Mutex::new(KnownRoots::default()),
            root_agreement: Mutex::new(RootAgreement::default()),
            publication: Mutex::new(PublicationCache::default()),
            signing_cursors: Mutex::new([None, None]),
            timing: SettlementTiming::default(),
            dashboard: None,
            openrouter,
            oa_org,
            lease_issue_lock: tokio::sync::Mutex::new(()),
            lease_locks: LeaseLocks::default(),
            oa_usage_backoff_until: AtomicU64::new(0),
            #[cfg(test)]
            test_chain: Some(Arc::default()),
            #[cfg(feature = "adversary")]
            adversary: crate::adversary::mode(),
            _writer_lock: writer_lock,
        })
    }

    /// Drill builds: make this processor misbehave (tests set it per
    /// processor; the binary sets the process mode before construction).
    #[cfg(feature = "adversary")]
    pub fn set_adversary(&mut self, mode: Option<crate::adversary::AdversaryMode>) {
        self.adversary = mode;
    }

    /// Admit `request`, settle it at `charge_gwei` and sign its successor at
    /// once, as an unspent nullifier allows (tests).
    #[cfg(test)]
    pub(crate) fn finalize_test_lease(
        &self,
        request: &ApiRequestV2,
        charge_gwei: u128,
    ) -> Result<RequestResponseV2, ServerError> {
        if let Some(response) = self.validate_and_reserve(request)? {
            return Ok(response);
        }
        self.settle_request_for_test(
            request,
            SettlementResult {
                status_code: 200,
                payload: self
                    .settlement_payload(request, serde_json::json!({"status":"finalized"}))?,
                charge_applied: charge_gwei,
                usage: None,
                billing_label: "native-test".into(),
            },
        )?;
        self.sign_settled(request)
    }

    /// Persist a settlement on a reservation that has no lease row (tests).
    #[cfg(test)]
    pub(crate) fn settle_request_for_test(
        &self,
        request: &ApiRequestV2,
        result: SettlementResult,
    ) -> Result<(), ServerError> {
        check_signable(request)?;
        let charge = result
            .charge_applied
            .min(request.public_inputs.solvency_bound);
        self.store.execute_for_test(
            "UPDATE nullifiers SET settled_charge = ?1, settled_basis = 'measured',
                settled_at = ?2, response_code = ?3, response_payload = ?4
             WHERE nullifier = ?5 AND status = 'Reserved' AND settled_charge IS NULL",
            rusqlite::params![
                charge as i64,
                current_timestamp() as i64,
                result.status_code,
                result.payload,
                request.public_inputs.request_nullifier.to_hex()
            ],
        );
        Ok(())
    }

    pub fn with_dashboard(mut self, dashboard: Arc<DashboardHub>) -> Self {
        self.dashboard = Some(dashboard);
        self
    }

    pub fn dashboard(&self) -> Option<&Arc<DashboardHub>> {
        self.dashboard.as_ref()
    }

    /// Set the root admission accepts, as one the indexer and the vault
    /// agree on now. For embedders and tests: run_server's root poller
    /// (`refresh_roots`) only accepts a root the vault confirms.
    pub fn update_root(&self, new_root: Felt252) {
        self.agree_on_root(new_root, current_timestamp());
    }

    fn agree_on_root(&self, root: Felt252, now: u64) {
        if let Ok(mut current) = self.current_root.write() {
            *current = root;
        }
        if let Ok(mut agreement) = self.root_agreement.lock() {
            *agreement = RootAgreement {
                agreed_at: Some(now),
                disagreeing: false,
            };
        }
        self.observe_root(root, now);
    }

    /// One refresh of the root poller (O5): the indexer's root (None without
    /// an indexer) and the vault's currentRoot() at latest. Admission accepts
    /// a root only while the two agree, and only for
    /// `root_max_staleness_seconds` after they last did. A failed read
    /// changes nothing: the last agreement ages out.
    pub fn record_root_refresh(
        &self,
        indexer_root: Option<Felt252>,
        vault_root: Felt252,
        now: u64,
    ) {
        match indexer_root {
            Some(indexer_root) if indexer_root != vault_root => {
                if let Ok(mut agreement) = self.root_agreement.lock() {
                    if !agreement.disagreeing {
                        tracing::warn!(
                            indexer_root = %indexer_root,
                            vault_root = %vault_root,
                            "the indexer root and the vault's currentRoot() disagree; admission refuses requests until they agree"
                        );
                    }
                    agreement.disagreeing = true;
                }
                // The vault's root is real: clearance may still use it.
                self.observe_root(vault_root, now);
            }
            _ => self.agree_on_root(vault_root, now),
        }
    }

    /// Read the indexer root (when configured) and the vault's currentRoot()
    /// and record the refresh. Errors leave the last agreement to age out.
    pub async fn refresh_roots(&self, indexer_url: Option<&str>) -> anyhow::Result<()> {
        let indexer_root = match indexer_url {
            Some(url) => Some(fetch_indexer_root(url).await?),
            None => None,
        };
        let vault_root = self.native_oracle.vault_current_root().await?;
        *self.vault_root_cache.lock().await = Some((Ok(vault_root), Instant::now()));
        self.record_root_refresh(indexer_root, vault_root, current_timestamp());
        Ok(())
    }

    /// O5: the root admission accepts now, if the indexer and the vault
    /// agreed on it recently enough.
    fn fresh_root(&self, now: u64) -> Result<Felt252, ServerError> {
        let agreement = self
            .root_agreement
            .lock()
            .map(|agreement| *agreement)
            .map_err(|_| ServerError::Internal("root state lock poisoned".into()))?;
        if agreement.disagreeing {
            return Err(ServerError::RootUnavailable(
                "the indexer root and the vault's currentRoot() disagree".into(),
            ));
        }
        let max = self.config.root_max_staleness_seconds;
        match agreement.agreed_at {
            Some(at) if now.saturating_sub(at) <= max => Ok(self.current_root()),
            _ => Err(ServerError::RootUnavailable(format!(
                "no root confirmed by the vault in the last {max} s"
            ))),
        }
    }

    fn observe_root(&self, root: Felt252, now: u64) {
        if let Ok(mut roots) = self.recent_roots.lock() {
            roots.observe(root, now, self.config.clearance_root_window_seconds);
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

    /// The setup of the verifying keys this server loaded.
    pub fn setup_id(&self) -> &str {
        self.verifier.setup_id()
    }

    pub fn clearance_signing_key(&self) -> CurvePointWire {
        self.signer.clearance_public_key()
    }

    pub async fn native_billing_quote(&self) -> Result<NativeBillingQuote, ServerError> {
        self.native_oracle.quote(current_timestamp()).await
    }

    /// The proof-bound lease terms exactly as persisted: the prompt-free
    /// authorization and the frozen quote, checked only intrinsically.
    /// Settlement uses these and never reads mutable configuration.
    fn lease_terms(
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
        quote.validate_intrinsic(request.public_inputs.chain_id)?;
        let authorization = serde_json::from_value(payload).map_err(|_| {
            ServerError::InvalidRequest("invalid prompt-free lease authorization".into())
        })?;
        Ok((authorization, quote))
    }

    /// Admission only: the frozen terms must also match the live deployment.
    fn lease_authorization(
        &self,
        request: &ApiRequestV2,
    ) -> Result<(OpenRouterLeaseAuthorization, NativeBillingQuote), ServerError> {
        let (authorization, quote) = Self::lease_terms(request)?;
        let config = self.config.native_billing.as_ref().ok_or_else(|| {
            ServerError::InvalidRequest("native ETH billing configuration is required".into())
        })?;
        quote.validate_identity(config, self.config.chain_id)?;
        Ok((authorization, quote))
    }

    fn lease_limit_micro_usd(&self, request: &ApiRequestV2) -> Result<u128, ServerError> {
        Self::lease_terms(request)?
            .1
            .limit_micro_usd(request.public_inputs.solvency_bound)
    }

    fn settlement_payload(
        &self,
        request: &ApiRequestV2,
        mut payload: serde_json::Value,
    ) -> Result<String, ServerError> {
        let quote = Self::lease_terms(request)?.1;
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

    /// A settlement payload that cannot fail: the frozen quote when it parses,
    /// otherwise the request's untouched billing_quote value. Clients require
    /// the quote they signed to be echoed.
    fn fallback_settlement_payload(
        &self,
        request: &ApiRequestV2,
        payload: serde_json::Value,
    ) -> String {
        self.settlement_payload(request, payload.clone())
            .unwrap_or_else(|_| {
                let mut payload = payload;
                if let Some(object) = payload.as_object_mut() {
                    object.insert("billing_quote".into(), Self::raw_billing_quote(request));
                }
                payload.to_string()
            })
    }

    fn raw_billing_quote(request: &ApiRequestV2) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&request.payload)
            .ok()
            .and_then(|payload| payload.get("billing_quote").cloned())
            .unwrap_or(serde_json::Value::Null)
    }

    #[cfg(test)]
    fn lease_charge_units(
        &self,
        request: &ApiRequestV2,
        micro_usd: u128,
    ) -> Result<u128, ServerError> {
        Self::lease_terms(request)?.1.charge_units(micro_usd)
    }

    fn lease_config(&self) -> Result<&OpenRouterLeaseConfig, ServerError> {
        self.config
            .openrouter_leases
            .as_ref()
            .ok_or_else(|| ServerError::Internal("lease configuration is unavailable".into()))
    }

    /// The write-once deadline of a lease created now.
    fn new_lease_deadline(&self, lease_config: &OpenRouterLeaseConfig, created_at: u64) -> u64 {
        created_at
            .saturating_add(lease_config.ttl_seconds)
            .saturating_add(lease_config.settlement_grace_seconds)
            .saturating_add(lease_config.settlement_deadline_seconds)
    }

    /// The deadline a lease recorded without one receives at first sight:
    /// a full settlement window from its expiry or from now, whichever is later.
    fn first_sight_deadline(
        &self,
        lease_config: &OpenRouterLeaseConfig,
        expires_at: u64,
        now: u64,
    ) -> u64 {
        expires_at
            .max(now)
            .saturating_add(lease_config.settlement_grace_seconds)
            .saturating_add(lease_config.settlement_deadline_seconds)
    }

    /// A lease's write-once settlement deadline, assigned (once) at first
    /// sight for a row recorded without one.
    fn settlement_deadline(
        &self,
        lease: &OpenRouterLeaseRecord,
        now: u64,
    ) -> Result<u64, ServerError> {
        if let Some(deadline) = lease.settlement_deadline_at {
            return Ok(deadline);
        }
        let deadline = self.first_sight_deadline(self.lease_config()?, lease.expires_at, now);
        self.store
            .assign_settlement_deadline(&lease.client_request_id, deadline)
    }

    fn assign_missing_settlement_deadlines(&self, now: u64) {
        let Ok(lease_config) = self.lease_config() else {
            return;
        };
        let rows = match self.store.leases_without_settlement_deadline() {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(error = %error, "cannot assign lease settlement deadlines");
                return;
            }
        };
        for (client_request_id, expires_at) in rows {
            let deadline = self.first_sight_deadline(lease_config, expires_at, now);
            if let Err(error) = self
                .store
                .assign_settlement_deadline(&client_request_id, deadline)
            {
                tracing::error!(%client_request_id, error = %error, "cannot assign a lease settlement deadline");
            }
        }
    }

    /// A runtime key was, or may have been, returned to the client. Only
    /// such a lease can be charged more than zero.
    fn may_have_delivered(lease: &OpenRouterLeaseRecord) -> bool {
        matches!(
            lease.status.as_str(),
            "active" | "retiring" | "disabled" | "revoking"
        ) && lease.delivered != Some(false)
    }

    /// A pending lease whose key has not been returned to the client. While
    /// issuance holds its lock it may still return it; such a lease settles
    /// at zero only under that lock.
    fn never_delivered(lease: &OpenRouterLeaseRecord) -> bool {
        matches!(
            lease.status.as_str(),
            "provisioning" | "active" | "retiring" | "disabled" | "revoking"
        ) && !Self::may_have_delivered(lease)
    }

    /// A pending lease reopened by the operator with a concession: it
    /// finalizes at zero, whatever was delivered.
    fn conceded(lease: &OpenRouterLeaseRecord) -> bool {
        lease.charge_basis.as_deref() == Some("operator_conceded") && !lease_terminal(&lease.status)
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

    /// The upstream request ID of an issued OA lease for usage settlement.
    /// Leases issued before the bound namespace existed used the plain
    /// client request ID upstream; settle them under it first.
    fn oa_usage_request_id(&self, lease: &OpenRouterLeaseRecord) -> Result<String, ServerError> {
        let expected = Self::native_oa_request_id(&lease.api_request)?;
        match lease.oa_client_request_id.as_deref() {
            Some(id) if id == expected => Ok(expected),
            None => Ok(lease.client_request_id.clone()),
            Some(_) => Err(ServerError::Unsettleable(
                "OA lease upstream request ID does not match its bound request".into(),
            )),
        }
    }

    /// The lease TTL frozen at creation; legacy rows use the configured TTL.
    fn lease_ttl_seconds(&self, lease: &OpenRouterLeaseRecord) -> Result<u64, ServerError> {
        let valid = |ttl: u64| ttl > 0 && (lease.key_source != "oa_org" || ttl.is_multiple_of(60));
        match lease.ttl_seconds {
            Some(ttl) if valid(ttl) => Ok(ttl),
            Some(_) => Err(ServerError::Unsettleable(
                "persisted lease TTL is not a positive whole number of minutes".into(),
            )),
            None => {
                let ttl = self.lease_config()?.ttl_seconds;
                if !valid(ttl) {
                    return Err(ServerError::Internal(
                        "OA org lease duration is not a positive whole number of minutes".into(),
                    ));
                }
                Ok(ttl)
            }
        }
    }

    /// Reserve one prompt-free zkAPI request and mint its bounded OpenRouter
    /// runtime key using its frozen native ETH price quote.
    pub async fn issue_openrouter_lease(
        &self,
        request: &ApiRequestV2,
    ) -> Result<IssuedOpenRouterLease, ServerError> {
        let public = &request.public_inputs;
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "version, chain, or contract mismatch".to_string(),
            ));
        }
        // A new reservation's quote is checked against the live deployment by
        // the oracle below; an exact retry keeps its frozen quote.
        let (authorization, billing_quote) = Self::lease_terms(request)?;
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
        let limit_micro_usd =
            billing_quote.limit_micro_usd(request.public_inputs.solvency_bound)?;
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
        // Matching retries remain valid after the oracle round ages out. An
        // unreadable store is an error: never a new request whose quote and
        // freshness are checked again.
        let existing_lease = self
            .store
            .try_lookup_openrouter_lease(&request.client_request_id)?;
        let existing_reservation = self
            .store
            .try_lookup_by_nullifier(&request.public_inputs.request_nullifier)?;
        if let Some(existing) = existing_lease.as_ref() {
            if api_request_binding(&existing.api_request)? != api_request_binding(request)? {
                return Err(ServerError::Replay);
            }
        }
        if existing_reservation.is_none() {
            // The operator's per-request exposure ceiling (§5.2). A request
            // reserved earlier keeps its admission.
            if let Some(max_micro_usd) = self.config.request_limit_max_usd_micros {
                if limit_micro_usd > max_micro_usd {
                    return Err(ServerError::RequestLimitExceeded {
                        limit_micro_usd,
                        max_micro_usd,
                    });
                }
            }
            self.native_oracle
                .validate(&billing_quote, current_timestamp())
                .await?;
            // Oracle reads may span expiry; no await may separate this check
            // from the synchronous proof validation and reservation below.
            self.native_oracle
                .assert_fresh(&billing_quote, current_timestamp())?;
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
        // A new reservation is written with its evidence and its settleable
        // provisioning lease row in one transaction: a crash can never leave
        // a reservation that no settlement sweep visits.
        let issuance = existing_lease.is_none().then_some(IssuanceLease {
            lease_config,
            spending_limit_usd,
            oa_request_id: oa_request_id.as_deref(),
        });
        if self
            .validate_and_reserve_with(request, issuance.as_ref())?
            .is_some()
        {
            return Err(ServerError::Replay);
        }
        let mut issued_at = current_timestamp();
        let mut ttl_seconds = lease_config.ttl_seconds;
        let existing = self
            .store
            .try_lookup_openrouter_lease(&request.client_request_id)?;
        // The lease row this call just wrote with the reservation is new: no
        // retry handling applies to it.
        let created_now = existing_reservation.is_none() && existing_lease.is_none();
        let existing = existing.filter(|_| !created_now);
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
            if existing.status == "cancelled" {
                return Err(ServerError::NullifierUsed);
            }
            // A lease committed to a zero (or conceded) settlement never
            // mints a key again; it is about to be finalized.
            if existing.status != "provisioning"
                || existing.key_hash.is_some()
                || existing.charge_basis.is_some()
            {
                return Err(ServerError::LeasePending);
            }
            if existing.key_source == "oa_org"
                && existing.oa_provisioning_outcome == OaProvisioningOutcome::ConfirmedUnissued
            {
                // A definitive rejection is terminal. Never mint another key
                // while recovering a crash between its evidence and signature.
                self.finalize_never_delivered_lease(&existing.client_request_id)?;
                self.sign_if_settled(request).await;
                return Err(ServerError::OaKeyPolicyRejected);
            }
        } else if !created_now {
            // A reservation from before reservations carried their lease row:
            // persist a settleable lease before any further I/O. A chain or
            // provider failure from here on leaves a provisioning row, which
            // settles at zero, rather than a bare nullifier reservation.
            self.create_issuance_lease(
                request,
                lease_config,
                spending_limit_usd,
                oa_request_id.as_deref(),
            )?;
        }
        // A reservation preserves the accepted request, not permission to mint
        // new access after its collateral has entered an escape or been paid
        // out. Check immediately before provider I/O, including OA retries
        // that might be the first successful upstream issuance.
        self.native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await?;
        if let Some(existing) = existing.as_ref() {
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
                    self.create_issuance_lease(
                        request,
                        lease_config,
                        spending_limit_usd,
                        oa_request_id.as_deref(),
                    )?;
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
                    self.persisted_oa_request_id(existing)?;
                    // The persisted TTL, not the live configuration, defines
                    // the lease the station issues and settles.
                    ttl_seconds = self.lease_ttl_seconds(existing)?;
                    // Never deliver a key whose settlement could not finish
                    // before this lease's deadline; it then settles at zero.
                    if let Some(deadline) = existing.settlement_deadline_at {
                        let latest_start = current_timestamp()
                            .saturating_add(ttl_seconds)
                            .saturating_add(lease_config.settlement_grace_seconds)
                            .saturating_add(MIN_SETTLEMENT_RETRY_WINDOW_SECONDS);
                        if latest_start > deadline {
                            return Err(ServerError::LeasePending);
                        }
                    }
                    spending_limit_usd = existing.spending_limit_usd;
                    issued_at = existing.issued_at;
                }
            }
        }
        let requested_expires_at = current_timestamp().saturating_add(ttl_seconds);
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
                        // Keep the provisioning row: it was never delivered and
                        // settles at zero unless an exact retry reissues it
                        // (which first removes any key created ambiguously).
                        let _ = self.store.record_openrouter_lease_error(
                            &request.client_request_id,
                            &error.to_string(),
                        );
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
                        ttl_seconds,
                    )
                    .await;
                let created = match created {
                    Ok(created) => created,
                    Err(ServerError::OaKeyPolicyRejected) if first_attempt => {
                        self.store.confirm_oa_unissued(&request.client_request_id)?;
                        self.finalize_never_delivered_lease(&request.client_request_id)?;
                        self.sign_if_settled(request).await;
                        return Err(ServerError::OaKeyPolicyRejected);
                    }
                    Err(error) => {
                        let _ = self.store.record_openrouter_lease_error(
                            &request.client_request_id,
                            &error.to_string(),
                        );
                        return Err(error);
                    }
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
        // The issuer's identity lets startup refuse another org or API base
        // while this lease is unsettled.
        if let Err(error) = self.store.activate_openrouter_lease_from(
            &request.client_request_id,
            &key_hash,
            Some(&lease_config.source.identity()),
        ) {
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
        // the runtime key unless its authorization is still unspent. Then
        // durably mark the key delivered before returning it: a key that is
        // never returned can only ever be charged zero, and a lease committed
        // to a zero settlement refuses the mark.
        let delivered = match self
            .native_oracle
            .assert_request_unspent(&request.public_inputs.request_nullifier)
            .await
        {
            Ok(()) => self
                .store
                .mark_openrouter_lease_delivered(&request.client_request_id),
            Err(error) => Err(error),
        };
        if let Err(error) = delivered {
            self.discard_undelivered_key(
                &lease_config.source,
                &request.client_request_id,
                &key_hash,
            );
            return Err(error);
        }
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

    /// A provisioning lease row for issuance, with its TTL and write-once
    /// settlement deadline frozen now. Its key is undelivered until marked.
    fn create_issuance_lease(
        &self,
        request: &ApiRequestV2,
        lease_config: &OpenRouterLeaseConfig,
        spending_limit_usd: f64,
        oa_request_id: Option<&str>,
    ) -> Result<(), ServerError> {
        self.store
            .create_openrouter_lease_bound(&self.issuance_lease_row(
                request,
                &IssuanceLease {
                    lease_config,
                    spending_limit_usd,
                    oa_request_id,
                },
                current_timestamp(),
            ))
    }

    fn issuance_lease_row<'a>(
        &self,
        request: &'a ApiRequestV2,
        issuance: &IssuanceLease<'a>,
        now: u64,
    ) -> NewOpenRouterLease<'a> {
        let lease_config = issuance.lease_config;
        let expires_at = now.saturating_add(lease_config.ttl_seconds);
        NewOpenRouterLease {
            request,
            key_source: lease_config.source.label(),
            issued_at: now,
            expires_at,
            settle_after: expires_at.saturating_add(lease_config.settlement_grace_seconds),
            spending_limit_usd: issuance.spending_limit_usd,
            oa_client_request_id: issuance.oa_request_id,
            ttl_seconds: Some(lease_config.ttl_seconds),
            settlement_deadline_at: Some(self.new_lease_deadline(lease_config, now)),
            delivered: Some(false),
        }
    }

    /// An activated key that issuance will never return; its lease settles
    /// at zero. A direct key is queued for disabling and deletion at once.
    /// The OA org offers no revocation: an OA key was only ever seen by the
    /// org, its station and this process, which drops it, and it expires with
    /// the lease TTL.
    fn discard_undelivered_key(
        &self,
        source: &OpenRouterLeaseSourceConfig,
        client_request_id: &str,
        key_hash: &str,
    ) {
        match source {
            OpenRouterLeaseSourceConfig::OpenRouter { .. } => {
                let key_name = format!("zkapi-{client_request_id}");
                let cleanup = KeyCleanup {
                    key_source: "openrouter",
                    key_hash: Some(key_hash),
                    key_name: &key_name,
                };
                if let Err(error) = self.store.enqueue_key_cleanup(client_request_id, &cleanup) {
                    // Its zero settlement queues the deletion again.
                    tracing::warn!(%client_request_id, error = %error, "could not queue an undelivered key for deletion");
                }
            }
            OpenRouterLeaseSourceConfig::OaOrg { .. } => {
                tracing::warn!(
                    %client_request_id,
                    key_hash,
                    "OA key activated but never returned; the org offers no revocation, so it lapses at the lease TTL"
                );
            }
        }
    }

    /// Read-only expiration handshake. It serializes behind in-flight issuance
    /// without provisioning a key or mutating the wallet/nullifier database.
    /// The issuance lock is held only to check that nothing reserved the
    /// request, before and again after the oracle reads, never across them.
    pub async fn expire_unaccepted_native_lease(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<serde_json::Value, ServerError> {
        let (authorization, quote) = Self::lease_terms(request)?;
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
        #[cfg(feature = "adversary")]
        if self.adversary == Some(crate::adversary::AdversaryMode::LieExpired) {
            // Whatever was reserved: the client may reuse its anchor, and the
            // server keeps the proof of a reservation it denies.
            return Ok(serde_json::json!({
                "status": "expired_unaccepted", "client_request_id": client_request_id,
                "request_nullifier": request.public_inputs.request_nullifier,
                "payload_hash": request.payload_hash,
                "server_time_ms": current_timestamp().saturating_mul(1000),
            }));
        }
        self.ensure_unaccepted(client_request_id, request).await?;
        // Admission rejects an expired quote whatever the configuration, so a
        // configuration change can never strand an expired unaccepted journal.
        let status = if quote.expires_at <= current_timestamp() {
            "expired_unaccepted"
        } else {
            let config = self.config.native_billing.as_ref().ok_or_else(|| {
                ServerError::InvalidRequest("native ETH billing configuration is required".into())
            })?;
            quote.validate_identity(config, self.config.chain_id)?;
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
        // An issuance that reserved the request meanwhile is seen here. One
        // that takes the lock later reads the oracle and the clock later, and
        // expiry and supersession only advance, so it cannot reserve it.
        self.ensure_unaccepted(client_request_id, request).await?;
        Ok(serde_json::json!({
            "status":status, "client_request_id":client_request_id,
            "request_nullifier":request.public_inputs.request_nullifier,
            "payload_hash":request.payload_hash, "server_time_ms":current_timestamp().saturating_mul(1000),
        }))
    }

    /// Under the issuance lock (awaiting earlier in-flight issuance), require
    /// that neither the request's nullifier nor its ID has a reservation. A
    /// store that cannot be read is an error, never an absent reservation.
    async fn ensure_unaccepted(
        &self,
        client_request_id: &str,
        request: &ApiRequestV2,
    ) -> Result<(), ServerError> {
        let _guard = self.lease_issue_lock.lock().await;
        if self
            .store
            .try_lookup_by_nullifier(&request.public_inputs.request_nullifier)?
            .is_some()
            || self
                .store
                .try_lookup_openrouter_lease(client_request_id)?
                .is_some()
            || self
                .store
                .try_lookup_by_client_id(client_request_id)?
                .is_some()
        {
            return Err(ServerError::LeasePending);
        }
        Ok(())
    }

    /// Settle every due lease. Pass 1 finalizes without provider or chain I/O:
    /// conceded leases and never-delivered leases at zero, and possibly
    /// delivered leases past their write-once deadline. A never-delivered
    /// lease needs the issuance lock: a busy lock defers it to the next tick,
    /// or, once it is past its deadline, to a bounded wait for the lock that
    /// follows pass 1. Pass 2 settles from provider usage, bounded per attempt
    /// and per tick, nearest deadline first (see `settle_from_provider_usage`).
    /// Pass 3 deletes provider keys of terminal leases, outside every lock.
    /// Each lease is handled under its own lock (`LeaseLocks`), on the row as
    /// stored then; a lease whose lock is held or awaited is being settled
    /// by its owner's retirement, which applies the same rules, and is seen
    /// again next tick.
    pub async fn settle_due_openrouter_leases(&self) {
        let started = Instant::now();
        let now = current_timestamp();
        self.assign_missing_settlement_deadlines(now);
        let mut provider_io = Vec::new();
        let mut overdue_unissued = Vec::new();
        for scanned in self.store.due_openrouter_leases(now) {
            let Some(lease_guard) = self.lease_locks.try_lock(&scanned.client_request_id) else {
                continue;
            };
            let lease = match self
                .store
                .try_lookup_openrouter_lease(&scanned.client_request_id)
            {
                Ok(Some(lease)) if !lease_terminal(&lease.status) => lease,
                Ok(_) => continue,
                Err(error) => {
                    self.note_settlement_failure(&scanned, &error);
                    continue;
                }
            };
            let result = if Self::conceded(&lease) {
                self.finalize_conceded_lease(&lease.client_request_id)
            } else if Self::never_delivered(&lease) {
                // Issuance holds this lock across provider I/O and until
                // it has returned or abandoned the key.
                match self.lease_issue_lock.try_lock() {
                    Ok(_issue_guard) => {
                        self.finalize_never_delivered_lease(&lease.client_request_id)
                    }
                    Err(_) => {
                        if matches!(self.settlement_deadline(&lease, now), Ok(deadline) if now >= deadline)
                        {
                            overdue_unissued.push((lease, lease_guard));
                        }
                        continue;
                    }
                }
            } else {
                match self.settlement_deadline(&lease, now) {
                    Ok(deadline)
                        if now >= deadline
                            && matches!(lease.key_source.as_str(), "openrouter" | "oa_org") =>
                    {
                        self.finalize_lease_fallback(
                            &lease.client_request_id,
                            FallbackCause::Deadline,
                        )
                    }
                    Ok(_) => {
                        // Pass 2 takes the lease's lock again per attempt.
                        provider_io.push(lease);
                        continue;
                    }
                    Err(error) => Err(error),
                }
            };
            if let Err(error) = result {
                self.note_settlement_failure(&lease, &error);
            }
        }
        if !overdue_unissued.is_empty() {
            // Queue for the lock (FIFO) instead of skipping: no stream of
            // lock holders can postpone these past their deadline. The
            // wait is bounded so that the rest of the tick still runs. Their
            // own locks are kept meanwhile.
            match tokio::time::timeout(self.timing.issue_lock_timeout, self.lease_issue_lock.lock())
                .await
            {
                Ok(_issue_guard) => {
                    for (lease, _lease_guard) in &overdue_unissued {
                        if let Err(error) =
                            self.finalize_never_delivered_lease(&lease.client_request_id)
                        {
                            self.note_settlement_failure(lease, &error);
                        }
                    }
                }
                Err(_) => tracing::warn!(
                    leases = overdue_unissued.len(),
                    "issuance lock stayed busy; never-delivered leases past their settlement deadline are retried next tick"
                ),
            }
        }
        drop(overdue_unissued);
        self.settle_from_provider_usage(provider_io, started).await;
        // Sign what settled (this tick or earlier), and re-check deferrals.
        self.sign_settled_successors().await;
        self.cleanup_provider_keys().await;
    }

    /// Pass 2: one provider-I/O attempt per due lease until the tick budget is
    /// spent. Leases are drawn from two orders over the same set: nearest
    /// write-once deadline first, and least recently attempted first. Each
    /// attempt comes from whichever order has used less of this tick, so the
    /// lease nearest its deadline is attempted first, and leases that keep
    /// failing slowly near their deadlines cannot starve the rest (nor the
    /// reverse). A pending result defers its lease (`note_settlement_failure`),
    /// so it is not polled again on every tick. Once the OA org rate-limits a
    /// usage read, no OA attempt starts before its retry time, in this tick
    /// or a later one (`oa_usage_rate_limited`). Each attempt takes only its
    /// lease's lock, and skips a lease whose lock is held or awaited (by its
    /// owner's retirement): retirements wait for no other lease's attempt,
    /// and no lease's retirements hold up the others' attempts.
    async fn settle_from_provider_usage(
        &self,
        leases: Vec<OpenRouterLeaseRecord>,
        started: Instant,
    ) {
        let mut by_deadline: Vec<usize> = (0..leases.len()).collect();
        by_deadline.sort_by_key(|&index| {
            let lease = &leases[index];
            (
                lease.settlement_deadline_at.unwrap_or(u64::MAX),
                lease.updated_at,
                lease.settle_after,
            )
        });
        // The store returns leases least recently attempted first.
        let by_age: Vec<usize> = (0..leases.len()).collect();
        let orders = [by_deadline, by_age];
        let mut next = [0usize; 2];
        let mut spent = [Duration::ZERO; 2];
        let mut attempted = vec![false; leases.len()];
        while started.elapsed() < self.timing.tick_budget {
            let order = usize::from(spent[1] < spent[0]);
            let queue = &orders[order];
            while next[order] < queue.len() && attempted[queue[next[order]]] {
                next[order] += 1;
            }
            // Either order holds every lease: once one is used up, all were
            // attempted.
            let Some(&index) = queue.get(next[order]) else {
                break;
            };
            next[order] += 1;
            attempted[index] = true;
            let attempt_started = Instant::now();
            self.attempt_provider_settlement(&leases[index]).await;
            spent[order] += attempt_started.elapsed();
        }
    }

    /// One pass-2 attempt under the lease's lock, on the lease as stored now:
    /// an owner's retirement may have settled, advanced or deferred it since
    /// the scan. A lease whose lock is held or awaited is left to its owner's
    /// retirement.
    async fn attempt_provider_settlement(&self, scanned: &OpenRouterLeaseRecord) {
        if scanned.key_source == "oa_org" && self.oa_usage_backoff(current_timestamp()).is_some() {
            return;
        }
        let Some(_lease_guard) = self.lease_locks.try_lock(&scanned.client_request_id) else {
            return;
        };
        let lease = match self
            .store
            .try_lookup_openrouter_lease(&scanned.client_request_id)
        {
            Ok(Some(lease)) if !lease_terminal(&lease.status) => lease,
            Ok(_) => return,
            Err(error) => {
                self.note_settlement_failure(scanned, &error);
                return;
            }
        };
        match self.pending_deferral(&lease, current_timestamp()) {
            Ok(None) => {}
            Ok(Some(_)) => return,
            Err(error) => {
                self.note_settlement_failure(&lease, &error);
                return;
            }
        }
        let attempt = tokio::time::timeout(
            self.timing.attempt_timeout,
            self.settle_with_provider(&lease),
        )
        .await
        .unwrap_or_else(|_| {
            Err(ServerError::Internal(
                "settlement attempt timed out".to_string(),
            ))
        });
        if let Err(error) = attempt {
            self.note_settlement_failure(&lease, &error);
        }
    }

    fn note_settlement_failure(&self, lease: &OpenRouterLeaseRecord, error: &ServerError) {
        // Waiting for a drain interval, an OA receipt or the end of an OA rate
        // limit is not a failure: the lease is asked again after the retry
        // time it was given.
        if let ServerError::LeaseSettlementPending {
            retry_after_seconds,
        } = error
        {
            self.defer_pending_settlement(lease, *retry_after_seconds);
            return;
        }
        tracing::warn!(
            client_request_id = %lease.client_request_id,
            error = %error,
            "OpenRouter lease settlement will be retried"
        );
        let _ = self
            .store
            .record_openrouter_lease_error(&lease.client_request_id, &error.to_string());
    }

    /// The time a pending settlement of this lease was deferred to
    /// (`defer_pending_settlement`), while it is still ahead.
    fn pending_deferral(
        &self,
        lease: &OpenRouterLeaseRecord,
        now: u64,
    ) -> Result<Option<u64>, ServerError> {
        Ok(self
            .store
            .openrouter_lease_next_attempt_at(&lease.client_request_id)?
            .filter(|next_attempt_at| *next_attempt_at > now))
    }

    /// Defer the next provider-I/O attempt of a lease whose settlement is
    /// pending by its retry time: at least the poll interval, at most
    /// MAX_PENDING_SETTLEMENT_DEFERRAL_SECONDS, and never more than half of the
    /// time left before its deadline, so that it is asked again shortly
    /// before the deadline turns it into a worst-case charge.
    fn defer_pending_settlement(&self, lease: &OpenRouterLeaseRecord, retry_after_seconds: u64) {
        let now = current_timestamp();
        let left = lease
            .settlement_deadline_at
            .map_or(u64::MAX, |deadline| deadline.saturating_sub(now));
        let delay = self.pending_retry_delay(retry_after_seconds).min(left / 2);
        if let Err(error) = self.store.defer_openrouter_lease_settlement(
            &lease.client_request_id,
            now.saturating_add(delay),
            now,
        ) {
            tracing::warn!(
                client_request_id = %lease.client_request_id,
                error = %error,
                "could not defer a pending lease settlement; it is asked again next tick"
            );
        }
    }

    /// A retry time given for a pending result or a rate limit, bounded: at
    /// least the poll interval, at most MAX_PENDING_SETTLEMENT_DEFERRAL_SECONDS.
    fn pending_retry_delay(&self, retry_after_seconds: u64) -> u64 {
        let poll = self
            .config
            .openrouter_leases
            .as_ref()
            .map_or(1, |config| config.settlement_poll_seconds.max(1));
        retry_after_seconds.clamp(poll, MAX_PENDING_SETTLEMENT_DEFERRAL_SECONDS.max(poll))
    }

    /// Seconds left before OA usage reads start again, while the org's rate
    /// limit (`oa_usage_rate_limited`) lasts.
    fn oa_usage_backoff(&self, now: u64) -> Option<u64> {
        let until = self.oa_usage_backoff_until.load(Ordering::Acquire);
        (until > now).then(|| until - now)
    }

    /// The OA org answered a usage read with 429 (it shares one limit across
    /// the server's leases): start no other OA usage read, in this tick, a
    /// later one or a retirement, before its retry time (bounded by
    /// `pending_retry_delay`). The result is a pending one, so the lease is
    /// deferred without counting a failure, and a retirement answers
    /// `lease_settlement_pending`. A lease that reaches its settlement
    /// deadline meanwhile is finalized as any other.
    fn oa_usage_rate_limited(&self, reason: &str, retry_after_seconds: u64) -> ServerError {
        let now = current_timestamp();
        let until = now.saturating_add(self.pending_retry_delay(retry_after_seconds));
        let previous = self
            .oa_usage_backoff_until
            .fetch_max(until, Ordering::AcqRel);
        if previous <= now {
            tracing::warn!(
                reason,
                retry_after_seconds = until - now,
                "the OA org rate-limited a lease usage read; no OA usage read starts before the retry time"
            );
        }
        ServerError::LeaseSettlementPending {
            retry_after_seconds: until.max(previous) - now,
        }
    }

    /// One provider-I/O settlement attempt for a possibly delivered lease. A
    /// deterministic failure finalizes at once without provider I/O.
    async fn settle_with_provider(&self, lease: &OpenRouterLeaseRecord) -> Result<(), ServerError> {
        let result = match lease.key_source.as_str() {
            "openrouter" => match &self.openrouter {
                Some(provisioner) => self.settle_openrouter_lease(lease, provisioner).await,
                None => Err(ServerError::Internal(
                    "direct OpenRouter settlement credential is unavailable".to_string(),
                )),
            },
            "oa_org" => self.settle_oa_org_lease(lease).await,
            // Never force-finalized, so that a rollback stays safe.
            source => Err(ServerError::Internal(format!(
                "unsupported lease key source {source}"
            ))),
        };
        match result {
            Err(ServerError::Unsettleable(message)) => {
                self.note_settlement_failure(lease, &ServerError::Unsettleable(message.clone()));
                self.finalize_lease_fallback(
                    &lease.client_request_id,
                    FallbackCause::Unsettleable(message),
                )
            }
            other => other,
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
        let pending = || ServerError::LeaseSettlementPending {
            retry_after_seconds: self
                .config
                .openrouter_leases
                .as_ref()
                .map_or(1, |lease| lease.settlement_poll_seconds.max(1)),
        };
        // The lease as stored, if `request` is its owner's proof.
        let owned_lease = || {
            let lease = self
                .store
                .try_lookup_openrouter_lease(client_request_id)?
                .ok_or_else(|| {
                    ServerError::InvalidRequest("unknown OpenRouter lease".to_string())
                })?;
            let request_matches = serde_json::to_value(request)
                .and_then(|request| {
                    serde_json::to_value(&lease.api_request).map(|issued| request == issued)
                })
                .map_err(|error| {
                    ServerError::Internal(format!(
                        "failed to compare lease retirement proof: {error}"
                    ))
                })?;
            if request.client_request_id != client_request_id || !request_matches {
                return Err(ServerError::InvalidRequest(
                    "lease retirement proof does not match the issued lease".to_string(),
                ));
            }
            Ok(lease)
        };
        // Check the proof before taking the lease's lock too, so that only
        // its owner can make the sweep leave the lease to a retirement.
        owned_lease()?;
        // Waits only for settlement of this lease.
        let Ok(_lease_guard) = tokio::time::timeout(
            self.timing.retire_lock_timeout,
            self.lease_locks.lock(client_request_id),
        )
        .await
        else {
            return Err(pending());
        };
        let lease = owned_lease()?;
        tokio::time::timeout(self.timing.retire_timeout, self.retire_locked(&lease))
            .await
            .map_err(|_| pending())??;
        // A lease the retirement settled has its successor signed at once
        // (if its nullifier is unspent); a failed chain read leaves it to the
        // signing pass of the next sweep.
        self.sign_if_settled(&lease.api_request).await;
        self.openrouter_lease_status(client_request_id)?
            .ok_or_else(|| ServerError::Internal("retired lease disappeared".to_string()))
    }

    /// Callers hold the lease's lock.
    async fn retire_locked(&self, lease: &OpenRouterLeaseRecord) -> Result<(), ServerError> {
        if lease_terminal(&lease.status) {
            return Ok(());
        }
        let result = if Self::conceded(lease) {
            self.finalize_conceded_lease(&lease.client_request_id)
        } else if Self::never_delivered(lease) {
            // Issuance may still return this key until it releases its lock.
            // Wait for it (within the retirement timeout), then settle at
            // zero only a lease that is still undelivered.
            let issue_guard = self.lease_issue_lock.lock().await;
            let current = self
                .store
                .try_lookup_openrouter_lease(&lease.client_request_id)?
                .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
            if !Self::never_delivered(&current) {
                drop(issue_guard);
                return self.retire_delivered(&current).await;
            }
            self.finalize_never_delivered_lease(&current.client_request_id)
        } else {
            return self.retire_delivered(lease).await;
        };
        if let Err(error) = &result {
            self.note_settlement_failure(lease, error);
        }
        result
    }

    /// Retire a lease that may have been delivered, or that became terminal.
    async fn retire_delivered(&self, lease: &OpenRouterLeaseRecord) -> Result<(), ServerError> {
        let now = current_timestamp();
        let result = match lease.status.as_str() {
            status if lease_terminal(status) => return Ok(()),
            "active" | "retiring" | "disabled" | "revoking" => {
                match self.settlement_deadline(lease, now)? {
                    deadline
                        if now >= deadline
                            && matches!(lease.key_source.as_str(), "openrouter" | "oa_org") =>
                    {
                        self.finalize_lease_fallback(
                            &lease.client_request_id,
                            FallbackCause::Deadline,
                        )
                    }
                    _ => {
                        // Like pass 2, honour the deferral of a pending
                        // result: repeated retirements of a lease whose
                        // receipt is pending answer without provider I/O.
                        if let Some(next_attempt_at) = self.pending_deferral(lease, now)? {
                            return Err(ServerError::LeaseSettlementPending {
                                retry_after_seconds: next_attempt_at - now,
                            });
                        }
                        // Nor does it ask a rate-limiting OA org again early.
                        if lease.key_source == "oa_org" {
                            if let Some(retry_after_seconds) = self.oa_usage_backoff(now) {
                                return Err(ServerError::LeaseSettlementPending {
                                    retry_after_seconds,
                                });
                            }
                        }
                        self.settle_with_provider(lease).await
                    }
                }
            }
            _ => return Err(ServerError::LeasePending),
        };
        if let Err(error) = &result {
            self.note_settlement_failure(lease, error);
        }
        result
    }

    /// Check a lease row against its nullifier reservation. A mismatch is a
    /// corrupt binding (never signed), named in its review; a different
    /// deployment or signing key is an operator configuration error and stays
    /// pending. A lease the operator reopened has its saved request verified
    /// again, as admission verified it: one its owner's proof does not
    /// authorize is a corrupt binding too.
    fn check_lease_binding(
        &self,
        lease: &OpenRouterLeaseRecord,
    ) -> Result<LeaseBinding, ServerError> {
        let public = &lease.api_request.public_inputs;
        let record = self
            .store
            .try_lookup_by_nullifier(&lease.request_nullifier)?;
        let record = match (lease_binding_mismatch(lease, record.as_ref())?, record) {
            (None, Some(record)) => record,
            (mismatch, _) => {
                // Unverified here: either side may be the corrupt one.
                return Ok(LeaseBinding::Corrupt(mismatch.map_or_else(
                    || "lease has no nullifier reservation".into(),
                    |mismatch| {
                        format!(
                            "lease row does not match its nullifier reservation: {mismatch} \
                             (either side may be corrupt; `zkapi settlement reopen` verifies \
                             the saved request and names the side to repair)"
                        )
                    },
                )));
            }
        };
        let signing_key = self.state_signing_key();
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
            || public.state_signing_key_x != signing_key.x
            || public.state_signing_key_y != signing_key.y
        {
            return Err(ServerError::Internal(
                "lease belongs to a different deployment or state signing key; refusing to sign"
                    .into(),
            ));
        }
        // A signed transcript is only reconciled: nothing more is signed.
        if record.status != NullifierStatus::Finalized
            && self.store.lease_reopened(&lease.client_request_id)?
        {
            if let Some(mismatch) = saved_request_mismatch(&self.verifier, &lease.api_request) {
                return Ok(LeaseBinding::Corrupt(format!(
                    "the reopened lease's saved request does not verify: {mismatch}"
                )));
            }
        }
        Ok(LeaseBinding::Valid(Box::new(record)))
    }

    fn review(
        lease: &OpenRouterLeaseRecord,
        reason: &str,
        charge_basis: Option<&str>,
        detail: String,
        reported_usage_micro_usd: Option<u128>,
        charge_applied: Option<u128>,
    ) -> SettlementReview {
        SettlementReview {
            client_request_id: lease.client_request_id.clone(),
            request_nullifier: lease.request_nullifier,
            key_source: lease.key_source.clone(),
            reason: reason.to_string(),
            charge_basis: charge_basis.map(str::to_string),
            detail,
            reported_usage_micro_usd,
            charge_applied,
            solvency_bound: lease.api_request.public_inputs.solvency_bound,
        }
    }

    fn direct_key_cleanup<'a>(
        lease: &'a OpenRouterLeaseRecord,
        key_name: &'a str,
    ) -> Option<KeyCleanup<'a>> {
        (lease.key_source == "openrouter").then_some(KeyCleanup {
            key_source: "openrouter",
            key_hash: lease.key_hash.as_deref(),
            key_name,
        })
    }

    /// Cancel a lease whose binding is corrupt. Nothing is ever signed for
    /// it; a direct key it may hold is still disabled and deleted in the
    /// background, queued with the cancellation. (A possibly delivered direct
    /// lease settled with provider I/O reaches this only once its usage is
    /// captured, or at its deadline, so that a reopening can charge that
    /// usage; a review was also recorded when its corruption was found.)
    fn cancel_corrupt_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
        detail: &str,
    ) -> Result<(), ServerError> {
        let review = Self::review(
            lease,
            "binding_corrupt",
            None,
            detail.to_string(),
            None,
            None,
        );
        Self::alert_corrupt_binding(lease);
        let key_name = format!("zkapi-{}", lease.client_request_id);
        self.store.cancel_corrupt_openrouter_lease(
            &lease.client_request_id,
            &review,
            Self::direct_key_cleanup(lease, &key_name),
        )
    }

    /// Record the `binding_corrupt` review of a pending lease at once, while
    /// its cancellation waits for its key's usage to be captured, so that its
    /// alert is not delayed: once, not on every attempt.
    fn review_corrupt_binding(
        &self,
        lease: &OpenRouterLeaseRecord,
        detail: &str,
    ) -> Result<(), ServerError> {
        let review = Self::review(
            lease,
            "binding_corrupt",
            None,
            format!(
                "{detail}; its key is disabled and its usage captured first, retried like any \
                 settlement until its deadline, then the lease is cancelled"
            ),
            None,
            None,
        );
        if self.store.review_corrupt_binding(&review)? {
            Self::alert_corrupt_binding(lease);
        }
        Ok(())
    }

    fn alert_corrupt_binding(lease: &OpenRouterLeaseRecord) {
        tracing::error!(
            client_request_id = %lease.client_request_id,
            reason = "binding_corrupt",
            "settlement required operator review"
        );
    }

    /// The transcript committed before the lease row (a crash window, or a
    /// legacy row): record the lease from the signed transcript, never
    /// signing another balance.
    fn reconcile_finalized_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
        record: &TranscriptRecord,
    ) -> Result<(), ServerError> {
        let payload = record
            .response_payload
            .as_deref()
            .and_then(|payload| serde_json::from_str::<serde_json::Value>(payload).ok())
            .unwrap_or_default();
        let usage_usd = payload["usage_usd"].as_f64().unwrap_or_else(|| {
            payload["usage_credits"]
                .as_u64()
                .map(|credits| pricing::micro_usd_to_usd(u128::from(credits)))
                .unwrap_or_default()
        });
        let basis = payload["charge_basis"].as_str().unwrap_or("measured");
        let key_name = format!("zkapi-{}", lease.client_request_id);
        self.store.finalize_openrouter_lease_with(
            &lease.client_request_id,
            &LeaseFinalization {
                usage_usd,
                charge_applied: record.charge_applied.unwrap_or_default(),
                charge_basis: basis,
                review: None,
                // Deletion is idempotent: a crash may have preceded it.
                key_cleanup: Self::direct_key_cleanup(lease, &key_name),
                guard: FinalizeGuard::NotCancelled,
            },
        )?;
        Ok(())
    }

    /// Finalize a lease whose runtime key was never returned to the client
    /// at zero: provisioning rows, and activations whose key was never
    /// delivered. Callers hold lease_issue_lock, so no issuance can deliver
    /// the key meanwhile; the row is also fenced before signing, so that the
    /// key can never be delivered afterwards. Zero-charge successors are
    /// always signed. A direct key that may exist is deleted in the background.
    fn finalize_never_delivered_lease(&self, client_request_id: &str) -> Result<(), ServerError> {
        let lease = self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
        if lease_terminal(&lease.status) {
            return Ok(());
        }
        if !Self::never_delivered(&lease) {
            return Err(ServerError::Internal(
                "lease may have been delivered; it cannot settle at zero".into(),
            ));
        }
        let record = match self.check_lease_binding(&lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(&lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(&lease, &record);
        }
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::LeasePending);
        }
        // Commit to the zero charge before signing it: from here on the key
        // can neither be activated nor marked delivered.
        if !self.store.fence_unissued_settlement(client_request_id)? {
            return Err(ServerError::Internal(
                "lease key was delivered before its zero settlement".into(),
            ));
        }
        let reason = match (lease.status.as_str(), lease.key_source.as_str()) {
            ("provisioning", "oa_org") => match lease.oa_provisioning_outcome {
                OaProvisioningOutcome::NotStarted => "issuance_not_started",
                OaProvisioningOutcome::ConfirmedUnissued => "issuer_policy_rejected",
                OaProvisioningOutcome::MayHaveIssued => "issuance_not_completed",
            },
            ("provisioning", _) => "issuance_not_completed",
            _ => "key_never_delivered",
        };
        let (body, billing_label) = if lease.key_source == "oa_org" {
            (
                serde_json::json!({
                    "type": "oa_org_unissued_lease_cancellation",
                    "issued": false,
                    "delivered": false,
                    "usage_credits": 0,
                    "usage_usd": 0,
                    "charge_basis": "unissued",
                    "reason": reason,
                }),
                "direct:oa-org-unissued",
            )
        } else {
            (
                serde_json::json!({
                    "type": "openrouter_ephemeral_lease_settlement",
                    "issued": false,
                    "delivered": false,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_usd": 0,
                    "charge_basis": "unissued",
                    "reason": reason,
                }),
                "direct:openrouter-unissued",
            )
        };
        if !self.finalize_at_zero(
            &lease,
            body,
            billing_label,
            "unissued",
            FinalizeGuard::Unissued,
        )? {
            return Ok(());
        }
        tracing::info!(
            client_request_id = %lease.client_request_id,
            reason,
            "finalized a never-delivered lease at zero"
        );
        Ok(())
    }

    /// Finalize at zero a lease the operator reopened with a concession
    /// (`charge_basis` "operator_conceded"), whatever was delivered: the
    /// operator concedes its charge. Signed only once the binding, deployment
    /// and signing key check out again. A direct key that may exist is
    /// deleted in the background.
    fn finalize_conceded_lease(&self, client_request_id: &str) -> Result<(), ServerError> {
        let lease = self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
        if lease_terminal(&lease.status) {
            return Ok(());
        }
        if !Self::conceded(&lease) {
            return Err(ServerError::Internal(
                "lease charge was not conceded".into(),
            ));
        }
        let record = match self.check_lease_binding(&lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(&lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(&lease, &record);
        }
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::LeasePending);
        }
        let source_type = if lease.key_source == "oa_org" {
            "oa_org_ephemeral_lease_settlement"
        } else {
            "openrouter_ephemeral_lease_settlement"
        };
        let body = serde_json::json!({
            "type": source_type,
            "issued_at": lease.issued_at,
            "expires_at": lease.expires_at,
            "usage_usd": 0,
            "charge_basis": "operator_conceded",
            "settlement_reason": "operator_conceded",
        });
        let billing_label = format!("direct:{}-operator-conceded", lease.key_source);
        if !self.finalize_at_zero(
            &lease,
            body,
            &billing_label,
            "operator_conceded",
            FinalizeGuard::Conceded,
        )? {
            return Ok(());
        }
        tracing::info!(
            client_request_id = %lease.client_request_id,
            "finalized a reopened lease at zero; the operator conceded its charge"
        );
        Ok(())
    }

    /// Settle a lease committed to a zero charge under `guard`; its
    /// successor is signed by the signing pass. Returns false when its saved
    /// request can never be signed: the lease is then cancelled as a corrupt
    /// binding.
    fn finalize_at_zero(
        &self,
        lease: &OpenRouterLeaseRecord,
        body: serde_json::Value,
        billing_label: &str,
        charge_basis: &str,
        guard: FinalizeGuard,
    ) -> Result<bool, ServerError> {
        let request = &lease.api_request;
        let payload = self.fallback_settlement_payload(request, body);
        let key_name = format!("zkapi-{}", lease.client_request_id);
        let settled = match self.settle_lease(
            lease,
            SettlementResult {
                status_code: 200,
                payload,
                charge_applied: 0,
                usage: None,
                billing_label: billing_label.into(),
            },
            charge_basis,
            0.0,
            None,
            // Best effort and outside every lock: retries now return the
            // settled lease before any key creation.
            Self::direct_key_cleanup(lease, &key_name),
            guard,
        ) {
            Ok(settled) => settled,
            Err(ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail)) => {
                self.cancel_corrupt_lease(lease, &detail)?;
                return Ok(false);
            }
            Err(error) => return Err(error),
        };
        if settled.is_none() {
            // Nothing was written; the next scan sees the lease as it is.
            return Err(ServerError::Internal(
                "lease changed during zero settlement".into(),
            ));
        }
        Ok(true)
    }

    /// Finalize a possibly delivered lease without provider I/O: at its
    /// captured usage when a direct key was already disabled and only its
    /// deletion failed, otherwise at the request's solvency bound. Records an
    /// operator review. A corrupt binding is cancelled, never signed.
    fn finalize_lease_fallback(
        &self,
        client_request_id: &str,
        cause: FallbackCause,
    ) -> Result<(), ServerError> {
        let lease = self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .ok_or_else(|| ServerError::Internal("pending lease disappeared".into()))?;
        if lease_terminal(&lease.status) {
            return Ok(());
        }
        if !Self::may_have_delivered(&lease) {
            return Err(ServerError::Internal(
                "a never-delivered lease settles at zero".into(),
            ));
        }
        let record = match self.check_lease_binding(&lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(&lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(&lease, &record);
        }
        if record.status != NullifierStatus::Reserved {
            return Err(ServerError::LeasePending);
        }
        let request = &lease.api_request;
        let bound = request.public_inputs.solvency_bound;
        let deadline = lease.settlement_deadline_at;
        let (settlement_reason, detail) = match &cause {
            FallbackCause::Deadline => (
                "settlement_deadline",
                format!(
                    "not settled by its deadline; last error: {}",
                    lease.last_error.as_deref().unwrap_or("none")
                ),
            ),
            FallbackCause::Unsettleable(message) => ("unsettleable", message.clone()),
        };
        let source_type = if lease.key_source == "oa_org" {
            "oa_org_ephemeral_lease_settlement"
        } else {
            "openrouter_ephemeral_lease_settlement"
        };
        // A revoking direct key was confirmed disabled and its usage captured;
        // only deletion failed. Charge that usage, not the worst case.
        let captured = match (
            lease.key_source.as_str(),
            lease.status.as_str(),
            lease.usage_usd,
        ) {
            ("openrouter", "revoking", Some(usage_usd)) => Self::lease_terms(request)
                .ok()
                .map(|(_, quote)| (usage_usd, quote)),
            _ => None,
        };
        let (charge, basis, usage_usd, review, body) = match captured {
            Some((usage_usd, quote)) => {
                let reported = pricing::usd_to_micro_usd(usage_usd);
                let capped = quote.capped_charge_units(reported, bound);
                let basis = if capped.clamped {
                    "clamped"
                } else {
                    "measured"
                };
                let mut body = serde_json::json!({
                    "type": source_type,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_usd": usage_usd,
                    "charge_basis": basis,
                    "settlement_reason": settlement_reason,
                    "key_deleted": false,
                });
                if capped.clamped {
                    body["reported_usage_micro_usd"] = reported.to_string().into();
                    body["charged_usage_micro_usd"] = capped.charged_micro_usd.to_string().into();
                }
                let review = Self::review(
                    &lease,
                    "finalized_before_key_deletion",
                    Some(basis),
                    detail,
                    Some(reported),
                    Some(capped.charge),
                );
                (capped.charge, basis, usage_usd, review, body)
            }
            None => {
                let body = serde_json::json!({
                    "type": source_type,
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "charge_basis": "worst_case",
                    "settlement_reason": settlement_reason,
                    "settlement_deadline": deadline,
                });
                let reason = match cause {
                    FallbackCause::Deadline => "deadline_worst_case",
                    FallbackCause::Unsettleable(_) => "unsettleable_worst_case",
                };
                let review = Self::review(
                    &lease,
                    reason,
                    Some("worst_case"),
                    detail,
                    None,
                    Some(bound),
                );
                (bound, "worst_case", 0.0, review, body)
            }
        };
        let payload = self.fallback_settlement_payload(request, body);
        let key_name = format!("zkapi-{}", lease.client_request_id);
        let settled = match self.settle_lease(
            &lease,
            SettlementResult {
                status_code: 200,
                payload,
                charge_applied: charge,
                usage: None,
                billing_label: format!("direct:{}-{basis}", lease.key_source),
            },
            basis,
            usage_usd,
            Some(&review),
            Self::direct_key_cleanup(&lease, &key_name),
            FinalizeGuard::NotCancelled,
        ) {
            Ok(Some(settled)) => settled,
            Ok(None) => {
                return Err(ServerError::Internal(
                    "lease changed during its fallback settlement".into(),
                ))
            }
            Err(ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail)) => {
                return self.cancel_corrupt_lease(&lease, &detail)
            }
            Err(error) => return Err(error),
        };
        tracing::error!(
            client_request_id = %lease.client_request_id,
            reason = %review.reason,
            charge = settled.charge,
            "settlement required operator review"
        );
        Ok(())
    }

    /// Ask the OA org for the station-signed final child-key usage. Pending or
    /// unavailable receipts are retried until the lease's deadline.
    async fn settle_oa_org_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
    ) -> Result<(), ServerError> {
        let record = match self.check_lease_binding(lease)? {
            LeaseBinding::Valid(record) => record,
            LeaseBinding::Corrupt(detail) => return self.cancel_corrupt_lease(lease, &detail),
        };
        if record.status == NullifierStatus::Finalized {
            return self.reconcile_finalized_lease(lease, &record);
        }
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OA org lease has no key hash".to_string())
        })?;
        let provisioner = self.oa_org.as_ref().ok_or_else(|| {
            ServerError::Internal("OA org lease provider is unavailable".to_string())
        })?;
        let duration_minutes = self.lease_ttl_seconds(lease)? / 60;
        let (_, quote) = Self::lease_terms(&lease.api_request)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let bound = lease.api_request.public_inputs.solvency_bound;
        let expected_limit_credits = quote
            .limit_micro_usd(bound)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        if lease.spending_limit_usd.to_bits()
            != pricing::micro_usd_to_usd(expected_limit_credits).to_bits()
        {
            return Err(ServerError::Unsettleable(
                "OA lease spending limit does not match its bound request".into(),
            ));
        }
        let oa_request_id = self.oa_usage_request_id(lease)?;
        let receipt = match provisioner
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
            .await
        {
            Err(ServerError::OaRateLimited {
                reason,
                retry_after_seconds,
            }) => return Err(self.oa_usage_rate_limited(&reason, retry_after_seconds)),
            other => other?,
        };
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
        // Clamp before conversion: a receipt above the issued limit still
        // settles, at no more than the proof-bound budget.
        let capped = quote.capped_charge_units(receipt.usage_credits, bound);
        let basis = if capped.clamped {
            "clamped"
        } else {
            "measured"
        };
        let usage_usd = pricing::micro_usd_to_usd(receipt.usage_credits);
        let payload = self
            .settlement_payload(
                &lease.api_request,
                serde_json::json!({
                    "type": "oa_org_ephemeral_lease_settlement",
                    "issued_at": lease.issued_at,
                    "expires_at": lease.expires_at,
                    "usage_credits": receipt.usage_credits,
                    "charged_usage_credits": capped.charged_micro_usd,
                    "usage_usd": usage_usd,
                    "charge_basis": basis,
                    "usage_receipt_expires_at": receipt.expires_at,
                    "usage_receipt_closed_at": receipt.closed_at,
                    "usage_finalized_at": receipt.finalized_at,
                    "station_id": receipt.station_id,
                    "station_signature": receipt.station_signature,
                    "org_signature": receipt.org_signature,
                }),
            )
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: capped.charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "oa_org_signed_usage_receipt".to_string(),
            }),
            billing_label: "direct:oa-org-ephemeral".to_string(),
        };
        let review = capped.clamped.then(|| {
            Self::review(
                lease,
                "usage_clamped",
                Some(basis),
                "station-signed usage exceeded the proof-bound lease budget".into(),
                Some(receipt.usage_credits),
                Some(
                    capped
                        .charge
                        .min(lease.api_request.public_inputs.solvency_bound),
                ),
            )
        });
        self.finish_measured_settlement(lease, provider_response, usage_usd, basis, review)
    }

    async fn settle_openrouter_lease(
        &self,
        lease: &crate::nullifier_store::OpenRouterLeaseRecord,
        provisioner: &OpenRouterProvisioner,
    ) -> Result<(), ServerError> {
        // A corrupt binding is never signed. Its key, which may have been
        // delivered, is still retired up to its captured usage first, retried
        // like any settlement until its deadline (where the fallback cancels
        // it without usage): the cancellation keeps that usage, so that a
        // reopening charges it, and queues the key's deletion. Its review is
        // recorded at once.
        let corrupt = match self.check_lease_binding(lease)? {
            LeaseBinding::Valid(record) if record.status == NullifierStatus::Finalized => {
                // Also reconcile a legacy/crash-window finalized transcript; its
                // key deletion is queued and retried in the background.
                return self.reconcile_finalized_lease(lease, &record);
            }
            LeaseBinding::Valid(_) => None,
            LeaseBinding::Corrupt(detail) => {
                self.review_corrupt_binding(lease, &detail)?;
                Some(detail)
            }
        };
        let usage_usd = self.capture_openrouter_usage(lease, provisioner).await?;
        if let Some(detail) = corrupt {
            return self.cancel_corrupt_lease(lease, &detail);
        }
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OpenRouter lease has no key hash".to_string())
        })?;
        // Fail closed until the deadline. A 503 or ambiguous DELETE leaves the
        // nullifier reserved and the revoking lease visible to the scanner.
        provisioner.delete_key(key_hash).await?;
        let (_, quote) = Self::lease_terms(&lease.api_request)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        // Clamp to the proof-bound budget before converting, so that no
        // reported usage can make the conversion fail.
        let reported = pricing::usd_to_micro_usd(usage_usd);
        let capped =
            quote.capped_charge_units(reported, lease.api_request.public_inputs.solvency_bound);
        let basis = if capped.clamped {
            "clamped"
        } else {
            "measured"
        };
        let mut body = serde_json::json!({
            "type": "openrouter_ephemeral_lease_settlement",
            "issued_at": lease.issued_at,
            "expires_at": lease.expires_at,
            "usage_usd": usage_usd,
            "charge_basis": basis,
        });
        if capped.clamped {
            tracing::warn!(
                client_request_id = %lease.client_request_id,
                reported_micro_usd = reported,
                charge = capped.charge,
                "OpenRouter usage exceeded the proof-bound lease limit; clamped charge"
            );
            body["reported_usage_micro_usd"] = reported.to_string().into();
            body["charged_usage_micro_usd"] = capped.charged_micro_usd.to_string().into();
        }
        let payload = self
            .settlement_payload(&lease.api_request, body)
            .map_err(|error| ServerError::Unsettleable(error.to_string()))?;
        let provider_response = SettlementResult {
            status_code: 200,
            payload,
            charge_applied: capped.charge,
            usage: Some(UsageInfo {
                cost_usd: usage_usd,
                cost_source: "openrouter_key_aggregate".to_string(),
            }),
            billing_label: "direct:openrouter-ephemeral".to_string(),
        };
        let review = capped.clamped.then(|| {
            Self::review(
                lease,
                "usage_clamped",
                Some(basis),
                "OpenRouter usage exceeded the proof-bound lease budget".into(),
                Some(reported),
                Some(
                    capped
                        .charge
                        .min(lease.api_request.public_inputs.solvency_bound),
                ),
            )
        });
        self.finish_measured_settlement(lease, provider_response, usage_usd, basis, review)
    }

    /// Retire a direct key up to its captured usage, persisting each phase
    /// before its side effect: disable it (retiring), wait out the provider's
    /// drain interval (disabled), then capture its usage (revoking). A
    /// revoking lease returns the usage captured earlier.
    async fn capture_openrouter_usage(
        &self,
        lease: &OpenRouterLeaseRecord,
        provisioner: &OpenRouterProvisioner,
    ) -> Result<f64, ServerError> {
        let key_hash = lease.key_hash.as_deref().ok_or_else(|| {
            ServerError::Internal("active OpenRouter lease has no key hash".to_string())
        })?;
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
            let grace = self.lease_config()?.settlement_grace_seconds;
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
        if phase == "disabled" {
            let now = current_timestamp();
            if now < settle_after {
                return Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds: settle_after - now,
                });
            }
            let usage = provisioner.get_key_usage(key_hash).await?;
            if !usage.disabled {
                // The write-once deadline still applies across this cycle.
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
            Ok(usage.usage_usd)
        } else if phase == "revoking" {
            lease.usage_usd.ok_or_else(|| {
                ServerError::Unsettleable(
                    "OpenRouter revocation has no persisted usage".to_string(),
                )
            })
        } else {
            Err(ServerError::LeasePending)
        }
    }

    /// A signing failure caused by the persisted request itself cannot heal.
    fn deterministic_as_unsettleable(error: ServerError) -> ServerError {
        match error {
            ServerError::InvalidProof(detail) | ServerError::InvalidRequest(detail) => {
                ServerError::Unsettleable(detail)
            }
            other => other,
        }
    }

    /// Settle a lease from its measured usage. A request that can never be
    /// signed is unsettleable (the caller finalizes it at the fallback).
    fn finish_measured_settlement(
        &self,
        lease: &OpenRouterLeaseRecord,
        result: SettlementResult,
        usage_usd: f64,
        basis: &str,
        review: Option<SettlementReview>,
    ) -> Result<(), ServerError> {
        let settled = self
            .settle_lease(
                lease,
                result,
                basis,
                usage_usd,
                review.as_ref(),
                None,
                FinalizeGuard::NotCancelled,
            )
            .map_err(Self::deterministic_as_unsettleable)?
            .ok_or_else(|| ServerError::Internal("lease changed during its settlement".into()))?;
        if let Some(review) = &review {
            tracing::error!(
                client_request_id = %lease.client_request_id,
                reason = %review.reason,
                charge = settled.charge,
                "settlement required operator review"
            );
        }
        Ok(())
    }

    /// Disable and delete the provider keys of terminal direct leases, retried
    /// with backoff until the provider confirms removal (404 included). Runs
    /// outside every lock: a terminal lease's retries never create a key.
    async fn cleanup_provider_keys(&self) {
        let Some(provisioner) = self.openrouter.as_ref() else {
            return;
        };
        let started = Instant::now();
        let now = current_timestamp();
        let pending = match self.store.due_key_cleanups(now, KEY_CLEANUP_BATCH) {
            Ok(pending) => pending,
            Err(error) => {
                tracing::warn!(error = %error, "provider key cleanup scan failed");
                return;
            }
        };
        for cleanup in pending {
            if started.elapsed() >= self.timing.cleanup_budget {
                break;
            }
            if cleanup.key_source != "openrouter" {
                let _ = self.store.complete_key_cleanup(&cleanup.client_request_id);
                continue;
            }
            let attempt = async {
                match cleanup.key_hash.as_deref() {
                    Some(hash) => provisioner.retire_key(hash).await,
                    None => provisioner.retire_keys_named(&cleanup.key_name).await,
                }
            };
            let result = tokio::time::timeout(self.timing.cleanup_attempt_timeout, attempt)
                .await
                .unwrap_or_else(|_| Err(ServerError::Internal("key cleanup timed out".into())));
            match result {
                Ok(()) => {
                    let _ = self.store.complete_key_cleanup(&cleanup.client_request_id);
                }
                Err(error) => {
                    let backoff = 2u64
                        .saturating_pow(cleanup.attempts.min(16) as u32)
                        .min(KEY_CLEANUP_MAX_BACKOFF_SECONDS);
                    tracing::warn!(
                        client_request_id = %cleanup.client_request_id,
                        error = %error,
                        "provider key cleanup will be retried"
                    );
                    let _ = self.store.defer_key_cleanup(
                        &cleanup.client_request_id,
                        &error.to_string(),
                        now.saturating_add(backoff),
                    );
                }
            }
        }
    }

    /// Validate proof/deployment bindings and reserve the request nullifier.
    /// Returns a prior finalized response for an idempotent replay.
    #[cfg(test)]
    fn validate_and_reserve(
        &self,
        request: &ApiRequestV2,
    ) -> Result<Option<RequestResponseV2>, ServerError> {
        self.validate_and_reserve_with(request, None)
    }

    /// `validate_and_reserve`, writing `issuance`'s lease row in the
    /// reservation's transaction.
    fn validate_and_reserve_with(
        &self,
        request: &ApiRequestV2,
        issuance: Option<&IssuanceLease<'_>>,
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
        if let Some(existing) = self
            .store
            .try_lookup_by_nullifier(&public.request_nullifier)?
        {
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
                NullifierStatus::ExitedUnsigned => Err(ServerError::NullifierUsed),
            };
        }
        // O5: only the exact current root, confirmed by the vault recently.
        let root = self.fresh_root(current_timestamp())?;
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
        if public.request_time.saturating_add(MAX_REQUEST_AGE_SECONDS) < now
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
        let lease = issuance
            .map(|issuance| self.issuance_lease_row(request, issuance, current_timestamp()));
        self.store
            .reserve_openrouter_lease_with(request, lease.as_ref())?;
        Ok(None)
    }

    /// Settle a lease (§5.1 step 1): fix its charge and persist it on the
    /// reservation, which stays Reserved, while finalizing the lease row
    /// under `guard`, with its review and key cleanup, in one transaction.
    /// The charge is clamped to the request's solvency bound. A request that
    /// can never be signed (`check_signable`) is refused with InvalidProof
    /// before anything is written. Returns None, writing nothing, when the
    /// lease row no longer satisfies `guard`. The successor is signed later
    /// (`sign_successor`), only while the nullifier is unspent on chain.
    #[allow(clippy::too_many_arguments)]
    fn settle_lease(
        &self,
        lease: &OpenRouterLeaseRecord,
        result: SettlementResult,
        basis: &str,
        usage_usd: f64,
        review: Option<&SettlementReview>,
        key_cleanup: Option<KeyCleanup<'_>>,
        guard: FinalizeGuard,
    ) -> Result<Option<SettledCharge>, ServerError> {
        let request = &lease.api_request;
        let public = &request.public_inputs;
        if public.protocol_version != self.config.protocol_version
            || public.chain_id != self.config.chain_id
            || public.contract_address != self.config.contract_address
        {
            return Err(ServerError::Internal(
                "refusing to settle a successor for a different deployment".into(),
            ));
        }
        check_signable(request)?;
        // The request proved balance >= solvency_bound; never charge more.
        let charge = result.charge_applied.min(public.solvency_bound);
        if charge != result.charge_applied {
            tracing::error!(
                client_request_id = %request.client_request_id,
                charge = result.charge_applied,
                solvency_bound = public.solvency_bound,
                "settlement charge exceeded the solvency bound; clamped"
            );
        }
        let settlement = SettledCharge {
            charge,
            basis: basis.to_string(),
            response_code: result.status_code,
            response_payload: result.payload,
            settled_at: current_timestamp(),
        };
        let outcome = self.store.settle_openrouter_lease(
            &lease.client_request_id,
            &public.request_nullifier,
            &settlement,
            &LeaseFinalization {
                usage_usd,
                charge_applied: charge,
                charge_basis: basis,
                review,
                key_cleanup,
                guard,
            },
        )?;
        Ok(match outcome {
            SettleOutcome::Settled(settled) => {
                if let Some(hub) = &self.dashboard {
                    self.record_dashboard_settlement(
                        hub,
                        request,
                        &settled,
                        &result.billing_label,
                        result.usage.as_ref(),
                    );
                }
                Some(settled)
            }
            SettleOutcome::LeaseChanged => None,
        })
    }

    fn record_dashboard_settlement(
        &self,
        hub: &DashboardHub,
        request: &ApiRequestV2,
        settled: &SettledCharge,
        billing_label: &str,
        usage: Option<&UsageInfo>,
    ) {
        let public = &request.public_inputs;
        hub.record(DashboardEvent {
            seq: hub.next_seq(),
            ts_ms: current_timestamp_ms(),
            client_request_id: request.client_request_id.clone(),
            billing_label: billing_label.to_string(),
            request_nullifier: public.request_nullifier,
            active_root: public.active_root,
            anon_commitment: CurvePointWire {
                x: public.anonymous_commitment_x,
                y: public.anonymous_commitment_y,
            },
            solvency_bound: public.solvency_bound,
            solvency_bound_usd: Self::lease_terms(request)
                .ok()
                .and_then(|(_, quote)| quote.limit_micro_usd(public.solvency_bound).ok())
                .map(pricing::micro_usd_to_usd)
                .unwrap_or(0.0),
            proof_backend: "groth16_bn254".to_string(),
            proof_public_output_hash: public.authorization_tag,
            proof_size_bytes: 256,
            request_raw: redact_secrets(&request.payload),
            response_code: settled.response_code,
            response_text: redact_secrets(&settled.response_payload),
            response_hash: zkapi_types::canonical_response_hash(
                settled.response_payload.as_bytes(),
            ),
            usage: usage.cloned(),
            charge_applied: settled.charge,
            charge_usd: usage.map(|usage| usage.cost_usd).unwrap_or(0.0),
            upstream_ms: 0,
            total_ms: 0,
        });
    }

    /// Whether the request at `nullifier` is unspent on chain
    /// (`usedNullifiers(N) == false` at latest): Ok, NullifierUsed, or a
    /// retriable error when the chain cannot be read.
    async fn request_unspent(&self, nullifier: &Felt252) -> Result<(), ServerError> {
        #[cfg(test)]
        if let Some(chain) = &self.test_chain {
            let mut chain = chain.lock().unwrap();
            chain.reads += 1;
            if chain.unavailable {
                return Err(ServerError::Internal("test chain unavailable".into()));
            }
            return if chain.used.contains(nullifier) {
                Err(ServerError::NullifierUsed)
            } else {
                Ok(())
            };
        }
        self.native_oracle.assert_request_unspent(nullifier).await
    }

    /// How long a settled request's signature waits, after its nullifier was
    /// first found consumed, for the consuming exit to be defeated (O7).
    fn exit_deferral_window(&self) -> Option<u64> {
        self.config
            .challenge_period_seconds
            .map(|period| period.saturating_add(EXIT_DEFERRAL_SLACK_SECONDS))
    }

    /// Sign the successor of a settled request (§5.1 step 2, O7): only if its
    /// nullifier is unspent on chain (`usedNullifiers(N)` at latest). A
    /// consumed nullifier defers the signature, from its first observation,
    /// and after `challengePeriod + 3600` s makes the request ExitedUnsigned
    /// (terminal); a defeated exit clears the flag and the successor is
    /// signed at the persisted charge. A signed or ended request returns its
    /// outcome without a chain read. A failed chain read is an error, and the
    /// next sweep retries.
    pub async fn sign_successor(&self, request: &ApiRequestV2) -> Result<SignOutcome, ServerError> {
        let nullifier = request.public_inputs.request_nullifier;
        let record = self
            .store
            .try_lookup_by_nullifier(&nullifier)?
            .ok_or_else(|| ServerError::Internal("the request has no reservation".into()))?;
        match record.status {
            NullifierStatus::Finalized => {
                return Ok(SignOutcome::Signed(Box::new(response_from_record(
                    &record,
                    &request.client_request_id,
                )?)))
            }
            NullifierStatus::ExitedUnsigned => return Ok(SignOutcome::ExitedUnsigned),
            NullifierStatus::Reserved if record.settled_charge.is_some() => {}
            status => {
                return Err(ServerError::Internal(format!(
                    "the request is not settled ({status:?}); nothing to sign"
                )))
            }
        }
        match self.request_unspent(&nullifier).await {
            Ok(()) => Ok(SignOutcome::Signed(Box::new(self.sign_settled(request)?))),
            Err(ServerError::NullifierUsed) => {
                match self.store.defer_signature(
                    &nullifier,
                    current_timestamp(),
                    self.exit_deferral_window(),
                )? {
                    SignatureDeferral::Deferred { since } => {
                        if record.exit_deferred_since.is_none() {
                            tracing::warn!(
                                client_request_id = %request.client_request_id,
                                "the settled request's nullifier is consumed on chain by an exit; its successor is not signed unless the exit is defeated (exit_deferred)"
                            );
                        }
                        Ok(SignOutcome::Deferred { since })
                    }
                    SignatureDeferral::ExitedUnsigned => {
                        tracing::warn!(
                            client_request_id = %request.client_request_id,
                            "the exit consuming the settled request's nullifier was not defeated within the deferral window; no successor is ever signed (ExitedUnsigned)"
                        );
                        Ok(SignOutcome::ExitedUnsigned)
                    }
                }
            }
            Err(error) => Err(error),
        }
    }

    /// Sign and record the successor of a settled request at its persisted
    /// charge, after the caller established its nullifier is unspent. The
    /// transcript is written once (`finalize_signed`).
    fn sign_settled(&self, request: &ApiRequestV2) -> Result<RequestResponseV2, ServerError> {
        #[cfg(feature = "adversary")]
        if self.adversary == Some(crate::adversary::AdversaryMode::Withhold) {
            return Err(ServerError::Internal(
                "adversary withhold: the successor is never signed".into(),
            ));
        }
        let nullifier = request.public_inputs.request_nullifier;
        let record = self
            .store
            .try_lookup_by_nullifier(&nullifier)?
            .ok_or_else(|| ServerError::Internal("the request has no reservation".into()))?;
        if record.reservation_kind != "openrouter_lease" {
            return Err(ServerError::InvalidRequest(
                "only native lease reservations can settle".into(),
            ));
        }
        if record.client_request_id.as_deref() != Some(request.client_request_id.as_str())
            || record.api_request_binding.as_deref() != Some(api_request_binding(request)?.as_str())
        {
            return Err(ServerError::Internal(
                "the request does not match its reservation; refusing to sign".into(),
            ));
        }
        // Signed already, ended, or not settled: nothing to sign (O1).
        let (NullifierStatus::Reserved, Some(charge), Some(basis)) = (
            record.status,
            record.settled_charge,
            record.settled_basis.clone(),
        ) else {
            return Err(ServerError::Internal(format!(
                "the request is {:?}{}: no successor is signed",
                record.status,
                if record.settled_charge.is_some() {
                    ""
                } else {
                    " and not settled"
                }
            )));
        };
        #[allow(unused_mut)]
        let mut settled = SettledCharge {
            charge,
            basis,
            response_code: record.response_code.unwrap_or(200),
            response_payload: record.response_payload.clone().unwrap_or_default(),
            settled_at: record.settled_at.unwrap_or_default(),
        };
        #[cfg(feature = "adversary")]
        if self.adversary == Some(crate::adversary::AdversaryMode::Overcharge) {
            // Charge one unit above the request's bound, persisted as its
            // settled charge, so the overcharged successor is what recovery
            // serves.
            settled.charge = request.public_inputs.solvency_bound.saturating_add(1);
            self.store
                .overcharge_for_adversary(&nullifier, settled.charge)?;
        }
        #[cfg(feature = "adversary")]
        let adversarial = crate::adversary::successor(
            self.adversary,
            &*self.signer,
            &self.config.successor_deployment(),
            request,
            &settled,
            current_timestamp(),
        );
        #[cfg(not(feature = "adversary"))]
        let adversarial: Option<Result<crate::successor::SignedSuccessor, ServerError>> = None;
        let signed = match adversarial {
            Some(signed) => signed?,
            None => build_signed_successor(
                &*self.signer,
                &self.config.successor_deployment(),
                request,
                &settled,
                current_timestamp(),
            )?,
        };
        let mut transcript = signed.transcript;
        transcript.created_at = record.created_at;
        transcript.exit_deferred_since = record.exit_deferred_since;
        self.store.finalize_signed(&transcript)?;
        Ok(signed.response)
    }

    /// Sign the successor of `request` now if it is settled and unsigned, as
    /// `sign_successor` would (best effort: the signing pass retries).
    async fn sign_if_settled(&self, request: &ApiRequestV2) {
        match self
            .store
            .try_lookup_by_nullifier(&request.public_inputs.request_nullifier)
        {
            Ok(Some(record)) if record.settled_unsigned() => {
                if let Err(error) = self.sign_successor(request).await {
                    tracing::warn!(
                        client_request_id = %request.client_request_id,
                        error = %error,
                        "successor signing will be retried"
                    );
                }
            }
            Ok(_) => {}
            Err(error) => tracing::warn!(error = %error, "settled-request lookup failed"),
        }
    }

    /// The signing pass of every sweep: sign the successors of settled
    /// requests whose nullifiers are unspent, and re-check deferred ones.
    /// Each request is handled under its lease's lock; one whose lock is held
    /// (by its owner's retirement) is left to that holder.
    ///
    /// Requests never found consumed and deferred ones are paged separately,
    /// up to `SIGN_BATCH` of each per pass, each page starting where the
    /// previous one ended and wrapping around after a short page. Deferred
    /// requests (which may stay deferred for `challengePeriod + 3600` s), or
    /// requests that keep failing to sign, therefore never starve a newly
    /// settled request, and every deferred request is re-checked within
    /// `⌈deferred / SIGN_BATCH⌉ + 1` passes. A request the first page just
    /// deferred is not read again by the second.
    pub async fn sign_settled_successors(&self) {
        let mut handled = std::collections::HashSet::new();
        for (class, deferred) in [(0, false), (1, true)] {
            let after = match self.signing_cursors.lock() {
                Ok(cursors) => cursors[class].clone(),
                Err(_) => None,
            };
            let records =
                match self
                    .store
                    .settled_unsigned_requests(deferred, after.as_ref(), SIGN_BATCH)
                {
                    Ok(records) => records,
                    Err(error) => {
                        tracing::error!(error = %error, "settled-request scan failed");
                        continue;
                    }
                };
            let next = if records.len() < SIGN_BATCH {
                None
            } else {
                records.last().map(SettledScanKey::of)
            };
            if let Ok(mut cursors) = self.signing_cursors.lock() {
                cursors[class] = next;
            }
            let records = records
                .into_iter()
                .filter(|record| handled.insert(record.nullifier))
                .collect();
            self.sign_settled_page(records).await;
        }
    }

    async fn sign_settled_page(&self, records: Vec<TranscriptRecord>) {
        for record in records {
            let Some(id) = record.client_request_id.as_deref() else {
                tracing::error!(nullifier = %record.nullifier, "a settled request has no client request id");
                continue;
            };
            let Some(_guard) = self.lease_locks.try_lock(id) else {
                continue;
            };
            let lease = match self.store.try_lookup_openrouter_lease(id) {
                Ok(Some(lease)) if lease.request_nullifier == record.nullifier => lease,
                Ok(_) => {
                    tracing::error!(client_request_id = %id, "a settled request has no matching lease row; its successor cannot be signed until it is repaired");
                    continue;
                }
                Err(error) => {
                    tracing::error!(client_request_id = %id, error = %error, "a settled request's lease row cannot be read");
                    continue;
                }
            };
            if let Err(error) = self.sign_successor(&lease.api_request).await {
                tracing::warn!(client_request_id = %id, error = %error, "successor signing will be retried");
            }
        }
    }

    pub fn openrouter_leases_enabled(&self) -> bool {
        self.config.openrouter_leases.is_some()
    }

    /// The deadline a pending lease will be finalized by, without assigning
    /// one (reads must not write).
    fn pending_settlement_deadline(&self, lease: &OpenRouterLeaseRecord, now: u64) -> Option<u64> {
        if lease_terminal(&lease.status) {
            return None;
        }
        lease.settlement_deadline_at.or_else(|| {
            self.lease_config()
                .ok()
                .map(|config| self.first_sight_deadline(config, lease.expires_at, now))
        })
    }

    /// A lease's non-secret status; None for an unknown lease. A store that
    /// cannot be read is an error, never an unknown lease.
    pub fn openrouter_lease_status(
        &self,
        client_request_id: &str,
    ) -> Result<Option<OpenRouterLeaseStatusResponse>, ServerError> {
        let now = current_timestamp();
        Ok(self
            .store
            .try_lookup_openrouter_lease(client_request_id)?
            .map(|lease| OpenRouterLeaseStatusResponse {
                settlement_deadline: self.pending_settlement_deadline(&lease, now),
                // The basis of a settled charge only.
                charge_basis: lease.charge_basis.filter(|_| {
                    matches!(
                        lease.status.as_str(),
                        "finalized" | "exit_deferred" | "exited_unsigned"
                    )
                }),
                status: lease.status,
                client_request_id: lease.client_request_id,
                issued_at: lease.issued_at,
                expires_at: lease.expires_at,
                settle_after: lease.settle_after,
                spending_limit_usd: lease.spending_limit_usd,
                usage_usd: lease.usage_usd,
                charge_applied: lease.charge_applied,
                last_error: lease.last_error,
            }))
    }

    /// Sign a mutual-close clearance for a nullifier and reserve it for good
    /// (§5.3). The caller proves note ownership with a kind-2 withdrawal proof
    /// for exactly that nullifier, valid for at most another hour. A
    /// nullifier with any request row (reserved, settled, signed or ended) is
    /// `NullifierUsed`. The ownership proof is never stored or logged.
    pub async fn process_clearance(
        &self,
        request: &ClearanceRequestV2C,
    ) -> Result<ClearanceResponseV2, ServerError> {
        let nullifier = request.withdrawal_nullifier;
        let already_reserved = match self.store.try_lookup_by_nullifier(&nullifier)? {
            Some(record) if record.status == NullifierStatus::ClearanceReserved => true,
            Some(_) => return Err(ServerError::NullifierUsed),
            None => false,
        };
        self.verify_clearance_ownership(&nullifier, &request.ownership_proof)
            .await?;
        let message = core::clearance_message(
            self.config.protocol_version,
            self.config.chain_id,
            &self.config.contract_address,
            &nullifier,
        );
        let signature = self.signer.sign_clearance(&message);
        if !already_reserved {
            // A concurrent lease reservation wins the primary key: NullifierUsed.
            self.store
                .reserve_clearance(&nullifier, "ownership_proof")?;
        }
        Ok(ClearanceResponseV2 {
            status: "ok".to_string(),
            withdrawal_nullifier: nullifier,
            signature,
        })
    }

    /// Verify a kind-2 ownership proof for exactly this nullifier and
    /// deployment, fresh (`now <= valid_until <= now + 3600`), with its zero
    /// fields zero (`next_nullifier`, `conceded`, `destination`), at a root
    /// the server or the vault knows. Cheap checks come first; the
    /// verification permit is released before any I/O; the vault root read
    /// is single-flight and cached; rejected (root, nullifier) pairs are
    /// answered from a negative cache.
    async fn verify_clearance_ownership(
        &self,
        nullifier: &Felt252,
        ownership: &ClearanceOwnershipProofV2C,
    ) -> Result<(), ServerError> {
        let inputs = &ownership.public_inputs;
        if inputs.withdrawal_nullifier != *nullifier {
            return Err(ServerError::InvalidRequest(
                "ownership proof is for a different nullifier".into(),
            ));
        }
        if inputs.withdrawal_kind() != Some(WithdrawalKind::Ownership) {
            return Err(ServerError::InvalidRequest(
                "ownership proof must be a kind-2 (ownership) withdrawal proof".into(),
            ));
        }
        if inputs.next_nullifier != Felt252::ZERO
            || inputs.conceded != 0
            || inputs.destination != [0u8; 20]
        {
            return Err(ServerError::InvalidRequest(
                "an ownership proof has a zero next_nullifier, conceded amount and destination"
                    .into(),
            ));
        }
        let now = current_timestamp();
        if inputs.valid_until < now {
            return Err(ServerError::InvalidRequest(
                "ownership proof expired (valid_until has passed)".into(),
            ));
        }
        if inputs.valid_until > now.saturating_add(OWNERSHIP_PROOF_MAX_VALIDITY_SECONDS) {
            return Err(ServerError::InvalidRequest(format!(
                "ownership proof valid_until is more than {OWNERSHIP_PROOF_MAX_VALIDITY_SECONDS} s ahead"
            )));
        }
        if inputs.protocol_version != self.config.protocol_version
            || inputs.chain_id != self.config.chain_id
            || inputs.contract_address != self.config.contract_address
        {
            return Err(ServerError::ProtocolMismatch(
                "ownership proof is for a different deployment".into(),
            ));
        }
        let state_key = self.signer.state_public_key();
        let clearance_key = self.signer.clearance_public_key();
        if inputs.state_signing_key_x != state_key.x
            || inputs.state_signing_key_y != state_key.y
            || inputs.clearance_signing_key_x != clearance_key.x
            || inputs.clearance_signing_key_y != clearance_key.y
        {
            return Err(ServerError::InvalidRequest(
                "ownership proof signing keys do not match this deployment".into(),
            ));
        }
        let root = inputs.active_root;
        let window = self.config.clearance_root_window_seconds;
        let known_root = root == self.current_root()
            || self
                .recent_roots
                .lock()
                .map(|roots| roots.contains(&root, now, window))
                .unwrap_or(false);
        let mut vault_root_read = None;
        if !known_root {
            let rejected = self
                .rejected_clearances
                .lock()
                .ok()
                .and_then(|rejected| rejected.lookup(&root, nullifier, now));
            // A replay is answered without a pairing check while the vault
            // root it was rejected against is still current (a cached read).
            if let Some(rejected_against) = rejected {
                let vault_root = self.cached_vault_root().await?;
                if vault_root == rejected_against {
                    return Err(ServerError::StaleRoot {
                        latest_root: vault_root.to_hex(),
                    });
                }
                vault_root_read = Some(vault_root);
            }
        }
        {
            let _permit =
                tokio::time::timeout(CLEARANCE_PERMIT_TIMEOUT, self.clearance_permits.acquire())
                    .await
                    .map_err(|_| ServerError::CapacityExhausted)?
                    .map_err(|_| ServerError::CapacityExhausted)?;
            // Generic errors: verifier details could echo request bytes.
            if !self
                .withdrawal_verifier
                .verify(inputs, &ownership.proof)
                .map_err(|_| ServerError::InvalidProof("ownership proof is malformed".into()))?
            {
                return Err(ServerError::InvalidProof(
                    "ownership proof failed verification".into(),
                ));
            }
        }
        if known_root {
            return Ok(());
        }
        // Only a verified proof reaches the vault, and the reads are cached.
        let vault_root = match vault_root_read {
            Some(vault_root) => vault_root,
            None => self.cached_vault_root().await?,
        };
        if vault_root == root {
            self.observe_root(root, now);
            return Ok(());
        }
        // Amendment A1: any root the vault ever held, such as the one a
        // client saved with its deposit-time path, proves the note exists
        // (the tree is append-only for every note that is not Closed, and a
        // close of a Closed note reverts).
        if self.vault_knows_root(&root, &vault_root).await? {
            return Ok(());
        }
        if let Ok(mut rejected) = self.rejected_clearances.lock() {
            rejected.insert(root, *nullifier, vault_root, now.saturating_add(window));
        }
        Err(ServerError::StaleRoot {
            latest_root: vault_root.to_hex(),
        })
    }

    /// Whether the vault ever set `root` (`knownRoots`), its current root
    /// being `vault_root`. Concurrent callers wait for the one in-flight read;
    /// a failed read is not cached.
    async fn vault_knows_root(
        &self,
        root: &Felt252,
        vault_root: &Felt252,
    ) -> Result<bool, ServerError> {
        let mut cache = self.vault_known_roots.lock().await;
        if let Some(known) = cache.lookup(root, vault_root) {
            return Ok(known);
        }
        let known = self.native_oracle.vault_known_root(root).await?;
        cache.record(*root, *vault_root, known);
        Ok(known)
    }

    /// The vault's currentRoot(), read at most once per TTL; concurrent
    /// callers wait for the one in-flight read.
    async fn cached_vault_root(&self) -> Result<Felt252, ServerError> {
        let mut cached = self.vault_root_cache.lock().await;
        if let Some((read, read_at)) = cached.as_ref() {
            if read_at.elapsed() < self.timing.vault_root_ttl {
                // A failed read is cached too: an RPC outage costs at most one
                // read per TTL instead of a queue of slow reads.
                return read.clone().map_err(ServerError::Internal);
            }
        }
        let read = self
            .native_oracle
            .vault_current_root()
            .await
            .map_err(|error| match error {
                ServerError::Internal(message) => message,
                other => other.to_string(),
            });
        *cached = Some((read.clone(), Instant::now()));
        read.map_err(ServerError::Internal)
    }

    /// Recovery by client request ID. `not_found` (nullifier_status
    /// `unknown`) means the store was read and holds no such request; a store
    /// that cannot be read is a retriable database error. Once the request's
    /// nullifier is published on chain, only its status is returned.
    pub async fn recover_by_client_id(
        &self,
        client_request_id: &str,
    ) -> Result<RecoveryResponseV2, ServerError> {
        match self.store.try_lookup_by_client_id(client_request_id)? {
            Some(record) => self.recovery_from_record(&record).await,
            None => Ok(not_found_recovery()),
        }
    }

    /// Recovery by nullifier, with the same contract as by client request ID.
    pub async fn recover_by_nullifier(
        &self,
        nullifier: &Felt252,
    ) -> Result<RecoveryResponseV2, ServerError> {
        match self.store.try_lookup_by_nullifier(nullifier)? {
            Some(record) => self.recovery_from_record(&record).await,
            None => Ok(not_found_recovery()),
        }
    }

    async fn recovery_from_record(
        &self,
        record: &TranscriptRecord,
    ) -> Result<RecoveryResponseV2, ServerError> {
        let mut recovery = recovery_from_record(record);
        if record.status == NullifierStatus::Reserved
            && record.reservation_kind == "openrouter_lease"
            && record.settled_charge.is_none()
        {
            // Informational: a lease row that cannot be read omits the
            // deadline, but never hides the reservation itself.
            let lease = record.client_request_id.as_deref().and_then(|id| {
                self.store
                    .try_lookup_openrouter_lease(id)
                    .map_err(|error| {
                        tracing::warn!(error = %error, "settlement deadline unavailable for recovery");
                    })
                    .ok()
                    .flatten()
            });
            recovery.settlement_deadline = lease
                .filter(|lease| lease.request_nullifier == record.nullifier)
                .and_then(|lease| self.pending_settlement_deadline(&lease, current_timestamp()));
        }
        // §5.2: a published nullifier's request data is no longer served.
        // Recovery falls back to the vault's logs when the indexer's table
        // cannot be read.
        let reserved_at = record
            .request_inputs_json
            .as_deref()
            .and_then(|json| serde_json::from_str::<RequestPublicInputsV2>(json).ok())
            .map_or(record.created_at, |inputs| {
                inputs.request_time.min(record.created_at)
            });
        if (recovery.request_response.is_some() || recovery.settlement_deadline.is_some())
            && self
                .nullifier_published(&record.nullifier, Some(reserved_at))
                .await?
        {
            recovery.request_response = None;
            recovery.settlement_deadline = None;
        }
        Ok(recovery)
    }

    /// Whether `nullifier` is published: consumed (`usedNullifiers`) or
    /// challenged (`challengedNullifiers`) on chain at latest, or named as a
    /// withdrawal or next nullifier in a vault event (the indexer's
    /// published-nullifier table, `GET /v1/nullifiers/{N}/published`).
    /// With `reserved_at`, the time its request was reserved, the vault's
    /// logs stand in for that table when it cannot be read or no indexer is
    /// configured (see `read_publication`). A failed read is a retriable
    /// error: the answer fails closed.
    pub async fn nullifier_published(
        &self,
        nullifier: &Felt252,
        reserved_at: Option<u64>,
    ) -> Result<bool, ServerError> {
        let now = current_timestamp();
        if let Some(cached) = self
            .publication
            .lock()
            .ok()
            .and_then(|cache| cache.lookup(nullifier, now))
        {
            return Ok(cached);
        }
        let published = self.read_publication(nullifier, reserved_at).await?;
        if let Ok(mut cache) = self.publication.lock() {
            cache.record(*nullifier, published, now);
        }
        Ok(published)
    }

    /// The flags, then the indexer's table. Without that table, and given
    /// `reserved_at`, the vault's `EscapeConcessionRecorded` logs from
    /// `reserved_at - PUBLICATION_SCAN_SLACK_SECONDS` on decide: every other
    /// event's nullifier stays consumed or challenged, so only an escape's
    /// `nextNullifier` needs a log, and only once that escape was defeated
    /// (which clears `usedNullifiers` for it). A request is reserved only
    /// while its nullifier is unconsumed, so an escape naming it before the
    /// reservation was defeated before it, with a request proof at it the
    /// server had not reserved: one only the note's owner can make (L1).
    /// The scan therefore misses only a nullifier its owner published.
    async fn read_publication(
        &self,
        nullifier: &Felt252,
        reserved_at: Option<u64>,
    ) -> Result<bool, ServerError> {
        if self.nullifier_flagged(nullifier).await? {
            return Ok(true);
        }
        let indexed = match self.config.indexer_url.as_deref() {
            Some(indexer_url) => self.indexer_published(indexer_url, nullifier).await,
            None => Err(ServerError::ChainReadUnavailable(
                "no indexer is configured".into(),
            )),
        };
        match (indexed, reserved_at) {
            (Ok(published), _) => Ok(published),
            (Err(error), None) => Err(error),
            (Err(error), Some(reserved_at)) => {
                if self.config.indexer_url.is_some() {
                    tracing::warn!(error = %error, "published-nullifier table unavailable; scanning the vault's logs");
                }
                self.escape_named_next_nullifier(
                    nullifier,
                    reserved_at.saturating_sub(PUBLICATION_SCAN_SLACK_SECONDS),
                )
                .await
            }
        }
    }

    /// `usedNullifiers(N) || challengedNullifiers(N)` at latest.
    async fn nullifier_flagged(&self, nullifier: &Felt252) -> Result<bool, ServerError> {
        let unavailable = |error: ServerError| ServerError::ChainReadUnavailable(error.to_string());
        #[cfg(test)]
        if let Some(chain) = &self.test_chain {
            let mut chain = chain.lock().unwrap();
            chain.reads += 1;
            if chain.unavailable {
                return Err(ServerError::ChainReadUnavailable(
                    "test chain unavailable".into(),
                ));
            }
            return Ok(chain.used.contains(nullifier) || chain.challenged.contains(nullifier));
        }
        Ok(self
            .native_oracle
            .nullifier_flag(crate::native_billing::USED_NULLIFIERS_SELECTOR, nullifier)
            .await
            .map_err(unavailable)?
            || self
                .native_oracle
                .nullifier_flag(
                    crate::native_billing::CHALLENGED_NULLIFIERS_SELECTOR,
                    nullifier,
                )
                .await
                .map_err(unavailable)?)
    }

    /// The indexer's published-nullifier table.
    async fn indexer_published(
        &self,
        indexer_url: &str,
        nullifier: &Felt252,
    ) -> Result<bool, ServerError> {
        #[cfg(test)]
        if let Some(chain) = &self.test_chain {
            let chain = chain.lock().unwrap();
            if chain.indexer_unavailable {
                return Err(ServerError::ChainReadUnavailable(
                    "test indexer unavailable".into(),
                ));
            }
            return Ok(chain.events.contains(nullifier));
        }
        fetch_indexer_published(indexer_url, nullifier)
            .await
            .map_err(|error| ServerError::ChainReadUnavailable(error.to_string()))
    }

    /// Whether a vault `EscapeConcessionRecorded` log at or after `since`
    /// names `nullifier`.
    async fn escape_named_next_nullifier(
        &self,
        nullifier: &Felt252,
        since: u64,
    ) -> Result<bool, ServerError> {
        #[cfg(test)]
        if let Some(chain) = &self.test_chain {
            let mut chain = chain.lock().unwrap();
            if chain.unavailable {
                return Err(ServerError::ChainReadUnavailable(
                    "test chain unavailable".into(),
                ));
            }
            chain.scans.push(since);
            return Ok(chain.events.contains(nullifier)
                && chain
                    .event_times
                    .get(nullifier)
                    .is_none_or(|time| *time >= since));
        }
        self.native_oracle
            .escape_named_next_nullifier(nullifier, since, PUBLICATION_SCAN_MAX_BLOCKS)
            .await
            .map_err(|error| ServerError::ChainReadUnavailable(error.to_string()))
    }

    /// `GET /v2/nullifiers/{N}/evidence` (§5.2, the clients' stale-device
    /// check): the public inputs and proof of the earliest request the server
    /// reserved at `nullifier`, None when it holds none. Refused
    /// (`Published`) once `nullifier` is published on chain: evidence is never
    /// served for a public nullifier.
    pub async fn request_evidence(
        &self,
        nullifier: &Felt252,
    ) -> Result<Option<RequestEvidenceResponse>, ServerError> {
        let Some(evidence) = self.store.earliest_reserve_evidence(nullifier)? else {
            return Ok(None);
        };
        // Strict: a configured indexer that cannot answer fails the read.
        // Without one, the vault's logs from the reservation decide.
        let reserved_at = self
            .config
            .indexer_url
            .is_none()
            .then(|| evidence.created_at.min(evidence.public_inputs.request_time));
        if self.nullifier_published(nullifier, reserved_at).await? {
            return Err(ServerError::Published);
        }
        Ok(Some(RequestEvidenceResponse {
            public_inputs: evidence.public_inputs,
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: base64::engine::general_purpose::STANDARD.encode(&evidence.proof),
            },
        }))
    }

    /// Settlement health for the operator dashboard; never public.
    pub fn settlement_counts(&self) -> Result<SettlementCounts, ServerError> {
        self.store.settlement_counts(current_timestamp())
    }

    /// Pending leases and settlement reviews for the operator dashboard.
    pub fn settlement_overview(&self, limit: usize) -> Result<SettlementOverview, ServerError> {
        let now = current_timestamp();
        let pending = self
            .store
            .pending_openrouter_leases(limit)?
            .into_iter()
            .map(|lease| {
                let deadline = self.pending_settlement_deadline(&lease, now);
                PendingLeaseView {
                    client_request_id: lease.client_request_id,
                    request_nullifier: lease.request_nullifier,
                    key_source: lease.key_source,
                    status: lease.status,
                    delivered: lease.delivered,
                    charge_basis: lease.charge_basis,
                    expires_at: lease.expires_at,
                    settle_after: lease.settle_after,
                    settlement_deadline: deadline,
                    seconds_until_deadline: deadline.map(|deadline| deadline.saturating_sub(now)),
                    attempts: lease.settlement_attempts,
                    first_error_at: lease.first_error_at,
                    last_error: lease.last_error,
                }
            })
            .collect();
        let reviews = self
            .store
            .settlement_reviews(limit)?
            .into_iter()
            .map(|stored| SettlementReviewView {
                client_request_id: stored.review.client_request_id,
                request_nullifier: stored.review.request_nullifier,
                key_source: stored.review.key_source,
                reason: stored.review.reason,
                charge_basis: stored.review.charge_basis,
                detail: stored.review.detail,
                reported_usage_micro_usd: stored
                    .review
                    .reported_usage_micro_usd
                    .map(|value| value.to_string()),
                charge_applied: stored.review.charge_applied.map(|value| value.to_string()),
                solvency_bound: stored.review.solvency_bound.to_string(),
                created_at: stored.created_at,
                acknowledged_at: stored.acknowledged_at,
            })
            .collect();
        Ok(SettlementOverview {
            generated_at: now,
            settlement_deadline_seconds: self
                .config
                .openrouter_leases
                .as_ref()
                .map(|lease| lease.settlement_deadline_seconds),
            counts: self.store.settlement_counts(now)?,
            pending,
            reviews,
        })
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

/// The body of `GET /v2/nullifiers/{N}/evidence`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RequestEvidenceResponse {
    pub public_inputs: RequestPublicInputsV2,
    pub proof: Groth16ProofWire,
}

/// The tree root the indexer serves.
pub(crate) async fn fetch_indexer_root(indexer_url: &str) -> anyhow::Result<Felt252> {
    #[derive(serde::Deserialize)]
    struct RootResponse {
        root: Felt252,
    }

    let base = indexer_url.trim_end_matches('/');
    let url = format!("{base}/v1/tree/root");
    let response = reqwest::get(&url).await?;
    let response = response.error_for_status()?;
    Ok(response.json::<RootResponse>().await?.root)
}

/// Whether the indexer's published-nullifier table holds `nullifier`: the
/// withdrawal or next nullifier of any vault event
/// (`GET /v1/nullifiers/{N}/published` -> `{"published": bool}`).
pub(crate) async fn fetch_indexer_published(
    indexer_url: &str,
    nullifier: &Felt252,
) -> anyhow::Result<bool> {
    #[derive(serde::Deserialize)]
    struct PublishedResponse {
        published: bool,
    }

    let base = indexer_url.trim_end_matches('/');
    let url = format!("{base}/v1/nullifiers/{}/published", nullifier.to_hex());
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?
        .get(&url)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json::<PublishedResponse>().await?.published)
}

/// The `nullifier_status` a recovery response reports.
pub(crate) fn nullifier_status_label(record: &TranscriptRecord) -> &'static str {
    match record.status {
        NullifierStatus::Reserved if record.exit_deferred_since.is_some() => "exit_deferred",
        NullifierStatus::Reserved => "reserved",
        NullifierStatus::Finalized => "finalized",
        NullifierStatus::ClearanceReserved => "clearance_reserved",
        NullifierStatus::ExitedUnsigned => "exited_unsigned",
    }
}

fn recovery_from_record(record: &TranscriptRecord) -> RecoveryResponseV2 {
    let status = nullifier_status_label(record);
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
        settlement_deadline: None,
    }
}

fn not_found_recovery() -> RecoveryResponseV2 {
    RecoveryResponseV2 {
        status: "not_found".to_string(),
        nullifier_status: "unknown".to_string(),
        request_response: None,
        settlement_deadline: None,
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

/// A chain the tests control: which nullifiers are consumed, challenged or
/// named in vault events, and whether it can be read at all.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct TestChain {
    pub(crate) used: std::collections::HashSet<Felt252>,
    pub(crate) challenged: std::collections::HashSet<Felt252>,
    /// Nullifiers named in vault events: the indexer's table, and the logs
    /// a scan reads (at `event_times`, or any time when absent).
    pub(crate) events: std::collections::HashSet<Felt252>,
    pub(crate) event_times: std::collections::HashMap<Felt252, u64>,
    /// The RPC cannot be read (flags and logs).
    pub(crate) unavailable: bool,
    /// The indexer's table cannot be read.
    pub(crate) indexer_unavailable: bool,
    pub(crate) reads: usize,
    /// The `since` of every log scan.
    pub(crate) scans: Vec<u64>,
}

#[cfg(test)]
impl RequestProcessor {
    /// Mark `nullifier` consumed (or not) on the test chain.
    pub(crate) fn set_test_spent(&self, nullifier: Felt252, spent: bool) {
        let mut chain = self.test_chain.as_ref().unwrap().lock().unwrap();
        if spent {
            chain.used.insert(nullifier);
        } else {
            chain.used.remove(&nullifier);
        }
        // A changed chain invalidates cached publication answers.
        if let Ok(mut cache) = self.publication.lock() {
            *cache = PublicationCache::default();
        }
    }

    /// The test chain; the caller may change it, so cached publication
    /// answers are dropped.
    pub(crate) fn test_chain(&self) -> std::sync::MutexGuard<'_, TestChain> {
        if let Ok(mut cache) = self.publication.lock() {
            *cache = PublicationCache::default();
        }
        self.test_chain.as_ref().unwrap().lock().unwrap()
    }

    /// Recovery by client request ID from a synchronous test: with the test
    /// chain it awaits no I/O.
    pub(crate) fn recover_now(
        &self,
        client_request_id: &str,
    ) -> Result<RecoveryResponseV2, ServerError> {
        futures_util::FutureExt::now_or_never(self.recover_by_client_id(client_request_id))
            .expect("recovery awaited I/O")
    }

    /// Run one settlement sweep from a synchronous test.
    pub(crate) fn sign_settled_now(&self) {
        futures_util::FutureExt::now_or_never(self.sign_settled_successors())
            .expect("signing awaited I/O")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};

    use crate::test_support::PreparedTestRequest;

    use crate::config::OpenRouterLeaseConfig;

    fn setup_directory() -> String {
        crate::test_support::setup_directory()
    }

    /// The seeds of `oa_lease_processor`'s signer.
    fn oa_seeds() -> (Felt252, Felt252) {
        (Felt252::from_u64(11), Felt252::from_u64(12))
    }

    fn random_field_for_test() -> Felt252 {
        zkapi_proof::compact::random_field()
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
                    // Lifecycle fixtures use 1970 timestamps; tests of the
                    // deadline set realistic times and their own deadline.
                    settlement_deadline_seconds: crate::test_support::TEST_DEADLINE_DISABLED,
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
                proof: crate::test_support::fake_proof(3),
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
        request.proof.proof = crate::test_support::fake_proof(9);
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
        /// Fail every vault read (including the pre-provider spend check).
        fail_rpc: bool,
        creates: usize,
        provider_calls: usize,
        nullifier_reads: usize,
        /// A key an ambiguous create left behind under this request name.
        orphan_name: Option<String>,
        /// Key cleanup calls: "disable:<hash>" / "delete:<hash>".
        cleanup: Vec<String>,
    }

    type IssuanceMockState = Arc<std::sync::Mutex<IssuanceMock>>;

    async fn issuance_rpc(
        axum::extract::State(state): axum::extract::State<IssuanceMockState>,
        axum::Json(body): axum::Json<serde_json::Value>,
    ) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
        let mut state = state.lock().unwrap();
        if state.fail_rpc || (state.fail_rpc_after_create && state.creates > 0) {
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
            let data = body["params"][0]["data"].as_str().unwrap_or_default();
            assert!(data.starts_with(&format!("0x{}", hex::encode(&selector[..4]))));
            assert_eq!(data.len(), 2 + 8 + 64);
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
        async fn list(
            State(state): State<IssuanceMockState>,
            axum::extract::Query(query): axum::extract::Query<
                std::collections::HashMap<String, String>,
            >,
        ) -> Json<Value> {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            let first_page = query.get("offset").map(String::as_str) == Some("0");
            match state.orphan_name.clone() {
                Some(name) if first_page => Json(json!({"data":[
                    {"hash":"orphan-hash", "name":name},
                    {"hash":"unrelated-hash", "name":"zkapi-unrelated"}
                ]})),
                _ => Json(json!({"data":[]})),
            }
        }
        async fn cleanup(
            State(state): State<IssuanceMockState>,
            method: axum::http::Method,
            axum::extract::Path(hash): axum::extract::Path<String>,
        ) -> (StatusCode, Json<Value>) {
            let mut state = state.lock().unwrap();
            state.provider_calls += 1;
            let verb = if method == axum::http::Method::PATCH {
                "disable"
            } else {
                "delete"
            };
            state.cleanup.push(format!("{verb}:{hash}"));
            if verb == "disable" {
                (StatusCode::OK, Json(json!({"data":{"disabled":true}})))
            } else {
                (StatusCode::OK, Json(json!({"deleted":true})))
            }
        }
        let app = Router::new()
            .route("/rpc", post(issuance_rpc))
            .route("/v1/keys", get(list).post(create))
            .route(
                "/v1/keys/{hash}",
                axum::routing::patch(cleanup).delete(cleanup),
            )
            .route("/api/zkapi/request_key", post(create))
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
        request.proof.proof = crate::test_support::fake_proof(9);
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

    /// A lease whose upstream issuance outcome is unknown was never returned
    /// to the client: activation precedes delivery. It settles at zero with no
    /// provider reads, instead of waiting forever for issuer evidence.
    #[tokio::test]
    async fn expired_unconfirmed_provisioning_finalizes_at_zero_without_provider_calls() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        let before = state.lock().unwrap().provider_calls;
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_applied, Some(0));
        assert_eq!(lease.charge_basis.as_deref(), Some("unissued"));
        assert!(lease.key_hash.is_none());
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["type"], "oa_org_unissued_lease_cancellation");
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(payload["issued"], false);
        assert_eq!(
            payload["billing_quote"],
            serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
        );
        {
            let state = state.lock().unwrap();
            assert_eq!(
                state.provider_calls, before,
                "no reconciliation or usage read"
            );
            assert_eq!(state.creates, 0);
        }
        // An exact retry recovers the signed zero-charge response, never a key.
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
                .unwrap()
                .status,
            "finalized"
        );
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn ambiguous_unissued_lease_retires_at_zero_without_reissuing() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        processor
            .store
            .begin_oa_issuance(&request.client_request_id)
            .unwrap();
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("unissued"));
        assert_eq!(status.settlement_deadline, None);
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .next_state_sig,
            record.next_state_sig
        );
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
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::MayHaveIssued
        );
        assert_eq!(lease.status, "provisioning");
        assert!(lease.last_error.is_some());
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
        // The key was never returned, whatever the issuer did: zero, and the
        // record keeps the earlier uncertainty rather than a confirmed rejection.
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(state.lock().unwrap().creates, 2);
        server.abort();
    }

    #[tokio::test]
    async fn confirmed_rejection_finalizes_at_zero_without_chain_reads_and_recovers_after_crash() {
        // Zero-charge successors need no chain read: an unavailable RPC after
        // the rejection does not block finalization.
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            policy_reject: true,
            fail_rpc_after_create: true,
            ..Default::default()
        }));
        let (processor, request, server) = issuance_processor(true, state.clone()).await;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::OaKeyPolicyRejected)
        ));
        let reads = state.lock().unwrap().nullifier_reads;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            lease.oa_provisioning_outcome,
            OaProvisioningOutcome::ConfirmedUnissued
        );
        assert_eq!(lease.status, "finalized");
        assert_eq!(lease.charge_basis.as_deref(), Some("unissued"));
        assert_eq!(state.lock().unwrap().creates, 1);
        server.abort();

        // A crash between the confirmed rejection and its finalization is
        // recovered by the background settler.
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
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .unwrap()
                .status,
            "finalized"
        );
        let record = processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap();
        assert_eq!(record.charge_applied, Some(0));
        let payload: serde_json::Value =
            serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap();
        assert_eq!(payload["reason"], "issuer_policy_rejected");
        let state = state.lock().unwrap();
        assert_eq!(state.creates, 0);
        assert_eq!(state.nullifier_reads, 0);
        assert!(reads >= 1);
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
        // A transcript signed before the lease row was finalized (a crash
        // window of an earlier release).
        processor
            .settle_request_for_test(&request, SettlementResult {
                status_code: 200,
                payload: processor.settlement_payload(&request, serde_json::json!({
                    "type":"oa_org_unissued_lease_cancellation", "issued":false, "usage_credits":0
                })).unwrap(),
                charge_applied: 0, usage: None, billing_label: "test".into(),
            })
            .unwrap();
        let signed = processor.sign_settled(&request).unwrap();
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
            // The failed attempt leaves a settleable provisioning row (it is
            // never delivered and settles at zero), not a bare reservation.
            let lease = processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "provisioning");
            assert!(lease.last_error.is_some());
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
            // Its key was never issued: nothing is owed for it if its owner
            // escapes (§5.4 Ω).
            assert_eq!(
                crate::watcher::ChallengeWatcher::new(processor.store.clone())
                    .owed(&request.public_inputs.request_nullifier)
                    .unwrap()
                    .basis,
                crate::watcher::OwedBasis::Nothing(crate::watcher::NothingOwed::NeverDelivered)
            );
            server.abort();
        }
    }

    #[tokio::test]
    async fn collateral_change_during_issuance_never_exposes_key_and_awaits_settlement_evidence() {
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
                // The key was issued but never returned: nothing is owed for it
                // if its owner escapes (§5.4 Ω); the retained active row lets
                // bounded settlement settle it at zero.
                let watcher = crate::watcher::ChallengeWatcher::new(processor.store.clone());
                let nullifier = request.public_inputs.request_nullifier;
                let owed = watcher.owed(&nullifier).unwrap();
                let progress = owed.settlement.clone().unwrap();
                assert_eq!(progress.lease_status.as_deref(), Some("active"));
                assert!(progress.key_issued);
                // A key recorded as never returned owes nothing; one without
                // delivery provenance counts as possibly delivered (§5.4 Ω).
                if lease.delivered == Some(false) {
                    assert_eq!(
                        owed.basis,
                        crate::watcher::OwedBasis::Nothing(
                            crate::watcher::NothingOwed::NeverDelivered
                        )
                    );
                    assert!(!progress.possibly_delivered);
                } else {
                    assert_eq!(owed.basis, crate::watcher::OwedBasis::Unsettled);
                }
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

    /// Final round (server-fixup2#2): an activated lease records the
    /// identity of the key source that issued it (the OA org URL or the
    /// OpenRouter API base), which the startup key-source check compares.
    #[tokio::test]
    async fn issued_lease_records_its_issuers_identity() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
            let (processor, request, server) = issuance_processor(oa, state).await;
            processor.issue_openrouter_lease(&request).await.unwrap();
            let identity = processor
                .config
                .openrouter_leases
                .as_ref()
                .unwrap()
                .source
                .identity();
            assert!(identity.starts_with("http://127.0.0.1:"), "{identity}");
            assert_eq!(
                processor.store.query_i64_for_test(
                    "SELECT COUNT(*) FROM openrouter_leases
                     WHERE client_request_id = ?1 AND key_source_identity = ?2",
                    rusqlite::params![request.client_request_id, identity],
                ),
                1
            );
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
        /// Every usage read fails (a provider outage).
        usage_unavailable: bool,
        /// Every deletion fails.
        delete_unavailable: bool,
        /// The provider keeps reporting the key as enabled.
        report_enabled: bool,
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
            if state.fail_usage || state.usage_unavailable {
                state.fail_usage = false;
                return Err(StatusCode::SERVICE_UNAVAILABLE);
            }
            let disabled = state.disabled && !state.report_enabled;
            Ok(Json(
                serde_json::json!({"data": {"disabled": disabled, "usage": state.usage, "byok_usage": 0.0}}),
            ))
        }
        async fn delete(State(state): State<MockState>) -> StatusCode {
            let mut state = state.lock().unwrap();
            state.events.push("delete");
            assert!(state.disabled);
            if state.delete_unavailable {
                return StatusCode::SERVICE_UNAVAILABLE;
            }
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
            .route("/v1/keys/{hash}", get(usage).patch(disable).delete(delete))
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
    fn native_quote_is_bound_by_real_proof_and_settles_in_gwei() {
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
        let mut note = crate::test_support::processor_note(&processor, oa_seeds(), 2_000_000);
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
        let prepared = note.prepare_request("native-real-proof", payload.clone(), now, 400_000);
        assert_eq!(prepared.request.payload, payload);
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
        processor
            .settle_request_for_test(
                &prepared.request,
                SettlementResult {
                    status_code: 200,
                    payload: serde_json::json!({"billing_quote":quote,"usage_credits":123456})
                        .to_string(),
                    charge_applied: charge,
                    usage: None,
                    billing_label: "native-test".into(),
                },
            )
            .unwrap();
        let response = processor.sign_settled(&prepared.request).unwrap();
        note.complete(&prepared, &response).unwrap();
        assert_eq!(note.state.balance, 2_000_000 - charge);
    }

    /// The successor the server signs is at the derived anchor `succ(N)`, so
    /// the client installs it (S4) and its next request spends it (Q6a):
    /// three requests chain through the server and the request circuit.
    #[tokio::test]
    async fn signed_successors_chain_at_derived_anchors_through_the_circuit() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let mut processor = oa_lease_processor(store);
        processor.config.request_charge_cap = 1_000;
        let mut note = crate::test_support::processor_note(&processor, oa_seeds(), 2_000_000);
        let mut anchors = vec![note.state.anchor];
        for step in 0..3u128 {
            let now = current_timestamp();
            let prepared = note.prepare_request(
                &format!("chain-{step}"),
                crate::test_support::lease_payload(&processor.config, now),
                now,
                1_000,
            );
            let nullifier = prepared.request.public_inputs.request_nullifier;
            let response = processor
                .finalize_test_lease(&prepared.request, 100 + step)
                .unwrap();
            assert_eq!(response.next_anchor, core::next_anchor(&nullifier));
            assert_ne!(response.next_anchor, Felt252::ONE);
            note.complete(&prepared, &response).unwrap();
            anchors.push(note.state.anchor);
            // The installed state's prev_anchor is the one the request spent.
            assert_eq!(note.state.prev_anchor, Some(anchors[anchors.len() - 2]));
        }
        assert_eq!(note.state.balance, 2_000_000 - 100 - 101 - 102);
        // A successor at any other anchor fails the client's check (S4).
        let now = current_timestamp();
        let prepared = note.prepare_request(
            "foreign-anchor",
            crate::test_support::lease_payload(&processor.config, now),
            now,
            1_000,
        );
        let mut response = processor.finalize_test_lease(&prepared.request, 1).unwrap();
        response.next_anchor = random_field_for_test();
        assert!(note.clone().complete(&prepared, &response).is_err());
    }

    /// Review regression: a real signed-branch request proof whose state
    /// signature was forged with the published seed-0x1 secret mints nothing
    /// from a deployment with strong keys, through the full issuance path.
    #[tokio::test]
    async fn forged_development_key_state_signature_mints_nothing_under_strong_keys() {
        use crate::native_billing::NativeBillingConfig;
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};

        // The latest finalized oracle round, quoted by the forged payload, so
        // the request reaches proof admission exactly as it would over HTTP.
        let updated_at = current_timestamp() - 30;
        let reads = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let recorded = reads.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let recorded = recorded.clone();
                async move {
                    let data = request["params"][0]["data"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();
                    recorded.lock().unwrap().push(data.clone());
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else {
                        assert_eq!(request["params"][1], "finalized");
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
        let rpc = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });

        let (state_seed, clear_seed) = crate::signer::strong_test_seeds();
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = RequestProcessor::try_new(
            ServerConfig {
                request_charge_cap: 400_000,
                contract_address: Felt252::from_u64(1),
                native_billing: Some(NativeBillingConfig {
                    rpc_url,
                    max_age_seconds: 3600,
                    ..crate::test_support::native_config()
                }),
                openrouter_leases: Some(crate::test_support::lease_config()),
                proof_setup_dir: setup_directory(),
                ..Default::default()
            },
            store.clone(),
            Arc::new(ServerSigner::try_new(&state_seed, &clear_seed).unwrap()),
            Felt252::ZERO,
        )
        .unwrap();

        // A note, then a "signed" successor state at its derived anchor,
        // signed with the publicly known development secret.
        let development = zkapi_proof::dev::DevDeployment::new(1, Felt252::from_u64(1));
        let note = zkapi_proof::dev::DevNote {
            secret: zkapi_proof::compact::random_scalar(),
            note_id: 0,
            deposit_amount: 2_000_000,
            expiry: 4_000_000_000,
        };
        let genesis = note.genesis(zkapi_proof::compact::random_scalar());
        let forged = zkapi_proof::dev::DevState::signed(
            &note,
            &development,
            2_000_000,
            zkapi_proof::compact::random_scalar(),
            genesis.successor_anchor(),
            Some(genesis.anchor),
        );
        let wallet = crate::test_support::TestNote {
            deployment: development,
            state: forged,
            tree: zkapi_proof::dev::tree_with(&[&note]),
        };
        processor.update_root(wallet.root());
        let quote = NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at,
            expires_at: updated_at + 3600,
        };
        let request = wallet
            .prepare_request(
                "forged-development-key",
                json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                    .to_string(),
                current_timestamp(),
                400_000,
            )
            .request;
        // The proof itself is genuine for the development key.
        assert!(processor
            .verifier
            .verify(&request.public_inputs, &request.proof)
            .unwrap());

        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(&error, ServerError::InvalidRequest(message)
                if message == "state signing key does not match this deployment"),
            "{error}"
        );
        // Claiming this deployment's key instead leaves a signature the real
        // Groth16 verifier rejects.
        let mut relabelled = request.clone();
        let deployment_key = processor.state_signing_key();
        relabelled.public_inputs.state_signing_key_x = deployment_key.x;
        relabelled.public_inputs.state_signing_key_y = deployment_key.y;
        let error = processor
            .issue_openrouter_lease(&relabelled)
            .await
            .err()
            .unwrap();
        assert!(matches!(&error, ServerError::InvalidProof(_)), "{error}");

        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert!(store
            .lookup_openrouter_lease(&request.client_request_id)
            .is_none());
        // Neither attempt reached the vault spend check that precedes key issuance.
        assert!(!reads
            .lock()
            .unwrap()
            .iter()
            .any(|data| data.starts_with("0xaad24061")));
        rpc.abort();
    }

    // ---- Bounded settlement (G5) -------------------------------------------

    /// A verified-boundary lease request with its own id and nullifier.
    fn lease_request_for(
        processor: &RequestProcessor,
        id: &str,
        nullifier: u64,
        payload: Option<String>,
    ) -> ApiRequestV2 {
        let mut request = unverified_lease_request(processor);
        request.client_request_id = id.to_string();
        if let Some(payload) = payload {
            request.payload = payload;
        }
        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
        request.public_inputs.request_nullifier = Felt252::from_u64(nullifier);
        let commitment = zkapi_proof::compact::balance_commitment(
            3_000_000,
            &Felt252::from_u64(13),
            &Felt252::from_u64(14),
        );
        request.public_inputs.anonymous_commitment_x = commitment.x;
        request.public_inputs.anonymous_commitment_y = commitment.y;
        request.proof.proof = crate::test_support::fake_proof(9);
        request
    }

    struct LeaseSetup<'a> {
        key_source: &'a str,
        expires_at: u64,
        deadline: Option<u64>,
        key_hash: Option<&'a str>,
        delivered: Option<bool>,
        ttl: Option<u64>,
    }

    /// Reserve `request` and record its lease row as issuance would.
    fn add_lease(processor: &RequestProcessor, request: &ApiRequestV2, setup: LeaseSetup<'_>) {
        processor.store.reserve_openrouter_lease(request).unwrap();
        let oa_id = (setup.key_source == "oa_org")
            .then(|| RequestProcessor::native_oa_request_id(request).unwrap());
        let limit = RequestProcessor::lease_terms(request)
            .ok()
            .and_then(|(_, quote)| {
                quote
                    .limit_micro_usd(request.public_inputs.solvency_bound)
                    .ok()
            })
            .map(pricing::micro_usd_to_usd)
            .unwrap_or(3.0);
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request,
                key_source: setup.key_source,
                issued_at: setup.expires_at.saturating_sub(300),
                expires_at: setup.expires_at,
                settle_after: setup.expires_at,
                spending_limit_usd: limit,
                oa_client_request_id: oa_id.as_deref(),
                ttl_seconds: setup.ttl,
                settlement_deadline_at: setup.deadline,
                delivered: setup.delivered,
            })
            .unwrap();
        if let Some(hash) = setup.key_hash {
            processor
                .store
                .activate_openrouter_lease(&request.client_request_id, hash)
                .unwrap();
        }
    }

    fn record_of(processor: &RequestProcessor, request: &ApiRequestV2) -> TranscriptRecord {
        processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .unwrap()
    }

    fn payload_of(record: &TranscriptRecord) -> serde_json::Value {
        serde_json::from_str(record.response_payload.as_deref().unwrap()).unwrap()
    }

    fn review_of(processor: &RequestProcessor, request: &ApiRequestV2) -> Option<SettlementReview> {
        processor
            .store
            .settlement_reviews(100)
            .unwrap()
            .into_iter()
            .find(|stored| stored.review.client_request_id == request.client_request_id)
            .map(|stored| stored.review)
    }

    /// A genuine lease request under `oa_lease_processor`'s deployment and
    /// keys (a real Groth16 proof over a fresh note), with the wallet note
    /// that installs its successor.
    fn browser_lease_request(id: &str) -> (crate::test_support::TestNote, PreparedTestRequest) {
        let mut wallet_server = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        wallet_server.config.request_charge_cap = 400_000;
        let note = crate::test_support::processor_note(&wallet_server, oa_seeds(), 2_000_000);
        let now = current_timestamp();
        let prepared = note.prepare_request(
            id,
            crate::test_support::lease_payload(&wallet_server.config, now),
            now,
            400_000,
        );
        (note, prepared)
    }

    /// The store-level reopening without verifying the saved request: what
    /// an operator tool that skipped verification (or a database edit after
    /// a reopening) leaves for the server.
    fn reopen_unverified(
        store: &NullifierStore,
        client_request_id: &str,
        options: crate::nullifier_store::ReopenOptions<'_>,
        now: u64,
    ) -> Result<crate::nullifier_store::ReopenedLease, crate::nullifier_store::ReopenRefusal> {
        store.reopen_cancelled_lease(client_request_id, options, &|_| None, now)
    }

    fn conceded() -> crate::nullifier_store::ReopenOptions<'static> {
        crate::nullifier_store::ReopenOptions {
            zero_charge: true,
            rebind: false,
            saved_request: None,
        }
    }

    fn frozen_quote(request: &ApiRequestV2) -> serde_json::Value {
        serde_json::from_str::<serde_json::Value>(&request.payload).unwrap()["billing_quote"]
            .clone()
    }

    // ---- Settle, then sign (§5.1, O7) ----------------------------------------

    /// A delivered OA lease past its deadline: the sweep settles it at its
    /// solvency bound without provider I/O.
    fn overdue_lease(processor: &RequestProcessor, id: &str, nullifier: u64) -> ApiRequestV2 {
        let now = current_timestamp();
        let request = lease_request_for(processor, id, nullifier, None);
        add_lease(
            processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 1_000,
                deadline: Some(now - 1),
                key_hash: Some(&format!("{id}-hash")),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        request
    }

    fn lease_status_of(processor: &RequestProcessor, request: &ApiRequestV2) -> String {
        processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap()
            .status
    }

    /// O7: a settled request whose nullifier an exit consumed is not signed;
    /// its charge stays fixed, its lease and recovery report exit_deferred,
    /// and once the exit is defeated (the nullifier is unspent again) its
    /// successor is signed at the persisted charge and the derived anchor.
    #[tokio::test]
    async fn o7_defers_signing_while_the_nullifier_is_consumed_and_signs_after_a_defeat() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.challenge_period_seconds = Some(7_200);
        let request = overdue_lease(&processor, "exiting", 0x0e);
        let nullifier = request.public_inputs.request_nullifier;
        let bound = request.public_inputs.solvency_bound;
        processor.set_test_spent(nullifier, true);
        let before = processor.signer.state_signature_count();
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.settled_charge, Some(bound));
        assert_eq!(record.settled_basis.as_deref(), Some("worst_case"));
        let since = record.exit_deferred_since.expect("deferred");
        assert!(record.next_state_sig.is_none());
        assert_eq!(lease_status_of(&processor, &request), "exit_deferred");
        assert_eq!(processor.signer.state_signature_count(), before);
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "exit_deferred");
        assert!(recovery.request_response.is_none());
        // Every sweep re-checks; the first observation is kept.
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            record_of(&processor, &request).exit_deferred_since,
            Some(since)
        );
        assert_eq!(processor.signer.state_signature_count(), before);
        // A request at a consumed nullifier is not admitted again either.
        assert!(matches!(
            processor.sign_successor(&request).await.unwrap(),
            SignOutcome::Deferred { .. }
        ));

        // The exit is defeated: the flag clears, and the successor is signed
        // at the charge fixed by the settlement deadline.
        processor.set_test_spent(nullifier, false);
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(bound));
        assert_eq!(record.settled_charge, Some(bound));
        assert_eq!(record.next_anchor, Some(core::next_anchor(&nullifier)));
        assert_eq!(lease_status_of(&processor, &request), "finalized");
        assert_eq!(processor.signer.state_signature_count(), before + 1);
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "finalized");
        assert_eq!(recovery.request_response.unwrap().charge_applied, bound);
    }

    /// A full page of deferred requests, settled earlier and still consumed
    /// on chain, does not delay the successor of a newly settled request:
    /// the pass signs it in the same sweep.
    #[tokio::test]
    async fn deferred_requests_never_starve_a_newly_settled_one() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.challenge_period_seconds = Some(172_800);
        for i in 0..SIGN_BATCH as u64 {
            let request = overdue_lease(&processor, &format!("exiting-{i}"), 0x1000 + i);
            processor.set_test_spent(request.public_inputs.request_nullifier, true);
        }
        processor.settle_due_openrouter_leases().await;
        processor.store.execute_for_test(
            "UPDATE nullifiers SET settled_at = settled_at - 10 WHERE exit_deferred_since IS NOT NULL",
            rusqlite::params![],
        );
        let deferred = processor
            .store
            .settled_unsigned_requests(true, None, SIGN_BATCH + 1)
            .unwrap();
        assert_eq!(deferred.len(), SIGN_BATCH);
        let honest = overdue_lease(&processor, "honest", 0x9999);
        let before = processor.signer.state_signature_count();
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &honest);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(lease_status_of(&processor, &honest), "finalized");
        assert_eq!(processor.signer.state_signature_count(), before + 1);
    }

    /// Deferred requests are re-checked page by page: one whose exit is
    /// defeated is signed within two passes even behind a full page of
    /// requests that stay deferred, and the others stay deferred.
    #[tokio::test]
    async fn every_deferred_request_is_rechecked_however_many_precede_it() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.challenge_period_seconds = Some(172_800);
        let mut requests = Vec::new();
        for i in 0..=SIGN_BATCH as u64 {
            let request = overdue_lease(&processor, &format!("exiting-{i}"), 0x1000 + i);
            processor.set_test_spent(request.public_inputs.request_nullifier, true);
            requests.push(request);
        }
        processor.settle_due_openrouter_leases().await;
        processor.settle_due_openrouter_leases().await;
        let late = requests.pop().unwrap();
        // Settled after every other one, so it sorts last.
        processor.store.execute_for_test(
            "UPDATE nullifiers SET settled_at = settled_at + 10 WHERE nullifier = ?1",
            rusqlite::params![late.public_inputs.request_nullifier.to_hex()],
        );
        assert_eq!(lease_status_of(&processor, &late), "exit_deferred");
        let before = processor.signer.state_signature_count();
        // Its exit is defeated; the others stay consumed.
        processor.set_test_spent(late.public_inputs.request_nullifier, false);
        processor.sign_settled_successors().await;
        processor.sign_settled_successors().await;
        assert_eq!(
            record_of(&processor, &late).status,
            NullifierStatus::Finalized
        );
        assert_eq!(lease_status_of(&processor, &late), "finalized");
        assert_eq!(processor.signer.state_signature_count(), before + 1);
        for request in &requests {
            assert_eq!(
                record_of(&processor, request).status,
                NullifierStatus::Reserved
            );
        }
        // Further passes sign nothing else.
        processor.sign_settled_successors().await;
        assert_eq!(processor.signer.state_signature_count(), before + 1);
    }

    /// O7: still consumed `challengePeriod + 3600` s after the first
    /// observation, the request becomes ExitedUnsigned: terminal, never
    /// signed, whatever the chain does afterwards. Without a known challenge
    /// period the deferral never ends.
    #[tokio::test]
    async fn o7_ends_in_exited_unsigned_after_the_deferral_window() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.challenge_period_seconds = Some(100);
        let request = overdue_lease(&processor, "exited", 0x0f);
        let nullifier = request.public_inputs.request_nullifier;
        processor.set_test_spent(nullifier, true);
        let before = processor.signer.state_signature_count();
        processor.settle_due_openrouter_leases().await;
        assert_eq!(lease_status_of(&processor, &request), "exit_deferred");
        // Not yet past the window: still deferred.
        let first = current_timestamp() - 100 - 3_600 + 5;
        processor.store.execute_for_test(
            "UPDATE nullifiers SET exit_deferred_since = ?1 WHERE nullifier = ?2",
            rusqlite::params![first as i64, nullifier.to_hex()],
        );
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Reserved
        );
        // Past it: terminal.
        processor.store.execute_for_test(
            "UPDATE nullifiers SET exit_deferred_since = ?1 WHERE nullifier = ?2",
            rusqlite::params![(first - 10) as i64, nullifier.to_hex()],
        );
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::ExitedUnsigned);
        assert_eq!(
            record.settled_charge,
            Some(request.public_inputs.solvency_bound)
        );
        assert_eq!(lease_status_of(&processor, &request), "exited_unsigned");
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "exited_unsigned");
        assert!(recovery.request_response.is_none());
        // Terminal: an unspent nullifier later signs nothing.
        processor.set_test_spent(nullifier, false);
        processor.settle_due_openrouter_leases().await;
        assert!(matches!(
            processor.sign_successor(&request).await.unwrap(),
            SignOutcome::ExitedUnsigned
        ));
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::ExitedUnsigned
        );
        assert_eq!(processor.signer.state_signature_count(), before);
        // ExitedUnsigned rows block a clearance and a replay alike.
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::NullifierUsed)
        ));

        // No challenge period known (a library embedding): never terminal.
        processor.config.challenge_period_seconds = None;
        let open = overdue_lease(&processor, "deferred-forever", 0x10);
        processor.set_test_spent(open.public_inputs.request_nullifier, true);
        processor.settle_due_openrouter_leases().await;
        processor.store.execute_for_test(
            "UPDATE nullifiers SET exit_deferred_since = 1 WHERE nullifier = ?1",
            rusqlite::params![open.public_inputs.request_nullifier.to_hex()],
        );
        processor.settle_due_openrouter_leases().await;
        assert_eq!(lease_status_of(&processor, &open), "exit_deferred");
    }

    /// The signing gate reads `usedNullifiers(N)` over the vault RPC: a
    /// consumed nullifier defers, an unspent one signs, and a failed read
    /// leaves the settled request to the next sweep, neither signed nor
    /// deferred.
    #[tokio::test]
    async fn the_signing_gate_reads_used_nullifiers_over_the_vault_rpc() {
        let mock = Arc::new(std::sync::Mutex::new(IssuanceMock {
            spent: true,
            ..Default::default()
        }));
        let app = axum::Router::new()
            .route("/", axum::routing::post(issuance_rpc))
            .with_state(mock.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        configure_issuance_rpc(&mut processor, url);
        processor.test_chain = None;
        let request = overdue_lease(&processor, "rpc-gate", 0x11);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(mock.lock().unwrap().nullifier_reads, 1);
        assert!(record_of(&processor, &request)
            .exit_deferred_since
            .is_some());
        mock.lock().unwrap().fail_rpc = true;
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(processor.sign_successor(&request).await.is_err());
        {
            let mut mock = mock.lock().unwrap();
            mock.fail_rpc = false;
            mock.spent = false;
        }
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Finalized
        );
        server.abort();
    }

    /// The startup self-test runs at construction with an ephemeral key; the
    /// production signer signs nothing until a successor is due.
    #[test]
    fn the_startup_self_test_never_invokes_the_production_signer() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        assert_eq!(processor.signer.state_signature_count(), 0);
        let request = reserved_request(&processor);
        processor
            .settle_request_for_test(
                &request,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 1,
                    usage: None,
                    billing_label: "test".into(),
                },
            )
            .unwrap();
        processor.sign_settled(&request).unwrap();
        assert_eq!(processor.signer.state_signature_count(), 1);
    }

    /// O1: at most one successor per nullifier, whatever path runs again:
    /// another signing attempt or pass returns the stored transcript, a
    /// second write is refused, a settled lease is not settled again, and a
    /// reopening can neither sign again nor concede the charge.
    #[tokio::test]
    async fn no_path_signs_a_second_successor() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let request = overdue_lease(&processor, "once", 0x12);
        processor.settle_due_openrouter_leases().await;
        let first = record_of(&processor, &request);
        assert_eq!(first.status, NullifierStatus::Finalized);
        let signatures = processor.signer.state_signature_count();
        // The signing pass and a direct attempt return the stored response.
        processor.sign_settled_now();
        match processor.sign_successor(&request).await.unwrap() {
            SignOutcome::Signed(response) => {
                assert_eq!(Some(response.next_state_signature), first.next_state_sig);
                assert_eq!(Some(response.blind_delta_srv), first.blind_delta_srv);
            }
            other => panic!("{other:?}"),
        }
        // A second transcript is refused at the store, before any signature
        // is persisted.
        assert!(processor.sign_settled(&request).is_err());
        // The lease's settlement paths change nothing.
        processor.settle_due_openrouter_leases().await;
        let lease = processor.store.lookup_openrouter_lease("once").unwrap();
        assert!(processor
            .finalize_lease_fallback("once", FallbackCause::Deadline)
            .is_ok());
        assert!(processor
            .store
            .settle_openrouter_lease(
                "once",
                &request.public_inputs.request_nullifier,
                &SettledCharge {
                    charge: 0,
                    basis: "measured".into(),
                    response_code: 200,
                    response_payload: "{}".into(),
                    settled_at: 0,
                },
                &LeaseFinalization {
                    usage_usd: 0.0,
                    charge_applied: 0,
                    charge_basis: "measured",
                    review: None,
                    key_cleanup: None,
                    guard: FinalizeGuard::NotCancelled,
                },
            )
            .is_err());
        assert_eq!(lease.status, "finalized");
        // A reopening refuses a lease that is not cancelled.
        assert!(matches!(
            reopen_unverified(&processor.store, "once", conceded(), current_timestamp()),
            Err(crate::nullifier_store::ReopenRefusal::NotCancelled(_))
        ));
        let last = record_of(&processor, &request);
        assert_eq!(last.next_state_sig, first.next_state_sig);
        assert_eq!(last.next_commitment_x, first.next_commitment_x);
        assert_eq!(last.charge_applied, first.charge_applied);
        assert_eq!(processor.signer.state_signature_count(), signatures);
    }

    /// A reopened lease whose reservation already settled keeps that charge
    /// (written once) and cannot be conceded; --rebind cannot rewrite it.
    #[test]
    fn a_settled_charge_survives_a_reopening_and_refuses_concession_and_rebind() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let request = lease_request_for(&processor, "settled-then-cancelled", 0x13, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: 400,
                deadline: None,
                key_hash: Some("settled-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        // A charge persisted before the lease row was cancelled (by hand).
        processor
            .settle_request_for_test(
                &request,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 77,
                    usage: None,
                    billing_label: "test".into(),
                },
            )
            .unwrap();
        processor
            .store
            .cancel_openrouter_lease(
                "settled-then-cancelled",
                &review_for(&request, "binding_corrupt"),
            )
            .unwrap();
        assert!(matches!(
            reopen_unverified(
                &processor.store,
                "settled-then-cancelled",
                conceded(),
                current_timestamp()
            ),
            Err(crate::nullifier_store::ReopenRefusal::AlreadySettled)
        ));
        // A settled reservation is never rewritten by --rebind either.
        let payload_hash = request.payload_hash.to_hex();
        processor.store.execute_for_test(
            "UPDATE nullifiers SET payload_hash = '0x5' WHERE nullifier = ?1",
            rusqlite::params![request.public_inputs.request_nullifier.to_hex()],
        );
        assert!(matches!(
            reopen_unverified(
                &processor.store,
                "settled-then-cancelled",
                crate::nullifier_store::ReopenOptions {
                    zero_charge: false,
                    rebind: true,
                    saved_request: None,
                },
                current_timestamp()
            ),
            Err(crate::nullifier_store::ReopenRefusal::RebindSettled)
        ));
        processor.store.execute_for_test(
            "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
            rusqlite::params![
                payload_hash,
                request.public_inputs.request_nullifier.to_hex()
            ],
        );
        let reopened = reopen_unverified(
            &processor.store,
            "settled-then-cancelled",
            crate::nullifier_store::ReopenOptions::default(),
            current_timestamp(),
        )
        .unwrap();
        assert_eq!(reopened.settles, "settled_charge");
        // Settling it again keeps the persisted charge.
        let lease = processor
            .store
            .lookup_openrouter_lease("settled-then-cancelled")
            .unwrap();
        let settled = processor
            .settle_lease(
                &lease,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 5,
                    usage: None,
                    billing_label: "test".into(),
                },
                "measured",
                0.0,
                None,
                None,
                FinalizeGuard::NotCancelled,
            )
            .unwrap()
            .unwrap();
        assert_eq!(settled.charge, 77);
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease("settled-then-cancelled")
                .unwrap()
                .charge_applied,
            Some(77)
        );
        assert_eq!(processor.sign_settled(&request).unwrap().charge_applied, 77);
    }

    fn review_for(request: &ApiRequestV2, reason: &str) -> SettlementReview {
        SettlementReview {
            client_request_id: request.client_request_id.clone(),
            request_nullifier: request.public_inputs.request_nullifier,
            key_source: "oa_org".into(),
            reason: reason.into(),
            charge_basis: None,
            detail: "test".into(),
            reported_usage_micro_usd: None,
            charge_applied: None,
            solvency_bound: request.public_inputs.solvency_bound,
        }
    }

    /// O2 and the transactional reserve: a new request's reservation, its
    /// evidence and its provisioning lease row are written together or not
    /// at all, so no reservation is left that no sweep settles.
    #[test]
    fn a_new_reservation_is_written_with_its_evidence_and_lease_row_or_not_at_all() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.request_charge_cap = 400_000;
        let note = crate::test_support::processor_note(&processor, oa_seeds(), 2_000_000);
        let now = current_timestamp();
        let prepared = note.prepare_request(
            "atomic-lease",
            crate::test_support::lease_payload(&processor.config, now),
            now,
            400_000,
        );
        let request = &prepared.request;
        let nullifier = request.public_inputs.request_nullifier;
        let lease_config = processor.config.openrouter_leases.clone().unwrap();
        let issuance = IssuanceLease {
            lease_config: &lease_config,
            spending_limit_usd: 0.4,
            oa_request_id: Some("bound-upstream-id"),
        };
        processor.store.execute_for_test(
            "CREATE TRIGGER inject_lease_failure BEFORE INSERT ON openrouter_leases
             BEGIN SELECT RAISE(ABORT, 'injected lease failure'); END",
            [],
        );
        let error = processor
            .validate_and_reserve_with(request, Some(&issuance))
            .unwrap_err();
        assert!(
            error.to_string().contains("injected lease failure"),
            "{error}"
        );
        assert!(processor.store.lookup_by_nullifier(&nullifier).is_none());
        assert!(processor
            .store
            .request_evidence(&nullifier)
            .unwrap()
            .is_empty());
        processor
            .store
            .execute_for_test("DROP TRIGGER inject_lease_failure", []);
        assert!(processor
            .validate_and_reserve_with(request, Some(&issuance))
            .unwrap()
            .is_none());
        assert_eq!(
            record_of(&processor, request).status,
            NullifierStatus::Reserved
        );
        let evidence = processor.store.request_evidence(&nullifier).unwrap();
        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].public_inputs, request.public_inputs);
        let lease = processor
            .store
            .lookup_openrouter_lease("atomic-lease")
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert_eq!(lease.delivered, Some(false));
        assert_eq!(
            lease.oa_client_request_id.as_deref(),
            Some("bound-upstream-id")
        );
        assert!(lease.settlement_deadline_at.is_some());
        // The verified evidence is the request's real proof.
        assert!(processor
            .verifier
            .verify(&evidence[0].public_inputs, &request.proof)
            .unwrap());
    }

    // ---- Admission: root freshness (O5) and the lease ceiling (§5.2) -------

    /// O5: admission requires the exact root the indexer and the vault's
    /// currentRoot() agreed on within `root_max_staleness_seconds`: none
    /// yet, a disagreement or a stale agreement refuse with a retriable
    /// root_unavailable; an exact retry of a reserved request is unaffected.
    #[test]
    fn admission_refuses_without_a_fresh_vault_confirmed_root() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let root = Felt252::from_u64(0x5005);
        let mut request = unverified_lease_request(&processor);
        request.public_inputs.active_root = root;
        let refused = |processor: &RequestProcessor| {
            let error = processor.validate_and_reserve(&request).unwrap_err();
            assert!(matches!(error, ServerError::RootUnavailable(_)), "{error}");
            assert!(error.is_retriable());
            assert_eq!(error.error_code(), "root_unavailable");
        };
        // Never refreshed.
        refused(&processor);
        let now = current_timestamp();
        // The indexer and the vault disagree.
        processor.record_root_refresh(Some(Felt252::from_u64(0x6006)), root, now);
        refused(&processor);
        // They agreed, but longer ago than the staleness bound.
        processor.record_root_refresh(Some(root), root, now - 61);
        refused(&processor);
        // Fresh agreement: the root check passes (the fixture's proof does
        // not verify, so admission stops there).
        processor.record_root_refresh(Some(root), root, now);
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::InvalidProof(_))
        ));
        // A disagreement refuses at once, however fresh the last agreement.
        processor.record_root_refresh(Some(Felt252::from_u64(0x6006)), root, now);
        refused(&processor);
        processor.record_root_refresh(Some(root), root, now);
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::InvalidProof(_))
        ));
        // Without an indexer, the vault's root alone counts.
        processor.record_root_refresh(None, Felt252::from_u64(0x7007), now);
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::StaleRoot { .. })
        ));
        // A reserved request's exact retry precedes every root check.
        processor.record_root_refresh(Some(root), Felt252::from_u64(0x8008), now);
        let reserved = reserved_request(&processor);
        assert!(processor.validate_and_reserve(&reserved).unwrap().is_none());
    }

    /// The root poller reads the indexer and the vault: a lagging indexer
    /// makes admission refuse until both report the same root.
    #[tokio::test]
    async fn the_root_poller_requires_the_indexer_to_match_the_vault() {
        use axum::{routing::get, routing::post, Json, Router};
        use serde_json::{json, Value};
        let vault_root = Felt252::from_u64(0xa11);
        let indexer_root = Arc::new(std::sync::Mutex::new(Felt252::from_u64(0xa10)));
        let served = indexer_root.clone();
        let app = Router::new()
            .route(
                "/",
                post(move |Json(request): Json<Value>| async move {
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else {
                        assert_eq!(request["params"][0]["data"], CURRENT_ROOT_SELECTOR_FOR_TEST);
                        format!("0x{}", hex::encode(vault_root.as_bytes()))
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }),
            )
            .route(
                "/v1/tree/root",
                get(move || {
                    let served = served.clone();
                    async move { Json(json!({"root": *served.lock().unwrap()})) }
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        configure_issuance_rpc(&mut processor, url.clone());
        let mut request = unverified_lease_request(&processor);
        request.public_inputs.active_root = vault_root;
        processor.refresh_roots(Some(&url)).await.unwrap();
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::RootUnavailable(_))
        ));
        *indexer_root.lock().unwrap() = vault_root;
        processor.refresh_roots(Some(&url)).await.unwrap();
        assert_eq!(processor.current_root(), vault_root);
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::InvalidProof(_))
        ));
        // The indexer diverges again: admission refuses from the next
        // refresh, within the staleness bound of the last agreement.
        *indexer_root.lock().unwrap() = Felt252::from_u64(0xa12);
        processor.refresh_roots(Some(&url)).await.unwrap();
        assert!(matches!(
            processor.validate_and_reserve(&request),
            Err(ServerError::RootUnavailable(_))
        ));
        server.abort();
    }

    const CURRENT_ROOT_SELECTOR_FOR_TEST: &str = crate::native_billing::CURRENT_ROOT_SELECTOR;

    /// §5.2: a request whose lease budget exceeds the operator's ceiling is
    /// refused before anything is reserved or read from the chain; at or
    /// below it, admission proceeds.
    #[tokio::test]
    async fn the_lease_ceiling_refuses_larger_budgets_before_reserving() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        // $1000/ETH: 3,000,000 gwei of solvency bound is a $3 budget.
        let request = unverified_lease_request(&processor);
        processor.config.request_limit_max_usd_micros = Some(2_999_999);
        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(
            matches!(
                error,
                ServerError::RequestLimitExceeded {
                    limit_micro_usd: 3_000_000,
                    max_micro_usd: 2_999_999
                }
            ),
            "{error}"
        );
        assert!(!error.is_retriable());
        assert!(processor
            .store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert!(processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .is_none());
        // At the ceiling, admission continues (to the unreachable oracle).
        processor.config.request_limit_max_usd_micros = Some(3_000_000);
        let error = processor
            .issue_openrouter_lease(&request)
            .await
            .err()
            .unwrap();
        assert!(
            !matches!(error, ServerError::RequestLimitExceeded { .. }),
            "{error}"
        );
    }

    /// §5.2: once a request's nullifier is published on chain, recovery
    /// returns its status only.
    #[test]
    fn recovery_omits_the_response_of_a_published_nullifier() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let request = reserved_request(&processor);
        processor
            .settle_request_for_test(
                &request,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 3,
                    usage: None,
                    billing_label: "test".into(),
                },
            )
            .unwrap();
        processor.sign_settled(&request).unwrap();
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "finalized");
        assert!(recovery.request_response.is_some());
        let nullifier = request.public_inputs.request_nullifier;
        processor.test_chain().events.insert(nullifier);
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "finalized");
        assert!(recovery.request_response.is_none());
        let by_nullifier =
            futures_util::FutureExt::now_or_never(processor.recover_by_nullifier(&nullifier))
                .unwrap()
                .unwrap();
        assert!(by_nullifier.request_response.is_none());
        // Publication cannot be read: no response is served.
        processor.test_chain().events.clear();
        processor.test_chain().unavailable = true;
        assert!(matches!(
            processor.recover_now(&request.client_request_id),
            Err(ServerError::ChainReadUnavailable(_))
        ));
    }

    /// Review regression: while the indexer's published-nullifier table
    /// cannot be read, recovery reads the vault's EscapeConcessionRecorded
    /// logs from an hour before the reservation instead of failing: the
    /// response is served unless such a log names the nullifier (the
    /// successor nullifier of a defeated escape, whose flags are clear). An
    /// unreadable chain still fails closed, and the evidence endpoint stays
    /// strict.
    #[test]
    fn recovery_reads_the_vaults_logs_while_the_indexer_is_unavailable() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.indexer_url = Some("http://127.0.0.1:9".into());
        let request = reserved_request(&processor);
        processor
            .settle_request_for_test(
                &request,
                SettlementResult {
                    status_code: 200,
                    payload: "{}".into(),
                    charge_applied: 3,
                    usage: None,
                    billing_label: "test".into(),
                },
            )
            .unwrap();
        processor.sign_settled(&request).unwrap();
        let nullifier = request.public_inputs.request_nullifier;
        let record = processor
            .store
            .try_lookup_by_nullifier(&nullifier)
            .unwrap()
            .unwrap();
        let since = request.public_inputs.request_time.min(record.created_at)
            - PUBLICATION_SCAN_SLACK_SECONDS;
        processor.test_chain().indexer_unavailable = true;
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert!(recovery.request_response.is_some());
        assert_eq!(processor.test_chain().scans, [since]);
        // A defeated escape named it as its successor nullifier: no flag is
        // set, and the log decides.
        processor.test_chain().events.insert(nullifier);
        processor.test_chain().event_times.insert(nullifier, since);
        let recovery = processor.recover_now(&request.client_request_id).unwrap();
        assert_eq!(recovery.nullifier_status, "finalized");
        assert!(recovery.request_response.is_none());
        // With the indexer back, its table answers and nothing is scanned.
        processor.test_chain().indexer_unavailable = false;
        processor.test_chain().scans.clear();
        assert!(processor
            .recover_now(&request.client_request_id)
            .unwrap()
            .request_response
            .is_none());
        assert!(processor.test_chain().scans.is_empty());
        // The evidence endpoint never falls back while an indexer is
        // configured.
        processor.test_chain().events.clear();
        processor.test_chain().indexer_unavailable = true;
        assert!(matches!(
            futures_util::FutureExt::now_or_never(processor.request_evidence(&nullifier)).unwrap(),
            Err(ServerError::ChainReadUnavailable(_))
        ));
        assert!(processor.test_chain().scans.is_empty());
        // Without one, the vault's logs from the reservation decide.
        processor.config.indexer_url = None;
        assert!(
            futures_util::FutureExt::now_or_never(processor.request_evidence(&nullifier))
                .unwrap()
                .unwrap()
                .is_some()
        );
        assert_eq!(processor.test_chain().scans.len(), 1);
        // Neither the flags nor the logs can be read: fail closed.
        processor.test_chain().unavailable = true;
        assert!(matches!(
            processor.recover_now(&request.client_request_id),
            Err(ServerError::ChainReadUnavailable(_))
        ));
    }

    /// An OA usage relay that returns a finalized, station-signed receipt.
    async fn oa_usage_server(
        usage_credits: u128,
        expected_duration_minutes: u64,
    ) -> (
        String,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::Mutex<usize>>,
    ) {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let seen = calls.clone();
        let app = Router::new().route(
            "/api/zkapi/key_usage",
            post(move |Json(body): Json<Value>| {
                let seen = seen.clone();
                async move {
                    *seen.lock().unwrap() += 1;
                    assert_eq!(body["duration_minutes"], expected_duration_minutes);
                    let expires_at = body["expires_at_unix"].as_u64().unwrap() - 30;
                    Json(json!({"source":"oa_org", "version":1, "status":"finalized",
                        "client_request_id":body["client_request_id"], "station_request_id":"ab".repeat(32),
                        "key_hash":body["key_hash"], "usage_credits":usage_credits,
                        "credit_limit_credits":body["credit_limit_credits"], "expires_at_unix":expires_at,
                        "closed_at_unix":expires_at, "finalized_at_unix":expires_at + 1,
                        "station_id":"station", "station_signature":"ab".repeat(64),
                        "org_signature":"cd".repeat(64)}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, server, calls)
    }

    /// Report regression 1: usage far above the proof-bound budget used to
    /// make the conversion fail on every scan, for ever.
    #[tokio::test]
    async fn overflowing_usage_finalizes_clamped_instead_of_retrying() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 1e12,
            ..Default::default()
        }));
        let (processor, request, server) = retirement_processor(state.clone(), 0, None).await;
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("clamped"));
        let bound = request.public_inputs.solvency_bound;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert!(record.next_anchor.is_some() && record.next_state_sig.is_some());
        let expected = RequestProcessor::lease_terms(&request)
            .unwrap()
            .1
            .capped_charge_units(pricing::usd_to_micro_usd(1e12), bound);
        assert!(expected.clamped);
        assert_eq!(record.charge_applied, Some(expected.charge));
        assert!(expected.charge <= bound);
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "clamped");
        assert_eq!(payload["reported_usage_micro_usd"], "1000000000000000000");
        assert_eq!(
            payload["charged_usage_micro_usd"],
            expected.charged_micro_usd.to_string()
        );
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "usage_clamped"
        );
        let events = state.lock().unwrap().events.clone();
        assert_eq!(events, ["disable", "usage", "delete"]);
        // A later scan makes no provider calls and never re-signs.
        processor.settle_due_openrouter_leases().await;
        assert_eq!(state.lock().unwrap().events, events);
        assert_eq!(
            record_of(&processor, &request).next_state_sig,
            record.next_state_sig
        );
        server.abort();
    }

    /// Report regression 2: changing --native-price-* must not strand leases
    /// bound to the old quote policy.
    #[tokio::test]
    async fn lease_settles_unchanged_after_native_config_changes() {
        let changed = crate::native_billing::NativeBillingConfig {
            rpc_url: "http://127.0.0.1:9".into(),
            feed_address: "0x0000000000000000000000000000000000000abc".into(),
            decimals: 9,
            max_age_seconds: 7200,
        };
        // Direct key, across a restart with the changed configuration.
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000002,
            ..Default::default()
        }));
        let directory = tempfile::tempdir().unwrap();
        let db_path = directory.path().join("server.db");
        let (processor, request, server) =
            retirement_processor(state.clone(), 0, Some(&db_path)).await;
        assert!(processor.lease_authorization(&request).is_ok());
        let mut config = processor.config.clone();
        let signer = processor.signer.clone();
        drop(processor);
        config.native_billing = Some(changed.clone());
        let processor = RequestProcessor::try_new(
            config,
            Arc::new(NullifierStore::new(&db_path).unwrap()),
            signer,
            Felt252::ZERO,
        )
        .unwrap();
        assert!(processor.lease_authorization(&request).is_err());
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        let record = record_of(&processor, &request);
        // $1000/ETH frozen quote: 2 micro-USD is 2 gwei.
        assert_eq!(record.charge_applied, Some(2));
        assert_eq!(payload_of(&record)["billing_quote"], frozen_quote(&request));
        server.abort();

        // OA key, after the same configuration change.
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc) = issuance_processor(true, issuance).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "oa-hash")
            .unwrap();
        processor.config.native_billing = Some(changed);
        let (url, usage, calls) = oa_usage_server(1_000_000, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(1_000_000));
        assert_eq!(payload_of(&record)["billing_quote"], frozen_quote(&request));
        assert_eq!(*calls.lock().unwrap(), 1);
        rpc.abort();
        usage.abort();
    }

    /// Report regression 3: a transient failure retries until the lease's
    /// write-once deadline, then finalizes at the worst case without I/O.
    #[tokio::test]
    async fn transient_failure_retries_until_deadline_then_finalizes_worst_case() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let pending = lease_request_for(&processor, "before-deadline", 501, None);
        add_lease(
            &processor,
            &pending,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hash-a"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let overdue = lease_request_for(&processor, "past-deadline", 502, None);
        add_lease(
            &processor,
            &overdue,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 200,
                deadline: Some(now - 140),
                key_hash: Some("hash-b"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.settle_due_openrouter_leases().await;

        let retrying = processor
            .store
            .lookup_openrouter_lease(&pending.client_request_id)
            .unwrap();
        assert_eq!(retrying.status, "disabled");
        assert!(retrying.settlement_attempts >= 1);
        assert!(retrying.first_error_at.is_some());
        assert_eq!(
            record_of(&processor, &pending).status,
            NullifierStatus::Reserved
        );
        let status = processor
            .openrouter_lease_status(&pending.client_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(status.settlement_deadline, Some(now + 3_600));

        let bound = overdue.public_inputs.solvency_bound;
        let record = record_of(&processor, &overdue);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(bound));
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "worst_case");
        assert_eq!(payload["settlement_reason"], "settlement_deadline");
        assert_eq!(payload["settlement_deadline"], now - 140);
        assert_eq!(payload["billing_quote"], frozen_quote(&overdue));
        let review = review_of(&processor, &overdue).unwrap();
        assert_eq!(review.reason, "deadline_worst_case");
        assert_eq!(review.charge_applied, Some(bound));
        let status = processor
            .openrouter_lease_status(&overdue.client_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("worst_case"));
        assert_eq!(status.settlement_deadline, None);
        // The finalized lease's key is disabled and deleted in the background.
        assert_eq!(
            processor.settlement_counts().unwrap().pending_key_cleanups,
            0
        );
        server.abort();
    }

    /// The deadline is written once: a provider that keeps reporting the key
    /// enabled (disabled -> retiring -> disabled ...) cannot postpone it.
    #[tokio::test]
    async fn deadline_fires_while_provider_keeps_reporting_the_key_enabled() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            report_enabled: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let deadline = now + 2;
        let request = lease_request_for(&processor, "stuck-enabled", 503, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 10,
                deadline: Some(deadline),
                key_hash: Some("hash-enabled"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let mut first_error_at = None;
        for cycle in 1..=2 {
            processor.settle_due_openrouter_leases().await;
            let lease = processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(lease.status, "retiring");
            assert_eq!(lease.settlement_deadline_at, Some(deadline));
            assert_eq!(lease.settlement_attempts, cycle);
            first_error_at = first_error_at.or(lease.first_error_at);
            assert_eq!(lease.first_error_at, first_error_at);
        }
        while current_timestamp() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        assert_eq!(payload_of(&record)["charge_basis"], "worst_case");
        server.abort();
    }

    #[tokio::test]
    async fn deadline_sweep_ignores_hung_provider() {
        use axum::{routing::any, Router};
        let calls = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
        let seen = calls.clone();
        let app = Router::new().route(
            "/v1/keys/{hash}",
            any(
                move |axum::extract::Path(hash): axum::extract::Path<String>| {
                    let seen = seen.clone();
                    async move {
                        seen.lock().unwrap().push(hash);
                        tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                        axum::http::StatusCode::SERVICE_UNAVAILABLE
                    }
                },
            ),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.openrouter_leases.as_mut().unwrap().source =
            OpenRouterLeaseSourceConfig::OpenRouter {
                management_key: "test".into(),
                api_base: url.clone(),
            };
        processor.openrouter = Some(Arc::new(
            OpenRouterProvisioner::new("test".into(), url).unwrap(),
        ));
        processor.oa_org = None;
        processor.timing.attempt_timeout = std::time::Duration::from_millis(500);
        processor.timing.tick_budget = std::time::Duration::from_millis(500);
        processor.timing.cleanup_attempt_timeout = std::time::Duration::from_millis(200);
        let now = current_timestamp();
        let overdue = lease_request_for(&processor, "overdue", 504, None);
        add_lease(
            &processor,
            &overdue,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("overdue-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let hung = lease_request_for(&processor, "hung", 505, None);
        add_lease(
            &processor,
            &hung,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hung-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            processor.settle_due_openrouter_leases(),
        )
        .await
        .expect("a hung provider stalled the settlement sweep");
        let record = record_of(&processor, &overdue);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(overdue.public_inputs.solvency_bound)
        );
        let hung_lease = processor
            .store
            .lookup_openrouter_lease(&hung.client_request_id)
            .unwrap();
        assert_eq!(hung_lease.status, "retiring");
        assert_eq!(
            hung_lease.last_error.as_deref(),
            Some("internal error: settlement attempt timed out")
        );
        // The overdue lease was finalized before any provider call; only its
        // background key cleanup (which timed out) reached the provider.
        assert!(calls
            .lock()
            .unwrap()
            .iter()
            .all(|hash| hash == "hung-hash" || hash == "overdue-hash"));
        server.abort();
    }

    #[tokio::test]
    async fn revoking_lease_at_deadline_charges_persisted_usage() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            delete_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "revoking", 506, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("hash-revoking"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        for (from, to, usage) in [
            ("active", "retiring", None),
            ("retiring", "disabled", None),
            ("disabled", "revoking", Some(0.000002)),
        ] {
            processor
                .store
                .advance_openrouter_retirement(&request.client_request_id, from, to, 0, usage)
                .unwrap();
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        // The measured usage, not the solvency bound.
        assert_eq!(record.charge_applied, Some(2));
        let payload = payload_of(&record);
        assert_eq!(payload["charge_basis"], "measured");
        assert_eq!(payload["key_deleted"], false);
        assert_eq!(payload["settlement_reason"], "settlement_deadline");
        let review = review_of(&processor, &request).unwrap();
        assert_eq!(review.reason, "finalized_before_key_deletion");
        assert_eq!(review.charge_applied, Some(2));
        // Deletion keeps failing: the key stays queued and is retried later.
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        assert_eq!(
            processor.settlement_counts().unwrap().pending_key_cleanups,
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn oa_receipt_above_limit_is_clamped_and_finalizes() {
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, rpc) = issuance_processor(true, issuance).await;
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "oa-hash")
            .unwrap();
        let (url, usage, _) = oa_usage_server(10_000_000, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        let bound = request.public_inputs.solvency_bound;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(bound));
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "oa_org_ephemeral_lease_settlement");
        assert_eq!(payload["usage_credits"], 10_000_000);
        assert_eq!(payload["charged_usage_credits"], 3_000_000);
        assert_eq!(payload["charge_basis"], "clamped");
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "usage_clamped"
        );
        assert_eq!(
            processor
                .openrouter_lease_status(&request.client_request_id)
                .unwrap()
                .unwrap()
                .charge_basis
                .as_deref(),
            Some("clamped")
        );
        rpc.abort();
        usage.abort();
    }

    #[tokio::test]
    async fn oa_usage_and_resumed_issuance_use_the_persisted_ttl() {
        let issuance = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, _, rpc) = issuance_processor(true, issuance.clone()).await;
        let now = current_timestamp();
        let settled = lease_request_for(&processor, "persisted-ttl", 507, None);
        add_lease(
            &processor,
            &settled,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("ttl-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        // The configured TTL changes after the leases were bound.
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 600;
        let (url, usage, calls) = oa_usage_server(1, 5).await;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.settle_due_openrouter_leases().await;
        assert_eq!(*calls.lock().unwrap(), 1);
        assert_eq!(
            record_of(&processor, &settled).status,
            NullifierStatus::Finalized
        );
        usage.abort();

        // Resumed issuance requests, and accepts, the persisted 5 minutes.
        let resumed = lease_request_for(&processor, "resumed-ttl", 508, None);
        add_lease(
            &processor,
            &resumed,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 300,
                deadline: Some(now + 3_600),
                key_hash: None,
                delivered: Some(false),
                ttl: Some(300),
            },
        );
        let issuer = format!(
            "http://{}",
            rpc_address(&processor.config.native_billing.as_ref().unwrap().rpc_url)
        );
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(issuer, "test-secret".into()).unwrap(),
        ));
        let issued = processor.issue_openrouter_lease(&resumed).await.unwrap();
        assert!(issued.lease.expires_at <= current_timestamp() + 300);
        let lease = processor
            .store
            .lookup_openrouter_lease(&resumed.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.delivered, Some(true));
        assert_eq!(lease.ttl_seconds, Some(300));
        assert_eq!(issuance.lock().unwrap().creates, 1);
        rpc.abort();
    }

    /// The issuance mock serves its RPC under /rpc on the same listener.
    fn rpc_address(rpc_url: &str) -> String {
        rpc_url
            .trim_start_matches("http://")
            .trim_end_matches("/rpc")
            .to_string()
    }

    #[tokio::test]
    async fn abandoned_direct_provisioning_finalizes_zero_after_orphan_cleanup() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 1;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert_eq!(lease.delivered, Some(false));
        let reads = {
            let mut state = state.lock().unwrap();
            // The ambiguous create left a key behind under the request name.
            state.orphan_name = Some(format!("zkapi-{}", request.client_request_id));
            state.cleanup.clear();
            state.nullifier_reads
        };
        while current_timestamp() <= lease.settle_after {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        let payload = payload_of(&record);
        assert_eq!(payload["type"], "openrouter_ephemeral_lease_settlement");
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["issued"], false);
        assert_eq!(payload["reason"], "issuance_not_completed");
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        {
            let state = state.lock().unwrap();
            // Disabled, then deleted; an unrelated key is untouched.
            assert_eq!(state.cleanup, ["disable:orphan-hash", "delete:orphan-hash"]);
            // A zero charge needs no chain read.
            assert_eq!(state.nullifier_reads, reads);
        }
        assert!(processor
            .recover_now(&request.client_request_id)
            .unwrap()
            .request_response
            .is_some());
        let creates = state.lock().unwrap().creates;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(state.lock().unwrap().creates, creates);
        server.abort();
    }

    /// The critique's orphan race: an exact retry in flight holds the issue
    /// lock, so zero finalization defers; after it, retries never mint a key.
    #[tokio::test]
    async fn zero_finalization_defers_to_in_flight_issuance() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(false, state.clone()).await;
        let guard = processor.lease_issue_lock.lock().await;
        processor.settle_due_openrouter_leases().await;
        assert_eq!(
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status,
            "provisioning"
        );
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Reserved
        );
        drop(guard);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(record_of(&processor, &request).charge_applied, Some(0));
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Replay)
        ));
        assert_eq!(state.lock().unwrap().creates, 0);
        server.abort();
    }

    #[tokio::test]
    async fn activation_never_returned_to_the_client_finalizes_at_zero() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            consume_on_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        processor
            .config
            .openrouter_leases
            .as_mut()
            .unwrap()
            .ttl_seconds = 1;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::NullifierUsed)
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.delivered, Some(false));
        let reads = state.lock().unwrap().nullifier_reads;
        while current_timestamp() <= lease.settle_after {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.charge_applied, Some(0));
        let payload = payload_of(&record);
        assert_eq!(payload["charge_basis"], "unissued");
        assert_eq!(payload["reason"], "key_never_delivered");
        let state = state.lock().unwrap();
        assert_eq!(state.cleanup, ["disable:test-hash", "delete:test-hash"]);
        assert_eq!(state.nullifier_reads, reads);
        server.abort();
    }

    /// The worst case applies only to a key that may have been delivered.
    #[tokio::test]
    async fn worst_case_applies_only_to_possibly_delivered_leases() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state, 0, None).await;
        let now = current_timestamp();
        let mut cases = Vec::new();
        for (id, nullifier, key_hash, delivered, expected) in [
            (
                "delivered",
                511,
                Some("hash-1"),
                Some(true),
                Some(3_000_000),
            ),
            (
                "unknown-provenance",
                512,
                Some("hash-2"),
                None,
                Some(3_000_000),
            ),
            ("never-returned", 513, Some("hash-3"), Some(false), Some(0)),
            ("never-issued", 514, None, Some(false), Some(0)),
        ] {
            let request = lease_request_for(&processor, id, nullifier, None);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "openrouter",
                    expires_at: now - 100,
                    deadline: Some(now - 1),
                    key_hash,
                    delivered,
                    ttl: Some(300),
                },
            );
            cases.push((request, expected));
        }
        processor.settle_due_openrouter_leases().await;
        for (request, expected) in cases {
            let record = record_of(&processor, &request);
            assert_eq!(
                record.charge_applied, expected,
                "{}",
                request.client_request_id
            );
            let basis = payload_of(&record)["charge_basis"].clone();
            assert_eq!(
                basis,
                if expected == Some(0) {
                    "unissued"
                } else {
                    "worst_case"
                },
                "{}",
                request.client_request_id
            );
        }
        server.abort();
    }

    /// An honest user who escapes after a failed issuance is never charged,
    /// even once the server clock passes the lease's deadline.
    #[tokio::test]
    async fn honest_escape_after_failed_issuance_past_deadline_finalizes_at_zero() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock {
            fail_create: true,
            ..Default::default()
        }));
        let (mut processor, request, server) = issuance_processor(false, state.clone()).await;
        let lease_config = processor.config.openrouter_leases.as_mut().unwrap();
        lease_config.ttl_seconds = 1;
        lease_config.settlement_deadline_seconds = 1;
        assert!(processor.issue_openrouter_lease(&request).await.is_err());
        state.lock().unwrap().spent = true; // the user escaped on chain
        let deadline = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap()
            .settlement_deadline_at
            .unwrap();
        while current_timestamp() <= deadline {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let reads = state.lock().unwrap().nullifier_reads;
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        assert!(review_of(&processor, &request).is_none());
        assert_eq!(state.lock().unwrap().nullifier_reads, reads);
        server.abort();
    }

    #[tokio::test]
    async fn zero_usage_is_signed_without_a_chain_read() {
        // The fixture oracle RPC is unreachable: nothing here may need it.
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, request, server) = retirement_processor(state, 0, None).await;
        processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        assert!(record.next_state_sig.is_some());
        assert_eq!(payload_of(&record)["charge_basis"], "measured");
        server.abort();
    }

    #[test]
    fn settlement_clamps_charge_above_solvency_bound() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let request = lease_request_for(&processor, "clamped", 77, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: 400,
                deadline: None,
                key_hash: Some("clamped-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let lease = processor.store.lookup_openrouter_lease("clamped").unwrap();
        let bound = request.public_inputs.solvency_bound;
        let result = |charge| SettlementResult {
            status_code: 200,
            payload: processor
                .settlement_payload(&request, serde_json::json!({}))
                .unwrap(),
            charge_applied: charge,
            usage: None,
            billing_label: "test".into(),
        };
        let settled = processor
            .settle_lease(
                &lease,
                result(bound + 1),
                "measured",
                0.0,
                None,
                None,
                FinalizeGuard::NotCancelled,
            )
            .unwrap()
            .unwrap();
        assert_eq!(settled.charge, bound);
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert_eq!(record.settled_charge, Some(bound));
        let response = processor.sign_settled(&request).unwrap();
        assert_eq!(response.charge_applied, bound);
        assert_eq!(record_of(&processor, &request).charge_applied, Some(bound));
        // A successor for another deployment is never settled or signed.
        let mut foreign = lease_request_for(&processor, "foreign", 515, None);
        foreign.public_inputs.chain_id = 5;
        add_lease(
            &processor,
            &foreign,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: 400,
                deadline: None,
                key_hash: Some("foreign-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let lease = processor.store.lookup_openrouter_lease("foreign").unwrap();
        assert!(processor
            .settle_lease(
                &lease,
                result(0),
                "measured",
                0.0,
                None,
                None,
                FinalizeGuard::NotCancelled
            )
            .is_err());
        assert_eq!(record_of(&processor, &foreign).settled_charge, None);
        assert!(processor.sign_settled(&foreign).is_err());
    }

    #[tokio::test]
    async fn unsettleable_persisted_quote_finalizes_worst_case_immediately() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage: 0.000002,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let mut payload: serde_json::Value =
            serde_json::from_str(&crate::test_support::lease_payload(&processor.config, now))
                .unwrap();
        payload["billing_quote"]["expires_at"] = (now - 10).into(); // before updated_at
        let request = lease_request_for(&processor, "bad-quote", 516, Some(payload.to_string()));
        assert!(RequestProcessor::lease_terms(&request).is_err());
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 1,
                deadline: Some(now + 3_600),
                key_hash: Some("hash-bad"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(
            record.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        let settled = payload_of(&record);
        assert_eq!(settled["charge_basis"], "worst_case");
        assert_eq!(settled["settlement_reason"], "unsettleable");
        // The untouched quote is echoed so that clients can match it.
        assert_eq!(settled["billing_quote"], payload["billing_quote"]);
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "unsettleable_worst_case"
        );
        server.abort();
    }

    #[tokio::test]
    async fn corrupted_binding_is_cancelled_never_signed() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock::default()));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "corrupt", 517, None);
        processor.store.reserve_openrouter_lease(&request).unwrap();
        // The lease row holds a different request than the reservation.
        let mut tampered = request.clone();
        tampered.proof.proof = crate::test_support::fake_proof(8);
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &tampered,
                key_source: "openrouter",
                issued_at: now - 400,
                expires_at: now - 100,
                settle_after: now - 100,
                spending_limit_usd: 3.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(now - 1),
                delivered: Some(true),
            })
            .unwrap();
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "hash-corrupt")
            .unwrap();
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "cancelled");
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(record.next_state_sig.is_none());
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "binding_corrupt"
        );
        // Its key is still stopped; the cancelled lease is never retried.
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        processor.settle_due_openrouter_leases().await;
        assert_eq!(state.lock().unwrap().events, ["disable", "delete"]);
        assert_eq!(processor.settlement_counts().unwrap().cancelled, 1);
        server.abort();
    }

    #[tokio::test]
    async fn retire_endpoint_applies_fallback_past_deadline() {
        let state = Arc::new(std::sync::Mutex::new(RetirementMock {
            usage_unavailable: true,
            ..Default::default()
        }));
        let (processor, _, server) = retirement_processor(state.clone(), 0, None).await;
        let now = current_timestamp();
        let request = lease_request_for(&processor, "retire-late", 518, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("hash-late"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let status = processor
            .retire_openrouter_lease(&request.client_request_id, &request)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert_eq!(status.charge_basis.as_deref(), Some("worst_case"));
        assert_eq!(
            status.charge_applied,
            Some(request.public_inputs.solvency_bound)
        );
        // No usage read: the deadline had passed.
        assert!(!state.lock().unwrap().events.contains(&"usage"));
        server.abort();
    }

    #[tokio::test]
    async fn issuance_rpc_failure_leaves_settleable_provisioning_row() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (processor, request, server) = issuance_processor(false, state.clone()).await;
        // A bare reservation: issuance accepted the request, then stopped.
        processor
            .store
            .remove_failed_openrouter_lease(&request.client_request_id)
            .unwrap();
        state.lock().unwrap().fail_rpc = true;
        assert!(matches!(
            processor.issue_openrouter_lease(&request).await,
            Err(ServerError::Internal(_))
        ));
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "provisioning");
        assert_eq!(lease.delivered, Some(false));
        assert_eq!(lease.ttl_seconds, Some(300));
        let deadline = lease.settlement_deadline_at.unwrap();
        assert!(deadline >= lease.issued_at.saturating_add(300));
        assert_eq!(state.lock().unwrap().provider_calls, 0);
        assert_eq!(
            processor
                .recover_now(&request.client_request_id)
                .unwrap()
                .settlement_deadline,
            Some(deadline)
        );
        server.abort();
    }

    #[tokio::test]
    async fn expire_check_acknowledges_expired_quote_after_config_change() {
        use crate::native_billing::NativeBillingConfig;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        // Quotes made under a 3600 s policy; the server now runs 4500 s.
        processor.config.native_billing = Some(NativeBillingConfig {
            max_age_seconds: 4500,
            ..crate::test_support::native_config()
        });
        let quote = |updated_at: u64| {
            serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
                "asset":"native_eth", "units_per_eth":1_000_000_000, "chain_id":1,
                "feed_address":"0x694aa1769357215de4fac081bf1f309adc325306", "round_id":"123",
                "answer":"100000000000", "decimals":8, "updated_at":updated_at,
                "expires_at":updated_at + 3600}})
            .to_string()
        };
        let expired = lease_request_for(&processor, "expired-quote", 519, Some(quote(100)));
        assert_eq!(
            processor
                .expire_unaccepted_native_lease(&expired.client_request_id, &expired)
                .await
                .unwrap()["status"],
            "expired_unaccepted"
        );
        let live = lease_request_for(&processor, "live-quote", 520, Some(quote(now)));
        assert!(matches!(
            processor
                .expire_unaccepted_native_lease(&live.client_request_id, &live)
                .await,
            Err(ServerError::InvalidRequest(_))
        ));
    }

    /// Drill builds (§5.5, §10.7 B): each adversary mode misbehaves as its
    /// drill expects, and the client's checks (S1-S6) refuse what it signs.
    #[cfg(feature = "adversary")]
    #[test]
    fn adversary_modes_misbehave_and_clients_refuse_their_successors() {
        use crate::adversary::AdversaryMode;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let setup = |mode: Option<AdversaryMode>, secret: u64| {
            let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
            processor.config.request_charge_cap = 400_000;
            processor.set_adversary(mode);
            // Each note has a random secret, so its own nullifier.
            let _ = secret;
            let note = crate::test_support::processor_note(&processor, oa_seeds(), 2_000_000);
            let now = current_timestamp();
            let payload = crate::test_support::lease_payload(&processor.config, now);
            let prepared = note.prepare_request("adversary", payload, now, 400_000);
            (processor, note, prepared)
        };
        for (mode, check) in [
            (AdversaryMode::BornSpent, "S4"),
            (AdversaryMode::RandomAnchor, "S4"),
            (AdversaryMode::Overcharge, "S3"),
        ] {
            let (processor, note, prepared) = setup(Some(mode), 7);
            let response = processor.finalize_test_lease(&prepared.request, 1).unwrap();
            let error =
                crate::test_support::complete_response(&note.deployment, &prepared, &response)
                    .unwrap_err()
                    .to_string();
            assert!(error.starts_with(check), "{mode:?}: {error}");
        }
        // reuse-anchor: a second successor is signed at the first's anchor.
        let (processor, _, first) = setup(Some(AdversaryMode::ReuseAnchor), 8);
        let anchor = processor
            .finalize_test_lease(&first.request, 1)
            .unwrap()
            .next_anchor;
        let (processor, note, second) = setup(Some(AdversaryMode::ReuseAnchor), 9);
        let response = processor.finalize_test_lease(&second.request, 1).unwrap();
        assert_eq!(response.next_anchor, anchor);
        assert!(
            crate::test_support::complete_response(&note.deployment, &second, &response)
                .unwrap_err()
                .to_string()
                .starts_with("S4")
        );
        // withhold: settled, never signed; recovery answers without a
        // successor.
        let (processor, _, prepared) = setup(Some(AdversaryMode::Withhold), 10);
        let error = processor
            .finalize_test_lease(&prepared.request, 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("withhold"), "{error}");
        let record = processor
            .store
            .lookup_by_nullifier(&prepared.request.public_inputs.request_nullifier)
            .unwrap();
        assert!(record.settled_unsigned());
        let recovery = processor
            .recover_now(&prepared.request.client_request_id)
            .unwrap();
        assert!(recovery.request_response.is_none());
        // lie-expired: a reserved request is called expired, and its proof
        // kept; an honest server refuses.
        for (mode, lies) in [(Some(AdversaryMode::LieExpired), true), (None, false)] {
            let (processor, _, prepared) = setup(mode, 11);
            let request = &prepared.request;
            assert!(processor.validate_and_reserve(request).unwrap().is_none());
            let answer = runtime.block_on(
                processor.expire_unaccepted_native_lease(&request.client_request_id, request),
            );
            if lies {
                assert_eq!(answer.unwrap()["status"], "expired_unaccepted");
                assert!(processor
                    .store
                    .lookup_by_nullifier(&request.public_inputs.request_nullifier)
                    .is_some());
            } else {
                assert!(answer.is_err());
            }
        }
    }

    #[test]
    fn worst_case_response_completes_in_browser_wallet() {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.config.request_charge_cap = 400_000;
        let note = crate::test_support::processor_note(&processor, oa_seeds(), 2_000_000);
        let now = current_timestamp();
        let payload = crate::test_support::lease_payload(&processor.config, now);
        let prepared = note.prepare_request("worst-case-wallet", payload, now, 400_000);
        let request = prepared.request.clone();
        assert!(processor.validate_and_reserve(&request).unwrap().is_none());
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request: &request,
                key_source: "oa_org",
                issued_at: now - 400,
                expires_at: now - 100,
                settle_after: now - 100,
                spending_limit_usd: 0.4,
                oa_client_request_id: Some(
                    &RequestProcessor::native_oa_request_id(&request).unwrap(),
                ),
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(now - 1),
                delivered: Some(true),
            })
            .unwrap();
        processor
            .store
            .activate_openrouter_lease(&request.client_request_id, "wallet-hash")
            .unwrap();
        runtime.block_on(processor.settle_due_openrouter_leases());
        let response = processor
            .recover_now(&request.client_request_id)
            .unwrap()
            .request_response
            .unwrap();
        assert_eq!(response.charge_applied, 400_000);
        let payload: serde_json::Value = serde_json::from_str(&response.response_payload).unwrap();
        assert_eq!(payload["charge_basis"], "worst_case");
        assert_eq!(payload["billing_quote"], frozen_quote(&request));
        let next =
            crate::test_support::complete_response(&note.deployment, &prepared, &response).unwrap();
        assert_eq!(next.balance, 2_000_000 - 400_000);
    }

    // ---- Zero settlement vs. key delivery (review: unsettleable lease) ------

    /// The fixture's lease row as production issuance creates it for a new
    /// request: delivered = false, with its TTL and write-once deadline.
    fn production_issuance_row(processor: &RequestProcessor, request: &ApiRequestV2, oa: bool) {
        processor
            .store
            .remove_failed_openrouter_lease(&request.client_request_id)
            .unwrap();
        let oa_id = oa.then(|| RequestProcessor::native_oa_request_id(request).unwrap());
        let lease_config = processor.config.openrouter_leases.clone().unwrap();
        processor
            .create_issuance_lease(request, &lease_config, 3.0, oa_id.as_deref())
            .unwrap();
    }

    /// A chain RPC reporting every request nullifier unspent; its
    /// `park_at`-th usedNullifiers read waits for a permit of the returned
    /// semaphore. Issuance's post-activation read is the second.
    async fn parked_spend_rpc(
        processor: &mut RequestProcessor,
        park_at: usize,
    ) -> (
        Arc<tokio::sync::Notify>,
        Arc<tokio::sync::Semaphore>,
        tokio::task::JoinHandle<()>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let reads = Arc::new(AtomicUsize::new(0));
        let parked = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let (notify, permits) = (parked.clone(), release.clone());
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let (reads, notify, permits) = (reads.clone(), notify.clone(), permits.clone());
                async move {
                    let chain_id = body["method"] == "eth_chainId";
                    if !chain_id && reads.fetch_add(1, Ordering::SeqCst) + 1 == park_at {
                        notify.notify_one();
                        permits.acquire().await.unwrap().forget();
                    }
                    let result = if chain_id {
                        "0x1".to_string()
                    } else {
                        format!("0x{:064x}", 0)
                    };
                    axum::Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (parked, release, server)
    }

    /// A chain RPC answering every read after `latency`: request nullifiers
    /// are unspent, and the oracle's finalized round is `round`, at $1000,
    /// updated at `updated_at`.
    async fn slow_chain_rpc(
        processor: &mut RequestProcessor,
        latency: Duration,
        updated_at: u64,
        round: Arc<std::sync::atomic::AtomicU64>,
    ) -> tokio::task::JoinHandle<()> {
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let round = round.clone();
                async move {
                    tokio::time::sleep(latency).await;
                    let data = body["params"][0]["data"].as_str().unwrap_or_default();
                    let result = if body["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else if data.starts_with("0x9a6fc8f5") || data == "0xfeaf968c" {
                        let round = if data == "0xfeaf968c" {
                            round.load(std::sync::atomic::Ordering::SeqCst)
                        } else {
                            u64::from_str_radix(&data[10..], 16).unwrap()
                        };
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            round, 100_000_000_000u64, updated_at, updated_at, round
                        )
                    } else {
                        // usedNullifiers(request_nullifier): false.
                        format!("0x{:064x}", 0)
                    };
                    axum::Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() })
    }

    fn spawn_issuance(
        processor: &Arc<RequestProcessor>,
        request: &ApiRequestV2,
    ) -> tokio::task::JoinHandle<Result<IssuedOpenRouterLease, ServerError>> {
        let (processor, request) = (processor.clone(), request.clone());
        tokio::spawn(async move { processor.issue_openrouter_lease(&request).await })
    }

    fn spawn_retirement(
        processor: &Arc<RequestProcessor>,
        request: &ApiRequestV2,
    ) -> tokio::task::JoinHandle<Result<OpenRouterLeaseStatusResponse, ServerError>> {
        let (processor, request) = (processor.clone(), request.clone());
        tokio::spawn(async move {
            processor
                .retire_openrouter_lease(&request.client_request_id, &request)
                .await
        })
    }

    /// The review's invariant: a key returned to the client never belongs to
    /// a lease committed to, or finalized at, zero as never delivered.
    fn assert_returned_key_settles_from_usage(
        processor: &RequestProcessor,
        request: &ApiRequestV2,
        issued: &Result<IssuedOpenRouterLease, ServerError>,
        context: &str,
    ) {
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        let record = record_of(processor, request);
        let zero_unissued = lease.charge_basis.as_deref() == Some("unissued")
            || (record.status == NullifierStatus::Finalized
                && payload_of(&record)["charge_basis"] == "unissued");
        match issued {
            Ok(_) => {
                assert!(
                    !zero_unissued,
                    "{context}: a returned key settled at zero: {lease:?}"
                );
                assert_eq!(lease.delivered, Some(true), "{context}");
            }
            Err(_) => assert_ne!(lease.delivered, Some(true), "{context}"),
        }
    }

    /// Review regression (unsettleable lease #1), deterministic: the client
    /// retires its own lease while issuance waits in the post-activation
    /// chain read. The retirement waits for that issuance, which returns the
    /// key, then settles the delivered lease from usage, never at zero.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn retirement_waits_for_in_flight_issuance_of_its_key() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
            let (mut processor, request, server) = issuance_processor(oa, state).await;
            production_issuance_row(&processor, &request, oa);
            let (parked, release, rpc) = parked_spend_rpc(&mut processor, 2).await;
            let processor = Arc::new(processor);
            let issuance = spawn_issuance(&processor, &request);
            parked.notified().await;
            let lease = processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap();
            assert_eq!(
                (lease.status.as_str(), lease.delivered),
                ("active", Some(false))
            );
            let retirement = spawn_retirement(&processor, &request);
            // Nothing settles the key while issuance may still return it.
            tokio::time::sleep(Duration::from_millis(300)).await;
            assert!(
                !retirement.is_finished(),
                "oa={oa}: retirement did not wait for issuance"
            );
            assert_eq!(
                record_of(&processor, &request).status,
                NullifierStatus::Reserved
            );
            release.add_permits(1);
            let issued = issuance.await.unwrap();
            assert_eq!(
                issued
                    .as_ref()
                    .map(|issued| issued.lease.api_key.as_str())
                    .ok(),
                Some("runtime-key"),
                "oa={oa}"
            );
            // It then settles the delivered key from usage, which this
            // provider mock never reports.
            assert!(retirement.await.unwrap().is_err());
            assert_returned_key_settles_from_usage(
                &processor,
                &request,
                &issued,
                &format!("oa={oa}"),
            );
            assert_eq!(
                record_of(&processor, &request).status,
                NullifierStatus::Reserved
            );
            rpc.abort();
            server.abort();
        }
    }

    /// Review regression (unsettleable lease #1), stress: on a multi-threaded
    /// runtime the client retires its lease while issuance is in flight,
    /// parked in its last chain read and released at varying moments, and,
    /// unparked on a file-backed database, at a moment an attacker would pick
    /// from the public lease status. A key returned to the client is never
    /// settled at zero as never delivered.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn retirement_racing_key_delivery_never_frees_a_returned_key() {
        let iterations: u64 = std::env::var("ZKAPI_RACE_ITERATIONS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(24);
        let mut seed = current_timestamp_ms();
        let mut returned = 0;
        for iteration in 0..iterations {
            for oa in [false, true] {
                let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
                let (mut processor, request, server) = issuance_processor(oa, state).await;
                production_issuance_row(&processor, &request, oa);
                let (parked, release, rpc) = parked_spend_rpc(&mut processor, 2).await;
                let processor = Arc::new(processor);
                let issuance = spawn_issuance(&processor, &request);
                parked.notified().await;
                let retirement = spawn_retirement(&processor, &request);
                let delay = Duration::from_micros((iteration % 6) * 250);
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                release.add_permits(1);
                let issued = issuance.await.unwrap();
                let _ = retirement.await.unwrap();
                let context = format!("parked oa={oa} iteration={iteration}");
                assert_returned_key_settles_from_usage(&processor, &request, &issued, &context);
                returned += u64::from(issued.is_ok());
                rpc.abort();
                server.abort();

                let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
                let (mut processor, request, server) = issuance_processor(oa, state).await;
                let directory = tempfile::tempdir().unwrap();
                let store =
                    Arc::new(NullifierStore::new(directory.path().join("server.db")).unwrap());
                store.reserve_openrouter_lease(&request).unwrap();
                processor.store = store;
                production_issuance_row(&processor, &request, oa);
                let round = Arc::new(std::sync::atomic::AtomicU64::new(123));
                let rpc = slow_chain_rpc(&mut processor, Duration::from_millis(5), 0, round).await;
                let processor = Arc::new(processor);
                let issuance = spawn_issuance(&processor, &request);
                while !issuance.is_finished()
                    && processor
                        .openrouter_lease_status(&request.client_request_id)
                        .unwrap()
                        .is_none_or(|status| status.status != "active")
                {
                    tokio::time::sleep(Duration::from_micros(100)).await;
                }
                // A random moment of the 10 ms post-activation read.
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                std::thread::sleep(Duration::from_micros((seed >> 33) % 10_000));
                let retirement = spawn_retirement(&processor, &request);
                let issued = issuance.await.unwrap();
                let _ = retirement.await.unwrap();
                let context = format!("timed oa={oa} iteration={iteration}");
                assert_returned_key_settles_from_usage(&processor, &request, &issued, &context);
                returned += u64::from(issued.is_ok());
                rpc.abort();
                server.abort();
            }
        }
        // Retirement never cancels an issuance in flight.
        assert_eq!(returned, iterations * 4);
    }

    /// Review regression (unsettleable lease #1), sweep: an activated lease
    /// whose key was not returned settles at zero only under the issuance
    /// lock. While an issuance holds it, and may still return the key, the
    /// sweep defers the lease; once the lock is free it settles it at zero.
    #[tokio::test]
    async fn sweep_defers_undelivered_activation_while_issuance_holds_the_lock() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        let request = lease_request_for(&processor, "undelivered-due", 610, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now + 3_600),
                key_hash: Some("undelivered-hash"),
                delivered: Some(false),
                ttl: Some(300),
            },
        );
        let issue_guard = processor.lease_issue_lock.lock().await;
        processor.settle_due_openrouter_leases().await;
        let lease = processor
            .store
            .lookup_openrouter_lease(&request.client_request_id)
            .unwrap();
        assert_eq!(
            (lease.status.as_str(), lease.charge_basis),
            ("active", None)
        );
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Reserved
        );
        drop(issue_guard);
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &request);
        assert_eq!(record.charge_applied, Some(0));
        assert_eq!(payload_of(&record)["reason"], "key_never_delivered");
    }

    /// Defense in depth: a lease fenced for a zero settlement while issuance
    /// waited in its last chain read never returns its key. A direct key is
    /// queued for deletion at once; the OA org offers no revocation.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fenced_lease_never_returns_its_key() {
        for oa in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
            let (mut processor, request, server) = issuance_processor(oa, state.clone()).await;
            production_issuance_row(&processor, &request, oa);
            let (parked, release, rpc) = parked_spend_rpc(&mut processor, 2).await;
            let processor = Arc::new(processor);
            let issuance = spawn_issuance(&processor, &request);
            parked.notified().await;
            assert!(processor
                .store
                .fence_unissued_settlement(&request.client_request_id)
                .unwrap());
            release.add_permits(1);
            let issued = issuance.await.unwrap();
            assert!(issued.is_err(), "oa={oa}: a fenced lease returned its key");
            assert_returned_key_settles_from_usage(
                &processor,
                &request,
                &issued,
                &format!("oa={oa}"),
            );
            assert_eq!(
                processor.settlement_counts().unwrap().pending_key_cleanups,
                u64::from(!oa)
            );
            processor.settle_due_openrouter_leases().await;
            let record = record_of(&processor, &request);
            assert_eq!(record.charge_applied, Some(0));
            let payload = payload_of(&record);
            assert_eq!(payload["charge_basis"], "unissued");
            assert_eq!(payload["reason"], "key_never_delivered");
            let cleanup = state.lock().unwrap().cleanup.clone();
            if oa {
                assert!(cleanup.is_empty());
            } else {
                assert_eq!(cleanup, ["disable:test-hash", "delete:test-hash"]);
            }
            rpc.abort();
            server.abort();
        }
    }

    /// A direct provisioning row, never delivered, past its write-once
    /// deadline, replacing the fixture's row.
    fn overdue_provisioning_row(processor: &RequestProcessor, request: &ApiRequestV2, now: u64) {
        processor
            .store
            .remove_failed_openrouter_lease(&request.client_request_id)
            .unwrap();
        processor
            .store
            .create_openrouter_lease_bound(&NewOpenRouterLease {
                request,
                key_source: "openrouter",
                issued_at: now - 100_000,
                expires_at: now - 99_700,
                settle_after: now - 99_700,
                spending_limit_usd: 3.0,
                oa_client_request_id: None,
                ttl_seconds: Some(300),
                settlement_deadline_at: Some(now - 50_000),
                delivered: Some(false),
            })
            .unwrap();
    }

    /// Review regression (unsettleable lease #2): a closed-loop flood of
    /// proof-less /expire calls, each of which used to hold the issuance lock
    /// across five oracle reads, cannot keep never-delivered leases past
    /// their deadline from finalizing at zero.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn expire_flood_cannot_postpone_overdue_zero_settlements() {
        use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, direct, server) = issuance_processor(false, state).await;
        let now = current_timestamp();
        overdue_provisioning_row(&processor, &direct, now);
        let oa = lease_request_for(&processor, "oa-overdue", 601, None);
        add_lease(
            &processor,
            &oa,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 29_700,
                deadline: Some(now - 8_000),
                key_hash: None,
                delivered: Some(false),
                ttl: Some(300),
            },
        );
        let round = Arc::new(AtomicU64::new(123));
        let rpc = slow_chain_rpc(&mut processor, Duration::from_millis(15), now - 5, round).await;
        let processor = Arc::new(processor);
        let stop = Arc::new(AtomicBool::new(false));
        let sent = Arc::new(AtomicUsize::new(0));
        let attackers: Vec<_> = (0..4u64)
            .map(|worker| {
                let (processor, template) = (processor.clone(), direct.clone());
                let (stop, sent) = (stop.clone(), sent.clone());
                tokio::spawn(async move {
                    let mut n = worker * 1_000_000;
                    while !stop.load(Ordering::SeqCst) {
                        // A random ID and nullifier with a current quote and
                        // no proof: all /expire needs.
                        n += 1;
                        let mut request = template.clone();
                        request.client_request_id = format!("attacker-{n}");
                        request.public_inputs.request_nullifier = Felt252::from_u64(9_000_000 + n);
                        request.payload =
                            crate::test_support::lease_payload(&processor.config, now - 5);
                        request.payload_hash = canonical_payload_hash(request.payload.as_bytes());
                        let _ = processor
                            .expire_unaccepted_native_lease(&request.client_request_id, &request)
                            .await;
                        sent.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        while sent.load(Ordering::SeqCst) < 8 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let finalized = |request: &ApiRequestV2| {
            record_of(&processor, request).status == NullifierStatus::Finalized
        };
        let mut ticks = 0;
        while ticks < 10 && !(finalized(&direct) && finalized(&oa)) {
            processor.settle_due_openrouter_leases().await;
            ticks += 1;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let settled_under_flood = finalized(&direct) && finalized(&oa);
        stop.store(true, Ordering::SeqCst);
        for attacker in attackers {
            attacker.await.unwrap();
        }
        assert!(
            settled_under_flood,
            "the flood kept overdue leases reserved through {ticks} sweep ticks"
        );
        for request in [&direct, &oa] {
            let record = record_of(&processor, request);
            assert_eq!(record.charge_applied, Some(0));
            assert_eq!(payload_of(&record)["charge_basis"], "unissued");
        }
        rpc.abort();
        server.abort();
    }

    /// Review regression (unsettleable lease #2): past its deadline, a
    /// never-delivered lease waits for a busy issuance lock, bounded, instead
    /// of skipping it every tick; a lock held past the bound still lets the
    /// tick finish its other work.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn overdue_zero_settlement_waits_a_bounded_time_for_the_issuance_lock() {
        let state = Arc::new(std::sync::Mutex::new(IssuanceMock::default()));
        let (mut processor, request, server) = issuance_processor(false, state).await;
        let now = current_timestamp();
        overdue_provisioning_row(&processor, &request, now);
        // A possibly delivered lease past its deadline needs no issuance lock.
        let delivered = lease_request_for(&processor, "delivered-overdue", 602, None);
        add_lease(
            &processor,
            &delivered,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("delivered-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.timing.issue_lock_timeout = Duration::from_millis(200);
        let processor = Arc::new(processor);
        let hold = |duration: Duration| {
            let (processor, acquired) = (processor.clone(), Arc::new(tokio::sync::Notify::new()));
            let notify = acquired.clone();
            let holder = tokio::spawn(async move {
                let _issue_guard = processor.lease_issue_lock.lock().await;
                notify.notify_one();
                tokio::time::sleep(duration).await;
            });
            (acquired, holder)
        };
        // Held past the bound: the tick finishes its other work and retries
        // the lease next tick.
        let (acquired, holder) = hold(Duration::from_secs(5));
        acquired.notified().await;
        let started = Instant::now();
        processor.settle_due_openrouter_leases().await;
        assert!(started.elapsed() < Duration::from_secs(2));
        let lease_status = |request: &ApiRequestV2| {
            processor
                .store
                .lookup_openrouter_lease(&request.client_request_id)
                .unwrap()
                .status
        };
        assert_eq!(lease_status(&request), "provisioning");
        assert_eq!(lease_status(&delivered), "finalized");
        assert_eq!(
            record_of(&processor, &delivered).charge_applied,
            Some(delivered.public_inputs.solvency_bound)
        );
        holder.abort();
        let _ = holder.await;
        // Released within the bound: the same tick finalizes it at zero.
        let (acquired, holder) = hold(Duration::from_millis(50));
        acquired.notified().await;
        processor.settle_due_openrouter_leases().await;
        holder.await.unwrap();
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(0));
        server.abort();
    }

    /// Review regression (unsettleable lease #2): /expire holds the issuance
    /// lock only to check that nothing reserved the request, never across its
    /// oracle reads, and checks again before acknowledging: a request reserved
    /// meanwhile is never acknowledged as unaccepted.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expire_releases_the_issuance_lock_during_oracle_reads() {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let updated_at = current_timestamp() - 5;
        let latest = Arc::new(std::sync::atomic::AtomicU64::new(123));
        let parked = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        let app = {
            let (latest, notify, permits) = (latest.clone(), parked.clone(), release.clone());
            let parked_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
            axum::Router::new().route(
                "/",
                axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                    let (latest, notify, permits, parked_once) = (
                        latest.clone(),
                        notify.clone(),
                        permits.clone(),
                        parked_once.clone(),
                    );
                    async move {
                        let data = body["params"][0]["data"].as_str().unwrap_or_default();
                        let result = if body["method"] == "eth_chainId" {
                            "0x1".to_string()
                        } else if data == "0x313ce567" {
                            format!("0x{:064x}", 8)
                        } else if data == "0x4d1352fd" {
                            format!("0x{:064x}", 1_000_000_000)
                        } else {
                            let round = if data == "0xfeaf968c" {
                                latest.load(std::sync::atomic::Ordering::SeqCst)
                            } else {
                                // The first read of the quoted round waits.
                                if !parked_once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                                    notify.notify_one();
                                    permits.acquire().await.unwrap().forget();
                                }
                                123
                            };
                            format!(
                                "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                                round, 100_000_000_000u64, updated_at, updated_at, round
                            )
                        };
                        axum::Json(serde_json::json!({"jsonrpc":"2.0","id":1,"result":result}))
                    }
                }),
            )
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            &mut processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let rpc = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let payload = crate::test_support::lease_payload(&processor.config, updated_at);
        let reserved =
            lease_request_for(&processor, "reserved-meanwhile", 606, Some(payload.clone()));
        let unaccepted = lease_request_for(&processor, "superseded", 607, Some(payload));
        let processor = Arc::new(processor);
        let expiry = {
            let (processor, request) = (processor.clone(), reserved.clone());
            tokio::spawn(async move {
                processor
                    .expire_unaccepted_native_lease(&request.client_request_id, &request)
                    .await
            })
        };
        parked.notified().await;
        // The oracle read runs without the issuance lock...
        drop(
            processor
                .lease_issue_lock
                .try_lock()
                .expect("/expire held the issuance lock across its oracle reads"),
        );
        // ...while an issuance reserves the request, and a newer round
        // finalizes.
        processor.store.reserve_openrouter_lease(&reserved).unwrap();
        latest.store(124, std::sync::atomic::Ordering::SeqCst);
        release.add_permits(1);
        assert!(matches!(
            expiry.await.unwrap(),
            Err(ServerError::LeasePending)
        ));
        // An unreserved request is acknowledged as superseded.
        let ack = processor
            .expire_unaccepted_native_lease(&unaccepted.client_request_id, &unaccepted)
            .await
            .unwrap();
        assert_eq!(ack["status"], "superseded_unaccepted");
        rpc.abort();
    }

    // ---- Reopening a cancelled lease (review: binding_corrupt remediation) --

    /// Review regression (cancelled-lease remediation): the offline reopen
    /// command and a serving processor exclude each other through the
    /// database writer lock, and the command never creates a database.
    #[test]
    fn reopen_command_and_server_exclude_each_other() {
        use crate::nullifier_store::OfflineStore;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        let error = OfflineStore::open(&path).err().unwrap();
        assert!(error.to_string().contains("writer lock"), "{error}");
        let (config, signer) = (processor.config.clone(), processor.signer.clone());
        drop(processor);
        let offline = OfflineStore::open(&path).unwrap();
        let store = || Arc::new(NullifierStore::new(&path).unwrap());
        assert!(
            RequestProcessor::try_new(config.clone(), store(), signer.clone(), Felt252::ZERO)
                .is_err()
        );
        drop(offline);
        assert!(RequestProcessor::try_new(config, store(), signer, Felt252::ZERO).is_ok());
        let missing = directory.path().join("missing.db");
        assert!(OfflineStore::open(&missing).is_err());
        assert!(!missing.exists());
    }

    /// Review regression (cancelled-lease remediation): a lease cancelled for
    /// a corrupt binding is reopened once the operator repairs the binding;
    /// the next sweep checks the binding again and finalizes it with a
    /// signed successor that the browser wallet installs: from measured
    /// usage, at the solvency bound past its deadline, at zero when never
    /// delivered, and at zero when the operator concedes the charge.
    #[test]
    fn reopened_lease_settles_with_a_successor_the_wallet_installs() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (usage_url, usage_server, usage_calls) = runtime.block_on(oa_usage_server(1_234, 5));
        let serving = |path: &std::path::Path| {
            let mut processor = oa_lease_processor(Arc::new(NullifierStore::new(path).unwrap()));
            processor.config.request_charge_cap = 400_000;
            processor.oa_org = Some(Arc::new(
                OaOrgProvisioner::new(usage_url.clone(), "test-secret".into()).unwrap(),
            ));
            processor
        };
        // One real browser request, settled in a fresh database per case.
        let mut wallet_server = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        wallet_server.config.request_charge_cap = 400_000;
        let note = crate::test_support::processor_note(&wallet_server, oa_seeds(), 2_000_000);
        let now = current_timestamp();
        let prepared = note.prepare_request(
            "reopened-lease",
            crate::test_support::lease_payload(&wallet_server.config, now),
            now,
            400_000,
        );
        drop(wallet_server);
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let request = prepared.request.clone();
        let id = request.client_request_id.clone();
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let bound = request.public_inputs.solvency_bound;
        for (case, delivered, deadline, zero_charge, settles, charge, basis) in [
            (
                "measured",
                Some(true),
                now + 3_600,
                false,
                "measured_until_deadline",
                1_234,
                "measured",
            ),
            (
                "bound",
                Some(true),
                now - 1,
                false,
                "deadline_fallback",
                bound,
                "worst_case",
            ),
            (
                "never delivered",
                Some(false),
                now + 3_600,
                false,
                "zero_never_delivered",
                0,
                "unissued",
            ),
            (
                "conceded",
                Some(true),
                now + 3_600,
                true,
                "operator_conceded",
                0,
                "operator_conceded",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let set_payload_hash = |store: &NullifierStore, payload_hash: String| {
                store.execute_for_test(
                    "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
                    rusqlite::params![payload_hash, nullifier],
                );
            };
            let processor = serving(&path);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(deadline),
                    key_hash: Some("reopen-hash"),
                    delivered,
                    ttl: Some(300),
                },
            );
            // A database fault: the reservation's payload hash changes.
            set_payload_hash(&processor.store, "0x1".into());
            runtime.block_on(processor.settle_due_openrouter_leases());
            let status = processor.openrouter_lease_status(&id).unwrap().unwrap();
            assert_eq!(status.status, "cancelled", "{case}");
            assert_eq!(
                record_of(&processor, &request).status,
                NullifierStatus::Reserved
            );
            let cancelled = review_of(&processor, &request).unwrap();
            assert_eq!(cancelled.reason, "binding_corrupt");
            assert!(
                cancelled.detail.contains("nullifiers.payload_hash"),
                "{}",
                cancelled.detail
            );
            // The operator stops the server and reopens the lease, which is
            // refused until the binding is repaired.
            drop(processor);
            {
                let offline = OfflineStore::open(&path).unwrap();
                let options = ReopenOptions {
                    zero_charge,
                    rebind: false,
                    saved_request: None,
                };
                match offline.reopen_cancelled_lease(&id, options, &verifier) {
                    Err(ReopenRefusal::BindingCorrupt(mismatch)) => {
                        assert_eq!(mismatch.field, "nullifiers.payload_hash")
                    }
                    other => panic!("{case}: expected a binding refusal, got {other:?}"),
                }
                set_payload_hash(
                    &NullifierStore::new(&path).unwrap(),
                    request.payload_hash.to_hex(),
                );
                let reopened = offline
                    .reopen_cancelled_lease(&id, options, &verifier)
                    .unwrap();
                assert_eq!(
                    (reopened.status.as_str(), reopened.settles),
                    ("active", settles),
                    "{case}"
                );
                assert_eq!(reopened.settlement_deadline_at, Some(deadline));
            }
            // The restarted server finalizes it on its next sweep.
            let calls = *usage_calls.lock().unwrap();
            let processor = serving(&path);
            runtime.block_on(processor.settle_due_openrouter_leases());
            let status = processor.openrouter_lease_status(&id).unwrap().unwrap();
            assert_eq!(
                (status.status.as_str(), status.charge_basis.as_deref()),
                ("finalized", Some(basis)),
                "{case}"
            );
            assert_eq!(
                *usage_calls.lock().unwrap() - calls,
                usize::from(case == "measured"),
                "{case}"
            );
            let response = processor
                .recover_now(&id)
                .unwrap()
                .request_response
                .unwrap();
            assert_eq!(response.charge_applied, charge, "{case}");
            let payload: serde_json::Value =
                serde_json::from_str(&response.response_payload).unwrap();
            assert_eq!(payload["charge_basis"], basis);
            assert_eq!(payload["billing_quote"], frozen_quote(&request));
            let next =
                crate::test_support::complete_response(&note.deployment, &prepared, &response)
                    .unwrap();
            assert_eq!(next.balance, 2_000_000 - charge, "{case}");
            // The cancellation's review was handled; the reopening is open.
            let reviews = processor.store.settlement_reviews(10).unwrap();
            assert!(reviews
                .iter()
                .any(|stored| stored.review.reason == "binding_corrupt"
                    && stored.acknowledged_at.is_some()));
            assert!(reviews
                .iter()
                .any(|stored| stored.review.reason == "binding_reopened"
                    && stored.acknowledged_at.is_none()));
        }
        usage_server.abort();
    }

    /// Review regression (cancelled-lease remediation): the server checks a
    /// reopened lease's binding, deployment and signing key again before it
    /// signs anything. A binding corrupt again is cancelled again with a new
    /// review; a lease of another signing key is never signed by this one.
    #[tokio::test]
    async fn reopened_lease_is_checked_again_before_anything_is_signed() {
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor = oa_lease_processor(store.clone());
        let now = current_timestamp();
        let set_reservation = |request: &ApiRequestV2, column: &str, value: String| {
            store.execute_for_test(
                &format!("UPDATE nullifiers SET {column} = ?1 WHERE nullifier = ?2"),
                rusqlite::params![value, request.public_inputs.request_nullifier.to_hex()],
            );
        };
        let reviews_of = |request: &ApiRequestV2| {
            store
                .settlement_reviews(100)
                .unwrap()
                .into_iter()
                .filter(|stored| stored.review.client_request_id == request.client_request_id)
                .collect::<Vec<_>>()
        };
        let setup = |id: &str, nullifier: u64| {
            let request = lease_request_for(&processor, id, nullifier, None);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(now + 3_600),
                    key_hash: Some(id),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            request
        };
        // Cancelled, repaired and reopened with a concession, then corrupt
        // again before the sweep: cancelled again, never signed.
        let again = setup("corrupt-again", 604);
        set_reservation(&again, "payload_hash", "0x1".into());
        processor.settle_due_openrouter_leases().await;
        set_reservation(&again, "payload_hash", again.payload_hash.to_hex());
        reopen_unverified(&store, &again.client_request_id, conceded(), now).unwrap();
        set_reservation(&again, "api_request_binding", "stale".into());
        processor.settle_due_openrouter_leases().await;
        let lease = store
            .lookup_openrouter_lease(&again.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "cancelled");
        let record = record_of(&processor, &again);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(record.next_state_sig.is_none());
        let reviews = reviews_of(&again);
        assert_eq!(reviews.len(), 3);
        let open: Vec<_> = reviews
            .iter()
            .filter(|stored| stored.acknowledged_at.is_none())
            .map(|stored| stored.review.reason.as_str())
            .collect();
        assert_eq!(open.len(), 2);
        assert!(open.contains(&"binding_reopened") && open.contains(&"binding_corrupt"));
        assert!(reviews.iter().any(|stored| stored.acknowledged_at.is_none()
            && stored
                .review
                .detail
                .contains("nullifiers.api_request_binding")));

        // Reopened with a concession, under another state signing key: that
        // server refuses to sign; this deployment's server verifies the
        // genuine request and signs the zero.
        let foreign = browser_lease_request("other-key").1.request;
        add_lease(
            &processor,
            &foreign,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now + 3_600),
                key_hash: Some("other-key"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let lease = store
            .lookup_openrouter_lease(&foreign.client_request_id)
            .unwrap();
        let review = RequestProcessor::review(
            &lease,
            "binding_corrupt",
            None,
            "simulated corruption, since repaired".into(),
            None,
            None,
        );
        store
            .cancel_openrouter_lease(&foreign.client_request_id, &review)
            .unwrap();
        reopen_unverified(&store, &foreign.client_request_id, conceded(), now).unwrap();
        let other_key = RequestProcessor::try_new(
            processor.config.clone(),
            store.clone(),
            Arc::new(ServerSigner::new(
                &Felt252::from_u64(13),
                &Felt252::from_u64(14),
            )),
            Felt252::ZERO,
        )
        .unwrap();
        other_key.settle_due_openrouter_leases().await;
        let lease = store
            .lookup_openrouter_lease(&foreign.client_request_id)
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.charge_basis.as_deref(), Some("operator_conceded"));
        assert!(lease.last_error.unwrap().contains("refusing to sign"));
        assert_eq!(
            record_of(&processor, &foreign).status,
            NullifierStatus::Reserved
        );
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &foreign);
        assert_eq!(record.charge_applied, Some(0));
        let payload = payload_of(&record);
        assert_eq!(payload["charge_basis"], "operator_conceded");
        assert_eq!(payload["type"], "oa_org_ephemeral_lease_settlement");
        assert_eq!(payload["billing_quote"], frozen_quote(&foreign));
    }

    /// A direct OpenRouter key mock with one key: PATCH disables it, GET
    /// reports $0.01 of usage (its first `failing_reads` GETs answer 503),
    /// DELETE deletes it; a deleted key answers 404. Records each call's
    /// method.
    #[derive(Default)]
    struct DirectKeyMock {
        disabled: bool,
        deleted: bool,
        failing_reads: usize,
        calls: Vec<String>,
    }

    async fn direct_key_server(
        state: Arc<std::sync::Mutex<DirectKeyMock>>,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use axum::{
            extract::{Path, State},
            http::{Method, StatusCode},
            routing::get,
            Json, Router,
        };
        use serde_json::{json, Value};
        type KeyState = Arc<std::sync::Mutex<DirectKeyMock>>;
        async fn key(
            State(state): State<KeyState>,
            method: Method,
            Path(_hash): Path<String>,
        ) -> (StatusCode, Json<Value>) {
            let mut key = state.lock().unwrap();
            key.calls.push(method.to_string());
            if key.deleted {
                return (StatusCode::NOT_FOUND, Json(json!({"error": "not found"})));
            }
            if method == Method::GET && key.failing_reads > 0 {
                key.failing_reads -= 1;
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({"error": "unavailable"})),
                );
            }
            if method == Method::PATCH {
                key.disabled = true;
            } else if method == Method::DELETE {
                key.deleted = true;
                return (StatusCode::OK, Json(json!({"deleted": true})));
            }
            (
                StatusCode::OK,
                Json(json!({"data": {"usage": 0.01, "byok_usage": 0.0, "disabled": key.disabled}})),
            )
        }
        let app = Router::new()
            .route("/v1/keys/{hash}", get(key).patch(key).delete(key))
            .with_state(state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, server)
    }

    /// Review regression (reopening a delivered direct lease): a corrupt
    /// binding found while settling a possibly delivered direct lease is
    /// cancelled only once the key's usage is captured, and the cancelled row
    /// keeps that usage while the key is deleted. Reopened, the lease resumes
    /// revoking, reports `captured_usage` and settles at that usage, not at
    /// its solvency bound, with a successor the wallet installs.
    #[test]
    fn corrupt_direct_lease_keeps_its_captured_usage_for_a_reopening() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let state = Arc::new(std::sync::Mutex::new(DirectKeyMock::default()));
        let (url, server) = runtime.block_on(direct_key_server(state.clone()));
        let serving = |path: &std::path::Path| {
            let mut processor = oa_lease_processor(Arc::new(NullifierStore::new(path).unwrap()));
            processor.config.openrouter_leases.as_mut().unwrap().source =
                OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "k".into(),
                    api_base: url.clone(),
                };
            processor.openrouter = Some(Arc::new(
                OpenRouterProvisioner::new("k".into(), url.clone()).unwrap(),
            ));
            processor.oa_org = None;
            processor
        };
        let (note, prepared) = browser_lease_request("direct-delivered");
        let request = prepared.request.clone();
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let set_payload_hash = |store: &NullifierStore, payload_hash: String| {
            store.execute_for_test(
                "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
                rusqlite::params![payload_hash, nullifier],
            );
        };
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let now = current_timestamp();
        let processor = serving(&path);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "openrouter",
                expires_at: now - 100,
                deadline: Some(now + 3_600),
                key_hash: Some("k1"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        // A database fault: the reservation's payload hash changes.
        set_payload_hash(&processor.store, "0x1".into());
        runtime.block_on(processor.settle_due_openrouter_leases());
        let lease = processor
            .store
            .lookup_openrouter_lease("direct-delivered")
            .unwrap();
        assert_eq!(lease.status, "cancelled");
        // Disabled and measured before the cancellation, which queued the
        // key's deletion; that ran in the same tick.
        assert_eq!(lease.usage_usd, Some(0.01));
        assert_eq!(
            state.lock().unwrap().calls,
            ["PATCH", "GET", "PATCH", "DELETE"]
        );
        assert!(state.lock().unwrap().deleted);
        assert_eq!(
            record_of(&processor, &request).status,
            NullifierStatus::Reserved
        );
        assert_eq!(
            review_of(&processor, &request).unwrap().reason,
            "binding_corrupt"
        );
        // The operator repairs the binding, stops the server and reopens.
        set_payload_hash(&processor.store, request.payload_hash.to_hex());
        drop(processor);
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let reopened = OfflineStore::open(&path)
            .unwrap()
            .reopen_cancelled_lease("direct-delivered", ReopenOptions::default(), &verifier)
            .unwrap();
        assert_eq!(
            (reopened.status.as_str(), reopened.settles, reopened.warning),
            ("revoking", "captured_usage", None)
        );
        assert!(!reopened.key_cleanup_withdrawn);
        // The restarted server settles at once at the captured usage: $0.01
        // is 10,000 units at the test quote, well below the solvency bound.
        let processor = serving(&path);
        runtime.block_on(processor.settle_due_openrouter_leases());
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(10_000));
        assert!(request.public_inputs.solvency_bound > 10_000);
        assert_eq!(payload_of(&record)["charge_basis"], "measured");
        // The deleted key was never read again: only the idempotent DELETE.
        assert_eq!(
            state.lock().unwrap().calls,
            ["PATCH", "GET", "PATCH", "DELETE", "DELETE"]
        );
        let response = processor
            .recover_now("direct-delivered")
            .unwrap()
            .request_response
            .unwrap();
        let next =
            crate::test_support::complete_response(&note.deployment, &prepared, &response).unwrap();
        assert_eq!(next.balance, 2_000_000 - 10_000);
        server.abort();
    }

    /// Review regression (reopening a delivered direct lease): a lease that
    /// was reopened and is not signed yet can still be conceded, for
    /// instance once the reopening warned that only its solvency bound can
    /// be charged. A signed one cannot.
    #[test]
    fn reopened_lease_can_be_conceded_until_it_is_signed() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (note, prepared) = browser_lease_request("concede-later");
        let request = prepared.request.clone();
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let now = current_timestamp();
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("concede-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.store.execute_for_test(
            "UPDATE nullifiers SET payload_hash = '0x1' WHERE nullifier = ?1",
            rusqlite::params![nullifier],
        );
        runtime.block_on(processor.settle_due_openrouter_leases());
        assert_eq!(
            processor
                .openrouter_lease_status("concede-later")
                .unwrap()
                .unwrap()
                .status,
            "cancelled"
        );
        processor.store.execute_for_test(
            "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
            rusqlite::params![request.payload_hash.to_hex(), nullifier],
        );
        drop(processor);
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let offline = OfflineStore::open(&path).unwrap();
        // Past its deadline, nothing can be measured: the reopening warns
        // that the full solvency bound would be charged...
        let reopened = offline
            .reopen_cancelled_lease("concede-later", ReopenOptions::default(), &verifier)
            .unwrap();
        assert_eq!(reopened.settles, "deadline_fallback");
        assert!(reopened.warning.unwrap().contains("--zero-charge"));
        // ...and the operator concedes the charge instead, before restarting.
        let concession = offline
            .reopen_cancelled_lease("concede-later", conceded(), &verifier)
            .unwrap();
        assert_eq!(
            (concession.status.as_str(), concession.settles),
            ("active", "operator_conceded")
        );
        assert!(matches!(
            offline.reopen_cancelled_lease("concede-later", ReopenOptions::default(), &verifier),
            Err(ReopenRefusal::NotCancelled(status)) if status == "active"
        ));
        drop(offline);
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        runtime.block_on(processor.settle_due_openrouter_leases());
        let record = record_of(&processor, &request);
        assert_eq!(record.charge_applied, Some(0));
        assert_eq!(payload_of(&record)["charge_basis"], "operator_conceded");
        let reopenings = processor
            .store
            .settlement_reviews(10)
            .unwrap()
            .into_iter()
            .filter(|stored| stored.review.reason == "binding_reopened")
            .count();
        assert_eq!(reopenings, 2);
        let response = processor
            .recover_now("concede-later")
            .unwrap()
            .request_response
            .unwrap();
        let next =
            crate::test_support::complete_response(&note.deployment, &prepared, &response).unwrap();
        assert_eq!(next.balance, 2_000_000);
        drop(processor);
        // Signed: nothing left to concede.
        assert!(matches!(
            OfflineStore::open(&path)
                .unwrap()
                .reopen_cancelled_lease("concede-later", conceded(), &verifier),
            Err(ReopenRefusal::NotCancelled(status)) if status == "finalized"
        ));
    }

    /// Review regression (reopen authenticity): a fault inside the saved
    /// request (here its solvency bound) shows up as a disagreement with the
    /// reservation's request binding. Recomputing that binding from the row,
    /// as the review's field name might suggest, does not get the lease
    /// reopened: the command verifies the saved request against its Groth16
    /// proof first and names the request as the corrupt side, also with
    /// --rebind or --zero-charge. Restored from a backup, the request
    /// verifies; the reservation, now the corrupt side, is rebound from it,
    /// and the server signs no more than the proven bound.
    #[test]
    fn reopen_refuses_a_saved_request_its_proof_does_not_authorize() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (note, prepared) = browser_lease_request("tampered");
        let request = prepared.request.clone();
        let proven_bound = request.public_inputs.solvency_bound;
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let now = current_timestamp();
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("tampered-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let mut tampered = request.clone();
        tampered.public_inputs.solvency_bound = proven_bound * 3;
        let set_request = |store: &NullifierStore, saved: &ApiRequestV2| {
            store.execute_for_test(
                "UPDATE openrouter_leases SET api_request_json = ?1
                 WHERE client_request_id = 'tampered'",
                rusqlite::params![serde_json::to_string(saved).unwrap()],
            );
        };
        set_request(&processor.store, &tampered);
        runtime.block_on(processor.settle_due_openrouter_leases());
        assert_eq!(
            processor
                .openrouter_lease_status("tampered")
                .unwrap()
                .unwrap()
                .status,
            "cancelled"
        );
        let detail = review_of(&processor, &request).unwrap().detail;
        assert!(
            detail.contains("nullifiers.api_request_binding"),
            "{detail}"
        );
        assert!(detail.contains("either side may be corrupt"), "{detail}");
        // The misled repair: the reservation's binding recomputed from the row.
        processor.store.execute_for_test(
            "UPDATE nullifiers SET api_request_binding = ?1 WHERE nullifier = ?2",
            rusqlite::params![api_request_binding(&tampered).unwrap(), nullifier],
        );
        drop(processor);
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        for options in [
            ReopenOptions::default(),
            ReopenOptions {
                zero_charge: false,
                rebind: true,
                saved_request: None,
            },
            conceded(),
        ] {
            let refusal = OfflineStore::open(&path)
                .unwrap()
                .reopen_cancelled_lease("tampered", options, &verifier)
                .unwrap_err();
            let message = refusal.to_string();
            match refusal {
                ReopenRefusal::BindingCorrupt(mismatch) => {
                    assert_eq!(mismatch.field, "openrouter_leases.api_request_json");
                    assert!(message.contains("Groth16"), "{message}");
                    assert!(message.contains("backup"), "{message}");
                }
                other => panic!("{options:?}: expected the request refused, got {other:?}"),
            }
        }
        // Nothing changed while it refused.
        let store = NullifierStore::new(&path).unwrap();
        assert_eq!(
            store.lookup_openrouter_lease("tampered").unwrap().status,
            "cancelled"
        );
        assert_eq!(store.settlement_reviews(10).unwrap().len(), 1);
        // The request restored from a backup verifies: the reservation, whose
        // binding the misled repair changed, is now the corrupt side.
        set_request(&store, &request);
        drop(store);
        let offline = OfflineStore::open(&path).unwrap();
        let refusal = offline
            .reopen_cancelled_lease("tampered", ReopenOptions::default(), &verifier)
            .unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                if mismatch.field == "nullifiers.api_request_binding"),
            "{refusal}"
        );
        assert!(refusal.to_string().contains("--rebind"), "{refusal}");
        let reopened = offline
            .reopen_cancelled_lease(
                "tampered",
                ReopenOptions {
                    zero_charge: false,
                    rebind: true,
                    saved_request: None,
                },
                &verifier,
            )
            .unwrap();
        assert_eq!(reopened.reservation, "rewritten");
        assert_eq!(reopened.settles, "deadline_fallback");
        drop(offline);
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        runtime.block_on(processor.settle_due_openrouter_leases());
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(record.charge_applied, Some(proven_bound));
        let signed: RequestPublicInputsV2 =
            serde_json::from_str(record.request_inputs_json.as_deref().unwrap()).unwrap();
        assert_eq!(signed.solvency_bound, proven_bound);
        let response = processor
            .recover_now("tampered")
            .unwrap()
            .request_response
            .unwrap();
        let next =
            crate::test_support::complete_response(&note.deployment, &prepared, &response).unwrap();
        assert_eq!(next.balance, 2_000_000 - proven_bound);
    }

    /// Review regression (reopen authenticity): the server verifies a
    /// reopened lease's saved request again before it signs anything. A
    /// request changed after a verified reopening, with its reservation
    /// binding recomputed to match, is cancelled again, never signed.
    #[test]
    fn server_verifies_a_reopened_lease_before_signing() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let request = browser_lease_request("edited-after-reopen").1.request;
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let now = current_timestamp();
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("edited-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let set_payload_hash = |store: &NullifierStore, payload_hash: String| {
            store.execute_for_test(
                "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
                rusqlite::params![payload_hash, nullifier],
            );
        };
        set_payload_hash(&processor.store, "0x1".into());
        runtime.block_on(processor.settle_due_openrouter_leases());
        set_payload_hash(&processor.store, request.payload_hash.to_hex());
        drop(processor);
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        OfflineStore::open(&path)
            .unwrap()
            .reopen_cancelled_lease("edited-after-reopen", ReopenOptions::default(), &verifier)
            .unwrap();
        // Edited after the reopening, consistently on both sides.
        let mut edited = request.clone();
        edited.public_inputs.solvency_bound *= 3;
        let store = NullifierStore::new(&path).unwrap();
        store.execute_for_test(
            "UPDATE openrouter_leases SET api_request_json = ?1
             WHERE client_request_id = 'edited-after-reopen'",
            rusqlite::params![serde_json::to_string(&edited).unwrap()],
        );
        store.execute_for_test(
            "UPDATE nullifiers SET api_request_binding = ?1 WHERE nullifier = ?2",
            rusqlite::params![api_request_binding(&edited).unwrap(), nullifier],
        );
        drop(store);
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        runtime.block_on(processor.settle_due_openrouter_leases());
        let lease = processor
            .store
            .lookup_openrouter_lease("edited-after-reopen")
            .unwrap();
        assert_eq!(lease.status, "cancelled");
        let record = record_of(&processor, &request);
        assert_eq!(record.status, NullifierStatus::Reserved);
        assert!(record.next_state_sig.is_none());
        let detail = processor
            .store
            .settlement_reviews(10)
            .unwrap()
            .into_iter()
            .find(|stored| {
                stored.review.reason == "binding_corrupt" && stored.acknowledged_at.is_none()
            })
            .unwrap()
            .review
            .detail;
        assert!(
            detail.contains("the reopened lease's saved request does not verify")
                && detail.contains("openrouter_leases.api_request_json"),
            "{detail}"
        );
    }

    /// Review regression (unrepairable reservations): a reservation whose
    /// request binding went stale, or whose row is missing, cannot be
    /// repaired with sqlite3 (the binding is a keccak digest of the saved
    /// request). Once the saved request verifies, --rebind rewrites the
    /// reservation from it or re-creates the missing row, and the reopened
    /// lease settles with a successor the wallet installs. A reservation row
    /// kept under another nullifier is mis-keyed, not missing: it is never
    /// duplicated.
    #[test]
    fn rebind_repairs_a_reservation_from_the_verified_request() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (note, prepared) = browser_lease_request("rebound");
        let request = prepared.request.clone();
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let rebind = |zero_charge| ReopenOptions {
            zero_charge,
            rebind: true,
            saved_request: None,
        };
        for (case, corrupt, field, zero_charge, reservation, charge) in [
            (
                "stale binding",
                "UPDATE nullifiers SET api_request_binding = 'stale' WHERE nullifier = ?1",
                "nullifiers.api_request_binding",
                false,
                "rewritten",
                request.public_inputs.solvency_bound,
            ),
            (
                "missing row",
                "DELETE FROM nullifiers WHERE nullifier = ?1",
                "nullifiers.nullifier",
                true,
                "recreated",
                0,
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let now = current_timestamp();
            let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(now - 1),
                    key_hash: Some("rebound-hash"),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            processor
                .store
                .execute_for_test(corrupt, rusqlite::params![nullifier]);
            runtime.block_on(processor.settle_due_openrouter_leases());
            assert_eq!(
                processor
                    .openrouter_lease_status("rebound")
                    .unwrap()
                    .unwrap()
                    .status,
                "cancelled",
                "{case}"
            );
            drop(processor);
            let offline = OfflineStore::open(&path).unwrap();
            // Neither a plain reopening nor a concession repairs it...
            for options in [ReopenOptions::default(), conceded()] {
                let refusal = offline
                    .reopen_cancelled_lease("rebound", options, &verifier)
                    .unwrap_err();
                assert!(
                    matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                        if mismatch.field == field),
                    "{case}: {refusal}"
                );
                assert!(
                    refusal.to_string().contains("--rebind"),
                    "{case}: {refusal}"
                );
            }
            // ...--rebind does, from the verified request.
            let reopened = offline
                .reopen_cancelled_lease("rebound", rebind(zero_charge), &verifier)
                .unwrap();
            assert_eq!(reopened.reservation, reservation, "{case}");
            drop(offline);
            let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
            let record = record_of(&processor, &request);
            assert_eq!(record.status, NullifierStatus::Reserved, "{case}");
            assert_eq!(
                record.api_request_binding,
                Some(api_request_binding(&request).unwrap())
            );
            let review = processor
                .store
                .settlement_reviews(10)
                .unwrap()
                .into_iter()
                .find(|stored| stored.review.reason == "binding_reopened")
                .unwrap()
                .review;
            assert!(review.detail.contains(reservation), "{}", review.detail);
            runtime.block_on(processor.settle_due_openrouter_leases());
            let record = record_of(&processor, &request);
            assert_eq!(record.status, NullifierStatus::Finalized, "{case}");
            assert_eq!(record.charge_applied, Some(charge), "{case}");
            let response = processor
                .recover_now("rebound")
                .unwrap()
                .request_response
                .unwrap();
            let next =
                crate::test_support::complete_response(&note.deployment, &prepared, &response)
                    .unwrap();
            assert_eq!(next.balance, 2_000_000 - charge, "{case}");
        }

        // Mis-keyed: the row's nullifier column changed. Not re-created.
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("server.db");
        let now = current_timestamp();
        let processor = oa_lease_processor(Arc::new(NullifierStore::new(&path).unwrap()));
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now - 100,
                deadline: Some(now - 1),
                key_hash: Some("rebound-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.store.execute_for_test(
            "UPDATE nullifiers SET nullifier = '0x5eed' WHERE nullifier = ?1",
            rusqlite::params![nullifier],
        );
        runtime.block_on(processor.settle_due_openrouter_leases());
        drop(processor);
        let refusal = OfflineStore::open(&path)
            .unwrap()
            .reopen_cancelled_lease("rebound", rebind(false), &verifier)
            .unwrap_err();
        assert!(
            matches!(&refusal, ReopenRefusal::ReservationElsewhere { nullifier, .. }
                if nullifier == "0x5eed"),
            "{refusal}"
        );
        let store = NullifierStore::new(&path).unwrap();
        assert!(store
            .lookup_by_nullifier(&request.public_inputs.request_nullifier)
            .is_none());
        assert_eq!(
            store.lookup_openrouter_lease("rebound").unwrap().status,
            "cancelled"
        );
    }

    /// A serving processor whose OA org relay is `usage_url`, as in the
    /// settlement tests that measure OA usage.
    fn oa_usage_processor(path: &std::path::Path, usage_url: &str) -> RequestProcessor {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::new(path).unwrap()));
        processor.config.request_charge_cap = 400_000;
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(usage_url.to_string(), "test-secret".into()).unwrap(),
        ));
        processor
    }

    /// Install the signed successor of `request` in its owner's wallet, and
    /// return the new balance.
    fn installed_balance(
        processor: &RequestProcessor,
        note: &crate::test_support::TestNote,
        prepared: &PreparedTestRequest,
    ) -> u128 {
        let response = processor
            .recover_now(&prepared.request.client_request_id)
            .unwrap()
            .request_response
            .unwrap();
        crate::test_support::complete_response(&note.deployment, prepared, &response)
            .unwrap()
            .balance
    }

    /// Two genuine requests that their owner authorized for the same note
    /// state, so with the same nullifier, differing only in request time.
    fn same_state_lease_requests(
        id: &str,
    ) -> (
        crate::test_support::TestNote,
        PreparedTestRequest,
        PreparedTestRequest,
    ) {
        let mut wallet_server = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        wallet_server.config.request_charge_cap = 400_000;
        let note = crate::test_support::processor_note(&wallet_server, oa_seeds(), 2_000_000);
        let now = current_timestamp();
        let prepare = |request_time: u64| {
            note.prepare_request(
                id,
                crate::test_support::lease_payload(&wallet_server.config, now),
                request_time,
                400_000,
            )
        };
        let first = prepare(now);
        let second = prepare(now + 1);
        (note, first, second)
    }

    /// Review regression (lease-row repair): a fault in the lease row's
    /// client_request_id, its primary key, is cancelled with its review under
    /// the faulted id. Setting the column by hand, as the command used to
    /// advise, left the review behind, so that every reopening was refused.
    /// The command now names --rebind, which rewrites the row from the
    /// verified request and moves its reviews with it; a row renamed by hand
    /// is still found by its nullifier. Either way the lease settles with a
    /// successor the wallet installs.
    #[test]
    fn rebind_rewrites_a_lease_row_whose_client_request_id_is_corrupt() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (usage_url, usage_server, _) = runtime.block_on(oa_usage_server(1_234, 5));
        let (note, prepared) = browser_lease_request("lease-a");
        let request = prepared.request.clone();
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let rebind = ReopenOptions {
            rebind: true,
            ..ReopenOptions::default()
        };
        for renamed_by_hand in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let now = current_timestamp();
            let processor = oa_usage_processor(&path, &usage_url);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(now + 3_600),
                    key_hash: Some("lease-a-hash"),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            // A database fault in the lease row's primary key.
            processor.store.execute_for_test(
                "UPDATE openrouter_leases SET client_request_id = 'lease-a-x'
                 WHERE client_request_id = 'lease-a'",
                [],
            );
            runtime.block_on(processor.settle_due_openrouter_leases());
            assert_eq!(
                processor
                    .store
                    .lookup_openrouter_lease("lease-a-x")
                    .unwrap()
                    .status,
                "cancelled"
            );
            let reviews = processor.store.settlement_reviews(10).unwrap();
            assert_eq!(reviews.len(), 1);
            assert_eq!(reviews[0].review.client_request_id, "lease-a-x");
            drop(processor);
            let offline = OfflineStore::open(&path).unwrap();
            let refusal = offline
                .reopen_cancelled_lease("lease-a-x", ReopenOptions::default(), &verifier)
                .unwrap_err();
            assert!(
                matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                    if mismatch.field == "openrouter_leases.client_request_id"),
                "{refusal}"
            );
            assert!(refusal.to_string().contains("--rebind"), "{refusal}");
            let reopened = if renamed_by_hand {
                NullifierStore::new(&path).unwrap().execute_for_test(
                    "UPDATE openrouter_leases SET client_request_id = 'lease-a'
                     WHERE client_request_id = 'lease-a-x'",
                    [],
                );
                offline
                    .reopen_cancelled_lease("lease-a", ReopenOptions::default(), &verifier)
                    .unwrap()
            } else {
                offline
                    .reopen_cancelled_lease("lease-a-x", rebind, &verifier)
                    .unwrap()
            };
            assert_eq!(reopened.client_request_id, "lease-a");
            assert_eq!(
                reopened.lease_row,
                if renamed_by_hand {
                    "unchanged"
                } else {
                    "rewritten"
                }
            );
            assert_eq!(reopened.settles, "measured_until_deadline");
            assert!(matches!(
                offline.reopen_cancelled_lease("lease-a-x", rebind, &verifier),
                Err(ReopenRefusal::UnknownLease(_))
            ));
            drop(offline);
            // The lease's reviews are all under its id, its cancellation's
            // acknowledged by the reopening.
            let processor = oa_usage_processor(&path, &usage_url);
            let reviews = processor.store.settlement_reviews(10).unwrap();
            assert_eq!(reviews.len(), 2);
            assert!(reviews
                .iter()
                .all(|stored| stored.review.client_request_id == "lease-a"));
            assert!(reviews
                .iter()
                .any(|stored| stored.review.reason == "binding_corrupt"
                    && stored.acknowledged_at.is_some()));
            runtime.block_on(processor.settle_due_openrouter_leases());
            let status = processor
                .openrouter_lease_status("lease-a")
                .unwrap()
                .unwrap();
            assert_eq!(
                (status.status.as_str(), status.charge_basis.as_deref()),
                ("finalized", Some("measured"))
            );
            assert_eq!(
                installed_balance(&processor, &note, &prepared),
                2_000_000 - 1_234
            );
        }
        usage_server.abort();
    }

    /// Review regression (corrupt saved request): a fault inside the saved
    /// request could only be repaired from a database backup, while its
    /// owner's copy of the request was refused everywhere. --saved-request
    /// restores it from a copy whose authenticity the database proves: the
    /// copy verifies, and its binding is the one its reservation recorded at
    /// admission. A tampered copy, another request its owner authorized for
    /// the same note state, and another lease's request are refused, changing
    /// nothing. Restored, also over an unreadable saved request, the lease
    /// settles with a successor the wallet installs.
    #[test]
    fn saved_request_restores_a_corrupt_request_from_an_authentic_copy() {
        use crate::nullifier_store::{
            OfflineStore, ReopenOptions, ReopenRefusal, GROTH16_UNVERIFIED, SAVED_REQUEST_FIELD,
        };
        fn supplying(saved_request: &ApiRequestV2) -> ReopenOptions<'_> {
            ReopenOptions {
                saved_request: Some(saved_request),
                ..ReopenOptions::default()
            }
        }
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (usage_url, usage_server, _) = runtime.block_on(oa_usage_server(1_234, 5));
        let (note, prepared, same_state) = same_state_lease_requests("bitrot");
        let request = prepared.request.clone();
        assert_eq!(
            same_state.request.public_inputs.request_nullifier,
            request.public_inputs.request_nullifier
        );
        let other_lease = browser_lease_request("other-lease").1.request;
        let mut faulted = request.clone();
        faulted.public_inputs.request_time += 1;
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        for unreadable in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let now = current_timestamp();
            let processor = oa_usage_processor(&path, &usage_url);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(now + 3_600),
                    key_hash: Some("bitrot-hash"),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            let set_saved = |store: &NullifierStore, saved: &str| {
                store.execute_for_test(
                    "UPDATE openrouter_leases SET api_request_json = ?1
                     WHERE client_request_id = 'bitrot'",
                    rusqlite::params![saved],
                );
            };
            // A fault inside the saved request: its request time changes.
            set_saved(&processor.store, &serde_json::to_string(&faulted).unwrap());
            runtime.block_on(processor.settle_due_openrouter_leases());
            assert_eq!(
                processor
                    .openrouter_lease_status("bitrot")
                    .unwrap()
                    .unwrap()
                    .status,
                "cancelled"
            );
            if unreadable {
                // Damaged further after its cancellation.
                set_saved(&processor.store, "{\"client_request_id\":\"bitr");
            }
            drop(processor);
            let offline = OfflineStore::open(&path).unwrap();
            let refusal = offline
                .reopen_cancelled_lease("bitrot", ReopenOptions::default(), &verifier)
                .unwrap_err();
            assert!(
                matches!(&refusal, ReopenRefusal::BindingCorrupt(mismatch)
                    if mismatch.field == SAVED_REQUEST_FIELD),
                "{refusal}"
            );
            assert!(refusal.to_string().contains("--saved-request"), "{refusal}");
            assert!(matches!(
                offline.reopen_cancelled_lease("bitrot", supplying(&faulted), &verifier),
                Err(ReopenRefusal::SuppliedRequestUnverified(detail)) if detail == GROTH16_UNVERIFIED
            ));
            assert!(matches!(
                offline.reopen_cancelled_lease("bitrot", supplying(&same_state.request), &verifier),
                Err(ReopenRefusal::SuppliedRequestNotReserved(_))
            ));
            assert!(matches!(
                offline.reopen_cancelled_lease("bitrot", supplying(&other_lease), &verifier),
                Err(ReopenRefusal::SuppliedRequestForAnotherLease)
            ));
            {
                let store = NullifierStore::new(&path).unwrap();
                assert_eq!(store.settlement_reviews(10).unwrap().len(), 1);
                assert_eq!(store.settlement_counts(now).unwrap().cancelled, 1);
            }
            let reopened = offline
                .reopen_cancelled_lease("bitrot", supplying(&request), &verifier)
                .unwrap();
            assert_eq!(
                (reopened.saved_request, reopened.settles),
                ("restored", "measured_until_deadline")
            );
            drop(offline);
            let processor = oa_usage_processor(&path, &usage_url);
            let restored = processor.store.lookup_openrouter_lease("bitrot").unwrap();
            assert_eq!(
                api_request_binding(&restored.api_request).unwrap(),
                api_request_binding(&request).unwrap()
            );
            runtime.block_on(processor.settle_due_openrouter_leases());
            let status = processor
                .openrouter_lease_status("bitrot")
                .unwrap()
                .unwrap();
            assert_eq!(
                (status.status.as_str(), status.charge_basis.as_deref()),
                ("finalized", Some("measured"))
            );
            assert_eq!(
                installed_balance(&processor, &note, &prepared),
                2_000_000 - 1_234
            );
        }
        usage_server.abort();
    }

    /// Final review, round 2: a pending (delivered, active) lease whose saved
    /// request cannot be decoded was skipped by every settlement tick, so its
    /// write-once deadline never applied and its nullifier stayed reserved,
    /// while `settlement reopen --saved-request` refused it as not
    /// cancelled: lease routes promised an operator repair that no tool made.
    /// The command now restores the request of such a pending lease, keeping
    /// its status, and the next tick settles it: from measured usage before
    /// its deadline, at its solvency bound once that has passed (the output
    /// warns), and the wallet installs the successor.
    #[test]
    fn saved_request_restores_a_pending_lease_the_sweep_could_not_read() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (usage_url, usage_server, usage_calls) = runtime.block_on(oa_usage_server(1_234, 5));
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        for past_deadline in [false, true] {
            let (note, prepared) = browser_lease_request("rotting");
            let request = prepared.request.clone();
            let bound = request.public_inputs.solvency_bound;
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let now = current_timestamp();
            let processor = oa_usage_processor(&path, &usage_url);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "oa_org",
                    expires_at: now - 100,
                    deadline: Some(if past_deadline { now - 1 } else { now + 3_600 }),
                    key_hash: Some("rotting-hash"),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            processor.store.execute_for_test(
                "UPDATE openrouter_leases SET api_request_json = '{\"client_request_id\":\"rot'
                 WHERE client_request_id = 'rotting'",
                [],
            );
            let calls_before = *usage_calls.lock().unwrap();
            for _ in 0..3 {
                runtime.block_on(processor.settle_due_openrouter_leases());
            }
            // Never settled, not even past its deadline: still active and
            // reserved, and its status unreadable.
            assert_eq!(*usage_calls.lock().unwrap(), calls_before);
            assert_eq!(
                processor.store.query_i64_for_test(
                    "SELECT status = 'active' FROM openrouter_leases
                     WHERE client_request_id = 'rotting'",
                    [],
                ),
                1
            );
            assert_eq!(
                record_of(&processor, &request).status,
                NullifierStatus::Reserved
            );
            assert!(matches!(
                processor.openrouter_lease_status("rotting"),
                Err(ServerError::LeaseRecordUnreadable)
            ));
            drop(processor);

            let offline = OfflineStore::open(&path).unwrap();
            assert!(matches!(
                offline.reopen_cancelled_lease("rotting", ReopenOptions::default(), &verifier),
                Err(ReopenRefusal::NotCancelled(status)) if status == "active"
            ));
            let restored = offline
                .reopen_cancelled_lease(
                    "rotting",
                    ReopenOptions {
                        saved_request: Some(&request),
                        ..ReopenOptions::default()
                    },
                    &verifier,
                )
                .unwrap();
            assert_eq!(
                (
                    restored.status.as_str(),
                    restored.saved_request,
                    restored.restored_pending
                ),
                ("active", "restored", true)
            );
            assert_eq!(
                (restored.settles, restored.warning.is_some()),
                if past_deadline {
                    ("deadline_fallback", true)
                } else {
                    ("measured_until_deadline", false)
                }
            );
            drop(offline);

            let processor = oa_usage_processor(&path, &usage_url);
            runtime.block_on(processor.settle_due_openrouter_leases());
            let status = processor
                .openrouter_lease_status("rotting")
                .unwrap()
                .unwrap();
            let charge = if past_deadline {
                assert_eq!(
                    (status.status.as_str(), status.charge_basis.as_deref()),
                    ("finalized", Some("worst_case"))
                );
                // Past its deadline: no provider I/O.
                assert_eq!(*usage_calls.lock().unwrap(), calls_before);
                bound
            } else {
                assert_eq!(
                    (status.status.as_str(), status.charge_basis.as_deref()),
                    ("finalized", Some("measured"))
                );
                1_234
            };
            assert_eq!(
                record_of(&processor, &request).status,
                NullifierStatus::Finalized
            );
            assert_eq!(
                installed_balance(&processor, &note, &prepared),
                2_000_000 - charge
            );
        }
        usage_server.abort();
    }

    /// Review regression (usage capture of a corrupt direct lease): one
    /// transient provider error while capturing the usage of a possibly
    /// delivered direct lease with a corrupt binding used to cancel it at
    /// once and delete its key, its usage lost. The capture is now retried
    /// like any settlement, while the corruption is reviewed (and alerted) at
    /// once, and the lease cannot be reopened yet. It is cancelled with its
    /// usage once that is read, and a reopening charges that usage. Still
    /// unread at its deadline, it is cancelled then, without usage.
    #[test]
    fn corrupt_direct_lease_capture_is_retried_like_any_settlement() {
        use crate::nullifier_store::{OfflineStore, ReopenOptions, ReopenRefusal};
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (note, prepared) = browser_lease_request("flaky-corrupt");
        let request = prepared.request.clone();
        let nullifier = request.public_inputs.request_nullifier.to_hex();
        let bound = request.public_inputs.solvency_bound;
        let verifier = RequestVerifier::load(setup_directory()).unwrap();
        let set_payload_hash = |store: &NullifierStore, payload_hash: String| {
            store.execute_for_test(
                "UPDATE nullifiers SET payload_hash = ?1 WHERE nullifier = ?2",
                rusqlite::params![payload_hash, nullifier],
            );
        };
        let corrupt_reviews = |store: &NullifierStore| {
            store
                .settlement_reviews(10)
                .unwrap()
                .into_iter()
                .filter(|stored| stored.review.reason == "binding_corrupt")
                .collect::<Vec<_>>()
        };
        for deadline_passes in [false, true] {
            let state = Arc::new(std::sync::Mutex::new(DirectKeyMock {
                failing_reads: 1,
                ..DirectKeyMock::default()
            }));
            let (url, server) = runtime.block_on(direct_key_server(state.clone()));
            let serving = |path: &std::path::Path| {
                let mut processor =
                    oa_lease_processor(Arc::new(NullifierStore::new(path).unwrap()));
                processor.config.openrouter_leases.as_mut().unwrap().source =
                    OpenRouterLeaseSourceConfig::OpenRouter {
                        management_key: "k".into(),
                        api_base: url.clone(),
                    };
                processor.openrouter = Some(Arc::new(
                    OpenRouterProvisioner::new("k".into(), url.clone()).unwrap(),
                ));
                processor.oa_org = None;
                processor
            };
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            let now = current_timestamp();
            let processor = serving(&path);
            add_lease(
                &processor,
                &request,
                LeaseSetup {
                    key_source: "openrouter",
                    expires_at: now - 100,
                    deadline: Some(now + 3_600),
                    key_hash: Some("k1"),
                    delivered: Some(true),
                    ttl: Some(300),
                },
            );
            set_payload_hash(&processor.store, "0x1".into());
            runtime.block_on(processor.settle_due_openrouter_leases());
            // The usage read failed once: retried, not cancelled. The key is
            // disabled, not deleted, and the corruption is reviewed at once.
            let lease = processor
                .store
                .lookup_openrouter_lease("flaky-corrupt")
                .unwrap();
            assert_eq!((lease.status.as_str(), lease.usage_usd), ("disabled", None));
            assert_eq!(state.lock().unwrap().calls, ["PATCH", "GET"]);
            let reviews = corrupt_reviews(&processor.store);
            assert_eq!(reviews.len(), 1);
            assert!(
                reviews[0].review.detail.contains("nullifiers.payload_hash")
                    && reviews[0].review.detail.contains("usage captured first"),
                "{}",
                reviews[0].review.detail
            );
            drop(processor);
            assert!(matches!(
                OfflineStore::open(&path).unwrap().reopen_cancelled_lease(
                    "flaky-corrupt",
                    ReopenOptions::default(),
                    &verifier
                ),
                Err(ReopenRefusal::CapturePending(status)) if status == "disabled"
            ));
            if deadline_passes {
                NullifierStore::new(&path).unwrap().execute_for_test(
                    "UPDATE openrouter_leases SET settlement_deadline_at = ?1
                     WHERE client_request_id = 'flaky-corrupt'",
                    rusqlite::params![(now - 1) as i64],
                );
            }
            let processor = serving(&path);
            runtime.block_on(processor.settle_due_openrouter_leases());
            let lease = processor
                .store
                .lookup_openrouter_lease("flaky-corrupt")
                .unwrap();
            assert_eq!(lease.status, "cancelled");
            // Read once the provider answered; at the deadline, never read.
            let (usage, calls) = if deadline_passes {
                (None, vec!["PATCH", "GET", "PATCH", "DELETE"])
            } else {
                (Some(0.01), vec!["PATCH", "GET", "GET", "PATCH", "DELETE"])
            };
            assert_eq!(lease.usage_usd, usage);
            assert_eq!(state.lock().unwrap().calls, calls);
            // Retries add no review; the cancellation adds its own.
            assert_eq!(corrupt_reviews(&processor.store).len(), 2);
            set_payload_hash(&processor.store, request.payload_hash.to_hex());
            drop(processor);
            let reopened = OfflineStore::open(&path)
                .unwrap()
                .reopen_cancelled_lease("flaky-corrupt", ReopenOptions::default(), &verifier)
                .unwrap();
            let charge = if deadline_passes {
                assert_eq!(
                    (reopened.status.as_str(), reopened.settles),
                    ("active", "deadline_fallback")
                );
                assert!(reopened.warning.is_some());
                bound
            } else {
                assert_eq!(
                    (reopened.status.as_str(), reopened.settles, reopened.warning),
                    ("revoking", "captured_usage", None)
                );
                10_000
            };
            let processor = serving(&path);
            runtime.block_on(processor.settle_due_openrouter_leases());
            let record = record_of(&processor, &request);
            assert_eq!(record.status, NullifierStatus::Finalized);
            assert_eq!(record.charge_applied, Some(charge));
            assert_eq!(
                installed_balance(&processor, &note, &prepared),
                2_000_000 - charge
            );
            server.abort();
        }
    }

    #[test]
    fn settlement_overview_lists_pending_leases_and_reviews() {
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let now = current_timestamp();
        let request = lease_request_for(&processor, "pending-view", 521, None);
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 100,
                deadline: Some(now + 1_000),
                key_hash: Some("view-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor
            .store
            .record_openrouter_lease_error(&request.client_request_id, "usage pending")
            .unwrap();
        let overview = processor.settlement_overview(10).unwrap();
        assert_eq!(overview.pending.len(), 1);
        let pending = &overview.pending[0];
        assert_eq!(pending.client_request_id, request.client_request_id);
        assert_eq!(pending.settlement_deadline, Some(now + 1_000));
        assert!(pending.seconds_until_deadline.unwrap() <= 1_000);
        assert_eq!(pending.attempts, 1);
        assert_eq!(overview.counts.pending, 1);
        assert_eq!(overview.counts.retrying, 1);
        assert!(overview.reviews.is_empty());
        let json = serde_json::to_value(&overview).unwrap();
        assert_eq!(json["counts"]["pending"], 1);
        assert_eq!(json["pending"][0]["last_error"], "usage pending");
    }

    // ---- Clearance ownership (G6) ------------------------------------------

    fn clearance(fixture: &crate::test_support::OwnershipFixture) -> ClearanceRequestV2C {
        fixture.request.clone()
    }

    /// A vault RPC whose currentRoot() is `root`; counts every call.
    async fn vault_root_rpc(
        processor: &mut RequestProcessor,
        root: Felt252,
    ) -> (
        Arc<std::sync::Mutex<Felt252>>,
        Arc<std::sync::Mutex<usize>>,
        tokio::task::JoinHandle<()>,
    ) {
        vault_root_rpc_with_history(processor, root, &[]).await
    }

    /// A vault RPC serving currentRoot() (`root`, changeable) and
    /// knownRoots(r): true for its current root and every root of `history`.
    async fn vault_root_rpc_with_history(
        processor: &mut RequestProcessor,
        root: Felt252,
        history: &[Felt252],
    ) -> (
        Arc<std::sync::Mutex<Felt252>>,
        Arc<std::sync::Mutex<usize>>,
        tokio::task::JoinHandle<()>,
    ) {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let current = Arc::new(std::sync::Mutex::new(root));
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let history: Arc<Vec<Felt252>> = Arc::new(history.to_vec());
        let (served, counted) = (current.clone(), calls.clone());
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let (served, counted, history) = (served.clone(), counted.clone(), history.clone());
                async move {
                    *counted.lock().unwrap() += 1;
                    let data = request["params"][0]["data"].as_str().unwrap_or_default();
                    let result = if request["method"] == "eth_chainId" {
                        "0x1".to_string()
                    } else if let Some(word) = data.strip_prefix("0x12ad7381") {
                        assert_eq!(request["params"][1], "latest");
                        let asked = Felt252::from_hex(word).unwrap();
                        let known = asked == *served.lock().unwrap() || history.contains(&asked);
                        format!("0x{:064x}", known as u8)
                    } else {
                        assert_eq!(data, "0xfdab463d");
                        assert_eq!(request["params"][1], "latest");
                        format!("0x{}", hex::encode(served.lock().unwrap().as_bytes()))
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (current, calls, server)
    }

    #[tokio::test]
    async fn clearance_accepts_a_real_kind_2_ownership_proof() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let request = clearance(fixture);
        let nullifier = request.withdrawal_nullifier;
        assert_eq!(request.ownership_proof.public_inputs.kind, 2);
        let response = processor.process_clearance(&request).await.unwrap();
        let message = core::clearance_message(
            processor.config.protocol_version,
            processor.config.chain_id,
            &processor.config.contract_address,
            &nullifier,
        );
        assert!(zkapi_proof::compact::verify_signature(
            &processor.clearance_signing_key(),
            &message,
            &response.signature
        )
        .unwrap());
        let record = processor.store.lookup_by_nullifier(&nullifier).unwrap();
        assert_eq!(record.status, NullifierStatus::ClearanceReserved);
        assert_eq!(
            processor
                .store
                .clearance_auth(&nullifier)
                .unwrap()
                .as_deref(),
            Some("ownership_proof")
        );
        // Idempotent for the owner.
        processor.process_clearance(&request).await.unwrap();
        assert_eq!(processor.store.get_all_nullifiers().len(), 1);
        // The reservation is permanent: the note state can never also be
        // spent on a request (the signed clearance has no expiry).
        let lease = lease_request_for(&processor, "after-clearance", 1, None);
        let mut lease = lease;
        lease.public_inputs.request_nullifier = nullifier;
        assert!(matches!(
            processor.validate_and_reserve(&lease),
            Err(ServerError::Replay)
        ));
        // The kind-1 close itself verifies with that clearance.
        let note = &fixture.note;
        let (public, mut witness) = note
            .state
            .withdrawal(
                &note.deployment,
                &note.tree,
                &zkapi_proof::dev::DevWithdrawal {
                    kind: WithdrawalKind::MutualClose,
                    destination: [0x11; 20],
                    conceded: 0,
                    valid_until: current_timestamp() + 3_600,
                },
            )
            .unwrap();
        witness.clearance_signature = Some(response.signature);
        let proof = crate::test_support::withdrawal_prover()
            .prove(&public, witness)
            .unwrap();
        assert!(processor
            .withdrawal_verifier
            .verify(&public, &proof)
            .unwrap());
        assert_eq!(public.kind, 1);
        assert_eq!(public.withdrawal_nullifier, nullifier);
        assert_eq!(
            public.final_balance,
            request.ownership_proof.public_inputs.final_balance
        );
    }

    /// §5.3: only a fresh kind-2 proof with its zero fields zero, for this
    /// nullifier, deployment and keys, verifies ownership. Each refusal is
    /// made before verification or by it, and reserves nothing.
    #[tokio::test]
    async fn clearance_rejects_wrong_kind_stale_nonzero_foreign_or_tampered_proofs() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let valid = clearance(fixture);
        let now = current_timestamp();
        let mutate = |change: &dyn Fn(&mut ClearanceRequestV2C)| {
            let mut request = valid.clone();
            change(&mut request);
            request
        };
        fn inputs(
            request: &mut ClearanceRequestV2C,
        ) -> &mut zkapi_types::WithdrawalPublicInputsV2C {
            &mut request.ownership_proof.public_inputs
        }
        let cases: Vec<(&str, ClearanceRequestV2C)> = vec![
            (
                "other nullifier",
                mutate(&|r| r.withdrawal_nullifier = Felt252::from_u64(99)),
            ),
            ("escape kind", mutate(&|r| inputs(r).kind = 0)),
            ("close kind", mutate(&|r| inputs(r).kind = 1)),
            ("unknown kind", mutate(&|r| inputs(r).kind = 3)),
            (
                "next nullifier",
                mutate(&|r| inputs(r).next_nullifier = Felt252::from_u64(5)),
            ),
            ("conceded", mutate(&|r| inputs(r).conceded = 1)),
            (
                "destination",
                mutate(&|r| inputs(r).destination = [0x11; 20]),
            ),
            ("expired", mutate(&|r| inputs(r).valid_until = now - 1)),
            (
                "too far ahead",
                mutate(&|r| inputs(r).valid_until = now + 3_700),
            ),
            (
                "contract",
                mutate(&|r| inputs(r).contract_address = Felt252::from_u64(2)),
            ),
            ("chain", mutate(&|r| inputs(r).chain_id = 5)),
            (
                "state key",
                mutate(&|r| inputs(r).state_signing_key_x = Felt252::from_u64(3)),
            ),
            (
                "clearance key",
                mutate(&|r| inputs(r).clearance_signing_key_y = Felt252::from_u64(4)),
            ),
            ("balance", mutate(&|r| inputs(r).final_balance += 1)),
            ("validity bound", mutate(&|r| inputs(r).valid_until -= 1)),
            (
                "flipped proof byte",
                mutate(&|r| {
                    let proof = &mut r.ownership_proof.proof.proof;
                    let mut bytes = base64::engine::general_purpose::STANDARD
                        .decode(&*proof)
                        .unwrap();
                    bytes[40] ^= 1;
                    *proof = base64::engine::general_purpose::STANDARD.encode(bytes);
                }),
            ),
        ];
        for (label, request) in cases {
            let error = processor.process_clearance(&request).await.unwrap_err();
            let expected = match label {
                "other nullifier" | "escape kind" | "close kind" | "unknown kind"
                | "next nullifier" | "conceded" | "destination" | "expired" | "too far ahead"
                | "state key" | "clearance key" => matches!(error, ServerError::InvalidRequest(_)),
                "contract" | "chain" => matches!(error, ServerError::ProtocolMismatch(_)),
                _ => matches!(error, ServerError::InvalidProof(_)),
            };
            assert!(expected, "{label}: {error}");
            assert!(processor
                .store
                .lookup_by_nullifier(&request.withdrawal_nullifier)
                .is_none());
        }
        // A request proof is not an ownership proof, even on the wire.
        let request_proof = serde_json::json!({
            "withdrawal_nullifier": valid.withdrawal_nullifier,
            "ownership_proof": {
                "public_inputs": unverified_lease_request(&processor).public_inputs,
                "proof": valid.ownership_proof.proof,
            }
        });
        assert!(serde_json::from_value::<ClearanceRequestV2C>(request_proof).is_err());
        assert!(processor.store.get_all_nullifiers().is_empty());
        // The untouched proof is admitted.
        processor.process_clearance(&valid).await.unwrap();
    }

    #[tokio::test]
    async fn clearance_root_window_and_vault_fallback() {
        let fixture = crate::test_support::ownership_fixture().await;
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.timing.vault_root_ttl = std::time::Duration::ZERO;
        let vault_root = Felt252::from_u64(0x7007);
        let (served, calls, server) = vault_root_rpc(&mut processor, vault_root).await;
        // An unknown root the vault does not have: stale, reporting the
        // vault's root, and nothing reserved.
        let request = clearance(fake);
        match processor.process_clearance(&request).await {
            Err(ServerError::StaleRoot { latest_root }) => {
                assert_eq!(latest_root, vault_root.to_hex())
            }
            other => panic!("expected stale root, got {other:?}"),
        }
        assert!(processor.store.get_all_nullifiers().is_empty());
        // currentRoot(), then knownRoots(root), each after eth_chainId.
        assert_eq!(*calls.lock().unwrap(), 4);
        // The indexer lags, but the vault already has the proof's root.
        *served.lock().unwrap() = fixture.root;
        let request = clearance(fixture);
        processor.process_clearance(&request).await.unwrap();
        assert_eq!(*calls.lock().unwrap(), 6);
        assert!(processor.recent_roots.lock().unwrap().contains(
            &fixture.root,
            current_timestamp(),
            processor.config.clearance_root_window_seconds
        ));
        // A root last seen longer ago than the window, or never seen, needs
        // the vault: refused unless the vault ever held it.
        let window = processor.config.clearance_root_window_seconds;
        processor.recent_roots.lock().unwrap().entries =
            VecDeque::from([(fixture.root, current_timestamp() - window - 1)]);
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.withdrawal_nullifier)
                .unwrap()
                .status,
            NullifierStatus::ClearanceReserved
        );
        let other = Arc::new(NullifierStore::in_memory().unwrap());
        let mut fresh = oa_lease_processor(other);
        fresh.timing.vault_root_ttl = std::time::Duration::ZERO;
        let (_, _, fresh_server) = vault_root_rpc(&mut fresh, vault_root).await;
        fresh.recent_roots.lock().unwrap().entries =
            VecDeque::from([(fixture.root, current_timestamp() - window - 1)]);
        assert!(matches!(
            fresh.process_clearance(&request).await,
            Err(ServerError::StaleRoot { .. })
        ));
        assert!(fresh.store.get_all_nullifiers().is_empty());
        server.abort();
        fresh_server.abort();
    }

    /// Review regression (Amendment A1): an ownership proof at a root the
    /// vault held long ago, such as the deposit-time root a client saved its
    /// path at, is accepted once the vault's knownRoots(root) holds it, and
    /// the answer is cached. The current root and the recent window are
    /// unchanged.
    #[tokio::test]
    async fn clearance_accepts_any_root_the_vault_ever_held() {
        let fixture = crate::test_support::ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.timing.vault_root_ttl = std::time::Duration::ZERO;
        let vault_root = Felt252::from_u64(0x7010);
        let (_, calls, server) =
            vault_root_rpc_with_history(&mut processor, vault_root, &[fixture.root]).await;
        assert!(!processor.recent_roots.lock().unwrap().contains(
            &fixture.root,
            current_timestamp(),
            processor.config.clearance_root_window_seconds
        ));
        let request = clearance(fixture);
        processor.process_clearance(&request).await.unwrap();
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&request.withdrawal_nullifier)
                .unwrap()
                .status,
            NullifierStatus::ClearanceReserved
        );
        assert_eq!(*calls.lock().unwrap(), 4);
        // Known once, known for good: a second check of the root reads only
        // the current root.
        assert!(processor
            .vault_knows_root(&fixture.root, &vault_root)
            .await
            .unwrap());
        assert_eq!(*calls.lock().unwrap(), 4);
        server.abort();
    }

    #[tokio::test]
    async fn ownership_proof_replay_hits_the_negative_cache_not_the_rpc() {
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let vault_root = Felt252::from_u64(0x7008);
        let (served, calls, server) = vault_root_rpc(&mut processor, vault_root).await;
        let request = clearance(fake);
        for _ in 0..6 {
            match processor.process_clearance(&request).await {
                Err(ServerError::StaleRoot { latest_root }) => {
                    assert_eq!(latest_root, vault_root.to_hex())
                }
                other => panic!("expected stale root, got {other:?}"),
            }
        }
        // One currentRoot() and one knownRoots(), each after eth_chainId, for
        // all six attempts.
        assert_eq!(*calls.lock().unwrap(), 4);
        assert!(processor.store.get_all_nullifiers().is_empty());
        // Once the cached vault read expires, a replay costs one shared read
        // (still no pairing check) while the vault root is unchanged.
        processor.timing.vault_root_ttl = std::time::Duration::ZERO;
        assert!(matches!(
            processor.process_clearance(&request).await,
            Err(ServerError::StaleRoot { .. })
        ));
        assert_eq!(*calls.lock().unwrap(), 6);
        // A vault that moves re-evaluates the pair rather than trusting it.
        *served.lock().unwrap() = Felt252::from_u64(0x7009);
        match processor.process_clearance(&request).await {
            Err(ServerError::StaleRoot { latest_root }) => {
                assert_eq!(latest_root, Felt252::from_u64(0x7009).to_hex())
            }
            other => panic!("expected stale root, got {other:?}"),
        }
        assert_eq!(*calls.lock().unwrap(), 10);
        // Without the negative cache, concurrent readers still share one read,
        // and the root is still unknown under the same vault root.
        processor
            .rejected_clearances
            .lock()
            .unwrap()
            .entries
            .clear();
        processor.timing.vault_root_ttl = std::time::Duration::from_secs(5);
        *processor.vault_root_cache.try_lock().unwrap() = None;
        let processor = Arc::new(processor);
        let attempts: Vec<_> = (0..4)
            .map(|_| {
                let processor = processor.clone();
                let request = request.clone();
                tokio::spawn(async move { processor.process_clearance(&request).await })
            })
            .collect();
        for attempt in attempts {
            assert!(matches!(
                attempt.await.unwrap(),
                Err(ServerError::StaleRoot { .. })
            ));
        }
        // Four concurrent requests: one more eth_chainId + currentRoot().
        assert_eq!(*calls.lock().unwrap(), 10 + 2);
        server.abort();
    }

    #[tokio::test]
    async fn vault_root_read_failures_are_cached_briefly() {
        let fake = crate::test_support::fake_tree_ownership_fixture().await;
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        let calls = Arc::new(std::sync::Mutex::new(0usize));
        let counted = calls.clone();
        let app = axum::Router::new().route(
            "/",
            axum::routing::post(move || {
                let counted = counted.clone();
                async move {
                    *counted.lock().unwrap() += 1;
                    axum::http::StatusCode::SERVICE_UNAVAILABLE
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        configure_issuance_rpc(
            &mut processor,
            format!("http://{}", listener.local_addr().unwrap()),
        );
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let request = clearance(fake);
        for _ in 0..3 {
            let error = processor.process_clearance(&request).await.unwrap_err();
            assert!(
                matches!(&error, ServerError::Internal(message) if message.starts_with("vault read failed")),
                "{error}"
            );
            assert!(error.is_retriable());
        }
        // One failed eth_chainId for all three attempts.
        assert_eq!(*calls.lock().unwrap(), 1);
        assert!(processor.store.get_all_nullifiers().is_empty());
        server.abort();
    }

    #[tokio::test]
    async fn clearance_never_reserves_lease_reserved_nullifier() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let mut lease = lease_request_for(&processor, "spent-by-request", 1, None);
        lease.public_inputs.request_nullifier = fixture.request.withdrawal_nullifier;
        processor.store.reserve_openrouter_lease(&lease).unwrap();
        assert!(matches!(
            processor.process_clearance(&clearance(fixture)).await,
            Err(ServerError::NullifierUsed)
        ));
        assert_eq!(
            processor
                .store
                .lookup_by_nullifier(&lease.public_inputs.request_nullifier)
                .unwrap()
                .status,
            NullifierStatus::Reserved
        );
    }

    #[tokio::test]
    async fn clearance_verification_capacity_is_bounded() {
        let fixture = crate::test_support::ownership_fixture().await;
        let processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.update_root(fixture.root);
        let permits = processor
            .clearance_permits
            .acquire_many(CLEARANCE_VERIFY_PERMITS as u32)
            .await
            .unwrap();
        let error = processor
            .process_clearance(&clearance(fixture))
            .await
            .unwrap_err();
        assert!(matches!(error, ServerError::CapacityExhausted));
        assert!(processor.store.get_all_nullifiers().is_empty());
        drop(permits);
        processor
            .process_clearance(&clearance(fixture))
            .await
            .unwrap();
    }

    // ---- Pass-2 scheduling: pending receipts, deadlines, retirement --------

    type UsageCalls = Arc<std::sync::Mutex<std::collections::HashMap<String, usize>>>;

    /// An OA usage relay that answers by key hash: "pending-*" says pending
    /// (retry after `retry_after` s) and "error-*" fails with 503, both after
    /// `delay`; "flaky-*" fails once, then settles; any other key gets a
    /// finalized receipt of 1000 credits at once. Counts calls per key.
    async fn oa_scheduling_server(
        delay: std::time::Duration,
        retry_after: u64,
    ) -> (String, tokio::task::JoinHandle<()>, UsageCalls) {
        use axum::{http::StatusCode, routing::post, Json, Router};
        use serde_json::{json, Value};
        let calls = UsageCalls::default();
        let seen = calls.clone();
        let app = Router::new().route(
            "/api/zkapi/key_usage",
            post(move |Json(body): Json<Value>| {
                let seen = seen.clone();
                async move {
                    let key = body["key_hash"].as_str().unwrap().to_string();
                    let count = {
                        let mut calls = seen.lock().unwrap();
                        let count = calls.entry(key.clone()).or_default();
                        *count += 1;
                        *count
                    };
                    if key.starts_with("pending") {
                        tokio::time::sleep(delay).await;
                        return (
                            StatusCode::OK,
                            Json(json!({"source":"oa_org", "version":1, "status":"pending",
                                "client_request_id":body["client_request_id"],
                                "station_request_id":"ab".repeat(32), "key_hash":key,
                                "retry_after_seconds":retry_after})),
                        );
                    }
                    if key.starts_with("error") || (key.starts_with("flaky") && count == 1) {
                        tokio::time::sleep(delay).await;
                        return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
                    }
                    (StatusCode::OK, Json(finalized_usage_receipt(&body, &key)))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (url, server, calls)
    }

    /// A finalized OA usage receipt of 1000 credits for the usage read `body`.
    fn finalized_usage_receipt(body: &serde_json::Value, key: &str) -> serde_json::Value {
        let expires_at = body["expires_at_unix"].as_u64().unwrap() - 30;
        serde_json::json!({"source":"oa_org", "version":1, "status":"finalized",
            "client_request_id":body["client_request_id"],
            "station_request_id":"ab".repeat(32), "key_hash":key,
            "usage_credits":1000, "credit_limit_credits":body["credit_limit_credits"],
            "expires_at_unix":expires_at, "closed_at_unix":expires_at,
            "finalized_at_unix":expires_at + 1, "station_id":"station",
            "station_signature":"ab".repeat(64), "org_signature":"cd".repeat(64)})
    }

    /// An OA processor settling against `url`, with a scaled-down tick budget
    /// (production: 120 s).
    fn oa_scheduling_processor(url: String, tick_budget: std::time::Duration) -> RequestProcessor {
        let mut processor = oa_lease_processor(Arc::new(NullifierStore::in_memory().unwrap()));
        processor.oa_org = Some(Arc::new(
            OaOrgProvisioner::new(url, "test-secret".into()).unwrap(),
        ));
        processor.timing.tick_budget = tick_budget;
        processor
    }

    /// A delivered OA lease past its drain with `key_hash`, a write-once
    /// `deadline` and a last-attempt time of `updated_at`.
    fn add_delivered_oa_lease(
        processor: &RequestProcessor,
        id: &str,
        nullifier: u64,
        key_hash: &str,
        deadline: u64,
        updated_at: i64,
    ) -> ApiRequestV2 {
        let request = lease_request_for(processor, id, nullifier, None);
        add_lease(
            processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: current_timestamp() - 100,
                deadline: Some(deadline),
                key_hash: Some(key_hash),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.store.execute_for_test(
            "UPDATE openrouter_leases SET updated_at = ?1 WHERE client_request_id = ?2",
            rusqlite::params![updated_at, id],
        );
        request
    }

    fn calls_to(calls: &UsageCalls, key: &str) -> usize {
        calls.lock().unwrap().get(key).copied().unwrap_or(0)
    }

    /// Final round (server-fixup2#1): the OA org limits usage reads across
    /// all of the server's leases. Once it answers one with 429 and a
    /// Retry-After, no OA usage read starts before that time: not for the
    /// rest of the tick's leases, not in later ticks, and not for a
    /// retirement, which answers lease_settlement_pending. The limited lease
    /// is deferred like a pending receipt, and nothing counts as a failure.
    /// Afterwards settlement resumes, nearest deadline first.
    #[tokio::test]
    async fn rate_limited_usage_reads_wait_for_the_orgs_retry_after() {
        use axum::{http::StatusCode, routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::sync::atomic::AtomicBool;
        let calls = UsageCalls::default();
        let limited = Arc::new(AtomicBool::new(true));
        let (seen, limit) = (calls.clone(), limited.clone());
        let app = Router::new().route(
            "/api/zkapi/key_usage",
            post(move |Json(body): Json<Value>| {
                let (seen, limit) = (seen.clone(), limit.clone());
                async move {
                    let key = body["key_hash"].as_str().unwrap().to_string();
                    *seen.lock().unwrap().entry(key.clone()).or_default() += 1;
                    if limit.load(Ordering::SeqCst) {
                        return (
                            StatusCode::TOO_MANY_REQUESTS,
                            [("retry-after", "60")],
                            Json(json!({"reason": "oa_minute_request_limit"})),
                        );
                    }
                    (
                        StatusCode::OK,
                        [("cache-control", "no-store")],
                        Json(finalized_usage_receipt(&body, &key)),
                    )
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let processor = oa_scheduling_processor(url, std::time::Duration::from_secs(5));
        let now = current_timestamp();
        let requests: Vec<ApiRequestV2> = (0..10u64)
            .map(|i| {
                add_delivered_oa_lease(
                    &processor,
                    &format!("rl-{i}"),
                    700 + i,
                    &format!("rl-hash-{i}"),
                    now + 3_600 + i,
                    1,
                )
            })
            .collect();
        let total = |calls: &UsageCalls| calls.lock().unwrap().values().sum::<usize>();
        for _ in 0..3 {
            processor.settle_due_openrouter_leases().await;
        }
        // One read, of the lease nearest its deadline.
        assert_eq!(total(&calls), 1);
        assert_eq!(calls_to(&calls, "rl-hash-0"), 1);
        assert_eq!(
            processor.store.query_i64_for_test(
                "SELECT COALESCE(SUM(settlement_attempts), 0) FROM openrouter_leases",
                []
            ),
            0
        );
        assert_eq!(
            processor.store.query_i64_for_test(
                "SELECT COUNT(*) FROM openrouter_leases WHERE last_error IS NOT NULL",
                []
            ),
            0
        );
        let deferred = processor
            .store
            .openrouter_lease_next_attempt_at("rl-0")
            .unwrap()
            .unwrap();
        assert!(deferred >= now + 59 && deferred <= current_timestamp() + 60);
        assert_eq!(
            processor.store.query_i64_for_test(
                "SELECT COUNT(*) FROM openrouter_leases WHERE next_attempt_at IS NOT NULL",
                []
            ),
            1
        );
        // Retirements, of the limited lease or another, do not ask either.
        for request in [&requests[0], &requests[5]] {
            match processor
                .retire_openrouter_lease(&request.client_request_id, request)
                .await
            {
                Err(ServerError::LeaseSettlementPending {
                    retry_after_seconds,
                }) => assert!((1..=60).contains(&retry_after_seconds)),
                other => panic!("expected lease_settlement_pending, got {other:?}"),
            }
        }
        assert_eq!(total(&calls), 1);
        // Once the retry time has come (simulated), every lease settles.
        limited.store(false, Ordering::SeqCst);
        processor.oa_usage_backoff_until.store(0, Ordering::SeqCst);
        processor
            .store
            .execute_for_test("UPDATE openrouter_leases SET next_attempt_at = NULL", []);
        processor.settle_due_openrouter_leases().await;
        for request in &requests {
            assert_settled_from_usage(&processor, request);
        }
        assert_eq!(total(&calls), 11);
        server.abort();
    }

    fn assert_settled_from_usage(processor: &RequestProcessor, request: &ApiRequestV2) {
        let record = record_of(processor, request);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(payload_of(&record)["charge_basis"], "measured");
        assert!(record.charge_applied.unwrap() < request.public_inputs.solvency_bound);
        assert!(review_of(processor, request).is_none());
    }

    /// Sweep until `deadline` has passed.
    async fn sweep_through(processor: &RequestProcessor, deadline: u64) {
        while current_timestamp() <= deadline {
            processor.settle_due_openrouter_leases().await;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }

    /// Final review (seam:settlement-lifecycle#1): OA receipts that stay
    /// pending once held the front of pass 2 on every tick, so a lease behind
    /// them whose receipt was available was never attempted and was charged
    /// its solvency bound at its deadline.
    #[tokio::test]
    async fn pending_receipts_ahead_cannot_starve_a_lease_near_its_deadline() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(150), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_millis(400));
        let now = current_timestamp();
        for i in 0..3u64 {
            add_delivered_oa_lease(
                &processor,
                &format!("pending-{i}"),
                800 + i,
                &format!("pending-hash-{i}"),
                now + 3_600,
                100 + i as i64,
            );
        }
        let deadline = now + 4;
        let healthy =
            add_delivered_oa_lease(&processor, "healthy", 900, "healthy-hash", deadline, 200);
        sweep_through(&processor, deadline).await;
        assert_settled_from_usage(&processor, &healthy);
        assert_eq!(calls_to(&calls, "healthy-hash"), 1);
        server.abort();
    }

    /// The realistic ordering: the lease was delivered first, then one
    /// transient org error moved it behind pending leases delivered after it,
    /// whose deadlines are later than its own.
    #[tokio::test]
    async fn a_transient_error_cannot_strand_a_lease_behind_pending_receipts() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(150), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_millis(400));
        let now = current_timestamp();
        let deadline = now + 4;
        let flaky = add_delivered_oa_lease(&processor, "flaky", 900, "flaky-hash", deadline, 50);
        for i in 0..3u64 {
            add_delivered_oa_lease(
                &processor,
                &format!("pending-{i}"),
                800 + i,
                &format!("pending-hash-{i}"),
                deadline + 60,
                100 + i as i64,
            );
        }
        sweep_through(&processor, deadline).await;
        assert_settled_from_usage(&processor, &flaky);
        assert_eq!(calls_to(&calls, "flaky-hash"), 2);
        server.abort();
    }

    /// A pending receipt is not a failed attempt: nothing is counted, and the
    /// org's retry-after is honoured durably (bounded by half the time left
    /// before the deadline), instead of polling it again on every tick.
    #[tokio::test]
    async fn pending_receipt_waits_for_its_retry_after_without_counting_a_failure() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(1), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_secs(5));
        let now = current_timestamp();
        let far = add_delivered_oa_lease(&processor, "far", 801, "pending-far", now + 3_600, 1);
        add_delivered_oa_lease(&processor, "near", 802, "pending-near", now + 20, 1);
        processor.settle_due_openrouter_leases().await;
        processor.settle_due_openrouter_leases().await;
        assert_eq!(calls_to(&calls, "pending-far"), 1);
        assert_eq!(calls_to(&calls, "pending-near"), 1);
        let lease = processor
            .store
            .try_lookup_openrouter_lease(&far.client_request_id)
            .unwrap()
            .unwrap();
        assert_eq!(lease.status, "active");
        assert_eq!(lease.settlement_attempts, 0);
        assert_eq!(lease.first_error_at, None);
        assert_eq!(lease.last_error, None);
        let next_attempt = |id: &str| {
            processor.store.query_i64_for_test(
                "SELECT next_attempt_at FROM openrouter_leases WHERE client_request_id = ?1",
                rusqlite::params![id],
            )
        };
        let far_next = next_attempt("far");
        assert!(
            (now as i64 + 30..=now as i64 + 32).contains(&far_next),
            "{far_next}"
        );
        // 30 s would overshoot half of the 20 s left: the lease near its
        // deadline is asked again within 10 s.
        let near_next = next_attempt("near");
        assert!(
            (now as i64..=now as i64 + 10).contains(&near_next),
            "{near_next}"
        );
        // Once the retry time has come, it is asked again.
        processor.store.execute_for_test(
            "UPDATE openrouter_leases SET next_attempt_at = ?1 WHERE client_request_id = 'far'",
            rusqlite::params![now as i64 - 1],
        );
        processor.settle_due_openrouter_leases().await;
        assert_eq!(calls_to(&calls, "pending-far"), 2);
        server.abort();
    }

    /// Nearest-deadline-first must not let leases that keep failing slowly
    /// near their deadline starve every other lease: part of each tick goes
    /// to the least recently attempted lease.
    #[tokio::test]
    async fn slow_failures_near_their_deadline_cannot_starve_other_leases() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(200), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_millis(500));
        let now = current_timestamp();
        for i in 0..3u64 {
            add_delivered_oa_lease(
                &processor,
                &format!("error-{i}"),
                800 + i,
                &format!("error-hash-{i}"),
                now + 3_600 + i,
                100,
            );
        }
        let healthy =
            add_delivered_oa_lease(&processor, "healthy", 900, "healthy-hash", now + 7_200, 1);
        processor.settle_due_openrouter_leases().await;
        assert_settled_from_usage(&processor, &healthy);
        // The lease nearest its deadline was still attempted first.
        assert_eq!(calls_to(&calls, "error-hash-0"), 1);
        server.abort();
    }

    /// Final review, round 1: the nearest-deadline order is what reaches a
    /// lease near its deadline that a transient error just moved to the back
    /// of the least-recently-attempted order, while slow failures fill the
    /// tick.
    #[tokio::test]
    async fn a_lease_near_its_deadline_is_attempted_first_in_a_saturated_tick() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(200), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_millis(500));
        let now = current_timestamp();
        for i in 0..5u64 {
            add_delivered_oa_lease(
                &processor,
                &format!("error-{i}"),
                800 + i,
                &format!("error-hash-{i}"),
                now + 3_600 + i,
                100 + i as i64,
            );
        }
        // Attempted a moment ago (a transient error), due well before the
        // others.
        let near =
            add_delivered_oa_lease(&processor, "near", 900, "near-hash", now + 600, now as i64);
        processor.settle_due_openrouter_leases().await;
        assert_settled_from_usage(&processor, &near);
        assert_eq!(calls_to(&calls, "near-hash"), 1);
        // The tick was saturated: it could not reach every slow failure.
        let attempted = (0..5)
            .filter(|i| calls_to(&calls, &format!("error-hash-{i}")) > 0)
            .count();
        assert!(attempted < 5, "{attempted}");
        server.abort();
    }

    /// Final review, round 1: owner retirements of one lease whose receipt
    /// stays pending, sent back to back, once queued on a settlement lock
    /// shared by every lease, ahead of each pass-2 attempt, so that pass 2
    /// reached a handful of leases per tick and the rest were charged their
    /// solvency bound at their deadlines. Each also asked the org again.
    /// Production ratio kept: tick budget / retirement lock wait = 12.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_retirement_flood_on_one_lease_cannot_throttle_other_settlements() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(50), 30).await;
        let mut processor = oa_scheduling_processor(url, std::time::Duration::from_millis(2_400));
        processor.timing.retire_lock_timeout = std::time::Duration::from_millis(200);
        processor.timing.retire_timeout = std::time::Duration::from_millis(900);
        let processor = Arc::new(processor);
        let now = current_timestamp();
        let attacker = add_delivered_oa_lease(
            &processor,
            "attacker",
            700,
            "pending-attacker",
            now + 3_600,
            1_000,
        );
        let healthy: Vec<_> = (0..100u64)
            .map(|i| {
                add_delivered_oa_lease(
                    &processor,
                    &format!("h{i}"),
                    1_000 + i,
                    &format!("healthy-{i}"),
                    now + 3_600,
                    100 + i as i64,
                )
            })
            .collect();
        let stop = Arc::new(AtomicBool::new(false));
        let retirements = Arc::new(AtomicUsize::new(0));
        let flood: Vec<_> = (0..8)
            .map(|_| {
                let processor = processor.clone();
                let attacker = attacker.clone();
                let stop = stop.clone();
                let retirements = retirements.clone();
                tokio::spawn(async move {
                    while !stop.load(Ordering::Relaxed) {
                        let outcome = processor
                            .retire_openrouter_lease(&attacker.client_request_id, &attacker)
                            .await;
                        assert!(
                            matches!(outcome, Err(ServerError::LeaseSettlementPending { .. })),
                            "{outcome:?}"
                        );
                        retirements.fetch_add(1, Ordering::Relaxed);
                        tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                    }
                })
            })
            .collect();
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        processor.settle_due_openrouter_leases().await;
        stop.store(true, Ordering::Relaxed);
        for task in flood {
            task.await.unwrap();
        }
        let unsettled = healthy
            .iter()
            .filter(|request| record_of(&processor, request).status != NullifierStatus::Finalized)
            .count();
        assert_eq!(unsettled, 0, "of {} healthy leases", healthy.len());
        for request in &healthy {
            assert_settled_from_usage(&processor, request);
        }
        // The pending receipt was asked for once; every later retirement
        // honoured its deferral without asking the org again.
        assert!(retirements.load(Ordering::Relaxed) > 8);
        assert_eq!(calls_to(&calls, "pending-attacker"), 1);
        server.abort();
    }

    /// The sweep never waits for a lease's lock, and never settles a lease
    /// whose lock is held (by its owner's retirement) behind its holder's
    /// back: it leaves the lease to the holder and settles it on a later tick.
    #[tokio::test]
    async fn the_sweep_leaves_a_lease_whose_lock_is_held_to_its_holder() {
        let (url, server, calls) =
            oa_scheduling_server(std::time::Duration::from_millis(1), 30).await;
        let processor = oa_scheduling_processor(url, std::time::Duration::from_secs(5));
        let now = current_timestamp();
        let overdue =
            add_delivered_oa_lease(&processor, "overdue", 700, "overdue-hash", now - 1, 1);
        let due = add_delivered_oa_lease(&processor, "due", 701, "due-hash", now + 3_600, 1);
        let held = [
            processor.lease_locks.lock(&overdue.client_request_id).await,
            processor.lease_locks.lock(&due.client_request_id).await,
        ];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            processor.settle_due_openrouter_leases(),
        )
        .await
        .expect("the sweep waited for a held lease lock");
        assert_eq!(
            record_of(&processor, &overdue).status,
            NullifierStatus::Reserved
        );
        assert_eq!(
            record_of(&processor, &due).status,
            NullifierStatus::Reserved
        );
        assert_eq!(calls_to(&calls, "due-hash"), 0);
        drop(held);
        processor.settle_due_openrouter_leases().await;
        let record = record_of(&processor, &overdue);
        assert_eq!(record.status, NullifierStatus::Finalized);
        assert_eq!(payload_of(&record)["charge_basis"], "worst_case");
        assert_settled_from_usage(&processor, &due);
        server.abort();
    }

    /// Only a lease's owner can make the sweep leave the lease to a
    /// retirement: a retirement whose proof does not match is refused before
    /// it takes the lease's lock.
    #[tokio::test]
    async fn a_retirement_without_the_owners_proof_never_takes_the_lease_lock() {
        let mut processor = oa_scheduling_processor(
            "http://127.0.0.1:9".into(),
            std::time::Duration::from_secs(1),
        );
        processor.timing.retire_lock_timeout = std::time::Duration::from_millis(200);
        let now = current_timestamp();
        let owner = add_delivered_oa_lease(&processor, "owner", 700, "owner-hash", now + 3_600, 1);
        let mut forged = owner.clone();
        forged.payload.push(' ');
        let _held = processor.lease_locks.lock(&owner.client_request_id).await;
        let error = processor
            .retire_openrouter_lease(&owner.client_request_id, &forged)
            .await
            .unwrap_err();
        assert!(
            matches!(&error, ServerError::InvalidRequest(detail) if detail.contains("does not match")),
            "{error:?}"
        );
    }

    /// An owner's retirement waits for no other lease's settlement, so it is
    /// served during a long pass 2 instead of timing out as
    /// lease_settlement_pending.
    #[tokio::test]
    async fn owner_retirement_interleaves_with_a_long_settlement_pass() {
        let (url, server, _calls) =
            oa_scheduling_server(std::time::Duration::from_millis(300), 30).await;
        let mut processor = oa_scheduling_processor(url, std::time::Duration::from_secs(10));
        processor.timing.retire_lock_timeout = std::time::Duration::from_secs(1);
        let processor = Arc::new(processor);
        let now = current_timestamp();
        for i in 0..5u64 {
            add_delivered_oa_lease(
                &processor,
                &format!("pending-{i}"),
                800 + i,
                &format!("pending-hash-{i}"),
                now + 3_600,
                100,
            );
        }
        let owner = lease_request_for(&processor, "owner", 900, None);
        add_lease(
            &processor,
            &owner,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 200,
                deadline: Some(now + 7_200),
                key_hash: Some("owner-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let sweep = tokio::spawn({
            let processor = processor.clone();
            async move { processor.settle_due_openrouter_leases().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let status = processor
            .retire_openrouter_lease(&owner.client_request_id, &owner)
            .await
            .unwrap();
        assert_eq!(status.status, "finalized");
        assert!(
            !sweep.is_finished(),
            "the sweep ended before the retirement"
        );
        sweep.await.unwrap();
        assert_settled_from_usage(&processor, &owner);
        server.abort();
    }

    /// Final review (seam:http-contract#2): a store that cannot be read is a
    /// retriable 500 database_error on every recovery route, never an
    /// unknown request or nullifier (which clients read as authoritative),
    /// and never an attestation that an accepted request was not accepted.
    #[tokio::test]
    async fn store_failures_are_database_errors_never_unknown_or_unaccepted() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let processor = Arc::new(oa_lease_processor(Arc::new(
            NullifierStore::in_memory().unwrap(),
        )));
        // An accepted lease request whose quote has expired since.
        let quote = serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,
            "billing_quote":{"asset":"native_eth", "units_per_eth":1_000_000_000, "chain_id":1,
            "feed_address":"0x694aa1769357215de4fac081bf1f309adc325306", "round_id":"123",
            "answer":"100000000000", "decimals":8, "updated_at":100, "expires_at":3700}});
        let request = lease_request_for(&processor, "accepted", 530, Some(quote.to_string()));
        let now = current_timestamp();
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 200,
                deadline: Some(now + 3_600),
                key_hash: Some("accepted-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        let app = crate::routes::create_router(processor.clone());
        let call = |method: &'static str, uri: String, body: Option<&ApiRequestV2>| {
            let app = app.clone();
            let body = body.map(|body| serde_json::to_vec(body).unwrap());
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(body.map_or_else(Body::empty, Body::from))
                    .unwrap();
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let nullifier = format!(
            "/v2/nullifiers/{}",
            request.public_inputs.request_nullifier.to_hex()
        );
        let by_id = "/v2/requests/accepted".to_string();
        let lease = "/v2/openrouter/leases/accepted".to_string();
        let expire = "/v2/openrouter/leases/accepted/expire".to_string();
        let issue = "/v2/openrouter/leases".to_string();
        let (status, body) = call("GET", nullifier.clone(), None).await;
        assert_eq!(
            (status, &body["nullifier_status"]),
            (StatusCode::OK, &"reserved".into())
        );
        let (status, body) = call("POST", expire.clone(), Some(&request)).await;
        assert_eq!(
            (status, &body["error_code"]),
            (StatusCode::CONFLICT, &"lease_pending".into())
        );

        // The store becomes unreadable (an I/O error, a corrupt page, a lock
        // held past the busy timeout): here, its tables are renamed away.
        processor
            .store
            .execute_for_test("ALTER TABLE nullifiers RENAME TO nullifiers_offline", []);
        processor
            .store
            .execute_for_test("ALTER TABLE openrouter_leases RENAME TO leases_offline", []);
        for (method, uri, body) in [
            ("GET", nullifier.clone(), None),
            ("GET", by_id.clone(), None),
            ("GET", lease.clone(), None),
            ("POST", lease.clone(), Some(&request)),
            ("POST", expire.clone(), Some(&request)),
            ("POST", issue.clone(), Some(&request)),
        ] {
            let (status, body) = call(method, uri.clone(), body).await;
            assert_eq!(
                status,
                StatusCode::INTERNAL_SERVER_ERROR,
                "{method} {uri}: {body}"
            );
            assert_eq!(
                body["error_code"], "database_error",
                "{method} {uri}: {body}"
            );
            assert_eq!(body["retriable"], true, "{method} {uri}: {body}");
        }

        // Once the store is readable again, the true answers return.
        processor
            .store
            .execute_for_test("ALTER TABLE nullifiers_offline RENAME TO nullifiers", []);
        processor
            .store
            .execute_for_test("ALTER TABLE leases_offline RENAME TO openrouter_leases", []);
        let (status, body) = call("GET", by_id, None).await;
        assert_eq!(
            (status, &body["nullifier_status"]),
            (StatusCode::OK, &"reserved".into())
        );
        assert_eq!(body["settlement_deadline"], now + 3_600);
        let (status, body) = call("POST", expire, Some(&request)).await;
        assert_eq!(
            (status, &body["error_code"]),
            (StatusCode::CONFLICT, &"lease_pending".into())
        );
        let (status, _) = call("GET", lease, None).await;
        assert_eq!(status, StatusCode::OK);
        // Only a readable store reports an unknown request.
        let (status, body) = call("GET", "/v2/requests/never-seen".into(), None).await;
        assert_eq!(
            (status, &body["status"], &body["nullifier_status"]),
            (StatusCode::OK, &"not_found".into(), &"unknown".into())
        );
    }

    /// Final review, round 1: a lease row that is present but cannot be
    /// decoded never heals by itself. It is not a retriable database_error
    /// (which turned off the clients' 404 fallback and kept them retrying):
    /// lease routes answer 404 lease_record_unreadable, not retriable, which
    /// sends clients to the authoritative nullifier record, still readable.
    #[tokio::test]
    async fn an_undecodable_lease_row_sends_clients_to_the_nullifier_record() {
        use axum::body::{to_bytes, Body};
        use axum::http::{Request, StatusCode};
        use tower::ServiceExt;
        let processor = Arc::new(oa_lease_processor(Arc::new(
            NullifierStore::in_memory().unwrap(),
        )));
        let request = lease_request_for(&processor, "rot", 531, None);
        let now = current_timestamp();
        add_lease(
            &processor,
            &request,
            LeaseSetup {
                key_source: "oa_org",
                expires_at: now + 200,
                deadline: Some(now + 3_600),
                key_hash: Some("rot-hash"),
                delivered: Some(true),
                ttl: Some(300),
            },
        );
        processor.store.execute_for_test(
            "UPDATE openrouter_leases SET api_request_json = '{\"client_request_id\":\"rot'
             WHERE client_request_id = 'rot'",
            [],
        );
        let app = crate::routes::create_router(processor.clone());
        let call = |method: &'static str, uri: String, body: Option<&ApiRequestV2>| {
            let app = app.clone();
            let body = body.map(|body| serde_json::to_vec(body).unwrap());
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(body.map_or_else(Body::empty, Body::from))
                    .unwrap();
                let response = app.oneshot(request).await.unwrap();
                let status = response.status();
                let bytes = to_bytes(response.into_body(), 1 << 20).await.unwrap();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&bytes)
                        .unwrap_or(serde_json::Value::Null),
                )
            }
        };
        let lease = "/v2/openrouter/leases/rot".to_string();
        for (method, body) in [("GET", None), ("POST", Some(&request))] {
            let (status, body) = call(method, lease.clone(), body).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{method}: {body}");
            assert_eq!(
                body["error_code"], "lease_record_unreadable",
                "{method}: {body}"
            );
            assert_eq!(body["retriable"], false, "{method}: {body}");
        }
        let (status, body) = call(
            "GET",
            format!(
                "/v2/nullifiers/{}",
                request.public_inputs.request_nullifier.to_hex()
            ),
            None,
        )
        .await;
        assert_eq!(
            (status, &body["nullifier_status"]),
            (StatusCode::OK, &"reserved".into())
        );
        // An unknown lease is still a bare 404.
        let (status, body) = call("GET", "/v2/openrouter/leases/never-seen".into(), None).await;
        assert_eq!(
            (status, body),
            (StatusCode::NOT_FOUND, serde_json::Value::Null)
        );
    }
}
