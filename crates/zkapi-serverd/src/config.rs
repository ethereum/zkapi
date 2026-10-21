//! Server configuration.

use zkapi_types::Felt252;

/// Default time after a lease's natural settlement start (issuance + TTL +
/// grace) at which an unsettled, possibly delivered lease is force-finalized.
pub const DEFAULT_SETTLEMENT_DEADLINE_SECONDS: u64 = 21_600;
/// Minimum retry window that a settlement deadline must leave after grace.
pub const MIN_SETTLEMENT_RETRY_WINDOW_SECONDS: u64 = 900;
/// Bound on the background sweep's own latency (tick budget plus attempt
/// timeout) used by the startup timing check.
pub const SETTLEMENT_SWEEP_SLACK_SECONDS: u64 = 600;
/// How long a root the server observed stays acceptable for clearance.
pub const DEFAULT_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 3_600;
pub const MIN_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 60;
pub const MAX_CLEARANCE_ROOT_WINDOW_SECONDS: u64 = 86_400;
/// O5: admission requires a Merkle root on which the indexer and the vault's
/// currentRoot() agreed at most this long ago.
pub const DEFAULT_ROOT_MAX_STALENESS_SECONDS: u64 = 60;
pub const MAX_ROOT_MAX_STALENESS_SECONDS: u64 = 3_600;
/// The per-request lease ceiling recommended for the canary and beyond
/// (`--request-limit-max-usd-micros`, §5.2): $6.
pub const RECOMMENDED_REQUEST_LIMIT_MAX_USD_MICROS: u128 = 6_000_000;
/// Slack of the challenger's raise timing check (§5.4): the raise must land
/// `ttl + grace + settlement deadline + raise lead + 4·poll + 1200 <=
/// challengePeriod`.
pub const RAISE_TIMING_SLACK_SECONDS: u64 = 1_200;
/// After a settled request's nullifier is first found consumed on chain,
/// its signature waits challengePeriod + this long for the consuming exit
/// to be defeated before the request becomes ExitedUnsigned (O7).
pub const EXIT_DEFERRAL_SLACK_SECONDS: u64 = 3_600;

/// Source used to provision prompt-private, short-lived OpenRouter keys.
#[derive(Clone)]
pub enum OpenRouterLeaseSourceConfig {
    /// Mint child keys directly with an OpenRouter management key.
    OpenRouter {
        management_key: String,
        /// OpenRouter API base without `/v1`.
        api_base: String,
    },
    /// Ask an OA org to relay key creation to a verifier-enrolled station.
    OaOrg {
        org_base_url: String,
        /// Dedicated zkAPI service credential configured by the org.
        shared_secret: String,
    },
}

impl OpenRouterLeaseSourceConfig {
    pub fn label(&self) -> &'static str {
        match self {
            Self::OpenRouter { .. } => "openrouter",
            Self::OaOrg { .. } => "oa_org",
        }
    }

    /// The endpoint that issues and measures this source's keys, recorded
    /// with each lease it activates: the OA org base URL, or the direct
    /// OpenRouter API base, without user info, query, fragment or trailing
    /// slash. A credential (shared secret or management key) is not part of
    /// it, so rotating one keeps the identity; nor, therefore, is the
    /// OpenRouter account behind an API base.
    pub fn identity(&self) -> String {
        let endpoint = match self {
            Self::OpenRouter { api_base, .. } => api_base,
            Self::OaOrg { org_base_url, .. } => org_base_url,
        }
        .trim();
        match reqwest::Url::parse(endpoint) {
            Ok(mut url) => {
                let _ = url.set_username("");
                let _ = url.set_password(None);
                url.set_query(None);
                url.set_fragment(None);
                url.as_str().trim_end_matches('/').to_string()
            }
            Err(_) => endpoint.trim_end_matches('/').to_string(),
        }
    }
}

impl std::fmt::Debug for OpenRouterLeaseSourceConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenRouter { api_base, .. } => formatter
                .debug_struct("OpenRouter")
                .field("management_key", &"[configured]")
                .field("api_base", api_base)
                .finish(),
            Self::OaOrg { org_base_url, .. } => formatter
                .debug_struct("OaOrg")
                .field("org_base_url", org_base_url)
                .field("shared_secret", &"[configured]")
                .finish(),
        }
    }
}

/// Prompt-private lease configuration for native ETH billing.
#[derive(Debug, Clone)]
pub struct OpenRouterLeaseConfig {
    pub source: OpenRouterLeaseSourceConfig,
    /// Runtime-key validity window.
    pub ttl_seconds: u64,
    /// Delay after expiry (and after disabling directly managed keys) before
    /// reading aggregate usage, allowing in-flight calls and accounting to drain.
    pub settlement_grace_seconds: u64,
    /// Background settlement scan interval.
    pub settlement_poll_seconds: u64,
    /// Seconds after a lease's issuance + TTL + grace by which an unsettled
    /// lease is finalized: a lease that may have been delivered at its measured
    /// (or, failing that, worst-case) charge. Written once per lease row.
    pub settlement_deadline_seconds: u64,
}

impl OpenRouterLeaseConfig {
    /// The settlement window `W` clients wait for (§6.4 E0): a lease's charge
    /// is final by its issuance + TTL + grace + settlement deadline.
    pub fn settlement_window_seconds(&self) -> u64 {
        self.ttl_seconds
            .saturating_add(self.settlement_grace_seconds)
            .saturating_add(self.settlement_deadline_seconds)
    }

    /// The challenger's raise timing check (§5.4): a raise decided
    /// `raise_lead_seconds` before an escape's deadline, once the request it
    /// raises for has settled, lands inside the challenge period:
    /// ttl + grace + deadline + raise lead + 4*poll + 1200 <= challengePeriod.
    pub fn validate_raise_timing(
        &self,
        raise_lead_seconds: u64,
        challenge_period_seconds: u64,
    ) -> anyhow::Result<()> {
        let bound = self
            .settlement_window_seconds()
            .checked_add(raise_lead_seconds)
            .and_then(|value| {
                value.checked_add(self.settlement_poll_seconds.max(1).checked_mul(4)?)
            })
            .and_then(|value| value.checked_add(RAISE_TIMING_SLACK_SECONDS))
            .ok_or_else(|| anyhow::anyhow!("raise timing overflows"))?;
        anyhow::ensure!(
            bound <= challenge_period_seconds,
            "refusing to start: lease TTL ({} s) + settlement grace ({} s) + settlement deadline \
             ({} s) + raise lead ({raise_lead_seconds} s) + 4 x poll ({} s) + \
             {RAISE_TIMING_SLACK_SECONDS} s = {bound} s exceeds the vault challengePeriod() \
             ({challenge_period_seconds} s); lower --raise-lead-seconds or the settlement deadline",
            self.ttl_seconds,
            self.settlement_grace_seconds,
            self.settlement_deadline_seconds,
            self.settlement_poll_seconds.max(1),
        );
        Ok(())
    }

    /// Every lease that may have been delivered must reach a Finalized
    /// transcript well inside the vault's escape challenge period:
    /// ttl + grace + deadline + 2*poll + slack <= challengePeriod / 2.
    pub fn validate_settlement_timing(&self, challenge_period_seconds: u64) -> anyhow::Result<()> {
        let minimum = self
            .settlement_grace_seconds
            .checked_add(MIN_SETTLEMENT_RETRY_WINDOW_SECONDS)
            .ok_or_else(|| anyhow::anyhow!("settlement grace overflows"))?;
        anyhow::ensure!(
            self.settlement_deadline_seconds >= minimum,
            "--openrouter-settlement-deadline-seconds ({}) must leave at least {} s of retries after the settlement grace ({} s)",
            self.settlement_deadline_seconds,
            MIN_SETTLEMENT_RETRY_WINDOW_SECONDS,
            self.settlement_grace_seconds
        );
        let bound = self
            .ttl_seconds
            .checked_add(self.settlement_grace_seconds)
            .and_then(|value| value.checked_add(self.settlement_deadline_seconds))
            .and_then(|value| {
                value.checked_add(self.settlement_poll_seconds.max(1).checked_mul(2)?)
            })
            .and_then(|value| value.checked_add(SETTLEMENT_SWEEP_SLACK_SECONDS))
            .ok_or_else(|| anyhow::anyhow!("lease settlement timing overflows"))?;
        anyhow::ensure!(
            bound <= challenge_period_seconds / 2,
            "refusing to start: lease TTL ({} s) + settlement grace ({} s) + settlement deadline ({} s) + 2 x poll ({} s) + {} s = {} s exceeds half of the vault challengePeriod() ({} s); lower --openrouter-settlement-deadline-seconds or the lease TTL",
            self.ttl_seconds,
            self.settlement_grace_seconds,
            self.settlement_deadline_seconds,
            self.settlement_poll_seconds.max(1),
            SETTLEMENT_SWEEP_SLACK_SECONDS,
            bound,
            challenge_period_seconds
        );
        Ok(())
    }
}

/// The challenger's startup timing checks (§5.4) against the vault's
/// challenge period `cp`, for the server's settlement window `W = ttl + grace
/// + settlement deadline` (the deployment manifest's
/// `settlement_window_seconds`) and settlement poll interval:
///
/// * G5: `W + 2·poll + 600 <= cp / 2`, so a request that may have been
///   delivered settles well inside every escape's window;
/// * raise: `W + raise_lead + 4·poll + 1200 <= cp`, so a raise decided
///   `raise_lead` before the deadline follows the settlement of any request
///   reserved before the escape.
pub fn validate_challenger_timing(
    settlement_window_seconds: u64,
    settlement_poll_seconds: u64,
    raise_lead_seconds: u64,
    challenge_period_seconds: u64,
) -> anyhow::Result<()> {
    let poll = settlement_poll_seconds.max(1);
    let g5 = settlement_window_seconds
        .checked_add(poll.saturating_mul(2))
        .and_then(|value| value.checked_add(SETTLEMENT_SWEEP_SLACK_SECONDS))
        .ok_or_else(|| anyhow::anyhow!("settlement timing overflows"))?;
    anyhow::ensure!(
        g5 <= challenge_period_seconds / 2,
        "refusing to start: settlement window ({settlement_window_seconds} s) + 2 x poll \
         ({poll} s) + {SETTLEMENT_SWEEP_SLACK_SECONDS} s = {g5} s exceeds half of the vault \
         challengePeriod() ({challenge_period_seconds} s)"
    );
    let raise = settlement_window_seconds
        .checked_add(raise_lead_seconds)
        .and_then(|value| value.checked_add(poll.checked_mul(4)?))
        .and_then(|value| value.checked_add(RAISE_TIMING_SLACK_SECONDS))
        .ok_or_else(|| anyhow::anyhow!("raise timing overflows"))?;
    anyhow::ensure!(
        raise <= challenge_period_seconds,
        "refusing to start: settlement window ({settlement_window_seconds} s) + raise lead \
         ({raise_lead_seconds} s) + 4 x poll ({poll} s) + {RAISE_TIMING_SLACK_SECONDS} s = \
         {raise} s exceeds the vault challengePeriod() ({challenge_period_seconds} s); lower \
         --raise-lead-seconds"
    );
    Ok(())
}

/// Configuration for the zkAPI server.
#[derive(Clone)]
pub struct ServerConfig {
    /// Protocol version (must be 2).
    pub protocol_version: u16,
    /// Chain ID this server is bound to.
    pub chain_id: u64,
    /// Optional shared Sepolia service gate; contains only a redacted digest.
    pub testnet_password: Option<crate::testnet_auth::TestnetPassword>,
    /// On-chain contract address.
    pub contract_address: Felt252,
    /// Minimum proof-bound lease budget, in whole gwei.
    pub request_charge_cap: u128,
    /// HTTP listen address (e.g. "0.0.0.0:3000").
    pub listen_addr: String,
    /// Path to the SQLite database file.
    pub db_path: String,
    /// Required secret seed for the proof-friendly state-signing key. There is
    /// no default: zero means unset, and startup refuses any seed whose key is
    /// not the vault's immutable stateSigningKeyX/Y.
    pub state_seed: Felt252,
    /// Required secret seed for the clearance-signing key; startup requires
    /// its key to equal the vault's clearanceSigningKeyX/Y.
    pub clear_seed: Felt252,
    /// Initial Merkle root the server should accept until the indexer updates it.
    pub initial_root: Felt252,
    /// Optional base URL for an indexer that serves the latest tree root.
    pub indexer_url: Option<String>,
    /// Poll interval for indexer root refresh.
    pub root_poll_interval_ms: u64,
    /// Required prompt-private OpenRouter lease configuration.
    pub openrouter_leases: Option<OpenRouterLeaseConfig>,
    /// Required native ETH oracle configuration, checked before server startup.
    pub native_billing: Option<crate::native_billing::NativeBillingConfig>,
    /// Directory containing the v2 Groth16 proving/verifying key files.
    pub proof_setup_dir: String,
    /// Legacy deployments only: let POST /v2/withdraw/clearance reserve a
    /// nullifier without an ownership proof. Circuit zkapi-v2-concession-v1
    /// requires a kind-2 ownership proof: the server refuses to start with
    /// it set.
    pub allow_legacy_clearance: bool,
    /// How long after the server last observed a Merkle root a clearance
    /// ownership proof may use it without a vault read. Any other root is
    /// accepted once the vault's knownRoots(root) holds it (Amendment A1).
    pub clearance_root_window_seconds: u64,
    /// O5: admission refuses (`root_unavailable`) unless the indexer root and
    /// the vault's currentRoot() agreed at most this many seconds ago.
    pub root_max_staleness_seconds: u64,
    /// The operator's per-request exposure ceiling: a request whose lease
    /// budget (`limit_micro_usd(solvency_bound)`) exceeds it is refused.
    /// None disables it; 6,000,000 during the canary, and recommended
    /// permanently.
    pub request_limit_max_usd_micros: Option<u128>,
    /// The vault's challengePeriod(), from the verified deployment binding.
    /// Sets how long a settled request's signature is deferred while an exit
    /// consumes its nullifier (O7) before it becomes ExitedUnsigned: None
    /// (a library embedding without a binding) never ends the deferral.
    pub challenge_period_seconds: Option<u64>,
    /// The deployment manifest (`--deployment`): run_server requires it, to
    /// probe the vault and adapter against it and to bind the database.
    pub deployment: Option<crate::deployment::DeploymentManifest>,
    /// Start even though the database holds leases (or live direct-key
    /// deletions) of a lease key source other than the configured one, which
    /// this server can neither measure nor delete: each such lease is
    /// finalized at its settlement deadline without a usage measurement.
    /// Off by default; startup otherwise refuses until they drain.
    pub allow_key_source_switch: bool,
}

impl ServerConfig {
    pub fn validate_testnet_auth(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.testnet_password.is_none()
                || self.chain_id == crate::testnet_auth::SEPOLIA_CHAIN_ID,
            "ZKAPI_TESTNET_PASSWORD is only supported on Sepolia (chain ID 11155111)"
        );
        Ok(())
    }

    /// Reject incomplete native configurations before startup opens any state.
    pub fn validate_native_mode(&self) -> anyhow::Result<()> {
        self.validate_testnet_auth()?;
        anyhow::ensure!(
            self.native_billing.is_some(),
            "native ETH billing configuration is required"
        );
        anyhow::ensure!(
            self.openrouter_leases.is_some(),
            "native ETH requires prompt-private leases"
        );
        anyhow::ensure!(
            self.request_charge_cap > 0
                && self.request_charge_cap <= crate::native_billing::MAX_SAFE_UNITS,
            "native request cap must fit browser-safe gwei units"
        );
        anyhow::ensure!(
            (MIN_CLEARANCE_ROOT_WINDOW_SECONDS..=MAX_CLEARANCE_ROOT_WINDOW_SECONDS)
                .contains(&self.clearance_root_window_seconds),
            "--clearance-root-window-seconds must be between {MIN_CLEARANCE_ROOT_WINDOW_SECONDS} and {MAX_CLEARANCE_ROOT_WINDOW_SECONDS}"
        );
        anyhow::ensure!(
            !self.allow_legacy_clearance,
            "refusing to start with --allow-legacy-clearance: circuit zkapi-v2-concession-v1 \
             signs a clearance only against a kind-2 ownership proof"
        );
        anyhow::ensure!(
            (1..=MAX_ROOT_MAX_STALENESS_SECONDS).contains(&self.root_max_staleness_seconds),
            "--root-max-staleness-seconds must be between 1 and {MAX_ROOT_MAX_STALENESS_SECONDS}"
        );
        anyhow::ensure!(
            self.request_limit_max_usd_micros
                .is_none_or(|max| max > 0 && max <= crate::native_billing::MAX_SAFE_UNITS),
            "--request-limit-max-usd-micros must be positive and browser-safe"
        );
        Ok(())
    }

    /// The deployment of the state messages this server signs.
    pub fn successor_deployment(&self) -> crate::successor::Deployment {
        crate::successor::Deployment {
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            contract_address: self.contract_address,
        }
    }
}

/// The daemon timing of one documented network (§10.4), checked by the
/// parameter-set test against both startup checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParameterSet {
    pub name: &'static str,
    pub challenge_period_seconds: u64,
    pub ttl_seconds: u64,
    pub settlement_grace_seconds: u64,
    pub settlement_deadline_seconds: u64,
    pub settlement_poll_seconds: u64,
    pub raise_lead_seconds: u64,
}

/// The documented mainnet, Sepolia production and Sepolia drill parameters
/// (§10.4 table).
pub const PARAMETER_SETS: [ParameterSet; 3] = [
    ParameterSet {
        name: "mainnet",
        challenge_period_seconds: 172_800,
        ttl_seconds: 300,
        settlement_grace_seconds: 5,
        settlement_deadline_seconds: 21_600,
        settlement_poll_seconds: 2,
        raise_lead_seconds: 21_600,
    },
    ParameterSet {
        name: "sepolia",
        challenge_period_seconds: 43_200,
        ttl_seconds: 300,
        settlement_grace_seconds: 5,
        settlement_deadline_seconds: 14_400,
        settlement_poll_seconds: 2,
        raise_lead_seconds: 21_600,
    },
    ParameterSet {
        name: "sepolia-drill",
        challenge_period_seconds: 7_200,
        ttl_seconds: 300,
        settlement_grace_seconds: 5,
        settlement_deadline_seconds: 1_800,
        settlement_poll_seconds: 2,
        raise_lead_seconds: 1_800,
    },
];

impl ParameterSet {
    /// The lease timing of this network, with `source` as its key source.
    pub fn lease_config(&self, source: OpenRouterLeaseSourceConfig) -> OpenRouterLeaseConfig {
        OpenRouterLeaseConfig {
            source,
            ttl_seconds: self.ttl_seconds,
            settlement_grace_seconds: self.settlement_grace_seconds,
            settlement_poll_seconds: self.settlement_poll_seconds,
            settlement_deadline_seconds: self.settlement_deadline_seconds,
        }
    }
}

impl std::fmt::Debug for ServerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Exhaustive on purpose: a new field fails to compile here until its
        // author decides whether it is secret.
        let Self {
            protocol_version,
            chain_id,
            testnet_password,
            contract_address,
            request_charge_cap,
            listen_addr,
            db_path,
            state_seed: _,
            clear_seed: _,
            initial_root,
            indexer_url,
            root_poll_interval_ms,
            openrouter_leases,
            native_billing,
            proof_setup_dir,
            allow_legacy_clearance,
            clearance_root_window_seconds,
            root_max_staleness_seconds,
            request_limit_max_usd_micros,
            challenge_period_seconds,
            deployment,
            allow_key_source_switch,
        } = self;
        formatter
            .debug_struct("ServerConfig")
            .field("protocol_version", protocol_version)
            .field("chain_id", chain_id)
            .field("testnet_password", testnet_password)
            .field("contract_address", contract_address)
            .field("request_charge_cap", request_charge_cap)
            .field("listen_addr", listen_addr)
            .field("db_path", db_path)
            .field("state_seed", &"[redacted]")
            .field("clear_seed", &"[redacted]")
            .field("initial_root", initial_root)
            .field("indexer_url", indexer_url)
            .field("root_poll_interval_ms", root_poll_interval_ms)
            .field("openrouter_leases", openrouter_leases)
            // NativeBillingConfig's Debug redacts its RPC URL (provider API keys).
            .field("native_billing", native_billing)
            .field("proof_setup_dir", proof_setup_dir)
            .field("allow_legacy_clearance", allow_legacy_clearance)
            .field(
                "clearance_root_window_seconds",
                clearance_root_window_seconds,
            )
            .field("root_max_staleness_seconds", root_max_staleness_seconds)
            .field("request_limit_max_usd_micros", request_limit_max_usd_micros)
            .field("challenge_period_seconds", challenge_period_seconds)
            .field(
                "deployment",
                &deployment
                    .as_ref()
                    .map(|manifest| &manifest.contract_address),
            )
            .field("allow_key_source_switch", allow_key_source_switch)
            .finish()
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            protocol_version: 2,
            chain_id: 1,
            testnet_password: None,
            contract_address: Felt252::ZERO,
            request_charge_cap: 1_000_000,
            listen_addr: "0.0.0.0:3000".to_string(),
            db_path: "zkapi_server.db".to_string(),
            // Zero means unset; ServerSigner::try_new and run_server reject it.
            state_seed: Felt252::ZERO,
            clear_seed: Felt252::ZERO,
            initial_root: Felt252::ZERO,
            indexer_url: None,
            root_poll_interval_ms: 1_000,
            openrouter_leases: None,
            native_billing: None,
            proof_setup_dir: "protocol/setup/v2-concession".to_string(),
            allow_legacy_clearance: false,
            clearance_root_window_seconds: DEFAULT_CLEARANCE_ROOT_WINDOW_SECONDS,
            root_max_staleness_seconds: DEFAULT_ROOT_MAX_STALENESS_SECONDS,
            request_limit_max_usd_micros: None,
            challenge_period_seconds: None,
            deployment: None,
            allow_key_source_switch: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_config_debug_redacts_signing_seeds_and_credentials() {
        let (state_seed, clear_seed) = crate::signer::strong_test_seeds();
        let mut config = ServerConfig {
            state_seed,
            clear_seed,
            testnet_password: Some(
                crate::testnet_auth::TestnetPassword::new("SECRET-TESTNET-PASSWORD").unwrap(),
            ),
            native_billing: Some(crate::native_billing::NativeBillingConfig {
                rpc_url: "https://eth-mainnet.example/v2/SECRET_PROVIDER_KEY".into(),
                ..crate::test_support::native_config()
            }),
            openrouter_leases: Some(OpenRouterLeaseConfig {
                source: OpenRouterLeaseSourceConfig::OpenRouter {
                    management_key: "sk-or-v1-SECRET_MANAGEMENT_KEY".into(),
                    api_base: "https://openrouter.example/api".into(),
                },
                ..crate::test_support::lease_config()
            }),
            ..Default::default()
        };
        let mut rendered = vec![format!("{config:?}"), format!("{config:#?}")];
        config.openrouter_leases = Some(crate::test_support::lease_config());
        rendered.push(format!("{config:#?}"));
        for output in rendered {
            for secret in [
                state_seed.to_hex(),
                clear_seed.to_hex(),
                state_seed.to_hex()[2..].to_string(),
                clear_seed.to_hex()[2..].to_string(),
                "SECRET_PROVIDER_KEY".into(),
                "SECRET_MANAGEMENT_KEY".into(),
                "SECRET-TESTNET-PASSWORD".into(),
                "test-secret".into(),
            ] {
                assert!(!output.contains(&secret), "{output}");
            }
            assert!(output.contains("[redacted]"));
            assert!(output.contains("chain_id"));
            assert!(output.contains("0x694aa1769357215de4fac081bf1f309adc325306"));
        }
    }

    #[test]
    fn key_source_identity_is_the_endpoint_without_its_credentials() {
        let oa = |url: &str, secret: &str| OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url: url.into(),
            shared_secret: secret.into(),
        };
        let direct = |base: &str, key: &str| OpenRouterLeaseSourceConfig::OpenRouter {
            management_key: key.into(),
            api_base: base.into(),
        };
        assert_eq!(
            oa("https://Org.Example/zkapi/", "a").identity(),
            "https://org.example/zkapi"
        );
        // A rotated credential keeps the identity; another org does not.
        assert_eq!(
            oa("https://org.example", "a").identity(),
            oa("https://org.example/", "b").identity()
        );
        assert_ne!(
            oa("https://org.example", "a").identity(),
            oa("https://other-org.example", "a").identity()
        );
        assert_eq!(
            direct("https://user:pass@openrouter.ai/api/?x=1#f", "sk").identity(),
            "https://openrouter.ai/api"
        );
        assert_eq!(
            direct("https://openrouter.ai/api", "sk-1").identity(),
            direct("https://openrouter.ai/api", "sk-2").identity()
        );
    }

    #[test]
    fn settlement_timing_validation() {
        let lease = crate::test_support::lease_config();
        assert_eq!(
            lease.settlement_deadline_seconds,
            DEFAULT_SETTLEMENT_DEADLINE_SECONDS
        );
        // Defaults fit a 24 h challenge period: 300 + 0 + 21600 + 2 + 600.
        lease.validate_settlement_timing(86_400).unwrap();
        let cli_defaults = OpenRouterLeaseConfig {
            settlement_grace_seconds: 5,
            settlement_poll_seconds: 2,
            ..crate::test_support::lease_config()
        };
        cli_defaults.validate_settlement_timing(86_400).unwrap();
        // Exactly at the bound passes; one second over fails.
        let at_bound = 43_200 - (300 + 600 + 2);
        let mut tight = OpenRouterLeaseConfig {
            settlement_deadline_seconds: at_bound,
            ..crate::test_support::lease_config()
        };
        tight.validate_settlement_timing(86_400).unwrap();
        tight.settlement_deadline_seconds += 1;
        let error = tight
            .validate_settlement_timing(86_400)
            .unwrap_err()
            .to_string();
        assert!(error.contains("challengePeriod()"), "{error}");
        let long = OpenRouterLeaseConfig {
            settlement_deadline_seconds: 43_000,
            ..crate::test_support::lease_config()
        };
        assert!(long.validate_settlement_timing(86_400).is_err());
        // A short challenge period (e.g. a test vault) needs a short deadline.
        assert!(lease.validate_settlement_timing(3_600).is_err());
        // The deadline must leave a retry window after the drain grace.
        let short = OpenRouterLeaseConfig {
            settlement_grace_seconds: 120,
            settlement_deadline_seconds: 120 + MIN_SETTLEMENT_RETRY_WINDOW_SECONDS - 1,
            ..crate::test_support::lease_config()
        };
        let error = short
            .validate_settlement_timing(86_400)
            .unwrap_err()
            .to_string();
        assert!(error.contains("must leave at least 900 s"), "{error}");
        let overflow = OpenRouterLeaseConfig {
            settlement_deadline_seconds: u64::MAX,
            ..crate::test_support::lease_config()
        };
        assert!(overflow.validate_settlement_timing(u64::MAX).is_err());
    }

    #[test]
    fn clearance_root_window_is_bounded() {
        let mut config = ServerConfig {
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        assert!(!config.allow_legacy_clearance);
        config.validate_native_mode().unwrap();
        for window in [0, 59, 86_401] {
            config.clearance_root_window_seconds = window;
            assert!(config.validate_native_mode().is_err(), "{window}");
        }
        for window in [60, 86_400] {
            config.clearance_root_window_seconds = window;
            config.validate_native_mode().unwrap();
        }
    }

    #[test]
    fn this_deployment_refuses_legacy_clearance_and_unbounded_staleness() {
        let mut config = ServerConfig {
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            ..Default::default()
        };
        assert_eq!(config.root_max_staleness_seconds, 60);
        assert_eq!(config.request_limit_max_usd_micros, None);
        config.validate_native_mode().unwrap();
        config.allow_legacy_clearance = true;
        let error = config.validate_native_mode().unwrap_err().to_string();
        assert!(error.contains("--allow-legacy-clearance"), "{error}");
        config.allow_legacy_clearance = false;
        for staleness in [0, MAX_ROOT_MAX_STALENESS_SECONDS + 1] {
            config.root_max_staleness_seconds = staleness;
            assert!(config.validate_native_mode().is_err(), "{staleness}");
        }
        config.root_max_staleness_seconds = 60;
        config.request_limit_max_usd_micros = Some(0);
        assert!(config.validate_native_mode().is_err());
        config.request_limit_max_usd_micros = Some(RECOMMENDED_REQUEST_LIMIT_MAX_USD_MICROS);
        config.validate_native_mode().unwrap();
    }

    /// §10.4: both startup checks pass on every documented network, with the
    /// sums the table records, and fail one second past their bound.
    #[test]
    fn documented_parameter_sets_pass_the_g5_and_raise_checks() {
        let expected = [
            ("mainnet", 21_905, 22_509, 44_713),
            ("sepolia", 14_705, 15_309, 37_513),
            ("sepolia-drill", 2_105, 2_709, 5_113),
        ];
        for (set, (name, window, g5, raise)) in PARAMETER_SETS.iter().zip(expected) {
            assert_eq!(set.name, name);
            let lease = set.lease_config(crate::test_support::lease_config().source);
            assert_eq!(lease.settlement_window_seconds(), window, "{name}");
            assert_eq!(
                window + 2 * set.settlement_poll_seconds + SETTLEMENT_SWEEP_SLACK_SECONDS,
                g5,
                "{name}"
            );
            assert_eq!(
                window
                    + set.raise_lead_seconds
                    + 4 * set.settlement_poll_seconds
                    + RAISE_TIMING_SLACK_SECONDS,
                raise,
                "{name}"
            );
            lease
                .validate_settlement_timing(set.challenge_period_seconds)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            lease
                .validate_raise_timing(set.raise_lead_seconds, set.challenge_period_seconds)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            // One second more of raise lead than the challenge period allows.
            let slack = set.challenge_period_seconds - raise;
            let error = lease
                .validate_raise_timing(
                    set.raise_lead_seconds + slack + 1,
                    set.challenge_period_seconds,
                )
                .unwrap_err()
                .to_string();
            assert!(error.contains("--raise-lead-seconds"), "{name}: {error}");
            lease
                .validate_raise_timing(set.raise_lead_seconds + slack, set.challenge_period_seconds)
                .unwrap();
            // A deadline one second past half the challenge period fails G5.
            let g5_slack = set.challenge_period_seconds / 2 - g5;
            let late = OpenRouterLeaseConfig {
                settlement_deadline_seconds: set.settlement_deadline_seconds + g5_slack + 1,
                ..lease.clone()
            };
            assert!(late
                .validate_settlement_timing(set.challenge_period_seconds)
                .is_err());
        }
        // The drill vault's settlement does not fit a mainnet-sized raise lead.
        let drill = PARAMETER_SETS[2].lease_config(crate::test_support::lease_config().source);
        assert!(drill.validate_raise_timing(21_600, 7_200).is_err());
    }

    /// §10.4: zkapi-challenged's own startup check, from the manifest's
    /// settlement window, agrees with the server's on every documented
    /// network and fails one second past either bound.
    #[test]
    fn challenger_timing_check_passes_the_documented_parameter_sets() {
        for set in PARAMETER_SETS {
            let lease = set.lease_config(crate::test_support::lease_config().source);
            let window = lease.settlement_window_seconds();
            let (poll, lead, period) = (
                set.settlement_poll_seconds,
                set.raise_lead_seconds,
                set.challenge_period_seconds,
            );
            validate_challenger_timing(window, poll, lead, period)
                .unwrap_or_else(|error| panic!("{}: {error}", set.name));
            let raise = window + lead + 4 * poll + RAISE_TIMING_SLACK_SECONDS;
            let error = validate_challenger_timing(window, poll, lead + period - raise + 1, period)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("--raise-lead-seconds"),
                "{}: {error}",
                set.name
            );
            let g5 = window + 2 * poll + SETTLEMENT_SWEEP_SLACK_SECONDS;
            let late_window = window + period / 2 - g5 + 1;
            assert!(
                validate_challenger_timing(late_window, poll, 0, period).is_err(),
                "{}",
                set.name
            );
            validate_challenger_timing(late_window - 1, poll, 0, period).unwrap();
        }
        // Each network's challenger refuses the next tighter network's period.
        let mainnet = PARAMETER_SETS[0];
        assert!(validate_challenger_timing(
            21_905,
            mainnet.settlement_poll_seconds,
            mainnet.raise_lead_seconds,
            PARAMETER_SETS[1].challenge_period_seconds
        )
        .is_err());
    }
}
