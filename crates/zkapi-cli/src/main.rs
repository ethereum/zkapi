use anyhow::Context;
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use zkapi_serverd::config::{OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig};
use zkapi_serverd::nullifier_store::{ReopenOptions, ReopenRefusal, GROTH16_UNVERIFIED};
use zkapi_serverd::signer::ServerSigner;
use zkapi_types::Felt252;

#[derive(Debug, Parser)]
#[command(name = "zkapi", about = "Native ETH zkAPI operator commands")]
struct Cli {
    #[arg(long, default_value_t = 2)]
    protocol_version: u16,
    #[arg(long, default_value_t = 1)]
    chain_id: u64,
    #[arg(long, default_value = "0x0")]
    contract_address: String,
    #[arg(long, default_value_t = 50_000)]
    request_charge_cap: u128,
    // Help must never print environment values (hide_env_values on every env arg).
    #[arg(
        long,
        env = "ZKAPI_PROOF_SETUP_DIR",
        default_value = "protocol/setup/v2-concession",
        hide_env_values = true
    )]
    proof_setup_dir: String,
    /// Drill and acceptance builds only: make serverd misbehave (§5.5). A
    /// release build has no such flag and rejects it.
    #[cfg(feature = "adversary")]
    #[arg(long, value_enum, global = true)]
    adversary: Option<zkapi_serverd::adversary::AdversaryMode>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Generate a fresh development setup in a new directory.
    Setup {
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Derive the deployment-pinned public signing keys for the vault constructor.
    ///
    /// Reads ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED (preferred; flags are visible
    /// in the process list). Both are required hex field elements with no
    /// defaults. Zero, subgroup-order multiples, guessable values, the published
    /// development keys (seeds 0x1/0x2 in any spelling, in either role) and one
    /// seed reused for both roles are rejected. Generate each seed with:
    /// printf '0x%s\n' "$(openssl rand -hex 31)"
    SigningKeys {
        /// State-signing secret seed; overrides ZKAPI_STATE_SEED. No default.
        #[arg(long)]
        state_seed: Option<String>,
        /// Clearance-signing secret seed; overrides ZKAPI_CLEAR_SEED. No default.
        #[arg(long)]
        clear_seed: Option<String>,
    },
    /// Run the native ETH API server.
    ///
    /// ZKAPI_STATE_SEED and ZKAPI_CLEAR_SEED are required and have no
    /// defaults. Startup refuses unless their public keys equal the vault's
    /// immutable stateSigningKeyX/Y and clearanceSigningKeyX/Y, read over
    /// --native-billing-rpc-url, which must serve --chain-id.
    #[command(name = "serverd", alias = "server")]
    Serverd {
        #[arg(long, default_value = "127.0.0.1:3000")]
        listen: String,
        /// OpenRouter management API base for direct lease provisioning.
        #[arg(long, default_value = "https://openrouter.ai/api")]
        openrouter_api_base: String,
        /// OpenRouter Management API key used only to mint bounded runtime leases.
        #[arg(long)]
        openrouter_management_key: Option<String>,
        /// OA org base URL used to obtain station-issued, verifier-backed keys.
        #[arg(long)]
        oa_org_url: Option<String>,
        /// Validity of each prompt-private runtime key.
        #[arg(long, default_value_t = 300)]
        openrouter_lease_ttl_seconds: u64,
        /// Usage propagation delay after key expiry before settlement.
        #[arg(long, default_value_t = 5)]
        openrouter_settlement_grace_seconds: u64,
        #[arg(long, default_value_t = 2)]
        openrouter_settlement_poll_seconds: u64,
        /// Seconds after a lease's issuance + TTL + grace by which an unsettled
        /// lease is finalized: at its measured usage, or at worst at the
        /// request's solvency bound. Startup requires TTL + grace + this +
        /// 2 x poll + 600 <= the vault's challengePeriod() / 2.
        #[arg(
            long,
            env = "ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS",
            default_value_t = zkapi_serverd::config::DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
            hide_env_values = true
        )]
        openrouter_settlement_deadline_seconds: u64,
        /// Legacy deployments only. Circuit zkapi-v2-concession-v1 signs a
        /// clearance only against a kind-2 ownership proof: the server
        /// refuses to start with this set.
        #[arg(
            long,
            env = "ZKAPI_ALLOW_LEGACY_CLEARANCE",
            action = clap::ArgAction::SetTrue,
            value_parser = clap::builder::BoolishValueParser::new(),
            hide_env_values = true
        )]
        allow_legacy_clearance: bool,
        /// The deployment manifest (the trusted_deployment profile the
        /// database was initialized from with `zkapi db init`). Required:
        /// startup probes the vault, adapter and Poseidon library against it.
        #[arg(long, env = "ZKAPI_DEPLOYMENT_MANIFEST", hide_env_values = true)]
        deployment: Option<PathBuf>,
        /// Admission refuses (root_unavailable) unless the indexer root and
        /// the vault's currentRoot() agreed at most this many seconds ago.
        #[arg(
            long,
            env = "ZKAPI_ROOT_MAX_STALENESS_SECONDS",
            default_value_t = zkapi_serverd::config::DEFAULT_ROOT_MAX_STALENESS_SECONDS,
            hide_env_values = true
        )]
        root_max_staleness_seconds: u64,
        /// Refuse a request whose lease budget exceeds this many micro-USD
        /// (the operator's per-request exposure). Unset: no ceiling;
        /// 6000000 during the canary, and recommended permanently.
        #[arg(
            long,
            env = "ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS",
            hide_env_values = true
        )]
        request_limit_max_usd_micros: Option<u128>,
        /// How long a Merkle root the server observed stays acceptable for a
        /// clearance ownership proof without a vault read (60..=86400); any
        /// other root the vault ever held is accepted after one.
        #[arg(
            long,
            env = "ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS",
            default_value_t = zkapi_serverd::config::DEFAULT_CLEARANCE_ROOT_WINDOW_SECONDS,
            hide_env_values = true
        )]
        clearance_root_window_seconds: u64,
        /// Start although the database holds leases of another lease key
        /// source (the other source type, or another OA org URL or OpenRouter
        /// API base), which this server can neither measure nor delete: each
        /// is charged at its settlement deadline without a usage measurement,
        /// normally its full solvency bound. Default off: startup refuses
        /// until the other source drains. For a database holding unsettled
        /// leases of two or more sources, or a source that can no longer be
        /// reached; see docs/native-eth-billing.md, "Changing the key source".
        #[arg(
            long,
            env = "ZKAPI_ALLOW_KEY_SOURCE_SWITCH",
            action = clap::ArgAction::SetTrue,
            value_parser = clap::builder::BoolishValueParser::new(),
            hide_env_values = true
        )]
        allow_key_source_switch: bool,
        /// Required native ETH oracle RPC for gwei billing and the startup vault
        /// signing-key check; must serve --chain-id. May embed a provider key.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_BILLING_RPC_URL",
            required = true,
            hide_env_values = true
        )]
        native_billing_rpc_url: Option<String>,
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_FEED_ADDRESS",
            required = true,
            hide_env_values = true
        )]
        native_price_feed_address: Option<String>,
        /// Must equal the published manifest's native price feed decimals.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_FEED_DECIMALS",
            default_value_t = 8,
            hide_env_values = true
        )]
        native_price_feed_decimals: u8,
        /// Must equal the published manifest's native_price_max_age_seconds.
        #[arg(
            long,
            env = "ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS",
            default_value_t = 4500,
            hide_env_values = true
        )]
        native_price_max_age_seconds: u64,
        #[arg(long, default_value = "zkapi-server.db")]
        db_path: String,
        /// Required state-signing secret seed; overrides ZKAPI_STATE_SEED
        /// (preferred; flags are visible in the process list). No default.
        #[arg(long)]
        state_seed: Option<String>,
        /// Required clearance-signing secret seed; overrides ZKAPI_CLEAR_SEED.
        /// No default.
        #[arg(long)]
        clear_seed: Option<String>,
        /// Merkle root accepted until the indexer serves one. With
        /// --indexer-url, an indexer that cannot serve a verified root at
        /// startup falls back to the vault's currentRoot(), then to this.
        #[arg(long, default_value = "0x0")]
        initial_root: String,
        #[arg(long)]
        indexer_url: Option<String>,
        #[arg(long, default_value_t = 1_000)]
        root_poll_interval_ms: u64,
    },
    Indexer {
        #[arg(long, default_value = "127.0.0.1:3001")]
        listen: String,
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
        #[arg(long)]
        contract_address: String,
        #[arg(long, default_value_t = 0)]
        from_block: u64,
        #[arg(long, default_value_t = 1_000)]
        poll_interval_ms: u64,
        #[arg(long)]
        cursor_path: Option<String>,
        /// Blocks a vault event must be buried before the checkpoint commits it.
        #[arg(long, default_value_t = 12)]
        confirmations: u64,
        /// Expected chain id for the RPC and checkpoint. Separate from the
        /// top-level --chain-id; there is no fallback to its default.
        #[arg(long)]
        chain_id: Option<u64>,
        /// Archive the checkpoint and replay from --from-block.
        #[arg(long)]
        resync: bool,
        /// Seconds without a verified poll before the indexer reports stale.
        #[arg(long, default_value_t = 120)]
        stale_after_secs: u64,
        #[arg(long, default_value_t = 1_000)]
        max_block_range: u64,
        /// Seconds the RPC head may age before the indexer reports stale; 0 disables.
        #[arg(long, default_value_t = 180)]
        max_head_age_secs: u64,
    },
    /// Offline settlement remediation on a stopped API server's database.
    #[command(subcommand)]
    Settlement(SettlementCommand),
    /// Server database administration.
    #[command(subcommand)]
    Db(DbCommand),
}

#[derive(Debug, Clone, Subcommand)]
enum DbCommand {
    /// Create (or migrate) a server database and bind it to a deployment,
    /// before any daemon starts (order: indexer, `zkapi db init`,
    /// zkapi-challenged, serverd).
    ///
    /// Creates the schema, the append-only request_evidence table and its
    /// triggers, and the deployment_binding row from the manifest: chain,
    /// vault, signing keys, challenge period, circuit, setup and verifying-key
    /// hashes. The verifying keys in --proof-setup-dir must be the ones the
    /// manifest pins. serverd verifies the binding against the vault on its
    /// first start. Refuses a placeholder (not_deployed) manifest, a database
    /// bound to anything else, and a database a running server holds.
    Init {
        /// The deployment manifest (trusted_deployment profile).
        #[arg(long)]
        deployment: PathBuf,
        /// The server's SQLite database (the --db-path of serverd).
        #[arg(long)]
        db: PathBuf,
        /// The proof setup the daemons load (defaults to the top-level
        /// --proof-setup-dir).
        #[arg(long = "proof-setup-dir")]
        proof_setup_dir: Option<String>,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum SettlementCommand {
    /// Return a lease cancelled with a `binding_corrupt` review to settlement
    /// after its binding was repaired.
    ///
    /// Stop the API server first: this takes the server's database writer
    /// lock and refuses while a server holds it. It verifies the lease's saved
    /// request against its Groth16 proof with the server's proof setup
    /// (--proof-setup-dir, as for serverd) and refuses one its owner's proof
    /// does not authorize: supply the authentic request with --saved-request.
    /// It refuses while the lease row still disagrees with its nullifier
    /// reservation, naming the field and its repair (--rebind), and for a
    /// clearance-reserved nullifier (its owner exits by mutual close). The
    /// restarted server verifies the request and checks the binding,
    /// deployment and signing key again before signing: a lease never
    /// delivered settles at zero; one that may have been delivered settles at
    /// the usage captured before its direct key was deleted, or from measured
    /// usage until its unchanged settlement deadline, and at its solvency
    /// bound when no usage can be measured (the output then warns).
    ///
    /// With --saved-request, also restores the saved request of a pending
    /// lease that cannot be read (the server skips such a lease, deadline
    /// included, and answers its status with lease_record_unreadable),
    /// after the same checks, keeping its status ("result": "restored").
    Reopen {
        /// The server's SQLite database (the --db-path of serverd).
        #[arg(long)]
        db_path: String,
        /// The lease's id as its binding_corrupt review names it (or the
        /// server's log names an unreadable lease row).
        #[arg(long)]
        client_request_id: String,
        /// Finalize at zero instead (charge_basis "operator_conceded"): the
        /// operator concedes the request's charge. Also concedes a lease
        /// reopened earlier that is not settled yet.
        #[arg(long)]
        zero_charge: bool,
        /// Once the saved request verifies, repair the other side from it:
        /// the lease row's client_request_id and request_nullifier (its
        /// reviews follow a changed id), and the nullifier reservation's
        /// payload hash, request binding, request id and kind, or a missing
        /// reservation row. With --zero-charge, also for a lease reopened
        /// earlier.
        #[arg(long)]
        rebind: bool,
        /// A JSON file (`-` for standard input) holding the authentic
        /// request, restoring a saved request that does not verify or cannot
        /// be read: from a backup of the server database, or its owner's
        /// copy. Accepted only if it verifies, its binding is the one its
        /// nullifier reservation recorded at admission, and it shares the
        /// lease row's client_request_id or request_nullifier. Also for a
        /// pending lease whose saved request cannot be read.
        #[arg(long, value_name = "FILE")]
        saved_request: Option<String>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .init();

    let cli = Cli::parse();
    #[cfg(feature = "adversary")]
    if let Some(mode) = cli.adversary {
        anyhow::ensure!(
            matches!(cli.command, Commands::Serverd { .. }),
            "--adversary applies to serverd only"
        );
        zkapi_serverd::adversary::set(mode)?;
    }

    match cli.command.clone() {
        Commands::Setup { output_dir } => {
            anyhow::ensure!(
                !output_dir.exists(),
                "refusing to overwrite an existing setup directory"
            );
            zkapi_proof::compact::setup(&output_dir)?;
            print_json(&serde_json::json!({
                "status": "ok",
                "proof_backend": "groth16_bn254",
                "output_dir": output_dir,
            }))?;
        }
        Commands::SigningKeys {
            state_seed,
            clear_seed,
        } => {
            let (state_seed, clear_seed) =
                operator_signing_seeds(state_seed, clear_seed, |name| std::env::var(name).ok())?;
            let signer = ServerSigner::try_new(&state_seed, &clear_seed)?;
            print_json(&serde_json::json!({
                "state_signing_key": signer.state_public_key(),
                "clearance_signing_key": signer.clearance_public_key(),
            }))?;
        }
        Commands::Serverd {
            listen,
            openrouter_api_base,
            openrouter_management_key,
            oa_org_url,
            openrouter_lease_ttl_seconds,
            openrouter_settlement_grace_seconds,
            openrouter_settlement_poll_seconds,
            openrouter_settlement_deadline_seconds,
            allow_legacy_clearance,
            deployment,
            root_max_staleness_seconds,
            request_limit_max_usd_micros,
            clearance_root_window_seconds,
            allow_key_source_switch,
            native_billing_rpc_url,
            native_price_feed_address,
            native_price_feed_decimals,
            native_price_max_age_seconds,
            db_path,
            state_seed,
            clear_seed,
            initial_root,
            indexer_url,
            root_poll_interval_ms,
        } => {
            // Fail fast, before any provider or oracle configuration; run_server
            // re-validates the seeds and checks their keys against the vault.
            let (state_seed, clear_seed) =
                operator_signing_seeds(state_seed, clear_seed, |name| std::env::var(name).ok())?;
            let openrouter_api_base_for_leases = openrouter_api_base.clone();
            let openrouter_management_key = resolve_secret(
                openrouter_management_key,
                std::env::var("ZKAPI_OPENROUTER_MANAGEMENT_KEY").ok(),
            );
            let oa_org_shared_secret =
                resolve_secret(None, std::env::var("ZKAPI_OA_ORG_SHARED_SECRET").ok());
            let lease_source = match (openrouter_management_key, oa_org_url, oa_org_shared_secret) {
                (Some(_), Some(_), _) | (Some(_), _, Some(_)) => {
                    anyhow::bail!(
                        "configure either direct OpenRouter management or OA org key issuance, not both"
                    )
                }
                (Some(management_key), None, None) => {
                    Some(OpenRouterLeaseSourceConfig::OpenRouter {
                        management_key,
                        api_base: openrouter_api_base_for_leases,
                    })
                }
                (None, Some(org_base_url), Some(shared_secret)) => {
                    Some(OpenRouterLeaseSourceConfig::OaOrg {
                        org_base_url,
                        shared_secret,
                    })
                }
                (None, Some(_), None) => {
                    anyhow::bail!("--oa-org-url requires an OA org shared secret")
                }
                (None, None, Some(_)) => {
                    anyhow::bail!("an OA org shared secret requires --oa-org-url")
                }
                (None, None, None) => anyhow::bail!(
                    "configure an OA org or OpenRouter management credential for native leases"
                ),
            };
            let openrouter_leases = lease_source.map(|source| OpenRouterLeaseConfig {
                source,
                ttl_seconds: openrouter_lease_ttl_seconds,
                settlement_grace_seconds: openrouter_settlement_grace_seconds,
                settlement_poll_seconds: openrouter_settlement_poll_seconds,
                settlement_deadline_seconds: openrouter_settlement_deadline_seconds,
            });
            let native_billing = match (native_billing_rpc_url, native_price_feed_address) {
                (Some(rpc_url), Some(feed_address)) => {
                    Some(zkapi_serverd::native_billing::NativeBillingConfig {
                        rpc_url,
                        feed_address: feed_address.to_lowercase(),
                        decimals: native_price_feed_decimals,
                        max_age_seconds: native_price_max_age_seconds,
                    })
                }
                _ => anyhow::bail!("native ETH requires both oracle RPC and pinned feed address"),
            };
            let config = ServerConfig {
                protocol_version: cli.protocol_version,
                chain_id: cli.chain_id,
                testnet_password: None, // Loaded from the private server environment at startup.
                contract_address: parse_felt("contract address", &cli.contract_address)?,
                request_charge_cap: cli.request_charge_cap,
                listen_addr: listen,
                db_path,
                state_seed,
                clear_seed,
                initial_root: parse_felt("initial root", &initial_root)?,
                indexer_url,
                root_poll_interval_ms,
                openrouter_leases,
                native_billing,
                proof_setup_dir: cli.proof_setup_dir.clone(),
                allow_legacy_clearance,
                clearance_root_window_seconds,
                root_max_staleness_seconds,
                request_limit_max_usd_micros,
                // From the vault, once run_server has verified the binding.
                challenge_period_seconds: None,
                deployment: deployment
                    .as_deref()
                    .map(zkapi_serverd::deployment::DeploymentManifest::load)
                    .transpose()?,
                allow_key_source_switch,
            };
            zkapi_serverd::routes::run_server(config).await?;
        }
        Commands::Indexer {
            listen,
            rpc_url,
            contract_address,
            from_block,
            poll_interval_ms,
            cursor_path,
            confirmations,
            chain_id,
            resync,
            stale_after_secs,
            max_block_range,
            max_head_age_secs,
        } => {
            let config = zkapi_indexerd::IndexerConfig {
                listen_addr: listen,
                rpc_url,
                contract_address,
                from_block,
                poll_interval_ms,
                cursor_path,
                confirmations,
                chain_id,
                resync,
                stale_after_secs,
                max_block_range,
                max_head_age_secs,
            };
            zkapi_indexerd::run_indexer(config).await?;
        }
        Commands::Db(DbCommand::Init {
            deployment,
            db,
            proof_setup_dir,
        }) => {
            print_json(&init_database(
                &deployment,
                &db,
                proof_setup_dir.as_deref().unwrap_or(&cli.proof_setup_dir),
            )?)?;
        }
        Commands::Settlement(SettlementCommand::Reopen {
            db_path,
            client_request_id,
            zero_charge,
            rebind,
            saved_request,
        }) => {
            let saved_request = saved_request
                .as_deref()
                .map(|path| read_saved_request(path, std::io::stdin()))
                .transpose()?;
            print_json(&reopen_cancelled_lease(
                &db_path,
                &client_request_id,
                ReopenOptions {
                    zero_charge,
                    rebind,
                    saved_request: saved_request.as_ref(),
                },
                &cli.proof_setup_dir,
            )?)?;
        }
    }
    Ok(())
}

/// `zkapi db init`. The manifest and the verifying keys are checked before
/// the database is created.
fn init_database(
    deployment: &std::path::Path,
    db: &std::path::Path,
    proof_setup_dir: &str,
) -> anyhow::Result<zkapi_serverd::deployment::DbInitReport> {
    let manifest = zkapi_serverd::deployment::DeploymentManifest::load(deployment)
        .context("refusing to initialize the database")?;
    let identity = zkapi_serverd::nullifier_store::StatementIdentity::load(proof_setup_dir)
        .context("refusing to initialize the database")?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    zkapi_serverd::deployment::init_database(db, &manifest, &identity, now)
}

/// The request of `--saved-request`: a JSON file, or `-` for `stdin`.
fn read_saved_request(
    path: &str,
    mut stdin: impl std::io::Read,
) -> anyhow::Result<zkapi_types::wire::ApiRequestV2> {
    let text = if path == "-" {
        let mut text = String::new();
        stdin.read_to_string(&mut text).context(
            "refusing to reopen the lease: cannot read --saved-request from standard input",
        )?;
        text
    } else {
        std::fs::read_to_string(path)
            .with_context(|| format!("refusing to reopen the lease: cannot read {path}"))?
    };
    serde_json::from_str(&text).with_context(|| {
        format!("refusing to reopen the lease: --saved-request {path} does not hold a request")
    })
}

/// `zkapi settlement reopen`: holds the server writer lock for its whole run.
/// The request verifier is loaded first, so that a wrong setup directory
/// refuses before the database is touched.
fn reopen_cancelled_lease(
    db_path: &str,
    client_request_id: &str,
    options: ReopenOptions,
    proof_setup_dir: &str,
) -> anyhow::Result<serde_json::Value> {
    let verifier =
        zkapi_proof::compact::RequestVerifier::load(proof_setup_dir).with_context(|| {
            format!(
                "refusing to reopen the lease: cannot load the request verifying key from \
             {proof_setup_dir} (pass the server's --proof-setup-dir or ZKAPI_PROOF_SETUP_DIR)"
            )
        })?;
    let store = zkapi_serverd::nullifier_store::OfflineStore::open(db_path)
        .context("refusing to reopen the lease")?;
    let reopened = store
        .reopen_cancelled_lease(client_request_id, options, &verifier)
        .map_err(|refusal| anyhow::anyhow!("{}", refusal_message(&refusal, proof_setup_dir)))?;
    // A pending lease is not reopened: only its unreadable saved request
    // was restored.
    let result = if reopened.restored_pending {
        "restored"
    } else {
        "reopened"
    };
    let mut report = serde_json::to_value(reopened)?;
    report["result"] = result.into();
    Ok(report)
}

/// Why `zkapi settlement reopen` refused. A Groth16 failure, the only check
/// that depends on the proof setup, also names the setup it was checked with:
/// a wrong --proof-setup-dir must not pass for a corrupt saved request.
fn refusal_message(refusal: &ReopenRefusal, proof_setup_dir: &str) -> String {
    let groth16 = match refusal {
        ReopenRefusal::BindingCorrupt(mismatch) => mismatch.detail == GROTH16_UNVERIFIED,
        ReopenRefusal::SuppliedRequestUnverified(detail) => *detail == GROTH16_UNVERIFIED,
        _ => false,
    };
    if groth16 {
        format!(
            "refusing to reopen the lease: {refusal} (checked with the request verifying key in \
             {proof_setup_dir}; if the server runs with another --proof-setup-dir, run this \
             command with that one first)"
        )
    } else {
        format!("refusing to reopen the lease: {refusal}")
    }
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    const DEFAULT: &str = "warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info";
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT.into());

    // ark-r1cs-std instruments fine-grained field operations at INFO under the
    // `r1cs` target. Enabling those spans while proving debug-formats growing
    // constraint systems, turning a ~3-second proof into multi-gigabyte work.
    // Keep them disabled even when a caller uses a broad `RUST_LOG=info`.
    suppress_r1cs_info(filter)
}

fn suppress_r1cs_info(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    filter.add_directive("r1cs=warn".parse().expect("valid r1cs log directive"))
}

fn parse_felt(label: &str, value: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(value).map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
}

fn resolve_secret(cli_value: Option<String>, env_value: Option<String>) -> Option<String> {
    cli_value.or(env_value).filter(|value| !value.is_empty())
}

/// A required signing seed: the flag wins, an explicit empty flag never falls
/// back to the environment, and there is no default. Never echoes the value.
fn required_seed(
    role: &str,
    flag: &str,
    env_name: &str,
    cli_value: Option<String>,
    env_value: Option<String>,
) -> anyhow::Result<Felt252> {
    let value = resolve_secret(cli_value, env_value).ok_or_else(|| {
        anyhow::anyhow!(
            "{env_name} (or {flag}) is required and must not be empty; there is no default {role} signing seed"
        )
    })?;
    // Felt252::from_hex accepts a sign and slices by byte offset (panicking on
    // non-ASCII text), so admit only plain hex digits before parsing.
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(&value);
    anyhow::ensure!(
        !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit()),
        "{env_name} (or {flag}) must be a hex field element: an optional 0x followed by hex digits"
    );
    Felt252::from_hex(&value).map_err(|error| {
        anyhow::anyhow!("{env_name} (or {flag}) is not a valid {role} seed: {error}")
    })
}

/// Resolve both signing seeds and apply the operator key policy shared with
/// run_server: no zero, subgroup-order multiple, published development key,
/// guessable secret or reused key.
fn operator_signing_seeds(
    state_flag: Option<String>,
    clear_flag: Option<String>,
    env: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<(Felt252, Felt252)> {
    let state_seed = required_seed(
        "state",
        "--state-seed",
        "ZKAPI_STATE_SEED",
        state_flag,
        env("ZKAPI_STATE_SEED"),
    )?;
    let clear_seed = required_seed(
        "clearance",
        "--clear-seed",
        "ZKAPI_CLEAR_SEED",
        clear_flag,
        env("ZKAPI_CLEAR_SEED"),
    )?;
    ServerSigner::try_new(&state_seed, &clear_seed)
        .context("invalid signing seeds (ZKAPI_STATE_SEED / ZKAPI_CLEAR_SEED)")?;
    Ok((state_seed, clear_seed))
}

fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Release builds have no `--adversary` (§5.5): it is an unknown
    /// argument wherever it is placed.
    #[cfg(not(feature = "adversary"))]
    #[test]
    fn release_builds_reject_the_adversary_flag() {
        for argv in [
            ["zkapi", "--adversary", "hang", "serverd"],
            ["zkapi", "serverd", "--adversary", "hang"],
        ] {
            let error = Cli::try_parse_from(argv).unwrap_err();
            assert_eq!(
                error.kind(),
                clap::error::ErrorKind::UnknownArgument,
                "{error}"
            );
        }
    }

    /// Drill builds accept each mode, before or after the subcommand.
    #[cfg(feature = "adversary")]
    #[test]
    fn drill_builds_accept_the_adversary_modes() {
        use zkapi_serverd::adversary::AdversaryMode;
        for (name, mode) in [
            ("withhold", AdversaryMode::Withhold),
            ("born-spent", AdversaryMode::BornSpent),
            ("reuse-anchor", AdversaryMode::ReuseAnchor),
            ("random-anchor", AdversaryMode::RandomAnchor),
            ("overcharge", AdversaryMode::Overcharge),
            ("lie-expired", AdversaryMode::LieExpired),
            ("hang", AdversaryMode::Hang),
        ] {
            let cli = Cli::try_parse_from([
                "zkapi",
                "--adversary",
                name,
                "serverd",
                "--native-billing-rpc-url",
                "https://rpc.example",
                "--native-price-feed-address",
                "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            ])
            .unwrap();
            assert_eq!(cli.adversary, Some(mode));
        }
        assert!(Cli::try_parse_from(["zkapi", "--adversary", "steal", "serverd"]).is_err());
    }

    #[test]
    fn retired_wallet_and_auth_commands_are_rejected() {
        for command in [
            "client",
            "clientd",
            "keygen",
            "prepare-deposit",
            "confirm-deposit",
            "withdraw",
            "request",
        ] {
            assert!(Cli::try_parse_from(["zkapi", command]).is_err());
        }
        assert!(
            Cli::try_parse_from(["zkapi", "--auth-scheme", "blind-signature", "signing-keys"])
                .is_err()
        );
    }

    #[test]
    fn native_server_requires_oracle_and_feed() {
        assert!(Cli::try_parse_from(["zkapi", "serverd"]).is_err());
        assert!(Cli::try_parse_from([
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example"
        ])
        .is_err());
        let cli = Cli::try_parse_from([
            "zkapi",
            "--chain-id",
            "11155111",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--oa-org-url",
            "https://org.example",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Commands::Serverd {
                native_billing_rpc_url: Some(_),
                native_price_feed_address: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn indexer_and_signing_commands_remain_available() {
        assert!(Cli::try_parse_from(["zkapi", "indexer", "--contract-address", "0x1234"]).is_ok());
        assert!(Cli::try_parse_from([
            "zkapi",
            "signing-keys",
            "--state-seed",
            STRONG_STATE_SEED,
            "--clear-seed",
            STRONG_CLEAR_SEED
        ])
        .is_ok());
        assert!(Cli::try_parse_from(["zkapi", "setup"]).is_err());
    }

    // Independent 31-byte seeds that pass the operator key policy.
    const STRONG_STATE_SEED: &str =
        "0x5f3c8a91e2d4b7061a9c3e5f7082b4d6e8f0a1c3b5d7e9f1a2b4c6d8e0f1a3";
    const STRONG_CLEAR_SEED: &str =
        "0x1d7e4b2a9c6f3e8d5b0a7c4e1f9d6b3a8c5e2f7d4a1b9e6c3f8a5d2b7e4c19";

    fn env_with<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.to_string())
        }
    }

    fn state_seed(cli: Option<&str>, env: Option<&str>) -> anyhow::Result<Felt252> {
        required_seed(
            "state",
            "--state-seed",
            "ZKAPI_STATE_SEED",
            cli.map(str::to_string),
            env.map(str::to_string),
        )
    }

    #[test]
    fn signing_seeds_are_mandatory_and_empty_means_missing() {
        for (cli, env) in [
            (None, None),
            (Some(""), None),
            (None, Some("")),
            (Some(""), Some("")),
            (Some(""), Some(STRONG_STATE_SEED)),
        ] {
            let error = state_seed(cli, env).unwrap_err().to_string();
            assert!(
                error.contains("ZKAPI_STATE_SEED (or --state-seed) is required")
                    && error.contains("no default state signing seed"),
                "{cli:?}/{env:?}: {error}"
            );
        }
        // The flag wins over the environment; the environment fills an absent flag.
        let strong = |hex| Felt252::from_hex(hex).unwrap();
        assert_eq!(
            state_seed(Some(STRONG_STATE_SEED), Some(STRONG_CLEAR_SEED)).unwrap(),
            strong(STRONG_STATE_SEED)
        );
        assert_eq!(
            state_seed(None, Some(STRONG_CLEAR_SEED)).unwrap(),
            strong(STRONG_CLEAR_SEED)
        );
    }

    #[test]
    fn seed_values_are_validated_without_echo_or_panic() {
        // A smart quote pasted from a document used to panic inside Felt252::from_hex.
        let smart_quoted = format!("0x{}\u{201d}", "ab".repeat(30));
        let too_long = format!("0x{}", "c".repeat(65));
        for value in [
            smart_quoted.as_str(),
            too_long.as_str(),
            "seed-SECRET-VALUE",
            "+1",
            "0x+1",
            "-1",
            " 0x1",
            "0x1 ",
            "0x",
            "0X",
            "0xg1",
            "0x0x1",
        ] {
            let error = state_seed(Some(value), None).unwrap_err().to_string();
            assert!(error.contains("ZKAPI_STATE_SEED"), "{error}");
            for secret in [smart_quoted.as_str(), too_long.as_str(), "SECRET"] {
                assert!(!error.contains(secret), "{error}");
            }
        }
    }

    #[test]
    fn signing_keys_refuses_development_degenerate_and_reused_seeds() {
        let l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f1";
        let one_plus_l = "0x60c89ce5c263405370a08b6d0302b0bab3eedb83920ee0a677297dc392126f2";
        let two_plus_3l = "0x12259d6b14729c0fa51e1a247090812301bcc928ab62ca1f3657c794ab6374d5";
        for (state, clear) in [
            ("0x1", STRONG_CLEAR_SEED),
            ("1", STRONG_CLEAR_SEED),
            ("0X1", STRONG_CLEAR_SEED),
            ("0x0001", STRONG_CLEAR_SEED),
            ("+1", STRONG_CLEAR_SEED),
            (one_plus_l, STRONG_CLEAR_SEED),
            (STRONG_STATE_SEED, "0x2"),
            (STRONG_STATE_SEED, two_plus_3l),
            ("0x2", "0x1"),
            ("0x0", STRONG_CLEAR_SEED),
            (l, STRONG_CLEAR_SEED),
            ("0x7", "0x8"),
            ("0xb", "0xc"),
            ("0x2a", STRONG_CLEAR_SEED),
            (STRONG_STATE_SEED, "0x63"),
            (STRONG_STATE_SEED, STRONG_STATE_SEED),
        ] {
            // Exactly as `zkapi signing-keys --state-seed .. --clear-seed ..` parses them.
            let cli = Cli::try_parse_from([
                "zkapi",
                "signing-keys",
                "--state-seed",
                state,
                "--clear-seed",
                clear,
            ])
            .unwrap();
            let Commands::SigningKeys {
                state_seed,
                clear_seed,
            } = cli.command
            else {
                panic!("expected signing-keys");
            };
            assert!(
                operator_signing_seeds(state_seed, clear_seed, |_| None).is_err(),
                "{state}/{clear}"
            );
        }
        let (state, clear) = operator_signing_seeds(
            Some(STRONG_STATE_SEED.into()),
            Some(STRONG_CLEAR_SEED.into()),
            |_| None,
        )
        .unwrap();
        assert_eq!(state, Felt252::from_hex(STRONG_STATE_SEED).unwrap());
        assert_eq!(clear, Felt252::from_hex(STRONG_CLEAR_SEED).unwrap());
    }

    #[test]
    fn serverd_explicit_empty_seed_never_falls_back_to_the_environment() {
        let cli = Cli::try_parse_from([
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            "--state-seed",
            "",
        ])
        .unwrap();
        let Commands::Serverd {
            state_seed,
            clear_seed,
            ..
        } = cli.command
        else {
            panic!("expected serverd");
        };
        assert_eq!(state_seed.as_deref(), Some(""));
        let configured = [
            ("ZKAPI_STATE_SEED", STRONG_STATE_SEED),
            ("ZKAPI_CLEAR_SEED", STRONG_CLEAR_SEED),
        ];
        let error = operator_signing_seeds(state_seed, clear_seed, env_with(&configured))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("ZKAPI_STATE_SEED (or --state-seed) is required"),
            "{error}"
        );
        assert!(operator_signing_seeds(None, None, env_with(&configured)).is_ok());
        let swapped = [("ZKAPI_STATE_SEED", "0x2"), ("ZKAPI_CLEAR_SEED", "0x1")];
        let error = operator_signing_seeds(None, None, env_with(&swapped)).unwrap_err();
        assert!(format!("{error:#}").contains("published development key"));
    }

    #[test]
    fn seed_arguments_never_render_environment_values_in_help() {
        use clap::CommandFactory;
        let command = Cli::command();
        let mut env_backed = 0;
        for arg in command.get_arguments().chain(
            command
                .get_subcommands()
                .flat_map(|subcommand| subcommand.get_arguments()),
        ) {
            if arg.get_env().is_some() {
                env_backed += 1;
                assert!(arg.is_hide_env_values_set(), "{}", arg.get_id());
            }
        }
        assert!(env_backed >= 5);
        for name in ["signing-keys", "serverd"] {
            let mut subcommand = command.find_subcommand(name).unwrap().clone();
            for id in ["state_seed", "clear_seed"] {
                let arg = subcommand
                    .get_arguments()
                    .find(|arg| arg.get_id() == id)
                    .unwrap();
                assert!(arg.get_env().is_none(), "{name} {id}");
            }
            let help = subcommand.render_long_help().to_string();
            assert!(help.contains("ZKAPI_STATE_SEED"), "{help}");
            assert!(!help.contains("then 0x1") && !help.contains("then 0x2"));
        }
    }

    #[test]
    fn settlement_and_clearance_flags_default_to_the_safe_values() {
        let base = [
            "zkapi",
            "serverd",
            "--native-billing-rpc-url",
            "https://rpc.example",
            "--native-price-feed-address",
            "0x694AA1769357215DE4FAC081bf1f309aDC325306",
        ];
        let parse = |extra: &[&str]| {
            let mut args = base.to_vec();
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().command {
                Commands::Serverd {
                    openrouter_settlement_deadline_seconds,
                    allow_legacy_clearance,
                    root_max_staleness_seconds,
                    request_limit_max_usd_micros,
                    clearance_root_window_seconds,
                    allow_key_source_switch,
                    deployment,
                    ..
                } => (
                    openrouter_settlement_deadline_seconds,
                    allow_legacy_clearance,
                    root_max_staleness_seconds,
                    request_limit_max_usd_micros,
                    clearance_root_window_seconds,
                    allow_key_source_switch,
                    deployment,
                ),
                _ => panic!("expected serverd"),
            }
        };
        let overridden = parse(&[
            "--openrouter-settlement-deadline-seconds",
            "7200",
            "--allow-legacy-clearance",
            "--root-max-staleness-seconds",
            "30",
            "--request-limit-max-usd-micros",
            "6000000",
            "--clearance-root-window-seconds",
            "600",
            "--allow-key-source-switch",
            "--deployment",
            "/srv/zkapi/deployment.json",
        ]);
        assert_eq!(
            overridden,
            (
                7200,
                true,
                30,
                Some(6_000_000),
                600,
                true,
                Some("/srv/zkapi/deployment.json".into())
            )
        );
        // The proof-less clearance budget is gone with legacy clearance.
        let mut legacy = base.to_vec();
        legacy.extend(["--legacy-clearance-max-per-minute", "5"]);
        assert!(Cli::try_parse_from(legacy).is_err());
        if [
            "ZKAPI_OPENROUTER_SETTLEMENT_DEADLINE_SECONDS",
            "ZKAPI_ALLOW_LEGACY_CLEARANCE",
            "ZKAPI_ROOT_MAX_STALENESS_SECONDS",
            "ZKAPI_REQUEST_LIMIT_MAX_USD_MICROS",
            "ZKAPI_CLEARANCE_ROOT_WINDOW_SECONDS",
            "ZKAPI_ALLOW_KEY_SOURCE_SWITCH",
            "ZKAPI_DEPLOYMENT_MANIFEST",
        ]
        .iter()
        .any(|name| std::env::var_os(name).is_some())
        {
            eprintln!("skipping default checks: a settlement or clearance variable is set");
            return;
        }
        assert_eq!(parse(&[]), (21_600, false, 60, None, 3_600, false, None));
    }

    #[test]
    fn native_price_freshness_defaults_to_the_shipped_4500_seconds() {
        use clap::CommandFactory;
        let command = Cli::command();
        let serverd = command.find_subcommand("serverd").unwrap();
        for (id, env) in [
            (
                "native_price_max_age_seconds",
                "ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS",
            ),
            (
                "native_price_feed_decimals",
                "ZKAPI_NATIVE_PRICE_FEED_DECIMALS",
            ),
        ] {
            let arg = serverd
                .get_arguments()
                .find(|arg| arg.get_id() == id)
                .unwrap();
            assert_eq!(arg.get_env(), Some(std::ffi::OsStr::new(env)));
        }
        if std::env::var_os("ZKAPI_NATIVE_PRICE_MAX_AGE_SECONDS").is_some()
            || std::env::var_os("ZKAPI_NATIVE_PRICE_FEED_DECIMALS").is_some()
        {
            eprintln!("skipping default checks: ZKAPI_NATIVE_PRICE_* is set in this environment");
            return;
        }
        let parse = |extra: &[&str]| {
            let mut args = vec![
                "zkapi",
                "serverd",
                "--native-billing-rpc-url",
                "https://rpc.example",
                "--native-price-feed-address",
                "0x694AA1769357215DE4FAC081bf1f309aDC325306",
            ];
            args.extend_from_slice(extra);
            match Cli::try_parse_from(args).unwrap().command {
                Commands::Serverd {
                    native_price_max_age_seconds,
                    native_price_feed_decimals,
                    ..
                } => (native_price_max_age_seconds, native_price_feed_decimals),
                _ => panic!("expected serverd"),
            }
        };
        assert_eq!(parse(&[]), (4500, 8));
        assert_eq!(
            parse(&[
                "--native-price-max-age-seconds",
                "3600",
                "--native-price-feed-decimals",
                "18"
            ]),
            (3600, 18)
        );
    }

    #[test]
    fn settlement_reopen_takes_the_server_database_and_an_opt_in_concession() {
        let parse = |args: &[&str]| {
            let mut argv = vec!["zkapi", "settlement", "reopen"];
            argv.extend_from_slice(args);
            Cli::try_parse_from(argv).map(|cli| match cli.command {
                Commands::Settlement(SettlementCommand::Reopen {
                    db_path,
                    client_request_id,
                    zero_charge,
                    rebind,
                    saved_request,
                }) => (
                    db_path,
                    client_request_id,
                    zero_charge,
                    rebind,
                    saved_request,
                ),
                _ => panic!("expected settlement reopen"),
            })
        };
        let base = [
            "--db-path",
            "/var/lib/zkapi/server.db",
            "--client-request-id",
            "lease-1",
        ];
        assert_eq!(
            parse(&base).unwrap(),
            (
                "/var/lib/zkapi/server.db".into(),
                "lease-1".into(),
                false,
                false,
                None
            )
        );
        let mut conceded = base.to_vec();
        conceded.push("--zero-charge");
        assert!(parse(&conceded).unwrap().2);
        let mut rebound = base.to_vec();
        rebound.push("--rebind");
        assert!(parse(&rebound).unwrap().3);
        let mut restored = base.to_vec();
        restored.extend(["--saved-request", "-"]);
        assert_eq!(parse(&restored).unwrap().4.as_deref(), Some("-"));
        // No default database and no default lease.
        assert!(parse(&base[..2]).is_err());
        assert!(parse(&base[2..]).is_err());
        assert!(Cli::try_parse_from(["zkapi", "settlement"]).is_err());
    }

    /// A unique scratch directory; the CLI crate has no tempfile dependency.
    fn scratch_directory(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path =
            std::env::temp_dir().join(format!("zkapi-cli-{label}-{}-{nanos}", std::process::id()));
        std::fs::create_dir(&path).unwrap();
        path
    }

    /// The repository's development proof setup, as a test server's
    /// --proof-setup-dir.
    fn setup_directory() -> String {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/setup/v2-concession-dev")
            .to_string_lossy()
            .into_owned()
    }

    /// Review regression (reopen authenticity): the command verifies saved
    /// requests with the server's proof setup. A setup it cannot load refuses
    /// before the database is opened, so nothing is locked or changed.
    #[test]
    fn settlement_reopen_requires_the_server_proof_setup() {
        let cli = Cli::try_parse_from([
            "zkapi",
            "--proof-setup-dir",
            "/srv/zkapi/protocol/setup/v2",
            "settlement",
            "reopen",
            "--db-path",
            "/data/server.db",
            "--client-request-id",
            "lease-1",
        ])
        .unwrap();
        assert_eq!(cli.proof_setup_dir, "/srv/zkapi/protocol/setup/v2");
        let directory = scratch_directory("reopen-setup");
        let missing_setup = directory.join("no-setup");
        let missing_database = directory.join("server.db");
        let error = reopen_cancelled_lease(
            missing_database.to_str().unwrap(),
            "lease-1",
            ReopenOptions::default(),
            missing_setup.to_str().unwrap(),
        )
        .unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains("request verifying key"), "{message}");
        assert!(message.contains("--proof-setup-dir"), "{message}");
        // Refused before the database: not even a missing one is reported.
        assert!(!message.contains("no server database"), "{message}");
        assert!(!missing_database.exists());
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// Review regression (reopen authenticity): a Groth16 refusal, the only
    /// one that depends on the proof setup, names the setup it was checked
    /// with, so that a wrong --proof-setup-dir is not taken for a corrupt
    /// saved request; other refusals are unchanged.
    #[test]
    fn groth16_refusal_names_the_proof_setup_it_used() {
        use zkapi_serverd::nullifier_store::{BindingMismatch, SAVED_REQUEST_FIELD};
        let setup = "/srv/zkapi/protocol/setup/v2";
        let groth16 = ReopenRefusal::BindingCorrupt(BindingMismatch {
            field: SAVED_REQUEST_FIELD,
            detail: GROTH16_UNVERIFIED,
        });
        let message = refusal_message(&groth16, setup);
        assert!(message.contains("from a backup"), "{message}");
        assert!(message.contains(setup), "{message}");
        let tag = ReopenRefusal::BindingCorrupt(BindingMismatch {
            field: SAVED_REQUEST_FIELD,
            detail: "is not the request its proof authorized: the authorization tag does not \
                     bind its client_request_id and payload",
        });
        assert!(!refusal_message(&tag, setup).contains(setup));
        // So does one of a request supplied with --saved-request.
        let supplied = ReopenRefusal::SuppliedRequestUnverified(GROTH16_UNVERIFIED);
        let message = refusal_message(&supplied, setup);
        assert!(message.contains("--saved-request"), "{message}");
        assert!(message.contains(setup), "{message}");
        assert_eq!(
            refusal_message(&ReopenRefusal::NotBindingCorrupt, setup),
            format!(
                "refusing to reopen the lease: {}",
                ReopenRefusal::NotBindingCorrupt
            )
        );
    }

    /// A lease request as serverd stores it (a fixture: its proof does not
    /// verify).
    fn lease_request_json() -> serde_json::Value {
        serde_json::json!({
            "client_request_id": "lease-1", "payload": "{}", "payload_hash": "0x1",
            "public_inputs": {
                "protocol_version": 2, "chain_id": 1, "contract_address": "0x7b",
                "active_root": "0x0", "state_signing_key_x": "0x1", "state_signing_key_y": "0x2",
                "request_time": 1, "solvency_bound": 10, "request_nullifier": "0x99",
                "authorization_tag": "0x3", "anonymous_commitment_x": "0x4",
                "anonymous_commitment_y": "0x5"
            },
            // 256 zero bytes: the size of a Groth16 proof (it does not verify).
            "proof": {"backend": "groth16_bn254", "proof": "A".repeat(340) + "AA=="}
        })
    }

    /// Review regression (corrupt saved request): --saved-request reads the
    /// authentic request from a file (a database backup's
    /// api_request_json, or its owner's copy) or from standard input, and
    /// refuses anything that is not a request before the database is opened.
    #[test]
    fn saved_request_is_read_from_a_file_or_standard_input() {
        let text = lease_request_json().to_string();
        let directory = scratch_directory("saved-request");
        let file = directory.join("request.json");
        std::fs::write(&file, format!("{text}\n")).unwrap();
        let from_file = read_saved_request(file.to_str().unwrap(), std::io::empty()).unwrap();
        let from_stdin = read_saved_request("-", text.as_bytes()).unwrap();
        assert_eq!(from_file.client_request_id, "lease-1");
        assert_eq!(
            serde_json::to_value(&from_file).unwrap(),
            serde_json::to_value(&from_stdin).unwrap()
        );
        let error = read_saved_request("-", r#"{"prepared_request": {}}"#.as_bytes()).unwrap_err();
        assert!(
            format!("{error:#}").contains("does not hold a request"),
            "{error:#}"
        );
        let missing = directory.join("missing.json");
        let error = read_saved_request(missing.to_str().unwrap(), std::io::empty()).unwrap_err();
        assert!(format!("{error:#}").contains("cannot read"), "{error:#}");
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn settlement_reopen_refuses_without_changing_the_database() {
        use zkapi_serverd::nullifier_store::{NullifierStore, OfflineStore};
        let directory = scratch_directory("reopen");
        let setup = setup_directory();
        let conceded = ReopenOptions {
            zero_charge: true,
            rebind: false,
            saved_request: None,
        };
        let missing = directory.join("missing.db");
        let error = reopen_cancelled_lease(
            missing.to_str().unwrap(),
            "lease-1",
            ReopenOptions::default(),
            &setup,
        )
        .unwrap_err();
        assert!(
            format!("{error:#}").contains("no server database"),
            "{error:#}"
        );
        assert!(!missing.exists());

        let path = directory.join("server.db");
        let request: zkapi_types::wire::ApiRequestV2 =
            serde_json::from_value(lease_request_json()).unwrap();
        {
            let store = NullifierStore::new(&path).unwrap();
            store.reserve_openrouter_lease(&request).unwrap();
            store
                .create_openrouter_lease(&request, "oa_org", 10, 20, 21, 1.0)
                .unwrap();
        }
        let db_path = path.to_str().unwrap();
        // A lease that was never cancelled is not reopened.
        let error = reopen_cancelled_lease(db_path, "lease-1", ReopenOptions::default(), &setup)
            .unwrap_err();
        assert!(format!("{error:#}").contains("not cancelled"), "{error:#}");
        let error = reopen_cancelled_lease(db_path, "lease-2", conceded, &setup).unwrap_err();
        assert!(format!("{error:#}").contains("no lease"), "{error:#}");
        // Nothing runs while another holder (a server) has the writer lock.
        let held = OfflineStore::open(&path).unwrap();
        let error = reopen_cancelled_lease(db_path, "lease-1", ReopenOptions::default(), &setup)
            .unwrap_err();
        assert!(format!("{error:#}").contains("writer lock"), "{error:#}");
        drop(held);
        assert_eq!(
            NullifierStore::new(&path)
                .unwrap()
                .lookup_openrouter_lease("lease-1")
                .unwrap()
                .status,
            "provisioning"
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    /// A deployment manifest of the development setup.
    fn dev_manifest(
        identity: &zkapi_serverd::nullifier_store::StatementIdentity,
    ) -> serde_json::Value {
        let signer = ServerSigner::new(&Felt252::from_u64(11), &Felt252::from_u64(12));
        let hash = |byte: u8| format!("0x{}", hex_byte(byte).repeat(32));
        serde_json::json!({
            "trusted_deployment": {
                "deployment_id": "cli-test",
                "chain_id": 11155111,
                "contract_address": "0x00000000000000000000000000000000000000aa",
                "state_signing_key": signer.state_public_key(),
                "clearance_signing_key": signer.clearance_public_key(),
                "challenge_period": 43200,
                "circuit_id": identity.circuit_id,
                "setup_id": identity.setup_id,
                "request_vk_keccak256": identity.request_vk_keccak256,
                "withdrawal_vk_keccak256": identity.withdrawal_vk_keccak256,
                "vault_runtime_codehash": hash(1),
                "proof_adapter_address": "0x00000000000000000000000000000000000000bb",
                "adapter_runtime_codehash": hash(2),
                "poseidon_library_address": "0x00000000000000000000000000000000000000cc",
                "poseidon_runtime_codehash": hash(3),
            }
        })
    }

    fn hex_byte(byte: u8) -> String {
        format!("{byte:02x}")
    }

    #[test]
    fn db_init_parses_its_flags() {
        let cli = Cli::try_parse_from([
            "zkapi",
            "db",
            "init",
            "--deployment",
            "/srv/zkapi/deployment.json",
            "--db",
            "/data/server.db",
            "--proof-setup-dir",
            "/srv/zkapi/protocol/setup/v2-concession",
        ])
        .unwrap();
        match cli.command {
            Commands::Db(DbCommand::Init {
                deployment,
                db,
                proof_setup_dir,
            }) => {
                assert_eq!(deployment, PathBuf::from("/srv/zkapi/deployment.json"));
                assert_eq!(db, PathBuf::from("/data/server.db"));
                assert_eq!(
                    proof_setup_dir.as_deref(),
                    Some("/srv/zkapi/protocol/setup/v2-concession")
                );
            }
            _ => panic!("expected db init"),
        }
        // No default manifest or database.
        assert!(Cli::try_parse_from(["zkapi", "db", "init", "--db", "/data/server.db"]).is_err());
        assert!(
            Cli::try_parse_from(["zkapi", "db", "init", "--deployment", "/srv/d.json"]).is_err()
        );
    }

    /// `zkapi db init` creates the schema (with the append-only evidence
    /// table) and the deployment binding from the manifest, idempotently,
    /// and refuses a placeholder, a manifest of other verifying keys, and a
    /// database bound to another deployment, changing nothing.
    #[test]
    fn db_init_binds_a_database_to_the_manifest() {
        use zkapi_serverd::nullifier_store::{NullifierStore, StatementIdentity};
        let directory = scratch_directory("db-init");
        let setup = setup_directory();
        let identity = StatementIdentity::load(&setup).unwrap();
        let manifest = directory.join("deployment.json");
        let db = directory.join("server.db");
        let write =
            |value: &serde_json::Value| std::fs::write(&manifest, value.to_string()).unwrap();

        let mut placeholder = dev_manifest(&identity);
        placeholder["trusted_deployment"]["deployment_status"] = "not_deployed".into();
        write(&placeholder);
        let error = init_database(&manifest, &db, &setup).unwrap_err();
        assert!(format!("{error:#}").contains("not_deployed"), "{error:#}");
        let mut other_keys = dev_manifest(&identity);
        other_keys["trusted_deployment"]["request_vk_keccak256"] =
            format!("0x{}", "ab".repeat(32)).into();
        write(&other_keys);
        let error = init_database(&manifest, &db, &setup).unwrap_err();
        assert!(format!("{error:#}").contains("do not match"), "{error:#}");
        assert!(!db.exists());
        let missing_setup = directory.join("no-setup");
        write(&dev_manifest(&identity));
        assert!(init_database(&manifest, &db, missing_setup.to_str().unwrap()).is_err());
        assert!(!db.exists());

        let report = init_database(&manifest, &db, &setup).unwrap();
        assert_eq!(report.result, "bound");
        assert_eq!(report.binding_source, "manifest");
        let binding = NullifierStore::open_read_only(&db)
            .unwrap()
            .read_deployment_binding()
            .unwrap()
            .unwrap();
        assert_eq!(binding.chain_id, 11155111);
        assert_eq!(binding.challenge_period_seconds, 43200);
        assert_eq!(binding.setup_id.as_deref(), Some("dev"));
        assert_eq!(
            binding.request_vk_keccak256.as_deref(),
            Some(identity.request_vk_keccak256.as_str())
        );
        assert_eq!(
            init_database(&manifest, &db, &setup).unwrap().result,
            "already_bound"
        );
        let mut moved = dev_manifest(&identity);
        moved["trusted_deployment"]["contract_address"] =
            "0x00000000000000000000000000000000000000dd".into();
        write(&moved);
        let error = init_database(&manifest, &db, &setup).unwrap_err();
        assert!(
            format!("{error:#}").contains("bound to another vault"),
            "{error:#}"
        );
        assert_eq!(
            NullifierStore::open_read_only(&db)
                .unwrap()
                .read_deployment_binding()
                .unwrap()
                .unwrap(),
            binding
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn indexer_accepts_reorg_safety_flags() {
        let cli =
            Cli::try_parse_from(["zkapi", "indexer", "--contract-address", "0x1234"]).unwrap();
        let Commands::Indexer {
            confirmations,
            chain_id,
            resync,
            stale_after_secs,
            max_block_range,
            max_head_age_secs,
            ..
        } = cli.command
        else {
            panic!("expected the indexer command");
        };
        assert_eq!(confirmations, 12);
        assert_eq!(chain_id, None, "no fallback to the top-level --chain-id");
        assert!(!resync);
        assert_eq!(stale_after_secs, 120);
        assert_eq!(max_block_range, 1_000);
        assert_eq!(max_head_age_secs, 180);

        let cli = Cli::try_parse_from([
            "zkapi",
            "--chain-id",
            "1",
            "indexer",
            "--contract-address",
            "0x1234",
            "--confirmations",
            "3",
            "--chain-id",
            "11155111",
            "--resync",
            "--stale-after-secs",
            "60",
            "--max-block-range",
            "500",
            "--max-head-age-secs",
            "0",
        ])
        .unwrap();
        assert_eq!(cli.chain_id, 1);
        let Commands::Indexer {
            confirmations,
            chain_id,
            resync,
            stale_after_secs,
            max_block_range,
            max_head_age_secs,
            ..
        } = cli.command
        else {
            panic!("expected the indexer command");
        };
        assert_eq!(confirmations, 3);
        assert_eq!(chain_id, Some(11_155_111));
        assert!(resync);
        assert_eq!(stale_after_secs, 60);
        assert_eq!(max_block_range, 500);
        assert_eq!(max_head_age_secs, 0);
    }
}
