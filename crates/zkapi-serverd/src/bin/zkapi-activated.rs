//! Operator-run activation worker of the vault (revision 4): appends the
//! recorded notes to the request tree in proved batches of 16, 4 or 1, so
//! they can make anonymous requests. See docs/activation-worker.md.
use anyhow::Context;
use clap::Parser;
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use zkapi_serverd::{
    activation_service::{
        ActivationService, ActivationServiceConfig, DEFAULT_MAX_ACTIVATION_WAIT_SECONDS,
    },
    activation_status::{self, ActivationAlarmPolicy},
    challenge_service::{DeploymentCheckError, FeePolicy},
    deployment::DeploymentManifest,
};
use zkapi_types::Felt252;

#[derive(Parser)]
#[command(
    about = "Activate the notes a revision-4 vault recorded with proved insertion batches (activateNotes)"
)]
struct Args {
    /// Operator-controlled RPC supporting eth_sendTransaction for --sender
    /// (a signer instance of its own, not the challenger's).
    #[arg(long, env = "ZKAPI_ACTIVATION_RPC_URL", hide_env_values = true)]
    rpc_url: String,
    /// The indexer whose /v1/tree/notes/{id}/path serves the siblings of the
    /// cursor's slot; checked against the vault's currentRoot().
    #[arg(long, env = "ZKAPI_ACTIVATION_INDEXER_URL")]
    indexer_url: String,
    /// Dedicated gas-paying account managed by the configured signer RPC.
    /// Never the challenger's sender: each daemon owns its nonces. It must be
    /// the vault's activator() (the owner's setActivator): until it is, the
    /// worker sends nothing and reports not_activator.
    #[arg(long, env = "ZKAPI_ACTIVATION_SENDER")]
    sender: String,
    /// The deployment manifest (`trusted_deployment` profile): the vault,
    /// adapter and Poseidon codehashes, setup and verifying-key hashes, and
    /// optionally the activator (startup refuses a vault whose activator()
    /// differs).
    #[arg(long, env = "ZKAPI_DEPLOYMENT_MANIFEST")]
    deployment: PathBuf,
    /// Must equal the manifest's; defaults to it.
    #[arg(long)]
    contract_address: Option<String>,
    /// Must equal the manifest's; defaults to it.
    #[arg(long)]
    chain_id: Option<u64>,
    /// The worker's nonce is held until its transaction is this deep.
    #[arg(long, default_value_t = 2)]
    confirmations: u64,
    #[arg(long, env = "ZKAPI_ACTIVATION_CHECKPOINT")]
    checkpoint: PathBuf,
    /// The setup directory holding insertion1.pk, insertion4.pk and
    /// insertion16.pk (and the request and withdrawal verifying keys the
    /// startup probes compare with the adapter).
    #[arg(long, env = "ZKAPI_PROOF_SETUP_DIR")]
    proof_setup_dir: PathBuf,
    #[arg(long, default_value_t = 2000)]
    poll_interval_ms: u64,
    /// Longest wait, from when the oldest pending deposit was first seen, for
    /// a larger aligned batch to fill before a smaller one is proved: at low
    /// volume every deposit is activated alone within this bound.
    #[arg(
        long,
        env = "ZKAPI_MAX_ACTIVATION_WAIT_SECONDS",
        default_value_t = DEFAULT_MAX_ACTIVATION_WAIT_SECONDS
    )]
    max_activation_wait_seconds: u64,
    /// Build, prove and simulate activations without sending them.
    #[arg(long)]
    dry_run: bool,
    /// Highest maxFeePerGas (wei) the worker proposes; at most the signer's cap.
    #[arg(long, env = "ZKAPI_ACTIVATION_MAX_FEE_PER_GAS_WEI")]
    max_fee_per_gas_wei: u128,
    /// Highest maxPriorityFeePerGas (wei); at most the signer's tip cap and at
    /// least twice --priority-fee-per-gas-wei.
    #[arg(long, env = "ZKAPI_ACTIVATION_MAX_PRIORITY_FEE_PER_GAS_WEI")]
    max_priority_fee_per_gas_wei: u128,
    /// Tip of a first attempt (wei).
    #[arg(long, env = "ZKAPI_ACTIVATION_PRIORITY_FEE_PER_GAS_WEI", default_value_t = FeePolicy::DEFAULT_PRIORITY_FEE_PER_GAS)]
    priority_fee_per_gas_wei: u128,
    /// Highest gas limit x maxFeePerGas of one activation (wei); at most the
    /// upstream node's RPC fee cap. Bids also stay within the signer's
    /// tx_fee_cap_wei when it reports a lower one.
    #[arg(
        long,
        env = "ZKAPI_ACTIVATION_TX_FEE_CAP_WEI",
        default_value_t = FeePolicy::DEFAULT_TX_FEE_CAP_WEI,
        value_parser = FeePolicy::parse_tx_fee_cap
    )]
    tx_fee_cap_wei: u128,
    /// Blocks an activation may stay pending before a same-nonce replacement.
    #[arg(long, default_value_t = FeePolicy::DEFAULT_BUMP_AFTER_BLOCKS)]
    fee_bump_after_blocks: u64,
    /// Fee-cap increase of a replacement, in percent (10-100).
    #[arg(long, default_value_t = FeePolicy::DEFAULT_BUMP_PERCENT)]
    fee_bump_percent: u64,
    /// Internal status listener (GET /livez, /health, /status). Never publish it.
    #[arg(
        long,
        env = "ZKAPI_ACTIVATION_STATUS_LISTEN",
        default_value = "127.0.0.1:3003"
    )]
    status_listen: SocketAddr,
    /// The oldest pending note's wait at which the status warns...
    #[arg(long, default_value_t = 600)]
    pending_warning_seconds: u64,
    /// ...and at which it is critical.
    #[arg(long, default_value_t = 3600)]
    pending_critical_seconds: u64,
    #[arg(long, default_value_t = 120)]
    blocked_warning_seconds: u64,
    #[arg(long, default_value_t = 1800)]
    critical_blocked_seconds: u64,
    #[arg(long, default_value_t = 300)]
    stale_poll_seconds: u64,
    #[arg(long, default_value_t = 300)]
    startup_grace_seconds: u64,
    /// Default: 0.75M gas (a 16-note activation) times --max-fee-per-gas-wei,
    /// at most --tx-fee-cap-wei.
    #[arg(long)]
    min_sender_balance_wei: Option<u128>,
}

fn daemon_log_filter(filter: tracing_subscriber::EnvFilter) -> tracing_subscriber::EnvFilter {
    // ark-r1cs-std's INFO spans Debug-format field gadgets, including their
    // entire constraint system. A normal daemon INFO subscriber otherwise
    // makes proving consume gigabytes before it finishes. Never collect these
    // spans, including when an operator enables global debug/trace logging.
    filter.add_directive("r1cs=off".parse().expect("fixed tracing directive"))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(daemon_log_filter(tracing_subscriber::EnvFilter::from_default_env()))
        .init();
    let args = Args::parse();
    anyhow::ensure!(args.poll_interval_ms > 0, "poll interval must be positive");
    let manifest = DeploymentManifest::load(&args.deployment)?;
    let contract_address = match &args.contract_address {
        Some(address) => {
            let address = Felt252::from_hex(address).map_err(anyhow::Error::msg)?;
            anyhow::ensure!(
                format!("0x{}", hex::encode(&address.as_bytes()[12..]))
                    == manifest.contract_address,
                "--contract-address differs from the deployment manifest's {}",
                manifest.contract_address
            );
            address
        }
        None => Felt252::from_hex(&manifest.contract_address).map_err(anyhow::Error::msg)?,
    };
    let chain_id = args.chain_id.unwrap_or(manifest.chain_id);
    anyhow::ensure!(
        chain_id == manifest.chain_id,
        "--chain-id differs from the deployment manifest's {}",
        manifest.chain_id
    );
    if let Some(parent) = args
        .checkpoint
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.checkpoint.with_extension("lock"))?;
    fs2::FileExt::try_lock_exclusive(&lock)
        .context("another activation worker holds this checkpoint")?;
    let alarms = ActivationAlarmPolicy {
        pending_warning_seconds: args.pending_warning_seconds,
        pending_critical_seconds: args.pending_critical_seconds,
        blocked_warning_seconds: args.blocked_warning_seconds,
        critical_blocked_seconds: args.critical_blocked_seconds,
        stale_poll_seconds: args.stale_poll_seconds,
        startup_grace_seconds: args.startup_grace_seconds,
        min_sender_balance_wei: args.min_sender_balance_wei,
    };
    let config = ActivationServiceConfig {
        rpc_url: args.rpc_url,
        indexer_url: args.indexer_url,
        sender: args.sender,
        contract_address,
        chain_id,
        confirmations: args.confirmations,
        checkpoint: args.checkpoint,
        proof_setup_dir: args.proof_setup_dir,
        fee: FeePolicy {
            max_fee_per_gas: args.max_fee_per_gas_wei,
            max_priority_fee_per_gas: args.max_priority_fee_per_gas_wei,
            priority_fee_per_gas: args.priority_fee_per_gas_wei,
            tx_fee_cap_wei: args.tx_fee_cap_wei,
            bump_after_blocks: args.fee_bump_after_blocks,
            bump_percent: args.fee_bump_percent,
        },
        alarms: alarms.clone(),
        max_activation_wait_seconds: args.max_activation_wait_seconds,
        dry_run: args.dry_run,
    };
    let mut service = ActivationService::new(config)?;
    let listener = tokio::net::TcpListener::bind(args.status_listen)
        .await
        .with_context(|| format!("failed to bind --status-listen {}", args.status_listen))?;
    tracing::info!(address = %listener.local_addr()?, "activation status listening (internal only)");
    let status = activation_status::router(service.status_handle(), alarms);
    tokio::spawn(async move {
        if let Err(error) = axum::serve(listener, status).await {
            tracing::error!(error = %error, "activation status listener failed");
        }
    });
    // Never prove for a vault or adapter other than the manifest's, nor with
    // keys whose verifying keys the adapter does not pin.
    loop {
        match service.verify_deployment(&manifest).await {
            Ok(()) => {
                tracing::info!(
                    chain_id,
                    vault = %manifest.contract_address,
                    setup_id = %manifest.setup_id,
                    "deployment verified: startup probes and insertion verifying keys"
                );
                break;
            }
            Err(DeploymentCheckError::Mismatch(message)) => anyhow::bail!(message),
            Err(error) => {
                tracing::warn!(error = %error, "deployment verification will retry");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                }
            }
        }
    }
    let mut ticker = tokio::time::interval(Duration::from_millis(args.poll_interval_ms));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = ticker.tick() => if let Err(error) = service.poll_once().await {
                tracing::error!(error = %error, "activation poll failed; durable work will retry");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::daemon_log_filter;

    #[test]
    fn daemon_logging_never_formats_constraint_witnesses() {
        struct ConstraintWitness;
        impl std::fmt::Debug for ConstraintWitness {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                panic!("constraint witnesses must never reach the formatter");
            }
        }
        for directives in ["info", "trace,r1cs=trace"] {
            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(daemon_log_filter(tracing_subscriber::EnvFilter::new(directives)))
                .with_writer(std::io::sink)
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                assert!(tracing::enabled!(target: "zkapi_activated", tracing::Level::INFO));
                assert!(!tracing::enabled!(target: "r1cs", tracing::Level::INFO));
                let _span = tracing::info_span!(target: "r1cs", "field_arithmetic", witness = ?ConstraintWitness);
            });
        }
    }
}
