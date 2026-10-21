//! Standalone `zkapi-indexerd` binary.
//!
//! Mirrors the same functionality as `zkapi indexer`, but as a first-class
//! daemon binary so it can be packaged into its own container image (Week 9).

use clap::Parser;
use zkapi_indexerd::{run_indexer, IndexerConfig};

#[derive(Debug, Parser)]
#[command(name = "zkapi-indexerd", about = "zkAPI on-chain indexer daemon")]
struct Args {
    /// HTTP listen address.
    #[arg(long, default_value = "0.0.0.0:3001")]
    listen: String,
    /// Ethereum JSON-RPC endpoint to poll. It must serve eth_call by block
    /// hash (EIP-1898) for recent blocks.
    #[arg(long, default_value = "http://127.0.0.1:8545")]
    rpc_url: String,
    /// ZkApiVault contract address (0x-prefixed).
    #[arg(long)]
    contract_address: String,
    /// First block to scan from on a fresh start.
    #[arg(long, default_value_t = 0)]
    from_block: u64,
    /// Poll interval in milliseconds.
    #[arg(long, default_value_t = 1_000)]
    poll_interval_ms: u64,
    /// Path to persist the verified checkpoint across restarts.
    #[arg(long)]
    cursor_path: Option<String>,
    /// Blocks a vault event must be buried before it is committed to the
    /// checkpoint. The served view still tracks the verified head.
    #[arg(long, default_value_t = 12)]
    confirmations: u64,
    /// Expected chain id; the RPC and the checkpoint must match it.
    #[arg(long)]
    chain_id: Option<u64>,
    /// Archive the checkpoint and replay from --from-block.
    #[arg(long)]
    resync: bool,
    /// Seconds without a verified poll before the indexer reports stale (503).
    #[arg(long, default_value_t = 120)]
    stale_after_secs: u64,
    /// Largest eth_getLogs block range.
    #[arg(long, default_value_t = 1_000)]
    max_block_range: u64,
    /// Seconds the RPC head block may age before the indexer reports stale
    /// (503); 0 disables the check for chains that mine on demand.
    #[arg(long, default_value_t = 180)]
    max_head_age_secs: u64,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    run_indexer(IndexerConfig {
        listen_addr: args.listen,
        rpc_url: args.rpc_url,
        contract_address: args.contract_address,
        from_block: args.from_block,
        poll_interval_ms: args.poll_interval_ms,
        cursor_path: args.cursor_path,
        confirmations: args.confirmations,
        chain_id: args.chain_id,
        resync: args.resync,
        stale_after_secs: args.stale_after_secs,
        max_block_range: args.max_block_range,
        max_head_age_secs: args.max_head_age_secs,
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reorg_safety_flags_parse_with_defaults() {
        let args =
            Args::try_parse_from(["zkapi-indexerd", "--contract-address", "0x1234"]).unwrap();
        assert_eq!(args.confirmations, 12);
        assert_eq!(args.chain_id, None);
        assert!(!args.resync);
        assert_eq!(args.stale_after_secs, 120);
        assert_eq!(args.max_block_range, 1_000);
        assert_eq!(args.max_head_age_secs, 180);

        let args = Args::try_parse_from([
            "zkapi-indexerd",
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
        assert_eq!(args.confirmations, 3);
        assert_eq!(args.chain_id, Some(11_155_111));
        assert!(args.resync);
        assert_eq!(args.stale_after_secs, 60);
        assert_eq!(args.max_block_range, 500);
        assert_eq!(args.max_head_age_secs, 0);
    }
}
