//! `zkapi-walletd`: the wallet and prover companion that `zkapi-clientd`
//! runs. It keeps the private note state, proves requests and withdrawals for
//! circuit `zkapi-v2-concession-v1`, and serves the local bridge API.
//!
//! `zkapi-clientd` starts it as
//!
//! ```text
//! zkapi-walletd --require-oa-org-key-source --oa-verifier-url URL \
//!     --openrouter-inference-base URL client --deployment MANIFEST \
//!     --mode direct-openrouter --no-fund --listen HOST:PORT --state-dir DIR
//! ```
//!
//! with `ZKAPI_PROOF_SETUP_DIR`, `OA_ZKAPI_CHAIN_ID` and
//! `OA_ZKAPI_BRIDGE_TOKEN` in its environment.

use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use zkapi_companion::{run, AuthConfig, AuthService, ModelDescriptor, RequestMode};
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

#[derive(Debug, Parser)]
#[command(
    name = "zkapi-walletd",
    about = "zkAPI wallet and prover companion for zkapi-clientd"
)]
struct Cli {
    /// Directory holding the circuit's proving and verifying keys.
    #[arg(long, env = "ZKAPI_PROOF_SETUP_DIR", global = true)]
    proof_setup_dir: Option<PathBuf>,
    /// Trusted OA verifier used for station-issued key validation.
    #[arg(
        long,
        env = "ZKAPI_OA_VERIFIER_URL",
        default_value = "https://verifier2.openanonymity.ai"
    )]
    oa_verifier_url: String,
    /// Trusted OpenRouter inference origin for prompt-private leases.
    #[arg(
        long,
        env = "ZKAPI_OPENROUTER_INFERENCE_BASE",
        default_value = "https://openrouter.ai/api/v1"
    )]
    openrouter_inference_base: String,
    /// Require verifier-backed OA-org keys and reject direct/legacy leases.
    #[arg(long, env = "ZKAPI_REQUIRE_OA_ORG_KEY_SOURCE", default_value_t = false)]
    require_oa_org_key_source: bool,
    /// The user's own Ethereum RPC for exits: the latest exit time, Merkle
    /// path checks and log rebuilds also read through it (design §6.4 E0).
    #[arg(long, env = "ZKAPI_EXIT_RPC_URL", global = true)]
    exit_rpc_url: Option<String>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, Subcommand)]
enum Commands {
    /// Start the local OpenAI/Ollama-compatible client and bridge API for a
    /// published deployment. It never funds a note: deposits are made through
    /// zkapi-clientd.
    Client {
        /// Deployment manifest URL or local JSON path.
        #[arg(long)]
        deployment: String,
        /// Local HTTP address for OpenAI, Responses, and Ollama-compatible APIs.
        #[arg(long, default_value = "127.0.0.1:11434")]
        listen: String,
        /// Managed private wallet state directory. Defaults to a deployment-specific user state path.
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Fresh-note amount suggested to the funding page, in billing base units.
        #[arg(long, default_value_t = 2_000_000)]
        initial_credits: u128,
        /// Accepted for compatibility: this companion never funds a note.
        #[arg(long, hide = true)]
        no_fund: bool,
        /// Do not advertise a test deployment's optional faucet-style mint.
        #[arg(long)]
        skip_mint: bool,
        /// Request transport: server-side proxying, or prompt-private direct OpenRouter leases.
        #[arg(long, value_enum, default_value_t = ClientModeArg::Proxy)]
        mode: ClientModeArg,
    },
    /// Exit kits (`zkapi-exit-kit-v1`): an encrypted backup of the note
    /// state an escape needs, and an escape from one without this device's
    /// wallet, host or operator. The passphrase comes from
    /// ZKAPI_EXIT_KIT_PASSPHRASE, --passphrase-file, or the first line of
    /// standard input.
    ExitKit {
        #[command(subcommand)]
        action: ExitKitAction,
    },
}

#[derive(Debug, Clone, Subcommand)]
enum ExitKitAction {
    /// Write the kit of the wallet in --state-dir.
    Export {
        #[arg(long)]
        state_dir: PathBuf,
        /// The deployment manifest the wallet belongs to.
        #[arg(long)]
        deployment: PathBuf,
        #[arg(long)]
        out: PathBuf,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
    /// Escape from a kit (design §6.4 E4): prints the vault, the calldata and
    /// the payout, or signs and submits with --private-key-file.
    Escape {
        #[arg(long)]
        kit: PathBuf,
        /// The payout address.
        #[arg(long)]
        destination: String,
        /// Your Ethereum RPC: codehash checks, a Merkle path rebuild when the
        /// kit holds none, advisory reads and submission.
        #[arg(long)]
        rpc: Option<String>,
        /// The amount to concede, at most the kit's bound_at_state.
        #[arg(long, default_value_t = 0)]
        conceded: u128,
        /// Where the kit's state, exit lock and released proofs are kept.
        #[arg(long)]
        work_dir: Option<PathBuf>,
        /// Skip the stale-device pre-check: no operator call at all.
        #[arg(long)]
        offline: bool,
        /// Sign and submit with the secp256k1 key in this file (hex).
        #[arg(long, requires = "rpc")]
        private_key_file: Option<PathBuf>,
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ClientModeArg {
    Proxy,
    DirectOpenrouter,
}

impl From<ClientModeArg> for RequestMode {
    fn from(value: ClientModeArg) -> Self {
        match value {
            ClientModeArg::Proxy => RequestMode::Proxy,
            ClientModeArg::DirectOpenrouter => RequestMode::DirectOpenrouter,
        }
    }
}

/// Public client parameters published by a deployment. The companion reads
/// this manifest instead of requiring callers to copy contract addresses and
/// public signing keys into flags.
#[derive(Debug, Deserialize)]
struct DeploymentManifest {
    deployment_id: String,
    protocol_version: u16,
    chain_id: u64,
    rpc_url: String,
    contract_address: String,
    billing_token_address: Option<String>,
    #[serde(default)]
    billing_asset: String,
    #[serde(default)]
    billing_unit: String,
    #[serde(default)]
    native_asset_wei_per_unit: String,
    #[serde(default)]
    native_price_feed_address: String,
    #[serde(default)]
    native_price_feed_decimals: u8,
    #[serde(default)]
    native_price_max_age_seconds: u64,
    #[serde(default)]
    vault_revision: u32,
    /// `not_deployed` for a placeholder profile (design §10.5).
    #[serde(default)]
    deployment_status: Option<String>,
    /// 1 for a vault with the concession exit (revision 3).
    #[serde(default)]
    exit_concession: u8,
    /// W, the build-pinned settlement window (design §6.4 E0).
    #[serde(default)]
    settlement_window_seconds: u64,
    #[serde(default)]
    unsettled_request_escape_after_seconds: Option<u64>,
    #[serde(default)]
    deploy_block: u64,
    #[serde(default)]
    demo_mint_enabled: bool,
    protocol_server_url: String,
    indexer_url: String,
    request_charge_cap: u128,
    proof_backend: String,
    #[serde(default)]
    proof_setup: DeploymentProofSetup,
    state_signing_key: DeploymentCurvePoint,
    clearance_signing_key: DeploymentCurvePoint,
    #[serde(default)]
    models: Vec<ModelDescriptor>,
}

#[derive(Debug, Default, Deserialize)]
struct DeploymentProofSetup {
    #[serde(default)]
    circuit_id: String,
    #[serde(default)]
    setup_id: String,
}

#[derive(Debug, Deserialize)]
struct DeploymentCurvePoint {
    x: String,
    y: String,
}

struct ClientOptions {
    deployment: String,
    listen: String,
    requested_state_dir: Option<PathBuf>,
    suggested_deposit_amount: u128,
    skip_mint: bool,
    request_mode: RequestMode,
    proof_setup_dir: PathBuf,
    oa_verifier_url: String,
    openrouter_inference_base: String,
    require_oa_org_key_source: bool,
    exit_rpc_url: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(log_filter())
        .init();

    let cli = Cli::parse();
    match cli.command {
        Commands::Client {
            deployment,
            listen,
            state_dir,
            initial_credits,
            no_fund: _,
            skip_mint,
            mode,
        } => {
            let proof_setup_dir = cli.proof_setup_dir.ok_or_else(|| {
                anyhow::anyhow!(
                    "set ZKAPI_PROOF_SETUP_DIR (or --proof-setup-dir) to the directory holding this circuit's proving keys"
                )
            })?;
            configure_client_prover_threads()?;
            run_client(ClientOptions {
                deployment,
                listen,
                requested_state_dir: state_dir,
                suggested_deposit_amount: initial_credits,
                skip_mint,
                request_mode: mode.into(),
                proof_setup_dir,
                oa_verifier_url: cli.oa_verifier_url,
                openrouter_inference_base: cli.openrouter_inference_base,
                require_oa_org_key_source: cli.require_oa_org_key_source,
                exit_rpc_url: cli.exit_rpc_url,
            })
            .await
        }
        Commands::ExitKit { action } => run_exit_kit(action, cli.proof_setup_dir).await,
    }
}

fn read_passphrase(file: Option<&std::path::Path>) -> anyhow::Result<String> {
    if let Ok(passphrase) = std::env::var("ZKAPI_EXIT_KIT_PASSPHRASE") {
        return Ok(passphrase);
    }
    let text = match file {
        Some(path) => std::fs::read_to_string(path)?,
        None => {
            eprintln!("Exit kit passphrase:");
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            line
        }
    };
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

async fn run_exit_kit(
    action: ExitKitAction,
    proof_setup_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use zkapi_companion::exit_kit;
    match action {
        ExitKitAction::Export {
            state_dir,
            deployment,
            out,
            passphrase_file,
        } => {
            let manifest: serde_json::Value = serde_json::from_slice(&std::fs::read(&deployment)?)?;
            let contents = exit_kit::export(&state_dir, &manifest)?;
            let passphrase = read_passphrase(passphrase_file.as_deref())?;
            let file = exit_kit::encrypt(&contents, &passphrase)?;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            use std::io::Write;
            let mut handle = options.open(&out)?;
            handle.write_all(&serde_json::to_vec_pretty(&file)?)?;
            handle.sync_all()?;
            println!(
                "wrote {} (note {}, state {}, bound {})",
                out.display(),
                contents.note.note_id,
                contents.state_seq,
                contents.bound_at_state
            );
            Ok(())
        }
        ExitKitAction::Escape {
            kit,
            destination,
            rpc,
            conceded,
            work_dir,
            offline,
            private_key_file,
            passphrase_file,
        } => {
            let proof_setup_dir = proof_setup_dir.ok_or_else(|| {
                anyhow::anyhow!(
                    "set ZKAPI_PROOF_SETUP_DIR (or --proof-setup-dir) to the bundled proving keys"
                )
            })?;
            let file: exit_kit::KitFile = serde_json::from_slice(&std::fs::read(&kit)?)?;
            let contents = exit_kit::decrypt(&file, &read_passphrase(passphrase_file.as_deref())?)?;
            let destination = parse_address(&destination)?;
            let work_dir = work_dir.unwrap_or_else(|| {
                let id = contents.trusted_deployment["deployment_id"]
                    .as_str()
                    .unwrap_or("deployment");
                default_client_state_dir(&format!("exit-kit-{id}-note-{}", contents.note.note_id))
            });
            ensure_private_state_dir(&work_dir)?;
            let mut result = exit_kit::escape(
                &contents,
                &exit_kit::EscapeOptions {
                    destination,
                    conceded,
                    rpc_url: rpc.clone(),
                    work_dir,
                    proof_setup_dir: proof_setup_dir.to_string_lossy().into_owned(),
                    offline,
                },
            )
            .await?;
            if let (Some(key_file), Some(rpc)) = (private_key_file, rpc) {
                let text = std::fs::read_to_string(&key_file)?;
                let secret: [u8; 32] = hex::decode(text.trim().trim_start_matches("0x"))
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| {
                        anyhow::anyhow!("the private key file must hold 32 hex bytes")
                    })?;
                let rpc = zkapi_companion::chain::Rpc::new(&rpc)
                    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
                let to = parse_address(result["to"].as_str().unwrap_or(""))?;
                let hash = exit_kit::sign_and_send(
                    &rpc,
                    &secret,
                    contents.note.chain_id,
                    &to,
                    result["data"].as_str().unwrap_or(""),
                )
                .await?;
                result["transaction_hash"] = serde_json::json!(hash);
            }
            println!("{}", serde_json::to_string_pretty(&result)?);
            Ok(())
        }
    }
}

fn parse_address(text: &str) -> anyhow::Result<[u8; 20]> {
    text.strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .and_then(|bytes| <[u8; 20]>::try_from(bytes).ok())
        .filter(|address| *address != [0; 20])
        .ok_or_else(|| anyhow::anyhow!("{text} is not a nonzero 20-byte 0x address"))
}

fn log_filter() -> tracing_subscriber::EnvFilter {
    const DEFAULT: &str = "warn,zkapi_walletd=info,zkapi_companion=info";
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| DEFAULT.into());
    // ark-r1cs-std instruments fine-grained field operations at INFO under the
    // `r1cs` target. Enabling those spans while proving debug-formats growing
    // constraint systems, turning a ~3-second proof into multi-gigabyte work.
    // Keep them disabled even when a caller uses a broad `RUST_LOG=info`.
    filter.add_directive("r1cs=warn".parse().expect("valid r1cs log directive"))
}

/// Keep local Groth16 generation responsive without allowing arkworks' global
/// Rayon pool to saturate every logical CPU. Advanced callers can override the
/// default before launch with the standard `RAYON_NUM_THREADS` variable.
fn configure_client_prover_threads() -> anyhow::Result<()> {
    if std::env::var_os("RAYON_NUM_THREADS").is_some() {
        tracing::info!("using RAYON_NUM_THREADS for local proof generation");
        return Ok(());
    }
    const DEFAULT_PROVER_THREADS: usize = 2;
    rayon::ThreadPoolBuilder::new()
        .num_threads(DEFAULT_PROVER_THREADS)
        .build_global()
        .map_err(|error| anyhow::anyhow!("failed to configure prover worker threads: {error}"))?;
    tracing::info!(
        prover_threads = DEFAULT_PROVER_THREADS,
        "configured local proof generation"
    );
    Ok(())
}

async fn run_client(options: ClientOptions) -> anyhow::Result<()> {
    validate_oa_bridge_transport()?;
    let manifest = load_deployment_manifest(&options.deployment).await?;
    validate_deployment_manifest(&manifest)?;
    check_setup_directory(&manifest, &options.proof_setup_dir)?;
    let expected_chain: u64 = std::env::var("OA_ZKAPI_CHAIN_ID")
        .unwrap_or_else(|_| "1".to_string())
        .parse()?;
    if manifest.chain_id != expected_chain {
        anyhow::bail!("deployment chain does not match explicitly selected OA network");
    }
    let state_dir = options
        .requested_state_dir
        .clone()
        .unwrap_or_else(|| default_client_state_dir(&manifest.deployment_id));
    ensure_private_state_dir(&state_dir)?;
    let listen = options.listen.clone();
    let request_mode = options.request_mode;
    let service = auth_service_from_manifest(&manifest, state_dir.clone(), options)?;
    service.ensure_request_mode_available().await?;

    let status = service.status().await?;
    match status.note {
        None => eprintln!(
            "No active zkAPI note in {}. Requests will return 402 until a note is funded.",
            state_dir.display()
        ),
        Some(note) if note.current_balance < manifest.request_charge_cap => eprintln!(
            "Warning: active note {} has {} credits, below this deployment's {}-credit minimum proof bound. Paid requests may return 402.",
            note.note_id, note.current_balance, manifest.request_charge_cap
        ),
        Some(_) => {}
    }

    println!("zkAPI local gateway: http://{listen}");
    println!("  Local client page:        http://{listen}/");
    println!("  OpenAI Chat Completions: http://{listen}/v1/chat/completions");
    println!("  OpenAI Responses:        http://{listen}/v1/responses");
    println!("  Ollama Chat:              http://{listen}/api/chat");
    println!("  Models:                   http://{listen}/v1/models");
    match request_mode {
        RequestMode::Proxy => println!("  Privacy mode:             server proxy"),
        RequestMode::DirectOpenrouter => println!(
            "  Privacy mode:             direct OpenRouter (zkAPI server receives no prompts or responses)"
        ),
    }
    run(service, &listen).await
}

/// When zkapi-clientd runs the companion (it sets `OA_ZKAPI_BRIDGE_TOKEN`),
/// every outbound connection must go through its authenticated loopback
/// CONNECT proxy, with no bypass.
fn validate_oa_bridge_transport() -> anyhow::Result<()> {
    if std::env::var_os("OA_ZKAPI_BRIDGE_TOKEN").is_none() {
        return Ok(());
    }
    let proxy = std::env::var("HTTPS_PROXY").map_err(|_| {
        anyhow::anyhow!("OA companion requires the local authenticated CONNECT proxy")
    })?;
    let url = reqwest::Url::parse(&proxy)?;
    anyhow::ensure!(
        url.scheme() == "http"
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "::1"))
            && url.port().is_some()
            && !url.username().is_empty()
            && url.password().is_some_and(|value| value.len() >= 32)
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none(),
        "invalid OA local CONNECT proxy"
    );
    for key in [
        "HTTP_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ] {
        anyhow::ensure!(
            std::env::var(key).as_deref() == Ok(proxy.as_str()),
            "inconsistent OA proxy configuration"
        );
    }
    for key in ["NO_PROXY", "no_proxy"] {
        anyhow::ensure!(
            std::env::var(key).unwrap_or_default().is_empty(),
            "OA proxy bypass is prohibited"
        );
    }
    Ok(())
}

async fn load_deployment_manifest(source: &str) -> anyhow::Result<DeploymentManifest> {
    let bytes = if source.starts_with("https://") || source.starts_with("http://") {
        reqwest::get(source)
            .await
            .map_err(|err| anyhow::anyhow!("failed to fetch deployment manifest {source}: {err}"))?
            .error_for_status()
            .map_err(|err| {
                anyhow::anyhow!("deployment manifest {source} returned an error: {err}")
            })?
            .bytes()
            .await
            .map_err(|err| anyhow::anyhow!("failed to read deployment manifest {source}: {err}"))?
            .to_vec()
    } else {
        std::fs::read(source)
            .map_err(|err| anyhow::anyhow!("failed to read deployment manifest {source}: {err}"))?
    };
    serde_json::from_slice(&bytes)
        .map_err(|err| anyhow::anyhow!("invalid deployment manifest {source}: {err}"))
}

fn validate_deployment_manifest(manifest: &DeploymentManifest) -> anyhow::Result<()> {
    if manifest.protocol_version != 2 {
        anyhow::bail!(
            "deployment {} uses unsupported protocol version {}; expected v2",
            manifest.deployment_id,
            manifest.protocol_version
        );
    }
    if manifest.proof_backend != "groth16_bn254" {
        anyhow::bail!(
            "deployment {} uses unsupported proof backend {}; expected groth16_bn254",
            manifest.deployment_id,
            manifest.proof_backend
        );
    }
    if manifest.proof_setup.circuit_id != zkapi_proof::compact::CIRCUIT_ID {
        anyhow::bail!(
            "deployment {} has an incompatible proof circuit; expected {}. This companion serves only a vault built for that circuit. Keep existing funds and recovery data with the release that matches the deployment",
            manifest.deployment_id,
            zkapi_proof::compact::CIRCUIT_ID
        );
    }
    match manifest.deployment_status.as_deref() {
        None | Some("deployed") => {}
        Some("not_deployed") => anyhow::bail!(
            "deployment_not_deployed: deployment {} is a placeholder; its vault is not deployed yet",
            manifest.deployment_id
        ),
        // Deploy.s.sol's provisional output is never a deployment to use.
        Some(status) => anyhow::bail!(
            "deployment {} has deployment_status {status:?}; only a finalized deployment (\"deployed\") is served",
            manifest.deployment_id
        ),
    }
    if manifest.exit_concession != 1 || manifest.vault_revision < 3 {
        anyhow::bail!(
            "deployment {} has no concession exit (exit_concession 1, vault_revision 3); this companion serves only such a vault",
            manifest.deployment_id
        );
    }
    if manifest.settlement_window_seconds == 0 || manifest.proof_setup.setup_id.is_empty() {
        anyhow::bail!(
            "deployment {} does not pin settlement_window_seconds and proof_setup.setup_id",
            manifest.deployment_id
        );
    }
    if manifest.protocol_server_url.is_empty() || manifest.indexer_url.is_empty() {
        anyhow::bail!(
            "deployment {} is missing public service URLs",
            manifest.deployment_id
        );
    }
    Ok(())
}

/// The proving keys must be the setup the deployment pins: the setup
/// directory's `manifest.json` names its `setup_id` and circuit.
fn check_setup_directory(
    manifest: &DeploymentManifest,
    setup_dir: &std::path::Path,
) -> anyhow::Result<()> {
    #[derive(Deserialize)]
    struct SetupManifest {
        circuit_id: String,
        setup_id: String,
    }
    let path = setup_dir.join("manifest.json");
    let setup: SetupManifest = serde_json::from_slice(
        &std::fs::read(&path)
            .map_err(|error| anyhow::anyhow!("cannot read {}: {error}", path.display()))?,
    )
    .map_err(|error| anyhow::anyhow!("invalid {}: {error}", path.display()))?;
    if setup.circuit_id != zkapi_proof::compact::CIRCUIT_ID
        || setup.setup_id != manifest.proof_setup.setup_id
    {
        anyhow::bail!(
            "the proving setup in {} is {} / {}, but deployment {} pins {} / {}",
            setup_dir.display(),
            setup.circuit_id,
            setup.setup_id,
            manifest.deployment_id,
            zkapi_proof::compact::CIRCUIT_ID,
            manifest.proof_setup.setup_id
        );
    }
    Ok(())
}

fn auth_service_from_manifest(
    manifest: &DeploymentManifest,
    state_dir: PathBuf,
    options: ClientOptions,
) -> anyhow::Result<Arc<AuthService>> {
    let models = if manifest.models.is_empty() {
        vec![ModelDescriptor::new("openai/gpt-4o-mini")]
    } else {
        manifest.models.clone()
    };
    let proof_setup_dir = options
        .proof_setup_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("the proof setup directory must be valid UTF-8"))?
        .to_string();
    AuthService::new(AuthConfig {
        deployment_id: manifest.deployment_id.clone(),
        billing_asset: manifest.billing_asset.clone(),
        billing_unit: manifest.billing_unit.clone(),
        native_asset_wei_per_unit: manifest.native_asset_wei_per_unit.clone(),
        native_price_feed_address: manifest.native_price_feed_address.clone(),
        native_price_feed_decimals: manifest.native_price_feed_decimals,
        native_price_max_age_seconds: manifest.native_price_max_age_seconds,
        vault_revision: manifest.vault_revision,
        setup_id: manifest.proof_setup.setup_id.clone(),
        settlement_window_seconds: manifest.settlement_window_seconds,
        unsettled_request_escape_after_seconds: manifest.unsettled_request_escape_after_seconds,
        deploy_block: manifest.deploy_block,
        exit_rpc_url: options.exit_rpc_url.clone(),
        protocol_version: manifest.protocol_version,
        chain_id: manifest.chain_id,
        contract_address: parse_felt("deployment contract address", &manifest.contract_address)?,
        request_charge_cap: manifest.request_charge_cap,
        policy_charge_cap: 10_000_000,
        policy_enabled: false,
        auth_scheme: zkapi_auth::AuthSchemeKind::StateAnchor,
        protocol_server_url: manifest.protocol_server_url.clone(),
        indexer_url: manifest.indexer_url.clone(),
        listen_addr: options.listen,
        state_dir,
        models,
        suggested_deposit_amount: options.suggested_deposit_amount,
        demo_rpc_url: Some(manifest.rpc_url.clone()),
        demo_billing_token_address: manifest.billing_token_address.clone(),
        demo_mint_enabled: manifest.chain_id == 11_155_111
            && manifest.demo_mint_enabled
            && !options.skip_mint,
        demo_note_ttl_seconds: None,
        proof_setup_dir,
        state_signing_key: parse_curve_point(
            "deployment state signing key",
            &manifest.state_signing_key.x,
            &manifest.state_signing_key.y,
        )?,
        clearance_signing_key: parse_curve_point(
            "deployment clearance signing key",
            &manifest.clearance_signing_key.x,
            &manifest.clearance_signing_key.y,
        )?,
        request_mode: options.request_mode,
        oa_verifier_url: options.oa_verifier_url,
        openrouter_inference_base: options.openrouter_inference_base,
        require_oa_org_key_source: options.require_oa_org_key_source,
    })
    .map_err(Into::into)
}

fn default_client_state_dir(deployment_id: &str) -> PathBuf {
    let state_root = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .map(|path| path.join(".local").join("state"))
        })
        .unwrap_or_else(|| PathBuf::from("."));
    let safe_id: String = deployment_id
        .chars()
        .map(|character| match character {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' => character,
            _ => '_',
        })
        .collect();
    state_root.join("zkapi").join(safe_id)
}

fn ensure_private_state_dir(path: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path).map_err(|err| {
        anyhow::anyhow!("failed to create state directory {}: {err}", path.display())
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).map_err(|err| {
            anyhow::anyhow!("failed to secure state directory {}: {err}", path.display())
        })?;
    }
    Ok(())
}

fn parse_felt(label: &str, value: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(value).map_err(|err| anyhow::anyhow!("invalid {label}: {err}"))
}

fn parse_curve_point(label: &str, x: &str, y: &str) -> anyhow::Result<CurvePointWire> {
    Ok(CurvePointWire {
        x: parse_felt(&format!("{label} x"), x)?,
        y: parse_felt(&format!("{label} y"), y)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact arguments zkapi-clientd passes (`CompanionCommand` in
    /// zkapi-clientd/internal/zkapi/companion.go).
    const CLIENTD_ARGUMENTS: [&str; 17] = [
        "zkapi-walletd",
        "--require-oa-org-key-source",
        "--oa-verifier-url",
        "https://verifier.example",
        "--openrouter-inference-base",
        "https://inference.example/api/v1",
        "client",
        "--deployment",
        "/state/deployment-manifest.json",
        "--mode",
        "direct-openrouter",
        "--no-fund",
        "--listen",
        "127.0.0.1:11499",
        "--state-dir",
        "/state/sepolia/deployment",
        "--proof-setup-dir=/share/zkapi-clientd/proof-setup",
    ];

    #[test]
    fn parses_the_arguments_zkapi_clientd_passes() {
        let cli = Cli::try_parse_from(&CLIENTD_ARGUMENTS[..16]).expect("clientd arguments parse");
        assert!(cli.require_oa_org_key_source);
        assert_eq!(cli.oa_verifier_url, "https://verifier.example");
        assert_eq!(
            cli.openrouter_inference_base,
            "https://inference.example/api/v1"
        );
        match cli.command {
            Commands::Client {
                deployment,
                listen,
                state_dir,
                no_fund,
                mode,
                ..
            } => {
                assert_eq!(deployment, "/state/deployment-manifest.json");
                assert_eq!(listen, "127.0.0.1:11499");
                assert_eq!(state_dir, Some(PathBuf::from("/state/sepolia/deployment")));
                assert!(no_fund);
                assert!(matches!(mode, ClientModeArg::DirectOpenrouter));
            }
            Commands::ExitKit { .. } => panic!("parsed as the client"),
        }
        // The setup directory may also come as a flag (the environment
        // variable is the clientd path).
        let cli = Cli::try_parse_from(CLIENTD_ARGUMENTS).expect("flag form parses");
        assert_eq!(
            cli.proof_setup_dir,
            Some(PathBuf::from("/share/zkapi-clientd/proof-setup"))
        );
    }

    #[test]
    fn client_needs_an_explicit_deployment() {
        assert!(Cli::try_parse_from(["zkapi-walletd", "client"]).is_err());
        let cli = Cli::try_parse_from(["zkapi-walletd", "client", "--deployment", "m.json"])
            .expect("client parse");
        match cli.command {
            Commands::Client {
                initial_credits,
                mode,
                ..
            } => {
                assert_eq!(initial_credits, 2_000_000);
                assert!(matches!(mode, ClientModeArg::Proxy));
            }
            Commands::ExitKit { .. } => panic!("parsed as an exit kit"),
        }
    }

    #[test]
    fn exit_kit_escape_parses_its_arguments() {
        let cli = Cli::try_parse_from([
            "zkapi-walletd",
            "exit-kit",
            "escape",
            "--kit",
            "kit.json",
            "--destination",
            "0x2222222222222222222222222222222222222222",
            "--rpc",
            "http://127.0.0.1:8545",
            "--conceded",
            "500",
        ])
        .unwrap();
        match cli.command {
            Commands::ExitKit {
                action:
                    ExitKitAction::Escape {
                        conceded,
                        rpc,
                        offline,
                        ..
                    },
            } => {
                assert_eq!(conceded, 500);
                assert_eq!(rpc.as_deref(), Some("http://127.0.0.1:8545"));
                assert!(!offline);
            }
            _ => panic!("not an exit kit escape"),
        }
        // A key without an RPC to submit through is refused.
        assert!(Cli::try_parse_from([
            "zkapi-walletd",
            "exit-kit",
            "escape",
            "--kit",
            "k",
            "--destination",
            "0x1",
            "--private-key-file",
            "key",
        ])
        .is_err());
    }

    fn manifest_json() -> serde_json::Value {
        serde_json::json!({
            "deployment_id": "concession-test", "protocol_version": 2,
            "chain_id": 1, "rpc_url": "https://rpc.example",
            "contract_address": "0x1", "billing_token_address": null,
            "protocol_server_url": "https://server.example",
            "indexer_url": "https://indexer.example", "request_charge_cap": 1,
            "proof_backend": "groth16_bn254",
            "vault_revision": 3, "exit_concession": 1,
            "settlement_window_seconds": 21905,
            "state_signing_key": {"x": "0x1", "y": "0x2"},
            "clearance_signing_key": {"x": "0x3", "y": "0x4"}
        })
    }

    #[test]
    fn deployment_manifest_requires_an_explicit_demo_mint_flag() {
        let production: DeploymentManifest = serde_json::from_value(manifest_json()).unwrap();
        assert!(!production.demo_mint_enabled);
        let mut demo = manifest_json();
        demo["demo_mint_enabled"] = serde_json::Value::Bool(true);
        let demo: DeploymentManifest = serde_json::from_value(demo).unwrap();
        assert!(demo.demo_mint_enabled);
    }

    #[test]
    fn deployment_manifest_rejects_other_circuits() {
        let mut json = manifest_json();
        for circuit in [
            None,
            Some(""),
            Some("zkapi-v2-note-bound-v1"),
            Some("unknown-future-circuit"),
        ] {
            json.as_object_mut().unwrap().remove("proof_setup");
            if let Some(circuit_id) = circuit {
                json["proof_setup"] =
                    serde_json::json!({"circuit_id": circuit_id, "setup_id": "dev"});
            }
            let manifest: DeploymentManifest = serde_json::from_value(json.clone()).unwrap();
            let error = validate_deployment_manifest(&manifest)
                .unwrap_err()
                .to_string();
            assert!(error.contains("incompatible proof circuit"), "{error}");
            assert!(error.contains("zkapi-v2-concession-v1"), "{error}");
        }
        json["proof_setup"] =
            serde_json::json!({"circuit_id": "zkapi-v2-concession-v1", "setup_id": "dev"});
        let manifest: DeploymentManifest = serde_json::from_value(json.clone()).unwrap();
        validate_deployment_manifest(&manifest).unwrap();
        // The keys must be the pinned setup.
        let dev = std::path::Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/setup/v2-concession-dev"
        ));
        check_setup_directory(&manifest, dev).unwrap();
        let mut ceremony = json.clone();
        ceremony["proof_setup"]["setup_id"] = serde_json::json!("mpc-1");
        let ceremony: DeploymentManifest = serde_json::from_value(ceremony).unwrap();
        let error = check_setup_directory(&ceremony, dev)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("pins zkapi-v2-concession-v1 / mpc-1"),
            "{error}"
        );
    }

    /// A placeholder profile, a vault without the concession exit and a
    /// profile without the settlement window are refused.
    #[test]
    fn deployment_manifest_requires_a_deployed_concession_vault() {
        let mut base = manifest_json();
        base["proof_setup"] =
            serde_json::json!({"circuit_id": "zkapi-v2-concession-v1", "setup_id": "dev"});
        for (field, value, needle) in [
            (
                "deployment_status",
                serde_json::json!("not_deployed"),
                "deployment_not_deployed",
            ),
            (
                "deployment_status",
                serde_json::json!("pending"),
                "only a finalized deployment",
            ),
            (
                "deployment_status",
                serde_json::json!("simulated"),
                "only a finalized deployment",
            ),
            ("exit_concession", serde_json::json!(0), "concession exit"),
            ("vault_revision", serde_json::json!(2), "concession exit"),
            (
                "settlement_window_seconds",
                serde_json::json!(0),
                "settlement_window_seconds",
            ),
        ] {
            let mut json = base.clone();
            json[field] = value;
            let manifest: DeploymentManifest = serde_json::from_value(json).unwrap();
            let error = validate_deployment_manifest(&manifest)
                .unwrap_err()
                .to_string();
            assert!(error.contains(needle), "{field}: {error}");
        }
    }
}
