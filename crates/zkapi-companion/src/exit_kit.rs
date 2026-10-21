//! Exit kits (design §6.4 E7): `zkapi-exit-kit-v1`.
//!
//! A kit is the encrypted state an escape needs when neither the browser
//! host nor this device's wallet is available: the trusted deployment
//! profile, the note's secret and current signed state (`s`, `note_id`, `D`,
//! expiry, `B`, `r`, `τ`, `τ_prev`, `σ`), `bound_at_state`, `state_seq`,
//! `exported_at`, and the deposit-time Merkle path when one was kept.
//!
//! File format (JSON), the browser SDK's (`sdk/services/zkapiExitKit.mjs`):
//!
//! ```text
//! { "format": "zkapi-exit-kit-v1",
//!   "kdf": {"name": "PBKDF2", "hash": "SHA-256", "iterations": 600000, "salt": base64(16 bytes)},
//!   "cipher": {"name": "AES-256-GCM", "iv": base64(12 bytes)},
//!   "ciphertext": base64(AES-256-GCM(JSON contents), AAD "zkapi-exit-kit-v1") }
//! ```
//!
//! The contents carry the deposit-time path as
//! `merkle_path: {active_root, siblings}`. Kits written by earlier builds
//! of this crate (`"kdf": {"name": "PBKDF2-SHA256"}`, the path as
//! `deposit_path: {root, siblings}`) are read too, and amounts and counters
//! in the note may be JSON numbers or decimal strings.
//!
//! `zkapi-walletd exit-kit escape` runs E4 from a kit with the bundled keys:
//! a path from the kit or a rebuild through the user's RPC, the stale-device
//! pre-check, the codehash pins (advisory for exits), an escape conceding at
//! most `bound_at_state`. It prints the vault and calldata, or signs and
//! submits the transaction with a key the user supplies.

use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use base64::Engine;
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use zkapi_client::config::{ClientConfig, ClientProofMode};
use zkapi_client::exit_lock::ExitMode;
use zkapi_client::note_state::{DepositPath, NoteState};
use zkapi_client::wallet::Wallet;
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

use crate::chain::{self, Rpc};

pub const KIT_FORMAT: &str = "zkapi-exit-kit-v1";
pub const KIT_ITERATIONS: u32 = 600_000;

/// The decrypted contents of a kit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitContents {
    pub format: String,
    /// The deployment profile the note belongs to (the companion's deployment
    /// manifest, or a browser build's `trusted_deployment`).
    pub trusted_deployment: Value,
    /// The note's secret and current state.
    pub note: NoteState,
    /// Decimal.
    pub bound_at_state: String,
    pub state_seq: u64,
    pub exported_at: u64,
    /// The deposit-time Merkle path (Amendment A1), as the SDK writes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merkle_path: Option<KitMerklePath>,
    /// The same path as kits of earlier builds of this crate wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit_path: Option<DepositPath>,
}

/// A kit's deposit-time Merkle path: the root its deposit set and the
/// note's siblings there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KitMerklePath {
    pub active_root: Felt252,
    pub siblings: Vec<Felt252>,
}

impl KitContents {
    /// The kit's deposit-time path, in either encoding.
    pub fn path(&self) -> Option<DepositPath> {
        self.merkle_path
            .as_ref()
            .map(|path| DepositPath {
                root: path.active_root,
                siblings: path.siblings.clone(),
            })
            .or_else(|| self.deposit_path.clone())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KitKdf {
    /// `PBKDF2` with `hash` `SHA-256` (the SDK's WebCrypto names), or
    /// `PBKDF2-SHA256` without `hash` (earlier builds of this crate).
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    hash: Option<String>,
    iterations: u32,
    salt: String,
}

impl KitKdf {
    fn is_pbkdf2_sha256(&self) -> bool {
        matches!(
            (self.name.as_str(), self.hash.as_deref()),
            ("PBKDF2", Some("SHA-256")) | ("PBKDF2-SHA256", None | Some("SHA-256"))
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct KitCipher {
    name: String,
    iv: String,
}

/// The encrypted kit file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KitFile {
    format: String,
    kdf: KitKdf,
    cipher: KitCipher,
    ciphertext: String,
}

fn kit_error(message: impl Into<String>) -> anyhow::Error {
    anyhow::anyhow!("exit kit: {}", message.into())
}

fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> anyhow::Result<[u8; 32]> {
    let iterations = NonZeroU32::new(iterations)
        .filter(|count| count.get() <= 20_000_000)
        .ok_or_else(|| kit_error("invalid PBKDF2 iteration count"))?;
    let mut key = [0u8; 32];
    ring::pbkdf2::derive(
        ring::pbkdf2::PBKDF2_HMAC_SHA256,
        iterations,
        salt,
        passphrase.as_bytes(),
        &mut key,
    );
    Ok(key)
}

/// Encrypt `contents` under `passphrase` with `iterations` PBKDF2 rounds.
pub fn encrypt_with_iterations(
    contents: &KitContents,
    passphrase: &str,
    iterations: u32,
) -> anyhow::Result<KitFile> {
    seal(&serde_json::to_vec(contents)?, passphrase, iterations)
}

/// Seal the JSON contents `plain` into a kit file.
fn seal(plain: &[u8], passphrase: &str, iterations: u32) -> anyhow::Result<KitFile> {
    if passphrase.chars().count() < 12 {
        return Err(kit_error("the passphrase must have at least 12 characters"));
    }
    let random = SystemRandom::new();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 12];
    random
        .fill(&mut salt)
        .and_then(|_| random.fill(&mut iv))
        .map_err(|_| kit_error("no system randomness"))?;
    let key = derive_key(passphrase, &salt, iterations)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key).map_err(|_| kit_error("invalid key"))?,
    );
    let mut sealed = plain.to_vec();
    key.seal_in_place_append_tag(
        Nonce::assume_unique_for_key(iv),
        Aad::from(KIT_FORMAT.as_bytes()),
        &mut sealed,
    )
    .map_err(|_| kit_error("encryption failed"))?;
    let b64 = base64::engine::general_purpose::STANDARD;
    Ok(KitFile {
        format: KIT_FORMAT.into(),
        kdf: KitKdf {
            name: "PBKDF2".into(),
            hash: Some("SHA-256".into()),
            iterations,
            salt: b64.encode(salt),
        },
        cipher: KitCipher {
            name: "AES-256-GCM".into(),
            iv: b64.encode(iv),
        },
        ciphertext: b64.encode(sealed),
    })
}

pub fn encrypt(contents: &KitContents, passphrase: &str) -> anyhow::Result<KitFile> {
    encrypt_with_iterations(contents, passphrase, KIT_ITERATIONS)
}

pub fn decrypt(file: &KitFile, passphrase: &str) -> anyhow::Result<KitContents> {
    if file.format != KIT_FORMAT
        || !file.kdf.is_pbkdf2_sha256()
        || file.cipher.name != "AES-256-GCM"
    {
        return Err(kit_error(format!("not a {KIT_FORMAT} file")));
    }
    let b64 = base64::engine::general_purpose::STANDARD;
    let salt = b64
        .decode(&file.kdf.salt)
        .map_err(|_| kit_error("invalid salt"))?;
    let iv: [u8; 12] = b64
        .decode(&file.cipher.iv)
        .ok()
        .and_then(|iv| iv.try_into().ok())
        .ok_or_else(|| kit_error("invalid IV"))?;
    let mut sealed = b64
        .decode(&file.ciphertext)
        .map_err(|_| kit_error("invalid ciphertext"))?;
    let key = derive_key(passphrase, &salt, file.kdf.iterations)?;
    let key = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, &key).map_err(|_| kit_error("invalid key"))?,
    );
    let plain = key
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(KIT_FORMAT.as_bytes()),
            &mut sealed,
        )
        .map_err(|_| kit_error("wrong passphrase, or the kit was altered"))?;
    let mut value: Value = serde_json::from_slice(plain)?;
    normalize_contents(&mut value);
    let contents: KitContents = serde_json::from_value(value)
        .map_err(|error| kit_error(format!("unreadable contents: {error}")))?;
    if contents.format != KIT_FORMAT {
        return Err(kit_error("unknown contents format"));
    }
    contents
        .bound_at_state
        .parse::<u128>()
        .map_err(|_| kit_error("invalid bound_at_state"))?;
    Ok(contents)
}

/// The SDK writes a note's amounts and counters as the browser holds them:
/// JSON numbers, or decimal strings for values beyond a double. The note
/// state reads integers, so decimal strings become numbers here, and the
/// bound becomes the decimal string this crate keeps it as.
fn normalize_contents(value: &mut Value) {
    fn integer(value: &mut Value) {
        if let Some(text) = value.as_str() {
            if let Ok(number) = text.parse::<u64>() {
                *value = json!(number);
            } else if let Ok(number) = text.parse::<u128>() {
                if let Ok(parsed) = serde_json::from_str::<Value>(&number.to_string()) {
                    *value = parsed;
                }
            }
        }
    }
    if let Some(note) = value.get_mut("note").and_then(Value::as_object_mut) {
        for field in [
            "protocol_version",
            "chain_id",
            "note_id",
            "deposit_amount",
            "expiry_ts",
            "current_balance",
            "bound_at_state",
            "state_seq",
        ] {
            if let Some(entry) = note.get_mut(field) {
                integer(entry);
            }
        }
        // `null` where the browser holds no value: the field's default.
        note.retain(|_, entry| !entry.is_null());
    }
    if let Some(bound) = value.get_mut("bound_at_state") {
        if let Some(number) = bound.as_u64() {
            *bound = json!(number.to_string());
        }
    }
    for field in ["state_seq", "exported_at"] {
        if let Some(entry) = value.get_mut(field) {
            integer(entry);
        }
    }
    if value.get("merkle_path").is_some_and(Value::is_null) {
        if let Some(object) = value.as_object_mut() {
            object.remove("merkle_path");
        }
    }
}

pub fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The kit of the wallet in `state_dir`, for the deployment `manifest`.
pub fn export(state_dir: &Path, manifest: &Value) -> anyhow::Result<KitContents> {
    let note = NoteState::load(&state_dir.join("note_state.json"))
        .map_err(|error| kit_error(format!("no readable note state: {error}")))?;
    Ok(KitContents {
        format: KIT_FORMAT.into(),
        trusted_deployment: manifest.clone(),
        bound_at_state: note.bound_at_state.to_string(),
        state_seq: note.state_seq,
        exported_at: now_seconds(),
        merkle_path: note.deposit_path.as_ref().map(|path| KitMerklePath {
            active_root: path.root,
            siblings: path.siblings.clone(),
        }),
        deposit_path: None,
        note,
    })
}

/// A profile field, under the companion manifest's or a browser profile's
/// name.
fn profile_str<'a>(profile: &'a Value, names: &[&str]) -> Option<&'a str> {
    names.iter().find_map(|name| {
        let mut value = profile;
        for part in name.split('.') {
            value = value.get(part)?;
        }
        value.as_str()
    })
}

fn profile_u64(profile: &Value, names: &[&str]) -> Option<u64> {
    names.iter().find_map(|name| profile.get(name)?.as_u64())
}

fn felt(text: &str) -> anyhow::Result<Felt252> {
    Felt252::from_hex(text).map_err(|error| kit_error(format!("invalid field element: {error}")))
}

fn address(text: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = text
        .strip_prefix("0x")
        .and_then(|digits| hex::decode(digits).ok())
        .filter(|bytes| bytes.len() == 20)
        .ok_or_else(|| kit_error(format!("invalid address {text}")))?;
    Ok(bytes.try_into().expect("20 bytes"))
}

fn point(profile: &Value, name: &str) -> anyhow::Result<CurvePointWire> {
    let value = profile
        .get(name)
        .ok_or_else(|| kit_error(format!("the profile has no {name}")))?;
    Ok(CurvePointWire {
        x: felt(value["x"].as_str().unwrap_or(""))?,
        y: felt(value["y"].as_str().unwrap_or(""))?,
    })
}

/// What `exit-kit escape` was asked to do.
#[derive(Debug, Clone)]
pub struct EscapeOptions {
    pub destination: [u8; 20],
    pub conceded: u128,
    pub rpc_url: Option<String>,
    pub work_dir: PathBuf,
    pub proof_setup_dir: String,
    /// Skip the stale-device pre-check (no operator call at all).
    pub offline: bool,
}

/// E4 from a kit. Returns the transaction to send and what it pays.
///
/// The process-wide wallet lock (C1) is held for the whole exit, across its
/// awaits: nothing else in this process may touch the kit's state meanwhile.
#[allow(clippy::await_holding_lock)]
pub async fn escape(kit: &KitContents, options: &EscapeOptions) -> anyhow::Result<Value> {
    let profile = &kit.trusted_deployment;
    if profile_str(profile, &["deployment_status"]) == Some("not_deployed") {
        return Err(kit_error(
            "the kit's deployment is a not_deployed placeholder",
        ));
    }
    let bound: u128 = kit.bound_at_state.parse()?;
    if !zkapi_client::exit_policy::concession_allowed(options.conceded, bound) {
        return Err(kit_error(format!(
            "an escape from this state may concede at most {bound} (the state's bound), not {}",
            options.conceded
        )));
    }
    let vault = address(
        profile_str(profile, &["contract_address"])
            .ok_or_else(|| kit_error("the profile has no contract_address"))?,
    )?;
    let config = ClientConfig {
        protocol_version: kit.note.protocol_version,
        chain_id: kit.note.chain_id,
        contract_address: kit.note.contract_address,
        request_charge_cap: 0,
        policy_charge_cap: 0,
        policy_enabled: false,
        server_url: profile_str(profile, &["protocol_server_url"])
            .unwrap_or("https://invalid.invalid")
            .to_string(),
        state_dir: options.work_dir.to_string_lossy().into_owned(),
        proof_mode: ClientProofMode::Groth16 {
            setup_dir: options.proof_setup_dir.clone(),
        },
        state_signing_key: point(profile, "state_signing_key")?,
        clearance_signing_key: point(profile, "clearance_signing_key")?,
        settlement_window_seconds: profile_u64(profile, &["settlement_window_seconds"])
            .unwrap_or(0),
    };
    if zkapi_types::serialization::address_to_felt(&vault) != kit.note.contract_address {
        return Err(kit_error(
            "the kit's note belongs to another vault than its profile",
        ));
    }
    // The kit's state in the work directory: the exit lock and the released
    // proofs survive a rerun there. Another state in it is refused.
    std::fs::create_dir_all(&options.work_dir)?;
    let lock = crate::wallet_lock::WalletLock::for_state_dir(&options.work_dir);
    let _guard = lock
        .lock()
        .map_err(|_| kit_error("the wallet lock is poisoned"))?;
    let state_path = options.work_dir.join("note_state.json");
    if state_path.exists() {
        let saved = NoteState::load(&state_path)?;
        if saved.note_id != kit.note.note_id || saved.current_anchor != kit.note.current_anchor {
            return Err(kit_error(format!(
                "{} holds another note state; use another --work-dir",
                options.work_dir.display()
            )));
        }
    } else {
        let mut note = kit.note.clone();
        note.bound_at_state = bound;
        note.deposit_path = kit.path().or(note.deposit_path);
        note.save(&state_path)?;
    }
    let wallet = Wallet::new(config)?;
    let mut warnings = Vec::new();
    let rpc = options.rpc_url.as_deref().map(Rpc::new).transpose()?;
    // The pins: advisory for an exit, which stays allowed (§6.5).
    if let Some(rpc) = &rpc {
        warnings.extend(check_codehashes(rpc, profile, &vault).await);
    }
    // E4 step 1: the kit's path, else a rebuild from the vault's logs.
    let (root, siblings, source) = match wallet.deposit_path() {
        Some(path) => (path.root, path.siblings.clone(), "deposit"),
        None => {
            let rpc = rpc.as_ref().ok_or_else(|| {
                kit_error(
                    "the kit holds no Merkle path; pass --rpc to rebuild one from the vault's logs",
                )
            })?;
            let deploy_block = profile_u64(profile, &["deploy_block"]).unwrap_or(0);
            let (finalized, _) = rpc.block("finalized").await?;
            let logs = rpc
                .logs(
                    &vault,
                    json!([zkapi_client::tree::TREE_TOPICS]),
                    deploy_block,
                    finalized,
                )
                .await?;
            let leaf = wallet
                .current_note_leaf()
                .ok_or_else(|| kit_error("no note"))?;
            let (root, siblings) =
                zkapi_client::tree::path_from_logs(&logs, &vault, kit.note.note_id, &leaf)
                    .map_err(|error| kit_error(error.to_string()))?;
            (root, siblings, "rebuild")
        }
    };
    if let Some(rpc) = &rpc {
        if matches!(
            chain::known_root(rpc, &vault, &root, "latest").await,
            Ok(false)
        ) {
            warnings.push(format!(
                "{} reports the path's root as unknown to the vault; the escape may revert",
                rpc.url()
            ));
        }
    }
    // E4 step 2: the stale-device pre-check.
    let successor = wallet
        .current_successor_nullifier()
        .ok_or_else(|| kit_error("no note"))?;
    if !options.offline {
        let auth_config = crate::config::AuthConfig {
            protocol_server_url: wallet.config().server_url.clone(),
            chain_id: kit.note.chain_id,
            proof_setup_dir: options.proof_setup_dir.clone(),
            ..Default::default()
        };
        if let Err(error) = crate::service::exit::stale_device_check(&auth_config, &successor).await
        {
            return Err(anyhow::anyhow!(error.to_string()));
        }
    }
    wallet.set_exit_lock(ExitMode::Escape)?;
    let (public_inputs, proof) =
        wallet.withdrawal_escape_hatch(options.destination, options.conceded, root, siblings)?;
    let calldata = chain::withdrawal_calldata(chain::INITIATE_ESCAPE, &public_inputs, &proof)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if let Some(rpc) = &rpc {
        for value in [
            &public_inputs.withdrawal_nullifier,
            &public_inputs.next_nullifier,
        ] {
            if matches!(
                chain::challenged(rpc, &vault, value, "latest").await,
                Ok(true)
            ) {
                warnings.push(
                    "the vault reports a nullifier of this state as challenged: a newer state exists; restore the newest backup".into(),
                );
            }
        }
    }
    Ok(json!({
        "to": format!("0x{}", hex::encode(vault)),
        "data": calldata,
        "value": "0x0",
        "chain_id": kit.note.chain_id,
        "note_id": kit.note.note_id,
        "state_balance": kit.note.current_balance.to_string(),
        "conceded": options.conceded.to_string(),
        "bound_at_state": bound.to_string(),
        "payout": public_inputs.final_balance.to_string(),
        "valid_until": public_inputs.valid_until,
        "withdrawal_nullifier": public_inputs.withdrawal_nullifier,
        "next_nullifier": public_inputs.next_nullifier,
        "path_source": source,
        "state_seq": kit.state_seq,
        "exported_at": kit.exported_at,
        "finalize_data": chain::finalize_calldata(kit.note.note_id),
        "warnings": warnings,
    }))
}

/// The runtime codehashes and adapter of the profile, through `rpc`.
async fn check_codehashes(rpc: &Rpc, profile: &Value, vault: &[u8; 20]) -> Vec<String> {
    let mut warnings = Vec::new();
    let check = |label: &str, address: Option<[u8; 20]>, expected: Option<&str>| {
        (
            label.to_string(),
            address,
            expected.map(str::to_ascii_lowercase),
        )
    };
    let adapter =
        profile_str(profile, &["proof_adapter_address"]).and_then(|text| address(text).ok());
    let poseidon =
        profile_str(profile, &["poseidon_library_address"]).and_then(|text| address(text).ok());
    let pins = [
        check(
            "vault",
            Some(*vault),
            profile_str(
                profile,
                &[
                    "vault_runtime_codehash",
                    "deployment_evidence.vault_runtime_keccak256",
                ],
            ),
        ),
        check(
            "proof adapter",
            adapter,
            profile_str(
                profile,
                &[
                    "adapter_runtime_codehash",
                    "deployment_evidence.adapter_runtime_keccak256",
                ],
            ),
        ),
        check(
            "Poseidon library",
            poseidon,
            profile_str(
                profile,
                &[
                    "poseidon_runtime_codehash",
                    "deployment_evidence.poseidon_runtime_keccak256",
                ],
            ),
        ),
    ];
    for (label, address, expected) in pins {
        let (Some(address), Some(expected)) = (address, expected) else {
            warnings.push(format!("the profile pins no {label} codehash"));
            continue;
        };
        match rpc.code_hash(&address, "latest").await {
            Ok(hash) if format!("0x{}", hex::encode(hash)) == expected => {}
            Ok(hash) => warnings.push(format!(
                "deployment_mismatch: the {label} code at 0x{} hashes to 0x{}, not the pinned {expected}",
                hex::encode(address),
                hex::encode(hash)
            )),
            Err(error) => warnings.push(format!("the {label} code could not be read: {error}")),
        }
    }
    if let Some(adapter) = adapter {
        match rpc
            .call(vault, &format!("0x{}", chain::PROOF_ADAPTER), "latest")
            .await
        {
            Ok(word) if word.to_ascii_lowercase().ends_with(&hex::encode(adapter)) => {}
            Ok(_) => warnings.push(
                "deployment_mismatch: the vault's proofAdapter() is not the pinned adapter".into(),
            ),
            Err(error) => warnings.push(format!("proofAdapter() could not be read: {error}")),
        }
    }
    warnings
}

/// Sign and send `data` to `to` as an EIP-1559 transaction from the
/// secp256k1 key `secret` (32 bytes), through `rpc`. Returns the hash.
pub async fn sign_and_send(
    rpc: &Rpc,
    secret: &[u8; 32],
    chain_id: u64,
    to: &[u8; 20],
    data: &str,
) -> anyhow::Result<String> {
    use k256::ecdsa::SigningKey;
    use sha3::{Digest, Keccak256};
    let key =
        SigningKey::from_bytes(secret.into()).map_err(|_| kit_error("invalid private key"))?;
    let public = key.verifying_key().to_encoded_point(false);
    let from: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
        .try_into()
        .expect("20 bytes");
    let from_hex = format!("0x{}", hex::encode(from));
    let remote_chain = chain::quantity(&rpc.request("eth_chainId", json!([])).await?)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if remote_chain != chain_id {
        return Err(kit_error(format!(
            "the RPC serves chain {remote_chain}, the kit's note is on chain {chain_id}"
        )));
    }
    let nonce = chain::quantity(
        &rpc.request("eth_getTransactionCount", json!([from_hex, "pending"]))
            .await?,
    )
    .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let call = json!({"from": from_hex, "to": format!("0x{}", hex::encode(to)), "data": data});
    let gas = chain::quantity(&rpc.request("eth_estimateGas", json!([call])).await?)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let gas = gas + gas / 5;
    let block = rpc
        .request("eth_getBlockByNumber", json!(["latest", false]))
        .await?;
    let base_fee = chain::quantity(&block["baseFeePerGas"]).unwrap_or(1_000_000_000);
    let tip = rpc
        .request("eth_maxPriorityFeePerGas", json!([]))
        .await
        .ok()
        .and_then(|value| chain::quantity(&value).ok())
        .unwrap_or(1_000_000_000);
    let max_fee = base_fee.saturating_mul(2).saturating_add(tip);
    let data_bytes = hex::decode(data.trim_start_matches("0x"))?;
    let fields = |signature: Option<(u8, &[u8], &[u8])>| {
        let mut items = vec![
            rlp_uint(chain_id.into()),
            rlp_uint(nonce.into()),
            rlp_uint(tip.into()),
            rlp_uint(max_fee.into()),
            rlp_uint(gas.into()),
            rlp_bytes(to),
            rlp_uint(0),
            rlp_bytes(&data_bytes),
            rlp_list(&[]),
        ];
        if let Some((parity, r, s)) = signature {
            items.push(rlp_uint(parity.into()));
            items.push(rlp_bytes(strip_zeros(r)));
            items.push(rlp_bytes(strip_zeros(s)));
        }
        let mut encoded = vec![0x02];
        encoded.extend(rlp_list(&items));
        encoded
    };
    let digest = Keccak256::digest(fields(None));
    let (signature, recovery) = key
        .sign_prehash_recoverable(&digest)
        .map_err(|_| kit_error("signing failed"))?;
    let bytes = signature.to_bytes();
    let raw = fields(Some((recovery.to_byte(), &bytes[..32], &bytes[32..])));
    let hash = rpc
        .request(
            "eth_sendRawTransaction",
            json!([format!("0x{}", hex::encode(raw))]),
        )
        .await?;
    hash.as_str()
        .map(str::to_string)
        .ok_or_else(|| kit_error("eth_sendRawTransaction returned no hash"))
}

fn strip_zeros(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len());
    &bytes[start..]
}

fn rlp_length(prefix: u8, length: usize) -> Vec<u8> {
    if length < 56 {
        vec![prefix + length as u8]
    } else {
        let bytes = length.to_be_bytes();
        let bytes = strip_zeros(&bytes);
        let mut out = vec![prefix + 55 + bytes.len() as u8];
        out.extend_from_slice(bytes);
        out
    }
}

fn rlp_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }
    let mut out = rlp_length(0x80, bytes.len());
    out.extend_from_slice(bytes);
    out
}

fn rlp_uint(value: u128) -> Vec<u8> {
    rlp_bytes(strip_zeros(&value.to_be_bytes()))
}

fn rlp_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload: Vec<u8> = items.concat();
    let mut out = rlp_length(0xc0, payload.len());
    out.extend(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contents() -> KitContents {
        let note = NoteState::new_from_deposit(
            2,
            1,
            Felt252::from_u64(0x1234),
            4,
            Felt252::from_u64(42),
            1_000,
            4_000_000_000,
            "0x2a".into(),
            Felt252::from_u64(1),
            Felt252::from_u64(2),
        );
        KitContents {
            format: KIT_FORMAT.into(),
            trusted_deployment: json!({"deployment_id": "drill", "contract_address": "0x0000000000000000000000000000000000001234"}),
            note,
            bound_at_state: "500".into(),
            state_seq: 3,
            exported_at: 1_800_000_000,
            merkle_path: None,
            deposit_path: None,
        }
    }

    #[test]
    fn kits_round_trip_and_refuse_wrong_passphrases_and_tampering() {
        let kit = contents();
        let file = encrypt_with_iterations(&kit, "correct horse battery staple", 1_000).unwrap();
        let encoded = serde_json::to_value(&file).unwrap();
        assert_eq!(encoded["format"], KIT_FORMAT);
        // The SDK's envelope (zkapiExitKit.mjs): WebCrypto's names.
        assert_eq!(encoded["kdf"]["name"], "PBKDF2");
        assert_eq!(encoded["kdf"]["hash"], "SHA-256");
        assert_eq!(encoded["cipher"]["name"], "AES-256-GCM");
        assert!(!serde_json::to_string(&file).unwrap().contains("secret_s"));
        assert_eq!(
            serde_json::to_value(decrypt(&file, "correct horse battery staple").unwrap()).unwrap(),
            serde_json::to_value(&kit).unwrap()
        );
        assert!(decrypt(&file, "incorrect horse battery staple").is_err());
        let mut tampered = file.clone();
        let mut bytes = base64::engine::general_purpose::STANDARD
            .decode(&tampered.ciphertext)
            .unwrap();
        bytes[3] ^= 1;
        tampered.ciphertext = base64::engine::general_purpose::STANDARD.encode(bytes);
        assert!(decrypt(&tampered, "correct horse battery staple").is_err());
        assert!(encrypt_with_iterations(&kit, "short", 1_000).is_err());
        // The shipped iteration count.
        assert_eq!(KIT_ITERATIONS, 600_000);
    }

    const SETUP_DIR: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/setup/v2-concession-dev"
    );

    /// A wallet with a deposit-time path and a released request (bound 700),
    /// exported to a kit and escaped from it with no wallet, host, indexer
    /// or operator: the calldata is the 836-byte escape whose proof verifies
    /// and which concedes at most the kit's bound.
    #[tokio::test]
    async fn an_exported_kit_escapes_without_the_wallet() {
        let directory = tempfile::tempdir().unwrap();
        let state_dir = directory.path().join("wallet");
        let vault = [0x77u8; 20];
        let contract = zkapi_types::serialization::address_to_felt(&vault);
        let state_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(11));
        let clearance_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(12));
        let config = ClientConfig {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: contract,
            request_charge_cap: 700,
            policy_charge_cap: 700,
            policy_enabled: false,
            server_url: "http://127.0.0.1:1".into(),
            state_dir: state_dir.to_string_lossy().into_owned(),
            proof_mode: ClientProofMode::Groth16 {
                setup_dir: SETUP_DIR.into(),
            },
            state_signing_key: state_key.public_key(),
            clearance_signing_key: clearance_key.public_key(),
            settlement_window_seconds: 1_800,
        };
        let secret = Felt252::from_u64(31337);
        let leaf = zkapi_core::v2::note_leaf(
            9,
            &zkapi_core::v2::registration_commitment(&secret),
            2_000_000,
            4_000_000_000,
        );
        let mut tree = zkapi_client::tree::SparseTree::new();
        tree.set_leaf(8, Felt252::from_u64(5));
        tree.set_leaf(9, leaf);
        let mut wallet = Wallet::new(config).unwrap();
        wallet
            .confirm_deposit_with_path(
                secret,
                9,
                2_000_000,
                4_000_000_000,
                Some(DepositPath {
                    root: tree.root(),
                    siblings: tree.siblings(9).to_vec(),
                }),
            )
            .unwrap();
        wallet
            .prepare_request_with_bound(
                "{}",
                zkapi_types::canonical_payload_hash(b"{}"),
                tree.root(),
                tree.siblings(9).to_vec(),
                700,
            )
            .unwrap();
        let manifest = json!({
            "deployment_id": "drill-concession",
            "contract_address": format!("0x{}", hex::encode(vault)),
            "protocol_server_url": "http://127.0.0.1:1",
            "state_signing_key": {"x": state_key.public_key().x, "y": state_key.public_key().y},
            "clearance_signing_key": {"x": clearance_key.public_key().x, "y": clearance_key.public_key().y},
            "settlement_window_seconds": 1_800,
        });
        let kit = export(&state_dir, &manifest).unwrap();
        assert_eq!(kit.bound_at_state, "700");
        let file = encrypt_with_iterations(&kit, "a long enough passphrase", 1_000).unwrap();
        let kit = decrypt(&file, "a long enough passphrase").unwrap();
        let options = |conceded: u128, work_dir: &str| EscapeOptions {
            destination: [0x33; 20],
            conceded,
            rpc_url: None,
            work_dir: directory.path().join(work_dir),
            proof_setup_dir: SETUP_DIR.into(),
            offline: true,
        };
        let refused = escape(&kit, &options(701, "kit")).await.unwrap_err();
        assert!(refused.to_string().contains("at most 700"), "{refused}");
        let result = escape(&kit, &options(700, "kit")).await.unwrap();
        assert_eq!(result["path_source"], "deposit");
        assert_eq!(result["payout"], (2_000_000u128 - 700).to_string());
        assert_eq!(result["to"], format!("0x{}", hex::encode(vault)));
        let data = hex::decode(result["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(data.len(), 836);
        assert_eq!(hex::encode(&data[..4]), chain::INITIATE_ESCAPE);
        let words: Vec<&[u8]> = data[4..].chunks(32).collect();
        let word_u128 = |index: usize| u128::from_be_bytes(words[index][16..].try_into().unwrap());
        assert_eq!(word_u128(8), 9);
        assert_eq!(word_u128(12), 0);
        assert_eq!(word_u128(14), 700);
        assert_eq!(word_u128(9) + word_u128(14), 2_000_000);
        assert_eq!(&words[10][12..], &[0x33; 20]);
        // The proof in the calldata verifies under the bundled key.
        let public = zkapi_types::WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: contract,
            active_root: Felt252(words[3].try_into().unwrap()),
            state_signing_key_x: state_key.public_key().x,
            state_signing_key_y: state_key.public_key().y,
            clearance_signing_key_x: clearance_key.public_key().x,
            clearance_signing_key_y: clearance_key.public_key().y,
            note_id: 9,
            final_balance: word_u128(9),
            destination: [0x33; 20],
            withdrawal_nullifier: Felt252(words[11].try_into().unwrap()),
            kind: 0,
            next_nullifier: Felt252(words[13].try_into().unwrap()),
            conceded: 700,
            valid_until: word_u128(15) as u64,
        };
        let proof = zkapi_types::wire::Groth16ProofWire {
            backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(&data[4 + 18 * 32..]),
        };
        assert!(zkapi_proof::compact::WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&public, &proof)
            .unwrap());
        // The work directory keeps the exit lock: a rerun releases another
        // proof under it, and another note state there is refused.
        let lock = zkapi_client::exit_lock::ExitLock::load(
            &directory.path().join("kit").join("exit_lock.json"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(lock.released.len(), 1);
        let mut other = kit.clone();
        other.note.current_anchor = Felt252::from_u64(77);
        assert!(escape(&other, &options(0, "kit")).await.is_err());
    }

    /// The browser SDK's sealed kit (`tests/fixtures/sdk-exit-kit-v1.json`),
    /// made by `tests/fixtures/make-sdk-exit-kit.mjs` with the SDK's own
    /// `buildExitKitPayload` and `sealExitKit` from the inputs that
    /// `write_sdk_kit_fixture_inputs` writes.
    const SDK_KIT: &str = include_str!("../tests/fixtures/sdk-exit-kit-v1.json");
    const SDK_KIT_PASSPHRASE: &str = "zkapi exit kit fixture";
    const SDK_KIT_VAULT: [u8; 20] = [0x77; 20];

    /// The inputs of the SDK kit fixture: a browser-shaped note state (the
    /// WASM's field names, amounts as JSON numbers, the deposit-time path
    /// as `{active_root, siblings}`) and a `trusted_deployment` profile.
    /// Run with `ZKAPI_KIT_FIXTURE_INPUTS=<file>` and `--ignored`.
    #[test]
    #[ignore]
    fn write_sdk_kit_fixture_inputs() {
        let target = std::env::var("ZKAPI_KIT_FIXTURE_INPUTS").expect("ZKAPI_KIT_FIXTURE_INPUTS");
        let directory = tempfile::tempdir().unwrap();
        let state_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(11));
        let clearance_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(12));
        let contract = zkapi_types::serialization::address_to_felt(&SDK_KIT_VAULT);
        let secret = Felt252::from_u64(271_828);
        let leaf = zkapi_core::v2::note_leaf(
            4,
            &zkapi_core::v2::registration_commitment(&secret),
            5_000_000,
            4_000_000_000,
        );
        let mut tree = zkapi_client::tree::SparseTree::new();
        tree.set_leaf(3, Felt252::from_u64(5));
        tree.set_leaf(4, leaf);
        let mut wallet = Wallet::new(ClientConfig {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: contract,
            request_charge_cap: 0,
            policy_charge_cap: 0,
            policy_enabled: false,
            server_url: "http://127.0.0.1:1".into(),
            state_dir: directory.path().to_string_lossy().into_owned(),
            proof_mode: ClientProofMode::Groth16 {
                setup_dir: SETUP_DIR.into(),
            },
            state_signing_key: state_key.public_key(),
            clearance_signing_key: clearance_key.public_key(),
            settlement_window_seconds: 14_705,
        })
        .unwrap();
        wallet
            .confirm_deposit(secret, 4, 5_000_000, 4_000_000_000)
            .unwrap();
        let mut state = serde_json::to_value(wallet.state().unwrap()).unwrap();
        state["bound_at_state"] = json!(1_000_000);
        state["deposit_path"] = json!({
            "active_root": tree.root(),
            "siblings": tree.siblings(4).to_vec(),
        });
        let inputs = json!({
            "state": state,
            "state_seq": 1,
            "exported_at": 1_800_000_000u64,
            "trusted_deployment": {
                "deployment_status": "deployed",
                "deployment_id": "sdk-kit-fixture",
                "chain_id": 11_155_111,
                "contract_address": format!("0x{}", hex::encode(SDK_KIT_VAULT)),
                "deploy_block": 1,
                "protocol_server_url": "https://127.0.0.1:1",
                "state_signing_key": {"x": state_key.public_key().x, "y": state_key.public_key().y},
                "clearance_signing_key": {"x": clearance_key.public_key().x, "y": clearance_key.public_key().y},
                "settlement_window_seconds": 14_705,
                "circuit_id": "zkapi-v2-concession-v1",
                "setup_id": "dev",
            },
        });
        std::fs::write(target, serde_json::to_vec_pretty(&inputs).unwrap()).unwrap();
    }

    /// E7 across packages: a kit the browser SDK sealed (WebCrypto's kdf
    /// names, the deposit-time path as `merkle_path`, the browser's note
    /// encoding) decrypts here, and its escape proves from the kit's own
    /// path with no RPC, indexer or operator. Kits of this crate's earlier
    /// encoding (`PBKDF2-SHA256`, `deposit_path`) still decrypt.
    #[tokio::test]
    async fn a_kit_the_browser_sdk_sealed_escapes() {
        let file: KitFile = serde_json::from_str(SDK_KIT).unwrap();
        let encoded = serde_json::to_value(&file).unwrap();
        assert_eq!(
            (
                encoded["kdf"]["name"].as_str(),
                encoded["kdf"]["hash"].as_str()
            ),
            (Some("PBKDF2"), Some("SHA-256"))
        );
        // The shared exit-rule vectors (E7) name this kit, its passphrase and
        // what it holds; the browser SDK opens it against the same section.
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../protocol/rust/crates/zkapi-client/tests/vectors/exit-rules.json"
        ))
        .unwrap();
        let shared = &vectors["exit_kit"];
        assert_eq!(
            shared["fixture"],
            "crates/zkapi-companion/tests/fixtures/sdk-exit-kit-v1.json"
        );
        assert_eq!(shared["passphrase"], SDK_KIT_PASSPHRASE);
        assert!(decrypt(&file, shared["wrong_passphrase"].as_str().unwrap()).is_err());
        let kit = decrypt(&file, SDK_KIT_PASSPHRASE).unwrap();
        let expected = &shared["expected"];
        assert_eq!(kit.format, expected["format"]);
        assert_eq!(
            kit.trusted_deployment["deployment_id"],
            expected["deployment_id"]
        );
        assert_eq!(
            kit.trusted_deployment["contract_address"],
            expected["contract_address"]
        );
        assert_eq!(
            u64::from(kit.note.note_id),
            expected["note_id"].as_u64().unwrap()
        );
        assert_eq!(
            kit.note.deposit_amount.to_string(),
            expected["deposit_amount"]
        );
        assert_eq!(
            kit.note.current_balance.to_string(),
            expected["current_balance"]
        );
        assert_eq!(kit.note.current_anchor.to_hex(), expected["current_anchor"]);
        assert_eq!(kit.bound_at_state, expected["bound_at_state"]);
        assert_eq!(kit.state_seq, expected["state_seq"].as_u64().unwrap());
        assert_eq!(kit.exported_at, expected["exported_at"].as_u64().unwrap());
        assert!(kit.merkle_path.is_some() && kit.deposit_path.is_none());
        let shared_path = kit.merkle_path.as_ref().unwrap();
        assert_eq!(
            shared_path.active_root.to_hex(),
            expected["merkle_path_root"]
        );
        assert_eq!(
            shared_path.siblings.len() as u64,
            expected["merkle_path_siblings"].as_u64().unwrap()
        );
        let path = kit.path().unwrap();
        assert_eq!(path.siblings.len(), 32);
        let directory = tempfile::tempdir().unwrap();
        let options = |conceded: u128| EscapeOptions {
            destination: [0x44; 20],
            conceded,
            rpc_url: None,
            work_dir: directory.path().join("kit"),
            proof_setup_dir: SETUP_DIR.into(),
            offline: true,
        };
        assert!(escape(&kit, &options(1_000_001)).await.is_err());
        let result = escape(&kit, &options(1_000_000)).await.unwrap();
        assert_eq!(result["path_source"], "deposit");
        assert_eq!(result["to"], format!("0x{}", hex::encode(SDK_KIT_VAULT)));
        assert_eq!(result["payout"], "4000000");
        let data = hex::decode(result["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(data.len(), 836);
        let words: Vec<&[u8]> = data[4..].chunks(32).collect();
        let word_u128 = |index: usize| u128::from_be_bytes(words[index][16..].try_into().unwrap());
        let state_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(11));
        let clearance_key = zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(12));
        let public = zkapi_types::WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: zkapi_types::serialization::address_to_felt(&SDK_KIT_VAULT),
            active_root: Felt252(words[3].try_into().unwrap()),
            state_signing_key_x: state_key.public_key().x,
            state_signing_key_y: state_key.public_key().y,
            clearance_signing_key_x: clearance_key.public_key().x,
            clearance_signing_key_y: clearance_key.public_key().y,
            note_id: 4,
            final_balance: word_u128(9),
            destination: [0x44; 20],
            withdrawal_nullifier: Felt252(words[11].try_into().unwrap()),
            kind: 0,
            next_nullifier: Felt252(words[13].try_into().unwrap()),
            conceded: 1_000_000,
            valid_until: word_u128(15) as u64,
        };
        assert_eq!(public.active_root, path.root);
        let proof = zkapi_types::wire::Groth16ProofWire {
            backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(&data[4 + 18 * 32..]),
        };
        assert!(zkapi_proof::compact::WithdrawalVerifier::load(SETUP_DIR)
            .unwrap()
            .verify(&public, &proof)
            .unwrap());

        // This crate's earlier envelope and path encoding.
        let mut older = contents();
        older.deposit_path = Some(DepositPath {
            root: Felt252::from_u64(9),
            siblings: vec![Felt252::from_u64(1); 32],
        });
        let mut sealed =
            encrypt_with_iterations(&older, "correct horse battery staple", 1_000).unwrap();
        sealed.kdf.name = "PBKDF2-SHA256".into();
        sealed.kdf.hash = None;
        let opened = decrypt(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(opened.path().unwrap().root, Felt252::from_u64(9));
        for (name, hash) in [
            ("PBKDF2", None),
            ("PBKDF2", Some("SHA-1")),
            ("scrypt", None),
        ] {
            let mut other = sealed.clone();
            other.kdf.name = name.into();
            other.kdf.hash = hash.map(str::to_string);
            assert!(
                decrypt(&other, "correct horse battery staple").is_err(),
                "{name}"
            );
        }
    }

    /// The SDK writes a note's amounts and counters as JSON numbers, or as
    /// decimal strings for values beyond a double, and the bound either
    /// way: a kit whose note amounts, bound and counters are decimal
    /// strings, and whose top-level bound is a number, decrypts to the same
    /// contents and escapes.
    #[tokio::test]
    async fn a_kit_with_decimal_string_amounts_decrypts_and_escapes() {
        let file: KitFile = serde_json::from_str(SDK_KIT).unwrap();
        let kit = decrypt(&file, SDK_KIT_PASSPHRASE).unwrap();
        let mut plain = serde_json::to_value(&kit).unwrap();
        let note = plain["note"].as_object_mut().unwrap();
        for field in [
            "protocol_version",
            "chain_id",
            "note_id",
            "deposit_amount",
            "expiry_ts",
            "current_balance",
            "bound_at_state",
            "state_seq",
        ] {
            let entry = note.get_mut(field).unwrap();
            *entry = json!(entry.as_u64().unwrap().to_string());
        }
        assert_eq!(note["current_balance"], "5000000");
        plain["bound_at_state"] = json!(1_000_000u64);
        for field in ["state_seq", "exported_at"] {
            plain[field] = json!(plain[field].as_u64().unwrap().to_string());
        }
        let passphrase = "decimal strings for every amount";
        let sealed = seal(&serde_json::to_vec(&plain).unwrap(), passphrase, 1_000).unwrap();
        let opened = decrypt(&sealed, passphrase).unwrap();
        assert_eq!(
            serde_json::to_value(&opened).unwrap(),
            serde_json::to_value(&kit).unwrap()
        );
        let directory = tempfile::tempdir().unwrap();
        let result = escape(
            &opened,
            &EscapeOptions {
                destination: [0x44; 20],
                conceded: 1_000_000,
                rpc_url: None,
                work_dir: directory.path().join("kit"),
                proof_setup_dir: SETUP_DIR.into(),
                offline: true,
            },
        )
        .await
        .unwrap();
        assert_eq!(result["payout"], "4000000");
        let data = hex::decode(result["data"].as_str().unwrap().trim_start_matches("0x")).unwrap();
        assert_eq!(data.len(), 836);
    }

    /// E7 "with the companion's bundled keys and the codehash pins": a kit's
    /// escape refuses a placeholder profile and a note of another vault, and
    /// checks the profile's pinned runtime codehashes and adapter through
    /// the user's RPC: a mismatch is reported (an exit stays allowed), a
    /// match is silent.
    #[tokio::test]
    async fn a_kit_escape_checks_its_profile_and_pins() {
        use axum::{extract::State, routing::post, Json, Router};
        use sha3::{Digest, Keccak256};
        use std::sync::{Arc, Mutex};
        let file: KitFile = serde_json::from_str(SDK_KIT).unwrap();
        let kit = decrypt(&file, SDK_KIT_PASSPHRASE).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let options = |rpc_url: Option<String>, work_dir: &str| EscapeOptions {
            destination: [0x44; 20],
            conceded: 0,
            rpc_url,
            work_dir: directory.path().join(work_dir),
            proof_setup_dir: SETUP_DIR.into(),
            offline: true,
        };
        let mut placeholder = kit.clone();
        placeholder.trusted_deployment["deployment_status"] = json!("not_deployed");
        let refused = escape(&placeholder, &options(None, "a")).await.unwrap_err();
        assert!(refused.to_string().contains("not_deployed"), "{refused}");
        let mut other = kit.clone();
        other.trusted_deployment["contract_address"] = json!(format!("0x{}", "88".repeat(20)));
        let refused = escape(&other, &options(None, "b")).await.unwrap_err();
        assert!(refused.to_string().contains("another vault"), "{refused}");

        // The chain as the user's RPC serves it.
        let adapter = [0xadu8; 20];
        let poseidon = [0x9eu8; 20];
        type Codes = Arc<Mutex<std::collections::HashMap<[u8; 20], Vec<u8>>>>;
        let codes: Codes = Arc::new(Mutex::new(
            [
                (SDK_KIT_VAULT, vec![0x60, 0x01]),
                (adapter, vec![0x60, 0x02]),
                (poseidon, vec![0x60, 0x03]),
            ]
            .into_iter()
            .collect(),
        ));
        async fn rpc(State(codes): State<Codes>, Json(body): Json<Value>) -> Json<Value> {
            let params = &body["params"];
            let result = match body["method"].as_str().unwrap_or("") {
                "eth_getCode" => {
                    let address: [u8; 20] =
                        hex::decode(params[0].as_str().unwrap().trim_start_matches("0x"))
                            .unwrap()
                            .try_into()
                            .unwrap();
                    json!(format!(
                        "0x{}",
                        hex::encode(
                            codes
                                .lock()
                                .unwrap()
                                .get(&address)
                                .cloned()
                                .unwrap_or_default()
                        )
                    ))
                }
                "eth_call" => {
                    let data = params[0]["data"].as_str().unwrap();
                    let word = match &data[2..10] {
                        chain::PROOF_ADAPTER => format!("{}{}", "0".repeat(24), "ad".repeat(20)),
                        chain::IS_KNOWN_ROOT => format!("{:064x}", 1),
                        _ => format!("{:064x}", 0),
                    };
                    json!(format!("0x{word}"))
                }
                _ => Value::Null,
            };
            Json(json!({"jsonrpc": "2.0", "id": body["id"], "result": result}))
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let router = Router::new()
            .route("/", post(rpc))
            .with_state(codes.clone());
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let hash = |code: &[u8]| format!("0x{}", hex::encode(Keccak256::digest(code)));
        let mut pinned = kit.clone();
        let profile = &mut pinned.trusted_deployment;
        profile["proof_adapter_address"] = json!(format!("0x{}", hex::encode(adapter)));
        profile["poseidon_library_address"] = json!(format!("0x{}", hex::encode(poseidon)));
        profile["vault_runtime_codehash"] = json!(hash(&[0x60, 0x01]));
        profile["adapter_runtime_codehash"] = json!(hash(&[0x60, 0x02]));
        profile["poseidon_runtime_codehash"] = json!(hash(&[0x60, 0x03]));
        let mismatches = |result: &Value| {
            result["warnings"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|warning| warning.as_str().unwrap().starts_with("deployment_mismatch"))
                .count()
        };
        let result = escape(&pinned, &options(Some(url.clone()), "c"))
            .await
            .unwrap();
        assert_eq!(mismatches(&result), 0, "{result}");
        codes
            .lock()
            .unwrap()
            .insert(SDK_KIT_VAULT, vec![0x60, 0x0f]);
        let result = escape(&pinned, &options(Some(url), "d")).await.unwrap();
        assert_eq!(mismatches(&result), 1, "{result}");
        assert!(result["warnings"].to_string().contains("the vault code"));
        assert_eq!(result["path_source"], "deposit");
        server.abort();
    }

    #[test]
    fn rlp_matches_known_encodings() {
        assert_eq!(rlp_uint(0), vec![0x80]);
        assert_eq!(rlp_uint(15), vec![0x0f]);
        assert_eq!(rlp_uint(1024), vec![0x82, 0x04, 0x00]);
        assert_eq!(rlp_bytes(b"dog"), vec![0x83, b'd', b'o', b'g']);
        assert_eq!(rlp_list(&[]), vec![0xc0]);
        let long = vec![0xaa; 60];
        assert_eq!(&rlp_bytes(&long)[..2], &[0xb8, 60]);
    }
}
