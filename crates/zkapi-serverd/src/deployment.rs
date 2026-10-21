//! The deployment manifest a server stack is started from, and the startup
//! probes that check the live vault and adapter against it (§5.5).
//!
//! The manifest is the `trusted_deployment` profile of §10.3 (either the
//! bare object or a document that holds it under `trusted_deployment`), as
//! `Deploy.s.sol` and the published client configs write it. `zkapi db init`
//! binds a database to it; serverd refuses to start without it, refuses a
//! `not_deployed` placeholder, and before it signs anything checks over the
//! RPC that
//!
//! * the vault reports `CONCESSION_ESCAPE_VERSION() == 1` and
//!   `ROOT_HISTORY_WINDOW() == 86400`, and its `proofAdapter()` is the
//!   manifest's adapter;
//! * the adapter's `CIRCUIT_ID_HASH()`, `REQUEST_VK_HASH()` and
//!   `WITHDRAWAL_VK_HASH()` equal this build's circuit and the verifying keys
//!   it loaded;
//! * the runtime codehashes of the vault, the adapter and the Poseidon library
//!   equal the manifest's.
//!
//! Every probe fails closed.

use std::path::Path;

use anyhow::{bail, ensure, Context};
use serde::Deserialize;
use zkapi_proof::compact::{hex32, CIRCUIT_ID, CIRCUIT_ID_HASH};
use zkapi_types::wire::CurvePointWire;

use crate::native_billing::NativeBillingOracle;
use crate::nullifier_store::{DeploymentBinding, StatementIdentity, BINDING_SOURCE_MANIFEST};

/// `CONCESSION_ESCAPE_VERSION()` of a revision-3 vault.
pub const CONCESSION_ESCAPE_VERSION: u64 = 1;
/// `ROOT_HISTORY_WINDOW()` of a revision-3 vault.
pub const ROOT_HISTORY_WINDOW_SECONDS: u64 = 86_400;
/// The `deployment_status` of a profile whose vault does not exist yet.
pub const NOT_DEPLOYED: &str = "not_deployed";

pub const CONCESSION_ESCAPE_VERSION_SELECTOR: &str = "0x5e00b426"; // CONCESSION_ESCAPE_VERSION()
pub const ROOT_HISTORY_WINDOW_SELECTOR: &str = "0x1fe72de0"; // ROOT_HISTORY_WINDOW()
pub const PROOF_ADAPTER_SELECTOR: &str = "0xefc91e58"; // proofAdapter()
pub const CIRCUIT_ID_HASH_SELECTOR: &str = "0xda0e8385"; // CIRCUIT_ID_HASH()
pub const REQUEST_VK_HASH_SELECTOR: &str = "0xfe351488"; // REQUEST_VK_HASH()
pub const WITHDRAWAL_VK_HASH_SELECTOR: &str = "0x7fcd0926"; // WITHDRAWAL_VK_HASH()

/// The fields of a deployment profile the server stack uses. Other fields
/// of the profile are ignored.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeploymentManifest {
    #[serde(default)]
    pub deployment_id: Option<String>,
    /// `"not_deployed"` for a placeholder profile, which nothing serves.
    #[serde(default)]
    pub deployment_status: Option<String>,
    pub chain_id: u64,
    pub contract_address: String,
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    #[serde(alias = "challenge_period_seconds")]
    pub challenge_period: u64,
    pub circuit_id: String,
    pub setup_id: String,
    pub request_vk_keccak256: String,
    pub withdrawal_vk_keccak256: String,
    pub vault_runtime_codehash: String,
    pub proof_adapter_address: String,
    pub adapter_runtime_codehash: String,
    pub poseidon_library_address: String,
    pub poseidon_runtime_codehash: String,
    /// The build-pinned settlement window `W` clients wait for (§6.4 E0):
    /// the server's lease TTL + grace + settlement deadline must not exceed
    /// it.
    #[serde(default)]
    pub settlement_window_seconds: Option<u64>,
    #[serde(default)]
    pub exit_concession: Option<u64>,
    #[serde(default)]
    pub vault_revision: Option<u64>,
}

#[derive(Deserialize)]
struct Wrapped {
    trusted_deployment: DeploymentManifest,
}

/// 0x followed by 40 lowercase hex digits, from any case.
fn address(value: &str, field: &str) -> anyhow::Result<String> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    ensure!(
        body.len() == 40 && body.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "deployment manifest {field} is not a 20-byte hex address"
    );
    ensure!(
        body.bytes().any(|byte| byte != b'0'),
        "deployment manifest {field} is the zero address"
    );
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

/// 0x followed by 64 lowercase hex digits, from any case.
fn hash32(value: &str, field: &str) -> anyhow::Result<String> {
    let body = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    ensure!(
        body.len() == 64 && body.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "deployment manifest {field} is not a 32-byte hex value"
    );
    Ok(format!("0x{}", body.to_ascii_lowercase()))
}

impl DeploymentManifest {
    /// Parse and validate a manifest: the bare profile, or a document that
    /// holds it under `trusted_deployment`. Refuses a `not_deployed`
    /// placeholder and a profile of another circuit.
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let value: serde_json::Value =
            serde_json::from_str(text).context("deployment manifest is not JSON")?;
        let mut manifest: Self = if value.get("trusted_deployment").is_some() {
            serde_json::from_value::<Wrapped>(value)
                .context("invalid trusted_deployment profile")?
                .trusted_deployment
        } else {
            serde_json::from_value(value).context("invalid deployment manifest")?
        };
        match manifest.deployment_status.as_deref() {
            None | Some("deployed") => {}
            Some(NOT_DEPLOYED) => bail!(
                "the deployment manifest is a placeholder (deployment_status \"not_deployed\"): \
                 its vault is not deployed, so there is nothing to serve"
            ),
            // Deploy.s.sol's provisional output: only the manifest that
            // expected-codehashes.mjs --finalize checked on chain is final.
            Some(status @ ("pending" | "simulated")) => bail!(
                "the deployment manifest is provisional (deployment_status {status:?}): pin a \
                 vault only from the manifest `scripts/expected-codehashes.mjs --finalize` wrote"
            ),
            Some(status) => {
                bail!("the deployment manifest has an unknown deployment_status {status:?}")
            }
        }
        ensure!(
            manifest.circuit_id == CIRCUIT_ID,
            "the deployment manifest is for circuit {:?}, but this build serves {CIRCUIT_ID}",
            manifest.circuit_id
        );
        if let Some(capability) = manifest.exit_concession {
            ensure!(
                capability == 1,
                "the deployment manifest has exit_concession {capability}; this build requires 1"
            );
        }
        ensure!(
            manifest.challenge_period > 0,
            "the deployment manifest has a zero challenge period"
        );
        manifest.contract_address = address(&manifest.contract_address, "contract_address")?;
        manifest.proof_adapter_address =
            address(&manifest.proof_adapter_address, "proof_adapter_address")?;
        manifest.poseidon_library_address = address(
            &manifest.poseidon_library_address,
            "poseidon_library_address",
        )?;
        for (field, value) in [
            ("request_vk_keccak256", &mut manifest.request_vk_keccak256),
            (
                "withdrawal_vk_keccak256",
                &mut manifest.withdrawal_vk_keccak256,
            ),
            (
                "vault_runtime_codehash",
                &mut manifest.vault_runtime_codehash,
            ),
            (
                "adapter_runtime_codehash",
                &mut manifest.adapter_runtime_codehash,
            ),
            (
                "poseidon_runtime_codehash",
                &mut manifest.poseidon_runtime_codehash,
            ),
        ] {
            *value = hash32(value, field)?;
        }
        Ok(manifest)
    }

    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read the deployment manifest {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("deployment manifest {}", path.display()))
    }

    /// The statement identity the manifest pins.
    pub fn statement(&self) -> StatementIdentity {
        StatementIdentity {
            circuit_id: self.circuit_id.clone(),
            setup_id: self.setup_id.clone(),
            request_vk_keccak256: self.request_vk_keccak256.clone(),
            withdrawal_vk_keccak256: self.withdrawal_vk_keccak256.clone(),
        }
    }

    /// Require the verifying keys this build loaded to be the ones the
    /// manifest pins.
    pub fn check_statement(&self, loaded: &StatementIdentity) -> anyhow::Result<()> {
        ensure!(
            &self.statement() == loaded,
            "the loaded verifying keys do not match the deployment manifest: it pins circuit {} \
             setup {} request VK {} withdrawal VK {}, but the proof setup directory holds setup \
             {} request VK {} withdrawal VK {}",
            self.circuit_id,
            self.setup_id,
            self.request_vk_keccak256,
            self.withdrawal_vk_keccak256,
            loaded.setup_id,
            loaded.request_vk_keccak256,
            loaded.withdrawal_vk_keccak256
        );
        Ok(())
    }

    /// The database binding `zkapi db init` records: everything the manifest
    /// pins, marked unverified against the vault.
    pub fn binding(&self, recorded_at: u64) -> DeploymentBinding {
        DeploymentBinding {
            chain_id: self.chain_id,
            contract_address: self.contract_address.clone(),
            state_signing_key: self.state_signing_key.clone(),
            clearance_signing_key: self.clearance_signing_key.clone(),
            challenge_period_seconds: self.challenge_period,
            verified_at: recorded_at,
            verified_block: None,
            circuit_id: Some(self.circuit_id.clone()),
            setup_id: Some(self.setup_id.clone()),
            request_vk_keccak256: Some(self.request_vk_keccak256.clone()),
            withdrawal_vk_keccak256: Some(self.withdrawal_vk_keccak256.clone()),
            source: BINDING_SOURCE_MANIFEST.to_string(),
        }
    }

    /// Why a recorded binding is not this manifest's deployment, if it is
    /// not. Verification metadata (time, block, source) is not compared.
    pub fn binding_mismatch(&self, recorded: &DeploymentBinding) -> Option<String> {
        let expected = self.binding(recorded.verified_at);
        let checks: [(&str, bool); 5] = [
            (
                "vault",
                recorded.chain_id == expected.chain_id
                    && recorded.contract_address == expected.contract_address,
            ),
            (
                "state signing key",
                recorded.state_signing_key == expected.state_signing_key,
            ),
            (
                "clearance signing key",
                recorded.clearance_signing_key == expected.clearance_signing_key,
            ),
            (
                "challenge period",
                recorded.challenge_period_seconds == expected.challenge_period_seconds,
            ),
            ("statement", self.statement().mismatch(recorded).is_none()),
        ];
        checks
            .iter()
            .find(|(_, matches)| !matches)
            .map(|(field, _)| {
                format!(
                    "the database is bound to another {field} (vault {} on chain {}) than the \
                     deployment manifest (vault {} on chain {})",
                    recorded.contract_address,
                    recorded.chain_id,
                    self.contract_address,
                    self.chain_id
                )
            })
    }
}

/// What `zkapi db init` did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct DbInitReport {
    /// "bound": the binding was recorded now; "already_bound": the database
    /// was bound to this deployment and statement already, and is unchanged.
    pub result: &'static str,
    pub db_path: String,
    pub deployment_id: Option<String>,
    pub chain_id: u64,
    pub contract_address: String,
    pub circuit_id: String,
    pub setup_id: String,
    /// "manifest" until serverd verifies the binding against the vault.
    pub binding_source: String,
}

/// `zkapi db init`: create (or migrate) the server database at `db_path` with
/// its schema, the append-only `request_evidence` table and its triggers,
/// and bind it to `manifest`'s deployment and statement, whose verifying keys
/// must be the ones loaded from the proof setup (`loaded`). Holds the server
/// writer lock, so it refuses while a server runs. A database bound to
/// anything else is refused unchanged; one bound to this deployment already
/// is left as it is.
pub fn init_database(
    db_path: &Path,
    manifest: &DeploymentManifest,
    loaded: &StatementIdentity,
    now: u64,
) -> anyhow::Result<DbInitReport> {
    manifest.check_statement(loaded)?;
    let refuse_another = |recorded: &DeploymentBinding| match manifest.binding_mismatch(recorded) {
        Some(mismatch) => Err(anyhow::anyhow!(
            "refusing to initialize {}: {mismatch}; use a fresh database for each deployment, \
             circuit and setup",
            db_path.display()
        )),
        None => Ok(()),
    };
    // Before the schema is created or migrated: an existing database of any
    // release keeps a binding to another deployment untouched.
    if db_path.is_file() {
        if let Some(recorded) =
            crate::nullifier_store::NullifierStore::read_recorded_deployment_binding(db_path)
                .map_err(|error| {
                    anyhow::anyhow!(
                        "refusing to initialize {}: cannot read its deployment binding: {error}",
                        db_path.display()
                    )
                })?
        {
            refuse_another(&recorded)?;
        }
    }
    let store = crate::nullifier_store::NullifierStore::new(db_path)
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let _writer_lock = store
        .acquire_writer_lock()
        .map_err(|error| anyhow::anyhow!("{error}"))?;
    let (result, binding) = match store
        .read_deployment_binding()
        .map_err(|error| anyhow::anyhow!("{error}"))?
    {
        Some(recorded) => {
            refuse_another(&recorded)?;
            ("already_bound", recorded)
        }
        None => {
            let binding = manifest.binding(now);
            store
                .write_deployment_binding(&binding)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            ("bound", binding)
        }
    };
    Ok(DbInitReport {
        result,
        db_path: db_path.display().to_string(),
        deployment_id: manifest.deployment_id.clone(),
        chain_id: manifest.chain_id,
        contract_address: manifest.contract_address.clone(),
        circuit_id: manifest.circuit_id.clone(),
        setup_id: manifest.setup_id.clone(),
        binding_source: binding.source,
    })
}

/// What the startup probes read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeReport {
    pub proof_adapter_address: String,
    pub vault_runtime_codehash: String,
    pub adapter_runtime_codehash: String,
    pub poseidon_runtime_codehash: String,
}

/// Why a startup probe failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProbeError {
    /// A read failed (RPC unavailable, a reverted getter, no code): the
    /// probe could not run. Startup refuses; background re-verification
    /// retries.
    #[error("{0}")]
    Unavailable(String),
    /// A value differs from what this server or the manifest pins.
    #[error("{0}")]
    Mismatch(String),
}

/// Reads getters and runtime code at "latest": serverd's native-billing
/// oracle, or the challenger's RPC.
pub trait ContractReader {
    /// The single ABI word a no-argument getter `selector` of `address`
    /// returns.
    fn contract_word(
        &self,
        address: &str,
        selector: &str,
    ) -> impl std::future::Future<Output = Result<[u8; 32], String>> + Send;
    /// keccak256 of the runtime code at `address`; an address without code
    /// is an error.
    fn code_hash(
        &self,
        address: &str,
    ) -> impl std::future::Future<Output = Result<[u8; 32], String>> + Send;
}

impl ContractReader for NativeBillingOracle {
    async fn contract_word(&self, address: &str, selector: &str) -> Result<[u8; 32], String> {
        NativeBillingOracle::contract_word(self, address, selector)
            .await
            .map_err(|error| error.to_string())
    }

    async fn code_hash(&self, address: &str) -> Result<[u8; 32], String> {
        NativeBillingOracle::code_hash(self, address)
            .await
            .map_err(|error| error.to_string())
    }
}

/// The startup probes (§5.5), all at "latest" over the configured RPC. Any
/// failure, unreadable value or mismatch is an error.
pub async fn probe_deployment<R: ContractReader + Sync>(
    oracle: &R,
    manifest: &DeploymentManifest,
    loaded: &StatementIdentity,
) -> Result<ProbeReport, ProbeError> {
    manifest
        .check_statement(loaded)
        .map_err(|error| ProbeError::Mismatch(error.to_string()))?;
    let vault = &manifest.contract_address;
    let word = |selector: &'static str, target: String, name: &'static str| async move {
        oracle
            .contract_word(&target, selector)
            .await
            .map_err(|error| ProbeError::Unavailable(format!("{name} at {target}: {error}")))
    };
    let mismatch = |message: String| Err(ProbeError::Mismatch(message));
    let small = |bytes: [u8; 32]| -> Option<u64> {
        bytes[..24]
            .iter()
            .all(|byte| *byte == 0)
            .then(|| u64::from_be_bytes(bytes[24..].try_into().expect("8 bytes")))
    };
    let version = word(
        CONCESSION_ESCAPE_VERSION_SELECTOR,
        vault.clone(),
        "vault CONCESSION_ESCAPE_VERSION() (a revision-3 vault has it)",
    )
    .await?;
    if small(version) != Some(CONCESSION_ESCAPE_VERSION) {
        return mismatch(format!(
            "vault CONCESSION_ESCAPE_VERSION() is {}, not {CONCESSION_ESCAPE_VERSION}",
            hex32(&version)
        ));
    }
    let window = word(
        ROOT_HISTORY_WINDOW_SELECTOR,
        vault.clone(),
        "vault ROOT_HISTORY_WINDOW()",
    )
    .await?;
    if small(window) != Some(ROOT_HISTORY_WINDOW_SECONDS) {
        return mismatch(format!(
            "vault ROOT_HISTORY_WINDOW() is {}, not {ROOT_HISTORY_WINDOW_SECONDS}",
            hex32(&window)
        ));
    }
    let adapter_word = word(
        PROOF_ADAPTER_SELECTOR,
        vault.clone(),
        "vault proofAdapter()",
    )
    .await?;
    if adapter_word[..12].iter().any(|byte| *byte != 0) {
        return mismatch("vault proofAdapter() is not an address".into());
    }
    let adapter = format!("0x{}", hex::encode(&adapter_word[12..]));
    if adapter != manifest.proof_adapter_address {
        return mismatch(format!(
            "vault proofAdapter() is {adapter}, but the deployment manifest pins {}",
            manifest.proof_adapter_address
        ));
    }
    for (selector, name, expected, what) in [
        (
            CIRCUIT_ID_HASH_SELECTOR,
            "adapter CIRCUIT_ID_HASH()",
            hex32(&CIRCUIT_ID_HASH),
            "circuit",
        ),
        (
            REQUEST_VK_HASH_SELECTOR,
            "adapter REQUEST_VK_HASH()",
            loaded.request_vk_keccak256.clone(),
            "request verifying key",
        ),
        (
            WITHDRAWAL_VK_HASH_SELECTOR,
            "adapter WITHDRAWAL_VK_HASH()",
            loaded.withdrawal_vk_keccak256.clone(),
            "withdrawal verifying key",
        ),
    ] {
        let value = hex32(&word(selector, adapter.clone(), name).await?);
        if value != expected {
            return mismatch(format!(
                "{name} is {value}, but this server's {what} is {expected}"
            ));
        }
    }
    let mut report = ProbeReport {
        proof_adapter_address: adapter.clone(),
        vault_runtime_codehash: String::new(),
        adapter_runtime_codehash: String::new(),
        poseidon_runtime_codehash: String::new(),
    };
    for (name, target, expected, slot) in [
        (
            "vault",
            vault.clone(),
            &manifest.vault_runtime_codehash,
            &mut report.vault_runtime_codehash,
        ),
        (
            "adapter",
            adapter.clone(),
            &manifest.adapter_runtime_codehash,
            &mut report.adapter_runtime_codehash,
        ),
        (
            "Poseidon library",
            manifest.poseidon_library_address.clone(),
            &manifest.poseidon_runtime_codehash,
            &mut report.poseidon_runtime_codehash,
        ),
    ] {
        let codehash = hex32(&oracle.code_hash(&target).await.map_err(|error| {
            ProbeError::Unavailable(format!("{name} runtime code at {target}: {error}"))
        })?);
        if &codehash != expected {
            return mismatch(format!(
                "the {name} at {target} has runtime codehash {codehash}, but the deployment \
                 manifest pins {expected}"
            ));
        }
        *slot = codehash;
    }
    Ok(report)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use zkapi_types::Felt252;

    /// A manifest for the development setup at `contract`, signed by `keys`.
    pub(crate) fn manifest_json(
        contract: &str,
        keys: &crate::native_billing::VaultSigningKeys,
        identity: &StatementIdentity,
    ) -> serde_json::Value {
        serde_json::json!({
            "deployment_id": "test",
            "chain_id": 1,
            "contract_address": contract,
            "state_signing_key": keys.state,
            "clearance_signing_key": keys.clearance,
            "challenge_period": 86_400,
            "circuit_id": identity.circuit_id,
            "setup_id": identity.setup_id,
            "request_vk_keccak256": identity.request_vk_keccak256,
            "withdrawal_vk_keccak256": identity.withdrawal_vk_keccak256,
            "vault_runtime_codehash": hex32(&zkapi_proof::compact::keccak256(b"vault code")),
            "proof_adapter_address": "0x00000000000000000000000000000000000a11a5",
            "adapter_runtime_codehash": hex32(&zkapi_proof::compact::keccak256(b"adapter code")),
            "poseidon_library_address": "0x0000000000000000000000000000000000000bee",
            "poseidon_runtime_codehash": hex32(&zkapi_proof::compact::keccak256(b"poseidon code")),
            "settlement_window_seconds": 21_905,
            "exit_concession": 1,
            "vault_revision": 3,
        })
    }

    fn keys() -> crate::native_billing::VaultSigningKeys {
        let signer =
            crate::signer::ServerSigner::new(&Felt252::from_u64(11), &Felt252::from_u64(12));
        crate::native_billing::VaultSigningKeys {
            state: signer.state_public_key(),
            clearance: signer.clearance_public_key(),
        }
    }

    pub(crate) fn dev_identity() -> StatementIdentity {
        StatementIdentity::load(&crate::test_support::setup_directory()).unwrap()
    }

    /// The startup probes read the real vault's and adapter's getters
    /// (vault_calldata_golden.json, from the compiled protocol/contracts
    /// sources).
    #[test]
    fn probe_selectors_are_the_real_vault_and_adapter_getters() {
        use crate::test_support::real_selector;
        for (name, selector) in [
            (
                "CONCESSION_ESCAPE_VERSION",
                CONCESSION_ESCAPE_VERSION_SELECTOR,
            ),
            ("ROOT_HISTORY_WINDOW", ROOT_HISTORY_WINDOW_SELECTOR),
            ("proofAdapter", PROOF_ADAPTER_SELECTOR),
            ("CIRCUIT_ID_HASH", CIRCUIT_ID_HASH_SELECTOR),
            ("REQUEST_VK_HASH", REQUEST_VK_HASH_SELECTOR),
            ("WITHDRAWAL_VK_HASH", WITHDRAWAL_VK_HASH_SELECTOR),
        ] {
            assert_eq!(real_selector(name), selector, "{name}");
        }
    }

    #[test]
    fn manifests_parse_bare_or_wrapped_and_refuse_placeholders_and_other_circuits() {
        let identity = dev_identity();
        let bare = manifest_json(
            "0x00000000000000000000000000000000000000AA",
            &keys(),
            &identity,
        );
        let manifest = DeploymentManifest::parse(&bare.to_string()).unwrap();
        assert_eq!(
            manifest.contract_address,
            "0x00000000000000000000000000000000000000aa"
        );
        assert_eq!(manifest.challenge_period, 86_400);
        manifest.check_statement(&identity).unwrap();
        let wrapped =
            serde_json::json!({"trusted_deployment": bare, "proving_keys_base_url": "./"});
        assert_eq!(
            DeploymentManifest::parse(&wrapped.to_string()).unwrap(),
            manifest
        );
        // challenge_period_seconds is accepted as the clientd spelling.
        let mut clientd = bare.clone();
        let period = clientd
            .as_object_mut()
            .unwrap()
            .remove("challenge_period")
            .unwrap();
        clientd["challenge_period_seconds"] = period;
        assert_eq!(
            DeploymentManifest::parse(&clientd.to_string()).unwrap(),
            manifest
        );

        let mut placeholder = bare.clone();
        placeholder["deployment_status"] = "not_deployed".into();
        let error = DeploymentManifest::parse(&placeholder.to_string()).unwrap_err();
        assert!(error.to_string().contains("not_deployed"), "{error}");
        // Only a finalized deployment is served: Deploy.s.sol's provisional
        // statuses and unknown ones are refused; "deployed" is accepted.
        for status in ["pending", "simulated", "drill"] {
            let mut provisional = bare.clone();
            provisional["deployment_status"] = status.into();
            let error = DeploymentManifest::parse(&provisional.to_string()).unwrap_err();
            assert!(error.to_string().contains(status), "{error}");
        }
        let mut deployed = bare.clone();
        deployed["deployment_status"] = "deployed".into();
        assert!(DeploymentManifest::parse(&deployed.to_string()).is_ok());
        let mut legacy = bare.clone();
        legacy["circuit_id"] = "zkapi-v2-note-bound-v1".into();
        let error = DeploymentManifest::parse(&legacy.to_string()).unwrap_err();
        assert!(
            error.to_string().contains("zkapi-v2-note-bound-v1"),
            "{error}"
        );
        let mut capability = bare.clone();
        capability["exit_concession"] = 0.into();
        assert!(DeploymentManifest::parse(&capability.to_string()).is_err());
        let mut zero = bare;
        zero["proof_adapter_address"] = "0x0000000000000000000000000000000000000000".into();
        assert!(DeploymentManifest::parse(&zero.to_string()).is_err());
    }

    #[test]
    fn a_manifest_refuses_keys_of_another_setup() {
        let identity = dev_identity();
        let mut other = identity.clone();
        other.request_vk_keccak256 = hex32(&[9; 32]);
        let manifest = DeploymentManifest::parse(
            &manifest_json(
                "0x00000000000000000000000000000000000000aa",
                &keys(),
                &other,
            )
            .to_string(),
        )
        .unwrap();
        let error = manifest.check_statement(&identity).unwrap_err();
        assert!(error.to_string().contains("do not match"), "{error}");
    }

    /// Review regression: `zkapi db init` reads the binding of a database of
    /// the pre-change schema too, and refuses one bound to another vault, or
    /// bound before circuit identifiers were recorded, before migrating it.
    #[test]
    fn init_refuses_a_pre_change_database_without_migrating_it() {
        let identity = dev_identity();
        let keys = keys();
        let manifest = DeploymentManifest::parse(
            &manifest_json(
                "0x00000000000000000000000000000000000000aa",
                &keys,
                &identity,
            )
            .to_string(),
        )
        .unwrap();
        for (vault, expected) in [
            (
                "0x0000000000000000000000000000000000009999",
                "another vault",
            ),
            (
                "0x00000000000000000000000000000000000000aa",
                "another statement",
            ),
        ] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("server.db");
            {
                let conn = rusqlite::Connection::open(&path).unwrap();
                conn.execute_batch(crate::nullifier_store::tests::SCHEMA_4F21B66)
                    .unwrap();
                conn.execute(
                    "INSERT INTO deployment_binding (id, chain_id, contract_address, state_key_x,
                        state_key_y, clearance_key_x, clearance_key_y, challenge_period_seconds,
                        verified_at)
                     VALUES (1, 1, ?1, ?2, ?3, ?4, ?5, 86400, 7)",
                    rusqlite::params![
                        vault,
                        keys.state.x.to_hex(),
                        keys.state.y.to_hex(),
                        keys.clearance.x.to_hex(),
                        keys.clearance.y.to_hex()
                    ],
                )
                .unwrap();
            }
            let before = std::fs::read(&path).unwrap();
            let error = init_database(&path, &manifest, &identity, 9).unwrap_err();
            assert!(
                format!("{error:#}").contains(expected),
                "{vault}: {error:#}"
            );
            assert!(
                std::fs::read(&path).unwrap() == before,
                "{vault}: the database was migrated or rebound"
            );
        }
    }

    #[test]
    fn binding_mismatch_names_the_differing_part() {
        let identity = dev_identity();
        let manifest = DeploymentManifest::parse(
            &manifest_json(
                "0x00000000000000000000000000000000000000aa",
                &keys(),
                &identity,
            )
            .to_string(),
        )
        .unwrap();
        let binding = manifest.binding(1);
        assert_eq!(manifest.binding_mismatch(&binding), None);
        let mut moved = binding.clone();
        moved.contract_address = "0x00000000000000000000000000000000000000bb".into();
        assert!(manifest.binding_mismatch(&moved).unwrap().contains("vault"));
        let mut period = binding.clone();
        period.challenge_period_seconds = 7_200;
        assert!(manifest
            .binding_mismatch(&period)
            .unwrap()
            .contains("challenge period"));
        let mut setup = binding;
        setup.setup_id = Some("mpc-1".into());
        assert!(manifest
            .binding_mismatch(&setup)
            .unwrap()
            .contains("statement"));
    }
}
