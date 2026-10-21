//! Native lease fixtures; never compiled into the server binary.
//!
//! Real proofs use the development setup (`protocol/setup/v2-concession-dev`)
//! and the `zkapi_proof::dev` state chain. [`complete_response`] is the
//! client's successor check (S1–S6 of the design) and install, so a test can
//! spend the successor the server signed in the next request proof.
use std::sync::OnceLock;

use anyhow::{ensure, Context};
use zkapi_core::v2 as core;
use zkapi_core::MerkleTree;
use zkapi_proof::compact::{
    add_blindings, random_scalar, rerandomize, server_update, verify_signature, CompactSigner,
    RequestProver, WithdrawalProver,
};
use zkapi_proof::dev::{DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_types::wire::{
    ApiRequestV2, ClearanceOwnershipProofV2C, ClearanceRequestV2C, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    WithdrawalKind,
};

use crate::config::{
    OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig,
    DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
};
use crate::native_billing::NativeBillingConfig;

/// A settlement deadline no lifecycle test reaches. Most lifecycle fixtures
/// use 1970 timestamps, which a real deadline would force-finalize at once.
pub(crate) const TEST_DEADLINE_DISABLED: u64 = u64::MAX / 4;

pub(crate) fn native_config() -> NativeBillingConfig {
    NativeBillingConfig {
        rpc_url: "http://127.0.0.1:9".into(),
        feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
        decimals: 8,
        max_age_seconds: 4500,
    }
}

pub(crate) fn lease_config() -> OpenRouterLeaseConfig {
    OpenRouterLeaseConfig {
        source: OpenRouterLeaseSourceConfig::OaOrg {
            org_base_url: "http://127.0.0.1:9".into(),
            shared_secret: "test-secret".into(),
        },
        ttl_seconds: 300,
        settlement_grace_seconds: 0,
        settlement_poll_seconds: 1,
        settlement_deadline_seconds: DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
    }
}

pub(crate) fn lease_payload(config: &ServerConfig, now: u64) -> String {
    let native = config.native_billing.as_ref().unwrap();
    // A fixed $1000/ETH test quote makes one micro-USD equal one gwei.
    serde_json::json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":{
        "asset":"native_eth", "units_per_eth":1_000_000_000, "chain_id":config.chain_id,
        "feed_address":native.feed_address, "round_id":"123", "answer":"100000000000",
        "decimals":native.decimals, "updated_at":now, "expires_at":now+native.max_age_seconds,
    }})
    .to_string()
}

/// The development setup every test proof uses.
pub(crate) fn setup_directory() -> String {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/setup/v2-concession-dev")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .to_string()
}

/// A base64 Groth16-sized proof that does not verify: lifecycle fixtures
/// start at the durable boundary after admission verified the real one.
pub(crate) fn fake_proof(fill: u8) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode([fill; 256])
}

pub(crate) fn request_prover() -> &'static RequestProver {
    static PROVER: OnceLock<RequestProver> = OnceLock::new();
    PROVER.get_or_init(|| RequestProver::load(setup_directory()).unwrap())
}

pub(crate) fn withdrawal_prover() -> &'static WithdrawalProver {
    static PROVER: OnceLock<WithdrawalProver> = OnceLock::new();
    PROVER.get_or_init(|| WithdrawalProver::load(setup_directory()).unwrap())
}

/// The deployment a processor serves, signed with the given seeds (which the
/// test built the processor's `ServerSigner` from).
pub(crate) fn deployment_of(config: &ServerConfig, seeds: (Felt252, Felt252)) -> DevDeployment {
    DevDeployment {
        protocol_version: config.protocol_version,
        chain_id: config.chain_id,
        contract_address: config.contract_address,
        state_signer: CompactSigner::from_seed(&seeds.0),
        clearance_signer: CompactSigner::from_seed(&seeds.1),
    }
}

/// A note a test wallet holds: its deployment, current state and tree.
#[derive(Clone)]
pub(crate) struct TestNote {
    pub(crate) deployment: DevDeployment,
    pub(crate) state: DevState,
    pub(crate) tree: MerkleTree,
}

impl TestNote {
    /// A fresh genesis note of `deposit` as note 0, the only leaf of a fresh
    /// tree.
    pub(crate) fn genesis(deployment: DevDeployment, deposit: u128) -> Self {
        let note = DevNote {
            secret: random_scalar(),
            note_id: 0,
            deposit_amount: deposit,
            expiry: 4_000_000_000,
        };
        let tree = zkapi_proof::dev::tree_with(&[&note]);
        Self {
            deployment,
            state: note.genesis(random_scalar()),
            tree,
        }
    }

    pub(crate) fn root(&self) -> Felt252 {
        self.tree.root()
    }

    /// A real request proof from the current state for `payload`.
    pub(crate) fn prepare_request(
        &self,
        client_request_id: &str,
        payload: String,
        request_time: u64,
        solvency_bound: u128,
    ) -> PreparedTestRequest {
        let payload_hash = canonical_payload_hash(payload.as_bytes());
        let params = DevRequest {
            request_time,
            solvency_bound,
            request_context: canonical_request_context(client_request_id, &payload_hash),
            rerandomization: random_scalar(),
        };
        let (public, witness) = self
            .state
            .request(&self.deployment, &self.tree, &params)
            .unwrap();
        let proof = request_prover().prove(&public, witness).unwrap();
        PreparedTestRequest {
            request: ApiRequestV2 {
                client_request_id: client_request_id.into(),
                payload,
                payload_hash,
                public_inputs: public,
                proof,
            },
            params,
            state: self.state.clone(),
        }
    }

    /// The client's check (S1–S6) and install of the successor the server
    /// returned for `prepared`; the note moves to it.
    pub(crate) fn complete(
        &mut self,
        prepared: &PreparedTestRequest,
        response: &RequestResponseV2,
    ) -> anyhow::Result<()> {
        self.state = complete_response(&self.deployment, prepared, response)?;
        Ok(())
    }

    /// A kind-2 ownership proof of the current state, valid until
    /// `valid_until`, as a clearance request.
    pub(crate) fn ownership_request(&self, valid_until: u64) -> ClearanceRequestV2C {
        let (public, witness) = self
            .state
            .withdrawal(
                &self.deployment,
                &self.tree,
                &DevWithdrawal {
                    kind: WithdrawalKind::Ownership,
                    destination: [0; 20],
                    conceded: 0,
                    valid_until,
                },
            )
            .unwrap();
        let proof = withdrawal_prover().prove(&public, witness).unwrap();
        ClearanceRequestV2C {
            withdrawal_nullifier: public.withdrawal_nullifier,
            ownership_proof: ClearanceOwnershipProofV2C {
                public_inputs: public,
                proof,
            },
        }
    }
}

/// A request a test wallet proved, with what installs its successor.
#[derive(Clone)]
pub(crate) struct PreparedTestRequest {
    pub(crate) request: ApiRequestV2,
    pub(crate) params: DevRequest,
    /// The state the request was proved from.
    pub(crate) state: DevState,
}

/// The client's checks of a successor (S1–S6) and its install:
/// S1 the response is for this request and nullifier; S2 its hash; S3 its
/// charge is within the request's bound; S4 its anchor is `succ(N)`; S5 its
/// commitment is `C + ε·H − charge·G + δ·H`; S6 its signature verifies under
/// the deployment's state key. The installed state is `(B − charge,
/// r + ε + δ, succ(N))` with the old anchor as `prev_anchor`.
pub(crate) fn complete_response(
    deployment: &DevDeployment,
    prepared: &PreparedTestRequest,
    response: &RequestResponseV2,
) -> anyhow::Result<DevState> {
    let state = &prepared.state;
    let nullifier = state.nullifier();
    ensure!(
        response.client_request_id == prepared.request.client_request_id
            && response.request_nullifier == nullifier,
        "S1: the response is for another request"
    );
    ensure!(
        response.response_hash == canonical_response_hash(response.response_payload.as_bytes()),
        "S2: response hash"
    );
    ensure!(
        response.charge_applied <= prepared.params.solvency_bound,
        "S3: the charge exceeds the request's bound"
    );
    ensure!(
        response.next_anchor == core::next_anchor(&nullifier),
        "S4: the successor is not at succ(N)"
    );
    let anonymous = rerandomize(&state.commitment(), &prepared.params.rerandomization)?;
    ensure!(
        server_update(
            &anonymous,
            response.charge_applied,
            &response.blind_delta_srv
        )? == response.next_commitment,
        "S5: the successor commitment does not follow from the request"
    );
    let message = core::state_message(
        deployment.protocol_version,
        deployment.chain_id,
        &deployment.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &response.next_anchor,
    );
    ensure!(
        verify_signature(
            &deployment.state_key(),
            &message,
            &response.next_state_signature
        )?,
        "S6: the successor signature does not verify"
    );
    let next = DevState {
        note: state.note.clone(),
        balance: state
            .balance
            .checked_sub(response.charge_applied)
            .context("charge above balance")?,
        blinding: add_blindings(
            &add_blindings(&state.blinding, &prepared.params.rerandomization),
            &response.blind_delta_srv,
        ),
        anchor: response.next_anchor,
        prev_anchor: Some(state.anchor),
        signature: Some(response.next_state_signature),
    };
    ensure!(
        next.commitment() == response.next_commitment,
        "the successor commitment does not open"
    );
    Ok(next)
}

/// A genesis note of `deposit` under `processor`'s deployment, signed with
/// `seeds`, as the only leaf of a fresh tree whose root the processor has
/// observed.
pub(crate) fn processor_note(
    processor: &crate::processor::RequestProcessor,
    seeds: (Felt252, Felt252),
    deposit: u128,
) -> TestNote {
    let note = TestNote::genesis(deployment_of(processor.config(), seeds), deposit);
    assert_eq!(
        note.deployment.state_key(),
        processor.state_signing_key(),
        "the seeds are not the processor's"
    );
    processor.update_root(note.root());
    note
}

/// Kind-2 ownership proofs for clearance tests. Proving is slow in debug
/// builds, so each is generated once per test binary.
pub(crate) struct OwnershipFixture {
    pub(crate) note: TestNote,
    /// The note's tree root (the processor fixture must observe it).
    pub(crate) root: Felt252,
    pub(crate) request: ClearanceRequestV2C,
}

/// Deployment of `ownership_processor`: the keys and identity the cached
/// proofs are bound to.
pub(crate) fn ownership_server_config() -> ServerConfig {
    ServerConfig {
        request_charge_cap: 1,
        contract_address: Felt252::from_u64(1),
        native_billing: Some(native_config()),
        openrouter_leases: Some(lease_config()),
        proof_setup_dir: setup_directory(),
        ..Default::default()
    }
}

/// Seeds of `ownership_processor` (fixtures only; never served).
pub(crate) const OWNERSHIP_SEEDS: (u64, u64) = (11, 12);

pub(crate) fn ownership_seeds() -> (Felt252, Felt252) {
    (
        Felt252::from_u64(OWNERSHIP_SEEDS.0),
        Felt252::from_u64(OWNERSHIP_SEEDS.1),
    )
}

pub(crate) fn current_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn prove_ownership(fake_tree: bool) -> OwnershipFixture {
    let deployment = deployment_of(&ownership_server_config(), ownership_seeds());
    let mut note = TestNote::genesis(deployment, 1_950_000);
    if fake_tree {
        // A genesis note in a tree that no vault ever had: the proof itself
        // verifies, but its root is unknown to the server and the vault.
        note.tree.set_leaf(1, Felt252::from_u64(0xfa4e));
    }
    // Fresh for the whole test run: at most an hour ahead.
    let request = note.ownership_request(current_time() + 3_000);
    OwnershipFixture {
        root: note.root(),
        note,
        request,
    }
}

/// A real kind-2 proof for a note in a tree the processor fixture observes.
pub(crate) async fn ownership_fixture() -> &'static OwnershipFixture {
    static FIXTURE: tokio::sync::OnceCell<OwnershipFixture> = tokio::sync::OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            tokio::task::spawn_blocking(|| prove_ownership(false))
                .await
                .unwrap()
        })
        .await
}

/// A real kind-2 proof over a fake genesis tree: valid, but at a root no
/// vault knows.
pub(crate) async fn fake_tree_ownership_fixture() -> &'static OwnershipFixture {
    static FIXTURE: tokio::sync::OnceCell<OwnershipFixture> = tokio::sync::OnceCell::const_new();
    FIXTURE
        .get_or_init(|| async {
            tokio::task::spawn_blocking(|| prove_ownership(true))
                .await
                .unwrap()
        })
        .await
}

/// The real revision-3 vault's calldata, getter selectors and layouts, and
/// event layouts (`tests/fixtures/vault_calldata_golden.json`, checked
/// against the compiled protocol/contracts sources by
/// `check-calldata-golden.sh`).
pub(crate) fn real_vault_layout() -> &'static serde_json::Value {
    static LAYOUT: OnceLock<serde_json::Value> = OnceLock::new();
    LAYOUT.get_or_init(|| {
        serde_json::from_str(include_str!("../tests/fixtures/vault_calldata_golden.json"))
            .expect("vault_calldata_golden.json")
    })
}

/// The real vault's selector of `name`, as `0x` and 8 hex digits.
pub(crate) fn real_selector(name: &str) -> &'static str {
    real_vault_layout()["selectors"][name]
        .as_str()
        .unwrap_or_else(|| panic!("no selector {name} in vault_calldata_golden.json"))
}

/// The ABI words the real vault's struct getter `name` returns.
pub(crate) fn real_getter_words(name: &str) -> usize {
    real_vault_layout()["getter_words"][name]
        .as_u64()
        .unwrap_or_else(|| panic!("no getter {name} in vault_calldata_golden.json")) as usize
}

/// A log of the real vault's event `name`: its topics (`0x` words, topic0
/// first) and its data (`0x` hex).
pub(crate) fn real_event(name: &str) -> (Vec<String>, String) {
    let event = &real_vault_layout()["events"][name];
    let topics = event["topics"]
        .as_str()
        .and_then(|topics| topics.strip_prefix("0x"))
        .unwrap_or_else(|| panic!("no event {name} in vault_calldata_golden.json"));
    let topics = topics
        .as_bytes()
        .chunks(64)
        .map(|word| format!("0x{}", std::str::from_utf8(word).unwrap()))
        .collect();
    (topics, event["data"].as_str().unwrap().to_string())
}
