use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RequestMode {
    /// The zkAPI server forwards each LLM request to its configured provider.
    #[default]
    Proxy,
    /// The local daemon leases bounded OpenRouter keys and sends prompts
    /// directly; the zkAPI server sees only lease settlement.
    DirectOpenrouter,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModelDescriptor {
    pub id: String,
    pub owned_by: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl ModelDescriptor {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            owned_by: "zkapi".to_string(),
            tags: vec!["chat".to_string(), "responses".to_string()],
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub deployment_id: String,
    pub billing_asset: String,
    pub billing_unit: String,
    pub native_asset_wei_per_unit: String,
    pub native_price_feed_address: String,
    pub native_price_feed_decimals: u8,
    pub native_price_max_age_seconds: u64,
    /// The manifest's `vault_revision` (3 for circuit
    /// `zkapi-v2-concession-v1`); reported, not branched on.
    pub vault_revision: u32,
    /// The manifest's `proof_setup.setup_id` (`mpc-1`, or `dev` for drills
    /// and tests): reported on `/oa/v1/status`.
    pub setup_id: String,
    /// W: the build-pinned `settlement_window_seconds` (C4, E3).
    pub settlement_window_seconds: u64,
    /// E3's `unsettled_request_escape_after_seconds`; `None` is 43,200 s.
    pub unsettled_request_escape_after_seconds: Option<u64>,
    /// The vault's deployment block: where a log rebuild starts (§6.6).
    pub deploy_block: u64,
    /// The user's own RPC for exits (`--exit-rpc-url`): `E_low`, rebuilds
    /// and advisory reads also go through it.
    pub exit_rpc_url: Option<String>,

    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub request_charge_cap: u128,
    pub policy_charge_cap: u128,
    pub policy_enabled: bool,
    /// Authentication method this client uses; must match the server's.
    pub auth_scheme: zkapi_auth::AuthSchemeKind,
    pub protocol_server_url: String,
    pub indexer_url: String,
    pub listen_addr: String,
    pub state_dir: PathBuf,
    pub models: Vec<ModelDescriptor>,
    /// Fresh-note amount suggested by the bundled browser UI, in billing-token
    /// base units.
    pub suggested_deposit_amount: u128,
    pub demo_rpc_url: Option<String>,
    pub demo_billing_token_address: Option<String>,
    pub demo_mint_enabled: bool,
    pub demo_note_ttl_seconds: Option<u64>,
    /// Circuit-specific Groth16 key directory (`zkapi-v2-concession-v1`).
    pub proof_setup_dir: String,
    /// Deployment-pinned proof-friendly signing keys.
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    pub request_mode: RequestMode,
    /// Independently configured OA verifier trust anchor. Verifier URLs
    /// supplied by a zkAPI server must match this value exactly.
    pub oa_verifier_url: String,
    /// Independently configured inference origin. Lease responses must match
    /// this value exactly before a child key or prompt is transmitted.
    pub openrouter_inference_base: String,
    /// Reject direct/legacy OpenRouter leases and require verifier-backed OA
    /// org evidence. This is an independent anti-downgrade policy.
    pub require_oa_org_key_source: bool,
}

impl AuthConfig {
    /// Wire label for the configured proof backend.
    pub fn proof_backend_label(&self) -> &'static str {
        "groth16_bn254"
    }
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            deployment_id: String::new(),
            billing_asset: "erc20".into(),
            billing_unit: "micro_usdc".into(),
            native_asset_wei_per_unit: "0".into(),
            native_price_feed_address: String::new(),
            native_price_feed_decimals: 8,
            native_price_max_age_seconds: 3600,
            vault_revision: 3,
            setup_id: "dev".into(),
            settlement_window_seconds: 21_905,
            unsettled_request_escape_after_seconds: None,
            deploy_block: 0,
            exit_rpc_url: None,
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::ZERO,
            request_charge_cap: 1_000_000,
            policy_charge_cap: 10_000_000,
            policy_enabled: false,
            auth_scheme: zkapi_auth::AuthSchemeKind::StateAnchor,
            protocol_server_url: "http://127.0.0.1:3000".to_string(),
            indexer_url: "http://127.0.0.1:3001".to_string(),
            listen_addr: "127.0.0.1:11434".to_string(),
            state_dir: PathBuf::from(".zkapi"),
            models: vec![ModelDescriptor::new("zkapi-echo")],
            suggested_deposit_amount: 2_000_000,
            demo_rpc_url: None,
            demo_billing_token_address: None,
            demo_mint_enabled: false,
            demo_note_ttl_seconds: None,
            proof_setup_dir: "protocol/setup/v2-concession".to_string(),
            state_signing_key: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ONE,
            },
            clearance_signing_key: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ONE,
            },
            request_mode: RequestMode::Proxy,
            oa_verifier_url: "https://verifier2.openanonymity.ai".to_string(),
            openrouter_inference_base: "https://openrouter.ai/api/v1".to_string(),
            require_oa_org_key_source: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_backend_label_is_groth16() {
        assert_eq!(AuthConfig::default().proof_backend_label(), "groth16_bn254");
    }
}
