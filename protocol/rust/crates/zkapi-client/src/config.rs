//! Client configuration.

use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

/// Proof backend used by the wallet when building request/withdrawal proofs.
#[derive(Debug, Clone)]
pub enum ClientProofMode {
    /// Generate compact Groth16 proofs using the circuit-specific setup files.
    Groth16 { setup_dir: String },
}

/// Configuration for the client SDK, matching the deployed contract parameters.
pub struct ClientConfig {
    /// Protocol version (must be 2).
    pub protocol_version: u16,
    /// Chain ID of the target network.
    pub chain_id: u64,
    /// Address of the deployed ZkApiVault contract.
    pub contract_address: Felt252,
    /// Maximum charge the server may apply per ordinary request.
    pub request_charge_cap: u128,
    /// Maximum charge the server may apply under policy rejection.
    pub policy_charge_cap: u128,
    /// Whether policy-based charge enforcement is active on this deployment.
    pub policy_enabled: bool,
    /// Base URL of the zkAPI server (e.g. "http://localhost:8080").
    pub server_url: String,
    /// Directory for persisting wallet state and journals.
    pub state_dir: String,
    /// Proof backend used for runtime proof generation.
    pub proof_mode: ClientProofMode,
    /// Server signing keys pinned by the deployment contract/configuration.
    pub state_signing_key: CurvePointWire,
    pub clearance_signing_key: CurvePointWire,
    /// W: the build-pinned `settlement_window_seconds` of the deployment,
    /// for the near-expiry refusal (C4).
    pub settlement_window_seconds: u64,
}
