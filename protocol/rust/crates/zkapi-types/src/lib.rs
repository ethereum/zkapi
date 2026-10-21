//! Shared types for the zkAPI protocol.
//!
//! This crate defines the canonical data structures used across client, server,
//! and proof systems. All field elements are represented as 32-byte big-endian
//! arrays internally and serialized as `0x`-prefixed lowercase hex strings in JSON.

pub mod felt;
pub mod inputs;
pub mod note;
pub mod serialization;
pub mod signature;
pub mod wire;

pub use felt::Felt252;
pub use inputs::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash,
    RequestPublicInputsV2, WithdrawalKind, WithdrawalPublicInputsV2C,
};
pub use note::NullifierStatus;
pub use signature::SchnorrSignature;

/// Protocol version for the compact BN254 proof protocol.
pub const PROTOCOL_VERSION: u16 = 2;

/// Merkle tree depth.
pub const MERKLE_DEPTH: usize = 32;

/// BN254 scalar-field modulus used by the v2 statements.
pub const FIELD_MODULUS_HEX: &str =
    "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
