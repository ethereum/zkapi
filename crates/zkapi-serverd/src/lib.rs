//! Server-side logic for the zkAPI protocol.
//!
//! This crate implements proof verification, nullifier storage, API execution,
//! Baby-JubJub Schnorr signing, and HTTP routes for the zkAPI server.

#[cfg(feature = "adversary")]
pub mod adversary;
pub mod challenge_service;
pub mod challenge_status;
pub mod config;
pub mod dashboard;
pub mod deployment;
pub mod error;
pub mod native_billing;
pub mod nullifier_store;
pub mod oa_org;
pub mod openrouter;
pub mod pricing;
#[path = "processor_v2.rs"]
pub mod processor;
pub mod routes;
pub mod settlement;
#[path = "signer_v2.rs"]
pub mod signer;
pub mod successor;
pub mod testnet_auth;
pub mod watcher;
mod writer_lock;

#[cfg(test)]
pub(crate) mod test_support;

#[cfg(test)]
mod note_binding;
