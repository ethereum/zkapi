//! Client SDK for zkAPI: wallet state, note lifecycle, proof generation,
//! persistence, and recovery for circuit `zkapi-v2-concession-v1`.

pub mod config;
pub mod error;
pub mod exit_lock;
pub mod exit_policy;
pub mod journal;
pub mod note_state;
pub mod testnet_auth;
pub mod tree;
pub mod wallet;
