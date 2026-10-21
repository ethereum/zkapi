//! zkAPI Groth16 circuits (`zkapi-v2-concession-v1`) and native proof interface.
//!
//! * [`groth16`]: the request and withdrawal circuits and native mirrors of
//!   their hashes.
//! * [`compact`]: wire-level provers and verifiers, key headers and setup
//!   policy, setup directories and the generated Solidity adapter.
//! * [`reduction`]: the snarkjs-compatible R1CS-to-QAP reduction every prover
//!   uses.
//! * [`r1cs`]: export of the circuits as circom `.r1cs` files for the
//!   multi-party setup.
//! * [`ceremony`] (not on wasm32): powers-of-tau reading and the check that
//!   imported phase-2 keys belong to this build's circuits.
//! * [`dev`] (feature `dev-fixtures`): deterministic development fixtures.
//!
//! Features:
//! * `dev-setup` makes the build *accept* development and rehearsal keys
//!   ([`compact::check_setup_accepted`]). Tests and CI enable it, and so do
//!   the production builds of a single-party vault, but only when asked on
//!   their command line (`ALLOW_DEV_SETUP=1`, or `--setup dev` for the
//!   browser bundle); no production binary gets it through a dependency or
//!   feature unification.
//! * `dev-fixtures` exposes [`dev`]. It changes no acceptance policy.
//!
//! Generating development keys ([`compact::setup`]) needs neither feature.

#[cfg(not(target_arch = "wasm32"))]
pub mod ceremony;
pub mod compact;
#[cfg(feature = "dev-fixtures")]
pub mod dev;
pub mod groth16;
pub mod r1cs;
pub mod reduction;
