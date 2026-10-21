//! Rewrite the generated sources of an existing setup directory from its keys
//! (`Groth16ProofAdapter.sol`, `Bn254Poseidon.sol` and the manifest's `poseidon`
//! section), after a change to the generators that leaves the keys alone:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example refresh_setup_sources -- ../setup/v2-concession-dev
//! ```
fn main() -> anyhow::Result<()> {
    let directory = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: refresh_setup_sources SETUP_DIRECTORY"))?;
    zkapi_proof::compact::refresh_setup_sources(&directory)?;
    println!("regenerated the Solidity sources and the Poseidon manifest of {directory}");
    Ok(())
}
