//! Generate a fresh single-party development setup (setup id `dev`) with the
//! shipping `CircomReduction`:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example setup -- ../setup/v2-concession-dev
//! ```
//!
//! Writes the four keys, `manifest.json`, `Bn254Poseidon.sol` and
//! `Groth16ProofAdapter.sol`. Release builds refuse `dev` keys.
fn main() -> anyhow::Result<()> {
    let directory = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("usage: setup NEW_OUTPUT_DIRECTORY"))?;
    anyhow::ensure!(
        !std::path::Path::new(&directory).exists(),
        "refusing to overwrite an existing setup directory"
    );
    zkapi_proof::compact::setup(&directory)?;
    let manifest = std::fs::read_to_string(
        std::path::Path::new(&directory).join(zkapi_proof::compact::SETUP_MANIFEST_FILE),
    )?;
    let manifest: zkapi_proof::compact::SetupManifest = serde_json::from_str(&manifest)?;
    println!(
        "{} setup {} written to {directory}\nrequest VK keccak256 {}\nwithdrawal VK keccak256 {}",
        manifest.circuit_id,
        manifest.setup_id,
        manifest.vk_keccak256.request,
        manifest.vk_keccak256.withdrawal
    );
    Ok(())
}
