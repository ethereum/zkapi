//! Generate a fresh single-party development setup (setup id `dev`) with the
//! shipping `CircomReduction`:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example setup -- ../setup/v2-concession-dev
//! ```
//!
//! Writes the ten keys (request, withdrawal and the 1-, 4- and 16-note
//! insertion circuits), `manifest.json`, `Bn254Poseidon.sol` and
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
        "{} setup {} written to {directory}",
        manifest.circuit_id, manifest.setup_id
    );
    for kind in zkapi_proof::compact::KeyKind::ALL {
        println!("{kind} VK keccak256 {}", manifest.vk_keccak256.get(kind));
    }
    Ok(())
}
