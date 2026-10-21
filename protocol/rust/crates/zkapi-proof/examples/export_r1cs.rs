//! Export both circuits as circom `.r1cs` files for the snarkjs phase-2
//! setup (G-SETUP step 1):
//!
//! ```text
//! cargo run --release -p zkapi-proof --example export_r1cs -- OUTPUT_DIRECTORY
//! ```
//!
//! Writes `request.r1cs`, `withdrawal.r1cs` and `r1cs-manifest.json` (circuit
//! id, SHA-256 of each file and the circuit shapes). The matrices are the
//! finalized ones the arkworks generator and prover use
//! (`OptimizationGoal::Constraints`, then `finalize()`); wire order is
//! `[one, public inputs in statement order, witnesses]`.
use anyhow::{Context, Result};
use serde_json::json;
use zkapi_proof::compact::{circuit_shape, sha256, KeyKind, CIRCUIT_ID};
use zkapi_proof::r1cs::{r1cs_bytes, REQUEST_R1CS_FILE, WITHDRAWAL_R1CS_FILE};

fn main() -> Result<()> {
    let directory = std::env::args()
        .nth(1)
        .context("usage: export_r1cs OUTPUT_DIRECTORY")?;
    let directory = std::path::Path::new(&directory);
    std::fs::create_dir_all(directory)?;
    let mut files = serde_json::Map::new();
    let mut shapes = serde_json::Map::new();
    for (kind, file) in [
        (KeyKind::Request, REQUEST_R1CS_FILE),
        (KeyKind::Withdrawal, WITHDRAWAL_R1CS_FILE),
    ] {
        let bytes = r1cs_bytes(kind)?;
        let path = directory.join(file);
        std::fs::write(&path, &bytes).with_context(|| format!("write {}", path.display()))?;
        let digest = hex::encode(sha256(&bytes));
        let shape = circuit_shape(kind)?;
        println!(
            "{file}: {} constraints, {} public inputs, {} witnesses, domain 2^{}, sha256 {digest}",
            shape.constraints,
            shape.public_inputs,
            shape.witness_variables,
            shape.domain_size.trailing_zeros()
        );
        files.insert(file.to_string(), digest.into());
        shapes.insert(kind.as_str().to_string(), serde_json::to_value(shape)?);
    }
    let manifest = json!({
        "circuit_id": CIRCUIT_ID,
        "files": files,
        "circuits": shapes,
    });
    std::fs::write(
        directory.join("r1cs-manifest.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    Ok(())
}
