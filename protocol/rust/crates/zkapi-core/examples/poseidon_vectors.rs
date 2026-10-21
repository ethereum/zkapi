//! Regenerate the entries of a Poseidon vector file that derive from the note
//! tree's node hash (`merkle_node`, `merkle_root`, `zero_hashes`), keeping the
//! others, and print the constants the Solidity library and its tests pin:
//!
//! ```text
//! cargo run -p zkapi-core --example poseidon_vectors -- \
//!     zkapi-clientd/internal/zkapi/testdata/poseidon-vectors.json
//! ```
use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use zkapi_core::merkle::compute_zero_hashes;
use zkapi_core::v2::{hash_felts, merkle_node, merkle_root};
use zkapi_types::{Felt252, MERKLE_DEPTH};

fn felt(word: &str) -> Felt252 {
    Felt252::from_hex(word).expect("hex word")
}

fn word(value: &Felt252) -> String {
    format!("0x{}", hex::encode(value.as_bytes()))
}

fn main() -> anyhow::Result<()> {
    let zeros = compute_zero_hashes();
    if let Some(path) = std::env::args().nth(1) {
        let mut vectors: Map<String, Value> =
            serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        if let Some(Value::Array(nodes)) = vectors.get_mut("merkle_node") {
            for node in nodes.iter_mut() {
                let left = felt(node["left"].as_str().unwrap());
                let right = felt(node["right"].as_str().unwrap());
                node["node"] = json!(word(&merkle_node(&left, &right)));
            }
        }
        if let Some(Value::Array(roots)) = vectors.get_mut("merkle_root") {
            for entry in roots.iter_mut() {
                let note_id = entry["note_id"].as_u64().unwrap() as u32;
                let leaf = felt(entry["leaf"].as_str().unwrap());
                let mut siblings = [Felt252::ZERO; MERKLE_DEPTH];
                for (slot, sibling) in siblings
                    .iter_mut()
                    .zip(entry["siblings"].as_array().unwrap())
                {
                    *slot = felt(sibling.as_str().unwrap());
                }
                entry["root"] = json!(word(&merkle_root(note_id, &leaf, &siblings)));
            }
        }
        vectors.insert(
            "zero_hashes".into(),
            json!(zeros.iter().map(word).collect::<Vec<_>>()),
        );
        vectors.insert(
            "source".into(),
            json!("protocol/rust/crates/zkapi-core/src/v2.rs (arkworks PoseidonSponge, width 3, rate 2, alpha 5, 8 full + 57 partial rounds; merkle_node is one permutation with the domain in the capacity lane)"),
        );
        std::fs::write(
            &path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&Value::Object(vectors))?
            ),
        )?;
        eprintln!("rewrote {path}");
    }
    let mut out = BTreeMap::new();
    out.insert(
        "node_1_2",
        word(&merkle_node(&Felt252::from_u64(1), &Felt252::from_u64(2))),
    );
    out.insert(
        "hash5_1_2_3_4_5",
        word(&hash_felts(&[1u64, 2, 3, 4, 5].map(Felt252::from_u64))),
    );
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "vectors": out,
            "zero_hashes": zeros.iter().map(word).collect::<Vec<_>>(),
        }))?
    );
    Ok(())
}
