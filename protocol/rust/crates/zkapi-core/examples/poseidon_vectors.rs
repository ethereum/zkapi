//! Regenerate the entries of a Poseidon vector file that derive from the note
//! tree's node hash (`merkle_node`, `merkle_root`, `zero_hashes`) and the note
//! leaf (`note_leaf`, the `zkapi.v2c.leaf` domain), keeping the others, and
//! print the constants the Solidity library and its tests pin:
//!
//! ```text
//! cargo run -p zkapi-core --example poseidon_vectors -- \
//!     zkapi-clientd/internal/zkapi/testdata/poseidon-vectors.json
//! ```
use std::collections::BTreeMap;

use serde_json::{json, Map, Value};
use zkapi_core::merkle::compute_zero_hashes;
use zkapi_core::v2::{
    domain_value, hash_felts, merkle_node, merkle_root, note_fields, note_leaf,
    registration_commitment, DOMAIN_LEAF,
};
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
        if let Some(Value::Array(leaves)) = vectors.get_mut("note_leaf") {
            for entry in leaves.iter_mut() {
                let note_id = entry["note_id"].as_u64().unwrap() as u32;
                let commitment = felt(entry["commitment"].as_str().unwrap());
                let amount: u128 = entry["amount"].as_str().unwrap().parse()?;
                let expiry: u64 = entry["expiry_ts"].as_str().unwrap().parse()?;
                entry["fields"] = json!(word(&note_fields(note_id, amount, expiry)));
                entry["leaf"] = json!(word(&note_leaf(note_id, &commitment, amount, expiry)));
            }
        }
        if let Some(Value::Object(domains)) = vectors.get_mut("domains") {
            domains.insert(
                String::from_utf8(DOMAIN_LEAF.to_vec())?,
                json!(word(&domain_value(DOMAIN_LEAF))),
            );
        }
        vectors.insert(
            "zero_hashes".into(),
            json!(zeros.iter().map(word).collect::<Vec<_>>()),
        );
        vectors.insert(
            "source".into(),
            json!("protocol/rust/crates/zkapi-core/src/v2.rs (arkworks PoseidonSponge, width 3, rate 2, alpha 5, 8 full + 57 partial rounds; merkle_node and note_leaf are one permutation with the domain in the capacity lane, note_leaf over (commitment, note_fields))"),
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
    let registration = registration_commitment(&Felt252::from_u64(42));
    out.insert(
        "leaf_s42_n7_d5000000_e4000000000",
        word(&note_leaf(7, &registration, 5_000_000, 4_000_000_000)),
    );
    out.insert(
        "fields_n7_d5000000_e4000000000",
        word(&note_fields(7, 5_000_000, 4_000_000_000)),
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
