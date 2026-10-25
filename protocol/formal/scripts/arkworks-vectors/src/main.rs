//! Known-answer vectors for protocol/formal, computed with arkworks and zkapi-core.
//!
//! `permutation`: the Poseidon permutation of whole states (all three lanes, including a
//! non-zero capacity lane), with the configuration `zkapi_core::v2` builds at run time
//! (`find_poseidon_ark_and_mds::<Fr>(254, 2, 8, 57, 0)`, `PoseidonConfig::new(8, 57, 5, mds, ark,
//! 2, 1)`). arkworks keeps `permute` private; a sponge whose state is set directly and which then
//! squeezes `rate` elements runs exactly one permutation, so its state afterwards is the
//! permuted state. Lane 1 is cross-checked against `zkapi_core::v2::compress_fields`.
//!
//! `check PATH`: recompute, with the current zkapi-core, every entry of
//! `zkapi-clientd/internal/zkapi/testdata/poseidon-vectors.json` that protocol/formal uses.

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use serde_json::{json, Value};
use zkapi_core::v2::{
    compress_fields, hash_felts, merkle_node, merkle_root, note_leaf, registration_commitment, zero_hashes,
};
use zkapi_types::Felt252;

fn hex_bytes(s: &str) -> Vec<u8> {
    let s = s.strip_prefix("0x").expect("0x prefix");
    assert!(s.len() % 2 == 0);
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex")).collect()
}

fn fr(s: &str) -> Fr {
    Fr::from_be_bytes_mod_order(&hex_bytes(s))
}

fn hexf(x: &Fr) -> String {
    let b = x.into_bigint().to_bytes_be();
    format!("0x{}", b.iter().map(|v| format!("{v:02x}")).collect::<String>())
}

fn felt(s: &str) -> Felt252 {
    let b = hex_bytes(s);
    let mut a = [0u8; 32];
    a[32 - b.len()..].copy_from_slice(&b);
    Felt252(a)
}

fn hexfelt(x: &Felt252) -> String {
    format!("0x{}", x.0.iter().map(|v| format!("{v:02x}")).collect::<String>())
}

fn permute(state: [Fr; 3]) -> [Fr; 3] {
    let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(Fr::MODULUS_BIT_SIZE as u64, 2, 8, 57, 0);
    let config = PoseidonConfig::new(8, 57, 5, mds, ark, 2, 1);
    let mut sponge = PoseidonSponge::new(&config);
    sponge.state = state.to_vec();
    let _ = sponge.squeeze_native_field_elements(2);
    [sponge.state[0], sponge.state[1], sponge.state[2]]
}

fn permutation_vectors() -> Value {
    let p_minus_1 = "0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000000";
    let states: Vec<[&str; 3]> = vec![
        ["0x0b", "0x16", "0x21"],
        ["0x7a6b6170692e76322e6e6f6465", "0x01", "0x02"],
        ["0x00", "0x00", "0x00"],
        [p_minus_1, p_minus_1, p_minus_1],
        [
            "0x7a6b6170692e76322e6c656166",
            "0x1f1ce7a0de63179c049a52c56e2e7f90a49591693c784aaca4ddf1682d7ff74d",
            "0x2ea92e33da4fe4d87aeaa9b8bf14a69687ccfa2b47c2dad13af0fd3ba3c2956b",
        ],
    ];
    let mut out = Vec::new();
    for s in states {
        let input = [fr(s[0]), fr(s[1]), fr(s[2])];
        let r = permute(input);
        assert_eq!(r[1], compress_fields(input[0], input[1], input[2]), "lane 1 is compress_fields");
        out.push(json!({
            "state": input.iter().map(hexf).collect::<Vec<_>>(),
            "output": r.iter().map(hexf).collect::<Vec<_>>(),
        }));
    }
    json!({
        "source": "protocol/formal/scripts/arkworks-vectors (arkworks PoseidonSponge with zkapi-core v2's configuration: find_poseidon_ark_and_mds(254, 2, 8, 57, 0), alpha 5, rate 2, capacity 1); state = (capacity, rate0, rate1); output = the permuted state; lane 1 cross-checked against zkapi_core::v2::compress_fields",
        "permutation": out,
    })
}

fn check(path: &str) -> usize {
    let d: Value = serde_json::from_str(&std::fs::read_to_string(path).expect("read")).expect("json");
    let s = |v: &Value| v.as_str().expect("string").to_string();
    let mut bad = 0;
    let mut n = 0;
    for e in d["hash_fields"].as_array().unwrap() {
        let ins: Vec<Felt252> = e["inputs"].as_array().unwrap().iter().map(|x| felt(&s(x))).collect();
        n += 1;
        if hexfelt(&hash_felts(&ins)) != s(&e["output"]) { bad += 1; eprintln!("hash_fields {e}"); }
    }
    for e in d["hash_felts_reduced"].as_array().unwrap() {
        let ins: Vec<Felt252> = e["inputs"].as_array().unwrap().iter().map(|x| felt(&s(x))).collect();
        n += 1;
        if hexfelt(&hash_felts(&ins)) != s(&e["output"]) { bad += 1; eprintln!("hash_felts_reduced {e}"); }
    }
    for e in d["merkle_node"].as_array().unwrap() {
        n += 1;
        if hexfelt(&merkle_node(&felt(&s(&e["left"])), &felt(&s(&e["right"])))) != s(&e["node"]) {
            bad += 1; eprintln!("merkle_node {e}");
        }
    }
    for e in d["merkle_root"].as_array().unwrap() {
        let sib: Vec<Felt252> = e["siblings"].as_array().unwrap().iter().map(|x| felt(&s(x))).collect();
        let sib: [Felt252; 32] = sib.try_into().expect("32 siblings");
        let id = e["note_id"].as_u64().unwrap() as u32;
        n += 1;
        if hexfelt(&merkle_root(id, &felt(&s(&e["leaf"])), &sib)) != s(&e["root"]) {
            bad += 1; eprintln!("merkle_root {e}");
        }
    }
    for e in d["note_leaf"].as_array().unwrap() {
        let id = e["note_id"].as_u64().unwrap() as u32;
        let amount: u128 = s(&e["amount"]).parse().unwrap();
        let expiry: u64 = s(&e["expiry_ts"]).parse().unwrap();
        n += 1;
        if hexfelt(&note_leaf(id, &felt(&s(&e["commitment"])), amount, expiry)) != s(&e["leaf"]) {
            bad += 1; eprintln!("note_leaf {e}");
        }
    }
    for e in d["registration_commitment"].as_array().unwrap() {
        n += 1;
        if hexfelt(&registration_commitment(&felt(&s(&e["secret"])))) != s(&e["commitment"]) {
            bad += 1; eprintln!("registration_commitment {e}");
        }
    }
    let zs = zero_hashes();
    for (i, z) in d["zero_hashes"].as_array().unwrap().iter().enumerate() {
        n += 1;
        if hexfelt(&zs[i]) != s(z) { bad += 1; eprintln!("zero_hashes[{i}]"); }
    }
    println!("checked {n} vectors against zkapi-core, {bad} mismatches");
    bad
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("permutation") => println!("{}", serde_json::to_string_pretty(&permutation_vectors()).unwrap()),
        Some("check") => std::process::exit(if check(&args[2]) == 0 { 0 } else { 1 }),
        _ => {
            eprintln!("usage: arkworks-vectors permutation | check PATH");
            std::process::exit(2);
        }
    }
}
