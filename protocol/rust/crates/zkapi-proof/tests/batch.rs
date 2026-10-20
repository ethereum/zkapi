//! The reference batch verifier (`zkapi_proof::batch`) against real proofs of the development
//! setup: the shared vectors the Forge tests check the generated adapter against
//! (`protocol/contracts/test/fixtures/batch-verifier-vectors.json`) are reproduced from their
//! bytes, a batch is valid exactly when every one of its items verifies alone (a differential
//! search over subsets, duplicates and single-word tampering), re-randomized proofs (ark-groth16)
//! verify in batches next to their originals, and every narrow field, every input at or above r
//! and every proof word at or above q is refused as the adapter refuses it.
//!
//! The fixtures belong to the development setup; with another `ZKAPI_SETUP_DIR` (the ceremony's
//! keys) these tests have nothing to check and say so.

mod common;

use ark_bn254::{Bn254, Fr};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use base64::Engine;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde_json::Value;
use zkapi_proof::batch::{BatchRejection, BatchVerifier};
use zkapi_proof::compact::{
    batch_domain, keccak256, proof_from_wire, proof_to_wire, request_record, RequestVerifier,
    WithdrawalVerifier,
};
use zkapi_types::wire::{Groth16ProofWire, ProofBackendWire};
use zkapi_types::Felt252;

const SCALAR_MODULUS: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";
const BASE_MODULUS: &str = "30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47";

fn fixtures_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../contracts/test/fixtures")
}

fn json(file: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures_dir().join(file)).unwrap()).unwrap()
}

fn bytes(value: &Value) -> Vec<u8> {
    hex::decode(value.as_str().unwrap().trim_start_matches("0x")).unwrap()
}

struct Setup {
    request: RequestVerifier,
    withdrawal: WithdrawalVerifier,
}

/// The setup's verifiers, or `None` when the fixtures were made for another setup.
fn setup() -> Option<Setup> {
    let dir = common::setup_dir();
    let request = RequestVerifier::load(&dir).unwrap();
    let withdrawal = WithdrawalVerifier::load(&dir).unwrap();
    let vectors = json("batch-verifier-vectors.json");
    let want = hex::encode(withdrawal.verifying_key_keccak256());
    if vectors["withdrawal_vk_hash"].as_str().unwrap() != format!("0x{want}") {
        eprintln!(
            "the batch fixtures belong to setup {}, not to {}: nothing to check",
            vectors["setup_id"],
            dir.display()
        );
        return None;
    }
    Some(Setup {
        request,
        withdrawal,
    })
}

/// One statement: its words and its proof.
#[derive(Clone)]
struct Item {
    words: Vec<u8>,
    proof: Vec<u8>,
    request: bool,
}

/// Every statement of batch-exits.json: (withdrawals, requests), foreign ones last.
fn items() -> (Vec<Item>, Vec<Item>) {
    let exits = json("batch-exits.json");
    let read = |value: &Value, request: bool| Item {
        words: bytes(&value["inputs_abi"]),
        proof: bytes(&value["proof_hex"]),
        request,
    };
    let mut withdrawals = Vec::new();
    let mut requests = Vec::new();
    for note in exits["notes"].as_array().unwrap() {
        withdrawals.push(read(&note["close"], false));
        withdrawals.push(read(&note["escape"], false));
        requests.push(read(&note["req_state"], true));
        requests.push(read(&note["req_succ"], true));
    }
    for value in exits["foreign"]["withdrawals"].as_array().unwrap() {
        withdrawals.push(read(value, false));
    }
    for value in exits["foreign"]["requests"].as_array().unwrap() {
        requests.push(read(value, true));
    }
    (withdrawals, requests)
}

fn concat(items: &[Item]) -> (Vec<u8>, Vec<u8>) {
    (
        items.iter().flat_map(|i| i.words.clone()).collect(),
        items.iter().flat_map(|i| i.proof.clone()).collect(),
    )
}

fn wire(proof: &[u8]) -> Groth16ProofWire {
    Groth16ProofWire {
        backend: ProofBackendWire::Groth16Bn254,
        proof: base64::engine::general_purpose::STANDARD.encode(proof),
    }
}

impl Setup {
    fn batch(&self, request: bool) -> BatchVerifier<'_> {
        if request {
            self.request.batch()
        } else {
            self.withdrawal.batch()
        }
    }

    /// The single verification of one item as the adapter's assertValid* runs it: its narrow
    /// fields clean, then the Groth16 check over the raw words (a word at or above r is false, a
    /// non-canonical or off-curve proof an error).
    fn single(&self, item: &Item) -> bool {
        let batch = self.batch(item.request);
        if matches!(
            batch.verify(&item.words, &item.proof),
            Err(BatchRejection::DirtyField { .. })
        ) {
            return false;
        }
        let words: Vec<Felt252> = item
            .words
            .chunks(32)
            .map(|w| Felt252(w.try_into().unwrap()))
            .collect();
        let proof = wire(&item.proof);
        let verified = if item.request {
            self.request.verify_field_elements(&words, &proof)
        } else {
            self.withdrawal.verify_field_elements(&words, &proof)
        };
        verified.unwrap_or(false)
    }
}

#[test]
fn constants_are_the_adapters() {
    assert_eq!(batch_domain(), keccak256(b"zkapi.groth16.batch.v1"));
    let record = request_record();
    assert!(
        record[..12].iter().any(|b| *b != 0),
        "REQUEST_RECORD >= 2^160"
    );
    let adapter =
        std::fs::read_to_string(common::setup_dir().join("Groth16ProofAdapter.sol")).unwrap();
    assert!(adapter.contains(&format!("BATCH_DOMAIN = 0x{}", hex::encode(batch_domain()))));
    assert!(adapter.contains(&format!("REQUEST_RECORD = 0x{}", hex::encode(record))));
    assert!(adapter.contains("function verifyWithdrawalBatchOnce("));
    assert!(adapter.contains("function verifyRequestBatchOnce("));
    assert!(adapter.contains("if (_requestVerifiedEarlier(inputs, proof)) return;"));
    assert!(adapter.contains("type(IZkApiBatchProofAdapter).interfaceId"));
    assert!(adapter.contains("type(IZkApiProofAdapter).interfaceId"));
}

/// Every vector of batch-verifier-vectors.json, recomputed from its bytes: the seed, the
/// challenges, the outcome and the pairing input. The Forge tests hold the adapter to the same.
#[test]
fn vectors_are_reproduced() {
    let Some(setup) = setup() else { return };
    let vectors = json("batch-verifier-vectors.json");
    let cases = vectors["cases"].as_array().unwrap();
    assert!(cases.len() > 20);
    let mut outcomes = std::collections::BTreeMap::<String, usize>::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let verifier = setup.batch(case["kind"] == "request");
        let inputs = bytes(&case["inputs"]);
        let proofs = bytes(&case["proofs"]);
        let seed = verifier.seed(&inputs, &proofs);
        match &case["seed"] {
            Value::Null => assert!(seed.is_none(), "{name}"),
            value => assert_eq!(seed.map(|s| s.to_vec()), Some(bytes(value)), "{name}"),
        }
        let challenges: Vec<Vec<u8>> = verifier
            .challenges(&inputs, &proofs)
            .iter()
            .map(|r| r.into_bigint().to_bytes_be())
            .collect();
        let want: Vec<Vec<u8>> = case["challenges"]
            .as_array()
            .unwrap()
            .iter()
            .map(bytes)
            .collect();
        assert_eq!(challenges, want, "{name}");
        let outcome = match verifier.verify(&inputs, &proofs) {
            Ok(()) => "ok",
            Err(BatchRejection::DirtyField { .. }) => "dirty_field",
            Err(BatchRejection::InvalidProof) => "invalid_proof",
        };
        assert_eq!(outcome, case["outcome"].as_str().unwrap(), "{name}");
        *outcomes.entry(outcome.to_string()).or_default() += 1;
        let pairing = verifier.pairing_input(&inputs, &proofs).ok();
        match &case["pairing_input"] {
            Value::Null => assert!(pairing.is_none(), "{name}"),
            value => assert_eq!(pairing, Some(bytes(value)), "{name}"),
        }
    }
    assert!(
        outcomes.len() == 3,
        "every outcome is covered: {outcomes:?}"
    );
}

/// Batches of every size up to all 36 statements of each kind verify, folded and generic items
/// mixed.
#[test]
fn valid_batches_verify() {
    let Some(setup) = setup() else { return };
    let (withdrawals, requests) = items();
    for items in [&withdrawals, &requests] {
        for item in items.iter() {
            assert!(setup.single(item));
        }
        for n in [1, 2, 3, 5, 8, 16, items.len()] {
            let (inputs, proofs) = concat(&items[items.len() - n..]);
            let verifier = setup.batch(items[0].request);
            assert_eq!(verifier.verify(&inputs, &proofs), Ok(()), "n = {n}");
        }
    }
}

/// A batch verifies exactly when every item verifies alone: random subsets of the fixture pool
/// with duplicates, one word tampered (an input, a proof word, a narrow field's high bit) or none.
#[test]
fn a_batch_is_the_and_of_its_singles() {
    let Some(setup) = setup() else { return };
    let (withdrawals, requests) = items();
    let mut rng = StdRng::seed_from_u64(0x0ba7c4);
    let (mut accepted, mut refused) = (0, 0);
    for round in 0..300 {
        let pool = if round % 3 == 0 {
            &requests
        } else {
            &withdrawals
        };
        let n = rng.gen_range(1..=6);
        let mut batch: Vec<Item> = (0..n)
            .map(|_| pool[rng.gen_range(0..pool.len())].clone())
            .collect();
        if rng.gen_bool(0.2) && n > 1 {
            batch[n - 1] = batch[0].clone();
        }
        match rng.gen_range(0..4) {
            0 => {}
            1 => {
                let victim = rng.gen_range(0..n);
                let word = rng.gen_range(0..batch[victim].words.len() / 32);
                let byte = 32 * word + rng.gen_range(0..32);
                batch[victim].words[byte] ^= 1 << rng.gen_range(0..8);
            }
            2 => {
                let victim = rng.gen_range(0..n);
                let byte = rng.gen_range(0..256);
                batch[victim].proof[byte] ^= 1 << rng.gen_range(0..8);
            }
            _ => {
                let victim = rng.gen_range(0..n);
                // a high byte of any word: a narrow field turns dirty, a field element changes
                let word = rng.gen_range(0..batch[victim].words.len() / 32);
                batch[victim].words[32 * word] ^= 0x01;
            }
        }
        let expected = batch.iter().all(|item| setup.single(item));
        let (inputs, proofs) = concat(&batch);
        let got = setup
            .batch(batch[0].request)
            .verify(&inputs, &proofs)
            .is_ok();
        assert_eq!(got, expected, "round {round}");
        if got {
            accepted += 1
        } else {
            refused += 1
        }
    }
    assert!(
        accepted > 50 && refused > 50,
        "{accepted} accepted, {refused} refused"
    );
}

/// Re-randomized proofs (ark-groth16) verify alone and in batches, next to their originals.
#[test]
fn rerandomized_proofs_verify_in_batches() {
    let Some(setup) = setup() else { return };
    let (withdrawals, requests) = items();
    let mut rng = StdRng::seed_from_u64(7);
    for items in [&withdrawals[..12], &requests[..12]] {
        let request = items[0].request;
        let key = if request {
            setup.request.verifying_key()
        } else {
            setup.withdrawal.verifying_key()
        };
        let mut batch = Vec::new();
        for item in items {
            let proof = proof_from_wire(&wire(&item.proof)).unwrap();
            let fresh = Groth16::<Bn254>::rerandomize_proof(key, &proof, &mut rng);
            let fresh = base64::engine::general_purpose::STANDARD
                .decode(proof_to_wire(&fresh).unwrap().proof)
                .unwrap();
            assert_ne!(fresh, item.proof);
            let twin = Item {
                proof: fresh,
                ..item.clone()
            };
            assert!(setup.single(&twin));
            batch.push(item.clone());
            batch.push(twin);
        }
        let (inputs, proofs) = concat(&batch);
        assert_eq!(setup.batch(request).verify(&inputs, &proofs), Ok(()));
    }
}

/// Every narrow field with a bit above its width is the empty revert of its item; every 256-bit
/// input plus r and every proof word plus q is InvalidProof(), at any position.
#[test]
fn encodings_are_refused_as_the_adapter_refuses_them() {
    let Some(setup) = setup() else { return };
    let (withdrawals, requests) = items();
    let r = hex::decode(SCALAR_MODULUS).unwrap();
    let q = hex::decode(BASE_MODULUS).unwrap();
    let add = |word: &mut [u8], modulus: &[u8]| {
        let mut carry = 0u16;
        for k in (0..32).rev() {
            let sum = u16::from(word[k]) + u16::from(modulus[k]) + carry;
            word[k] = sum as u8;
            carry = sum >> 8;
        }
        carry == 0
    };
    for (items, widths) in [
        (
            &withdrawals,
            [
                16u16, 64, 160, 256, 256, 256, 256, 256, 32, 128, 160, 256, 8, 256, 128, 64,
            ]
            .to_vec(),
        ),
        (
            &requests,
            [16u16, 64, 160, 256, 256, 256, 64, 128, 256, 256, 256, 256].to_vec(),
        ),
    ] {
        let verifier = setup.batch(items[0].request);
        for position in [0usize, 2] {
            for (index, bits) in widths.iter().enumerate() {
                let mut batch: Vec<Item> = items[..3].to_vec();
                let offset = 32 * index;
                if *bits < 256 {
                    let bit = usize::from(*bits);
                    batch[position].words[offset + 31 - bit / 8] |= 1 << (bit % 8);
                    let (inputs, proofs) = concat(&batch);
                    assert_eq!(
                        verifier.verify(&inputs, &proofs),
                        Err(BatchRejection::DirtyField { item: position }),
                        "input {index} at {position}"
                    );
                } else if add(&mut batch[position].words[offset..offset + 32], &r) {
                    let (inputs, proofs) = concat(&batch);
                    assert_eq!(
                        verifier.verify(&inputs, &proofs),
                        Err(BatchRejection::InvalidProof),
                        "input {index} + r at {position}"
                    );
                }
            }
            for word in 0..8 {
                let mut batch: Vec<Item> = items[..3].to_vec();
                if add(&mut batch[position].proof[32 * word..32 * word + 32], &q) {
                    let (inputs, proofs) = concat(&batch);
                    assert_eq!(
                        verifier.verify(&inputs, &proofs),
                        Err(BatchRejection::InvalidProof),
                        "proof word {word} + q at {position}"
                    );
                }
            }
        }
    }
    // the challenges are 128-bit, the first is 1
    let (inputs, proofs) = concat(&withdrawals[..4]);
    let challenges = setup.withdrawal.batch().challenges(&inputs, &proofs);
    assert_eq!(challenges[0], Fr::from(1u64));
    assert!(challenges[1..]
        .iter()
        .all(|r| r.into_bigint().num_bits() <= 128));
}
