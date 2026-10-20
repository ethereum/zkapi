//! Real-proof fixtures for the batch verifier and ZkApiExitBatcher, circuit
//! `zkapi-v2-concession-v1`:
//!
//! ```text
//! cargo run --release -p zkapi-proof --example batch_fixture -- ../setup/v2-concession-dev \
//!   ../contracts/test/fixtures/batch-exits.json ../contracts/test/fixtures/batch-verifier-vectors.json
//! ```
//!
//! `batch-exits.json`: the deployment of `vault_challenge_fixture` (chain 31337, the vault
//! CREATEd by `0xf00d` at nonce 0, the development keys, deposits of 1,000,000 gwei at
//! `timestamp` with a 30-day TTL) with 16 notes (ids 0-15, distinct secrets and destinations,
//! every proof at the root holding all 16). For note i, `s0` is its genesis and `s1` the state
//! after the request `req_state` from `s0` (solvency bound 100,000, charge 60,000):
//!
//! * `req_state`: the request at N0, the state evidence that raises `escape`;
//! * `req_succ`: a request from `s1` at N1 = `escape.next_nullifier`, the successor evidence that
//!   defeats `escape`;
//! * `escape`: a kind-0 escape from `s0` conceding 0; `close`: a kind-1 close from `s1` (clearance
//!   for N1); both to `destination` and valid until `valid_until`.
//!
//! `foreign`: four withdrawals and four requests of the same notes under another vault address
//! (0x…1234): statements no adapter folded for this vault takes, so they exercise the generic path.
//!
//! `batch-verifier-vectors.json`: batches built from those proofs (some re-randomized with
//! ark-groth16, some tampered), each with the reference verifier's (`zkapi_proof::batch`)
//! transcript seed, challenges, outcome and, when every check before the equation passes, the
//! exact pairing input the adapter hands to the precompile. The Rust tests recompute every vector
//! and the Forge tests check the adapter against them.
use anyhow::{ensure, Context, Result};
use ark_bn254::{Bn254, Fq, G1Affine};
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use base64::Engine;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde_json::{json, Value};
use zkapi_proof::batch::{off_subgroup_g2_words, BatchRejection};
use zkapi_proof::compact::{
    batch_domain, proof_from_wire, proof_to_wire, request_record, RequestProver, RequestVerifier,
    WithdrawalProver, WithdrawalVerifier, CIRCUIT_ID,
};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevWithdrawal};
use zkapi_types::wire::Groth16ProofWire;
use zkapi_types::{Felt252, WithdrawalKind};

const TIMESTAMP: u64 = 2_000_000_000;
const NOTE_TTL: u64 = 30 * 86_400;
const DEPOSIT: u128 = 1_000_000;
const VALID_UNTIL: u64 = TIMESTAMP + 7 * 86_400;
const NOTES: u32 = 16;
const FOREIGN: usize = 4;
// CREATE from address(0xf00d), nonce 0, as in vault_challenge_fixture.
const VAULT: &str = "0xFb1b848e938aE6474F890bfb28f6a793a515BAcb";
const FOREIGN_VAULT: u64 = 0x1234;
const SCALAR_MODULUS_HEX: &str = "30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001";

/// One statement: its ABI words and its 256-byte proof.
#[derive(Clone)]
struct Item {
    words: Vec<u8>,
    proof: Vec<u8>,
}

fn item(inputs: &[Felt252], proof: &Groth16ProofWire) -> Result<Item> {
    Ok(Item {
        words: inputs
            .iter()
            .flat_map(|field| field.as_bytes().iter().copied())
            .collect(),
        proof: base64::engine::general_purpose::STANDARD
            .decode(&proof.proof)
            .context("decode proof")?,
    })
}

fn hex0x(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn fixture(item: &Item) -> Value {
    json!({ "inputs_abi": hex0x(&item.words), "proof_hex": hex0x(&item.proof) })
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: batch_fixture SETUP_DIRECTORY BATCH_EXITS_JSON VECTORS_JSON";
    let setup = args.next().context(usage)?;
    let exits_path = args.next().context(usage)?;
    let vectors_path = args.next().context(usage)?;
    let requests = RequestProver::load(&setup)?;
    let request_verifier = RequestVerifier::load(&setup)?;
    let withdrawals = WithdrawalProver::load(&setup)?;
    let withdrawal_verifier = WithdrawalVerifier::load(&setup)?;

    let deployment = DevDeployment::new(
        31_337,
        Felt252::from_hex(VAULT).map_err(anyhow::Error::msg)?,
    );
    let foreign = DevDeployment::new(31_337, Felt252::from_u64(FOREIGN_VAULT));
    let expiry = (TIMESTAMP + NOTE_TTL).div_ceil(86_400) * 86_400;
    let notes: Vec<DevNote> = (0..NOTES)
        .map(|i| DevNote {
            secret: Felt252::from_u64(1_000 + u64::from(i)),
            note_id: i,
            deposit_amount: DEPOSIT,
            expiry,
        })
        .collect();
    let tree = tree_with(&notes.iter().collect::<Vec<_>>());

    let prove_request =
        |deployment: &DevDeployment, state: &zkapi_proof::dev::DevState, r: &DevRequest| {
            let (public, witness) = state.request(deployment, &tree, r)?;
            let proof = requests.prove(&public, witness)?;
            ensure!(request_verifier.verify(&public, &proof)?, "request");
            item(&public.to_field_elements(), &proof)
        };
    let prove_withdrawal = |deployment: &DevDeployment,
                            state: &zkapi_proof::dev::DevState,
                            kind: WithdrawalKind,
                            destination: [u8; 20]| {
        let (public, witness) = state.withdrawal(
            deployment,
            &tree,
            &DevWithdrawal {
                kind,
                destination,
                conceded: 0,
                valid_until: VALID_UNTIL,
            },
        )?;
        let proof = withdrawals.prove(&public, witness)?;
        ensure!(withdrawal_verifier.verify(&public, &proof)?, "withdrawal");
        item(&public.to_field_elements(), &proof)
    };

    let mut note_fixtures = Vec::new();
    // Per note: close, escape, req_state, req_succ.
    let mut proved: Vec<[Item; 4]> = Vec::new();
    let mut foreign_withdrawals = Vec::new();
    let mut foreign_requests = Vec::new();
    for (i, note) in notes.iter().enumerate() {
        let k = i as u64;
        let destination = [0x40u8 + i as u8; 20];
        let r0 = DevRequest {
            request_time: TIMESTAMP,
            solvency_bound: 100_000,
            request_context: Felt252::from_u64(200 + k),
            rerandomization: Felt252::from_u64(9 + 2 * k),
        };
        let r1 = DevRequest {
            request_time: TIMESTAMP,
            solvency_bound: 100_000,
            request_context: Felt252::from_u64(400 + k),
            rerandomization: Felt252::from_u64(11 + 2 * k),
        };
        let s0 = note.genesis(Felt252::from_u64(7 + k));
        let s1 = s0.successor(&deployment, &r0, 60_000, &Felt252::from_u64(17 + k))?;
        let req_state = prove_request(&deployment, &s0, &r0)?;
        let req_succ = prove_request(&deployment, &s1, &r1)?;
        let escape = prove_withdrawal(&deployment, &s0, WithdrawalKind::Escape, destination)?;
        let close = prove_withdrawal(&deployment, &s1, WithdrawalKind::MutualClose, destination)?;
        note_fixtures.push(json!({
            "registration": note.registration(),
            "destination": hex0x(&destination),
            "close": fixture(&close),
            "escape": fixture(&escape),
            "req_state": fixture(&req_state),
            "req_succ": fixture(&req_succ),
        }));
        proved.push([close, escape, req_state, req_succ]);
        if i < FOREIGN {
            let f0 = note.genesis(Felt252::from_u64(70 + k));
            foreign_requests.push(prove_request(&foreign, &f0, &r0)?);
            foreign_withdrawals.push(prove_withdrawal(
                &foreign,
                &f0,
                WithdrawalKind::Escape,
                destination,
            )?);
        }
        eprintln!("note {i} proved");
    }
    let exits = json!({
        "circuit_id": CIRCUIT_ID,
        "setup_id": requests.setup_id(),
        "chain_id": deployment.chain_id,
        "vault": VAULT,
        "deployer": "0x000000000000000000000000000000000000f00d",
        "timestamp": TIMESTAMP,
        "note_ttl": NOTE_TTL,
        "expiry": expiry,
        "deposit": DEPOSIT,
        "valid_until": VALID_UNTIL,
        "request_solvency_bound": 100_000,
        "n": NOTES,
        "root": tree.root(),
        "state_signing_key": deployment.state_key(),
        "clearance_signing_key": deployment.clearance_key(),
        "notes": note_fixtures,
        "foreign": {
            "vault": format!("{:#042x}", FOREIGN_VAULT),
            "withdrawals": foreign_withdrawals.iter().map(fixture).collect::<Vec<_>>(),
            "requests": foreign_requests.iter().map(fixture).collect::<Vec<_>>(),
        },
    });
    std::fs::write(
        &exits_path,
        format!("{}\n", serde_json::to_string_pretty(&exits)?),
    )
    .with_context(|| format!("write {exits_path}"))?;

    // ------------------------------------------------------------------ vectors
    let withdrawal_batch = withdrawal_verifier.batch();
    let request_batch = request_verifier.batch();
    let mut rng = StdRng::seed_from_u64(0x2026_1020);
    let rerandomize = |item: &Item, rng: &mut StdRng, kind_is_request: bool| -> Result<Item> {
        let wire = Groth16ProofWire {
            backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode(&item.proof),
        };
        let proof = proof_from_wire(&wire)?;
        let key = if kind_is_request {
            request_verifier.verifying_key()
        } else {
            withdrawal_verifier.verifying_key()
        };
        let fresh = Groth16::<Bn254>::rerandomize_proof(key, &proof, rng);
        let fresh = proof_to_wire(&fresh)?;
        Ok(Item {
            words: item.words.clone(),
            proof: base64::engine::general_purpose::STANDARD.decode(&fresh.proof)?,
        })
    };
    let close = |i: usize| proved[i][0].clone();
    let escape = |i: usize| proved[i][1].clone();
    let req_state = |i: usize| proved[i][2].clone();
    let req_succ = |i: usize| proved[i][3].clone();

    let mut cases = Vec::new();
    let mut case =
        |name: &str, request: bool, items: Vec<Item>, edit: &dyn Fn(&mut Vec<u8>, &mut Vec<u8>)| {
            let mut inputs: Vec<u8> = items.iter().flat_map(|i| i.words.clone()).collect();
            let mut proofs: Vec<u8> = items.iter().flat_map(|i| i.proof.clone()).collect();
            edit(&mut inputs, &mut proofs);
            let verifier = if request {
                &request_batch
            } else {
                &withdrawal_batch
            };
            let outcome = match verifier.verify(&inputs, &proofs) {
                Ok(()) => "ok",
                Err(BatchRejection::DirtyField { .. }) => "dirty_field",
                Err(BatchRejection::InvalidProof) => "invalid_proof",
            };
            let pairing = verifier.pairing_input(&inputs, &proofs).ok();
            cases.push(json!({
                "name": name,
                "kind": if request { "request" } else { "withdrawal" },
                "n": items.len(),
                "inputs": hex0x(&inputs),
                "proofs": hex0x(&proofs),
                "seed": verifier.seed(&inputs, &proofs).map(|seed| hex0x(&seed)),
                "challenges": verifier
                    .challenges(&inputs, &proofs)
                    .iter()
                    .map(|r| hex0x(&r.into_bigint().to_bytes_be()))
                    .collect::<Vec<_>>(),
                "outcome": outcome,
                "pairing_input": pairing.map(|bytes| hex0x(&bytes)),
            }));
        };
    let none = |_: &mut Vec<u8>, _: &mut Vec<u8>| {};
    // Word k of item i of a withdrawal (16 words) or request (12 words) batch.
    let at = |stride_words: usize, i: usize, k: usize| 32 * (stride_words * i + k);
    let set_word = |bytes: &mut [u8], offset: usize, word: [u8; 32]| {
        bytes[offset..offset + 32].copy_from_slice(&word)
    };
    let get_word = |bytes: &[u8], offset: usize| -> [u8; 32] {
        bytes[offset..offset + 32].try_into().expect("a word")
    };
    let add_word = |a: [u8; 32], b: [u8; 32]| -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut carry = 0u16;
        for k in (0..32).rev() {
            let sum = u16::from(a[k]) + u16::from(b[k]) + carry;
            out[k] = sum as u8;
            carry = sum >> 8;
        }
        out
    };
    let mut scalar_modulus = [0u8; 32];
    scalar_modulus.copy_from_slice(&hex::decode(SCALAR_MODULUS_HEX)?);
    let base_modulus: [u8; 32] = {
        let raw = Fq::MODULUS.to_bytes_be();
        let mut out = [0u8; 32];
        out[32 - raw.len()..].copy_from_slice(&raw);
        out
    };
    let one = {
        let mut w = [0u8; 32];
        w[31] = 1;
        w
    };

    case("withdrawal n=1 close", false, vec![close(0)], &none);
    case(
        "withdrawal n=4 closes and escapes",
        false,
        vec![close(0), escape(1), close(2), escape(3)],
        &none,
    );
    case(
        "withdrawal n=5 folded and generic items",
        false,
        vec![
            close(4),
            foreign_withdrawals[0].clone(),
            escape(5),
            foreign_withdrawals[1].clone(),
            close(6),
        ],
        &none,
    );
    let twice = rerandomize(&close(7), &mut rng, false)?;
    case(
        "withdrawal n=3 one statement with two re-randomized proofs",
        false,
        vec![close(7), twice, escape(8)],
        &none,
    );
    case(
        "withdrawal n=16 every close",
        false,
        (0..16).map(close).collect(),
        &none,
    );
    case("request n=1", true, vec![req_state(0)], &none);
    case(
        "request n=4 with a generic item",
        true,
        vec![
            req_state(1),
            req_succ(2),
            foreign_requests[0].clone(),
            req_succ(3),
        ],
        &none,
    );
    case(
        "request n=3 re-randomized",
        true,
        vec![
            rerandomize(&req_succ(4), &mut rng, true)?,
            rerandomize(&req_state(5), &mut rng, true)?,
            req_succ(6),
        ],
        &none,
    );
    // Tampered statements and proofs.
    case(
        "withdrawal nullifier of item 2 off by one",
        false,
        vec![close(0), close(1), close(2), close(3)],
        &|inputs, _| {
            let o = at(16, 2, 11);
            let w = add_word(get_word(inputs, o), one);
            set_word(inputs, o, w);
        },
    );
    case(
        "withdrawal nullifier of item 1 plus r (aliasing)",
        false,
        vec![close(0), close(1), close(2)],
        &|inputs, _| {
            let o = at(16, 1, 11);
            let w = add_word(get_word(inputs, o), scalar_modulus);
            set_word(inputs, o, w);
        },
    );
    case(
        "withdrawal noteId of item 1 with bit 32 set (dirty)",
        false,
        vec![close(0), close(1), close(2)],
        &|inputs, _| inputs[at(16, 1, 8) + 27] |= 1,
    );
    case(
        "dirty item 2 after an input at or above r in item 1",
        false,
        vec![close(0), close(1), close(2)],
        &|inputs, _| {
            let o = at(16, 1, 13);
            let w = add_word(get_word(inputs, o), scalar_modulus);
            set_word(inputs, o, w);
            inputs[at(16, 2, 12) + 30] |= 1;
        },
    );
    case(
        "proof word of item 0 plus q",
        false,
        vec![close(0), close(1)],
        &|_, proofs| {
            let w = add_word(get_word(proofs, 32 * 7), base_modulus);
            set_word(proofs, 32 * 7, w);
        },
    );
    case(
        "B of item 1 on the twist outside the subgroup",
        false,
        vec![close(0), close(1), close(2)],
        &|_, proofs| {
            for (k, word) in off_subgroup_g2_words(5).iter().enumerate() {
                set_word(proofs, 256 + 32 * (2 + k), *word);
            }
        },
    );
    case(
        "B of the only item outside the subgroup",
        false,
        vec![close(0)],
        &|_, proofs| {
            for (k, word) in off_subgroup_g2_words(5).iter().enumerate() {
                set_word(proofs, 32 * (2 + k), *word);
            }
        },
    );
    case(
        "A of item 0 off the curve, item 1 dirty: A_0 is checked only by the pairing",
        false,
        vec![close(0), close(1)],
        &|inputs, proofs| {
            proofs[31] ^= 1;
            inputs[at(16, 1, 12) + 30] |= 1;
        },
    );
    case(
        "C of item 0 off the curve, item 2 dirty: C_0 is checked at item 1",
        false,
        vec![close(0), close(1), close(2)],
        &|inputs, proofs| {
            proofs[32 * 6 + 31] ^= 1;
            inputs[at(16, 2, 12) + 30] |= 1;
        },
    );
    case(
        "cancelling pair: C_1 + G and C_2 - G",
        false,
        vec![close(0), close(1), close(2), close(3)],
        &|_, proofs| {
            let g = G1Affine::generator();
            for (item, sign) in [(1usize, false), (2usize, true)] {
                let base = 256 * item + 32 * 6;
                let c = G1Affine::new_unchecked(
                    Fq::from_be_bytes_mod_order(&proofs[base..base + 32]),
                    Fq::from_be_bytes_mod_order(&proofs[base + 32..base + 64]),
                );
                let moved = if sign {
                    c.into_group() - g
                } else {
                    c.into_group() + g
                };
                let (x, y) = moved.into_affine().xy().expect("not the identity");
                let encode = |v: Fq| {
                    let raw = v.into_bigint().to_bytes_be();
                    let mut out = [0u8; 32];
                    out[32 - raw.len()..].copy_from_slice(&raw);
                    out
                };
                set_word(proofs, base, encode(x));
                set_word(proofs, base + 32, encode(y));
            }
        },
    );
    case(
        "A of item 1 the identity",
        false,
        vec![close(0), close(1), close(2)],
        &|_, proofs| proofs[256..320].fill(0),
    );
    case(
        "proofs of items 0 and 1 swapped",
        false,
        vec![close(0), close(1)],
        &|_, proofs| {
            let (first, second) = proofs.split_at_mut(256);
            first.swap_with_slice(&mut second[..256]);
        },
    );
    case(
        "request nullifier of item 0 off by one",
        true,
        vec![req_state(0), req_state(1)],
        &|inputs, _| {
            let o = at(12, 0, 8);
            let w = add_word(get_word(inputs, o), one);
            set_word(inputs, o, w);
        },
    );
    case(
        "request solvency bound of item 1 dirty",
        true,
        vec![req_state(0), req_state(1)],
        &|inputs, _| inputs[at(12, 1, 7) + 15] |= 1,
    );
    case(
        "withdrawal proofs one byte short",
        false,
        vec![close(0), close(1)],
        &|_, proofs| {
            proofs.pop();
        },
    );
    case("withdrawal empty batch", false, vec![], &none);

    let vectors = json!({
        "circuit_id": CIRCUIT_ID,
        "setup_id": requests.setup_id(),
        "batch_domain": hex0x(&batch_domain()),
        "request_record": hex0x(&request_record()),
        "withdrawal_vk_hash": hex0x(&withdrawal_verifier.verifying_key_keccak256()),
        "request_vk_hash": hex0x(&request_verifier.verifying_key_keccak256()),
        "cases": cases,
    });
    std::fs::write(
        &vectors_path,
        format!("{}\n", serde_json::to_string_pretty(&vectors)?),
    )
    .with_context(|| format!("write {vectors_path}"))?;
    Ok(())
}
