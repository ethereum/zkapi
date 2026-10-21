//! Shared vectors for SDK parity (design §11 WP-E: "S1–S6, C1–C5 and E0–E7
//! parity with the SDK through shared vectors"), in one file,
//! `vectors/exit-rules.json`, which the browser SDK
//! (sdk/test/zkapi-exit-rules-vectors.test.mjs) and zkapi-clientd load too:
//!
//! - the exit decisions (C3's ownership proofs and concessions, C4, E0–E6,
//!   record classes, the E5 payout matcher), hand-written from the design;
//! - `successor_checks`: one note state and request journal, and signed
//!   responses that must install, be archived as `invalid_successor` (S3,
//!   S4, S5) or be rejected (S1, S2, S6).
//!   `ZKAPI_WRITE_VECTORS=1 cargo test -p zkapi-client --test shared_vectors`
//!   regenerates that section;
//! - `exit_kit` (E7), which zkapi-companion's exit-kit tests read.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use zkapi_client::config::{ClientConfig, ClientProofMode};
use zkapi_client::error::ClientError;
use zkapi_client::exit_policy::{self, ExitDecision, ExitFacts, NoteChainStatus, PayoutMatch};
use zkapi_client::journal::{read_archive, PendingRequestJournal};
use zkapi_client::note_state::NoteState;
use zkapi_client::wallet::Wallet;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{random_scalar, rerandomize, server_update, CompactSigner};
use zkapi_types::wire::{
    ApiRequestV2, CurvePointWire, Groth16ProofWire, ProofBackendWire, RequestResponseV2,
};
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, canonical_response_hash, Felt252,
    RequestPublicInputsV2,
};

fn vectors_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

/// The shared vector file.
const VECTORS: &str = "exit-rules.json";

fn load() -> Value {
    serde_json::from_slice(&std::fs::read(vectors_dir().join(VECTORS)).unwrap()).unwrap()
}

fn opt_u64(value: &Value) -> Option<u64> {
    value.as_u64()
}

#[test]
fn exit_policy_vectors() {
    let vectors = load();
    let constants = &vectors["constants"];
    for (name, value) in [
        ("call_timeout_seconds", exit_policy::CALL_TIMEOUT_SECONDS),
        (
            "recovery_budget_seconds",
            exit_policy::RECOVERY_BUDGET_SECONDS,
        ),
        (
            "initiate_margin_seconds",
            exit_policy::INITIATE_MARGIN_SECONDS,
        ),
        ("mutual_cutoff_seconds", exit_policy::MUTUAL_CUTOFF_SECONDS),
        (
            "settlement_grace_seconds",
            exit_policy::SETTLEMENT_GRACE_SECONDS,
        ),
        (
            "near_expiry_margin_seconds",
            exit_policy::NEAR_EXPIRY_MARGIN_SECONDS,
        ),
        (
            "unknown_reading_resolves_after_seconds",
            exit_policy::UNKNOWN_READING_RESOLVES_AFTER_SECONDS,
        ),
        (
            "default_unsettled_escape_after_seconds",
            exit_policy::DEFAULT_UNSETTLED_ESCAPE_AFTER_SECONDS,
        ),
        (
            "min_unsettled_escape_after_seconds",
            exit_policy::MIN_UNSETTLED_ESCAPE_AFTER_SECONDS,
        ),
        (
            "max_unsettled_escape_after_seconds",
            exit_policy::MAX_UNSETTLED_ESCAPE_AFTER_SECONDS,
        ),
        (
            "lock_release_margin_seconds",
            exit_policy::LOCK_RELEASE_MARGIN_SECONDS,
        ),
        (
            "exit_proof_validity_seconds",
            zkapi_client::wallet::EXIT_PROOF_VALIDITY_SECONDS,
        ),
        (
            "ownership_proof_validity_seconds",
            zkapi_client::wallet::OWNERSHIP_PROOF_VALIDITY_SECONDS,
        ),
        (
            "ownership_resend_margin_seconds",
            exit_policy::OWNERSHIP_RESEND_MARGIN_SECONDS,
        ),
    ] {
        assert_eq!(constants[name].as_u64(), Some(value), "{name}");
    }
    for case in vectors["e_low"].as_array().unwrap() {
        assert_eq!(
            exit_policy::e_low(
                case["expiry_ts"].as_u64().unwrap(),
                opt_u64(&case["pinned_rpc"]),
                opt_u64(&case["exit_rpc"]),
            ),
            case["expected"].as_u64().unwrap(),
            "{case}"
        );
    }
    for case in vectors["must_initiate_by"].as_array().unwrap() {
        assert_eq!(
            exit_policy::must_initiate_by(case["e_low"].as_u64().unwrap()),
            case["expected"].as_u64().unwrap()
        );
    }
    for case in vectors["near_expiry"].as_array().unwrap() {
        assert_eq!(
            exit_policy::note_near_expiry(
                case["now"].as_u64().unwrap(),
                case["settlement_window"].as_u64().unwrap(),
                case["must_initiate_by"].as_u64().unwrap(),
            ),
            case["expected"].as_bool().unwrap(),
            "{case}"
        );
    }
    for case in vectors["unsettled_escape_after"].as_array().unwrap() {
        assert_eq!(
            exit_policy::unsettled_escape_after(opt_u64(&case["configured"])),
            case["expected"].as_u64().unwrap()
        );
    }
    for case in vectors["classify"].as_array().unwrap() {
        let record: exit_policy::ReleasedRecord =
            serde_json::from_value(case["record"].clone()).unwrap();
        assert_eq!(
            serde_json::to_value(exit_policy::classify(&record)).unwrap(),
            case["expected"],
            "{case}"
        );
    }
    for case in vectors["decide"].as_array().unwrap() {
        let facts: ExitFacts = serde_json::from_value(case["facts"].clone()).unwrap();
        let decision: ExitDecision = exit_policy::decide(&facts);
        assert_eq!(
            serde_json::to_value(decision).unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
    for case in vectors["lock_releasable"].as_array().unwrap() {
        let released: Vec<exit_policy::ReleasedExit> =
            serde_json::from_value(case["released"].clone()).unwrap();
        let note: NoteChainStatus = serde_json::from_value(case["note"].clone()).unwrap();
        assert_eq!(
            exit_policy::lock_releasable(
                &released,
                case["user_cancels"].as_bool().unwrap(),
                note,
                opt_u64(&case["finalized_block_timestamp"]),
                case["now"].as_u64().unwrap(),
                case["status_trusted"].as_bool().unwrap(),
            ),
            case["expected"].as_bool().unwrap(),
            "{case}"
        );
    }
    for case in vectors["payout"].as_array().unwrap() {
        let raises: Vec<u128> = serde_json::from_value(case["raises"].clone()).unwrap();
        let matched: PayoutMatch = exit_policy::match_escape_payout(
            case["paid"].as_u64().unwrap().into(),
            case["state_balance"].as_u64().unwrap().into(),
            case["conceded_at_init"].as_u64().unwrap().into(),
            &raises,
            case["bound_at_state"].as_u64().map(u128::from),
        );
        assert_eq!(
            serde_json::to_value(matched).unwrap(),
            case["expected"],
            "{case}"
        );
    }
    for case in vectors["ownership_proof"].as_array().unwrap() {
        assert_eq!(
            serde_json::to_value(exit_policy::ownership_proof_action(
                opt_u64(&case["newest_valid_until"]),
                case["now"].as_u64().unwrap()
            ))
            .unwrap(),
            case["expected"],
            "{}",
            case["name"]
        );
    }
    for case in vectors["concession_allowed"].as_array().unwrap() {
        assert_eq!(
            exit_policy::concession_allowed(
                case["conceded"].as_u64().unwrap().into(),
                case["bound_at_state"].as_u64().unwrap().into()
            ),
            case["expected"].as_bool().unwrap()
        );
    }
}

#[derive(Serialize, Deserialize)]
struct SuccessorVectors {
    description: String,
    /// The state signing key's public key.
    state_signing_key: CurvePointWire,
    /// The note state, with `bound_at_state` set by its request.
    state: NoteState,
    /// The request journal of the state (ε is `user_rerandomization`).
    journal: PendingRequestJournal,
    cases: Vec<SuccessorCase>,
}

#[derive(Serialize, Deserialize)]
struct SuccessorCase {
    name: String,
    response: RequestResponseV2,
    /// `install`, `invalid_successor` or `reject`.
    expected: String,
    /// The request journal of this case, when it is not the shared one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    journal: Option<PendingRequestJournal>,
    /// For `install`: the installed state's balance, anchor, prev_anchor and
    /// blinding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    installed: Option<Value>,
}

fn successor_config(state_dir: &Path, key: &CurvePointWire) -> ClientConfig {
    ClientConfig {
        protocol_version: 2,
        chain_id: 11_155_111,
        contract_address: Felt252::from_hex(
            "0x00000000000000000000000049fa19f9bdece7a48ebc7749fd69ad40f577590f",
        )
        .unwrap(),
        request_charge_cap: 1_000,
        policy_charge_cap: 1_000,
        policy_enabled: false,
        server_url: "http://127.0.0.1:1".into(),
        state_dir: state_dir.to_string_lossy().into_owned(),
        proof_mode: ClientProofMode::Groth16 {
            setup_dir: "unused".into(),
        },
        state_signing_key: key.clone(),
        clearance_signing_key: key.clone(),
        settlement_window_seconds: 21_905,
    }
}

fn generate_successor_vectors() -> SuccessorVectors {
    let signer = CompactSigner::from_seed(&Felt252::from_u64(0x5151));
    let other = CompactSigner::from_seed(&Felt252::from_u64(0x5252));
    let key = signer.public_key();
    let dir = std::env::temp_dir().join(format!("zkapi-vectors-{}", uuid::Uuid::new_v4()));
    let mut wallet = Wallet::new(successor_config(&dir, &key)).unwrap();
    wallet
        .confirm_deposit(Felt252::from_u64(0xabc), 9, 3_000_000, 4_000_000_000)
        .unwrap();
    let mut state = wallet.state().unwrap().clone();
    state.bound_at_state = 1_000;
    let _ = std::fs::remove_dir_all(&dir);

    let nullifier = core::nullifier(&state.secret_s, state.note_id, &state.current_anchor);
    let rerandomization = random_scalar();
    let current = CurvePointWire {
        x: state.current_commitment_x,
        y: state.current_commitment_y,
    };
    let anonymous = rerandomize(&current, &rerandomization).unwrap();
    let payload = "{}".to_string();
    let payload_hash = canonical_payload_hash(payload.as_bytes());
    let client_request_id = "00000000-0000-4000-8000-000000000001".to_string();
    let context = canonical_request_context(&client_request_id, &payload_hash);
    let request = ApiRequestV2 {
        client_request_id: client_request_id.clone(),
        payload,
        payload_hash,
        public_inputs: RequestPublicInputsV2 {
            protocol_version: 2,
            chain_id: state.chain_id,
            contract_address: state.contract_address,
            active_root: Felt252::from_u64(7),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: 1_800_000_000,
            solvency_bound: 1_000,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        },
        // Installs never re-verify the request proof.
        proof: Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: "A".repeat(340) + "==",
        },
    };
    let journal = PendingRequestJournal {
        exists: true,
        client_request_id: client_request_id.clone(),
        nullifier,
        payload_hash,
        user_rerandomization: rerandomization,
        created_at_ms: 1_800_000_000_000,
        prepared_request: Some(request),
    };
    let respond = |charge: u128, anchor: Felt252, by: &CompactSigner| {
        let delta = random_scalar();
        let next = server_update(&anonymous, charge, &delta).unwrap();
        let message = core::state_message(
            2,
            state.chain_id,
            &state.contract_address,
            &next.x,
            &next.y,
            &anchor,
        );
        let body = "{\"ok\":true}".to_string();
        RequestResponseV2 {
            status: "ok".into(),
            client_request_id: client_request_id.clone(),
            request_nullifier: nullifier,
            response_code: 200,
            response_hash: canonical_response_hash(body.as_bytes()),
            response_payload: body,
            charge_applied: charge,
            next_commitment: next,
            next_anchor: anchor,
            blind_delta_srv: delta,
            next_state_signature: by.sign(&message),
            policy_reason_code: None,
            policy_evidence_hash: None,
        }
    };
    let derived = core::next_anchor(&nullifier);
    let mut cases = Vec::new();
    let mut case_with = |name: &str,
                         response: RequestResponseV2,
                         expected: &str,
                         journal: Option<PendingRequestJournal>| {
        cases.push(SuccessorCase {
            name: name.into(),
            response,
            expected: expected.into(),
            journal,
            installed: None,
        })
    };
    // S3's second clause: the journaled request must carry the state's one
    // bound. A journal whose request has another bound is from no request
    // this state made under C2, so its successor is not installed.
    let mut other_bound = journal.clone();
    if let Some(request) = other_bound.prepared_request.as_mut() {
        request.public_inputs.solvency_bound = 900;
    }
    case_with(
        "S3 the journaled request's bound is not bound_at_state: invalid_successor",
        respond(400, derived, &signer),
        "invalid_successor",
        Some(other_bound),
    );
    let mut case = |name: &str, response: RequestResponseV2, expected: &str| {
        case_with(name, response, expected, None)
    };
    case(
        "S1-S6 hold: install",
        respond(400, derived, &signer),
        "install",
    );
    case(
        "charge equal to the bound: install",
        respond(1_000, derived, &signer),
        "install",
    );
    let mut wrong_id = respond(400, derived, &signer);
    wrong_id.client_request_id = "00000000-0000-4000-8000-000000000002".into();
    case("S1 another request id: reject", wrong_id, "reject");
    let mut wrong_nullifier = respond(400, derived, &signer);
    wrong_nullifier.request_nullifier = Felt252::from_u64(5);
    case("S1 another nullifier: reject", wrong_nullifier, "reject");
    let mut wrong_hash = respond(400, derived, &signer);
    wrong_hash.response_payload = "{\"ok\":false}".into();
    case("S2 payload hash mismatch: reject", wrong_hash, "reject");
    case(
        "S3 charge above bound_at_state: invalid_successor",
        respond(1_001, derived, &signer),
        "invalid_successor",
    );
    case(
        "S4 anchor 0: invalid_successor",
        respond(400, Felt252::ZERO, &signer),
        "invalid_successor",
    );
    case(
        "S4 born-spent anchor 1: invalid_successor",
        respond(400, Felt252::ONE, &signer),
        "invalid_successor",
    );
    case(
        "S4 reused anchor: invalid_successor",
        respond(400, state.current_anchor, &signer),
        "invalid_successor",
    );
    case(
        "S4 random anchor: invalid_successor",
        respond(400, Felt252::from_u64(0xdead_beef), &signer),
        "invalid_successor",
    );
    case(
        "S4 another note's derived anchor: invalid_successor",
        respond(
            400,
            core::next_anchor(&core::nullifier(
                &state.secret_s,
                state.note_id + 1,
                &state.current_anchor,
            )),
            &signer,
        ),
        "invalid_successor",
    );
    let mut phantom = respond(400, derived, &signer);
    phantom.blind_delta_srv = random_scalar();
    case(
        "S5 phantom commitment: invalid_successor",
        phantom,
        "invalid_successor",
    );
    case(
        "S6 signed by another key: reject",
        respond(400, derived, &other),
        "reject",
    );
    case(
        "S6 checked before S4: an unsigned non-derived anchor is rejected",
        respond(400, Felt252::ONE, &other),
        "reject",
    );
    SuccessorVectors {
        description: "S1-S6 (design §6.1) for circuit zkapi-v2-concession-v1. Load `state` and `journal` (a case's own `journal` replaces it), deliver each `response` for the journal's request, and expect `install`, `invalid_successor` (a correctly signed successor failing S3, S4 or S5, archived and treated as withheld) or `reject` (S1, S2 or S6 fails; nothing changes). For `install`, `installed` is the resulting balance, anchor, prev_anchor, blinding and bound_at_state.".into(),
        state_signing_key: key,
        state,
        journal,
        cases,
    }
}

/// Deliver `case` to a fresh wallet holding the vectors' state and journal.
fn run_case(vectors: &SuccessorVectors, case: &SuccessorCase) -> (String, Option<Value>) {
    let dir = std::env::temp_dir().join(format!("zkapi-vectors-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    vectors.state.save(&dir.join("note_state.json")).unwrap();
    let journal = case.journal.as_ref().unwrap_or(&vectors.journal);
    PendingRequestJournal::write(&dir.join("pending_journal.json"), journal).unwrap();
    let mut wallet = Wallet::new(successor_config(&dir, &vectors.state_signing_key)).unwrap();
    let result = wallet.complete_pending_response(&case.response);
    let outcome = match &result {
        Ok(()) => {
            let state = wallet.state().unwrap();
            let installed = serde_json::json!({
                "current_balance": state.current_balance.to_string(),
                "current_anchor": state.current_anchor,
                "prev_anchor": state.prev_anchor,
                "balance_blinding": state.balance_blinding,
                "bound_at_state": state.bound_at_state.to_string(),
            });
            ("install".to_string(), Some(installed))
        }
        Err(ClientError::InvalidSuccessor(_)) => {
            assert!(!wallet.has_pending_request());
            let records = read_archive(&dir.join("request_archive"), &journal.nullifier).unwrap();
            assert_eq!(records.records.len(), 1);
            assert_eq!(records.records[0].disposition, "invalid_successor");
            assert_eq!(
                wallet.state().unwrap().current_anchor,
                vectors.state.current_anchor
            );
            ("invalid_successor".to_string(), None)
        }
        Err(_) => {
            assert!(wallet.has_pending_request());
            assert_eq!(
                wallet.state().unwrap().current_anchor,
                vectors.state.current_anchor
            );
            ("reject".to_string(), None)
        }
    };
    let _ = std::fs::remove_dir_all(dir);
    outcome
}

#[test]
fn successor_check_vectors() {
    let path = vectors_dir().join(VECTORS);
    if std::env::var_os("ZKAPI_WRITE_VECTORS").is_some() {
        let mut vectors = generate_successor_vectors();
        let installed: Vec<Option<Value>> = vectors
            .cases
            .iter()
            .map(|case| run_case(&vectors, case).1)
            .collect();
        for (case, installed) in vectors.cases.iter_mut().zip(installed) {
            case.installed = installed;
        }
        let mut file = load();
        file["successor_checks"] = serde_json::to_value(&vectors).unwrap();
        let mut bytes = serde_json::to_vec_pretty(&file).unwrap();
        bytes.push(b'\n');
        std::fs::write(&path, bytes).unwrap();
    }
    let vectors: SuccessorVectors =
        serde_json::from_value(load()["successor_checks"].clone()).unwrap();
    assert!(vectors.cases.len() >= 15);
    for case in &vectors.cases {
        let (outcome, installed) = run_case(&vectors, case);
        assert_eq!(outcome, case.expected, "{}", case.name);
        assert_eq!(installed, case.installed, "{}", case.name);
    }
}
