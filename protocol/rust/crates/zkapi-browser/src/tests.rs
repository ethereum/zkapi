use super::*;
use std::path::PathBuf;
use std::sync::OnceLock;
use zkapi_proof::compact::{
    key_header, strip_key_header, KeyKind, RequestVerifier, WithdrawalVerifier, REHEARSAL_SETUP_ID,
};
use zkapi_proof::dev::DevDeployment;

const NOTE_ID: u32 = 3;
const DEPOSIT: u128 = 2_000_000;
const EXPIRY: u64 = 1_900_000_000;
const VALID_UNTIL: u64 = 1_800_010_800;
const DESTINATION: &str = "0x1111111111111111111111111111111111111111";

fn setup_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2-concession-dev")
}

fn request_prover() -> &'static RequestProver {
    static PROVER: OnceLock<RequestProver> = OnceLock::new();
    PROVER.get_or_init(|| {
        load_request_prover(&std::fs::read(setup_dir().join("request.pk")).unwrap()).unwrap()
    })
}

fn withdrawal_prover() -> &'static WithdrawalProver {
    static PROVER: OnceLock<WithdrawalProver> = OnceLock::new();
    PROVER.get_or_init(|| {
        load_withdrawal_prover(&std::fs::read(setup_dir().join("withdrawal.pk")).unwrap()).unwrap()
    })
}

fn deployment() -> DevDeployment {
    DevDeployment::new(11_155_111, Felt252::from_u64(99))
}

fn config_with_cap(cap: u128) -> BrowserWalletConfig {
    let deployment = deployment();
    BrowserWalletConfig {
        protocol_version: 2,
        chain_id: deployment.chain_id,
        contract_address: deployment.contract_address,
        request_charge_cap: cap,
        policy_charge_cap: cap,
        policy_enabled: false,
        state_signing_key: deployment.state_key(),
        clearance_signing_key: deployment.clearance_key(),
    }
}

fn config() -> BrowserWalletConfig {
    config_with_cap(100)
}

fn genesis(secret: u64, note_id: u32) -> BrowserNoteState {
    confirm_deposit(
        &config(),
        ConfirmDepositArgs {
            secret: Felt252::from_u64(secret),
            note_id,
            amount: DEPOSIT,
            expiry_ts: EXPIRY,
        },
    )
    .unwrap()
}

/// A tree holding `state`'s note and two neighbours.
fn tree_for(state: &BrowserNoteState) -> MerkleTree {
    let mut tree = MerkleTree::new();
    tree.set_leaf(state.note_id - 1, Felt252::from_u64(7));
    tree.set_leaf(state.note_id, state_note_leaf(state));
    tree.set_leaf(state.note_id + 1, Felt252::from_u64(8));
    tree
}

fn request_args(tree: &MerkleTree, note_id: u32, id: &str) -> PrepareRequestArgs {
    PrepareRequestArgs {
        payload: "{\"mode\":\"openrouter_ephemeral_lease\",\"version\":1}".into(),
        active_root: tree.root(),
        merkle_siblings: tree.get_siblings(note_id).to_vec(),
        client_request_id: id.into(),
        request_time: 1_800_000_000,
        created_at_ms: 1_800_000_000_000,
    }
}

fn withdrawal_args(tree: &MerkleTree, note_id: u32, mode: &str) -> PrepareWithdrawalArgs {
    PrepareWithdrawalArgs {
        mode: mode.into(),
        destination: (mode != "ownership").then(|| DESTINATION.to_string()),
        conceded: (mode == "escape").then_some(0),
        valid_until: VALID_UNTIL,
        active_root: tree.root(),
        merkle_siblings: tree.get_siblings(note_id).to_vec(),
        clearance: None,
    }
}

/// A journal for a request at `state` with bound `bound`, as
/// `prepare_request` writes it (the proof itself is irrelevant to S1–S6).
fn journal_at(state: &BrowserNoteState, bound: u128, id: &str) -> PendingRequestJournal {
    let nullifier = withdrawal_nullifier(state);
    let payload_hash = canonical_payload_hash(b"payload");
    let config = config();
    PendingRequestJournal {
        exists: true,
        client_request_id: id.into(),
        nullifier,
        payload_hash,
        user_rerandomization: Felt252::from_u64(31),
        created_at_ms: 1,
        prepared_request: ApiRequestV2 {
            client_request_id: id.into(),
            payload: "payload".into(),
            payload_hash,
            public_inputs: RequestPublicInputsV2 {
                protocol_version: state.protocol_version,
                chain_id: state.chain_id,
                contract_address: state.contract_address,
                active_root: Felt252::from_u64(5),
                state_signing_key_x: config.state_signing_key.x,
                state_signing_key_y: config.state_signing_key.y,
                request_time: 1_800_000_000,
                solvency_bound: bound,
                request_nullifier: nullifier,
                authorization_tag: Felt252::from_u64(6),
                anonymous_commitment_x: Felt252::ZERO,
                anonymous_commitment_y: Felt252::ONE,
            },
            proof: Groth16ProofWire {
                backend: ProofBackendWire::Groth16Bn254,
                proof: String::new(),
            },
        },
    }
}

/// The response an operator signing with `signer` sends for `journal`: the
/// successor at `anchor` with `charge`, server blinding `delta`.
fn response_with(
    signer: &DevDeployment,
    state: &BrowserNoteState,
    journal: &PendingRequestJournal,
    charge: u128,
    delta: Felt252,
    anchor: Felt252,
) -> RequestResponseV2 {
    let current = CurvePointWire {
        x: state.current_commitment_x,
        y: state.current_commitment_y,
    };
    let anonymous = rerandomize(&current, &journal.user_rerandomization).unwrap();
    let next = server_update(&anonymous, charge, &delta).unwrap();
    RequestResponseV2 {
        status: "finalized".into(),
        client_request_id: journal.client_request_id.clone(),
        request_nullifier: journal.nullifier,
        response_code: 200,
        response_payload: "ok".into(),
        response_hash: canonical_response_hash(b"ok"),
        charge_applied: charge,
        next_anchor: anchor,
        blind_delta_srv: delta,
        next_state_signature: signer.sign_state(&next, &anchor),
        next_commitment: next,
        policy_reason_code: None,
        policy_evidence_hash: None,
    }
}

fn honest_response(
    state: &BrowserNoteState,
    journal: &PendingRequestJournal,
    charge: u128,
) -> RequestResponseV2 {
    response_with(
        &deployment(),
        state,
        journal,
        charge,
        Felt252::from_u64(77),
        core::next_anchor(&journal.nullifier),
    )
}

fn with_bound(state: &BrowserNoteState, bound: u128) -> BrowserNoteState {
    BrowserNoteState {
        bound_at_state: bound,
        ..state.clone()
    }
}

fn complete(
    state: &BrowserNoteState,
    journal: &PendingRequestJournal,
    response: RequestResponseV2,
) -> Result<BrowserNoteState> {
    complete_response(
        &config(),
        CompleteResponseArgs {
            state: state.clone(),
            journal: journal.clone(),
            response,
        },
    )
}

fn error_text<T>(result: Result<T>) -> String {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => format!("{error:#}"),
    }
}

fn assert_refused<T>(result: Result<T>, prefix: &str) {
    let message = error_text(result);
    assert!(
        message.starts_with(prefix),
        "expected {prefix:?}, got {message:?}"
    );
}

/// A signed state as `complete_response` installs it: `S_1` after a request
/// at genesis with bound `bound` and `charge`.
fn installed_successor(bound: u128, charge: u128) -> BrowserNoteState {
    let state = with_bound(&genesis(42, NOTE_ID), bound);
    let journal = journal_at(&state, bound, "first");
    complete(&state, &journal, honest_response(&state, &journal, charge)).unwrap()
}

#[test]
fn deposit_state_roundtrip_has_consistent_commitment() {
    let state = genesis(42, 7);
    let blinding = parse_scalar(&state.balance_blinding).unwrap();
    stored_commitment(&state, &blinding).unwrap();
    assert_eq!(state.current_anchor, core::GENESIS_ANCHOR);
    assert_eq!(state.prev_anchor, None);
    assert_eq!(state.bound_at_state, 0);
    let status = wallet_status(Some(&state), None).note.unwrap();
    assert_eq!((status.note_id, status.bound_at_state), (7, 0));
}

#[test]
fn states_saved_before_the_new_fields_deserialize_with_defaults() {
    let mut value = serde_json::to_value(genesis(42, 7)).unwrap();
    let object = value.as_object_mut().unwrap();
    object.remove("prev_anchor");
    object.remove("bound_at_state");
    let state: BrowserNoteState = serde_json::from_value(value).unwrap();
    assert_eq!((state.prev_anchor, state.bound_at_state), (None, 0));
}

#[test]
fn deployment_mismatch_and_inconsistent_states_are_rejected() {
    let state = genesis(42, 0);
    let mut wrong = config();
    wrong.chain_id = 1;
    assert_refused(validate_state(&wrong, &state), codes::STATE_INVALID);
    let mut flag = state.clone();
    flag.is_genesis = false;
    assert_refused(validate_state(&config(), &flag), codes::STATE_INVALID);
    assert_refused(
        validate_state(&config(), &with_bound(&state, DEPOSIT + 1)),
        codes::STATE_INVALID,
    );
    let mut genesis_with_prev = state.clone();
    genesis_with_prev.prev_anchor = Some(Felt252::from_u64(5));
    assert_refused(
        validate_state(&config(), &genesis_with_prev),
        codes::STATE_INVALID,
    );
    let mut unsigned = installed_successor(100, 10);
    unsigned.state_signature = None;
    assert_refused(validate_state(&config(), &unsigned), codes::STATE_INVALID);
}

#[test]
fn address_parser_is_strict() {
    assert_eq!(
        parse_address("0x1111111111111111111111111111111111111111").unwrap(),
        [0x11; 20]
    );
    assert_eq!(
        parse_address("000102030405060708090a0B0c0D0e0F10111213").unwrap(),
        std::array::from_fn(|index| index as u8)
    );
    assert!(parse_address("0x1234").is_err());
    assert!(parse_address("0x111111111111111111111111111111111111111").is_err());
    assert!(parse_address("0x11111111111111111111111111111111111111111").is_err());
    assert!(parse_address("0xgg11111111111111111111111111111111111111").is_err());
}

#[test]
fn an_honest_successor_installs_at_the_derived_anchor() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "honest");
    let next = complete(&state, &journal, honest_response(&state, &journal, 60)).unwrap();
    assert_eq!(next.prev_anchor, Some(core::GENESIS_ANCHOR));
    assert_eq!(next.current_anchor, core::next_anchor(&journal.nullifier));
    assert_eq!(next.current_balance, DEPOSIT - 60);
    assert_eq!(next.bound_at_state, 0, "an install resets the bound");
    assert!(!next.is_genesis);
    validate_state(&config(), &next).unwrap();
    // The successor's nullifier is the one an escape from the old state
    // publishes: only a request from this installed state can defeat it.
    assert_eq!(withdrawal_nullifier(&next), successor_nullifier(&state));
    // A worst-case charge equal to the bound installs too.
    complete(&state, &journal, honest_response(&state, &journal, 100)).unwrap();
}

#[test]
fn s4_refuses_every_anchor_but_the_derived_one() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "anchor");
    let other_note = genesis(42, NOTE_ID + 1);
    let other_secret = genesis(43, NOTE_ID);
    for (name, anchor) in [
        ("zero", Felt252::ZERO),
        ("genesis (born spent)", core::GENESIS_ANCHOR),
        ("reused", state.current_anchor),
        ("random", random_field()),
        (
            "foreign note",
            core::next_anchor(&withdrawal_nullifier(&other_note)),
        ),
        (
            "foreign secret",
            core::next_anchor(&withdrawal_nullifier(&other_secret)),
        ),
        (
            "old formula",
            core::next_anchor(&core::next_anchor(&journal.nullifier)),
        ),
    ] {
        let response = response_with(
            &deployment(),
            &state,
            &journal,
            10,
            Felt252::from_u64(77),
            anchor,
        );
        let message = error_text(complete(&state, &journal, response));
        assert!(
            message.starts_with("invalid_successor: S4"),
            "{name} anchor: {message}"
        );
    }
}

#[test]
fn s3_uses_the_bound_fixed_at_the_state() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "bound");
    // Above the bound.
    assert!(error_text(complete(
        &state,
        &journal,
        honest_response(&state, &journal, 101)
    ))
    .starts_with("invalid_successor: S3"));
    // A journal proven with another bound than the state records.
    let other = journal_at(&state, 90, "bound");
    assert!(error_text(complete(
        &state,
        &other,
        honest_response(&state, &other, 10)
    ))
    .starts_with("invalid_successor: S3"));
    // A state that recorded no bound has no request to settle.
    let unbound = with_bound(&state, 0);
    assert!(error_text(complete(
        &unbound,
        &journal,
        honest_response(&unbound, &journal, 0)
    ))
    .starts_with("invalid_successor: S3"));
}

#[test]
fn s5_refuses_a_phantom_commitment() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "phantom");
    let mut response = honest_response(&state, &journal, 10);
    // Signed, at the right anchor, but the commitment does not open with δ.
    response.blind_delta_srv = Felt252::from_u64(78);
    assert!(error_text(complete(&state, &journal, response)).starts_with("invalid_successor: S5"));
    // A commitment that opens to a smaller charge than the one claimed.
    let mut response = honest_response(&state, &journal, 10);
    response.charge_applied = 9;
    assert!(error_text(complete(&state, &journal, response)).starts_with("invalid_successor: S5"));
}

#[test]
fn s6_refuses_a_successor_the_pinned_key_did_not_sign() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "signature");
    let impostor = DevDeployment {
        state_signer: zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(9)),
        ..deployment()
    };
    // Even a successor that would fail S4 is first refused as unsigned, so it
    // is never archived as an operator's invalid successor.
    for anchor in [core::next_anchor(&journal.nullifier), Felt252::ONE] {
        let response = response_with(
            &impostor,
            &state,
            &journal,
            10,
            Felt252::from_u64(77),
            anchor,
        );
        assert_refused(
            complete(&state, &journal, response),
            codes::SUCCESSOR_SIGNATURE_INVALID,
        );
    }
}

#[test]
fn s1_and_s2_bind_the_response_to_this_state_and_request() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "identity");
    let mut response = honest_response(&state, &journal, 10);
    response.client_request_id = "other".into();
    assert_refused(
        complete(&state, &journal, response),
        codes::RESPONSE_IDENTITY_MISMATCH,
    );
    let mut response = honest_response(&state, &journal, 10);
    response.request_nullifier = Felt252::from_u64(5);
    assert_refused(
        complete(&state, &journal, response),
        codes::RESPONSE_IDENTITY_MISMATCH,
    );
    let mut response = honest_response(&state, &journal, 10);
    response.response_payload = "tampered".into();
    assert_refused(
        complete(&state, &journal, response),
        codes::RESPONSE_HASH_MISMATCH,
    );
    // A journal (and its signed response) made at another state of the note.
    let successor = with_bound(&installed_successor(100, 10), 100);
    let foreign = journal_at(&successor, 100, "identity");
    let response = honest_response(&successor, &foreign, 10);
    assert_refused(
        complete(&state, &foreign, response),
        codes::JOURNAL_STATE_MISMATCH,
    );
}

#[test]
fn requests_and_exits_follow_the_anchor_chain() {
    let genesis_state = genesis(42, NOTE_ID);
    let tree = tree_for(&genesis_state);
    let prover = request_prover();
    let request_vk = std::fs::read(setup_dir().join("request.vk")).unwrap();
    let request_verifier = RequestVerifier::load(setup_dir()).unwrap();
    let withdrawal_verifier = WithdrawalVerifier::load(setup_dir()).unwrap();

    // A genesis request fixes the state's bound (C2).
    let prepared = prepare_request_with_prover(
        &config_with_cap(100),
        &genesis_state,
        request_args(&tree, NOTE_ID, "genesis"),
        prover,
    )
    .unwrap();
    let request = &prepared.request;
    assert!(request_verifier
        .verify(&request.public_inputs, &request.proof)
        .unwrap());
    assert!(verify_request(&request.public_inputs, &request.proof.proof, &request_vk).unwrap());
    let mut mutated = request.public_inputs.clone();
    mutated.solvency_bound += 1;
    assert!(!verify_request(&mutated, &request.proof.proof, &request_vk).unwrap());
    assert_eq!(
        request.public_inputs.request_nullifier,
        core::nullifier(&genesis_state.secret_s, NOTE_ID, &core::GENESIS_ANCHOR)
    );
    assert_eq!(
        prepared.journal.nullifier,
        request.public_inputs.request_nullifier
    );
    let at_genesis = prepared.state;
    assert_eq!(at_genesis.bound_at_state, 100);
    assert_eq!(
        BrowserNoteState {
            bound_at_state: 0,
            ..at_genesis.clone()
        },
        genesis_state,
        "only the bound changes"
    );
    // Another bound at the same state is refused before proving; the same
    // bound (a retry) is allowed.
    assert_refused(
        prepare_request_with_prover(
            &config_with_cap(200),
            &at_genesis,
            request_args(&tree, NOTE_ID, "retry"),
            prover,
        ),
        codes::BOUND_FIXED_AT_STATE,
    );
    let retry = prepare_request_with_prover(
        &config_with_cap(100),
        &at_genesis,
        request_args(&tree, NOTE_ID, "retry"),
        prover,
    )
    .unwrap();
    assert_eq!(retry.state.bound_at_state, 100);

    // An escape from the state may concede up to its bound and publishes the
    // successor nullifier.
    let escape = prepare_withdrawal_with_prover(
        &config(),
        &at_genesis,
        PrepareWithdrawalArgs {
            conceded: Some(100),
            ..withdrawal_args(&tree, NOTE_ID, "escape")
        },
        withdrawal_prover(),
    )
    .unwrap();
    let inputs = &escape.public_inputs;
    assert!(withdrawal_verifier.verify(inputs, &escape.proof).unwrap());
    assert_eq!(
        (
            inputs.kind,
            inputs.conceded,
            inputs.final_balance,
            inputs.valid_until
        ),
        (0, 100, DEPOSIT - 100, VALID_UNTIL)
    );
    assert_eq!(inputs.withdrawal_nullifier, prepared.journal.nullifier);
    assert_eq!(inputs.next_nullifier, successor_nullifier(&at_genesis));
    assert_eq!(inputs.destination, [0x11; 20]);

    // The operator signs the successor at next_anchor(N_0); it installs, and
    // its request spends exactly the escape's next_nullifier (the defeat
    // evidence).
    let response = response_with(
        &deployment(),
        &at_genesis,
        &prepared.journal,
        60,
        Felt252::from_u64(1234),
        core::next_anchor(&prepared.journal.nullifier),
    );
    let signed = complete(&at_genesis, &prepared.journal, response).unwrap();
    let signed_request = prepare_request_with_prover(
        &config_with_cap(150),
        &signed,
        request_args(&tree, NOTE_ID, "signed"),
        prover,
    )
    .unwrap();
    assert!(request_verifier
        .verify(
            &signed_request.request.public_inputs,
            &signed_request.request.proof
        )
        .unwrap());
    assert_eq!(
        signed_request.request.public_inputs.request_nullifier,
        inputs.next_nullifier
    );

    // Without prev_anchor the signed state cannot prove a request (Q6a) but
    // can still exit.
    let without_prev = BrowserNoteState {
        prev_anchor: None,
        ..signed.clone()
    };
    assert_refused(
        prepare_request_with_prover(
            &config_with_cap(150),
            &without_prev,
            request_args(&tree, NOTE_ID, "lost"),
            prover,
        ),
        codes::PREV_ANCHOR_MISSING,
    );
    let exit = prepare_withdrawal_with_prover(
        &config(),
        &without_prev,
        withdrawal_args(&tree, NOTE_ID, "escape"),
        withdrawal_prover(),
    )
    .unwrap();
    assert!(withdrawal_verifier
        .verify(&exit.public_inputs, &exit.proof)
        .unwrap());
    assert_eq!(exit.public_inputs.final_balance, DEPOSIT - 60);
    assert_eq!(
        exit.public_inputs.next_nullifier,
        successor_nullifier(&signed)
    );

    // Ownership proof (kind 2): no destination, no concession, no successor.
    let ownership = prepare_withdrawal_with_prover(
        &config(),
        &signed,
        withdrawal_args(&tree, NOTE_ID, "ownership"),
        withdrawal_prover(),
    )
    .unwrap();
    let owned = &ownership.public_inputs;
    assert!(withdrawal_verifier.verify(owned, &ownership.proof).unwrap());
    assert_eq!(
        (
            owned.kind,
            owned.destination,
            owned.next_nullifier,
            owned.conceded
        ),
        (2, [0u8; 20], Felt252::ZERO, 0)
    );
    assert_eq!(owned.withdrawal_nullifier, withdrawal_nullifier(&signed));

    // Mutual close (kind 1) under the server clearance.
    let clearance = ClearanceResponseV2 {
        status: "cleared".into(),
        withdrawal_nullifier: withdrawal_nullifier(&signed),
        signature: deployment().sign_clearance(&withdrawal_nullifier(&signed)),
    };
    let close = prepare_withdrawal_with_prover(
        &config(),
        &signed,
        PrepareWithdrawalArgs {
            clearance: Some(clearance),
            ..withdrawal_args(&tree, NOTE_ID, "mutual")
        },
        withdrawal_prover(),
    )
    .unwrap();
    let closed = &close.public_inputs;
    assert!(withdrawal_verifier.verify(closed, &close.proof).unwrap());
    assert_eq!(
        (
            closed.kind,
            closed.next_nullifier,
            closed.conceded,
            closed.final_balance
        ),
        (1, Felt252::ZERO, 0, DEPOSIT - 60)
    );
}

#[test]
fn withdrawal_arguments_are_checked_before_proving() {
    let state = with_bound(&installed_successor(100, 10), 40);
    let tree = tree_for(&state);
    let prove = |args: PrepareWithdrawalArgs| {
        prepare_withdrawal_with_prover(&config(), &state, args, withdrawal_prover())
    };
    let escape = || withdrawal_args(&tree, NOTE_ID, "escape");
    assert_refused(
        prove(PrepareWithdrawalArgs {
            conceded: Some(41),
            ..escape()
        }),
        codes::CONCEDED_EXCEEDS_BOUND,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            conceded: None,
            ..escape()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            destination: Some(format!("0x{}", "0".repeat(40))),
            ..escape()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    let clearance = ClearanceResponseV2 {
        status: "cleared".into(),
        withdrawal_nullifier: withdrawal_nullifier(&state),
        signature: deployment().sign_clearance(&withdrawal_nullifier(&state)),
    };
    assert_refused(
        prove(PrepareWithdrawalArgs {
            clearance: Some(clearance.clone()),
            ..escape()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            valid_until: 0,
            ..escape()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            mode: "close".into(),
            ..escape()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            active_root: Felt252::from_u64(1),
            ..escape()
        }),
        codes::MERKLE_PATH_MISMATCH,
    );
    // A fresh state (bound 0) may only escape with c = 0.
    let fresh = BrowserNoteState {
        bound_at_state: 0,
        ..state.clone()
    };
    assert_refused(
        prepare_withdrawal_with_prover(
            &config(),
            &fresh,
            PrepareWithdrawalArgs {
                conceded: Some(1),
                ..escape()
            },
            withdrawal_prover(),
        ),
        codes::CONCEDED_EXCEEDS_BOUND,
    );

    let mutual = || PrepareWithdrawalArgs {
        clearance: Some(clearance.clone()),
        ..withdrawal_args(&tree, NOTE_ID, "mutual")
    };
    assert_refused(
        prove(PrepareWithdrawalArgs {
            conceded: Some(1),
            ..mutual()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            clearance: None,
            ..mutual()
        }),
        codes::CLEARANCE_INVALID,
    );
    let wrong_key = ClearanceResponseV2 {
        signature: deployment().sign_state(
            &CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ONE,
            },
            &Felt252::ONE,
        ),
        ..clearance.clone()
    };
    assert_refused(
        prove(PrepareWithdrawalArgs {
            clearance: Some(wrong_key),
            ..mutual()
        }),
        codes::CLEARANCE_INVALID,
    );
    let other_nullifier = ClearanceResponseV2 {
        withdrawal_nullifier: Felt252::from_u64(5),
        ..clearance.clone()
    };
    assert_refused(
        prove(PrepareWithdrawalArgs {
            clearance: Some(other_nullifier),
            ..mutual()
        }),
        codes::CLEARANCE_INVALID,
    );

    let ownership = || withdrawal_args(&tree, NOTE_ID, "ownership");
    assert_refused(
        prove(PrepareWithdrawalArgs {
            destination: Some(DESTINATION.into()),
            ..ownership()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            conceded: Some(1),
            ..ownership()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    assert_refused(
        prove(PrepareWithdrawalArgs {
            clearance: Some(clearance),
            ..ownership()
        }),
        codes::WITHDRAWAL_ARGS,
    );
    // Stale callers that still send the note-bound fields are refused.
    assert!(
        serde_json::from_value::<PrepareWithdrawalArgs>(serde_json::json!({
            "mode": "escape", "destination": DESTINATION, "conceded": 0, "valid_until": 1,
            "active_root": "0x1", "merkle_siblings": [], "has_clearance": false
        }))
        .is_err()
    );
}

#[test]
fn a_request_proof_needs_a_positive_bound_and_the_balance() {
    let state = genesis(42, NOTE_ID);
    let tree = tree_for(&state);
    let prover = request_prover();
    assert!(prepare_request_with_prover(
        &config_with_cap(0),
        &state,
        request_args(&tree, NOTE_ID, "zero"),
        prover
    )
    .is_err());
    assert_refused(
        prepare_request_with_prover(
            &config_with_cap(DEPOSIT + 1),
            &state,
            request_args(&tree, NOTE_ID, "rich"),
            prover,
        ),
        codes::INSUFFICIENT_BALANCE,
    );
    let mut wrong_root = request_args(&tree, NOTE_ID, "root");
    wrong_root.active_root = Felt252::from_u64(9);
    assert_refused(
        prepare_request_with_prover(&config(), &state, wrong_root, prover),
        codes::MERKLE_PATH_MISMATCH,
    );
}

fn relabel(bytes: &[u8], setup_id: &str, kind: KeyKind) -> Vec<u8> {
    let (_, payload) = strip_key_header(bytes, kind).unwrap();
    let mut relabelled = key_header(setup_id, kind).unwrap();
    relabelled.extend_from_slice(payload);
    relabelled
}

#[test]
fn the_bundle_loads_only_keys_of_its_own_setup() {
    assert_eq!(bundle_setup_id(), "dev", "tests run the dev-setup bundle");
    let request_vk = std::fs::read(setup_dir().join("request.vk")).unwrap();
    load_request_verifier(&request_vk).unwrap();
    // zkapi-proof's dev-setup build accepts rehearsal keys; the bundle does not.
    assert_refused(
        load_request_verifier(&relabel(&request_vk, REHEARSAL_SETUP_ID, KeyKind::Request)),
        codes::SETUP_MISMATCH,
    );
    assert_refused(
        load_request_verifier(&relabel(&request_vk, CEREMONY_SETUP_ID, KeyKind::Request)),
        codes::SETUP_MISMATCH,
    );
    let withdrawal_vk = std::fs::read(setup_dir().join("withdrawal.vk")).unwrap();
    assert!(load_request_verifier(&withdrawal_vk).is_err());
    assert!(verify_request(
        &journal_at(&genesis(42, 0), 1, "x")
            .prepared_request
            .public_inputs,
        "",
        &withdrawal_vk
    )
    .is_err());
}

#[test]
fn the_rebuilt_tree_matches_the_vault_tree_after_every_event() {
    let mut rebuilt = NoteTree::new();
    let mut reference = MerkleTree::new();
    let deposit = |note_id: u32| TreeEvent::NoteDeposited {
        note_id,
        commitment: core::registration_commitment(&Felt252::from_u64(100 + note_id as u64)),
        amount: 1_000 + note_id as u128,
        expiry_ts: EXPIRY,
    };
    for note_id in 0..6 {
        let event = deposit(note_id);
        let TreeEvent::NoteDeposited {
            commitment,
            amount,
            expiry_ts,
            ..
        } = event
        else {
            unreachable!()
        };
        reference.set_leaf(
            note_id,
            core::note_leaf(note_id, &commitment, amount, expiry_ts),
        );
        assert_eq!(rebuilt.apply(&event).unwrap(), reference.root());
    }
    reference.set_leaf(2, Felt252::ZERO);
    assert_eq!(
        rebuilt
            .apply(&TreeEvent::ClosedLeafRetired { note_id: 2 })
            .unwrap(),
        reference.root()
    );
    let path = rebuilt.path(4).unwrap();
    assert_eq!(path.active_root, reference.root());
    assert_eq!(path.siblings, reference.get_siblings(4).to_vec());
    assert_refused(rebuilt.path(2), codes::TREE_EVENT_INVALID);
    assert_refused(rebuilt.path(6), codes::TREE_EVENT_INVALID);
    // Out of order, a repeated retirement and a retirement of a note that
    // was never deposited are refused.
    assert_refused(rebuilt.apply(&deposit(7)), codes::TREE_EVENT_INVALID);
    assert_refused(
        rebuilt.apply(&TreeEvent::ClosedLeafRetired { note_id: 2 }),
        codes::TREE_EVENT_INVALID,
    );
    assert_refused(
        rebuilt.apply(&TreeEvent::ClosedLeafRetired { note_id: 6 }),
        codes::TREE_EVENT_INVALID,
    );

    // The dense-leaves form gives the same path.
    let leaves: Vec<Felt252> = (0..6).map(|index| reference.get_leaf(index)).collect();
    assert_eq!(tree_path_from_leaves(leaves.clone(), 4).unwrap(), path);
    assert_refused(
        tree_path_from_leaves(leaves.clone(), 2),
        codes::TREE_EVENT_INVALID,
    );
    assert_refused(tree_path_from_leaves(leaves, 6), codes::TREE_EVENT_INVALID);

    // Events travel as JSON with string amounts.
    let event: TreeEvent = serde_json::from_value(serde_json::json!({
        "event": "note_deposited", "note_id": 6, "commitment": "0x05",
        "amount": "340282366920938463463374607431768211455", "expiry_ts": 7
    }))
    .unwrap();
    assert_eq!(
        event,
        TreeEvent::NoteDeposited {
            note_id: 6,
            commitment: Felt252::from_u64(5),
            amount: u128::MAX,
            expiry_ts: 7
        }
    );
    assert!(serde_json::from_value::<TreeEvent>(serde_json::json!({
        "event": "note_deposited", "note_id": 6, "commitment": "0x05", "amount": 5, "expiry_ts": 7
    }))
    .is_err());
}

#[test]
fn a_lost_journal_response_is_checked_against_s1_s2_s4_and_s6() {
    let state = with_bound(&genesis(42, NOTE_ID), 100);
    let journal = journal_at(&state, 100, "lost");
    let honest = honest_response(&state, &journal, 60);
    // Without the journal (ε lost), the charge is usable only after S1, S2,
    // S4 and S6.
    assert_eq!(
        check_unrecoverable_response(&config(), &state, &honest).unwrap(),
        UnrecoverableResponse {
            charge_applied: 60,
            next_anchor: core::next_anchor(&journal.nullifier),
        }
    );
    // A charge above the bound passes these checks; the caller concedes
    // min(charge, bound).
    let above = honest_response(&state, &journal, 150);
    assert_eq!(
        check_unrecoverable_response(&config(), &state, &above)
            .unwrap()
            .charge_applied,
        150
    );
    // S1: another state's nullifier.
    let other = genesis(43, NOTE_ID);
    assert_refused(
        check_unrecoverable_response(&config(), &other, &honest),
        codes::RESPONSE_IDENTITY_MISMATCH,
    );
    // S2: a changed payload.
    let mut tampered = honest.clone();
    tampered.response_payload = "tampered".into();
    assert_refused(
        check_unrecoverable_response(&config(), &state, &tampered),
        codes::RESPONSE_HASH_MISMATCH,
    );
    // S6: an impostor's signature, even at the derived anchor.
    let impostor = DevDeployment {
        state_signer: zkapi_proof::compact::CompactSigner::from_seed(&Felt252::from_u64(9)),
        ..deployment()
    };
    let unsigned = response_with(
        &impostor,
        &state,
        &journal,
        60,
        Felt252::from_u64(77),
        core::next_anchor(&journal.nullifier),
    );
    assert_refused(
        check_unrecoverable_response(&config(), &state, &unsigned),
        codes::SUCCESSOR_SIGNATURE_INVALID,
    );
    // S4: a signed successor at any other anchor.
    let reused = response_with(
        &deployment(),
        &state,
        &journal,
        60,
        Felt252::from_u64(77),
        state.current_anchor,
    );
    assert!(
        error_text(check_unrecoverable_response(&config(), &state, &reused))
            .starts_with("invalid_successor: S4")
    );
}

#[test]
fn a_saved_path_is_kept_only_if_it_leads_to_its_root() {
    let state = genesis(42, NOTE_ID);
    let tree = tree_for(&state);
    let path = |root: Felt252| NotePathArgs {
        active_root: root,
        siblings: tree.get_siblings(NOTE_ID).to_vec(),
    };
    assert!(note_path_matches(&state, path(tree.root())).unwrap());
    // Another root, another note or another deposit amount does not match.
    assert!(!note_path_matches(&state, path(Felt252::from_u64(5))).unwrap());
    assert!(!note_path_matches(&genesis(42, NOTE_ID + 1), path(tree.root())).unwrap());
    // The deposit-time path stays valid while later deposits append leaves:
    // the vault keeps every root it held (Amendment A1).
    let mut later = tree.clone();
    later.set_leaf(NOTE_ID + 5, Felt252::from_u64(9));
    assert_ne!(later.root(), tree.root());
    assert!(note_path_matches(&state, path(tree.root())).unwrap());
    assert!(note_path_matches(
        &state,
        NotePathArgs {
            active_root: later.root(),
            siblings: later.get_siblings(NOTE_ID).to_vec(),
        }
    )
    .unwrap());
    // A path of the wrong depth is an error, not a mismatch.
    assert!(note_path_matches(
        &state,
        NotePathArgs {
            active_root: tree.root(),
            siblings: vec![Felt252::ZERO; 31],
        }
    )
    .is_err());
}
