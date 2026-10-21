//! Review regression: server-signed state for A must never authorize note B,
//! and the successors the server signs chain through the request circuit.
use crate::{
    config::ServerConfig, nullifier_store::NullifierStore, processor::RequestProcessor,
    signer::ServerSigner,
};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use zkapi_proof::compact::{random_scalar, WithdrawalVerifier};
use zkapi_proof::dev::{tree_with, DevDeployment, DevNote, DevRequest, DevState, DevWithdrawal};
use zkapi_types::{canonical_payload_hash, canonical_request_context, Felt252, WithdrawalKind};

use crate::test_support::{
    complete_response, deployment_of, request_prover, withdrawal_prover, PreparedTestRequest,
};

#[tokio::test]
async fn sequential_signed_state_cannot_branch_across_equal_or_unequal_notes() {
    let setup = crate::test_support::setup_directory();
    let withdrawal_verifier = WithdrawalVerifier::load(&setup).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expiry = now + 86400;
    let seeds = (Felt252::from_u64(7), Felt252::from_u64(8));
    for b_deposit in [50, 100] {
        let signer = Arc::new(ServerSigner::new(&seeds.0, &seeds.1));
        let a_note = DevNote {
            secret: Felt252::from_u64(42),
            note_id: 0,
            deposit_amount: 100,
            expiry,
        };
        let b_note = DevNote {
            secret: Felt252::from_u64(43),
            note_id: 1,
            deposit_amount: b_deposit,
            expiry,
        };
        let tree = tree_with(&[&a_note, &b_note]);
        let config = ServerConfig {
            request_charge_cap: 1,
            native_billing: Some(crate::test_support::native_config()),
            openrouter_leases: Some(crate::test_support::lease_config()),
            contract_address: Felt252::from_u64(0xdead),
            proof_setup_dir: setup.clone(),
            ..Default::default()
        };
        let deployment: DevDeployment = deployment_of(&config, seeds);
        let store = Arc::new(NullifierStore::in_memory().unwrap());
        let processor =
            RequestProcessor::try_new(config.clone(), store, signer.clone(), tree.root()).unwrap();
        processor.update_root(tree.root());
        let prepare = |id: &str, state: &DevState| {
            let payload = crate::test_support::lease_payload(&config, now);
            let payload_hash = canonical_payload_hash(payload.as_bytes());
            let params = DevRequest {
                request_time: now,
                solvency_bound: 1,
                request_context: canonical_request_context(id, &payload_hash),
                rerandomization: random_scalar(),
            };
            let (public, witness) = state.request(&deployment, &tree, &params).unwrap();
            (public, witness, params, payload, payload_hash)
        };
        let mut a = a_note.genesis(random_scalar());
        let mut after_first = None;
        for step in 0..2 {
            let id = format!("A-{b_deposit}-{step}");
            let (public, witness, params, payload, payload_hash) = prepare(&id, &a);
            let proof = request_prover().prove(&public, witness).unwrap();
            let request = zkapi_types::wire::ApiRequestV2 {
                client_request_id: id,
                payload,
                payload_hash,
                public_inputs: public,
                proof,
            };
            let response = processor.finalize_test_lease(&request, 1).unwrap();
            // The successor is at succ(N), and the next request spends it.
            a = complete_response(
                &deployment,
                &PreparedTestRequest {
                    request,
                    params,
                    state: a.clone(),
                },
                &response,
            )
            .unwrap();
            assert_eq!(a.balance, 99 - step as u128);
            if step == 0 {
                after_first = Some(a.clone());
            }
        }
        // Reuse the genuine 99-unit state after A has already continued to 98.
        let mut b = after_first.unwrap();
        b.note = b_note.clone();
        let (public, witness, ..) = prepare("B-transplant", &b);
        let error = request_prover()
            .prove(&public, witness)
            .unwrap_err()
            .to_string();
        assert!(error.contains("invalid witness"), "{error}");
        // Escape, mutual close and ownership withdrawals remain provable
        // after two requests.
        for kind in [
            WithdrawalKind::Escape,
            WithdrawalKind::MutualClose,
            WithdrawalKind::Ownership,
        ] {
            let destination = if kind == WithdrawalKind::Ownership {
                [0; 20]
            } else {
                [0x11; 20]
            };
            let (public, witness) = a
                .withdrawal(
                    &deployment,
                    &tree,
                    &DevWithdrawal {
                        kind,
                        destination,
                        conceded: 0,
                        valid_until: now + 3_600,
                    },
                )
                .unwrap();
            let proof = withdrawal_prover().prove(&public, witness).unwrap();
            assert!(withdrawal_verifier.verify(&public, &proof).unwrap());
        }
    }
}
