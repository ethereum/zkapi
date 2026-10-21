//! Signing the successor of a settled request (O1, §5.1).
//!
//! The successor of the state whose request spent nullifier `N` is signed at
//! exactly one anchor, the derived `τ' = succ(N) = H(d_anchor', N)`
//! (`zkapi_core::v2::next_anchor`). Anyone can compute it from `N`; the
//! request circuit refuses to spend a signed state at any other anchor (Q6a)
//! and clients refuse to install one (S4). Before signing,
//! [`sign_successor_state`] refuses an anchor of 0 or 1 and one that differs
//! from an independent recomputation (the circuit's native mirror,
//! `zkapi_proof::groth16::next_anchor`), so a bug in either derivation never
//! reaches the signer.
//!
//! [`self_test`] runs this code path at startup with an ephemeral key drawn
//! from the OS RNG and dropped afterwards; the production signer is never
//! invoked.

use base64::Engine;
use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    balance_commitment, random_field, random_scalar, server_update, verify_signature, CompactSigner,
};
use zkapi_types::wire::{
    ApiRequestV2, CurvePointWire, Groth16ProofWire, ProofBackendWire, RequestResponseV2,
};
use zkapi_types::{canonical_response_hash, Felt252, RequestPublicInputsV2, SchnorrSignature};

use crate::error::ServerError;
use crate::nullifier_store::{
    api_request_binding, NullifierStatus, SettledCharge, TranscriptRecord,
};

/// Signs state messages: the production [`crate::signer::ServerSigner`], or
/// the self-test's ephemeral key.
pub trait StateSigner {
    fn sign_state(&self, message: &Felt252) -> SchnorrSignature;
}

impl StateSigner for CompactSigner {
    fn sign_state(&self, message: &Felt252) -> SchnorrSignature {
        self.sign(message)
    }
}

/// The deployment a successor is signed for: `(protocol_version, chain_id,
/// contract_address)` of the state message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Deployment {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
}

/// The only anchor at which the successor of the request at `nullifier` is
/// signed.
pub fn derived_anchor(nullifier: &Felt252) -> Felt252 {
    core::next_anchor(nullifier)
}

/// `succ(N)` recomputed through the circuit's native mirror, independently of
/// `zkapi_core::v2::next_anchor`.
fn independent_anchor(nullifier: &Felt252) -> Felt252 {
    core::field_to_felt(&zkapi_proof::groth16::next_anchor(core::felt_to_field(
        nullifier,
    )))
}

/// Sign `M_state(next_commitment, next_anchor)` for the successor of the
/// request at `request_nullifier`, only if `next_anchor` is the derived
/// anchor: never 0 or 1 (genesis), and equal to an independent
/// recomputation. Otherwise nothing is signed and the error is `Internal`.
pub fn sign_successor_state<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request_nullifier: &Felt252,
    next_commitment: &CurvePointWire,
    next_anchor: &Felt252,
) -> Result<SchnorrSignature, ServerError> {
    if *next_anchor == Felt252::ZERO || *next_anchor == core::GENESIS_ANCHOR {
        return Err(ServerError::Internal(
            "refusing to sign a successor at anchor 0 or 1".into(),
        ));
    }
    if *next_anchor != independent_anchor(request_nullifier) {
        return Err(ServerError::Internal(
            "refusing to sign a successor at an anchor that is not succ(N)".into(),
        ));
    }
    Ok(signer.sign_state(&core::state_message(
        deployment.protocol_version,
        deployment.chain_id,
        &deployment.contract_address,
        &next_commitment.x,
        &next_commitment.y,
        next_anchor,
    )))
}

/// The deterministic checks a settled request must pass before its charge is
/// persisted: its anonymous commitment is a curve point the successor update
/// accepts, and its proof is the 256-byte Groth16 proof that becomes the
/// transcript's evidence. A request failing them can never be signed.
pub fn check_signable(request: &ApiRequestV2) -> Result<(), ServerError> {
    let public = &request.public_inputs;
    server_update(
        &CurvePointWire {
            x: public.anonymous_commitment_x,
            y: public.anonymous_commitment_y,
        },
        0,
        &Felt252::ZERO,
    )
    .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
    crate::nullifier_store::request_proof_bytes(request)?;
    Ok(())
}

/// The signed successor of a settled request and the transcript that records
/// it. Nothing is persisted here.
pub struct SignedSuccessor {
    pub response: RequestResponseV2,
    pub transcript: TranscriptRecord,
}

/// Build the successor of `request` at its settled charge: `C' = C_anon −
/// charge·G + δ·H` with a fresh `δ`, at the derived anchor, signed by
/// `signer` through [`sign_successor_state`].
pub fn build_signed_successor<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    settled: &SettledCharge,
    now: u64,
) -> Result<SignedSuccessor, ServerError> {
    let public = &request.public_inputs;
    if public.protocol_version != deployment.protocol_version
        || public.chain_id != deployment.chain_id
        || public.contract_address != deployment.contract_address
    {
        return Err(ServerError::Internal(
            "refusing to sign a successor for a different deployment".into(),
        ));
    }
    // The request proved balance >= solvency_bound; never sign more.
    if settled.charge > public.solvency_bound {
        return Err(ServerError::Internal(
            "refusing to sign a charge above the request's solvency bound".into(),
        ));
    }
    let next_anchor = derived_anchor(&public.request_nullifier);
    assemble_successor(
        signer,
        deployment,
        request,
        settled,
        (settled.charge, next_anchor),
        now,
        true,
    )
}

/// A successor at any `charge` and `next_anchor`, signed without the anchor
/// assertion: the `adversary` feature's born-spent, reused-anchor,
/// random-anchor and overcharging servers (§5.5). Never built without it.
#[cfg(feature = "adversary")]
pub(crate) fn build_adversarial_successor<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    settled: &SettledCharge,
    successor: (u128, Felt252),
    now: u64,
) -> Result<SignedSuccessor, ServerError> {
    assemble_successor(signer, deployment, request, settled, successor, now, false)
}

/// `C' = C_anon − charge·G + δ·H` with a fresh `δ`, signed at `next_anchor`
/// (through `sign_successor_state` when `checked`), and its transcript.
fn assemble_successor<S: StateSigner + ?Sized>(
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    settled: &SettledCharge,
    (charge, next_anchor): (u128, Felt252),
    now: u64,
    checked: bool,
) -> Result<SignedSuccessor, ServerError> {
    let public = &request.public_inputs;
    let anonymous = CurvePointWire {
        x: public.anonymous_commitment_x,
        y: public.anonymous_commitment_y,
    };
    let blind_delta = random_scalar();
    let next_commitment = server_update(&anonymous, charge, &blind_delta)
        .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
    let state_signature = if checked {
        sign_successor_state(
            signer,
            deployment,
            &public.request_nullifier,
            &next_commitment,
            &next_anchor,
        )?
    } else {
        signer.sign_state(&core::state_message(
            deployment.protocol_version,
            deployment.chain_id,
            &deployment.contract_address,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        ))
    };
    let response_hash = canonical_response_hash(settled.response_payload.as_bytes());
    let proof_bytes = base64::engine::general_purpose::STANDARD
        .decode(&request.proof.proof)
        .map_err(|error| ServerError::InvalidProof(error.to_string()))?;
    let transcript = TranscriptRecord {
        nullifier: public.request_nullifier,
        status: NullifierStatus::Finalized,
        reservation_kind: "openrouter_lease".into(),
        client_request_id: Some(request.client_request_id.clone()),
        payload_hash: Some(request.payload_hash),
        charge_applied: Some(charge),
        response_code: Some(settled.response_code),
        response_payload: Some(settled.response_payload.clone()),
        response_hash: Some(response_hash),
        next_commitment_x: Some(next_commitment.x),
        next_commitment_y: Some(next_commitment.y),
        next_anchor: Some(next_anchor),
        blind_delta_srv: Some(blind_delta),
        next_state_sig: Some(state_signature),
        policy_reason_code: None,
        policy_evidence_hash: None,
        proof_blob: Some(proof_bytes),
        request_inputs_json: serde_json::to_string(public).ok(),
        api_request_binding: Some(api_request_binding(request)?),
        created_at: now,
        finalized_at: Some(now),
        settled_charge: Some(settled.charge),
        settled_basis: Some(settled.basis.clone()),
        settled_at: Some(settled.settled_at),
        exit_deferred_since: None,
    };
    let response = RequestResponseV2 {
        status: "ok".to_string(),
        client_request_id: request.client_request_id.clone(),
        request_nullifier: public.request_nullifier,
        response_code: settled.response_code,
        response_payload: settled.response_payload.clone(),
        response_hash,
        charge_applied: charge,
        next_commitment,
        next_anchor,
        blind_delta_srv: blind_delta,
        next_state_signature: state_signature,
        policy_reason_code: None,
        policy_evidence_hash: None,
    };
    Ok(SignedSuccessor {
        response,
        transcript,
    })
}

/// Startup self-test of the successor signing path, including the anchor
/// assertion, with an ephemeral key from the OS RNG that is dropped
/// afterwards. The production signer is never invoked.
pub fn self_test(deployment: &Deployment) -> anyhow::Result<()> {
    let ephemeral = loop {
        if let Ok(signer) = CompactSigner::try_from_seed(&random_scalar()) {
            break signer;
        }
    };
    let nullifier = random_field();
    let anonymous = balance_commitment(1_000_000, &random_scalar(), &random_field());
    let request = ApiRequestV2 {
        client_request_id: "startup-self-test".into(),
        payload: "{}".into(),
        payload_hash: Felt252::ZERO,
        public_inputs: RequestPublicInputsV2 {
            protocol_version: deployment.protocol_version,
            chain_id: deployment.chain_id,
            contract_address: deployment.contract_address,
            active_root: Felt252::ZERO,
            state_signing_key_x: Felt252::ZERO,
            state_signing_key_y: Felt252::ZERO,
            request_time: 0,
            solvency_bound: 1_000,
            request_nullifier: nullifier,
            authorization_tag: Felt252::ZERO,
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        },
        proof: Groth16ProofWire {
            backend: ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD.encode([0u8; 256]),
        },
    };
    let settled = SettledCharge {
        charge: 7,
        basis: "measured".into(),
        response_code: 200,
        response_payload: "{}".into(),
        settled_at: 0,
    };
    check_signable(&request)?;
    let signed = build_signed_successor(&ephemeral, deployment, &request, &settled, 0)?;
    let response = &signed.response;
    let anchor = response.next_anchor;
    anyhow::ensure!(
        anchor == core::next_anchor(&nullifier)
            && anchor == independent_anchor(&nullifier)
            && anchor != Felt252::ZERO
            && anchor != core::GENESIS_ANCHOR,
        "successor self-test: the successor is not at the derived anchor succ(N)"
    );
    anyhow::ensure!(
        response.next_commitment == server_update(&anonymous, 7, &response.blind_delta_srv)?,
        "successor self-test: the successor commitment is not C_anon - charge*G + delta*H"
    );
    let message = core::state_message(
        deployment.protocol_version,
        deployment.chain_id,
        &deployment.contract_address,
        &response.next_commitment.x,
        &response.next_commitment.y,
        &anchor,
    );
    anyhow::ensure!(
        verify_signature(
            &ephemeral.public_key(),
            &message,
            &response.next_state_signature
        )?,
        "successor self-test: the successor signature does not verify"
    );
    // The assertion refuses every anchor but succ(N), without signing.
    for wrong in [Felt252::ZERO, core::GENESIS_ANCHOR, random_field()] {
        anyhow::ensure!(
            sign_successor_state(
                &ephemeral,
                deployment,
                &nullifier,
                &response.next_commitment,
                &wrong
            )
            .is_err(),
            "successor self-test: the anchor assertion accepted a non-derived anchor"
        );
    }
    // The ephemeral key goes out of scope here; it signed nothing else.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    struct CountingSigner {
        inner: CompactSigner,
        calls: Cell<usize>,
    }

    impl StateSigner for CountingSigner {
        fn sign_state(&self, message: &Felt252) -> SchnorrSignature {
            self.calls.set(self.calls.get() + 1);
            self.inner.sign(message)
        }
    }

    fn deployment() -> Deployment {
        Deployment {
            protocol_version: 2,
            chain_id: 1,
            contract_address: Felt252::from_u64(1),
        }
    }

    #[test]
    fn the_successor_anchor_is_derived_from_the_nullifier_alone() {
        let nullifier = Felt252::from_u64(0x5eed);
        let anchor = derived_anchor(&nullifier);
        assert_eq!(anchor, core::next_anchor(&nullifier));
        assert_eq!(anchor, independent_anchor(&nullifier));
        assert_ne!(anchor, Felt252::ZERO);
        assert_ne!(anchor, Felt252::ONE);
        // A different nullifier, a different anchor.
        assert_ne!(derived_anchor(&Felt252::from_u64(0x5eee)), anchor);
    }

    #[test]
    fn anchors_zero_one_and_foreign_are_refused_before_signing() {
        let signer = CountingSigner {
            inner: CompactSigner::from_seed(&Felt252::from_u64(11)),
            calls: Cell::new(0),
        };
        let nullifier = Felt252::from_u64(42);
        let commitment = balance_commitment(5, &Felt252::from_u64(3), &Felt252::from_u64(4));
        for anchor in [
            Felt252::ZERO,
            Felt252::ONE,
            random_field(),
            // The derived anchor of another nullifier (a reused anchor).
            derived_anchor(&Felt252::from_u64(43)),
        ] {
            let error =
                sign_successor_state(&signer, &deployment(), &nullifier, &commitment, &anchor)
                    .unwrap_err();
            assert!(matches!(error, ServerError::Internal(_)), "{error}");
        }
        assert_eq!(signer.calls.get(), 0, "nothing was signed");
        sign_successor_state(
            &signer,
            &deployment(),
            &nullifier,
            &commitment,
            &derived_anchor(&nullifier),
        )
        .unwrap();
        assert_eq!(signer.calls.get(), 1);
    }

    #[test]
    fn the_self_test_passes_with_an_ephemeral_key() {
        self_test(&deployment()).unwrap();
    }
}
