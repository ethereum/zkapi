//! State-anchor authentication method (the reference implementation).
//!
//! This is the zkAPI state chain of circuit `zkapi-v2-concession-v1`
//! expressed behind [`CredentialScheme`]: a note-bound Pedersen balance
//! commitment `C = B·G + r·H + L·J` on Baby-JubJub, a note-bound nullifier
//! `N = H(d_null', s, note_id, τ)`, successor anchors derived as
//! `τ' = H(d_anchor', N)`, and a Schnorr state signature over
//! `state_message(C', τ')` carrying the state forward. It delegates to the
//! protocol crates' primitives (`zkapi_core::v2`, `zkapi_proof::compact`)
//! rather than reimplementing them; the daemons run the same logic across the
//! HTTP boundary, with zero-knowledge proofs in place of the openings this
//! in-process reference reveals.

use std::collections::HashSet;

use starknet_types_core::felt::Felt;

use zkapi_core::v2 as core;
use zkapi_proof::compact::{
    add_blindings, balance_commitment, random_scalar, rerandomize, server_update, verify_signature,
    CompactSigner,
};
use zkapi_types::wire::CurvePointWire;
use zkapi_types::{Felt252, SchnorrSignature};

use crate::{AuthError, AuthSchemeKind, CredentialScheme};

/// Deposit expiry used by the in-process reference (far in the future).
const REFERENCE_EXPIRY: u64 = 4_000_000_000;

/// Client-held state-anchor credential: the opening of the current state.
#[derive(Clone)]
pub struct StateAnchorCredential {
    secret: Felt252,
    note_id: u32,
    deposit: u128,
    balance: u128,
    /// Baby-JubJub scalar opening the current commitment.
    blinding: Felt252,
    anchor: Felt252,
    /// The anchor of the state whose request produced this one (`None` at
    /// genesis).
    prev_anchor: Option<Felt252>,
    state_sig: Option<SchnorrSignature>,
}

/// Per-request presentation: the rerandomized commitment opening plus the
/// nullifier and the carried-forward state signature.
pub struct StateAnchorPresentation {
    secret: Felt252,
    note_id: u32,
    deposit: u128,
    balance: u128,
    blinding: Felt252,
    user_rerand: Felt252,
    anchor: Felt252,
    prev_anchor: Option<Felt252>,
    nullifier: Felt252,
    state_sig: Option<SchnorrSignature>,
}

/// State-anchor scheme: holds the server state signer and the spent-nullifier
/// set (the in-process stand-in for serverd's signer + nullifier store).
pub struct StateAnchorScheme {
    signer: CompactSigner,
    protocol_version: u16,
    chain_id: u64,
    contract: Felt252,
    next_note_id: u32,
    spent: HashSet<Felt252>,
}

impl StateAnchorScheme {
    pub fn new(
        signer: CompactSigner,
        protocol_version: u16,
        chain_id: u64,
        contract: Felt252,
    ) -> Self {
        Self {
            signer,
            protocol_version,
            chain_id,
            contract,
            next_note_id: 0,
            spent: HashSet::new(),
        }
    }

    /// Deterministic instance for tests and local demos.
    pub fn new_for_test() -> Self {
        Self::new(
            CompactSigner::from_seed(&Felt252::from_u64(0x57a7e)),
            zkapi_types::PROTOCOL_VERSION,
            31337,
            Felt252::from_u64(0xca7e),
        )
    }

    fn leaf(secret: &Felt252, note_id: u32, deposit: u128) -> Felt252 {
        core::note_leaf(
            note_id,
            &core::registration_commitment(secret),
            deposit,
            REFERENCE_EXPIRY,
        )
    }

    fn commitment(p: &StateAnchorPresentation) -> CurvePointWire {
        balance_commitment(
            p.balance,
            &p.blinding,
            &Self::leaf(&p.secret, p.note_id, p.deposit),
        )
    }

    /// The checks the request circuit makes on the opened state: `B <= D`;
    /// genesis holds the whole deposit; a signed state sits at the anchor
    /// derived from its predecessor's nullifier and carries a valid state
    /// signature over its commitment; the nullifier is this state's.
    fn verify_state(&self, p: &StateAnchorPresentation) -> Result<(), AuthError> {
        let fail = |message: &str| Err(AuthError::VerificationFailed(message.into()));
        if p.balance > p.deposit {
            return fail("the state balance exceeds the deposit");
        }
        if p.nullifier != core::nullifier(&p.secret, p.note_id, &p.anchor) {
            return fail("the nullifier is not this state's");
        }
        if p.anchor == core::GENESIS_ANCHOR {
            if p.balance != p.deposit {
                return fail("a genesis state must hold the whole deposit");
            }
            return Ok(());
        }
        let Some(prev_anchor) = p.prev_anchor else {
            return fail("a signed state needs its predecessor's anchor");
        };
        if p.anchor != core::next_anchor(&core::nullifier(&p.secret, p.note_id, &prev_anchor)) {
            return fail("the state anchor is not derived from its predecessor's nullifier");
        }
        let sig = p.state_sig.as_ref().ok_or_else(|| {
            AuthError::VerificationFailed("missing non-genesis state signature".into())
        })?;
        let commitment = Self::commitment(p);
        let message = core::state_message(
            self.protocol_version,
            self.chain_id,
            &self.contract,
            &commitment.x,
            &commitment.y,
            &p.anchor,
        );
        let valid = verify_signature(&self.signer.public_key(), &message, sig)
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        if !valid {
            return fail("state signature verification failed");
        }
        Ok(())
    }
}

/// The spend token as a Stark-field element (the trait's token type). A
/// BN254 nullifier is reduced into the Stark field; two distinct nullifiers
/// collide only with negligible probability.
fn token(nullifier: &Felt252) -> Felt {
    Felt::from_bytes_be(&nullifier.0)
}

/// A Stark-field secret is below the BN254 scalar modulus, so it is a
/// canonical BN254 field element as it stands.
fn secret_felt(secret: &Felt) -> Felt252 {
    Felt252(secret.to_bytes_be())
}

impl CredentialScheme for StateAnchorScheme {
    type Credential = StateAnchorCredential;
    type Presentation = StateAnchorPresentation;
    type Withdrawal = StateAnchorPresentation;

    fn kind(&self) -> AuthSchemeKind {
        AuthSchemeKind::StateAnchor
    }

    fn issue(&mut self, secret: Felt, balance: u128) -> Result<Self::Credential, AuthError> {
        let secret = secret_felt(&secret);
        if secret.is_zero() {
            return Err(AuthError::Crypto("the note secret must not be zero".into()));
        }
        let note_id = self.next_note_id;
        self.next_note_id += 1;
        Ok(StateAnchorCredential {
            secret,
            note_id,
            deposit: balance,
            balance,
            blinding: random_scalar(),
            anchor: core::GENESIS_ANCHOR,
            prev_anchor: None,
            state_sig: None,
        })
    }

    fn authenticate(
        &self,
        cred: &Self::Credential,
        charge_cap: u128,
    ) -> Result<(Self::Presentation, Felt), AuthError> {
        if cred.balance < charge_cap {
            return Err(AuthError::InsufficientBalance {
                have: cred.balance,
                need: charge_cap,
            });
        }
        let nullifier = core::nullifier(&cred.secret, cred.note_id, &cred.anchor);
        let presentation = StateAnchorPresentation {
            secret: cred.secret,
            note_id: cred.note_id,
            deposit: cred.deposit,
            balance: cred.balance,
            blinding: cred.blinding,
            user_rerand: random_scalar(),
            anchor: cred.anchor,
            prev_anchor: cred.prev_anchor,
            nullifier,
            state_sig: cred.state_sig,
        };
        Ok((presentation, token(&nullifier)))
    }

    fn verify(&mut self, p: &Self::Presentation) -> Result<Felt, AuthError> {
        self.verify_state(p)?;
        if !self.spent.insert(p.nullifier) {
            return Err(AuthError::Replay);
        }
        Ok(token(&p.nullifier))
    }

    fn apply_charge(
        &mut self,
        cred: &Self::Credential,
        p: &Self::Presentation,
        charge: u128,
    ) -> Result<Self::Credential, AuthError> {
        let next_balance =
            cred.balance
                .checked_sub(charge)
                .ok_or(AuthError::InsufficientBalance {
                    have: cred.balance,
                    need: charge,
                })?;
        // The operator sees only the rerandomized commitment and updates it
        // homomorphically: C' = C + ρ·H − charge·G + δ·H.
        let anonymous = rerandomize(&Self::commitment(p), &p.user_rerand)
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        let blind_delta = random_scalar();
        let next_commitment = server_update(&anonymous, charge, &blind_delta)
            .map_err(|error| AuthError::Crypto(error.to_string()))?;
        // The successor sits at the derived anchor, never a chosen one.
        let next_anchor = core::next_anchor(&p.nullifier);
        let message = core::state_message(
            self.protocol_version,
            self.chain_id,
            &self.contract,
            &next_commitment.x,
            &next_commitment.y,
            &next_anchor,
        );
        let state_sig = self.signer.sign(&message);

        // nextBlinding = currentBlinding + userRerand + blindDelta  (mod l)
        let next_blinding =
            add_blindings(&add_blindings(&cred.blinding, &p.user_rerand), &blind_delta);
        let opened = balance_commitment(
            next_balance,
            &next_blinding,
            &Self::leaf(&cred.secret, cred.note_id, cred.deposit),
        );
        if opened != next_commitment {
            return Err(AuthError::Crypto(
                "the successor commitment does not open to the charged balance".into(),
            ));
        }
        Ok(StateAnchorCredential {
            secret: cred.secret,
            note_id: cred.note_id,
            deposit: cred.deposit,
            balance: next_balance,
            blinding: next_blinding,
            anchor: next_anchor,
            prev_anchor: Some(cred.anchor),
            state_sig: Some(state_sig),
        })
    }

    fn build_withdrawal(&self, cred: &Self::Credential) -> Result<Self::Withdrawal, AuthError> {
        // Reveal the final commitment opening; the withdrawal nullifier is the
        // nullifier of the (never-spent) final anchor.
        Ok(StateAnchorPresentation {
            secret: cred.secret,
            note_id: cred.note_id,
            deposit: cred.deposit,
            balance: cred.balance,
            blinding: cred.blinding,
            user_rerand: Felt252::ZERO,
            anchor: cred.anchor,
            prev_anchor: cred.prev_anchor,
            nullifier: core::nullifier(&cred.secret, cred.note_id, &cred.anchor),
            state_sig: cred.state_sig,
        })
    }

    fn verify_withdrawal(&mut self, w: &Self::Withdrawal) -> Result<(u128, Felt), AuthError> {
        let token = self.verify(w)?;
        Ok((w.balance, token))
    }

    fn balance(&self, cred: &Self::Credential) -> u128 {
        cred.balance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each successor sits at `next_anchor` of its predecessor's nullifier,
    /// so a withdrawal from a state spends the nullifier the previous
    /// state's escape would have published as its successor.
    #[test]
    fn successors_sit_at_derived_anchors() {
        let mut scheme = StateAnchorScheme::new_for_test();
        let genesis = scheme.issue(Felt::from(7u64), 100).unwrap();
        let (presentation, _) = scheme.authenticate(&genesis, 10).unwrap();
        scheme.verify(&presentation).unwrap();
        let next = scheme.apply_charge(&genesis, &presentation, 4).unwrap();
        assert_eq!(next.anchor, core::next_anchor(&presentation.nullifier));
        assert_eq!(next.prev_anchor, Some(core::GENESIS_ANCHOR));
        let withdrawal = scheme.build_withdrawal(&next).unwrap();
        assert_eq!(
            withdrawal.nullifier,
            core::successor_nullifier(&genesis.secret, genesis.note_id, &genesis.anchor)
        );
        assert_eq!(scheme.verify_withdrawal(&withdrawal).unwrap().0, 96);
    }

    /// A signed state at an anchor that is not derived from its
    /// predecessor's nullifier is refused, as the request circuit refuses it.
    #[test]
    fn a_state_at_a_non_derived_anchor_is_refused() {
        let mut scheme = StateAnchorScheme::new_for_test();
        let genesis = scheme.issue(Felt::from(7u64), 100).unwrap();
        let (presentation, _) = scheme.authenticate(&genesis, 10).unwrap();
        scheme.verify(&presentation).unwrap();
        let mut next = scheme.apply_charge(&genesis, &presentation, 4).unwrap();
        next.anchor = Felt252::from_u64(0xbad);
        let (forged, _) = scheme.authenticate(&next, 10).unwrap();
        assert!(matches!(
            scheme.verify(&forged),
            Err(AuthError::VerificationFailed(message)) if message.contains("not derived")
        ));
        // Without the predecessor anchor the chain cannot be checked.
        let mut next = scheme.apply_charge(&genesis, &presentation, 4).unwrap();
        next.prev_anchor = None;
        let (orphan, _) = scheme.authenticate(&next, 10).unwrap();
        assert!(scheme.verify(&orphan).is_err());
    }

    /// Notes that share a secret have disjoint nullifier chains.
    #[test]
    fn notes_sharing_a_secret_have_distinct_tokens() {
        let mut scheme = StateAnchorScheme::new_for_test();
        let first = scheme.issue(Felt::from(7u64), 100).unwrap();
        let second = scheme.issue(Felt::from(7u64), 100).unwrap();
        let (a, token_a) = scheme.authenticate(&first, 10).unwrap();
        let (b, token_b) = scheme.authenticate(&second, 10).unwrap();
        assert_ne!(token_a, token_b);
        scheme.verify(&a).unwrap();
        scheme.verify(&b).unwrap();
    }
}
