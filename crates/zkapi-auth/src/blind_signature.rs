//! Blind-signature authentication method.
//!
//! A credential is a blind Schnorr signature (see [`crate::blind_schnorr`]) by
//! the server over the message `H(balance, serial)`. The signature binds the
//! balance (the client cannot alter it without invalidating the signature),
//! while blindness makes the issuance run unlinkable to the later
//! presentation. The `serial` doubles as the spend token / replay key.
//!
//! - Registration issues a credential for the deposited balance.
//! - Each request reveals `(balance, serial, signature)`; the server verifies
//!   the signature and reserves `serial`.
//! - A charge is a *refund*: the server re-issues a fresh blind credential for
//!   `balance - charge` under a new serial (variable-size refunds fall out for
//!   free — any next balance can be signed).
//! - Withdrawal reveals the final credential.

use std::collections::HashSet;

use sha3::{Digest, Keccak256};
use starknet_types_core::felt::Felt;

use crate::blind_schnorr::{self, SigningKey};
use crate::scalar;
use crate::{AuthError, AuthSchemeKind, CredentialScheme};

const CRED_DOMAIN: &[u8] = b"zkapi.bs.cred.v1";
const SERIAL_DOMAIN: &[u8] = b"zkapi.bs.serial.v1";

fn hash_to_felt(domain: &[u8], parts: &[&[u8]]) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update(part);
    }
    scalar::from_bytes_reduced(&hasher.finalize())
}

/// The message the server blind-signs: a binding of `(balance, serial)`.
fn credential_message(balance: u128, serial: &Felt) -> Felt {
    hash_to_felt(
        CRED_DOMAIN,
        &[&balance.to_be_bytes(), &serial.to_bytes_be()],
    )
}

/// Client-held blind-signature credential.
#[derive(Clone)]
pub struct BlindCredential {
    pub balance: u128,
    pub serial: Felt,
    pub signature: blind_schnorr::Signature,
}

/// Per-request presentation (client → server).
pub struct BlindPresentation {
    balance: u128,
    serial: Felt,
    signature: blind_schnorr::Signature,
}

/// The blind-signature scheme: holds the server signing key and the set of
/// spent serials (the in-process stand-in for serverd's nullifier store).
pub struct BlindSignatureScheme {
    key: SigningKey,
    spent: HashSet<Felt>,
}

impl BlindSignatureScheme {
    pub fn new(key: SigningKey) -> Self {
        Self {
            key,
            spent: HashSet::new(),
        }
    }

    /// Deterministic instance for tests / local demos.
    pub fn new_for_test() -> Self {
        Self::new(SigningKey::from_secret(Felt::from(0xb11d_516eu64)))
    }

    /// Public key x-coordinate operators publish so clients can verify
    /// credentials (e.g. in the attestation bundle).
    pub fn public_key_x(&self) -> Felt {
        self.key.public_x()
    }

    /// Run the (in-process) blind issuance protocol for `message`.
    fn blind_issue(&self, message: Felt) -> blind_schnorr::Signature {
        let mut rng = rand::thread_rng();
        let nonce = blind_schnorr::server_commit(&mut rng);
        let (state, c) =
            blind_schnorr::client_blind(&nonce.commitment, &self.key.public, message, &mut rng);
        let s = blind_schnorr::server_respond(&nonce, &self.key, &c);
        blind_schnorr::client_unblind(&state, &s)
    }

    fn next_serial(prev: &Felt) -> Felt {
        hash_to_felt(SERIAL_DOMAIN, &[&prev.to_bytes_be()])
    }
}

impl CredentialScheme for BlindSignatureScheme {
    type Credential = BlindCredential;
    type Presentation = BlindPresentation;
    type Withdrawal = BlindPresentation;

    fn kind(&self) -> AuthSchemeKind {
        AuthSchemeKind::BlindSignature
    }

    fn issue(&mut self, secret: Felt, balance: u128) -> Result<Self::Credential, AuthError> {
        // Initial serial is bound to the client secret so registration is
        // deterministic per user; later serials chain off it.
        let serial = hash_to_felt(SERIAL_DOMAIN, &[b"genesis", &secret.to_bytes_be()]);
        let signature = self.blind_issue(credential_message(balance, &serial));
        Ok(BlindCredential {
            balance,
            serial,
            signature,
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
        let presentation = BlindPresentation {
            balance: cred.balance,
            serial: cred.serial,
            signature: cred.signature.clone(),
        };
        Ok((presentation, cred.serial))
    }

    fn verify(&mut self, presentation: &Self::Presentation) -> Result<Felt, AuthError> {
        let message = credential_message(presentation.balance, &presentation.serial);
        if !blind_schnorr::verify(&self.key.public, &message, &presentation.signature) {
            return Err(AuthError::VerificationFailed(
                "invalid blind signature".into(),
            ));
        }
        if !self.spent.insert(presentation.serial) {
            return Err(AuthError::Replay);
        }
        Ok(presentation.serial)
    }

    fn apply_charge(
        &mut self,
        cred: &Self::Credential,
        _presentation: &Self::Presentation,
        charge: u128,
    ) -> Result<Self::Credential, AuthError> {
        let next_balance =
            cred.balance
                .checked_sub(charge)
                .ok_or(AuthError::InsufficientBalance {
                    have: cred.balance,
                    need: charge,
                })?;
        let next_serial = Self::next_serial(&cred.serial);
        // Refund = re-issue a fresh blind credential for the new balance.
        let signature = self.blind_issue(credential_message(next_balance, &next_serial));
        Ok(BlindCredential {
            balance: next_balance,
            serial: next_serial,
            signature,
        })
    }

    fn build_withdrawal(&self, cred: &Self::Credential) -> Result<Self::Withdrawal, AuthError> {
        Ok(BlindPresentation {
            balance: cred.balance,
            serial: cred.serial,
            signature: cred.signature.clone(),
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

    #[test]
    fn forged_balance_is_rejected() {
        // A credential issued for balance 100 cannot be presented as balance 5:
        // the signed message binds the balance.
        let mut scheme = BlindSignatureScheme::new_for_test();
        let cred = scheme.issue(Felt::from(1u64), 100).unwrap();
        let forged = BlindPresentation {
            balance: 5,
            serial: cred.serial,
            signature: cred.signature.clone(),
        };
        assert!(matches!(
            scheme.verify(&forged),
            Err(AuthError::VerificationFailed(_))
        ));
    }
}
