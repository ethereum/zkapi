//! Blind Schnorr signatures over the Stark curve.
//!
//! This is the cryptographic core of the blind-signature authentication
//! method. The server issues a signature on a client-chosen credential message
//! without learning the message or being able to link the issuance run to the
//! later presentation (request-by-request unlinkability):
//!
//! 1. Server samples nonce `k`, sends commitment `R = k·G`.
//! 2. Client blinds with random `α, β`: `R' = R + α·G + β·P`, computes the
//!    challenge `c' = H(R'.x, m)` and the blinded challenge `c = c' + β`,
//!    sends `c`.
//! 3. Server replies `s = k + c·x`.
//! 4. Client unblinds `s' = s + α`. The signature is `(c', s')`.
//!
//! Verification recovers `R'' = s'·G - c'·P` and checks `H(R''.x, m) == c'`.
//! The pair `(c', s')` is independent of the `(R, c, s)` transcript the signer
//! observed, so a malicious server cannot link a presented credential to its
//! issuance.

use std::ops::Neg;

use rand::Rng;
use sha3::{Digest, Keccak256};
use starknet_types_core::curve::{AffinePoint, ProjectivePoint};
use starknet_types_core::felt::Felt;

use crate::scalar;

const CHALLENGE_DOMAIN: &[u8] = b"zkapi.blind-schnorr.v1";

fn generator() -> ProjectivePoint {
    let g = AffinePoint::generator();
    ProjectivePoint::from_affine(g.x(), g.y()).expect("Stark generator is on curve")
}

/// Double-and-add scalar multiplication. `k` is taken modulo the group order.
fn scalar_mul(point: &ProjectivePoint, k: &Felt) -> ProjectivePoint {
    let k = scalar::reduce(k);
    let bits = k.to_bits_le();
    let mut result = ProjectivePoint::identity();
    let mut temp = point.clone();
    for bit in bits.iter() {
        if *bit {
            result = &result + &temp;
        }
        temp = &temp + &temp;
    }
    result
}

fn point_x(point: &ProjectivePoint) -> Felt {
    point.to_affine().expect("point is not the identity").x()
}

fn challenge(r_prime: &ProjectivePoint, message: &Felt) -> Felt {
    let mut hasher = Keccak256::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(point_x(r_prime).to_bytes_be());
    hasher.update(message.to_bytes_be());
    scalar::from_bytes_reduced(&hasher.finalize())
}

/// Sample a uniform-ish scalar mod `n`.
pub fn random_scalar(rng: &mut impl Rng) -> Felt {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    scalar::from_bytes_reduced(&bytes)
}

/// Server long-term blind-signing keypair.
#[derive(Clone)]
pub struct SigningKey {
    pub secret: Felt,
    pub public: ProjectivePoint,
}

impl SigningKey {
    pub fn from_secret(secret: Felt) -> Self {
        let secret = scalar::reduce(&secret);
        let public = scalar_mul(&generator(), &secret);
        Self { secret, public }
    }

    pub fn generate(rng: &mut impl Rng) -> Self {
        Self::from_secret(random_scalar(rng))
    }

    /// Affine x-coordinate of the public key — a compact identifier the server
    /// can publish (e.g. in its attestation bundle).
    pub fn public_x(&self) -> Felt {
        point_x(&self.public)
    }
}

/// Server per-issuance secret nonce plus its public commitment.
pub struct IssuanceNonce {
    k: Felt,
    pub commitment: ProjectivePoint,
}

/// Step 1: server commits to a fresh nonce.
pub fn server_commit(rng: &mut impl Rng) -> IssuanceNonce {
    let k = random_scalar(rng);
    let commitment = scalar_mul(&generator(), &k);
    IssuanceNonce { k, commitment }
}

/// Opaque client blinding state retained between blinding and unblinding.
pub struct BlindState {
    alpha: Felt,
    r_prime: ProjectivePoint,
    message: Felt,
}

/// Step 2: client blinds the commitment and produces the challenge to send.
pub fn client_blind(
    commitment: &ProjectivePoint,
    public: &ProjectivePoint,
    message: Felt,
    rng: &mut impl Rng,
) -> (BlindState, Felt) {
    let alpha = random_scalar(rng);
    let beta = random_scalar(rng);
    // R' = R + alpha*G + beta*P
    let r_prime = &(commitment + &scalar_mul(&generator(), &alpha)) + &scalar_mul(public, &beta);
    let c_prime = challenge(&r_prime, &message);
    let c = scalar::add(&c_prime, &beta);
    (
        BlindState {
            alpha,
            r_prime,
            message,
        },
        c,
    )
}

/// Step 3: server answers the blinded challenge.
pub fn server_respond(nonce: &IssuanceNonce, key: &SigningKey, c: &Felt) -> Felt {
    // s = k + c*x
    scalar::add(&nonce.k, &scalar::mul(c, &key.secret))
}

/// A finalized blind signature, unlinkable to its issuance transcript.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub c_prime: Felt,
    pub s_prime: Felt,
}

/// Step 4: client unblinds the server response into a verifiable signature.
pub fn client_unblind(state: &BlindState, s: &Felt) -> Signature {
    Signature {
        c_prime: challenge(&state.r_prime, &state.message),
        s_prime: scalar::add(s, &state.alpha),
    }
}

/// Verify a blind signature on `message` against the signer's public key.
pub fn verify(public: &ProjectivePoint, message: &Felt, sig: &Signature) -> bool {
    // R'' = s'*G - c'*P
    let s_g = scalar_mul(&generator(), &sig.s_prime);
    let c_p = scalar_mul(public, &sig.c_prime);
    let r_pp = &s_g + &c_p.neg();
    if r_pp.is_identity() {
        return false;
    }
    challenge(&r_pp, message) == sig.c_prime
}

#[cfg(test)]
mod tests {
    use super::*;

    fn issue(key: &SigningKey, message: Felt, rng: &mut impl Rng) -> Signature {
        let nonce = server_commit(rng);
        let (state, c) = client_blind(&nonce.commitment, &key.public, message, rng);
        let s = server_respond(&nonce, key, &c);
        client_unblind(&state, &s)
    }

    #[test]
    fn blind_signature_round_trips() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let message = Felt::from(0xc0ffeeu64);
        let sig = issue(&key, message, &mut rng);
        assert!(verify(&key.public, &message, &sig));
    }

    #[test]
    fn rejects_wrong_message() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let sig = issue(&key, Felt::from(1u64), &mut rng);
        assert!(!verify(&key.public, &Felt::from(2u64), &sig));
    }

    #[test]
    fn rejects_tampered_signature() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let message = Felt::from(7u64);
        let mut sig = issue(&key, message, &mut rng);
        sig.s_prime = scalar::add(&sig.s_prime, &Felt::from(1u64));
        assert!(!verify(&key.public, &message, &sig));
    }

    #[test]
    fn rejects_wrong_key() {
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let other = SigningKey::generate(&mut rng);
        let message = Felt::from(9u64);
        let sig = issue(&key, message, &mut rng);
        assert!(!verify(&other.public, &message, &sig));
    }

    #[test]
    fn distinct_issuance_runs_yield_valid_unlinkable_signatures() {
        // Two issuance runs of the SAME message produce different transcripts
        // but both verify — the property the request path relies on.
        let mut rng = rand::thread_rng();
        let key = SigningKey::generate(&mut rng);
        let message = Felt::from(42u64);
        let a = issue(&key, message, &mut rng);
        let b = issue(&key, message, &mut rng);
        assert!(verify(&key.public, &message, &a));
        assert!(verify(&key.public, &message, &b));
        assert_ne!(a, b);
    }
}
