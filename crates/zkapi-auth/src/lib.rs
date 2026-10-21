//! Swappable authentication / credential schemes for zkAPI.
//!
//! The daemons run with one of two interchangeable authentication methods,
//! selected by configuration:
//!
//! - [`AuthSchemeKind::StateAnchor`] — the reference state-anchor chain of
//!   circuit `zkapi-v2-concession-v1`: a note-bound Pedersen balance
//!   commitment on Baby-JubJub, a note-bound nullifier chain whose successor
//!   anchors are derived (`τ' = H(d_anchor', N)`), and a Schnorr state
//!   signature carrying the state forward (delegates to the `protocol`
//!   crates' primitives).
//! - [`AuthSchemeKind::BlindSignature`] — blind Schnorr credentials issued by
//!   the server, presented unlinkably per request.
//!
//! [`CredentialScheme`] is the thin interface both implement. It covers the
//! five operations the daemons need:
//!
//! 1. how the client builds the per-request presentation ([`CredentialScheme::authenticate`]),
//! 2. how the server verifies it ([`CredentialScheme::verify`]),
//! 3. how spend tokens are derived (returned by `authenticate` / `verify`),
//! 4. how the next state is computed after a charge ([`CredentialScheme::apply_charge`]),
//! 5. how withdrawal authorizations are built ([`CredentialScheme::build_withdrawal`]).
//!
//! The reference (in-process) implementations hold both client and server
//! state so the whole flow is unit-testable end to end; the daemons wire the
//! same operations across the HTTP boundary.

pub mod blind_schnorr;
pub mod scalar;

mod blind_signature;
mod state_anchor;

pub use blind_signature::BlindSignatureScheme;
pub use state_anchor::StateAnchorScheme;

use std::fmt;
use std::str::FromStr;

use starknet_types_core::felt::Felt;

/// Errors surfaced by a credential scheme.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("authentication verification failed: {0}")]
    VerificationFailed(String),
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },
    #[error("spend token already used (replay)")]
    Replay,
    #[error("crypto error: {0}")]
    Crypto(String),
}

/// Which authentication method a daemon runs with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AuthSchemeKind {
    /// Reference: state-anchor chain (Pedersen + nullifier + Schnorr).
    #[default]
    StateAnchor,
    /// Alternate: blind Schnorr credentials.
    BlindSignature,
}

impl AuthSchemeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::StateAnchor => "state-anchor",
            Self::BlindSignature => "blind-signature",
        }
    }
}

impl fmt::Display for AuthSchemeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for AuthSchemeKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
            "state-anchor" | "stateanchor" | "anchor" | "state" => Ok(Self::StateAnchor),
            "blind-signature" | "blindsignature" | "blind" | "bs" => Ok(Self::BlindSignature),
            other => Err(format!(
                "unknown auth scheme '{other}' (expected 'state-anchor' or 'blind-signature')"
            )),
        }
    }
}

/// The swappable credential-scheme interface.
///
/// A scheme instance owns the in-process server state (used spend tokens,
/// signing keys) so the full register → authenticate → charge → withdraw flow
/// can be exercised in one place. The daemons split these calls across the
/// client (`authenticate`, `build_withdrawal`) and server (`verify`,
/// `apply_charge`, `verify_withdrawal`) over HTTP.
pub trait CredentialScheme {
    /// Client-held credential (balance + the secret material that opens it).
    type Credential: Clone;
    /// Per-request presentation sent client → server.
    type Presentation;
    /// Withdrawal authorization sent client → server / chain.
    type Withdrawal;

    /// The configured scheme identity.
    fn kind(&self) -> AuthSchemeKind;

    /// Registration / genesis: issue the first credential for `balance`.
    fn issue(&mut self, secret: Felt, balance: u128) -> Result<Self::Credential, AuthError>;

    /// (1)+(3) Client builds a per-request presentation and derives a fresh
    /// spend token (the replay key). `charge_cap` bounds what the server may
    /// charge for this request.
    fn authenticate(
        &self,
        cred: &Self::Credential,
        charge_cap: u128,
    ) -> Result<(Self::Presentation, Felt), AuthError>;

    /// (2) Server verifies a presentation, reserving its spend token; returns
    /// the spend token on success.
    fn verify(&mut self, presentation: &Self::Presentation) -> Result<Felt, AuthError>;

    /// (4) Compute the next credential after the server applies `charge`.
    fn apply_charge(
        &mut self,
        cred: &Self::Credential,
        presentation: &Self::Presentation,
        charge: u128,
    ) -> Result<Self::Credential, AuthError>;

    /// (5) Client builds a withdrawal authorization for `cred`'s balance.
    fn build_withdrawal(&self, cred: &Self::Credential) -> Result<Self::Withdrawal, AuthError>;

    /// Server settles a withdrawal authorization; returns `(balance, spend token)`.
    fn verify_withdrawal(&mut self, w: &Self::Withdrawal) -> Result<(u128, Felt), AuthError>;

    /// Read the balance carried by a credential.
    fn balance(&self, cred: &Self::Credential) -> u128;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drive an identical deposit → many requests → withdraw flow through any
    /// scheme. This is the harness the "full test suite runs under each
    /// scheme" milestone item hangs on.
    fn exercise_scheme<S: CredentialScheme>(scheme: &mut S, expected_kind: AuthSchemeKind) {
        assert_eq!(scheme.kind(), expected_kind);

        let secret = Felt::from(0x5ec4e7u64);
        let mut cred = scheme.issue(secret, 100).expect("issue");
        assert_eq!(scheme.balance(&cred), 100);

        let mut seen_tokens = std::collections::HashSet::new();
        for _ in 0..5 {
            let (presentation, client_token) =
                scheme.authenticate(&cred, 10).expect("authenticate");
            let server_token = scheme.verify(&presentation).expect("verify");
            assert_eq!(client_token, server_token, "spend token must agree");
            assert!(
                seen_tokens.insert(server_token),
                "spend tokens must be unique"
            );

            // Replaying the same presentation must be rejected.
            assert!(matches!(
                scheme.verify(&presentation),
                Err(AuthError::Replay)
            ));

            cred = scheme
                .apply_charge(&cred, &presentation, 3)
                .expect("apply charge");
        }
        assert_eq!(scheme.balance(&cred), 100 - 5 * 3);

        let withdrawal = scheme.build_withdrawal(&cred).expect("build withdrawal");
        let (settled, _wtoken) = scheme
            .verify_withdrawal(&withdrawal)
            .expect("verify withdrawal");
        assert_eq!(settled, 85);
    }

    #[test]
    fn state_anchor_scheme_round_trips() {
        let mut scheme = StateAnchorScheme::new_for_test();
        exercise_scheme(&mut scheme, AuthSchemeKind::StateAnchor);
    }

    #[test]
    fn blind_signature_scheme_round_trips() {
        let mut scheme = BlindSignatureScheme::new_for_test();
        exercise_scheme(&mut scheme, AuthSchemeKind::BlindSignature);
    }

    #[test]
    fn scheme_kind_parses_from_config() {
        assert_eq!("state-anchor".parse(), Ok(AuthSchemeKind::StateAnchor));
        assert_eq!(
            "blind_signature".parse(),
            Ok(AuthSchemeKind::BlindSignature)
        );
        assert_eq!("blind".parse(), Ok(AuthSchemeKind::BlindSignature));
        assert!("nope".parse::<AuthSchemeKind>().is_err());
    }
}
