//! Stateless proof-friendly Schnorr signing for zkAPI v2.

use zkapi_proof::compact::{
    development_seed_for_public_key, validate_operator_signing_seeds, CompactSigner,
};
use zkapi_types::wire::CurvePointWire;
use zkapi_types::{Felt252, SchnorrSignature};

pub struct ServerSigner {
    state: CompactSigner,
    clearance: CompactSigner,
    /// State signatures made, for tests that prove a path never signs.
    #[cfg(test)]
    state_signatures: std::sync::atomic::AtomicUsize,
}

impl ServerSigner {
    /// Fixture constructor: applies no operator-key policy and run_server never
    /// uses it. Serving processors still refuse the published development keys.
    pub fn new(state_seed: &Felt252, clearance_seed: &Felt252) -> Self {
        Self {
            state: CompactSigner::from_seed(state_seed),
            clearance: CompactSigner::from_seed(clearance_seed),
            #[cfg(test)]
            state_signatures: Default::default(),
        }
    }

    /// Operator constructor enforcing the full seed policy (see
    /// `zkapi_proof::compact::validate_operator_signing_seeds`).
    pub fn try_new(state_seed: &Felt252, clearance_seed: &Felt252) -> anyhow::Result<Self> {
        let (state, clearance) = validate_operator_signing_seeds(state_seed, clearance_seed)?;
        Ok(Self {
            state,
            clearance,
            #[cfg(test)]
            state_signatures: Default::default(),
        })
    }

    /// Cheap check for every serving processor, including library embeddings
    /// that bypass run_server: refuse the published development keys in either
    /// role and one key reused for both roles.
    pub fn ensure_serving_keys(&self) -> anyhow::Result<()> {
        let state = self.state_public_key();
        let clearance = self.clearance_public_key();
        for (role, key) in [("state", &state), ("clearance", &clearance)] {
            if let Some(seed) = development_seed_for_public_key(key) {
                anyhow::bail!(
                    "refusing to serve the published development {role} signing key (seed {seed:#x})"
                );
            }
        }
        anyhow::ensure!(
            state != clearance,
            "refusing to serve one signing key for both the state and clearance roles"
        );
        Ok(())
    }

    pub fn state_public_key(&self) -> CurvePointWire {
        self.state.public_key()
    }

    pub fn clearance_public_key(&self) -> CurvePointWire {
        self.clearance.public_key()
    }

    /// Sign a state message. Successors are signed only through
    /// `crate::successor::sign_successor_state`, which refuses any anchor but
    /// the derived one.
    pub fn sign_state(&self, message: &Felt252) -> SchnorrSignature {
        #[cfg(test)]
        self.state_signatures
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.state.sign(message)
    }

    /// State signatures this signer made (tests only).
    #[cfg(test)]
    pub(crate) fn state_signature_count(&self) -> usize {
        self.state_signatures
            .load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn sign_clearance(&self, message: &Felt252) -> SchnorrSignature {
        self.clearance.sign(message)
    }
}

impl crate::successor::StateSigner for ServerSigner {
    fn sign_state(&self, message: &Felt252) -> SchnorrSignature {
        ServerSigner::sign_state(self, message)
    }
}

/// Independent 31-byte operator seeds that pass the full startup policy.
#[cfg(test)]
pub(crate) fn strong_test_seeds() -> (Felt252, Felt252) {
    (
        Felt252::from_hex("0x5f3c8a91e2d4b7061a9c3e5f7082b4d6e8f0a1c3b5d7e9f1a2b4c6d8e0f1a3")
            .unwrap(),
        Felt252::from_hex("0x1d7e4b2a9c6f3e8d5b0a7c4e1f9d6b3a8c5e2f7d4a1b9e6c3f8a5d2b7e4c19")
            .unwrap(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_new_rejects_default_config_seeds() {
        let config = crate::config::ServerConfig::default();
        let error = ServerSigner::try_new(&config.state_seed, &config.clear_seed)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("zero or a multiple"), "{error}");
    }

    #[test]
    fn try_new_matches_fixture_derivation() {
        let (state_seed, clear_seed) = strong_test_seeds();
        let signer = ServerSigner::try_new(&state_seed, &clear_seed).unwrap();
        let fixture = ServerSigner::new(&state_seed, &clear_seed);
        assert_eq!(signer.state_public_key(), fixture.state_public_key());
        assert_eq!(
            signer.clearance_public_key(),
            fixture.clearance_public_key()
        );
        signer.ensure_serving_keys().unwrap();
    }

    #[test]
    fn serving_check_refuses_development_and_reused_keys_but_keeps_fixtures() {
        let (strong, _) = strong_test_seeds();
        let one = Felt252::ONE;
        let two = Felt252::from_u64(2);
        for (state, clearance) in [(one, two), (two, one), (one, strong), (strong, two)] {
            let error = ServerSigner::new(&state, &clearance)
                .ensure_serving_keys()
                .unwrap_err()
                .to_string();
            assert!(error.contains("published development"), "{error}");
        }
        let error = ServerSigner::new(&strong, &strong)
            .ensure_serving_keys()
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("both the state and clearance roles"),
            "{error}"
        );
        // The cheap check deliberately leaves the small processor fixtures usable;
        // run_server applies the full policy that rejects them.
        ServerSigner::new(&Felt252::from_u64(7), &Felt252::from_u64(8))
            .ensure_serving_keys()
            .unwrap();
        assert!(ServerSigner::try_new(&Felt252::from_u64(7), &Felt252::from_u64(8)).is_err());
    }
}
