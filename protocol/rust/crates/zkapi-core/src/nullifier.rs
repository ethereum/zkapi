//! Nullifier computation for circuit `zkapi-v2-concession-v1`.
//!
//! N = Poseidon(domain("zkapi.v2c.null"), s, note_id, tau)
//! For genesis: tau = 1
//! For later states: tau = Poseidon(domain("zkapi.v2c.anchor"), N_prev)

use zkapi_types::Felt252;

/// Compute a nullifier from the user secret, note id and state anchor.
pub fn compute_nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252 {
    crate::v2::nullifier(secret, note_id, anchor)
}

/// Compute the genesis nullifier of a note.
pub fn compute_genesis_nullifier(secret: &Felt252, note_id: u32) -> Felt252 {
    compute_nullifier(secret, note_id, &crate::v2::GENESIS_ANCHOR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nullifier_deterministic() {
        let secret = Felt252::from_u64(42);
        let anchor = Felt252::from_u64(100);
        let n1 = compute_nullifier(&secret, 0, &anchor);
        let n2 = compute_nullifier(&secret, 0, &anchor);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_genesis_nullifier() {
        let secret = Felt252::from_u64(42);
        let n_genesis = compute_genesis_nullifier(&secret, 5);
        let n_manual = compute_nullifier(&secret, 5, &Felt252::ONE);
        assert_eq!(n_genesis, n_manual);
    }

    #[test]
    fn test_different_anchors_and_notes() {
        let secret = Felt252::from_u64(42);
        let n1 = compute_nullifier(&secret, 0, &Felt252::from_u64(1));
        let n2 = compute_nullifier(&secret, 0, &Felt252::from_u64(2));
        let n3 = compute_nullifier(&secret, 1, &Felt252::from_u64(1));
        assert_ne!(n1, n2);
        assert_ne!(n1, n3);
    }
}
