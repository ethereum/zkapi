//! Note leaf computation (circuit `zkapi-v2-concession-v2`).
//!
//! ```text
//! F = note_id·2^192 + deposit_amount·2^64 + expiry_ts
//! leaf = P(domain("zkapi.v2c.leaf"), C, F)[1]
//! ```
//!
//! One width-3 Poseidon permutation with the domain in the capacity lane
//! ([`crate::v2::compress_fields`]): the vault stores this word per note, the
//! request tree holds it at index `note_id`, and withdrawal proofs publish it
//! with `F`.

use zkapi_types::Felt252;

/// Compute the active note leaf `P(domain("zkapi.v2c.leaf"), commitment, F)[1]`.
pub fn compute_note_leaf(
    note_id: u32,
    commitment: &Felt252,
    deposit_amount: u128,
    expiry_ts: u64,
) -> Felt252 {
    crate::v2::note_leaf(note_id, commitment, deposit_amount, expiry_ts)
}

/// Compute the packed note fields `F = note_id·2^192 + deposit_amount·2^64 + expiry_ts`.
pub fn compute_note_fields(note_id: u32, deposit_amount: u128, expiry_ts: u64) -> Felt252 {
    crate::v2::note_fields(note_id, deposit_amount, expiry_ts)
}

/// Compute the registration commitment.
///
/// `C = Poseidon(domain("zkapi.v2.reg"), s, 0)`
pub fn compute_registration_commitment(secret: &Felt252) -> Felt252 {
    crate::v2::registration_commitment(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_leaf_deterministic() {
        let commitment = Felt252::from_u64(12345);
        let l1 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        let l2 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        assert_eq!(l1, l2);
    }

    #[test]
    fn test_note_leaf_different_ids() {
        let commitment = Felt252::from_u64(12345);
        let l1 = compute_note_leaf(0, &commitment, 1000, 1700000000);
        let l2 = compute_note_leaf(1, &commitment, 1000, 1700000000);
        assert_ne!(l1, l2);
    }

    #[test]
    fn test_note_leaf_binds_every_field() {
        let commitment = Felt252::from_u64(12345);
        let leaf = compute_note_leaf(3, &commitment, 1000, 1700000000);
        assert_ne!(leaf, compute_note_leaf(3, &commitment, 1001, 1700000000));
        assert_ne!(leaf, compute_note_leaf(3, &commitment, 1000, 1700000001));
        assert_ne!(
            leaf,
            compute_note_leaf(3, &Felt252::from_u64(12346), 1000, 1700000000)
        );
        assert_eq!(
            leaf,
            crate::v2::note_leaf_from_fields(
                &commitment,
                &compute_note_fields(3, 1000, 1700000000)
            )
        );
    }

    #[test]
    fn test_registration_commitment() {
        let secret = Felt252::from_u64(42);
        let c1 = compute_registration_commitment(&secret);
        let c2 = compute_registration_commitment(&secret);
        assert_eq!(c1, c2);
        assert!(!c1.is_zero());
    }
}
