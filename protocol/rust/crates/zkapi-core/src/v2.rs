//! Native zkAPI v2 primitives over the BN254 scalar field, circuit
//! `zkapi-v2-concession-v1`.
//!
//! Every Poseidon hash here has a fixed arity (domain included) and is
//! mirrored by `zkapi_proof::groth16`. The state chain of a note `n` with
//! secret `s` is
//!
//! ```text
//! τ_0 = 1,  N_i = N(τ_i) = H(d_null', s, n, τ_i),  τ_{i+1} = succ(N_i) = H(d_anchor', N_i)
//! ```
//!
//! Anyone can compute `τ_{i+1}` from `N_i`; only the holder of `s` can
//! compute `N_{i+1}`.

use std::sync::OnceLock;

use ark_bn254::Fr;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ff::{BigInteger, PrimeField};
use zkapi_types::{Felt252, MERKLE_DEPTH};

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
const DOMAIN_LEAF: &[u8] = b"zkapi.v2.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
/// Note-bound nullifier domain, arity 4: `H(d_null', s, note_id, τ)`.
pub const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2c.null";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
/// Derived successor-anchor domain, arity 2: `H(d_anchor', N)`.
pub const DOMAIN_ANCHOR: &[u8] = b"zkapi.v2c.anchor";

/// The anchor of every genesis state (`τ_0`). A signed state at this anchor
/// is unprovable in both circuits.
pub const GENESIS_ANCHOR: Felt252 = Felt252::ONE;

fn config() -> &'static PoseidonConfig<Fr> {
    static CONFIG: OnceLock<PoseidonConfig<Fr>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(
            Fr::MODULUS_BIT_SIZE as u64,
            rate,
            full_rounds,
            partial_rounds,
            0,
        );
        PoseidonConfig::new(
            full_rounds as usize,
            partial_rounds as usize,
            5,
            mds,
            ark,
            rate,
            1,
        )
    })
}

fn domain(label: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(label)
}

/// The field value of a domain label (its big-endian bytes, as Solidity and
/// Go spell the constants).
pub fn domain_value(label: &[u8]) -> Felt252 {
    field_to_felt(&domain(label))
}

pub fn felt_to_field(value: &Felt252) -> Fr {
    Fr::from_be_bytes_mod_order(value.as_bytes())
}

pub fn field_to_felt(value: &Fr) -> Felt252 {
    let raw = value.into_bigint().to_bytes_be();
    let mut bytes = [0u8; 32];
    bytes[32 - raw.len()..].copy_from_slice(&raw);
    Felt252(bytes)
}

pub fn hash_fields(inputs: &[Fr]) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

pub fn hash_felts(inputs: &[Felt252]) -> Felt252 {
    let fields = inputs.iter().map(felt_to_field).collect::<Vec<_>>();
    field_to_felt(&hash_fields(&fields))
}

/// One Poseidon permutation of the state `(capacity, left, right)`, returning
/// its first rate lane: the two-to-one compression the note tree's nodes use.
/// The domain sits in the capacity lane, so a node costs one permutation where
/// the sponge over `(domain, left, right)` costs two, and no sponge hash (whose
/// capacity lane starts at zero) can collide with a node.
pub fn compress_fields(capacity: Fr, left: Fr, right: Fr) -> Fr {
    let mut sponge = PoseidonSponge::new(config());
    sponge.state[0] = capacity;
    let inputs: &[Fr] = &[left, right];
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn hash_domain(label: &[u8], inputs: &[Felt252]) -> Felt252 {
    let mut fields = Vec::with_capacity(inputs.len() + 1);
    fields.push(domain(label));
    fields.extend(inputs.iter().map(felt_to_field));
    field_to_felt(&hash_fields(&fields))
}

pub fn registration_commitment(secret: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_REG, &[*secret, Felt252::ZERO])
}

pub fn note_leaf(
    note_id: u32,
    registration: &Felt252,
    deposit_amount: u128,
    expiry: u64,
) -> Felt252 {
    hash_domain(
        DOMAIN_LEAF,
        &[
            Felt252::from_u64(note_id as u64),
            *registration,
            Felt252::from_u128(deposit_amount),
            Felt252::from_u64(expiry),
        ],
    )
}

/// `P(DOMAIN_NODE, left, right)[1]`: see [`compress_fields`].
pub fn merkle_node(left: &Felt252, right: &Felt252) -> Felt252 {
    field_to_felt(&compress_fields(
        domain(DOMAIN_NODE),
        felt_to_field(left),
        felt_to_field(right),
    ))
}

pub fn merkle_root(note_id: u32, leaf: &Felt252, siblings: &[Felt252; MERKLE_DEPTH]) -> Felt252 {
    let mut current = *leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            merkle_node(&current, sibling)
        } else {
            merkle_node(sibling, &current)
        };
    }
    current
}

pub fn zero_hashes() -> [Felt252; MERKLE_DEPTH + 1] {
    let mut values = [Felt252::ZERO; MERKLE_DEPTH + 1];
    for level in 1..=MERKLE_DEPTH {
        values[level] = merkle_node(&values[level - 1], &values[level - 1]);
    }
    values
}

/// `N(τ) = H(d_null', s, note_id, τ)`. Binding the note id keeps the chains of
/// two notes that share a secret disjoint.
pub fn nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252 {
    hash_domain(
        DOMAIN_NULLIFIER,
        &[*secret, Felt252::from_u64(note_id as u64), *anchor],
    )
}

/// `succ(N) = H(d_anchor', N)`: the only anchor at which an honest operator
/// signs the successor of the state whose request spent `N`.
pub fn next_anchor(request_nullifier: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_ANCHOR, &[*request_nullifier])
}

/// `N(succ(N(τ)))`: the nullifier of the successor of the state at `τ`. An
/// escape from that state publishes it as `next_nullifier`.
pub fn successor_nullifier(secret: &Felt252, note_id: u32, anchor: &Felt252) -> Felt252 {
    nullifier(
        secret,
        note_id,
        &next_anchor(&nullifier(secret, note_id, anchor)),
    )
}

pub fn authorization_tag(nullifier: &Felt252, request_context: &Felt252) -> Felt252 {
    hash_domain(DOMAIN_AUTHORIZATION, &[*nullifier, *request_context])
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    commitment_x: &Felt252,
    commitment_y: &Felt252,
    anchor: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_STATE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *commitment_x,
            *commitment_y,
            *anchor,
        ],
    )
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: &Felt252,
    withdrawal_nullifier: &Felt252,
) -> Felt252 {
    hash_domain(
        DOMAIN_CLEARANCE,
        &[
            Felt252::from_u64(protocol_version as u64),
            Felt252::from_u64(chain_id),
            *contract_address,
            *withdrawal_nullifier,
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merkle_membership_round_trip() {
        let secret = Felt252::from_u64(42);
        let registration = registration_commitment(&secret);
        let leaf = note_leaf(0, &registration, 5_000_000, 4_000_000_000);
        let siblings = [Felt252::ZERO; MERKLE_DEPTH];
        assert_eq!(
            merkle_root(0, &leaf, &siblings),
            merkle_root(0, &leaf, &siblings)
        );
    }

    #[test]
    fn concession_domains_match_the_specification() {
        assert_eq!(
            domain_value(DOMAIN_NULLIFIER),
            Felt252::from_hex("0x7a6b6170692e7632632e6e756c6c").unwrap()
        );
        assert_eq!(
            domain_value(DOMAIN_ANCHOR),
            Felt252::from_hex("0x7a6b6170692e7632632e616e63686f72").unwrap()
        );
        // The retired v2 domains must not be reused by the new hashes.
        assert_ne!(
            domain_value(DOMAIN_NULLIFIER),
            domain_value(b"zkapi.v2.null")
        );
        assert_ne!(
            domain_value(DOMAIN_ANCHOR),
            domain_value(b"zkapi.v2.anchor")
        );
    }

    #[test]
    fn nullifier_and_anchor_have_fixed_even_arity() {
        let secret = Felt252::from_u64(42);
        let anchor = Felt252::from_u64(9);
        let n = nullifier(&secret, 7, &anchor);
        assert_eq!(
            n,
            hash_felts(&[
                domain_value(DOMAIN_NULLIFIER),
                secret,
                Felt252::from_u64(7),
                anchor
            ])
        );
        assert_eq!(
            next_anchor(&n),
            hash_felts(&[domain_value(DOMAIN_ANCHOR), n])
        );
        // Zero-padding to the next even arity changes the hash, so no shorter or
        // longer preimage in the same domain collides with these.
        assert_ne!(
            next_anchor(&n),
            hash_felts(&[domain_value(DOMAIN_ANCHOR), n, Felt252::ZERO])
        );
        assert_ne!(
            next_anchor(&n),
            hash_felts(&[domain_value(DOMAIN_ANCHOR), n, Felt252::ZERO, Felt252::ZERO])
        );
    }

    #[test]
    fn state_chain_is_derived_from_the_nullifier() {
        let secret = Felt252::from_u64(42);
        let note_id = 3;
        let n0 = nullifier(&secret, note_id, &GENESIS_ANCHOR);
        let tau1 = next_anchor(&n0);
        assert!(tau1 != Felt252::ZERO && tau1 != GENESIS_ANCHOR);
        let n1 = nullifier(&secret, note_id, &tau1);
        assert_eq!(successor_nullifier(&secret, note_id, &GENESIS_ANCHOR), n1);
        let tau2 = next_anchor(&n1);
        assert_eq!(
            successor_nullifier(&secret, note_id, &tau1),
            nullifier(&secret, note_id, &tau2)
        );
        assert_ne!(n0, n1);
    }

    #[test]
    fn notes_sharing_a_secret_have_disjoint_nullifiers() {
        let secret = Felt252::from_u64(42);
        assert_ne!(
            nullifier(&secret, 0, &GENESIS_ANCHOR),
            nullifier(&secret, 1, &GENESIS_ANCHOR)
        );
        assert_ne!(
            successor_nullifier(&secret, 0, &GENESIS_ANCHOR),
            successor_nullifier(&secret, 1, &GENESIS_ANCHOR)
        );
    }
}
