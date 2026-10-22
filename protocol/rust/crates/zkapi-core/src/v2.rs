//! Native zkAPI v2 primitives over the BN254 scalar field, circuit
//! `zkapi-v2-concession-v2`.
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
/// Note-leaf domain, a capacity-lane domain like [`DOMAIN_NODE`]: the leaf is one permutation
/// `P(d_leaf', R, F)[1]` ([`note_leaf`]). The retired sponge domain "zkapi.v2.leaf" of circuit
/// `zkapi-v2-concession-v1` is not reused.
pub const DOMAIN_LEAF: &[u8] = b"zkapi.v2c.leaf";
/// Note-tree node domain, in the capacity lane: `P(d_node, left, right)[1]` ([`merkle_node`]).
pub const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
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

/// Bits of the note ID, deposit and expiry in [`note_fields`]: `n` at bit 192, `D` at bit 64,
/// `e` at bit 0. A packed value is below 2^224, far below the field modulus.
pub const NOTE_FIELDS_BITS: u32 = 224;

/// `F = n·2^192 + D·2^64 + e`: the note's ID (u32), deposit (u128, gwei units) and bucketed
/// expiry (u64) in one field element, public input 8 of the withdrawal statement
/// (`noteFields`). Injective over integers and, since `F < 2^224 < p`, over field elements.
pub fn note_fields(note_id: u32, deposit_amount: u128, expiry: u64) -> Felt252 {
    zkapi_types::pack_note_fields(note_id, deposit_amount, expiry)
}

/// The `(note_id, deposit_amount, expiry)` of a packed [`note_fields`] value, or `None` for a
/// value at or above 2^224 (which no note packs to; the vault refuses it with
/// InvalidNoteFields).
pub fn unpack_note_fields(fields: &Felt252) -> Option<(u32, u128, u64)> {
    let bytes = fields.as_bytes();
    if bytes[..4].iter().any(|byte| *byte != 0) {
        return None;
    }
    Some((
        u32::from_be_bytes(bytes[4..8].try_into().expect("4 bytes")),
        u128::from_be_bytes(bytes[8..24].try_into().expect("16 bytes")),
        u64::from_be_bytes(bytes[24..32].try_into().expect("8 bytes")),
    ))
}

/// The note leaf `L = P(d_leaf', R, F)[1]`: one permutation of the state
/// `(DOMAIN_LEAF, registration, note_fields(note_id, deposit_amount, expiry))`, its first rate
/// lane ([`compress_fields`], `Bn254PoseidonRuntime.compress`). It is the request tree's leaf at
/// index `note_id` and the word the vault stores per note; withdrawal proofs publish it (public
/// input 3, `noteLeaf`) with `F` (input 8).
pub fn note_leaf(
    note_id: u32,
    registration: &Felt252,
    deposit_amount: u128,
    expiry: u64,
) -> Felt252 {
    note_leaf_from_fields(registration, &note_fields(note_id, deposit_amount, expiry))
}

/// [`note_leaf`] from an already packed `fields` word.
pub fn note_leaf_from_fields(registration: &Felt252, fields: &Felt252) -> Felt252 {
    field_to_felt(&compress_fields(
        domain(DOMAIN_LEAF),
        felt_to_field(registration),
        felt_to_field(fields),
    ))
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
    use ark_ff::Field;

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

    fn hex(value: &str) -> Felt252 {
        Felt252::from_hex(value).unwrap()
    }

    /// The design's vectors (spec C.1), reproduced independently by both reviewers.
    #[test]
    fn leaf_vectors_match_the_specification() {
        assert_eq!(
            domain_value(DOMAIN_LEAF),
            hex("0x7a6b6170692e7632632e6c656166")
        );
        assert_eq!(
            field_to_felt(&compress_fields(
                domain(DOMAIN_LEAF),
                Fr::from(1u64),
                Fr::from(u64::MAX) + Fr::from(2u64)
            )),
            hex("0x00381941483a5233ff52ff1e1a0b79464c7316b7b4f609468ba5de81d2686d42")
        );
        let registration = registration_commitment(&Felt252::from_u64(42));
        assert_eq!(
            registration,
            hex("0x26538304fc53474b13823162f0b9667c1538c7360828d3a1a2e8ffa019a2f8cc")
        );
        let fields = note_fields(7, 5_000_000, 4_000_000_000);
        assert_eq!(
            fields,
            hex("0x0000000000000007000000000000000000000000004c4b4000000000ee6b2800")
        );
        assert_eq!(
            note_leaf(7, &registration, 5_000_000, 4_000_000_000),
            hex("0x1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f")
        );
        assert_eq!(
            note_leaf_from_fields(&registration, &fields),
            note_leaf(7, &registration, 5_000_000, 4_000_000_000)
        );
        // node(1, 2) is unchanged: the setup manifests' test_node.
        assert_eq!(
            merkle_node(&Felt252::from_u64(1), &Felt252::from_u64(2)),
            hex("0x178f4ab3e9e68f4c3459db1c927c9abd074ba5079d8d972e6594b07a5ab1c3b1")
        );
    }

    /// The capacity-lane domains are pairwise distinct and nonzero (every sponge starts its
    /// capacity lane at 0), and the leaf domain is no sponge label either.
    #[test]
    fn leaf_domain_is_separated_from_every_other_domain() {
        let leaf = domain_value(DOMAIN_LEAF);
        assert_ne!(leaf, Felt252::ZERO);
        assert_ne!(leaf, domain_value(DOMAIN_NODE));
        for label in [
            DOMAIN_REG,
            DOMAIN_NODE,
            DOMAIN_NULLIFIER,
            DOMAIN_AUTHORIZATION,
            DOMAIN_STATE,
            DOMAIN_CLEARANCE,
            DOMAIN_ANCHOR,
            b"zkapi.v2.leaf".as_slice(),
            b"zkapi.v2.sig".as_slice(),
        ] {
            assert_ne!(
                leaf,
                domain_value(label),
                "{}",
                String::from_utf8_lossy(label)
            );
        }
    }

    #[test]
    fn note_fields_round_trip_at_the_boundaries() {
        for (note_id, amount, expiry) in [
            (0u32, 0u128, 0u64),
            (u32::MAX, u128::MAX, u64::MAX),
            (1, 1, 1),
            (u32::MAX - 1, 9_007_199_254_740_991, 86_400),
            (7, 5_000_000, 4_000_000_000),
        ] {
            let fields = note_fields(note_id, amount, expiry);
            assert_eq!(unpack_note_fields(&fields), Some((note_id, amount, expiry)));
            assert!(fields.as_bytes()[..4].iter().all(|byte| *byte == 0));
            // The integer value: n·2^192 + D·2^64 + e.
            let expected = Fr::from(note_id) * Fr::from(2u64).pow([192u64])
                + Fr::from(amount) * Fr::from(2u64).pow([64u64])
                + Fr::from(expiry);
            assert_eq!(felt_to_field(&fields), expected);
        }
        let mut wide = note_fields(0, 0, 0);
        wide.0[3] = 1;
        assert_eq!(unpack_note_fields(&wide), None);
        assert_ne!(
            note_leaf(7, &Felt252::from_u64(1), 5, 6),
            note_leaf(8, &Felt252::from_u64(1), 5, 6)
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
