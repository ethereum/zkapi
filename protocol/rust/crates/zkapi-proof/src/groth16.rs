//! Groth16 circuits of `zkapi-v2-concession-v2` (leaf-bound exits) over BN254.
//!
//! Both circuits use Poseidon over the BN254 scalar field, a note-bound
//! Baby-JubJub Pedersen balance commitment `C = B·G + r·H + L·J`, and a
//! Poseidon-challenged Schnorr state signature.
//!
//! * [`RequestCircuit`] (12 public inputs, constraints Q1–Q10 of the
//!   specification): the exact balance, note identity, expiry, state anchor
//!   and server signature stay private. The request context is bound through
//!   a public authorization tag while the state nullifier stays independent of
//!   the payload, so one state cannot authorize two requests. A signed state
//!   is spendable only at a derived anchor `τ = H(d_anchor', N(τ_prev))`
//!   (Q6a), and a state at `τ = 1` is spendable only as genesis (`B == D`).
//! * [`WithdrawalCircuit`] (16 public inputs, constraints W1–W14): opens a
//!   signed (or genesis) state and authorizes an escape (kind 0, which also
//!   publishes the successor nullifier and may concede an amount), a mutual
//!   close under a clearance signature (kind 1) or an ownership proof
//!   (kind 2, no destination). It proves no Merkle membership: it publishes
//!   the note's leaf `L` (input 3) and its fields
//!   `F = n·2^192 + D·2^64 + e` (input 8), binds `L = P(d_leaf', R(s), F)[1]`
//!   to the owner's secret, and the vault compares `L` with the leaf it
//!   stored at deposit.
//!
//! The note leaf is one Poseidon permutation with the domain in the capacity
//! lane, `L = P(d_leaf', H(d_reg, s, 0), F)[1]` ([`note_leaf`]), in both
//! circuits; the request circuit proves its membership in the request tree.
//!
//! The native helpers at the end of this module ([`nullifier`],
//! [`next_anchor`], [`successor_nullifier`], ...) mirror `zkapi_core::v2`.

use std::ops::Not;
use std::sync::OnceLock;

use ark_bn254::{Bn254, Fr as CircuitField};
use ark_crypto_primitives::sponge::constraints::CryptographicSpongeVar;
use ark_crypto_primitives::sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_crypto_primitives::sponge::poseidon::{
    find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
};
use ark_crypto_primitives::sponge::{CryptographicSponge, FieldBasedCryptographicSponge};
use ark_ec::twisted_edwards::TECurveConfig;
use ark_ec::{AdditiveGroup, AffineRepr, CurveConfig, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{
    constraints::EdwardsVar, EdwardsAffine, EdwardsConfig, EdwardsProjective,
    Fq as EdwardsBaseField, Fr as EdwardsScalarField,
};
use ark_ff::{BigInteger, Field, PrimeField, UniformRand};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::boolean::Boolean;
use ark_r1cs_std::cmp::CmpGadget;
use ark_r1cs_std::convert::ToBitsGadget;
use ark_r1cs_std::eq::EqGadget;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_r1cs_std::groups::CurveVar;
use ark_r1cs_std::prelude::{UInt128, UInt32, UInt64};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_relations::r1cs::{ConstraintSystem, OptimizationGoal, SynthesisMode};
use ark_snark::SNARK;
use ark_std::rand::{CryptoRng, RngCore};
use sha3::{Digest, Keccak256};

use crate::compact::Prover;

/// Public inputs of the request statement (13 instance variables with "one").
pub const REQUEST_PUBLIC_INPUTS: usize = 12;
/// Public inputs of the withdrawal statement (17 instance variables with "one").
pub const WITHDRAWAL_PUBLIC_INPUTS: usize = 16;
pub const REQUEST_MERKLE_DEPTH: usize = 32;
/// Bits of the withdrawal destination (an Ethereum address), checked in W12.
pub const DESTINATION_BITS: usize = 160;
/// `constraint_budget`: request constraints plus instance variables must stay
/// at or below this, leaving headroom in the 2^15 QAP domain.
pub const REQUEST_ROW_BUDGET: usize = 32_700;

const DOMAIN_REG: &[u8] = b"zkapi.v2.reg";
/// The note leaf's capacity-lane domain (zkapi_core::v2::DOMAIN_LEAF).
const DOMAIN_LEAF: &[u8] = b"zkapi.v2c.leaf";
const DOMAIN_NODE: &[u8] = b"zkapi.v2.node";
const DOMAIN_NULLIFIER: &[u8] = b"zkapi.v2c.null";
const DOMAIN_ANCHOR: &[u8] = b"zkapi.v2c.anchor";
const DOMAIN_AUTHORIZATION: &[u8] = b"zkapi.v2.auth";
const DOMAIN_STATE: &[u8] = b"zkapi.v2.state";
const DOMAIN_CLEARANCE: &[u8] = b"zkapi.v2.clear";
const DOMAIN_SIGNATURE: &[u8] = b"zkapi.v2.sig";

pub(crate) fn poseidon_config() -> &'static PoseidonConfig<CircuitField> {
    static CONFIG: OnceLock<PoseidonConfig<CircuitField>> = OnceLock::new();
    CONFIG.get_or_init(|| {
        let full_rounds = 8;
        let partial_rounds = 57;
        let rate = 2;
        let (ark, mds) = find_poseidon_ark_and_mds::<CircuitField>(
            CircuitField::MODULUS_BIT_SIZE as u64,
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

pub fn poseidon_hash(inputs: &[CircuitField]) -> CircuitField {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn poseidon_hash_var(
    cs: ConstraintSystemRef<CircuitField>,
    inputs: &[FpVar<CircuitField>],
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

/// One permutation of the state `(capacity, left, right)`, its first rate lane
/// (zkapi_core::v2::compress_fields). With a domain in the capacity lane it costs one
/// permutation instead of the sponge's two and cannot collide with any sponge hash, whose
/// capacity lane starts at zero.
pub fn compress(capacity: CircuitField, left: CircuitField, right: CircuitField) -> CircuitField {
    let mut sponge = PoseidonSponge::new(poseidon_config());
    sponge.state[0] = capacity;
    let inputs: &[CircuitField] = &[left, right];
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

/// The note tree's node hash: [`compress`] with `DOMAIN_NODE`.
pub fn merkle_node(left: CircuitField, right: CircuitField) -> CircuitField {
    compress(domain(DOMAIN_NODE), left, right)
}

/// [`compress`] in the circuit, with the capacity domain `label`: one permutation (240
/// constraints).
fn compress_var(
    cs: ConstraintSystemRef<CircuitField>,
    label: &[u8],
    left: &FpVar<CircuitField>,
    right: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, poseidon_config());
    sponge.state[0] = domain_var(label);
    let inputs: &[FpVar<CircuitField>] = &[left.clone(), right.clone()];
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn merkle_node_var(
    cs: ConstraintSystemRef<CircuitField>,
    left: &FpVar<CircuitField>,
    right: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    compress_var(cs, DOMAIN_NODE, left, right)
}

/// `F = n·2^192 + D·2^64 + e` over the bits of the range-checked integers: a linear
/// combination, no constraint. The UInt32/UInt128/UInt64 allocations constrain every bit to be
/// Boolean, so F < 2^224 < p and (n, D, e) ↦ F is injective.
fn note_fields_var(
    note_id: &UInt32<CircuitField>,
    deposit_amount: &UInt128<CircuitField>,
    expiry: &UInt64<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut bits = expiry.bits.to_vec();
    bits.extend(deposit_amount.bits.iter().cloned());
    bits.extend(note_id.bits.iter().cloned());
    Boolean::le_bits_to_fp(&bits)
}

/// The note leaf `L = P(d_leaf', H(d_reg, s, 0), fields)[1]`.
fn note_leaf_var(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    fields: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let registration = poseidon_hash_var(
        cs.clone(),
        &[domain_var(DOMAIN_REG), secret.clone(), FpVar::zero()],
    )?;
    compress_var(cs, DOMAIN_LEAF, &registration, fields)
}

fn domain(label: &[u8]) -> CircuitField {
    CircuitField::from_be_bytes_mod_order(label)
}

fn domain_var(label: &[u8]) -> FpVar<CircuitField> {
    FpVar::Constant(domain(label))
}

/// Independently derived blinding generator. Its discrete logarithm relative
/// to the standard Baby-JubJub generator is not known.
pub fn balance_blinding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.balance.blinding.generator"))
}

/// Independent third Pedersen generator for the private active-note leaf.
/// Do not derive this as a known scalar multiple of G or H: that would let
/// a client absorb a different note binding into the balance or blinding.
pub fn note_binding_generator() -> EdwardsProjective {
    static GENERATOR: OnceLock<EdwardsProjective> = OnceLock::new();
    *GENERATOR.get_or_init(|| derive_generator(b"zkapi.v2.note-binding.generator.v1"))
}

fn derive_generator(label: &[u8]) -> EdwardsProjective {
    for counter in 0u32..u32::MAX {
        let mut digest = Keccak256::new();
        digest.update(label);
        digest.update(counter.to_be_bytes());
        let x = EdwardsBaseField::from_be_bytes_mod_order(&digest.finalize());
        let x_squared = x.square();
        let numerator = EdwardsBaseField::ONE - x_squared;
        let denominator = EdwardsBaseField::ONE - (EdwardsConfig::COEFF_D * x_squared);
        let Some(denominator_inverse) = denominator.inverse() else {
            continue;
        };
        let Some(mut y) = (numerator * denominator_inverse).sqrt() else {
            continue;
        };
        if y.into_bigint().is_odd() {
            y = -y;
        }
        let point = EdwardsAffine::new_unchecked(x, y)
            .mul_bigint(EdwardsConfig::COFACTOR)
            .into_affine();
        if !point.is_zero() && point.is_in_correct_subgroup_assuming_on_curve() {
            return point.into_group();
        }
    }
    unreachable!("hash-to-curve counter exhausted")
}

/// C = balance*G + blinding*H + note_leaf*J. The full canonical field
/// representation of the leaf is multiplied by J (implicitly modulo its
/// prime subgroup order), identically to the circuit's bit decomposition.
pub fn balance_commitment(
    balance: u128,
    blinding: EdwardsScalarField,
    note_leaf: CircuitField,
) -> EdwardsProjective {
    EdwardsProjective::generator().mul_bigint(EdwardsScalarField::from(balance).into_bigint())
        + balance_blinding_generator().mul_bigint(blinding.into_bigint())
        + note_binding_generator().mul_bigint(note_leaf.into_bigint())
}

pub fn rerandomize_commitment(
    commitment: EdwardsProjective,
    rerandomization: EdwardsScalarField,
) -> EdwardsProjective {
    commitment + balance_blinding_generator().mul_bigint(rerandomization.into_bigint())
}

#[derive(Clone, Debug)]
pub struct StateSigningKey {
    secret: EdwardsScalarField,
    pub public: EdwardsAffine,
}

impl StateSigningKey {
    /// A zero secret is never remapped: it would silently become a public key.
    pub fn from_secret(secret: EdwardsScalarField) -> Self {
        assert!(
            secret != EdwardsScalarField::ZERO,
            "Schnorr signing secret must be nonzero"
        );
        let public = EdwardsProjective::generator()
            .mul_bigint(secret.into_bigint())
            .into_affine();
        Self { secret, public }
    }

    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        loop {
            let secret = EdwardsScalarField::rand(rng);
            if secret != EdwardsScalarField::ZERO {
                return Self::from_secret(secret);
            }
        }
    }

    pub fn sign(
        &self,
        message: CircuitField,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> StateSignature {
        let nonce = EdwardsScalarField::rand(rng);
        let r = EdwardsProjective::generator()
            .mul_bigint(nonce.into_bigint())
            .into_affine();
        let challenge = signature_challenge(r, message);
        let s = nonce + (challenge * self.secret);
        StateSignature { r, s }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct StateSignature {
    pub r: EdwardsAffine,
    pub s: EdwardsScalarField,
}

pub fn state_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    commitment: EdwardsAffine,
    anchor: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_STATE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        commitment.x,
        commitment.y,
        anchor,
    ])
}

pub fn clearance_message(
    protocol_version: u16,
    chain_id: u64,
    contract_address: CircuitField,
    withdrawal_nullifier: CircuitField,
) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_CLEARANCE),
        CircuitField::from(protocol_version as u64),
        CircuitField::from(chain_id),
        contract_address,
        withdrawal_nullifier,
    ])
}

fn signature_challenge(r: EdwardsAffine, message: CircuitField) -> EdwardsScalarField {
    let hash = poseidon_hash(&[domain(DOMAIN_SIGNATURE), r.x, r.y, message]);
    EdwardsScalarField::from_le_bytes_mod_order(&hash.into_bigint().to_bytes_le())
}

pub fn verify_state_signature(
    public: EdwardsAffine,
    message: CircuitField,
    signature: StateSignature,
) -> bool {
    let challenge = signature_challenge(signature.r, message);
    let lhs = EdwardsProjective::generator().mul_bigint(signature.s.into_bigint());
    let rhs = signature.r.into_group() + public.mul_bigint(challenge.into_bigint());
    lhs == rhs
}

fn scalar_bits_witness(
    cs: ConstraintSystemRef<CircuitField>,
    value: EdwardsScalarField,
) -> Result<Vec<Boolean<CircuitField>>, SynthesisError> {
    let native_bits = value.into_bigint().to_bits_le();
    (0..EdwardsScalarField::MODULUS_BIT_SIZE as usize)
        .map(|index| {
            Boolean::new_witness(cs.clone(), || {
                Ok(native_bits.get(index).copied().unwrap_or(false))
            })
        })
        .collect()
}

fn commitment_var(
    cs: ConstraintSystemRef<CircuitField>,
    balance: &UInt128<CircuitField>,
    blinding: EdwardsScalarField,
    note_leaf: &FpVar<CircuitField>,
) -> Result<EdwardsVar, SynthesisError> {
    let g = EdwardsVar::new_constant(cs.clone(), EdwardsProjective::generator())?;
    let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
    let j = EdwardsVar::new_constant(cs.clone(), note_binding_generator())?;
    let blinding_bits = scalar_bits_witness(cs, blinding)?;
    let note_bits = note_leaf.to_bits_le()?;
    Ok(g.scalar_mul_le(balance.bits.iter())?
        + h.scalar_mul_le(blinding_bits.iter())?
        + j.scalar_mul_le(note_bits.iter())?)
}

fn enforce_signature(
    cs: ConstraintSystemRef<CircuitField>,
    public_key: &EdwardsVar,
    message: &FpVar<CircuitField>,
    signature: StateSignature,
    condition: &Boolean<CircuitField>,
) -> Result<(), SynthesisError> {
    let r = EdwardsVar::new_witness(cs.clone(), || Ok(signature.r))?;
    let s_bits = scalar_bits_witness(cs.clone(), signature.s)?;
    let challenge_hash = poseidon_hash_var(
        cs.clone(),
        &[
            domain_var(DOMAIN_SIGNATURE),
            r.x.clone(),
            r.y.clone(),
            message.clone(),
        ],
    )?;
    let challenge_bits = challenge_hash.to_bits_le()?;
    let g = EdwardsVar::new_constant(cs, EdwardsProjective::generator())?;
    let lhs = g.scalar_mul_le(s_bits.iter())?;
    let rhs = r + public_key.scalar_mul_le(challenge_bits.iter())?;
    lhs.conditional_enforce_equal(&rhs, condition)
}

/// The request statement (public inputs 0–11).
#[derive(Clone, Debug)]
pub struct RequestPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub active_root: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_nullifier: CircuitField,
    pub authorization_tag: CircuitField,
    pub anonymous_commitment: EdwardsAffine,
}

impl RequestPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.active_root,
            self.state_signing_key.x,
            self.state_signing_key.y,
            CircuitField::from(self.request_time),
            CircuitField::from(self.solvency_bound),
            self.request_nullifier,
            self.authorization_tag,
            self.anonymous_commitment.x,
            self.anonymous_commitment.y,
        ]
    }
}

/// Private request witness. Genesis is `current_anchor == 1` (there is no
/// separate flag); `prev_anchor` is the anchor of the predecessor state and is
/// unconstrained at genesis (pass 0).
#[derive(Clone, Debug)]
pub struct RequestWitness {
    pub secret: CircuitField,
    pub request_context: CircuitField,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub merkle_siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
    pub current_balance: u128,
    pub current_blinding: EdwardsScalarField,
    pub rerandomization: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub prev_anchor: CircuitField,
    pub state_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct RequestCircuit {
    pub public: RequestPublic,
    pub witness: RequestWitness,
}

/// Registration `R = H(d_reg, s, 0)`, leaf `L = P(d_leaf', R, n·2^192 + D·2^64 + e)[1]`
/// and the depth-32 path over the bits of `n`, which must end at
/// `active_root`. Returns `L`.
fn enforce_note_membership(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    note_id: &UInt32<CircuitField>,
    deposit_amount: &UInt128<CircuitField>,
    expiry: &UInt64<CircuitField>,
    merkle_siblings: &[CircuitField; REQUEST_MERKLE_DEPTH],
    active_root: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let fields = note_fields_var(note_id, deposit_amount, expiry)?;
    let leaf = note_leaf_var(cs.clone(), secret, &fields)?;
    let mut current = leaf.clone();
    for (level, sibling_value) in merkle_siblings.iter().enumerate() {
        let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling_value))?;
        let bit = &note_id.bits[level];
        let left = bit.select(&sibling, &current)?;
        let right = bit.select(&current, &sibling)?;
        current = merkle_node_var(cs.clone(), &left, &right)?;
    }
    current.enforce_equal(active_root)?;
    Ok(leaf)
}

/// `H(d_null', s, n, τ)`.
fn nullifier_var(
    cs: ConstraintSystemRef<CircuitField>,
    secret: &FpVar<CircuitField>,
    note_id: &FpVar<CircuitField>,
    anchor: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    poseidon_hash_var(
        cs,
        &[
            domain_var(DOMAIN_NULLIFIER),
            secret.clone(),
            note_id.clone(),
            anchor.clone(),
        ],
    )
}

/// `H(d_anchor', N)`.
fn next_anchor_var(
    cs: ConstraintSystemRef<CircuitField>,
    nullifier: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    poseidon_hash_var(cs, &[domain_var(DOMAIN_ANCHOR), nullifier.clone()])
}

/// `M_state = H(d_state, pv, chain, contract, C.x, C.y, τ)`.
fn state_message_var(
    cs: ConstraintSystemRef<CircuitField>,
    protocol_version: &FpVar<CircuitField>,
    chain_id: &FpVar<CircuitField>,
    contract_address: &FpVar<CircuitField>,
    commitment: &EdwardsVar,
    anchor: &FpVar<CircuitField>,
) -> Result<FpVar<CircuitField>, SynthesisError> {
    poseidon_hash_var(
        cs,
        &[
            domain_var(DOMAIN_STATE),
            protocol_version.clone(),
            chain_id.clone(),
            contract_address.clone(),
            commitment.x.clone(),
            commitment.y.clone(),
            anchor.clone(),
        ],
    )
}

impl ConstraintSynthesizer<CircuitField> for RequestCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        // Public inputs 0–11, in statement order.
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let active_root = FpVar::new_input(cs.clone(), || Ok(self.public.active_root))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let request_time_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.request_time))
        })?;
        let solvency_bound_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.solvency_bound))
        })?;
        let request_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.request_nullifier))?;
        let authorization_tag = FpVar::new_input(cs.clone(), || Ok(self.public.authorization_tag))?;
        let anonymous_commitment =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.anonymous_commitment))?;

        // Q1: s != 0.
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;
        let request_context = FpVar::new_witness(cs.clone(), || Ok(self.witness.request_context))?;
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.witness.note_id))?;
        let note_id_field = note_id.to_fp()?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.current_balance))?;

        // Q2: request_time is a u64 equal to input 6, and expiry >= request_time.
        let request_time = UInt64::new_witness(cs.clone(), || Ok(self.public.request_time))?;
        request_time.to_fp()?.enforce_equal(&request_time_field)?;
        expiry.is_ge(&request_time)?.enforce_equal(&Boolean::TRUE)?;

        // Q3: solvency_bound is a u128 equal to input 7, and B >= sb.
        let solvency_bound = UInt128::new_witness(cs.clone(), || Ok(self.public.solvency_bound))?;
        solvency_bound
            .to_fp()?
            .enforce_equal(&solvency_bound_field)?;
        balance
            .is_ge(&solvency_bound)?
            .enforce_equal(&Boolean::TRUE)?;

        // Q4: D >= B.
        deposit_amount
            .is_ge(&balance)?
            .enforce_equal(&Boolean::TRUE)?;

        // Q5: registration, leaf and the path to input 3.
        let leaf = enforce_note_membership(
            cs.clone(),
            &secret,
            &note_id,
            &deposit_amount,
            &expiry,
            &self.witness.merkle_siblings,
            &active_root,
        )?;

        // Q6: genesis is exactly tau == 1, and genesis implies B == D.
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = anchor.is_eq(&FpVar::one())?;
        let is_signed = is_genesis.clone().not();
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        // Q6a: a signed state sits at the derived anchor H(d_anchor', N(tau_prev)).
        let prev_anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.prev_anchor))?;
        let prev_nullifier = nullifier_var(cs.clone(), &secret, &note_id_field, &prev_anchor)?;
        let derived_anchor = next_anchor_var(cs.clone(), &prev_nullifier)?;
        anchor.conditional_enforce_equal(&derived_anchor, &is_signed)?;

        // Q7: C = B*G + r*H + L*J, M_state(C, tau), Schnorr(PK_state) unless genesis.
        let current_commitment =
            commitment_var(cs.clone(), &balance, self.witness.current_blinding, &leaf)?;
        let state_message = state_message_var(
            cs.clone(),
            &protocol_version,
            &chain_id,
            &contract_address,
            &current_commitment,
            &anchor,
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_signed,
        )?;

        // Q8: C + eps*H equals inputs 10 and 11.
        let h = EdwardsVar::new_constant(cs.clone(), balance_blinding_generator())?;
        let rerandomization_bits = scalar_bits_witness(cs.clone(), self.witness.rerandomization)?;
        let computed_anonymous =
            current_commitment + h.scalar_mul_le(rerandomization_bits.iter())?;
        computed_anonymous.enforce_equal(&anonymous_commitment)?;

        // Q9: N(tau) = H(d_null', s, n, tau) equals input 8.
        let computed_nullifier = nullifier_var(cs.clone(), &secret, &note_id_field, &anchor)?;
        computed_nullifier.enforce_equal(&request_nullifier)?;

        // Q10: H(d_auth, input 8, request_context) equals input 9.
        let computed_authorization = poseidon_hash_var(
            cs,
            &[
                domain_var(DOMAIN_AUTHORIZATION),
                request_nullifier,
                request_context,
            ],
        )?;
        computed_authorization.enforce_equal(&authorization_tag)?;

        Ok(())
    }
}

/// The withdrawal statement (public inputs 0–15).
///
/// `note_leaf` (input 3) is the note's leaf and `note_fields` (input 8) its packed
/// `n·2^192 + D·2^64 + e`; both are raw field elements so that wrong or non-canonical values
/// can be expressed. `destination` is a field element so that out-of-range values can be
/// expressed; honest statements carry an Ethereum address (< 2^160).
/// `kind` is 0 (escape), 1 (mutual close) or 2 (ownership proof).
#[derive(Clone, Debug)]
pub struct WithdrawalPublic {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: CircuitField,
    pub note_leaf: CircuitField,
    pub state_signing_key: EdwardsAffine,
    pub clearance_signing_key: EdwardsAffine,
    pub note_fields: CircuitField,
    pub final_balance: u128,
    pub destination: CircuitField,
    pub withdrawal_nullifier: CircuitField,
    pub kind: u8,
    pub next_nullifier: CircuitField,
    pub conceded: u128,
    pub valid_until: u64,
}

impl WithdrawalPublic {
    pub fn to_field_elements(&self) -> Vec<CircuitField> {
        vec![
            CircuitField::from(self.protocol_version as u64),
            CircuitField::from(self.chain_id),
            self.contract_address,
            self.note_leaf,
            self.state_signing_key.x,
            self.state_signing_key.y,
            self.clearance_signing_key.x,
            self.clearance_signing_key.y,
            self.note_fields,
            CircuitField::from(self.final_balance),
            self.destination,
            self.withdrawal_nullifier,
            CircuitField::from(self.kind as u64),
            self.next_nullifier,
            CircuitField::from(self.conceded),
            CircuitField::from(self.valid_until),
        ]
    }
}

/// Private withdrawal witness. There is no `prev_anchor`: exits never need
/// the predecessor state, and no Merkle path: the leaf is public. `note_id`,
/// `deposit_amount` and `expiry` must pack to the statement's `note_fields`.
/// The destination bits and the kind bits `k1`, `k2` are derived from the
/// public inputs during synthesis.
#[derive(Clone, Debug)]
pub struct WithdrawalWitness {
    pub secret: CircuitField,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
    pub state_balance: u128,
    pub state_blinding: EdwardsScalarField,
    pub current_anchor: CircuitField,
    pub state_signature: StateSignature,
    pub clearance_signature: StateSignature,
}

#[derive(Clone, Debug)]
pub struct WithdrawalCircuit {
    pub public: WithdrawalPublic,
    pub witness: WithdrawalWitness,
}

impl ConstraintSynthesizer<CircuitField> for WithdrawalCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        // Public inputs 0–15, in statement order.
        let protocol_version = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.protocol_version as u64))
        })?;
        let chain_id =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.chain_id)))?;
        let contract_address = FpVar::new_input(cs.clone(), || Ok(self.public.contract_address))?;
        let note_leaf = FpVar::new_input(cs.clone(), || Ok(self.public.note_leaf))?;
        let state_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.state_signing_key))?;
        let clearance_signing_key =
            EdwardsVar::new_input(cs.clone(), || Ok(self.public.clearance_signing_key))?;
        let note_fields = FpVar::new_input(cs.clone(), || Ok(self.public.note_fields))?;
        let final_balance_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.final_balance))
        })?;
        let destination = FpVar::new_input(cs.clone(), || Ok(self.public.destination))?;
        let withdrawal_nullifier =
            FpVar::new_input(cs.clone(), || Ok(self.public.withdrawal_nullifier))?;
        let kind = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.kind as u64))
        })?;
        let next_nullifier = FpVar::new_input(cs.clone(), || Ok(self.public.next_nullifier))?;
        let conceded_field =
            FpVar::new_input(cs.clone(), || Ok(CircuitField::from(self.public.conceded)))?;
        let valid_until_field = FpVar::new_input(cs.clone(), || {
            Ok(CircuitField::from(self.public.valid_until))
        })?;

        // W1: s != 0.
        let secret = FpVar::new_witness(cs.clone(), || Ok(self.witness.secret))?;
        secret.enforce_not_equal(&FpVar::zero())?;

        // W2: n (u32), D (u128) and e (u64) pack to input 8: n·2^192 + D·2^64 + e.
        let note_id = UInt32::new_witness(cs.clone(), || Ok(self.witness.note_id))?;
        let note_id_field = note_id.to_fp()?;
        let deposit_amount = UInt128::new_witness(cs.clone(), || Ok(self.witness.deposit_amount))?;
        let expiry = UInt64::new_witness(cs.clone(), || Ok(self.witness.expiry))?;
        note_fields_var(&note_id, &deposit_amount, &expiry)?.enforce_equal(&note_fields)?;

        // W3: f (input 9) and c (input 14) are u128, B is a u128 witness, and
        // B == f + c over the field. f + c < 2^129 cannot wrap, so c <= B and f <= B.
        let final_balance = UInt128::new_witness(cs.clone(), || Ok(self.public.final_balance))?;
        final_balance.to_fp()?.enforce_equal(&final_balance_field)?;
        let conceded = UInt128::new_witness(cs.clone(), || Ok(self.public.conceded))?;
        conceded.to_fp()?.enforce_equal(&conceded_field)?;
        let balance = UInt128::new_witness(cs.clone(), || Ok(self.witness.state_balance))?;
        balance
            .to_fp()?
            .enforce_equal(&(final_balance.to_fp()? + conceded.to_fp()?))?;

        // W4: D >= B. The expiry is a u64 with no time check.
        deposit_amount
            .is_ge(&balance)?
            .enforce_equal(&Boolean::TRUE)?;

        // W5: registration R = H(d_reg, s, 0) and the leaf P(d_leaf', R, input 8)[1] equal
        // input 3. There is no Merkle path: the vault holds the leaf it computed at deposit.
        let leaf = note_leaf_var(cs.clone(), &secret, &note_fields)?;
        leaf.enforce_equal(&note_leaf)?;

        // W6: genesis is exactly tau == 1, and genesis implies B == D.
        let anchor = FpVar::new_witness(cs.clone(), || Ok(self.witness.current_anchor))?;
        let is_genesis = anchor.is_eq(&FpVar::one())?;
        balance
            .to_fp()?
            .conditional_enforce_equal(&deposit_amount.to_fp()?, &is_genesis)?;

        // W7: C = B*G + r*H + L*J, M_state(C, tau), Schnorr(PK_state) unless genesis.
        let state_commitment =
            commitment_var(cs.clone(), &balance, self.witness.state_blinding, &leaf)?;
        let state_message = state_message_var(
            cs.clone(),
            &protocol_version,
            &chain_id,
            &contract_address,
            &state_commitment,
            &anchor,
        )?;
        enforce_signature(
            cs.clone(),
            &state_signing_key,
            &state_message,
            self.witness.state_signature,
            &is_genesis.not(),
        )?;

        // W8: N = H(d_null', s, n, tau) equals input 11.
        let computed_nullifier = nullifier_var(cs.clone(), &secret, &note_id_field, &anchor)?;
        computed_nullifier.enforce_equal(&withdrawal_nullifier)?;

        // W9: input 12 == k1 + 2*k2 with k1, k2 Boolean and k1*k2 == 0.
        let k1 = Boolean::new_witness(cs.clone(), || Ok((self.public.kind & 1) == 1))?;
        let k2 = Boolean::new_witness(cs.clone(), || Ok((self.public.kind >> 1) & 1 == 1))?;
        let k1_field = FpVar::from(k1.clone());
        let k2_field = FpVar::from(k2.clone());
        kind.enforce_equal(&(k1_field.clone() + k2_field.double()?))?;
        k1_field.mul_equals(&k2_field, &FpVar::zero())?;
        let is_close = k1;
        let is_ownership = k2_field;
        let is_escape = FpVar::one() - &k1_field - &is_ownership;

        // W10: input 13 == is_escape * N+, where N+ = H(d_null', s, n, H(d_anchor', N)).
        let successor_anchor = next_anchor_var(cs.clone(), &withdrawal_nullifier)?;
        let successor_nullifier =
            nullifier_var(cs.clone(), &secret, &note_id_field, &successor_anchor)?;
        is_escape.mul_equals(&successor_nullifier, &next_nullifier)?;

        // W11: (k1 + k2) * c == 0, so only an escape concedes.
        (k1_field + &is_ownership).mul_equals(&conceded_field, &FpVar::zero())?;

        // W12: the destination is 160 bits, and zero for an ownership proof.
        let destination_value = self.public.destination.into_bigint().to_bits_le();
        let destination_bits = (0..DESTINATION_BITS)
            .map(|index| {
                Boolean::new_witness(cs.clone(), || {
                    Ok(destination_value.get(index).copied().unwrap_or(false))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Boolean::le_bits_to_fp(&destination_bits)?.enforce_equal(&destination)?;
        is_ownership.mul_equals(&destination, &FpVar::zero())?;

        // W13: M_clear = H(d_clear, pv, chain, contract, N); Schnorr(PK_clear) iff k1.
        let clear_message = poseidon_hash_var(
            cs.clone(),
            &[
                domain_var(DOMAIN_CLEARANCE),
                protocol_version,
                chain_id,
                contract_address,
                withdrawal_nullifier,
            ],
        )?;
        enforce_signature(
            cs.clone(),
            &clearance_signing_key,
            &clear_message,
            self.witness.clearance_signature,
            &is_close,
        )?;

        // W14: valid_until is a u64 equal to input 15 (the time check is the
        // vault's and the server's).
        let valid_until = UInt64::new_witness(cs, || Ok(self.public.valid_until))?;
        valid_until.to_fp()?.enforce_equal(&valid_until_field)?;
        Ok(())
    }
}

/// Native `N(τ) = H(d_null', s, note_id, τ)`.
pub fn nullifier(secret: CircuitField, note_id: u32, anchor: CircuitField) -> CircuitField {
    poseidon_hash(&[
        domain(DOMAIN_NULLIFIER),
        secret,
        CircuitField::from(note_id),
        anchor,
    ])
}

/// Native `succ(N) = H(d_anchor', N)`.
pub fn next_anchor(nullifier: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_ANCHOR), nullifier])
}

/// Native `N(succ(N(τ)))`.
pub fn successor_nullifier(
    secret: CircuitField,
    note_id: u32,
    anchor: CircuitField,
) -> CircuitField {
    nullifier(
        secret,
        note_id,
        next_anchor(nullifier(secret, note_id, anchor)),
    )
}

pub fn authorization_tag(nullifier: CircuitField, request_context: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_AUTHORIZATION), nullifier, request_context])
}

pub fn registration_commitment(secret: CircuitField) -> CircuitField {
    poseidon_hash(&[domain(DOMAIN_REG), secret, CircuitField::ZERO])
}

/// Native `F = n·2^192 + D·2^64 + e` (zkapi_core::v2::note_fields).
pub fn note_fields(note_id: u32, deposit_amount: u128, expiry: u64) -> CircuitField {
    let two = CircuitField::from(2u64);
    CircuitField::from(note_id) * two.pow([192u64])
        + CircuitField::from(deposit_amount) * two.pow([64u64])
        + CircuitField::from(expiry)
}

/// Native `L = P(d_leaf', R, F)[1]` (zkapi_core::v2::note_leaf).
pub fn note_leaf(
    note_id: u32,
    registration: CircuitField,
    deposit_amount: u128,
    expiry: u64,
) -> CircuitField {
    compress(
        domain(DOMAIN_LEAF),
        registration,
        note_fields(note_id, deposit_amount, expiry),
    )
}

pub fn merkle_root(
    note_id: u32,
    leaf: CircuitField,
    siblings: &[CircuitField; REQUEST_MERKLE_DEPTH],
) -> CircuitField {
    let mut current = leaf;
    for (level, sibling) in siblings.iter().enumerate() {
        current = if ((note_id >> level) & 1) == 0 {
            merkle_node(current, *sibling)
        } else {
            merkle_node(*sibling, current)
        };
    }
    current
}

/// Synthesize `circuit` exactly as the Groth16 generator and prover do:
/// `OptimizationGoal::Constraints`, then `finalize()` (which inlines every
/// linear combination). Setup, proving and R1CS export therefore all see the
/// same matrices. In [`SynthesisMode::Setup`] no witness values are computed.
pub fn synthesize<C: ConstraintSynthesizer<CircuitField>>(
    circuit: C,
    mode: SynthesisMode,
) -> Result<ConstraintSystemRef<CircuitField>, SynthesisError> {
    let cs = ConstraintSystem::new_ref();
    cs.set_optimization_goal(OptimizationGoal::Constraints);
    cs.set_mode(mode);
    circuit.generate_constraints(cs.clone())?;
    cs.finalize();
    Ok(cs)
}

/// Circuit-specific setup with the shipping reduction ([`Prover`]).
pub fn request_setup(
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Prover::circuit_specific_setup(circuit, rng)
}

/// Circuit-specific setup with the shipping reduction ([`Prover`]).
pub fn withdrawal_setup(
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    Prover::circuit_specific_setup(circuit, rng)
}

pub fn prove_withdrawal(
    proving_key: &ProvingKey<Bn254>,
    circuit: WithdrawalCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Prover::prove(proving_key, circuit, rng)
}

/// Standard Groth16 verification; independent of the prover's reduction.
pub fn verify_withdrawal(
    verifying_key: &VerifyingKey<Bn254>,
    public: &WithdrawalPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    verify_field_elements(verifying_key, &public.to_field_elements(), proof)
}

pub fn prove_request(
    proving_key: &ProvingKey<Bn254>,
    circuit: RequestCircuit,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<Proof<Bn254>, SynthesisError> {
    Prover::prove(proving_key, circuit, rng)
}

/// Standard Groth16 verification; independent of the prover's reduction.
pub fn verify_request(
    verifying_key: &VerifyingKey<Bn254>,
    public: &RequestPublic,
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    verify_field_elements(verifying_key, &public.to_field_elements(), proof)
}

/// Groth16 verification over raw public inputs (without the leading "one").
pub fn verify_field_elements(
    verifying_key: &VerifyingKey<Bn254>,
    public_inputs: &[CircuitField],
    proof: &Proof<Bn254>,
) -> Result<bool, SynthesisError> {
    let prepared = prepare_verifying_key(verifying_key);
    Groth16::<Bn254>::verify_with_processed_vk(&prepared, public_inputs, proof)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_r1cs_std::R1CSVar;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    fn test_rng() -> StdRng {
        StdRng::seed_from_u64(0x7a6b_6170_6932)
    }

    struct Note {
        secret: CircuitField,
        note_id: u32,
        deposit_amount: u128,
        expiry: u64,
        siblings: [CircuitField; REQUEST_MERKLE_DEPTH],
    }

    impl Note {
        fn new() -> Self {
            Self {
                secret: CircuitField::from(42u64),
                note_id: 0,
                deposit_amount: 5_000_000,
                expiry: 4_000_000_000,
                siblings: [CircuitField::ZERO; REQUEST_MERKLE_DEPTH],
            }
        }

        fn leaf(&self) -> CircuitField {
            note_leaf(
                self.note_id,
                registration_commitment(self.secret),
                self.deposit_amount,
                self.expiry,
            )
        }

        fn root(&self) -> CircuitField {
            merkle_root(self.note_id, self.leaf(), &self.siblings)
        }
    }

    const PV: u16 = 2;
    const CHAIN: u64 = 11_155_111;

    fn contract() -> CircuitField {
        CircuitField::from(0xdead_u64)
    }

    /// A signed request at the state that follows the genesis request.
    fn fixture() -> RequestCircuit {
        let mut rng = test_rng();
        let note = Note::new();
        let leaf = note.leaf();
        let current_balance = 4_900_000;
        let current_blinding = EdwardsScalarField::rand(&mut rng);
        let rerandomization = EdwardsScalarField::rand(&mut rng);
        let current_commitment =
            balance_commitment(current_balance, current_blinding, leaf).into_affine();
        let anonymous_commitment =
            rerandomize_commitment(current_commitment.into_group(), rerandomization).into_affine();
        let prev_anchor = CircuitField::ONE;
        let current_anchor = next_anchor(nullifier(note.secret, note.note_id, prev_anchor));
        let signer = StateSigningKey::generate(&mut rng);
        let message = state_message(PV, CHAIN, contract(), current_commitment, current_anchor);
        let signature = signer.sign(message, &mut rng);
        assert!(verify_state_signature(signer.public, message, signature));
        let request_context = CircuitField::from(777u64);
        let request_nullifier = nullifier(note.secret, note.note_id, current_anchor);

        RequestCircuit {
            public: RequestPublic {
                protocol_version: PV,
                chain_id: CHAIN,
                contract_address: contract(),
                active_root: note.root(),
                state_signing_key: signer.public,
                request_time: 3_000_000_000,
                solvency_bound: 1_000_000,
                request_nullifier,
                authorization_tag: authorization_tag(request_nullifier, request_context),
                anonymous_commitment,
            },
            witness: RequestWitness {
                secret: note.secret,
                request_context,
                note_id: note.note_id,
                deposit_amount: note.deposit_amount,
                expiry: note.expiry,
                merkle_siblings: note.siblings,
                current_balance,
                current_blinding,
                rerandomization,
                current_anchor,
                prev_anchor,
                state_signature: signature,
            },
        }
    }

    /// A mutual close (kind 1) from a signed state.
    fn withdrawal_fixture() -> WithdrawalCircuit {
        let mut rng = test_rng();
        let note = Note::new();
        let leaf = note.leaf();
        let state_balance = 4_900_000;
        let state_blinding = EdwardsScalarField::rand(&mut rng);
        let commitment = balance_commitment(state_balance, state_blinding, leaf).into_affine();
        let current_anchor = next_anchor(nullifier(note.secret, note.note_id, CircuitField::ONE));
        let state_signer = StateSigningKey::generate(&mut rng);
        let state_signature = state_signer.sign(
            state_message(PV, CHAIN, contract(), commitment, current_anchor),
            &mut rng,
        );
        let clearance_signer = StateSigningKey::generate(&mut rng);
        let withdrawal_nullifier = nullifier(note.secret, note.note_id, current_anchor);
        let clearance_signature = clearance_signer.sign(
            clearance_message(PV, CHAIN, contract(), withdrawal_nullifier),
            &mut rng,
        );

        WithdrawalCircuit {
            public: WithdrawalPublic {
                protocol_version: PV,
                chain_id: CHAIN,
                contract_address: contract(),
                note_leaf: leaf,
                state_signing_key: state_signer.public,
                clearance_signing_key: clearance_signer.public,
                note_fields: note_fields(note.note_id, note.deposit_amount, note.expiry),
                final_balance: state_balance,
                destination: CircuitField::from(0xbeef_u64),
                withdrawal_nullifier,
                kind: 1,
                next_nullifier: CircuitField::ZERO,
                conceded: 0,
                valid_until: 3_000_010_800,
            },
            witness: WithdrawalWitness {
                secret: note.secret,
                note_id: note.note_id,
                deposit_amount: note.deposit_amount,
                expiry: note.expiry,
                state_balance,
                state_blinding,
                current_anchor,
                state_signature,
                clearance_signature,
            },
        }
    }

    fn satisfied(circuit: impl ConstraintSynthesizer<CircuitField>) -> bool {
        // `which_is_unsatisfied` needs the constraint traces that only the
        // matrix-constructing mode records.
        synthesize(
            circuit,
            SynthesisMode::Prove {
                construct_matrices: true,
            },
        )
        .unwrap()
        .is_satisfied()
        .unwrap()
    }

    #[test]
    fn generators_are_distinct_nonzero_subgroup_points() {
        let g = EdwardsProjective::generator();
        let h = balance_blinding_generator();
        let j = note_binding_generator();
        assert_ne!(g, h);
        assert_ne!(g, j);
        assert_ne!(h, j);
        for point in [h, j] {
            assert_ne!(point, EdwardsProjective::default());
            assert!(point.into_affine().is_on_curve());
            assert!(point
                .into_affine()
                .is_in_correct_subgroup_assuming_on_curve());
        }
    }

    #[test]
    #[should_panic(expected = "Schnorr signing secret must be nonzero")]
    fn zero_signing_secret_is_rejected() {
        StateSigningKey::from_secret(EdwardsScalarField::ZERO);
    }

    #[test]
    fn fixtures_are_satisfied_with_the_specified_shape() {
        let cs = synthesize(
            fixture(),
            SynthesisMode::Prove {
                construct_matrices: true,
            },
        )
        .unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, REQUEST_PUBLIC_INPUTS);
        let cs = synthesize(
            withdrawal_fixture(),
            SynthesisMode::Prove {
                construct_matrices: true,
            },
        )
        .unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, WITHDRAWAL_PUBLIC_INPUTS);
    }

    #[test]
    fn signed_state_cannot_move_to_another_note() {
        for (secret, note_id, amount) in
            [(42, 1, 5_000_000), (43, 0, 5_000_000), (43, 1, 6_000_000)]
        {
            let mut circuit = fixture();
            let witness = &mut circuit.witness;
            witness.secret = CircuitField::from(secret as u64);
            witness.note_id = note_id;
            witness.deposit_amount = amount;
            // The attacker recomputes everything it controls for note B; only
            // A's genuine signature (over A's commitment and anchor) is kept.
            let leaf = note_leaf(
                note_id,
                registration_commitment(witness.secret),
                amount,
                witness.expiry,
            );
            witness.current_anchor =
                next_anchor(nullifier(witness.secret, note_id, witness.prev_anchor));
            circuit.public.active_root = merkle_root(note_id, leaf, &witness.merkle_siblings);
            circuit.public.request_nullifier =
                nullifier(witness.secret, note_id, witness.current_anchor);
            circuit.public.authorization_tag =
                authorization_tag(circuit.public.request_nullifier, witness.request_context);
            circuit.public.anonymous_commitment = rerandomize_commitment(
                balance_commitment(witness.current_balance, witness.current_blinding, leaf),
                witness.rerandomization,
            )
            .into_affine();
            assert!(!satisfied(circuit));
        }
    }

    #[test]
    fn signed_withdrawal_cannot_move_to_another_note() {
        for (secret, note_id, amount) in
            [(42, 1, 5_000_000), (43, 0, 5_000_000), (43, 1, 6_000_000)]
        {
            let mut circuit = fixture_escape_from(withdrawal_fixture());
            circuit.witness.secret = CircuitField::from(secret as u64);
            circuit.witness.note_id = note_id;
            circuit.witness.deposit_amount = amount;
            let leaf = note_leaf(
                note_id,
                registration_commitment(circuit.witness.secret),
                amount,
                circuit.witness.expiry,
            );
            circuit.public.note_leaf = leaf;
            circuit.public.note_fields = note_fields(note_id, amount, circuit.witness.expiry);
            circuit.public.withdrawal_nullifier = nullifier(
                circuit.witness.secret,
                note_id,
                circuit.witness.current_anchor,
            );
            circuit.public.next_nullifier = successor_nullifier(
                circuit.witness.secret,
                note_id,
                circuit.witness.current_anchor,
            );
            assert!(!satisfied(circuit));
        }
    }

    /// Turn the close fixture into an escape (kind 0) from the same state.
    fn fixture_escape_from(mut circuit: WithdrawalCircuit) -> WithdrawalCircuit {
        circuit.public.kind = 0;
        circuit.public.next_nullifier = successor_nullifier(
            circuit.witness.secret,
            circuit.witness.note_id,
            circuit.witness.current_anchor,
        );
        circuit
    }

    #[test]
    fn escape_conversion_of_the_fixture_is_satisfied() {
        assert!(satisfied(fixture_escape_from(withdrawal_fixture())));
    }

    /// Kind 2 (ownership, no destination) is the same leaf-bound statement.
    #[test]
    fn ownership_conversion_of_the_fixture_is_satisfied() {
        let mut circuit = withdrawal_fixture();
        circuit.public.kind = 2;
        circuit.public.destination = CircuitField::ZERO;
        assert!(satisfied(circuit));
    }

    fn two_pow(bits: u64) -> CircuitField {
        CircuitField::from(2u64).pow([bits])
    }

    /// Input 3 must be the leaf of the prover's own registration and input 8.
    #[test]
    fn withdrawal_refuses_a_wrong_leaf() {
        for circuit in [
            withdrawal_fixture(),
            fixture_escape_from(withdrawal_fixture()),
        ] {
            for delta in [CircuitField::ONE, -CircuitField::ONE] {
                let mut wrong = circuit.clone();
                wrong.public.note_leaf += delta;
                assert!(!satisfied(wrong));
            }
            // Another note's leaf: another secret, and another note ID with the same secret.
            let mut other = circuit.clone();
            other.public.note_leaf = note_leaf(
                0,
                registration_commitment(CircuitField::from(43u64)),
                5_000_000,
                4_000_000_000,
            );
            assert!(!satisfied(other));
            let mut other = circuit.clone();
            other.public.note_leaf = note_leaf(
                1,
                registration_commitment(circuit.witness.secret),
                5_000_000,
                4_000_000_000,
            );
            assert!(!satisfied(other));
            // A zero (retired) leaf.
            let mut retired = circuit.clone();
            retired.public.note_leaf = CircuitField::ZERO;
            assert!(!satisfied(retired));
        }
    }

    /// Input 8 must be exactly the packing of the witness's n, D and e: off by one, with
    /// neighbouring fields swapped or shifted, or carried above 2^224, it is unsatisfiable even
    /// with input 3 recomputed over the forged fields.
    #[test]
    fn withdrawal_refuses_fields_that_are_not_the_packing() {
        let base = withdrawal_fixture();
        let packed = base.public.note_fields;
        let (n, d, e) = (
            base.witness.note_id,
            base.witness.deposit_amount,
            base.witness.expiry,
        );
        let forged = [
            packed + CircuitField::ONE,
            packed - CircuitField::ONE,
            // n and e swapped.
            note_fields(e as u32, d, n as u64),
            // One unit of D moved into e and back the other way.
            packed - two_pow(64) + CircuitField::ONE,
            packed + two_pow(64) - CircuitField::ONE,
            // The same value with a bit carried above the u32 note ID.
            packed + two_pow(224),
            packed + two_pow(253),
            // D scaled into the note ID's bits.
            CircuitField::from(d) * two_pow(192) + CircuitField::from(e),
        ];
        for fields in forged {
            let mut circuit = fixture_escape_from(base.clone());
            circuit.public.note_fields = fields;
            circuit.public.note_leaf = compress(
                domain(DOMAIN_LEAF),
                registration_commitment(circuit.witness.secret),
                fields,
            );
            assert!(!satisfied(circuit));
        }
    }

    /// The witness's n, D and e must be the ones in input 8: the nullifiers use n, and W4 and
    /// W6 use D, from the fields the leaf binds.
    #[test]
    fn withdrawal_witness_must_match_the_fields() {
        let base = fixture_escape_from(withdrawal_fixture());
        let mut n = base.clone();
        n.witness.note_id = 1;
        assert!(!satisfied(n));
        let mut d = base.clone();
        d.witness.deposit_amount += 1;
        assert!(!satisfied(d));
        let mut d = base.clone();
        d.witness.deposit_amount = 6_000_000_000;
        assert!(!satisfied(d));
        let mut e = base.clone();
        e.witness.expiry += 86_400;
        assert!(!satisfied(e));
        // A genesis state must hold exactly the D of the fields.
        let mut genesis = withdrawal_fixture();
        genesis.witness.current_anchor = CircuitField::ONE;
        genesis.witness.state_balance = 5_000_000;
        genesis.public.final_balance = 5_000_000;
        genesis.public.kind = 0;
        genesis.public.withdrawal_nullifier = nullifier(
            genesis.witness.secret,
            genesis.witness.note_id,
            CircuitField::ONE,
        );
        genesis.public.next_nullifier = successor_nullifier(
            genesis.witness.secret,
            genesis.witness.note_id,
            CircuitField::ONE,
        );
        assert!(satisfied(genesis.clone()));
        let note = Note::new();
        let mut larger = genesis;
        larger.witness.deposit_amount = 6_000_000;
        larger.witness.state_balance = 6_000_000;
        larger.public.final_balance = 6_000_000;
        larger.public.note_fields = note_fields(note.note_id, 6_000_000, note.expiry);
        larger.public.note_leaf = note_leaf(
            note.note_id,
            registration_commitment(note.secret),
            6_000_000,
            note.expiry,
        );
        // Consistent with itself, so satisfied: the vault's stored leaf is what refuses it.
        assert!(satisfied(larger.clone()));
        assert_ne!(larger.public.note_leaf, note.leaf());
    }

    /// The leaf and fields gadgets compute the native helpers.
    #[test]
    fn leaf_gadgets_equal_native_helpers() {
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let secret = CircuitField::from(42u64);
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(secret)).unwrap();
        for (n, d, e) in [
            (7u32, 5_000_000u128, 4_000_000_000u64),
            (u32::MAX, u128::MAX, u64::MAX),
            (0, 0, 0),
        ] {
            let n_var = UInt32::new_witness(cs.clone(), || Ok(n)).unwrap();
            let d_var = UInt128::new_witness(cs.clone(), || Ok(d)).unwrap();
            let e_var = UInt64::new_witness(cs.clone(), || Ok(e)).unwrap();
            let fields = note_fields_var(&n_var, &d_var, &e_var).unwrap();
            assert_eq!(fields.value().unwrap(), note_fields(n, d, e));
            let leaf = note_leaf_var(cs.clone(), &secret_var, &fields).unwrap();
            assert_eq!(
                leaf.value().unwrap(),
                note_leaf(n, registration_commitment(secret), d, e)
            );
        }
        assert!(cs.is_satisfied().unwrap());
        // The design's vector: s = 42, n = 7, D = 5,000,000, e = 4,000,000,000.
        assert_eq!(
            note_leaf(7, registration_commitment(secret), 5_000_000, 4_000_000_000)
                .into_bigint()
                .to_bytes_be(),
            hex_bytes("1698e82280376fc3506cb7ebf7278db1764d0183aea5fd4d3b475c644b61395f")
        );
    }

    fn hex_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).unwrap())
            .collect()
    }

    /// Constraint counts of circuit zkapi-v2-concession-v2 (design C, circuit_changes §3): one
    /// permutation per leaf in both circuits, no Merkle path in the withdrawal circuit.
    #[test]
    fn circuit_shapes_are_pinned() {
        let request = synthesize(fixture(), SynthesisMode::Setup).unwrap();
        let withdrawal = synthesize(withdrawal_fixture(), SynthesisMode::Setup).unwrap();
        assert_eq!(
            (
                request.num_constraints(),
                request.num_instance_variables(),
                request.num_witness_variables()
            ),
            (23_507, 13, 23_215)
        );
        assert_eq!(
            (
                withdrawal.num_constraints(),
                withdrawal.num_instance_variables(),
                withdrawal.num_witness_variables()
            ),
            (20_545, 17, 20_062)
        );
        for cs in [request, withdrawal] {
            let rows = cs.num_constraints() + cs.num_instance_variables();
            assert_eq!(rows.next_power_of_two(), 1 << 15);
        }
    }

    /// Q6a, Q9, W8 and W10 gadgets compute exactly the native helpers.
    #[test]
    fn chain_gadgets_equal_native_helpers() {
        let secret = CircuitField::from(42u64);
        let note_id = 9u32;
        let anchor = CircuitField::from(12_345u64);
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        let secret_var = FpVar::new_witness(cs.clone(), || Ok(secret)).unwrap();
        let note_var = UInt32::new_witness(cs.clone(), || Ok(note_id))
            .unwrap()
            .to_fp()
            .unwrap();
        let anchor_var = FpVar::new_witness(cs.clone(), || Ok(anchor)).unwrap();
        let n = nullifier_var(cs.clone(), &secret_var, &note_var, &anchor_var).unwrap();
        let succ = next_anchor_var(cs.clone(), &n).unwrap();
        let n_plus = nullifier_var(cs.clone(), &secret_var, &note_var, &succ).unwrap();
        assert_eq!(n.value().unwrap(), nullifier(secret, note_id, anchor));
        assert_eq!(
            succ.value().unwrap(),
            next_anchor(nullifier(secret, note_id, anchor))
        );
        assert_eq!(
            n_plus.value().unwrap(),
            successor_nullifier(secret, note_id, anchor)
        );
        assert!(cs.is_satisfied().unwrap());
    }
}
