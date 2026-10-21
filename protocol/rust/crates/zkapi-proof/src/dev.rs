//! Development fixtures (feature `dev-fixtures`, which this crate's own tests
//! and examples always enable; it does not change which keys load): a
//! deployment signed with the published development keys, notes, and the
//! honest state chain
//!
//! ```text
//! S_0 (τ = 1, B = D) --request at N_0--> S_1 (τ_1 = succ(N_0), B - Δ_0) --request at N_1--> ...
//! ```
//!
//! The fixture generators and the tests of later packages build statements
//! with these helpers. The keys and secrets are public: never use them outside
//! tests, the drill vault and fixtures.

use anyhow::{ensure, Result};
use zkapi_core::v2 as core;
use zkapi_core::MerkleTree;
use zkapi_types::wire::CurvePointWire;
use zkapi_types::{
    Felt252, RequestPublicInputsV2, SchnorrSignature, WithdrawalKind, WithdrawalPublicInputsV2C,
};

use crate::compact::{
    add_blindings, balance_commitment, rerandomize, server_update, withdrawal_public_inputs,
    CompactSigner, RequestWitnessData, WithdrawalStatementParams, WithdrawalWitnessData,
    DEVELOPMENT_SIGNING_SEEDS,
};

/// A deployment (chain, vault and keys) signed with the development keys.
#[derive(Clone)]
pub struct DevDeployment {
    pub protocol_version: u16,
    pub chain_id: u64,
    pub contract_address: Felt252,
    pub state_signer: CompactSigner,
    pub clearance_signer: CompactSigner,
}

impl DevDeployment {
    /// Protocol version 2 with the development state key (seed 1) and
    /// clearance key (seed 2).
    pub fn new(chain_id: u64, contract_address: Felt252) -> Self {
        Self {
            protocol_version: zkapi_types::PROTOCOL_VERSION,
            chain_id,
            contract_address,
            state_signer: CompactSigner::from_seed(&Felt252::from_u64(
                DEVELOPMENT_SIGNING_SEEDS[0],
            )),
            clearance_signer: CompactSigner::from_seed(&Felt252::from_u64(
                DEVELOPMENT_SIGNING_SEEDS[1],
            )),
        }
    }

    pub fn state_key(&self) -> CurvePointWire {
        self.state_signer.public_key()
    }

    pub fn clearance_key(&self) -> CurvePointWire {
        self.clearance_signer.public_key()
    }

    /// The operator's state signature over `M_state(commitment, anchor)`.
    pub fn sign_state(&self, commitment: &CurvePointWire, anchor: &Felt252) -> SchnorrSignature {
        self.state_signer.sign(&core::state_message(
            self.protocol_version,
            self.chain_id,
            &self.contract_address,
            &commitment.x,
            &commitment.y,
            anchor,
        ))
    }

    /// The operator's clearance signature over `M_clear(withdrawal_nullifier)`.
    pub fn sign_clearance(&self, withdrawal_nullifier: &Felt252) -> SchnorrSignature {
        self.clearance_signer.sign(&core::clearance_message(
            self.protocol_version,
            self.chain_id,
            &self.contract_address,
            withdrawal_nullifier,
        ))
    }
}

/// The static part of a note.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevNote {
    pub secret: Felt252,
    pub note_id: u32,
    pub deposit_amount: u128,
    pub expiry: u64,
}

impl DevNote {
    /// `R = H(d_reg, s, 0)`, the vault's `Note.commitment`.
    pub fn registration(&self) -> Felt252 {
        core::registration_commitment(&self.secret)
    }

    /// The note's tree leaf.
    pub fn leaf(&self) -> Felt252 {
        core::note_leaf(
            self.note_id,
            &self.registration(),
            self.deposit_amount,
            self.expiry,
        )
    }

    /// The genesis state `(B = D, r, τ = 1)`.
    pub fn genesis(&self, blinding: Felt252) -> DevState {
        DevState {
            note: self.clone(),
            balance: self.deposit_amount,
            blinding,
            anchor: core::GENESIS_ANCHOR,
            prev_anchor: None,
            signature: None,
        }
    }
}

/// Parameters of one request proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevRequest {
    pub request_time: u64,
    pub solvency_bound: u128,
    pub request_context: Felt252,
    pub rerandomization: Felt252,
}

/// Parameters of one withdrawal proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevWithdrawal {
    pub kind: WithdrawalKind,
    pub destination: [u8; 20],
    pub conceded: u128,
    pub valid_until: u64,
}

/// One state of a note as its owner holds it.
#[derive(Clone, Debug)]
pub struct DevState {
    pub note: DevNote,
    pub balance: u128,
    pub blinding: Felt252,
    pub anchor: Felt252,
    /// The anchor of the predecessor state (`None` at genesis).
    pub prev_anchor: Option<Felt252>,
    pub signature: Option<SchnorrSignature>,
}

impl DevState {
    /// A state signed by `deployment` at an arbitrary anchor. Honest
    /// successors come from [`DevState::successor`]; this builds the states an
    /// operator could sign by mistake or malice (anchor 1, a reused or random
    /// anchor) for negative tests.
    pub fn signed(
        note: &DevNote,
        deployment: &DevDeployment,
        balance: u128,
        blinding: Felt252,
        anchor: Felt252,
        prev_anchor: Option<Felt252>,
    ) -> Self {
        let commitment = balance_commitment(balance, &blinding, &note.leaf());
        Self {
            note: note.clone(),
            balance,
            blinding,
            anchor,
            prev_anchor,
            signature: Some(deployment.sign_state(&commitment, &anchor)),
        }
    }

    pub fn is_genesis(&self) -> bool {
        self.anchor == core::GENESIS_ANCHOR
    }

    /// `C = B·G + r·H + L·J`.
    pub fn commitment(&self) -> CurvePointWire {
        balance_commitment(self.balance, &self.blinding, &self.note.leaf())
    }

    /// `N(τ)`.
    pub fn nullifier(&self) -> Felt252 {
        core::nullifier(&self.note.secret, self.note.note_id, &self.anchor)
    }

    /// `succ(N(τ))`, the anchor of this state's successor.
    pub fn successor_anchor(&self) -> Felt252 {
        core::next_anchor(&self.nullifier())
    }

    /// `N(succ(N(τ)))`, which an escape from this state publishes.
    pub fn successor_nullifier(&self) -> Felt252 {
        core::successor_nullifier(&self.note.secret, self.note.note_id, &self.anchor)
    }

    /// A request statement and witness from this state at `tree`'s root.
    pub fn request(
        &self,
        deployment: &DevDeployment,
        tree: &MerkleTree,
        request: &DevRequest,
    ) -> Result<(RequestPublicInputsV2, RequestWitnessData)> {
        let key = deployment.state_key();
        let anonymous = rerandomize(&self.commitment(), &request.rerandomization)?;
        let nullifier = self.nullifier();
        let public = RequestPublicInputsV2 {
            protocol_version: deployment.protocol_version,
            chain_id: deployment.chain_id,
            contract_address: deployment.contract_address,
            active_root: tree.root(),
            state_signing_key_x: key.x,
            state_signing_key_y: key.y,
            request_time: request.request_time,
            solvency_bound: request.solvency_bound,
            request_nullifier: nullifier,
            authorization_tag: core::authorization_tag(&nullifier, &request.request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let witness = RequestWitnessData {
            secret: self.note.secret,
            request_context: request.request_context,
            note_id: self.note.note_id,
            deposit_amount: self.note.deposit_amount,
            expiry: self.note.expiry,
            merkle_siblings: tree.get_siblings(self.note.note_id),
            current_balance: self.balance,
            current_blinding: self.blinding,
            rerandomization: request.rerandomization,
            current_anchor: self.anchor,
            prev_anchor: self.prev_anchor,
            state_signature: self.signature,
        };
        Ok((public, witness))
    }

    /// A withdrawal statement and witness from this state at `tree`'s root.
    /// A mutual close is signed by `deployment`'s clearance key.
    pub fn withdrawal(
        &self,
        deployment: &DevDeployment,
        tree: &MerkleTree,
        withdrawal: &DevWithdrawal,
    ) -> Result<(WithdrawalPublicInputsV2C, WithdrawalWitnessData)> {
        let witness = WithdrawalWitnessData {
            secret: self.note.secret,
            deposit_amount: self.note.deposit_amount,
            expiry: self.note.expiry,
            merkle_siblings: tree.get_siblings(self.note.note_id),
            state_balance: self.balance,
            state_blinding: self.blinding,
            current_anchor: self.anchor,
            kind: withdrawal.kind,
            conceded: withdrawal.conceded,
            valid_until: withdrawal.valid_until,
            state_signature: self.signature,
            clearance_signature: (withdrawal.kind == WithdrawalKind::MutualClose)
                .then(|| deployment.sign_clearance(&self.nullifier())),
        };
        let params = WithdrawalStatementParams {
            protocol_version: deployment.protocol_version,
            chain_id: deployment.chain_id,
            contract_address: deployment.contract_address,
            active_root: tree.root(),
            state_signing_key: deployment.state_key(),
            clearance_signing_key: deployment.clearance_key(),
            note_id: self.note.note_id,
            destination: withdrawal.destination,
        };
        let public = withdrawal_public_inputs(&params, &witness)?;
        Ok((public, witness))
    }

    /// The successor the honest operator signs after serving `request` from
    /// this state: `C' = C + ε·H − charge·G + δ·H` at anchor
    /// `next_anchor(N(τ))`, opened by the owner as `(B − charge, r + ε + δ)`.
    pub fn successor(
        &self,
        deployment: &DevDeployment,
        request: &DevRequest,
        charge: u128,
        server_blinding: &Felt252,
    ) -> Result<DevState> {
        ensure!(
            charge <= request.solvency_bound && charge <= self.balance,
            "charge exceeds the request's solvency bound or the balance"
        );
        let anonymous = rerandomize(&self.commitment(), &request.rerandomization)?;
        let next_commitment = server_update(&anonymous, charge, server_blinding)?;
        let anchor = self.successor_anchor();
        let signature = deployment.sign_state(&next_commitment, &anchor);
        let next = DevState {
            note: self.note.clone(),
            balance: self.balance - charge,
            blinding: add_blindings(
                &add_blindings(&self.blinding, &request.rerandomization),
                server_blinding,
            ),
            anchor,
            prev_anchor: Some(self.anchor),
            signature: Some(signature),
        };
        ensure!(
            next.commitment() == next_commitment,
            "successor commitment does not open"
        );
        Ok(next)
    }
}

/// A tree holding `notes` at their ids.
pub fn tree_with(notes: &[&DevNote]) -> MerkleTree {
    let mut tree = MerkleTree::new();
    for note in notes {
        tree.set_leaf(note.note_id, note.leaf());
    }
    tree
}
