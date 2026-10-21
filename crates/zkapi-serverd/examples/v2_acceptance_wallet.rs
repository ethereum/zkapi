//! In-memory wallet driver for scripts/v2-acceptance.mjs, circuit
//! `zkapi-v2-concession-v1` (vault revision 3).
//!
//! Each stdin line is a JSON command; stdout contains only JSON replies. Wallet
//! secrets, blindings and pending journals remain in this process. This helper
//! does no networking and never reads an existing wallet or signing credential.
//! It calls the same pure wallet operations the browser SDK runs in WASM
//! (`zkapi-browser`): the successor checks S1–S6, one bound per state (C2),
//! and the three withdrawal statements (escape with a concession, mutual close,
//! ownership proof). Named snapshots deliberately retain a genuine state (the
//! deposit's genesis state or a server-signed one) for the stale escape
//! scenarios (defeated by the successor's request); the helper never
//! constructs a synthetic signed state. It knows no signing keys: the harness
//! derives per-run keys from random seeds with `zkapi signing-keys` and passes
//! them to `init`.
//!
//! `spend_refused_successor` takes a server-signed successor the wallet
//! refused (S3, S4 or S5: the drill server's born-spent, reused or random
//! anchors), installs it in a scratch copy as if the checks had been skipped,
//! and tries to spend it: the wallet core refuses the request proof, and the
//! request circuit itself is synthesized for it and must be unsatisfied (Q6a,
//! `is_genesis = (τ == 1)`), so such a successor is never spendable.
//!
//! Withdrawal plans carry the vault calldata of the server's own encoder
//! (`zkapi_serverd::watcher::withdrawal_calldata`), so the harness submits
//! what the Rust encoder produced; an ownership proof carries the
//! `POST /v2/withdraw/clearance` body instead.
//!
//! Usage: `v2_acceptance_wallet SETUP_DIRECTORY` (the development setup,
//! `protocol/setup/v2-concession-dev`). The wallet serves only a local chain:
//! 31337, or 11155111 on a disposable Anvil (the harness runs the challenge
//! signer sidecar, which signs only for Sepolia's or mainnet's chain ID).

use anyhow::{bail, ensure, Context, Result};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
use base64::Engine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    path::PathBuf,
};
use zkapi_browser::{
    BrowserNoteState, BrowserWalletConfig, CompleteResponseArgs, ConfirmDepositArgs, NotePathArgs,
    PendingRequestJournal, PrepareRequestArgs, PrepareWithdrawalArgs, TreeSnapshot,
};
use zkapi_proof::compact::{
    add_blindings, random_scalar, request_circuit, rerandomize, verify_signature, RequestProver,
    RequestWitnessData, CIRCUIT_ID,
};
use zkapi_serverd::watcher::withdrawal_calldata;
use zkapi_types::wire::RequestResponseV2;
use zkapi_types::{
    canonical_payload_hash, canonical_request_context, Felt252, RequestPublicInputsV2,
};

/// A request journal moved out of the pending slot, as the SDK archives it.
struct ArchivedRequest {
    disposition: &'static str,
    journal: PendingRequestJournal,
}

struct WalletDriver {
    setup: PathBuf,
    config: Option<BrowserWalletConfig>,
    state: Option<BrowserNoteState>,
    deposit_secret: Option<Felt252>,
    journal: Option<PendingRequestJournal>,
    archive: Vec<ArchivedRequest>,
    snapshots: BTreeMap<String, BrowserNoteState>,
    request_prover: Option<RequestProver>,
    withdrawal_key: Option<Vec<u8>>,
    request_vk: Option<Vec<u8>>,
}

#[derive(Deserialize)]
struct ConfirmArgs {
    note_id: u32,
    amount: u128,
    expiry_ts: u64,
}

#[derive(Deserialize)]
struct PathArgs {
    snapshot: TreeSnapshot,
    note_id: u32,
    require_existing: bool,
}

#[derive(Deserialize)]
struct LeavesArgs {
    leaves: Vec<Felt252>,
    note_id: u32,
}

#[derive(Deserialize)]
struct VerifyArgs {
    public_inputs: RequestPublicInputsV2,
    proof: String,
}

#[derive(Deserialize)]
struct RefusedSuccessorArgs {
    response: RequestResponseV2,
    active_root: Felt252,
    merkle_siblings: Vec<Felt252>,
    request_time: u64,
}

/// The local chains this in-memory wallet serves: Anvil's default chain, or
/// a disposable Anvil running with Sepolia's chain ID (the challenge signer
/// sidecar signs only for 1 and 11155111).
const LOCAL_CHAINS: [u64; 2] = [31_337, 11_155_111];

impl WalletDriver {
    fn new(setup: PathBuf) -> Self {
        Self {
            setup,
            config: None,
            state: None,
            deposit_secret: None,
            journal: None,
            archive: Vec::new(),
            snapshots: BTreeMap::new(),
            request_prover: None,
            withdrawal_key: None,
            request_vk: None,
        }
    }

    fn config(&self) -> Result<&BrowserWalletConfig> {
        self.config.as_ref().context("initialize the wallet first")
    }

    fn current(&self) -> Result<&BrowserNoteState> {
        self.state.as_ref().context("confirm a deposit first")
    }

    fn status(&self) -> Value {
        json!({
            "state": zkapi_browser::wallet_status(self.state.as_ref(), self.journal.as_ref()),
            "withdrawal_nullifier": self.state.as_ref().map(zkapi_browser::withdrawal_nullifier),
            "successor_nullifier": self.state.as_ref().map(zkapi_browser::successor_nullifier),
            "pending_request": self.journal.is_some(),
            "archived": self.archive.iter().map(|record| json!({
                "disposition": record.disposition,
                "client_request_id": record.journal.client_request_id,
                "nullifier": record.journal.nullifier,
                "created_at_ms": record.journal.created_at_ms,
                "solvency_bound": record.journal.prepared_request.public_inputs.solvency_bound,
            })).collect::<Vec<_>>(),
        })
    }

    /// The pending journal moves to the archive as `disposition`; the state
    /// stays (its bound keeps C2 for any later request proof at it).
    fn archive_journal(&mut self, disposition: &'static str) -> Result<PendingRequestJournal> {
        let journal = self.journal.take().context("no pending request")?;
        self.archive.push(ArchivedRequest {
            disposition,
            journal: journal.clone(),
        });
        Ok(journal)
    }

    /// The state an exit proves from: a named snapshot (the stale escape
    /// scenario only) or the current state, which must have no pending
    /// request (archive one with `abandon_request` first).
    fn exit_state(&self, command: &Value, mode: &str) -> Result<&BrowserNoteState> {
        match command.get("snapshot") {
            Some(value) => {
                ensure!(
                    mode == "escape",
                    "snapshots are only for the stale escape scenario"
                );
                let name = value.as_str().context("snapshot must be a name")?;
                let snapshot = self.snapshots.get(name).context("unknown snapshot")?;
                ensure!(
                    self.current()?.current_anchor != snapshot.current_anchor,
                    "snapshot must have been consumed by a later verified settlement"
                );
                Ok(snapshot)
            }
            None => {
                ensure!(
                    self.journal.is_none(),
                    "a request is pending at this state: settle it, or archive it with abandon_request before an exit"
                );
                self.current()
            }
        }
    }

    /// A server-signed successor this wallet refused (archived
    /// `invalid_successor`), installed in a scratch copy as if S3–S5 had
    /// been skipped, and then spent: the wallet core's request proof and the
    /// request circuit itself must both refuse. The wallet's own state does
    /// not change.
    fn spend_refused_successor(&mut self, args: RefusedSuccessorArgs) -> Result<Value> {
        let config = self.config()?.clone();
        let state = self.current()?.clone();
        let response = args.response;
        let journal = self
            .archive
            .iter()
            .rev()
            .find(|record| {
                record.disposition == "invalid_successor"
                    && record.journal.client_request_id == response.client_request_id
            })
            .map(|record| record.journal.clone())
            .context("the wallet refused no successor for this request")?;
        ensure!(
            journal.nullifier == zkapi_browser::withdrawal_nullifier(&state),
            "the refused successor is not of the current state"
        );
        // S6: the successor really is the server's signed state.
        let message = zkapi_core::v2::state_message(
            state.protocol_version,
            state.chain_id,
            &state.contract_address,
            &response.next_commitment.x,
            &response.next_commitment.y,
            &response.next_anchor,
        );
        let server_signed = verify_signature(
            &config.state_signing_key,
            &message,
            &response.next_state_signature,
        )?;
        let blinding = Felt252::from_hex(&state.balance_blinding).map_err(anyhow::Error::msg)?;
        let next_blinding = add_blindings(
            &add_blindings(&blinding, &journal.user_rerandomization),
            &response.blind_delta_srv,
        );
        let mut forced = state.clone();
        forced.prev_anchor = Some(state.current_anchor);
        forced.current_balance = state
            .current_balance
            .checked_sub(response.charge_applied)
            .context("the refused successor charges more than the balance")?;
        forced.balance_blinding = next_blinding.to_hex();
        forced.current_commitment_x = response.next_commitment.x;
        forced.current_commitment_y = response.next_commitment.y;
        forced.current_anchor = response.next_anchor;
        forced.is_genesis = false;
        forced.state_signature = Some(response.next_state_signature);
        forced.bound_at_state = 0;
        let siblings: [Felt252; zkapi_types::MERKLE_DEPTH] = args
            .merkle_siblings
            .clone()
            .try_into()
            .map_err(|_| anyhow::anyhow!("expected 32 Merkle siblings"))?;
        let client_request_id = format!("refused-successor-{}", uuid_like(&response.next_anchor));
        let payload = "{}".to_string();
        if self.request_prover.is_none() {
            self.request_prover = Some(RequestProver::load(&self.setup)?);
        }
        // The wallet core refuses to prove a request from it.
        let wallet_refusal = match zkapi_browser::prepare_request_with_prover(
            &config,
            &forced,
            PrepareRequestArgs {
                payload: payload.clone(),
                active_root: args.active_root,
                merkle_siblings: args.merkle_siblings,
                client_request_id: client_request_id.clone(),
                request_time: args.request_time,
                created_at_ms: args.request_time.saturating_mul(1000),
            },
            self.request_prover
                .as_ref()
                .context("missing request prover")?,
        ) {
            Ok(_) => bail!("the wallet core proved a request from a refused successor"),
            Err(error) => format!("{error:#}"),
        };
        // The request circuit, synthesized for exactly this state.
        let nullifier =
            zkapi_core::v2::nullifier(&forced.secret_s, forced.note_id, &forced.current_anchor);
        let request_context = canonical_request_context(
            &client_request_id,
            &canonical_payload_hash(payload.as_bytes()),
        );
        let rerandomization = random_scalar();
        let anonymous = rerandomize(&response.next_commitment, &rerandomization)?;
        let public = RequestPublicInputsV2 {
            protocol_version: forced.protocol_version,
            chain_id: forced.chain_id,
            contract_address: forced.contract_address,
            active_root: args.active_root,
            state_signing_key_x: config.state_signing_key.x,
            state_signing_key_y: config.state_signing_key.y,
            request_time: args.request_time,
            solvency_bound: config.request_charge_cap,
            request_nullifier: nullifier,
            authorization_tag: zkapi_core::v2::authorization_tag(&nullifier, &request_context),
            anonymous_commitment_x: anonymous.x,
            anonymous_commitment_y: anonymous.y,
        };
        let witness = RequestWitnessData {
            secret: forced.secret_s,
            request_context,
            note_id: forced.note_id,
            deposit_amount: forced.deposit_amount,
            expiry: forced.expiry_ts,
            merkle_siblings: siblings,
            current_balance: forced.current_balance,
            current_blinding: next_blinding,
            rerandomization,
            current_anchor: forced.current_anchor,
            prev_anchor: forced.prev_anchor,
            state_signature: forced.state_signature,
        };
        let circuit = request_circuit(&public, &witness)?;
        let cs = ConstraintSystem::<ark_bn254::Fr>::new_ref();
        circuit
            .generate_constraints(cs.clone())
            .map_err(|error| anyhow::anyhow!("request circuit synthesis failed: {error}"))?;
        let circuit_satisfied = cs
            .is_satisfied()
            .map_err(|error| anyhow::anyhow!("request circuit check failed: {error}"))?;
        Ok(json!({
            "server_signed": server_signed,
            "next_anchor": response.next_anchor,
            "derived_anchor": zkapi_core::v2::next_anchor(&journal.nullifier),
            "charge_applied": response.charge_applied.to_string(),
            "forced_nullifier": nullifier,
            "genesis_nullifier": zkapi_core::v2::nullifier(
                &forced.secret_s,
                forced.note_id,
                &zkapi_core::v2::GENESIS_ANCHOR,
            ),
            "wallet_refusal": wallet_refusal,
            "circuit_satisfied": circuit_satisfied,
        }))
    }

    fn handle(&mut self, command: &Value) -> Result<Value> {
        match command["command"]
            .as_str()
            .context("command must be a string")?
        {
            "circuit" => Ok(json!({
                "circuit_id": CIRCUIT_ID,
                "setup_id": zkapi_browser::bundle_setup_id(),
            })),
            "init" => {
                ensure!(self.config.is_none(), "wallet is already initialized");
                let config: BrowserWalletConfig =
                    serde_json::from_value(command["config"].clone())?;
                ensure!(
                    config.protocol_version == 2,
                    "only protocol v2 is supported"
                );
                ensure!(
                    LOCAL_CHAINS.contains(&config.chain_id),
                    "acceptance wallet requires a local Anvil chain (31337, or 11155111 on Anvil)"
                );
                ensure!(
                    !config.contract_address.is_zero(),
                    "vault address is required"
                );
                self.config = Some(config);
                Ok(self.status())
            }
            "deposit_params" => {
                self.config()?;
                ensure!(self.state.is_none(), "wallet already has a note");
                ensure!(self.deposit_secret.is_none(), "deposit is already prepared");
                let params = zkapi_browser::generate_deposit_params();
                self.deposit_secret = Some(params.secret);
                Ok(json!({"registration_commitment": params.registration_commitment}))
            }
            "confirm_deposit" => {
                ensure!(self.state.is_none(), "wallet already has a note");
                let args: ConfirmArgs = serde_json::from_value(command["args"].clone())?;
                let state = zkapi_browser::confirm_deposit(
                    self.config()?,
                    ConfirmDepositArgs {
                        secret: self.deposit_secret.context("prepare a deposit first")?,
                        note_id: args.note_id,
                        amount: args.amount,
                        expiry_ts: args.expiry_ts,
                    },
                )?;
                self.state = Some(state);
                self.deposit_secret = None;
                Ok(self.status())
            }
            "prepare_request" => {
                ensure!(self.journal.is_none(), "a request is already pending");
                let args: PrepareRequestArgs = serde_json::from_value(command["args"].clone())?;
                if self.request_prover.is_none() {
                    self.request_prover = Some(RequestProver::load(&self.setup)?);
                }
                let prepared = zkapi_browser::prepare_request_with_prover(
                    self.config()?,
                    self.current()?,
                    args,
                    self.request_prover
                        .as_ref()
                        .context("missing request prover")?,
                )?;
                // The state records the request's bound (C2) together with
                // the journal, before the request leaves (§6.2).
                self.state = Some(prepared.state);
                self.journal = Some(prepared.journal);
                Ok(json!({
                    "request": prepared.request,
                    "bound_at_state": self.current()?.bound_at_state,
                }))
            }
            "complete_response" => {
                let response: RequestResponseV2 =
                    serde_json::from_value(command["response"].clone())?;
                let result = zkapi_browser::complete_response(
                    self.config()?,
                    CompleteResponseArgs {
                        state: self.current()?.clone(),
                        journal: self.journal.clone().context("no pending request")?,
                        response,
                    },
                );
                match result {
                    Ok(next) => {
                        self.state = Some(next);
                        self.archive_journal("installed")?;
                        Ok(self.status())
                    }
                    // S3, S4 or S5 failed on a correctly signed successor:
                    // archived and treated like a withheld one (§6.1).
                    Err(error)
                        if error
                            .to_string()
                            .starts_with(zkapi_browser::codes::INVALID_SUCCESSOR) =>
                    {
                        self.archive_journal("invalid_successor")?;
                        Err(error)
                    }
                    // S1, S2 or S6: nothing changes.
                    Err(error) => Err(error),
                }
            }
            "abandon_request" => {
                // A released request whose successor never arrives (withheld):
                // archived so the state can escape (E3/E4).
                let journal = self.archive_journal("abandoned_for_escape")?;
                Ok(json!({
                    "client_request_id": journal.client_request_id,
                    "nullifier": journal.nullifier,
                    "created_at_ms": journal.created_at_ms,
                    "bound_at_state": self.current()?.bound_at_state,
                }))
            }
            "check_unrecoverable_response" => {
                // E3 lost ε: a finalized response at this state passing S1,
                // S2, S4 and S6 whose journal is gone.
                let response: RequestResponseV2 =
                    serde_json::from_value(command["response"].clone())?;
                Ok(serde_json::to_value(
                    zkapi_browser::check_unrecoverable_response(
                        self.config()?,
                        self.current()?,
                        &response,
                    )?,
                )?)
            }
            "snapshot" => {
                ensure!(
                    self.journal.is_none(),
                    "settle the pending request before snapshotting"
                );
                let name = command["name"]
                    .as_str()
                    .context("snapshot name is required")?;
                ensure!(!name.is_empty(), "snapshot name must not be empty");
                ensure!(
                    !self.snapshots.contains_key(name),
                    "snapshot already exists"
                );
                let state = self.current()?.clone();
                // Only states this wallet installed: the deposit's genesis
                // state, or one whose server signature it verified.
                ensure!(
                    state.is_genesis || state.state_signature.is_some(),
                    "a stale-state snapshot must be a genuine deposit or verified settlement"
                );
                let reply = json!({
                    "name": name,
                    "withdrawal_nullifier": zkapi_browser::withdrawal_nullifier(&state),
                    "successor_nullifier": zkapi_browser::successor_nullifier(&state),
                });
                self.snapshots.insert(name.to_string(), state);
                Ok(reply)
            }
            "prepare_withdrawal" => {
                let args: PrepareWithdrawalArgs = serde_json::from_value(command["args"].clone())?;
                let state = self.exit_state(command, &args.mode)?.clone();
                if self.withdrawal_key.is_none() {
                    self.withdrawal_key = Some(std::fs::read(self.setup.join("withdrawal.pk"))?);
                }
                let plan = zkapi_browser::prepare_withdrawal(
                    self.config()?,
                    &state,
                    args,
                    self.withdrawal_key
                        .as_deref()
                        .context("missing withdrawal key")?,
                )?;
                let proof = base64::engine::general_purpose::STANDARD.decode(&plan.proof.proof)?;
                let inputs_abi = format!(
                    "0x{}",
                    plan.public_inputs
                        .to_field_elements()
                        .iter()
                        .map(|value| hex::encode(value.as_bytes()))
                        .collect::<String>()
                );
                let mut result = serde_json::to_value(&plan)?;
                result["inputs_abi"] = json!(inputs_abi);
                result["proof_hex"] = json!(format!("0x{}", hex::encode(&proof)));
                result["state_balance"] = json!(state.current_balance.to_string());
                result["bound_at_state"] = json!(state.bound_at_state.to_string());
                if plan.public_inputs.kind == 2 {
                    // Never valid on chain: the clearance request body.
                    result["clearance_request"] = json!({
                        "withdrawal_nullifier": plan.public_inputs.withdrawal_nullifier,
                        "ownership_proof": {
                            "public_inputs": plan.public_inputs,
                            "proof": plan.proof,
                        },
                    });
                } else {
                    let calldata = withdrawal_calldata(&plan.public_inputs, &proof)
                        .map_err(|error| anyhow::anyhow!(error))?;
                    result["calldata"] = json!(format!("0x{}", hex::encode(calldata)));
                }
                Ok(result)
            }
            "note_leaf" => {
                // The note's leaf, for a path rebuilt from leaves (§6.6).
                let state = self.current()?;
                Ok(json!({
                    "note_id": state.note_id,
                    "leaf": zkapi_core::v2::note_leaf(
                        state.note_id,
                        &zkapi_core::v2::registration_commitment(&state.secret_s),
                        state.deposit_amount,
                        state.expiry_ts,
                    ),
                }))
            }
            "note_path_matches" => {
                // Whether a saved (deposit-time) path still proves the note:
                // the vault accepts any root it ever held (Amendment A1).
                let args: NotePathArgs = serde_json::from_value(command["args"].clone())?;
                Ok(json!({
                    "matches": zkapi_browser::note_path_matches(self.current()?, args)?,
                }))
            }
            "tree_path" => {
                let args: PathArgs = serde_json::from_value(command["args"].clone())?;
                Ok(serde_json::to_value(zkapi_browser::tree_path(
                    args.snapshot,
                    args.note_id,
                    args.require_existing,
                )?)?)
            }
            "tree_path_from_leaves" => {
                // The §6.6 rebuild's last step, from leaves the harness read.
                let args: LeavesArgs = serde_json::from_value(command["args"].clone())?;
                Ok(serde_json::to_value(zkapi_browser::tree_path_from_leaves(
                    args.leaves,
                    args.note_id,
                )?)?)
            }
            "verify_request" => {
                // The stale-device pre-check (E4.2): does the operator's
                // evidence verify under the setup's request key?
                let args: VerifyArgs = serde_json::from_value(command["args"].clone())?;
                if self.request_vk.is_none() {
                    self.request_vk = Some(std::fs::read(self.setup.join("request.vk"))?);
                }
                Ok(json!({
                    "valid": zkapi_browser::verify_request(
                        &args.public_inputs,
                        &args.proof,
                        self.request_vk.as_deref().context("missing request key")?,
                    )?,
                }))
            }
            "spend_refused_successor" => {
                let args: RefusedSuccessorArgs = serde_json::from_value(command["args"].clone())?;
                self.spend_refused_successor(args)
            }
            "status" => Ok(self.status()),
            _ => bail!("unsupported command"),
        }
    }
}

/// A request id for the scratch request of `spend_refused_successor`.
fn uuid_like(anchor: &Felt252) -> String {
    hex::encode(&anchor.as_bytes()[24..])
}

fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let setup = PathBuf::from(
        args.next()
            .context("usage: v2_acceptance_wallet SETUP_DIRECTORY")?,
    );
    ensure!(
        args.next().is_none(),
        "usage: v2_acceptance_wallet SETUP_DIRECTORY"
    );
    let mut driver = WalletDriver::new(setup);
    let stdin = io::stdin();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    for line in stdin.lock().lines() {
        let line = line?;
        let parsed = serde_json::from_str::<Value>(&line);
        let (id, result) = match parsed {
            Ok(command) => (
                command.get("id").cloned().unwrap_or(Value::Null),
                driver.handle(&command),
            ),
            Err(error) => (Value::Null, Err(error.into())),
        };
        let reply = match result {
            Ok(result) => json!({"id": id, "ok": true, "result": result}),
            Err(error) => json!({"id": id, "ok": false, "error": format!("{error:#}")}),
        };
        serde_json::to_writer(&mut stdout, &reply)?;
        writeln!(stdout)?;
        stdout.flush()?;
    }
    Ok(())
}
