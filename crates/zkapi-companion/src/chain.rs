//! Ethereum JSON-RPC reads and vault ABI helpers for exits (design §6.4 E0,
//! E4, E5, §6.6, §6.7) and request roots. Every call has the exit-mode
//! timeout and is made to an RPC the deployment pins or the user configured,
//! never one an operator answer names.
//!
//! Vault revision 4 (leaf-bound exits): a note is one word, its leaf and
//! status (`noteRecord`), an exit carries the note's leaf and packed fields
//! instead of a root, and the request root is the computed `currentRoot()`.

use std::time::Duration;

use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_client::exit_policy::CALL_TIMEOUT_SECONDS;
use zkapi_client::tree::{collect_logs, LogFetchError};
use zkapi_types::Felt252;

use crate::error::AuthError;

pub const CURRENT_ROOT: &str = "fdab463d";
/// `noteRecord(uint32) → (uint256 leaf, uint8 status)`: the one stored word
/// of a note (vault revision 4; `notes(uint32)` is gone).
pub const NOTE_RECORD: &str = "d154f5bf";
pub const PENDING_WITHDRAWALS: &str = "a2f9f1ce";
pub const PENDING_CONCESSIONS: &str = "f8ffe6e0";
pub const CHALLENGED_NULLIFIERS: &str = "6cda756a";
/// `effectiveExpiry(uint32 noteId, bytes32 commitment, uint128 amount,
/// uint64 expiryTs)`: 0 unless the preimage reproduces the stored leaf.
pub const EFFECTIVE_EXPIRY: &str = "5a747a98";
pub const PROOF_ADAPTER: &str = "efc91e58";
pub const CONCESSION_ESCAPE_VERSION: &str = "5e00b426";
/// `LEAF_BOUND_EXIT_VERSION()`: 1 on vault revision 4; a revision-3 vault
/// has no such function and reverts.
pub const LEAF_BOUND_EXIT_VERSION: &str = "c0baafb1";
/// `minDeposit() → uint128`.
pub const MIN_DEPOSIT: &str = "41b3d185";
/// `initiateEscapeWithdrawal((uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint256,uint128,address,uint256,uint8,uint256,uint128,uint64),bytes)`.
pub const INITIATE_ESCAPE: &str = "8cd67c60";
/// `mutualClose(<the same tuple>,bytes)`.
pub const MUTUAL_CLOSE: &str = "bce12a6c";
pub const FINALIZE_ESCAPE: &str = "ff8f5585";
pub const CLAIM_ESCAPE_PAYOUT: &str = "88c10aee";

/// The withdrawal tuple, in public-input order (design §6.7): word 3 is the
/// note's leaf (`noteLeaf`), word 8 its packed fields (`noteFields`).
pub const WITHDRAWAL_INPUTS_ABI: &str = "(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint256,uint128,address,uint256,uint8,uint256,uint128,uint64)";

/// The vault's custom errors an exit may revert with, by selector.
pub const VAULT_ERRORS: [(&str, &str); 14] = [
    (
        "f2b1d50f",
        "NoteLeafMismatch: the note's secret, id, amount and expiry do not reproduce the leaf the vault stored at deposit",
    ),
    (
        "aa6aef76",
        "InvalidNoteFields: the packed note fields do not fit 224 bits",
    ),
    ("61a83aab", "NoteNotActive: the note is not active"),
    (
        "cb1a072e",
        "NotePendingWithdrawal: an escape of the note is pending",
    ),
    ("1e9a749a", "NoteExpired: the note has expired"),
    ("09bde339", "InvalidProof: the withdrawal proof does not verify"),
    ("b67a7713", "ProofExpired: the proof's valid_until has passed"),
    ("947e59c5", "ReplayedNullifier: the nullifier was already used"),
    (
        "2845df70",
        "ChallengedNullifier: a newer state of the note exists",
    ),
    ("9e87fac8", "Paused: the vault is paused"),
    ("c52e3eff", "InvalidBalance: the amounts are out of range"),
    ("ac6b05f5", "InvalidDestination: the payout address is refused"),
    ("06868d53", "WrongWithdrawalKind: the proof is of another kind"),
    (
        "9722445b",
        "InvalidDeploymentBinding: the proof is bound to another deployment",
    ),
];

/// The vault error a JSON-RPC error message carries as revert data, if any
/// (`eth_call` / `eth_estimateGas` include the 4-byte selector in `data`).
pub fn vault_error(message: &str) -> Option<&'static str> {
    let lowered = message.to_ascii_lowercase();
    VAULT_ERRORS
        .iter()
        .find(|(selector, _)| lowered.contains(&format!("0x{selector}")))
        .map(|(_, name)| *name)
}

pub fn topic(signature: &str) -> String {
    format!("0x{}", hex::encode(Keccak256::digest(signature.as_bytes())))
}

pub fn escape_concession_raised_topic() -> String {
    topic("EscapeConcessionRaised(uint32,uint256,uint128,uint128)")
}

pub fn escape_finalized_topic() -> String {
    topic("EscapeWithdrawalFinalized(uint32,uint256,uint128,address)")
}

pub fn escape_payout_deferred_topic() -> String {
    topic("EscapePayoutDeferred(uint32,address,uint128)")
}

/// `EscapeWithdrawalChallenged(uint32 indexed noteId, uint256 nullifier)`:
/// one data word since vault revision 4 (no root).
pub fn escape_challenged_topic() -> String {
    topic("EscapeWithdrawalChallenged(uint32,uint256)")
}

pub fn escape_initiated_topic() -> String {
    topic("EscapeWithdrawalInitiated(uint32,uint256,uint128,address,uint64)")
}

pub fn word_u64(value: u64) -> String {
    format!("{value:064x}")
}

pub fn word_felt(value: &Felt252) -> String {
    hex::encode(value.0)
}

pub fn word_address(address: &[u8; 20]) -> String {
    format!("{}{}", "0".repeat(24), hex::encode(address))
}

/// The ABI words of the 16-field withdrawal tuple, in order: word 3 is the
/// note's leaf and word 8 `noteFields = noteId·2^192 + D·2^64 + expiryTs`.
pub fn withdrawal_words(inputs: &zkapi_types::WithdrawalPublicInputsV2C) -> Vec<String> {
    vec![
        word_u64(inputs.protocol_version.into()),
        word_u64(inputs.chain_id),
        word_felt(&inputs.contract_address),
        word_felt(&inputs.note_leaf),
        word_felt(&inputs.state_signing_key_x),
        word_felt(&inputs.state_signing_key_y),
        word_felt(&inputs.clearance_signing_key_x),
        word_felt(&inputs.clearance_signing_key_y),
        word_felt(&inputs.note_fields()),
        format!("{:064x}", inputs.final_balance),
        word_address(&inputs.destination),
        word_felt(&inputs.withdrawal_nullifier),
        word_u64(inputs.kind.into()),
        word_felt(&inputs.next_nullifier),
        format!("{:064x}", inputs.conceded),
        word_u64(inputs.valid_until),
    ]
}

/// `selector | 16 tuple words | offset 0x220 | len 256 | 8 proof words`:
/// 836 bytes, the calldata of `initiateEscapeWithdrawal` or `mutualClose`.
pub fn withdrawal_calldata(
    selector: &str,
    inputs: &zkapi_types::WithdrawalPublicInputsV2C,
    proof: &zkapi_types::wire::Groth16ProofWire,
) -> Result<String, AuthError> {
    use base64::Engine;
    let proof = base64::engine::general_purpose::STANDARD
        .decode(&proof.proof)
        .ok()
        .filter(|bytes| bytes.len() == 256)
        .ok_or_else(|| AuthError::Wallet("the withdrawal proof is not 256 bytes".into()))?;
    let mut words = withdrawal_words(inputs);
    words.push(word_u64(17 * 32));
    words.push(word_u64(256));
    words.push(hex::encode(proof));
    Ok(format!("0x{selector}{}", words.concat()))
}

/// `finalizeEscapeWithdrawal(uint32 noteId)`.
pub fn finalize_calldata(note_id: u32) -> String {
    format!("0x{FINALIZE_ESCAPE}{}", word_u64(note_id.into()))
}

/// `claimEscapePayout(address destination)`.
pub fn claim_calldata(destination: &[u8; 20]) -> String {
    format!("0x{CLAIM_ESCAPE_PAYOUT}{}", word_address(destination))
}

/// A JSON-RPC endpoint: an HTTPS URL, or plain HTTP to a loopback node.
#[derive(Debug, Clone)]
pub struct Rpc {
    url: String,
    http: reqwest::Client,
    /// With [`Rpc::on_chain`]: the chain every reading must come from, and
    /// whether `eth_chainId` confirmed it (asked once, before any other call).
    chain: Option<(u64, std::sync::Arc<tokio::sync::OnceCell<()>>)>,
}

fn failure(message: impl Into<String>) -> AuthError {
    AuthError::Wallet(message.into())
}

/// Whether `url` may serve JSON-RPC to this wallet: HTTPS, or plain HTTP to
/// a node on this machine, with no credentials and no fragment. Every RPC
/// the companion reads (the escape's and the cooperative close's) follows
/// this one rule.
pub fn rpc_url_allowed(url: &reqwest::Url) -> bool {
    let loopback = matches!(
        url.host_str(),
        Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
    );
    (url.scheme() == "https" || (url.scheme() == "http" && loopback))
        && url.username().is_empty()
        && url.password().is_none()
        && url.fragment().is_none()
}

impl Rpc {
    pub fn new(url: &str) -> Result<Self, AuthError> {
        let parsed = reqwest::Url::parse(url).map_err(|_| failure("the RPC URL is not a URL"))?;
        if !rpc_url_allowed(&parsed) {
            return Err(failure(
                "an RPC must be HTTPS, or plain HTTP to a node on this machine",
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(CALL_TIMEOUT_SECONDS))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| failure("cannot build the RPC client"))?;
        Ok(Self {
            url: url.to_string(),
            http,
            chain: None,
        })
    }

    /// This RPC, trusted only on `chain_id`: its first call asks
    /// `eth_chainId`, and an RPC on another chain (or one that cannot say)
    /// fails every call, so each reader treats it as unavailable. An exit
    /// RPC the owner pasted for the wrong network never decides an exit.
    pub fn on_chain(mut self, chain_id: u64) -> Self {
        self.chain = Some((chain_id, std::sync::Arc::new(tokio::sync::OnceCell::new())));
        self
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    pub async fn request(&self, method: &str, params: Value) -> Result<Value, AuthError> {
        if let Some((chain_id, confirmed)) = &self.chain {
            confirmed
                .get_or_try_init(|| async {
                    let remote = quantity(&self.call_raw("eth_chainId", json!([])).await?)?;
                    if remote != *chain_id {
                        return Err(failure(format!(
                            "the RPC is on chain {remote}, not the vault's chain {chain_id}"
                        )));
                    }
                    Ok(())
                })
                .await?;
        }
        self.call_raw(method, params).await
    }

    async fn call_raw(&self, method: &str, params: Value) -> Result<Value, AuthError> {
        let response = self
            .http
            .post(&self.url)
            .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
            .send()
            .await
            .map_err(|error| failure(format!("RPC {method} failed: {error}")))?;
        if !response.status().is_success() {
            return Err(failure(format!(
                "RPC {method} answered {}",
                response.status()
            )));
        }
        let mut response = response;
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|error| failure(format!("RPC {method} failed: {error}")))?
        {
            if bytes.len() + chunk.len() > 32 << 20 {
                return Err(failure(format!("RPC {method} answer is too large")));
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|_| failure(format!("RPC {method} answer is not JSON")))?;
        if let Some(error) = value.get("error") {
            return Err(failure(format!("RPC {method} error: {error}")));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| failure(format!("RPC {method} answer has no result")))
    }

    pub async fn call(&self, to: &[u8; 20], data: &str, block: &str) -> Result<String, AuthError> {
        self.request(
            "eth_call",
            json!([{"to": format!("0x{}", hex::encode(to)), "data": data}, block]),
        )
        .await?
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| failure("eth_call result is not a string"))
    }

    /// The words of an `eth_call` result.
    pub async fn call_words(
        &self,
        to: &[u8; 20],
        data: &str,
        block: &str,
        expected: usize,
    ) -> Result<Vec<[u8; 32]>, AuthError> {
        let result = self.call(to, data, block).await?;
        let digits = result
            .strip_prefix("0x")
            .filter(|digits| digits.len() == expected * 64)
            .ok_or_else(|| failure("eth_call result has the wrong length"))?;
        (0..expected)
            .map(|index| {
                hex::decode(&digits[index * 64..(index + 1) * 64])
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .ok_or_else(|| failure("eth_call result is not hexadecimal"))
            })
            .collect()
    }

    pub async fn code_hash(&self, address: &[u8; 20], block: &str) -> Result<[u8; 32], AuthError> {
        let code = self
            .request(
                "eth_getCode",
                json!([format!("0x{}", hex::encode(address)), block]),
            )
            .await?;
        let bytes = code
            .as_str()
            .and_then(|text| text.strip_prefix("0x"))
            .and_then(|digits| hex::decode(digits).ok())
            .ok_or_else(|| failure("eth_getCode result is not hexadecimal"))?;
        Ok(Keccak256::digest(&bytes).into())
    }

    /// `(number, timestamp)` of the block with `tag`.
    pub async fn block(&self, tag: &str) -> Result<(u64, u64), AuthError> {
        let block = self
            .request("eth_getBlockByNumber", json!([tag, false]))
            .await?;
        Ok((quantity(&block["number"])?, quantity(&block["timestamp"])?))
    }

    pub async fn receipt(&self, hash: &str) -> Result<Option<Value>, AuthError> {
        let receipt = self
            .request("eth_getTransactionReceipt", json!([hash]))
            .await?;
        Ok((!receipt.is_null()).then_some(receipt))
    }

    /// Every log of `address` with `topics` in `from..=to`, read in chunks
    /// that halve on a range or size error (§6.6).
    pub async fn logs(
        &self,
        address: &[u8; 20],
        topics: Value,
        from: u64,
        to: u64,
    ) -> Result<Vec<Value>, AuthError> {
        collect_logs(from, to, |start, end| {
            let topics = topics.clone();
            async move {
                let result = self
                    .request(
                        "eth_getLogs",
                        json!([{
                            "address": format!("0x{}", hex::encode(address)),
                            "fromBlock": format!("0x{start:x}"),
                            "toBlock": format!("0x{end:x}"),
                            "topics": topics,
                        }]),
                    )
                    .await;
                match result {
                    Ok(Value::Array(logs)) => Ok(logs),
                    Ok(_) => Err(LogFetchError::Other(
                        "eth_getLogs result is not a list".into(),
                    )),
                    Err(error) => Err(LogFetchError::from_message(error.to_string())),
                }
            }
        })
        .await
        .map_err(|error| failure(error.to_string()))
    }
}

/// The request-tree rebuild (`zkapi_client::tree`) reads through the same
/// client: the chain check, the timeout and the size bound apply to it too.
impl zkapi_client::tree::JsonRpc for Rpc {
    async fn request(&self, method: &str, params: Value) -> Result<Value, String> {
        Rpc::request(self, method, params)
            .await
            .map_err(|error| error.to_string())
    }
}

pub fn quantity(value: &Value) -> Result<u64, AuthError> {
    value
        .as_str()
        .and_then(|text| text.strip_prefix("0x"))
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
        .ok_or_else(|| failure("an RPC quantity is invalid"))
}

pub fn word_to_u128(word: &[u8; 32]) -> Option<u128> {
    word[..16]
        .iter()
        .all(|byte| *byte == 0)
        .then(|| u128::from_be_bytes(word[16..].try_into().expect("16 bytes")))
}

pub fn word_to_u64(word: &[u8; 32]) -> Option<u64> {
    word_to_u128(word).and_then(|value| u64::try_from(value).ok())
}

/// The vault's view of one note: its stored leaf and status
/// (`noteRecord(noteId)`), and for a pending escape the current payout,
/// deadline and concession.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoteView {
    /// The leaf the vault stored at deposit; zero for an unknown or retired
    /// note.
    pub leaf: Felt252,
    pub status: u8,
    pub pending: Option<PendingEscape>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingEscape {
    pub nullifier: Felt252,
    pub final_balance: u128,
    pub destination: [u8; 20],
    pub deadline: u64,
    pub next_nullifier: Felt252,
    pub state_balance: u128,
    pub conceded: u128,
}

/// Decode `noteRecord(noteId)`: exactly two words, the leaf (a field
/// element) and the status (0 Uninitialized, 1 Active, 2 PendingWithdrawal,
/// 3 Closed; a retired note is Closed with leaf 0).
pub fn decode_note_record(words: &[[u8; 32]]) -> Result<(Felt252, u8), AuthError> {
    let [leaf, status] = words else {
        return Err(failure("noteRecord() is not two words"));
    };
    let leaf = Felt252::try_from_bytes_be(*leaf)
        .map_err(|_| failure("noteRecord() leaf is not a field element"))?;
    let status = word_to_u64(status)
        .and_then(|value| u8::try_from(value).ok())
        .filter(|status| *status <= 3)
        .ok_or_else(|| failure("invalid note status"))?;
    Ok((leaf, status))
}

/// `noteRecord(noteId)` at `block`: the note's stored leaf and status.
pub async fn note_record(
    rpc: &Rpc,
    vault: &[u8; 20],
    note_id: u32,
    block: &str,
) -> Result<(Felt252, u8), AuthError> {
    let words = rpc
        .call_words(
            vault,
            &format!("0x{NOTE_RECORD}{}", word_u64(note_id.into())),
            block,
            2,
        )
        .await?;
    decode_note_record(&words)
}

/// Read a note and its pending escape at `block`, both getters at the same
/// block (design §5.4).
pub async fn read_note(
    rpc: &Rpc,
    vault: &[u8; 20],
    note_id: u32,
    block: &str,
) -> Result<NoteView, AuthError> {
    let (leaf, status) = note_record(rpc, vault, note_id, block).await?;
    if status != 2 {
        return Ok(NoteView {
            leaf,
            status,
            pending: None,
        });
    }
    let pending = rpc
        .call_words(
            vault,
            &format!("0x{PENDING_WITHDRAWALS}{}", word_u64(note_id.into())),
            block,
            6,
        )
        .await?;
    let concession = rpc
        .call_words(
            vault,
            &format!("0x{PENDING_CONCESSIONS}{}", word_u64(note_id.into())),
            block,
            3,
        )
        .await?;
    let invalid = || failure("invalid pending escape");
    let mut destination = [0u8; 20];
    destination.copy_from_slice(&pending[4][12..]);
    Ok(NoteView {
        leaf,
        status,
        pending: Some(PendingEscape {
            nullifier: Felt252(pending[2]),
            final_balance: word_to_u128(&pending[3]).ok_or_else(invalid)?,
            destination,
            deadline: word_to_u64(&pending[5]).ok_or_else(invalid)?,
            next_nullifier: Felt252(concession[0]),
            state_balance: word_to_u128(&concession[1]).ok_or_else(invalid)?,
            conceded: word_to_u128(&concession[2]).ok_or_else(invalid)?,
        }),
    })
}

/// `challengedNullifiers(nullifier)`.
pub async fn challenged(
    rpc: &Rpc,
    vault: &[u8; 20],
    nullifier: &Felt252,
    block: &str,
) -> Result<bool, AuthError> {
    let word = rpc
        .call_words(
            vault,
            &format!("0x{CHALLENGED_NULLIFIERS}{}", word_felt(nullifier)),
            block,
            1,
        )
        .await?;
    Ok(word[0][31] == 1 && word[0][..31].iter().all(|byte| *byte == 0))
}

/// `effectiveExpiry(noteId, commitment, amount, expiryTs)` at latest: the
/// note's expiry with pauses added, or 0 when the preimage does not
/// reproduce the stored leaf (or the note is unknown or retired).
pub async fn effective_expiry(
    rpc: &Rpc,
    vault: &[u8; 20],
    note_id: u32,
    commitment: &Felt252,
    amount: u128,
    expiry_ts: u64,
) -> Result<u64, AuthError> {
    let word = rpc
        .call_words(
            vault,
            &format!(
                "0x{EFFECTIVE_EXPIRY}{}{}{amount:064x}{}",
                word_u64(note_id.into()),
                word_felt(commitment),
                word_u64(expiry_ts)
            ),
            "latest",
            1,
        )
        .await?;
    word_to_u64(&word[0]).ok_or_else(|| failure("invalid effective expiry"))
}

/// What the deployment check found at a vault.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaultCheck {
    /// `LEAF_BOUND_EXIT_VERSION()` is 1 (and `minDeposit()` the pinned value).
    LeafBound,
    /// The vault answered, and it is not the vault this build serves: a
    /// revision-3 vault (the probe reverts or answers another version), or
    /// another `minDeposit()` than the deployment pins.
    Refused(String),
    /// The RPC could not be asked.
    Unreachable(String),
}

/// Whether an RPC error is the vault's answer (a revert) rather than a
/// transport failure.
fn reverted(message: &str) -> bool {
    let lowered = message.to_ascii_lowercase();
    lowered.contains("revert") || lowered.contains("execution error")
}

/// The deployment check of vault revision 4: `LEAF_BOUND_EXIT_VERSION()`
/// must be 1 (a revision-3 vault has no such function), and when the
/// deployment pins `min_deposit_units`, `minDeposit()` must equal it. The
/// companion sends no deposits; the pin only has to describe this vault.
pub async fn check_leaf_bound_vault(
    rpc: &Rpc,
    vault: &[u8; 20],
    min_deposit_units: Option<u128>,
) -> VaultCheck {
    let version = match rpc
        .call(vault, &format!("0x{LEAF_BOUND_EXIT_VERSION}"), "latest")
        .await
    {
        Ok(result) => result,
        Err(error) if reverted(&error.to_string()) => {
            return VaultCheck::Refused(
                "the vault has no LEAF_BOUND_EXIT_VERSION(): it is not a vault revision 4 (leaf-bound exits) vault".into(),
            )
        }
        Err(error) => return VaultCheck::Unreachable(error.to_string()),
    };
    let one = format!("0x{}", word_u64(1));
    if !version.eq_ignore_ascii_case(&one) {
        return VaultCheck::Refused(format!(
            "the vault's LEAF_BOUND_EXIT_VERSION() is {version}, not 1: this companion serves only vault revision 4 (leaf-bound exits)"
        ));
    }
    let Some(pinned) = min_deposit_units else {
        return VaultCheck::LeafBound;
    };
    match rpc
        .call_words(vault, &format!("0x{MIN_DEPOSIT}"), "latest", 1)
        .await
    {
        Ok(words) => match word_to_u128(&words[0]) {
            Some(found) if found == pinned => VaultCheck::LeafBound,
            found => VaultCheck::Refused(format!(
                "the vault's minDeposit() is {}, but the deployment pins min_deposit_units {pinned}",
                found.map_or_else(|| "out of range".to_string(), |value| value.to_string())
            )),
        },
        Err(error) if reverted(&error.to_string()) => {
            VaultCheck::Refused("the vault has no minDeposit()".into())
        }
        Err(error) => VaultCheck::Unreachable(error.to_string()),
    }
}

/// The concessions `EscapeConcessionRaised` recorded for `note_id` at
/// `nullifier` in `from..=to`.
pub async fn raised_concessions(
    rpc: &Rpc,
    vault: &[u8; 20],
    note_id: u32,
    nullifier: &Felt252,
    from: u64,
    to: u64,
) -> Result<Vec<u128>, AuthError> {
    let logs = rpc
        .logs(
            vault,
            json!([
                escape_concession_raised_topic(),
                format!("0x{}", word_u64(note_id.into()))
            ]),
            from,
            to,
        )
        .await?;
    let mut raises = Vec::new();
    for log in logs {
        if log["removed"] == true {
            continue;
        }
        let data = log["data"]
            .as_str()
            .and_then(|text| text.strip_prefix("0x"))
            .filter(|digits| digits.len() == 3 * 64)
            .ok_or_else(|| failure("invalid EscapeConcessionRaised log"))?;
        if !data[..64].eq_ignore_ascii_case(&word_felt(nullifier)) {
            continue;
        }
        let conceded = u128::from_str_radix(&data[64 + 32..128], 16)
            .ok()
            .filter(|_| data[64..64 + 32].bytes().all(|byte| byte == b'0'))
            .ok_or_else(|| failure("invalid EscapeConcessionRaised log"))?;
        raises.push(conceded);
    }
    Ok(raises)
}

/// The transaction of an `EscapeWithdrawalChallenged` that defeated the
/// escape of `note_id` at `nullifier` in `from..=to`, if any.
pub async fn escape_defeat(
    rpc: &Rpc,
    vault: &[u8; 20],
    note_id: u32,
    nullifier: &Felt252,
    from: u64,
    to: u64,
) -> Result<Option<String>, AuthError> {
    let logs = rpc
        .logs(
            vault,
            json!([
                escape_challenged_topic(),
                format!("0x{}", word_u64(note_id.into()))
            ]),
            from,
            to,
        )
        .await?;
    for log in logs {
        if log["removed"] == true {
            continue;
        }
        let data = log["data"]
            .as_str()
            .and_then(|text| text.strip_prefix("0x"))
            .filter(|digits| digits.len() == 64)
            .ok_or_else(|| failure("invalid EscapeWithdrawalChallenged log"))?;
        if data[..64].eq_ignore_ascii_case(&word_felt(nullifier)) {
            let hash = log["transactionHash"]
                .as_str()
                .ok_or_else(|| failure("invalid EscapeWithdrawalChallenged log"))?;
            return Ok(Some(hash.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

pub fn vault_address(contract: &Felt252) -> Result<[u8; 20], AuthError> {
    zkapi_types::serialization::felt_to_address(contract)
        .ok_or_else(|| failure("the vault address is not an address"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_and_topics_match_the_vault_abi() {
        let selector = |signature: &str| topic(signature)[2..10].to_string();
        let tuple = WITHDRAWAL_INPUTS_ABI;
        assert_eq!(
            selector(&format!("initiateEscapeWithdrawal({tuple},bytes)")),
            INITIATE_ESCAPE
        );
        assert_eq!(
            selector(&format!("mutualClose({tuple},bytes)")),
            MUTUAL_CLOSE
        );
        assert_eq!(
            selector("finalizeEscapeWithdrawal(uint32)"),
            FINALIZE_ESCAPE
        );
        assert_eq!(selector("claimEscapePayout(address)"), CLAIM_ESCAPE_PAYOUT);
        assert_eq!(selector("noteRecord(uint32)"), NOTE_RECORD);
        assert_eq!(
            selector("effectiveExpiry(uint32,bytes32,uint128,uint64)"),
            EFFECTIVE_EXPIRY
        );
        assert_eq!(
            selector("LEAF_BOUND_EXIT_VERSION()"),
            LEAF_BOUND_EXIT_VERSION
        );
        assert_eq!(selector("minDeposit()"), MIN_DEPOSIT);
        assert_eq!(selector("currentRoot()"), CURRENT_ROOT);
        // The pins of vault revision 4 (vault_calldata_golden.json).
        assert_eq!(
            (INITIATE_ESCAPE, MUTUAL_CLOSE, NOTE_RECORD),
            ("8cd67c60", "bce12a6c", "d154f5bf")
        );
        assert_eq!(selector("pendingConcessions(uint32)"), PENDING_CONCESSIONS);
        assert_eq!(selector("pendingWithdrawals(uint32)"), PENDING_WITHDRAWALS);
        assert_eq!(
            selector("challengedNullifiers(uint256)"),
            CHALLENGED_NULLIFIERS
        );
        assert_eq!(
            selector("CONCESSION_ESCAPE_VERSION()"),
            CONCESSION_ESCAPE_VERSION
        );
        assert_eq!(selector("proofAdapter()"), PROOF_ADAPTER);
        assert_eq!(
            escape_concession_raised_topic(),
            "0x3faf5608f821061643ff6fdfe6dd0f6d7fb074bb565f35e3537a86ac08f0897c"
        );
        assert_eq!(
            escape_initiated_topic(),
            "0x5ad24b4d5235cdf161caf23bb21550824a1be902576056f666b56ac6c424f4b1"
        );
        assert_eq!(
            escape_challenged_topic(),
            "0x4bffb77581f1706ad6afe03cd651fb25b1b485f7eaef1826e2cc6f420f532161"
        );
        // Each named error is the selector of its signature.
        for (selector_hex, description) in VAULT_ERRORS {
            let name = description.split(':').next().unwrap();
            assert_eq!(selector(&format!("{name}()")), selector_hex, "{name}");
        }
        assert_eq!(
            (VAULT_ERRORS[0].0, VAULT_ERRORS[1].0),
            ("f2b1d50f", "aa6aef76")
        );
    }

    /// The revert data a JSON-RPC error carries names the vault's error.
    #[test]
    fn vault_errors_are_read_from_revert_data() {
        let message = r#"RPC eth_estimateGas error: {"code":3,"message":"execution reverted","data":"0xF2B1D50F"}"#;
        assert!(vault_error(message)
            .unwrap()
            .starts_with("NoteLeafMismatch"));
        assert!(vault_error(r#"{"data":"0xaa6aef76"}"#)
            .unwrap()
            .starts_with("InvalidNoteFields"));
        assert_eq!(vault_error("execution reverted"), None);
        // UnknownRoot (vault revision 3) is gone.
        assert_eq!(vault_error(r#"{"data":"0x8c520116"}"#), None);
    }

    /// `noteRecord` is exactly two words: a field-element leaf and a status
    /// of at most 3.
    #[test]
    fn note_records_decode_to_a_leaf_and_a_status() {
        let mut leaf = [0u8; 32];
        leaf[31] = 7;
        let status = |value: u8| {
            let mut word = [0u8; 32];
            word[31] = value;
            word
        };
        assert_eq!(
            decode_note_record(&[leaf, status(1)]).unwrap(),
            (Felt252::from_u64(7), 1)
        );
        assert_eq!(
            decode_note_record(&[[0; 32], status(3)]).unwrap(),
            (Felt252::ZERO, 3)
        );
        assert!(decode_note_record(&[leaf, status(4)]).is_err());
        assert!(decode_note_record(&[[0xff; 32], status(1)]).is_err());
        assert!(decode_note_record(&[leaf]).is_err());
        assert!(decode_note_record(&[leaf, status(1), status(1)]).is_err());
        let mut wide = status(1);
        wide[0] = 1;
        assert!(decode_note_record(&[leaf, wide]).is_err());
    }

    /// One URL rule for every RPC the companion reads: HTTPS, or plain HTTP
    /// to a node on this machine, never with credentials or a fragment.
    #[test]
    fn rpc_urls_are_https_or_a_node_on_this_machine() {
        let allowed = |url: &str| rpc_url_allowed(&reqwest::Url::parse(url).unwrap());
        for url in [
            "https://rpc.example",
            "http://127.0.0.1:8545",
            "http://localhost:8545",
            "http://[::1]:8545",
        ] {
            assert!(allowed(url), "{url}");
        }
        for url in [
            "http://rpc.example",
            "http://10.0.0.1:8545",
            "https://user:secret@rpc.example",
            "https://rpc.example/#fragment",
            "ws://127.0.0.1:8545",
        ] {
            assert!(!allowed(url), "{url}");
        }
    }

    /// The shared withdrawal golden vector (design §11 WP-F): real kind-0
    /// and kind-1 proofs whose calldata Forge pins to abi.encodeCall against
    /// the real vault. With ZKAPI_WITHDRAWAL_GOLDEN_OUT set, the encoder's
    /// output is written there for scripts/check-withdrawal-golden.mjs,
    /// which submits it to a vault on Anvil.
    #[test]
    fn real_proofs_encode_to_the_shared_withdrawal_golden_vector() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../protocol/contracts/test/fixtures/withdrawal-golden.json"
        ))
        .unwrap();
        let mut output = serde_json::Map::new();
        for (name, selector) in [("escape", INITIATE_ESCAPE), ("close", MUTUAL_CLOSE)] {
            let inputs: zkapi_types::WithdrawalPublicInputsV2C =
                serde_json::from_value(golden[name]["public_inputs"].clone()).unwrap();
            let proof = zkapi_types::wire::Groth16ProofWire {
                backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
                proof: golden[name]["proof"].as_str().unwrap().to_string(),
            };
            let calldata = withdrawal_calldata(selector, &inputs, &proof).unwrap();
            assert_eq!(
                calldata,
                golden[name]["calldata"].as_str().unwrap(),
                "{name}"
            );
            output.insert(name.into(), calldata.into());
        }
        if let Some(dir) = std::env::var_os("ZKAPI_WITHDRAWAL_GOLDEN_OUT") {
            std::fs::write(
                std::path::Path::new(&dir).join("rust-companion.json"),
                serde_json::to_vec(&output).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn withdrawal_calldata_is_836_bytes_with_the_proof_at_word_eighteen() {
        use base64::Engine;
        let inputs = zkapi_types::WithdrawalPublicInputsV2C {
            protocol_version: 2,
            chain_id: 11_155_111,
            contract_address: Felt252::from_u64(0x1234),
            note_leaf: Felt252::from_u64(5),
            state_signing_key_x: Felt252::from_u64(6),
            state_signing_key_y: Felt252::from_u64(7),
            clearance_signing_key_x: Felt252::from_u64(8),
            clearance_signing_key_y: Felt252::from_u64(9),
            note_id: 3,
            deposit_amount: 1_000,
            expiry_ts: 4_000_000_000,
            final_balance: 900,
            destination: [0x22; 20],
            withdrawal_nullifier: Felt252::from_u64(10),
            kind: 0,
            next_nullifier: Felt252::from_u64(11),
            conceded: 100,
            valid_until: 1_800_000_000,
        };
        let proof = zkapi_types::wire::Groth16ProofWire {
            backend: zkapi_types::wire::ProofBackendWire::Groth16Bn254,
            proof: base64::engine::general_purpose::STANDARD
                .encode((0..=255u8).collect::<Vec<_>>()),
        };
        let data = withdrawal_calldata(INITIATE_ESCAPE, &inputs, &proof).unwrap();
        let bytes = hex::decode(&data[2..]).unwrap();
        assert_eq!(bytes.len(), 836);
        let word = |index: usize| hex::encode(&bytes[4 + index * 32..4 + (index + 1) * 32]);
        assert_eq!(word(3), format!("{:064x}", 5));
        // noteFields = noteId·2^192 + D·2^64 + expiryTs.
        assert_eq!(
            word(8),
            format!("{:016x}{:032x}{:016x}", 3, 1_000, 4_000_000_000u64)
        );
        assert_eq!(word(9), format!("{:064x}", 900));
        assert_eq!(word(14), format!("{:064x}", 100));
        assert_eq!(word(15), format!("{:064x}", 1_800_000_000u64));
        assert_eq!(word(16), format!("{:064x}", 17 * 32));
        assert_eq!(word(17), format!("{:064x}", 256));
        assert_eq!(&bytes[4 + 18 * 32..], (0..=255u8).collect::<Vec<_>>());
        assert_eq!(finalize_calldata(3), format!("0xff8f5585{:064x}", 3));
    }
}
