//! The transaction lane shared by the operator daemons (`zkapi-challenged`
//! and `zkapi-activated`): EIP-1559 fee planning within the caps and a
//! per-transaction fee ceiling, same-nonce replacement rules, the
//! classification of signer refusals and ambiguous sends, the JSON-RPC
//! client whose errors keep provider URLs out of messages, and the atomic
//! write-ahead of a daemon's checkpoint. Each daemon owns its sender: the
//! nonce bookkeeping assumes nobody else sends from it.

use std::{path::Path, time::Duration};

use anyhow::{ensure, Context};
use serde::Serialize;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_types::Felt252;

use crate::{challenge_status::BlockedReason, deployment::ContractReader};

pub(crate) const GWEI: u128 = 1_000_000_000;

/// Older candidate hashes beyond this many are dropped from a nonce's record.
const MAX_SUPERSEDED_HASHES: usize = 32;
/// The signer may make several sequential upstream calls for one send.
pub(crate) const SEND_TIMEOUT: Duration = Duration::from_secs(95);

/// EIP-1559 fee proposals. The signer enforces its own caps, which must be at
/// least these. A same-nonce replacement raises the tip by the minimum valid
/// step and the fee cap by `bump_percent`; two replacements stay reserved for
/// the critical threshold. Every bid keeps gas limit x maxFeePerGas within
/// the transaction fee ceiling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FeePolicy {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub priority_fee_per_gas: u128,
    /// Highest gas limit x maxFeePerGas of one transaction (wei).
    pub tx_fee_cap_wei: u128,
    pub bump_after_blocks: u64,
    pub bump_percent: u64,
}

impl FeePolicy {
    pub const DEFAULT_PRIORITY_FEE_PER_GAS: u128 = 2 * GWEI;
    /// 1 ether, the default `--rpc.txfeecap` of geth and reth: their RPC
    /// refuses a transaction whose gas limit x maxFeePerGas exceeds it.
    pub const DEFAULT_TX_FEE_CAP_WEI: u128 = 1_000_000_000_000_000_000;
    pub const DEFAULT_BUMP_AFTER_BLOCKS: u64 = 3;
    pub const DEFAULT_BUMP_PERCENT: u64 = 25;

    pub fn new(max_fee_per_gas: u128, max_priority_fee_per_gas: u128) -> Self {
        Self {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            priority_fee_per_gas: Self::DEFAULT_PRIORITY_FEE_PER_GAS,
            tx_fee_cap_wei: Self::DEFAULT_TX_FEE_CAP_WEI,
            bump_after_blocks: Self::DEFAULT_BUMP_AFTER_BLOCKS,
            bump_percent: Self::DEFAULT_BUMP_PERCENT,
        }
    }

    /// A transaction fee ceiling as the signer reads it: a positive decimal
    /// wei amount without sign, leading zeros or spaces; empty means the
    /// default.
    pub fn parse_tx_fee_cap(value: &str) -> Result<u128, String> {
        if value.is_empty() {
            return Ok(Self::DEFAULT_TX_FEE_CAP_WEI);
        }
        if value.starts_with('0') || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("must be a positive decimal integer in wei".into());
        }
        value
            .parse()
            .map_err(|_| "exceeds the largest supported amount".into())
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        ensure!(
            self.priority_fee_per_gas > 0,
            "priority fee per gas must be positive"
        );
        ensure!(
            self.max_priority_fee_per_gas <= self.max_fee_per_gas,
            "max priority fee per gas must not exceed max fee per gas"
        );
        // Nodes accept a same-nonce replacement only when both fees rise by
        // at least 10%, so the tip needs room above the first bid: twice the
        // first tip allows about five replacements before the critical
        // threshold and the two reserved for it.
        ensure!(
            self.max_priority_fee_per_gas >= self.priority_fee_per_gas.saturating_mul(2),
            "max priority fee per gas must be at least twice the priority fee per gas, leaving tip headroom for same-nonce replacement"
        );
        ensure!(
            self.max_fee_per_gas <= u128::MAX / 1_000,
            "max fee per gas is implausibly large"
        );
        ensure!(
            self.tx_fee_cap_wei > 0,
            "transaction fee cap must be positive"
        );
        ensure!(
            self.bump_after_blocks >= 1,
            "fee bump interval must be at least one block"
        );
        ensure!(
            (10..=100).contains(&self.bump_percent),
            "fee bump percent must be between 10 and 100"
        );
        Ok(())
    }
}

/// A JSON-RPC error object. Display stays `"{method}: {error_json}"`.
#[derive(Debug)]
pub(crate) struct RpcError {
    pub(crate) method: String,
    pub(crate) error: Value,
}

impl RpcError {
    pub(crate) fn code(&self) -> Option<i64> {
        self.error.get("code").and_then(Value::as_i64)
    }

    pub(crate) fn reason(&self) -> Option<&str> {
        self.error.get("data")?.get("reason")?.as_str()
    }

    pub(crate) fn transaction_hash(&self) -> Option<String> {
        let hash = self.error.get("data")?.get("transaction_hash")?.as_str()?;
        let digits = hash.strip_prefix("0x")?;
        (digits.len() == 64 && digits.chars().all(|c| c.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    }
}

impl std::fmt::Display for RpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.error)
    }
}

impl std::error::Error for RpcError {}

/// An HTTP-level RPC failure. It never includes the URL, which may embed a key.
#[derive(Debug)]
pub(crate) struct TransportError {
    pub(crate) method: String,
    pub(crate) message: String,
    /// No connection was made, so the request never reached the signer.
    pub(crate) unsent: bool,
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.method, self.message)
    }
}

impl std::error::Error for TransportError {}

/// Outcome classes of a failed `eth_sendTransaction`.
pub(crate) enum SendFailure {
    /// -32602/-32601/-32003: a definitive refusal; nothing was broadcast.
    Refused(Option<String>),
    /// A connection never made, or a signer-reported failure before
    /// broadcast (transient); nothing was broadcast.
    NotBroadcast(BlockedReason),
    /// Possibly broadcast, with the candidate hash when the signer reports it.
    Ambiguous(Option<String>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Fees {
    pub max_fee: u128,
    pub tip: u128,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeePlan {
    /// No earlier attempt can occupy the nonce.
    First,
    /// Re-send after every earlier attempt left the pools.
    Resend(Fees),
    /// Must be a valid replacement of every earlier attempt.
    Bump(Fees),
}

/// One JSON-RPC call to `url`. A JSON-RPC error is an [`RpcError`]; an HTTP
/// failure is a [`TransportError`], which never includes the URL (it may
/// embed a provider key).
pub(crate) async fn rpc_request(
    client: &reqwest::Client,
    url: &str,
    method: &str,
    params: Value,
    timeout: Option<Duration>,
) -> anyhow::Result<Value> {
    let mut request = client
        .post(url)
        .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }));
    if let Some(timeout) = timeout {
        request = request.timeout(timeout);
    }
    let transport = |error: reqwest::Error| TransportError {
        method: method.into(),
        unsent: error.is_connect() || error.is_builder(),
        message: error.without_url().to_string(),
    };
    let response: Value = request
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(transport)?
        .json()
        .await
        .map_err(transport)?;
    if let Some(error) = response.get("error") {
        return Err(RpcError {
            method: method.into(),
            error: error.clone(),
        }
        .into());
    }
    response
        .get("result")
        .cloned()
        .with_context(|| format!("{method}: missing RPC result"))
}

/// The first of `names` (custom error signatures) whose selector the RPC
/// error's revert data or message carries, when the RPC passes it through.
pub(crate) fn revert_name(error: &anyhow::Error, names: &[&'static str]) -> Option<&'static str> {
    let rpc = error.downcast_ref::<RpcError>()?;
    let candidates = [
        rpc.error.get("data").and_then(Value::as_str),
        rpc.error
            .get("data")
            .and_then(|data| data.get("data"))
            .and_then(Value::as_str),
        rpc.error.get("message").and_then(Value::as_str),
    ];
    names.iter().copied().find(|signature| {
        let selector = hex::encode(selector(signature));
        candidates
            .iter()
            .flatten()
            .any(|text| text.to_ascii_lowercase().contains(&selector))
    })
}

/// Write `value` as pretty JSON to `path` atomically and durably: a
/// temporary file, fsync, rename, then fsync of the directory.
pub(crate) fn write_json_atomically<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    let mut file = std::fs::File::create(&temporary)?;
    std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(value)?)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

/// A daemon's RPC as a `ContractReader` for the startup probes.
pub(crate) struct RpcReader {
    pub(crate) client: reqwest::Client,
    pub(crate) url: String,
}

impl RpcReader {
    async fn rpc(&self, method: &str, params: Value) -> Result<Value, String> {
        let response: Value = self
            .client
            .post(&self.url)
            .json(&json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params }))
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| format!("{method}: {}", error.without_url()))?
            .json()
            .await
            .map_err(|error| format!("{method}: {}", error.without_url()))?;
        if let Some(error) = response.get("error") {
            return Err(format!("{method}: {error}"));
        }
        response
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: missing RPC result"))
    }
}

impl ContractReader for RpcReader {
    async fn contract_word(&self, address: &str, selector: &str) -> Result<[u8; 32], String> {
        let result = self
            .rpc(
                "eth_call",
                json!([{ "to": address, "data": selector }, "latest"]),
            )
            .await?;
        let word = result
            .as_str()
            .and_then(|raw| raw.strip_prefix("0x"))
            .filter(|raw| raw.len() == 64)
            .ok_or("getter returned no 32-byte word (is the contract deployed at this address on this chain?)")?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(word, &mut bytes).map_err(|_| "malformed ABI word".to_string())?;
        Ok(bytes)
    }

    async fn code_hash(&self, address: &str) -> Result<[u8; 32], String> {
        let code = self.rpc("eth_getCode", json!([address, "latest"])).await?;
        let body = code
            .as_str()
            .and_then(|raw| raw.strip_prefix("0x"))
            .ok_or("invalid eth_getCode response")?;
        if body.is_empty() {
            return Err("no contract code at this address on this chain".into());
        }
        let bytes = hex::decode(body).map_err(|_| "invalid eth_getCode response".to_string())?;
        Ok(Keccak256::digest(&bytes).into())
    }
}

/// Plan the fees of one send at its exact gas limit. `tx_fee_limit` is the
/// highest maxFeePerGas the transaction fee ceiling allows at that gas limit
/// and bounds every bid like a lower fee cap. A bump raises the tip by the
/// minimum valid replacement step and the fee cap by `bump_percent`.
///
/// Two valid replacements stay in reserve for the critical threshold: other
/// bids stay within 10/11 of 10/11 of the caps, unless the base fee needs
/// more, or rose above a pending bid that cannot otherwise be outbid. A
/// critical send bids 10/11 of the caps, then the caps. `Ok(None)` keeps a
/// pending attempt when only that reserve is left.
pub(crate) fn plan_fees(
    policy: &FeePolicy,
    plan: FeePlan,
    base_fee: Option<u128>,
    critical: bool,
    tx_fee_limit: Option<u128>,
    affordable: Option<u128>,
) -> Result<Option<Fees>, BlockedReason> {
    let caps = Fees {
        max_fee: policy
            .max_fee_per_gas
            .min(tx_fee_limit.unwrap_or(u128::MAX)),
        tip: policy.max_priority_fee_per_gas,
    };
    if base_fee.is_some_and(|base| base > policy.max_fee_per_gas) {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    if base_fee.is_some_and(|base| base > caps.max_fee) {
        return Err(BlockedReason::TxFeeCapReached);
    }
    let reserve = |steps: u32| {
        (0..steps).fold(caps, |fees, _| Fees {
            max_fee: headroom(fees.max_fee),
            tip: headroom(fees.tip),
        })
    };
    // Just under the caps, unless the base fee already exceeds that bid.
    let critical_target = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        _ => reserve(1),
    };
    // The limits of every other bid, raised only as far as the base fee needs.
    let limit = match base_fee {
        Some(base) if base > headroom(caps.max_fee) => caps,
        Some(base) if base > reserve(2).max_fee => reserve(1),
        _ => reserve(2),
    };
    let bid = |tip: u128| {
        base_fee.map_or(limit.max_fee, |base| {
            limit
                .max_fee
                .min(base.saturating_mul(2).saturating_add(tip))
        })
    };
    // A max fee the ceiling keeps from rising 10% (or below the raised tip)
    // is reported first: raising only the tip cap cannot help then.
    let cap_reason = |old: Fees| {
        let pinned = min_bump(old.max_fee).max(min_bump(old.tip)) > caps.max_fee;
        if pinned && caps.max_fee < policy.max_fee_per_gas {
            BlockedReason::TxFeeCapReached
        } else if min_bump(old.tip) > caps.tip {
            BlockedReason::TipCapReached
        } else {
            BlockedReason::FeeCapReached
        }
    };
    let bump = |old: Fees, limit: Fees| {
        let tip = min_bump(old.tip)
            .max(policy.priority_fee_per_gas)
            .min(limit.tip);
        let mut max_fee = old
            .max_fee
            .saturating_mul(100 + policy.bump_percent as u128)
            .div_ceil(100);
        if let Some(base) = base_fee {
            max_fee = max_fee.max(base.saturating_mul(2).saturating_add(tip));
        }
        let fees = Fees {
            max_fee: max_fee.min(limit.max_fee),
            tip,
        };
        is_valid_bump(old, fees).then_some(fees)
    };
    // A target's tip never exceeds its max fee, which the ceiling can lower
    // below the tip cap.
    let escalate = |old: Fees| {
        [critical_target, caps]
            .into_iter()
            .map(|fees| Fees {
                tip: fees.tip.min(fees.max_fee),
                ..fees
            })
            .find(|fees| is_valid_bump(old, *fees))
            .ok_or_else(|| cap_reason(old))
    };
    let mut fees = match plan {
        FeePlan::First if critical => critical_target,
        FeePlan::First => Fees {
            max_fee: bid(policy.priority_fee_per_gas),
            tip: policy.priority_fee_per_gas,
        },
        FeePlan::Resend(old) => {
            let tip = old.tip.min(caps.tip);
            let fees = Fees {
                max_fee: old.max_fee.min(caps.max_fee).max(bid(tip)),
                tip,
            };
            if critical {
                Fees {
                    max_fee: fees.max_fee.max(critical_target.max_fee),
                    tip: fees.tip.max(critical_target.tip),
                }
            } else {
                fees
            }
        }
        FeePlan::Bump(old) if critical => escalate(old)?,
        FeePlan::Bump(old) => match bump(old, limit) {
            Some(fees) => fees,
            // The pending bid can no longer be included: spend the reserve.
            None if base_fee.is_some_and(|base| base > old.max_fee) => escalate(old)?,
            None if bump(old, caps).is_none() => return Err(cap_reason(old)),
            None => return Ok(None),
        },
    };
    fees.tip = fees.tip.min(fees.max_fee);
    let mut clamped = false;
    if let Some(limit) = affordable.filter(|limit| fees.max_fee > *limit) {
        fees.max_fee = limit;
        fees.tip = fees.tip.min(limit);
        clamped = true;
    }
    let includable = fees.tip > 0 && base_fee.is_none_or(|base| fees.max_fee >= base);
    let valid = match plan {
        FeePlan::Bump(old) => is_valid_bump(old, fees),
        _ => true,
    };
    if clamped && !(includable && valid) {
        return Err(BlockedReason::InsufficientBalance);
    }
    if !includable {
        return Err(BlockedReason::BaseFeeAboveFeeCap);
    }
    Ok(Some(fees))
}

/// The blocked reason of a definitive signer refusal.
pub(crate) fn refusal_reason(reason: Option<&str>) -> BlockedReason {
    match reason {
        Some("base_fee_above_max_fee") => BlockedReason::BaseFeeAboveMaxFee,
        Some("insufficient_balance") => BlockedReason::InsufficientBalance,
        Some("tx_fee_above_cap") => BlockedReason::TxFeeAboveCap,
        Some("upstream_tx_fee_cap") => BlockedReason::UpstreamTxFeeCap,
        _ => BlockedReason::SignerRefused,
    }
}

/// The signer's transaction fee cap from a `tx_fee_above_cap` refusal: its
/// `tx_fee_cap_wei`, or else `max_fee_per_gas_allowed` x the gas limit.
pub(crate) fn refused_tx_fee_cap(error: &anyhow::Error, gas: u64) -> Option<u128> {
    let data = error.downcast_ref::<RpcError>()?.error.get("data")?;
    let field = |name: &str| data.get(name).and_then(|value| quantity_u128(value).ok());
    field("tx_fee_cap_wei")
        .or_else(|| {
            Some(
                field("max_fee_per_gas_allowed")?
                    .saturating_mul(field("gas_limit").unwrap_or(u128::from(gas))),
            )
        })
        .filter(|cap| *cap > 0)
}

/// Gas limit x maxFeePerGas of a refused send: the refusal's `gas_limit` and
/// `max_fee_per_gas` (the bundled signer reports both with
/// `upstream_tx_fee_cap`), else the send's own. A reported fee that leaves
/// no bound (zero) cannot be what the node refused; like a zero signer cap,
/// it is ignored for the send's own.
pub(crate) fn refused_tx_fee(error: &anyhow::Error, gas: u64, max_fee: u128) -> u128 {
    let data = error
        .downcast_ref::<RpcError>()
        .and_then(|rpc| rpc.error.get("data"));
    let field = |name: &str| {
        data.and_then(|data| data.get(name))
            .and_then(|value| quantity_u128(value).ok())
    };
    let reported = field("gas_limit")
        .unwrap_or(u128::from(gas))
        .saturating_mul(field("max_fee_per_gas").unwrap_or(max_fee));
    if headroom(reported) > 0 {
        reported
    } else {
        u128::from(gas).saturating_mul(max_fee)
    }
}

/// The smallest value nodes accept as a 10% replacement bump.
pub(crate) fn min_bump(value: u128) -> u128 {
    value.saturating_mul(110).div_ceil(100)
}

/// The largest value that still leaves one valid bump below `cap`.
pub(crate) fn headroom(cap: u128) -> u128 {
    cap.saturating_mul(10) / 11
}

/// Geth, reth, erigon and besu replace a pending transaction only when both
/// fees rise by at least 10%.
pub(crate) fn is_valid_bump(old: Fees, new: Fees) -> bool {
    new.max_fee >= min_bump(old.max_fee) && new.tip >= min_bump(old.tip) && new.tip <= new.max_fee
}

/// Fees of a pending transaction object; a legacy one bids its gas price as
/// both fees.
pub(crate) fn transaction_fees(transaction: &Value) -> Option<Fees> {
    let field = |name: &str| {
        transaction
            .get(name)
            .filter(|value| !value.is_null())
            .and_then(|value| quantity_u128(value).ok())
    };
    match (field("maxFeePerGas"), field("maxPriorityFeePerGas")) {
        (Some(max_fee), Some(tip)) => Some(Fees { max_fee, tip }),
        _ => field("gasPrice").map(|price| Fees {
            max_fee: price,
            tip: price,
        }),
    }
}

/// Record a candidate hash that may still mine, keeping the newest
/// [`MAX_SUPERSEDED_HASHES`].
pub(crate) fn push_superseded(hashes: &mut Vec<String>, hash: String) {
    if !hashes.contains(&hash) {
        hashes.push(hash);
    }
    let excess = hashes.len().saturating_sub(MAX_SUPERSEDED_HASHES);
    hashes.drain(..excess);
}

/// The outcome class of a failed `eth_sendTransaction`.
pub(crate) fn classify_send_error(error: &anyhow::Error) -> SendFailure {
    if error
        .downcast_ref::<TransportError>()
        .is_some_and(|transport| transport.unsent)
    {
        return SendFailure::NotBroadcast(BlockedReason::RpcError);
    }
    // Timeouts, HTTP errors and broken responses may follow a broadcast.
    let Some(rpc) = error.downcast_ref::<RpcError>() else {
        return SendFailure::Ambiguous(None);
    };
    match (rpc.code(), rpc.reason()) {
        (Some(-32602 | -32601 | -32003), reason) => SendFailure::Refused(reason.map(str::to_owned)),
        (Some(-32000), Some("simulation_failed")) => {
            SendFailure::NotBroadcast(BlockedReason::SimulationReverted)
        }
        (
            Some(-32000),
            Some(
                "upstream_unavailable"
                | "upstream_rejected"
                | "upstream_chain_mismatch"
                | "base_fee_unavailable",
            ),
        ) => SendFailure::NotBroadcast(BlockedReason::RpcError),
        _ => SendFailure::Ambiguous(rpc.transaction_hash()),
    }
}

pub(crate) fn selector(signature: &str) -> Vec<u8> {
    Keccak256::digest(signature.as_bytes())[..4].to_vec()
}

pub(crate) fn quantity(value: &Value) -> anyhow::Result<u64> {
    let value = quantity_u128(value)?;
    u64::try_from(value).context("quantity exceeds uint64")
}

pub(crate) fn quantity_u128(value: &Value) -> anyhow::Result<u128> {
    let value = value
        .as_str()
        .context("expected hex quantity")?
        .strip_prefix("0x")
        .context("hex quantity lacks prefix")?;
    parse_digits_u128(value).context("quantity exceeds uint128")
}

pub(crate) fn parse_hex_u128(value: &str) -> Option<u128> {
    parse_digits_u128(value.strip_prefix("0x")?)
}

pub(crate) fn parse_digits_u128(digits: &str) -> Option<u128> {
    if digits.chars().all(|c| c == '0') {
        return Some(0);
    }
    u128::from_str_radix(digits.trim_start_matches('0'), 16).ok()
}

pub(crate) fn felt_u128(value: &Felt252) -> anyhow::Result<u128> {
    value.to_u128().context("value exceeds uint128")
}

pub(crate) fn felt_u64(value: &Felt252) -> anyhow::Result<u64> {
    ensure!(
        value.as_bytes()[..24].iter().all(|byte| *byte == 0),
        "value exceeds uint64"
    );
    Ok(u64::from_be_bytes(
        value.as_bytes()[24..].try_into().unwrap(),
    ))
}

pub(crate) fn words(value: &Value) -> anyhow::Result<Vec<Felt252>> {
    let raw = value
        .as_str()
        .context("expected ABI bytes")?
        .strip_prefix("0x")
        .context("ABI bytes lack prefix")?;
    let bytes = hex::decode(raw)?;
    ensure!(bytes.len().is_multiple_of(32), "malformed ABI words");
    Ok(bytes
        .as_chunks::<32>()
        .0
        .iter()
        .map(|chunk| Felt252(*chunk))
        .collect())
}
