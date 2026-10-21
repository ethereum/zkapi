//! Native ETH uses integer gwei in the existing proof ledger. The oracle quote
//! is part of the proof-bound lease payload. Admission checks it against the
//! live deployment configuration; settlement uses only the persisted quote
//! (intrinsic checks) and never refreshes or re-validates it against config.
use std::time::Duration;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

use crate::error::ServerError;

pub const UNITS_PER_ETH: u128 = 1_000_000_000;
pub const MAX_SAFE_UNITS: u128 = 9_007_199_254_740_991;

/// Immutable vault getters read at startup, all at block "latest".
pub const STATE_SIGNING_KEY_X_SELECTOR: &str = "0x15fa2a9a"; // stateSigningKeyX()
pub const STATE_SIGNING_KEY_Y_SELECTOR: &str = "0x230e2a24"; // stateSigningKeyY()
pub const CLEARANCE_SIGNING_KEY_X_SELECTOR: &str = "0xdc41d636"; // clearanceSigningKeyX()
pub const CLEARANCE_SIGNING_KEY_Y_SELECTOR: &str = "0x112cd6bc"; // clearanceSigningKeyY()
pub const CHALLENGE_PERIOD_SELECTOR: &str = "0xf3f480d9"; // challengePeriod()
/// Read by the root poller (O5) and after a clearance ownership proof verified.
pub const CURRENT_ROOT_SELECTOR: &str = "0xfdab463d"; // currentRoot()
/// Nullifier flags, read before signing (O7) and before serving request data.
pub const USED_NULLIFIERS_SELECTOR: &str = "0xaad24061"; // usedNullifiers(uint256)
pub const CHALLENGED_NULLIFIERS_SELECTOR: &str = "0x6cda756a"; // challengedNullifiers(uint256)
/// Every root the vault ever set (Amendment A1); read for a clearance
/// ownership proof at a root the server has not seen recently.
pub const KNOWN_ROOTS_SELECTOR: &str = "0x12ad7381"; // knownRoots(uint256)
/// keccak256 of `EscapeConcessionRecorded(uint32,uint256,uint128,uint128)`,
/// the event that names an escape's `nextNullifier` (§4.2 step 11). Its
/// nullifier is not indexed: a scan reads every such log and compares.
pub const ESCAPE_CONCESSION_RECORDED_TOPIC: &str =
    "0x2254ee827bce198564720fe77733ebfab1a49361cd4f050f107445241b560b4d";
/// The block span of one eth_getLogs call of a publication scan (the
/// indexer's default `--max-block-range`).
pub const PUBLICATION_SCAN_CHUNK_BLOCKS: u64 = 1_000;
/// The largest JSON-RPC response body read: a getter's word, or a block
/// header with its transaction hashes, or a chunk of logs.
const MAX_RESPONSE_BYTES: usize = 65_536;
const MAX_BLOCK_OR_LOGS_RESPONSE_BYTES: usize = 4 << 20;

#[derive(Clone)]
pub struct NativeBillingConfig {
    pub rpc_url: String,
    pub feed_address: String,
    pub decimals: u8,
    pub max_age_seconds: u64,
}

// RPC URLs commonly embed a provider API key.
impl std::fmt::Debug for NativeBillingConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeBillingConfig")
            .field("rpc_url", &"[redacted]")
            .field("feed_address", &self.feed_address)
            .field("decimals", &self.decimals)
            .field("max_age_seconds", &self.max_age_seconds)
            .finish()
    }
}

/// The vault's immutable signing keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultSigningKeys {
    pub state: CurvePointWire,
    pub clearance: CurvePointWire,
}

/// The vault address in the form used for RPC reads and the deployment
/// binding: 0x followed by 40 lowercase hex digits.
pub fn vault_address_hex(contract_address: &Felt252) -> String {
    let address = contract_address.to_hex();
    let body = address.strip_prefix("0x").unwrap_or(&address);
    format!("0x{body:0>40}")
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NativeBillingQuote {
    pub asset: String,
    pub units_per_eth: u64,
    pub chain_id: u64,
    pub feed_address: String,
    pub round_id: String,
    pub answer: String,
    pub decimals: u8,
    pub updated_at: u64,
    pub expires_at: u64,
}

fn invalid(message: &str) -> ServerError {
    ServerError::InvalidRequest(message.to_string())
}

fn decimal(value: &str) -> Result<u128, ServerError> {
    if value.is_empty()
        || value.len() > 39
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid("invalid native billing quote integer"));
    }
    value
        .parse()
        .map_err(|_| invalid("native billing quote integer overflow"))
}

/// A settlement charge clamped to the proof-bound budget before conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CappedCharge {
    /// Whole gwei; never above the request's solvency bound.
    pub charge: u128,
    /// The usage actually billed, in micro-USD (or OA credits).
    pub charged_micro_usd: u128,
    /// Reported usage exceeded the frozen budget.
    pub clamped: bool,
    /// The conversion overflowed; the charge is the solvency bound.
    pub conversion_overflow: bool,
}

impl NativeBillingQuote {
    /// Checks that depend only on the quote and the chain it was bound to,
    /// never on mutable deployment configuration. Settlement uses only these.
    pub fn validate_intrinsic(&self, chain_id: u64) -> Result<(), ServerError> {
        if self.asset != "native_eth"
            || self.units_per_eth != UNITS_PER_ETH as u64
            || self.chain_id != chain_id
            || !valid_address(&self.feed_address)
            || self.feed_address != self.feed_address.to_lowercase()
            || self.decimals > 18
            || self.updated_at == 0
            || self.expires_at <= self.updated_at
        {
            return Err(invalid("native billing quote is malformed"));
        }
        let round = decimal(&self.round_id)?;
        let price = decimal(&self.answer)?;
        if round == 0 || round >= (1u128 << 80) || price == 0 || price > 1_000_000_000_000_000_000 {
            return Err(invalid("native billing quote is outside supported bounds"));
        }
        Ok(())
    }

    /// Admission only: the intrinsic checks plus equality with the live
    /// deployment's feed, decimals and freshness policy.
    pub fn validate_identity(
        &self,
        config: &NativeBillingConfig,
        chain_id: u64,
    ) -> Result<(), ServerError> {
        if self.chain_id != chain_id
            || self.feed_address != config.feed_address.to_lowercase()
            || self.decimals != config.decimals
            || self.expires_at
                != self
                    .updated_at
                    .checked_add(config.max_age_seconds)
                    .ok_or_else(|| invalid("native billing quote expiry overflow"))?
        {
            return Err(invalid(
                "native billing quote does not match the pinned deployment",
            ));
        }
        self.validate_intrinsic(chain_id)
    }

    /// Convert measured usage to a charge that can never fail and never
    /// exceeds `solvency_bound`: usage is clamped to the frozen budget
    /// `limit_micro_usd(solvency_bound)` before conversion, and a conversion
    /// overflow charges the bound. Since limit <= U*P*1e6/S, the ceiling
    /// conversion of the clamped usage is already <= U.
    pub fn capped_charge_units(&self, usage_micro_usd: u128, solvency_bound: u128) -> CappedCharge {
        let Ok(limit) = self.limit_micro_usd(solvency_bound) else {
            // Unreachable for an admitted request: issuance computed the same
            // limit before reserving.
            return CappedCharge {
                charge: solvency_bound,
                charged_micro_usd: usage_micro_usd,
                clamped: true,
                conversion_overflow: true,
            };
        };
        let charged_micro_usd = usage_micro_usd.min(limit);
        let (charge, conversion_overflow) = match self.charge_units(charged_micro_usd) {
            Ok(charge) => (charge.min(solvency_bound), false),
            Err(_) => (solvency_bound, true),
        };
        CappedCharge {
            charge,
            charged_micro_usd,
            clamped: usage_micro_usd > limit,
            conversion_overflow,
        }
    }

    fn scale(&self) -> Result<u128, ServerError> {
        UNITS_PER_ETH
            .checked_mul(
                10u128
                    .checked_pow(self.decimals as u32)
                    .ok_or_else(|| invalid("native billing decimals overflow"))?,
            )
            .ok_or_else(|| invalid("native billing scale overflow"))
    }

    pub fn limit_micro_usd(&self, units: u128) -> Result<u128, ServerError> {
        if units == 0 || units > MAX_SAFE_UNITS {
            return Err(invalid(
                "native lease amount is outside browser-safe bounds",
            ));
        }
        let result = units
            .checked_mul(decimal(&self.answer)?)
            .and_then(|n| n.checked_mul(1_000_000))
            .ok_or_else(|| invalid("native billing budget overflow"))?
            / self.scale()?;
        if result == 0 || result > MAX_SAFE_UNITS {
            return Err(invalid(
                "native lease USD budget is outside supported bounds",
            ));
        }
        Ok(result)
    }

    pub fn charge_units(&self, micro_usd: u128) -> Result<u128, ServerError> {
        if micro_usd == 0 {
            return Ok(0);
        }
        let numerator = micro_usd
            .checked_mul(self.scale()?)
            .ok_or_else(|| invalid("native billing charge overflow"))?;
        let denominator = decimal(&self.answer)?
            .checked_mul(1_000_000)
            .ok_or_else(|| invalid("native billing price overflow"))?;
        if denominator == 0 {
            return Err(invalid("native billing price is zero"));
        }
        let value = numerator / denominator + u128::from(numerator % denominator != 0);
        if value > MAX_SAFE_UNITS {
            return Err(invalid(
                "native billing charge is outside browser-safe bounds",
            ));
        }
        Ok(value)
    }
}

pub struct NativeBillingOracle {
    config: NativeBillingConfig,
    chain_id: u64,
    contract_address: String,
    http: reqwest::Client,
}

impl NativeBillingOracle {
    pub fn new(
        config: NativeBillingConfig,
        chain_id: u64,
        contract_address: String,
    ) -> anyhow::Result<Self> {
        let url = reqwest::Url::parse(&config.rpc_url)?;
        anyhow::ensure!(
            url.scheme() == "https"
                || (url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "::1"))),
            "native oracle RPC requires HTTPS or loopback HTTP"
        );
        anyhow::ensure!(
            url.username().is_empty() && url.password().is_none() && url.fragment().is_none(),
            "native oracle RPC cannot contain credentials or a fragment"
        );
        anyhow::ensure!(
            valid_address(&config.feed_address) && valid_address(&contract_address),
            "native oracle and vault require nonzero Ethereum addresses"
        );
        anyhow::ensure!(
            config.decimals <= 18 && config.max_age_seconds > 0 && config.max_age_seconds <= 86_400,
            "invalid native oracle decimals or freshness limit"
        );
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            config,
            chain_id,
            contract_address,
            http,
        })
    }

    /// The oracle a server configuration pins: its chain and its vault.
    pub fn for_server(config: &crate::config::ServerConfig) -> anyhow::Result<Self> {
        let native = config
            .native_billing
            .clone()
            .ok_or_else(|| anyhow::anyhow!("native ETH billing configuration is required"))?;
        Self::new(
            native,
            config.chain_id,
            vault_address_hex(&config.contract_address),
        )
    }

    /// The chain the RPC actually serves.
    pub async fn rpc_chain_id(&self) -> Result<u64, ServerError> {
        self.rpc("eth_chainId", json!([]))
            .await?
            .as_str()
            .and_then(|s| s.strip_prefix("0x"))
            .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit()))
            .and_then(|s| u64::from_str_radix(s, 16).ok())
            .ok_or_else(|| invalid("native oracle RPC returned an invalid chain ID"))
    }

    /// One 32-byte field word from a vault getter at "latest".
    async fn vault_word(&self, selector: &str) -> Result<Felt252, ServerError> {
        decode_field_word(&self.call(&self.contract_address, selector).await?)
    }

    /// The vault's immutable stateSigningKeyX/Y and clearanceSigningKeyX/Y.
    pub async fn vault_signing_keys(&self) -> Result<VaultSigningKeys, ServerError> {
        Ok(VaultSigningKeys {
            state: CurvePointWire {
                x: self.vault_word(STATE_SIGNING_KEY_X_SELECTOR).await?,
                y: self.vault_word(STATE_SIGNING_KEY_Y_SELECTOR).await?,
            },
            clearance: CurvePointWire {
                x: self.vault_word(CLEARANCE_SIGNING_KEY_X_SELECTOR).await?,
                y: self.vault_word(CLEARANCE_SIGNING_KEY_Y_SELECTOR).await?,
            },
        })
    }

    /// The vault's immutable challengePeriod(), in seconds.
    pub async fn vault_challenge_period(&self) -> Result<u64, ServerError> {
        self.vault_word(CHALLENGE_PERIOD_SELECTOR)
            .await?
            .to_u64()
            .filter(|seconds| *seconds > 0)
            .ok_or_else(|| invalid("vault challenge period is zero or out of range"))
    }

    /// The vault's live currentRoot() at "latest", after an eth_chainId check.
    pub async fn vault_current_root(&self) -> Result<Felt252, ServerError> {
        async {
            self.assert_chain().await?;
            self.vault_word(CURRENT_ROOT_SELECTOR).await
        }
        .await
        .map_err(|error| ServerError::Internal(format!("vault read failed: {error}")))
    }

    /// Whether the vault ever set `root` (`knownRoots(root)`, Amendment A1)
    /// at "latest", after an eth_chainId check.
    pub async fn vault_known_root(&self, root: &Felt252) -> Result<bool, ServerError> {
        async {
            self.assert_chain().await?;
            let data = format!("{KNOWN_ROOTS_SELECTOR}{}", hex::encode(root.as_bytes()));
            let raw = self.call(&self.contract_address, &data).await?;
            if raw.len() != 66 {
                return Err(invalid("invalid vault knownRoots response length"));
            }
            match decode_word(&raw, 0)? {
                0 => Ok(false),
                1 => Ok(true),
                _ => Err(invalid("invalid vault knownRoots boolean")),
            }
        }
        .await
        .map_err(|error| ServerError::Internal(format!("vault read failed: {error}")))
    }

    /// One raw 32-byte word from a getter of the contract at `address`, at
    /// "latest", after an eth_chainId check.
    pub async fn contract_word(
        &self,
        address: &str,
        selector: &str,
    ) -> Result<[u8; 32], ServerError> {
        self.assert_chain().await?;
        let raw = self.call(address, selector).await?;
        let word = raw
            .strip_prefix("0x")
            .filter(|word| word.len() == 64)
            .ok_or_else(|| {
                invalid("getter returned no 32-byte word (is the contract deployed at this address on this chain?)")
            })?;
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(word, &mut bytes).map_err(|_| invalid("malformed ABI word"))?;
        Ok(bytes)
    }

    /// keccak256 of the runtime code at `address` at "latest" (eth_getCode),
    /// after an eth_chainId check. An address without code is an error.
    pub async fn code_hash(&self, address: &str) -> Result<[u8; 32], ServerError> {
        self.assert_chain().await?;
        let code = self
            .rpc("eth_getCode", json!([address, "latest"]))
            .await?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| invalid("invalid eth_getCode response"))?;
        let body = code
            .strip_prefix("0x")
            .ok_or_else(|| invalid("invalid eth_getCode response"))?;
        if body.is_empty() {
            return Err(invalid("no contract code at this address on this chain"));
        }
        let bytes = hex::decode(body).map_err(|_| invalid("invalid eth_getCode response"))?;
        Ok(Keccak256::digest(&bytes).into())
    }

    /// A vault `mapping(uint256 => bool)` flag at "latest" (usedNullifiers,
    /// challengedNullifiers), after an eth_chainId check.
    pub async fn nullifier_flag(
        &self,
        selector: &str,
        nullifier: &Felt252,
    ) -> Result<bool, ServerError> {
        self.assert_chain().await?;
        let data = format!("{selector}{}", hex::encode(nullifier.as_bytes()));
        let raw = self.call(&self.contract_address, &data).await?;
        if raw.len() != 66 {
            return Err(invalid("invalid vault nullifier response length"));
        }
        match decode_word(&raw, 0)? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(invalid("invalid vault nullifier boolean")),
        }
    }

    /// The number and timestamp of block `tag` ("latest" or a quantity).
    async fn block_time(&self, tag: Value) -> Result<(u64, u64), ServerError> {
        let block = self
            .rpc_limited(
                "eth_getBlockByNumber",
                json!([tag, false]),
                MAX_BLOCK_OR_LOGS_RESPONSE_BYTES,
            )
            .await?;
        let field = |name: &str| {
            block
                .get(name)
                .and_then(Value::as_str)
                .and_then(quantity)
                .ok_or_else(|| invalid("invalid block response"))
        };
        Ok((field("number")?, field("timestamp")?))
    }

    /// Whether the vault named `nullifier` as an escape's `nextNullifier`
    /// (`EscapeConcessionRecorded`) in any block from the last one before
    /// `since` (a UNIX time) to the latest, after an eth_chainId check. The
    /// first block of the window is found by bisection on block timestamps;
    /// its logs are read in calls of [`PUBLICATION_SCAN_CHUNK_BLOCKS`]. A
    /// window of more than `max_blocks` blocks, or any failed or malformed
    /// read, is an error, never "not named".
    pub async fn escape_named_next_nullifier(
        &self,
        nullifier: &Felt252,
        since: u64,
        max_blocks: u64,
    ) -> Result<bool, ServerError> {
        self.assert_chain().await?;
        let (latest, latest_time) = self.block_time(json!("latest")).await?;
        // `start` is at or before every block at `since`: a block with a
        // timestamp at most `since`, or the genesis. Timestamps increase
        // strictly on Ethereum, so going back `latest_time - since` blocks
        // reaches one; elsewhere the distance doubles until it does.
        let mut distance = latest_time.saturating_sub(since).max(1);
        let mut start = latest;
        let mut start_time = latest_time;
        while start > 0 && start_time > since {
            start = start.saturating_sub(distance);
            start_time = self.block_time(json!(format!("0x{start:x}"))).await?.1;
            distance = distance.saturating_mul(2);
        }
        // Narrow it to the last block before `since` when that saves calls.
        let mut after = latest;
        while start_time <= since && after - start > PUBLICATION_SCAN_CHUNK_BLOCKS {
            let middle = start + (after - start) / 2;
            let middle_time = self.block_time(json!(format!("0x{middle:x}"))).await?.1;
            if middle_time <= since {
                start = middle;
            } else {
                after = middle;
            }
        }
        if latest - start >= max_blocks {
            return Err(invalid("publication scan window exceeds its block limit"));
        }
        let wanted = format!("0x{}", hex::encode(nullifier.as_bytes()));
        let mut from = start;
        while from <= latest {
            let to = latest.min(from.saturating_add(PUBLICATION_SCAN_CHUNK_BLOCKS - 1));
            let logs = self
                .rpc_limited(
                    "eth_getLogs",
                    json!([{
                        "address": self.contract_address,
                        "topics": [ESCAPE_CONCESSION_RECORDED_TOPIC],
                        "fromBlock": format!("0x{from:x}"),
                        "toBlock": format!("0x{to:x}"),
                    }]),
                    MAX_BLOCK_OR_LOGS_RESPONSE_BYTES,
                )
                .await?;
            let logs = logs
                .as_array()
                .ok_or_else(|| invalid("invalid eth_getLogs response"))?;
            for log in logs {
                if next_nullifier_of(log, &self.contract_address)? == wanted {
                    return Ok(true);
                }
            }
            from = to + 1;
        }
        Ok(false)
    }

    async fn rpc(&self, method: &str, params: Value) -> Result<Value, ServerError> {
        self.rpc_limited(method, params, MAX_RESPONSE_BYTES).await
    }

    async fn rpc_limited(
        &self,
        method: &str,
        params: Value,
        limit: usize,
    ) -> Result<Value, ServerError> {
        let response = self
            .http
            .post(&self.config.rpc_url)
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| invalid("native billing oracle RPC unavailable"))?;
        if !response.status().is_success()
            || response.content_length().is_some_and(|n| n > limit as u64)
        {
            return Err(invalid("native billing oracle RPC rejected the read"));
        }
        let mut response = response;
        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| invalid("native billing oracle RPC unavailable"))?
        {
            if body.len().saturating_add(chunk.len()) > limit {
                return Err(invalid("native billing oracle RPC response too large"));
            }
            body.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&body)
            .map_err(|_| invalid("invalid native billing oracle RPC response"))?;
        if value.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
            || value.get("id").and_then(Value::as_u64) != Some(1)
        {
            return Err(invalid(
                "native billing oracle RPC response identity mismatch",
            ));
        }
        if value.get("error").is_some() {
            return Err(invalid("native billing oracle RPC call failed"));
        }
        value
            .get("result")
            .cloned()
            .ok_or_else(|| invalid("missing native billing oracle RPC result"))
    }

    async fn call(&self, address: &str, data: &str) -> Result<String, ServerError> {
        self.call_at(address, data, "latest").await
    }

    async fn call_at(&self, address: &str, data: &str, block: &str) -> Result<String, ServerError> {
        self.rpc("eth_call", json!([{ "to":address, "data":data }, block]))
            .await?
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| invalid("invalid oracle contract response"))
    }

    async fn assert_chain(&self) -> Result<(), ServerError> {
        if self.rpc_chain_id().await? != self.chain_id {
            return Err(invalid("native oracle RPC returned the wrong chain"));
        }
        Ok(())
    }

    /// A durable request reservation is not fresh authorization to issue access.
    /// Check the current vault state even on exact retries, without refreshing
    /// their proof-bound price/root. Call again after activation before exposing
    /// the provider secret, since withdrawal may occur during provider I/O.
    pub async fn assert_request_unspent(&self, nullifier: &Felt252) -> Result<(), ServerError> {
        let result = async {
            self.assert_chain().await?;
            let selector = Keccak256::digest(b"usedNullifiers(uint256)");
            let data = format!(
                "0x{}{}",
                hex::encode(&selector[..4]),
                hex::encode(nullifier.as_bytes())
            );
            let raw = self.call(&self.contract_address, &data).await?;
            if raw.len() != 66 {
                return Err(invalid("invalid vault nullifier response length"));
            }
            match decode_word(&raw, 0)? {
                0 => Ok(()),
                1 => Err(ServerError::NullifierUsed),
                _ => Err(invalid("invalid vault nullifier boolean")),
            }
        }
        .await;
        // A failed read is not evidence that the client's request is invalid.
        // Keep its reservation recoverable and tell the client it can retry.
        result.map_err(|error| match error {
            ServerError::NullifierUsed => error,
            _ => ServerError::Internal(format!("vault authorization check failed: {error}")),
        })
    }

    async fn assert_deployment(&self) -> Result<(), ServerError> {
        self.assert_chain().await?;
        let decimals = decode_word(
            &self.call(&self.config.feed_address, "0x313ce567").await?,
            0,
        )?;
        if decimals != self.config.decimals as u128 {
            return Err(invalid("native oracle decimals do not match deployment"));
        }
        // This getter is absent on legacy token vaults; do not permit a pricing-only relabel.
        let unit = decode_word(&self.call(&self.contract_address, "0x4d1352fd").await?, 0)?;
        if unit != 1_000_000_000 {
            return Err(invalid("vault is not the configured native ETH deployment"));
        }
        Ok(())
    }

    pub async fn quote(&self, now: u64) -> Result<NativeBillingQuote, ServerError> {
        self.assert_deployment().await?;
        // Finalized rounds cannot roll back during an ordinary head reorg.
        // This is also the price source for the SDK's displayed USD reference.
        let raw = self
            .call_at(&self.config.feed_address, "0xfeaf968c", "finalized")
            .await?;
        let quote = self.decode_quote(&raw)?;
        self.assert_fresh(&quote, now)?;
        Ok(quote)
    }

    pub async fn validate(&self, quote: &NativeBillingQuote, now: u64) -> Result<(), ServerError> {
        quote.validate_identity(&self.config, self.chain_id)?;
        self.assert_fresh(quote, now)?;
        self.assert_deployment().await?;
        let data = format!("0x9a6fc8f5{:064x}", decimal(&quote.round_id)?);
        if self.decode_quote(
            &self
                .call_at(&self.config.feed_address, &data, "finalized")
                .await?,
        )? != *quote
        {
            return Err(invalid(
                "native billing quote does not match its finalized on-chain oracle round",
            ));
        }
        let latest = self.decode_quote(
            &self
                .call_at(&self.config.feed_address, "0xfeaf968c", "finalized")
                .await?,
        )?;
        self.assert_fresh(&latest, now)?;
        if decimal(&latest.round_id)? > decimal(&quote.round_id)? {
            return Err(ServerError::NativeQuoteSuperseded);
        }
        if latest != *quote {
            return Err(invalid(
                "native billing quote is not the latest finalized oracle round",
            ));
        }
        Ok(())
    }

    fn decode_quote(&self, raw: &str) -> Result<NativeBillingQuote, ServerError> {
        if raw.len() != 2 + 5 * 64 {
            return Err(invalid("invalid oracle round data length"));
        }
        let round_id = decode_word(raw, 0)?;
        let started_at = decode_word(raw, 2)?;
        let updated_at_word = decode_word(raw, 3)?;
        let answered_in_round = decode_word(raw, 4)?;
        if started_at == 0 || started_at > updated_at_word || answered_in_round < round_id {
            return Err(invalid("native price oracle round is incomplete"));
        }
        let updated_at = u64::try_from(decode_word(raw, 3)?)
            .map_err(|_| invalid("oracle timestamp overflow"))?;
        let quote = NativeBillingQuote {
            asset: "native_eth".to_string(),
            units_per_eth: UNITS_PER_ETH as u64,
            chain_id: self.chain_id,
            feed_address: self.config.feed_address.to_lowercase(),
            round_id: decode_word(raw, 0)?.to_string(),
            answer: decode_word(raw, 1)?.to_string(),
            decimals: self.config.decimals,
            updated_at,
            expires_at: updated_at
                .checked_add(self.config.max_age_seconds)
                .ok_or_else(|| invalid("oracle expiry overflow"))?,
        };
        quote.validate_identity(&self.config, self.chain_id)?;
        Ok(quote)
    }

    pub(crate) fn assert_fresh(
        &self,
        quote: &NativeBillingQuote,
        now: u64,
    ) -> Result<(), ServerError> {
        if quote.updated_at > now {
            return Err(invalid("native ETH price is in the future"));
        }
        if quote.expires_at <= now {
            return Err(ServerError::NativeQuoteExpired);
        }
        Ok(())
    }
}

/// A JSON-RPC quantity: 0x and at most 16 hex digits.
fn quantity(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .filter(|digits| !digits.is_empty() && digits.len() <= 16)
        .and_then(|digits| u64::from_str_radix(digits, 16).ok())
}

/// The `nextNullifier` word (0x and 64 lowercase hex digits) of an
/// `EscapeConcessionRecorded` log of `vault`. Any other log in the answer
/// is malformed: the filter asked for this event of this vault only.
fn next_nullifier_of(log: &Value, vault: &str) -> Result<String, ServerError> {
    let malformed = || invalid("malformed EscapeConcessionRecorded log");
    let address = log
        .get("address")
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let topic = log
        .get("topics")
        .and_then(Value::as_array)
        .and_then(|topics| topics.first())
        .and_then(Value::as_str)
        .ok_or_else(malformed)?;
    let data = log
        .get("data")
        .and_then(Value::as_str)
        .and_then(|data| data.strip_prefix("0x"))
        .ok_or_else(malformed)?;
    if !address.eq_ignore_ascii_case(vault)
        || !topic.eq_ignore_ascii_case(ESCAPE_CONCESSION_RECORDED_TOPIC)
        || data.len() != 3 * 64
        || !data.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(malformed());
    }
    Ok(format!("0x{}", data[..64].to_ascii_lowercase()))
}

fn valid_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..].bytes().all(|b| b.is_ascii_hexdigit())
        && value[2..].bytes().any(|b| b != b'0')
}
/// Exactly one ABI word holding a BN254 field element, e.g. a vault key
/// coordinate (decode_word rejects values of 128 bits or more).
fn decode_field_word(raw: &str) -> Result<Felt252, ServerError> {
    let word = raw
        .strip_prefix("0x")
        .ok_or_else(|| invalid("malformed vault ABI word"))?;
    if word.is_empty() {
        return Err(invalid(
            "vault getter returned no 32-byte word (is the vault deployed at this address on this chain?)",
        ));
    }
    if word.len() != 64 || !word.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("malformed vault ABI word"));
    }
    Felt252::from_hex_checked(word)
        .map_err(|_| invalid("vault getter value is not a field element"))
}

fn decode_word(raw: &str, index: usize) -> Result<u128, ServerError> {
    let word = raw
        .strip_prefix("0x")
        .and_then(|s| s.get(index * 64..(index + 1) * 64))
        .ok_or_else(|| invalid("malformed oracle ABI response"))?;
    if !word.bytes().all(|b| b.is_ascii_hexdigit()) || !word[..32].bytes().all(|b| b == b'0') {
        return Err(invalid("oracle value is negative or oversized"));
    }
    u128::from_str_radix(&word[32..], 16).map_err(|_| invalid("malformed oracle integer"))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn quote() -> NativeBillingQuote {
        NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 11155111,
            feed_address: "0x694aa1769357215de4fac081bf1f309adc325306".into(),
            round_id: "123".into(),
            answer: "250012345678".into(),
            decimals: 8,
            updated_at: 1_700_000_000,
            expires_at: 1_700_003_600,
        }
    }
    #[test]
    fn conservative_round_trip() {
        let q = quote();
        for units in [1u128, 99, 400_000, 2_000_000, 10_000_000] {
            let budget = q.limit_micro_usd(units).unwrap();
            assert!(q.charge_units(budget).unwrap() <= units);
            assert_eq!(q.charge_units(0).unwrap(), 0);
        }
    }
    #[test]
    fn one_micro_dollar_never_rounds_to_free() {
        assert_eq!(quote().charge_units(1).unwrap(), 1);
    }
    #[test]
    fn malformed_and_out_of_range_fail() {
        assert!(decimal("01").is_err());
        assert!(decimal("-1").is_err());
        assert!(quote().limit_micro_usd(MAX_SAFE_UNITS + 1).is_err());
        assert!(decode_word(&format!("0x{}", "f".repeat(64)), 0).is_err());
    }

    #[test]
    fn capped_charge_clamps_before_conversion_and_never_exceeds_bound() {
        let q = NativeBillingQuote {
            answer: "250000000000".into(), // $2,500/ETH, 8 decimals
            ..quote()
        };
        let bound = 50_000u128;
        let limit = q.limit_micro_usd(bound).unwrap();
        assert_eq!(limit, 125_000);
        for (usage, clamped) in [
            (u128::MAX, true),
            (1_000_000_000_000_000_000, true),
            (limit + 1, true),
            (limit, false),
            (limit - 1, false),
            (1, false),
            (0, false),
        ] {
            let capped = q.capped_charge_units(usage, bound);
            assert!(capped.charge <= bound, "{usage}");
            assert_eq!(capped.clamped, clamped, "{usage}");
            assert!(!capped.conversion_overflow, "{usage}");
            assert_eq!(capped.charged_micro_usd, usage.min(limit));
            assert_eq!(capped.charge, q.charge_units(usage.min(limit)).unwrap());
        }
        assert_eq!(q.capped_charge_units(0, bound).charge, 0);
        assert_eq!(q.capped_charge_units(u128::MAX, bound).charge, bound);
        // A plain conversion of the same over-limit usage fails outright.
        assert!(q.charge_units(1_000_000_000_000_000_000).is_err());
        // An unrepresentable budget charges the bound rather than failing.
        let capped = q.capped_charge_units(1, MAX_SAFE_UNITS + 1);
        assert!(capped.conversion_overflow && capped.charge == MAX_SAFE_UNITS + 1);
    }

    #[test]
    fn capped_charge_survives_conversion_overflow_at_18_decimals() {
        let q = NativeBillingQuote {
            decimals: 18,
            answer: "1000000000000000000".into(), // $1/ETH at 18 decimals
            ..quote()
        };
        // U * price * 1e6 overflows u128, so neither the budget nor a plain
        // conversion of a comparable usage can be computed.
        assert!(q.limit_micro_usd(MAX_SAFE_UNITS).is_err());
        assert!(q.charge_units(1_000_000_000_000).is_err());
        for usage in [0, 1, 1_000_000_000_000, u128::MAX] {
            let capped = q.capped_charge_units(usage, MAX_SAFE_UNITS);
            assert_eq!(capped.charge, MAX_SAFE_UNITS, "{usage}");
            assert!(capped.conversion_overflow, "{usage}");
        }
        // Below the overflow region the clamp-then-convert result is exact.
        let bound = 1_000_000_000;
        let limit = q.limit_micro_usd(bound).unwrap();
        let capped = q.capped_charge_units(u128::MAX, bound);
        assert_eq!(capped.charge, q.charge_units(limit).unwrap());
        assert!(capped.charge <= bound && capped.clamped && !capped.conversion_overflow);
    }

    #[test]
    fn intrinsic_validation_is_config_independent() {
        let q = quote();
        let config = NativeBillingConfig {
            rpc_url: "https://example.com".into(),
            feed_address: q.feed_address.clone(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        q.validate_identity(&config, 11155111).unwrap();
        q.validate_intrinsic(11155111).unwrap();
        for changed in [
            NativeBillingConfig {
                max_age_seconds: 7200,
                ..config.clone()
            },
            NativeBillingConfig {
                decimals: 9,
                ..config.clone()
            },
            NativeBillingConfig {
                feed_address: "0x0000000000000000000000000000000000000abc".into(),
                ..config.clone()
            },
        ] {
            assert!(q.validate_identity(&changed, 11155111).is_err());
            q.validate_intrinsic(11155111).unwrap();
        }
        for malformed in [
            NativeBillingQuote {
                expires_at: q.updated_at,
                ..q.clone()
            },
            NativeBillingQuote {
                expires_at: q.updated_at - 1,
                ..q.clone()
            },
            NativeBillingQuote {
                updated_at: 0,
                ..q.clone()
            },
            NativeBillingQuote {
                decimals: 19,
                ..q.clone()
            },
            NativeBillingQuote {
                asset: "erc20".into(),
                ..q.clone()
            },
            NativeBillingQuote {
                units_per_eth: 1,
                ..q.clone()
            },
            NativeBillingQuote {
                feed_address: q.feed_address.to_uppercase().replace("0X", "0x"),
                ..q.clone()
            },
            NativeBillingQuote {
                feed_address: "0x0000000000000000000000000000000000000000".into(),
                ..q.clone()
            },
            NativeBillingQuote {
                answer: "0".into(),
                ..q.clone()
            },
            NativeBillingQuote {
                round_id: "0".into(),
                ..q.clone()
            },
        ] {
            assert!(
                malformed.validate_intrinsic(11155111).is_err(),
                "{malformed:?}"
            );
            assert!(malformed.validate_identity(&config, 11155111).is_err());
        }
        assert!(q.validate_intrinsic(1).is_err());
    }

    #[tokio::test]
    async fn vault_word_reads_selectors_at_latest_after_chain_check() {
        use axum::{routing::post, Json, Router};
        use std::sync::{Arc, Mutex};
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let recorded = calls.clone();
        let root =
            Felt252::from_hex("0x2a1b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f80")
                .unwrap();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let calls = recorded.clone();
                async move {
                    calls.lock().unwrap().push(request.clone());
                    let result = match request["method"].as_str() {
                        Some("eth_chainId") => "0xaa36a7".to_string(),
                        _ if request["params"][0]["data"] == CURRENT_ROOT_SELECTOR => {
                            format!("0x{}", hex::encode(root.as_bytes()))
                        }
                        _ => format!("0x{:064x}", 86_400),
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let vault = "0x0000000000000000000000000000000000000001";
        let oracle = NativeBillingOracle::new(
            NativeBillingConfig {
                rpc_url,
                feed_address: quote().feed_address,
                decimals: 8,
                max_age_seconds: 3600,
            },
            11155111,
            vault.into(),
        )
        .unwrap();
        assert_eq!(oracle.vault_current_root().await.unwrap(), root);
        assert_eq!(oracle.vault_challenge_period().await.unwrap(), 86_400);
        {
            let calls = calls.lock().unwrap();
            assert_eq!(calls.len(), 3);
            assert_eq!(calls[0]["method"], "eth_chainId");
            assert_eq!(
                calls[1]["params"],
                json!([{"to":vault, "data":"0xfdab463d"}, "latest"])
            );
            assert_eq!(
                calls[2]["params"],
                json!([{"to":vault, "data":"0xf3f480d9"}, "latest"])
            );
        }
        // The runtime root read refuses an RPC on another chain.
        let other_chain = NativeBillingOracle::new(
            NativeBillingConfig {
                rpc_url: oracle.config.rpc_url.clone(),
                ..oracle.config.clone()
            },
            1,
            vault.into(),
        )
        .unwrap();
        let before = calls.lock().unwrap().len();
        assert!(matches!(
            other_chain.vault_current_root().await,
            Err(ServerError::Internal(message)) if message.starts_with("vault read failed")
        ));
        assert_eq!(calls.lock().unwrap().len(), before + 1);
        server.abort();
    }
    #[test]
    fn vault_signing_key_selectors_match_abi() {
        for (signature, selector) in [
            ("stateSigningKeyX()", STATE_SIGNING_KEY_X_SELECTOR),
            ("stateSigningKeyY()", STATE_SIGNING_KEY_Y_SELECTOR),
            ("clearanceSigningKeyX()", CLEARANCE_SIGNING_KEY_X_SELECTOR),
            ("clearanceSigningKeyY()", CLEARANCE_SIGNING_KEY_Y_SELECTOR),
            ("challengePeriod()", CHALLENGE_PERIOD_SELECTOR),
            ("currentRoot()", CURRENT_ROOT_SELECTOR),
            ("knownRoots(uint256)", KNOWN_ROOTS_SELECTOR),
        ] {
            let digest = Keccak256::digest(signature.as_bytes());
            assert_eq!(selector, format!("0x{}", hex::encode(&digest[..4])));
        }
        assert_eq!(CURRENT_ROOT_SELECTOR, "0xfdab463d");
        assert_eq!(KNOWN_ROOTS_SELECTOR, "0x12ad7381");
        assert_eq!(
            ESCAPE_CONCESSION_RECORDED_TOPIC,
            format!(
                "0x{}",
                hex::encode(Keccak256::digest(
                    b"EscapeConcessionRecorded(uint32,uint256,uint128,uint128)"
                ))
            )
        );
        // Independent literals from the ABI, rather than the encoder above.
        assert_eq!(
            [
                STATE_SIGNING_KEY_X_SELECTOR,
                STATE_SIGNING_KEY_Y_SELECTOR,
                CLEARANCE_SIGNING_KEY_X_SELECTOR,
                CLEARANCE_SIGNING_KEY_Y_SELECTOR,
                CHALLENGE_PERIOD_SELECTOR
            ],
            [
                "0x15fa2a9a",
                "0x230e2a24",
                "0xdc41d636",
                "0x112cd6bc",
                "0xf3f480d9"
            ]
        );
    }

    /// The getters, the EscapeConcessionRecorded topic and its data layout
    /// are the real vault's (vault_calldata_golden.json, from the compiled
    /// protocol/contracts sources): `nextNullifier` is data word 0 of three.
    #[test]
    fn vault_reads_match_the_real_vault() {
        use crate::test_support::{real_event, real_getter_words, real_selector};
        for (name, selector) in [
            ("stateSigningKeyX", STATE_SIGNING_KEY_X_SELECTOR),
            ("stateSigningKeyY", STATE_SIGNING_KEY_Y_SELECTOR),
            ("clearanceSigningKeyX", CLEARANCE_SIGNING_KEY_X_SELECTOR),
            ("clearanceSigningKeyY", CLEARANCE_SIGNING_KEY_Y_SELECTOR),
            ("challengePeriod", CHALLENGE_PERIOD_SELECTOR),
            ("currentRoot", CURRENT_ROOT_SELECTOR),
            ("usedNullifiers", USED_NULLIFIERS_SELECTOR),
            ("challengedNullifiers", CHALLENGED_NULLIFIERS_SELECTOR),
            ("knownRoots", KNOWN_ROOTS_SELECTOR),
        ] {
            assert_eq!(real_selector(name), selector, "{name}");
        }
        // knownRoots(root) answers one boolean word.
        assert_eq!(real_getter_words("knownRoots"), 1);
        let (topics, data) = real_event("EscapeConcessionRecorded");
        assert_eq!(topics[0], ESCAPE_CONCESSION_RECORDED_TOPIC);
        let vault = "0x00000000000000000000000000000000000000aa";
        let log = json!({"address": vault, "topics": topics, "data": data});
        // emit EscapeConcessionRecorded(7, 0x0202, 1_000_000, 100_000).
        assert_eq!(
            next_nullifier_of(&log, vault).unwrap(),
            format!("0x{:064x}", 0x0202)
        );
    }

    #[test]
    fn decode_field_word_rejects_short_and_out_of_field_words() {
        let error = decode_field_word("0x").unwrap_err().to_string();
        assert!(error.contains("no 32-byte word"), "{error}");
        for malformed in [
            String::new(),
            "0x0".into(),
            format!("0x{}", "0".repeat(63)),
            format!("0x{}", "0".repeat(65)),
            format!("0x{}", "0".repeat(128)),
            format!("0x{}g", "0".repeat(63)),
            format!("0x+{}", "0".repeat(63)),
            "0".repeat(64),
        ] {
            let error = decode_field_word(&malformed).unwrap_err().to_string();
            assert!(
                error.contains("malformed vault ABI word"),
                "{malformed}: {error}"
            );
        }
        let modulus = zkapi_types::FIELD_MODULUS_HEX.trim_start_matches("0x");
        let error = decode_field_word(&format!("0x{modulus:0>64}"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("not a field element"), "{error}");
        assert!(decode_field_word(&format!("0x{}", "f".repeat(64))).is_err());
        // Key coordinates are full-width field elements, unlike decode_word values.
        let coordinate =
            crate::signer::ServerSigner::new(&Felt252::from_u64(7), &Felt252::from_u64(8))
                .state_public_key()
                .x;
        assert!(coordinate.to_u128().is_none());
        assert_eq!(
            decode_field_word(&format!("0x{}", hex::encode(coordinate.as_bytes()))).unwrap(),
            coordinate
        );
    }

    /// The publication scan behind recovery's indexer fallback: it finds
    /// the first block of its window by bisection on timestamps, reads the
    /// vault's EscapeConcessionRecorded logs from there to the latest block
    /// in chunks, and refuses a window above its limit, a malformed log and
    /// a wrong chain.
    #[tokio::test]
    async fn the_publication_scan_reads_the_vaults_successor_nullifiers_since_a_time() {
        use axum::{routing::post, Json, Router};
        use std::sync::{Arc, Mutex};
        const LATEST: u64 = 100_000;
        const GENESIS_TIME: u64 = 1_600_000_000;
        let time = |block: u64| GENESIS_TIME + 12 * block;
        #[derive(Default)]
        struct Chain {
            /// (block, data) of each EscapeConcessionRecorded log.
            logs: Vec<(u64, String)>,
            ranges: Vec<(u64, u64)>,
            block_reads: usize,
            chain_id: &'static str,
        }
        let chain = Arc::new(Mutex::new(Chain {
            chain_id: "0xaa36a7",
            ..Default::default()
        }));
        let vault = "0x00000000000000000000000000000000000000aa";
        let quantity = |value: &Value| {
            u64::from_str_radix(value.as_str().unwrap().trim_start_matches("0x"), 16).unwrap()
        };
        let app = Router::new().route(
            "/",
            post({
                let chain = chain.clone();
                move |Json(request): Json<Value>| {
                    let chain = chain.clone();
                    async move {
                        let mut chain = chain.lock().unwrap();
                        let params = &request["params"];
                        let result = match request["method"].as_str().unwrap() {
                            "eth_chainId" => json!(chain.chain_id),
                            "eth_getBlockByNumber" => {
                                chain.block_reads += 1;
                                let number = if params[0] == "latest" {
                                    LATEST
                                } else {
                                    quantity(&params[0])
                                };
                                assert_eq!(params[1], false);
                                json!({"number": format!("0x{number:x}"),
                                    "timestamp": format!("0x{:x}", time(number)),
                                    "transactions": []})
                            }
                            "eth_getLogs" => {
                                let filter = &params[0];
                                assert_eq!(filter["address"], vault);
                                assert_eq!(
                                    filter["topics"],
                                    json!([ESCAPE_CONCESSION_RECORDED_TOPIC])
                                );
                                let range =
                                    (quantity(&filter["fromBlock"]), quantity(&filter["toBlock"]));
                                chain.ranges.push(range);
                                let logs: Vec<Value> = chain
                                    .logs
                                    .iter()
                                    .filter(|(block, _)| (range.0..=range.1).contains(block))
                                    .map(|(block, data)| {
                                        json!({"address": vault,
                                            "topics": [ESCAPE_CONCESSION_RECORDED_TOPIC,
                                                format!("0x{:064x}", 7)],
                                            "data": data,
                                            "blockNumber": format!("0x{block:x}")})
                                    })
                                    .collect();
                                json!(logs)
                            }
                            method => panic!("unexpected {method}"),
                        };
                        Json(json!({"jsonrpc": "2.0", "id": 1, "result": result}))
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let oracle = NativeBillingOracle::new(
            NativeBillingConfig {
                rpc_url,
                feed_address: quote().feed_address,
                decimals: 8,
                max_age_seconds: 3600,
            },
            11155111,
            vault.into(),
        )
        .unwrap();
        let named = Felt252::from_u64(0x4e);
        let data = |nullifier: &Felt252| {
            format!(
                "0x{}{:064x}{:064x}",
                hex::encode(nullifier.as_bytes()),
                5_000_000u64,
                0
            )
        };
        // The window starts within a chunk before the first block at `since`.
        let since = time(95_000) + 5;
        let first_at_since = 95_001;
        {
            let mut chain = chain.lock().unwrap();
            chain.logs.push((94_000, data(&named)));
            chain.logs.push((99_999, data(&Felt252::from_u64(0x99))));
        }
        assert!(!oracle
            .escape_named_next_nullifier(&named, since, 50_000)
            .await
            .unwrap());
        let (ranges, block_reads) = {
            let chain = chain.lock().unwrap();
            (chain.ranges.clone(), chain.block_reads)
        };
        let start = ranges[0].0;
        assert!(
            start <= first_at_since && first_at_since - start <= PUBLICATION_SCAN_CHUNK_BLOCKS,
            "{start}"
        );
        assert!(block_reads <= 12, "{block_reads}");
        // Contiguous chunks of at most PUBLICATION_SCAN_CHUNK_BLOCKS up to the latest.
        let mut next = start;
        for (from, to) in &ranges {
            assert_eq!(*from, next);
            assert!(to - from < PUBLICATION_SCAN_CHUNK_BLOCKS);
            next = to + 1;
        }
        assert_eq!(next, LATEST + 1);
        // A log in the window names it.
        chain.lock().unwrap().logs.push((95_500, data(&named)));
        assert!(oracle
            .escape_named_next_nullifier(&named, since, 50_000)
            .await
            .unwrap());
        // A window above the limit is refused, never "not named".
        let error = oracle
            .escape_named_next_nullifier(&named, time(10_000), 50_000)
            .await
            .unwrap_err()
            .to_string();
        assert!(error.contains("block limit"), "{error}");
        // A malformed log fails the scan.
        chain.lock().unwrap().logs.push((99_000, "0x1234".into()));
        assert!(oracle
            .escape_named_next_nullifier(&Felt252::from_u64(0x77), since, 50_000)
            .await
            .is_err());
        // So does a wrong chain.
        chain.lock().unwrap().logs.pop();
        chain.lock().unwrap().chain_id = "0x1";
        assert!(oracle
            .escape_named_next_nullifier(&named, since, 50_000)
            .await
            .is_err());
        task.abort();
    }

    #[test]
    fn server_oracle_pins_the_configured_vault_address() {
        assert_eq!(
            vault_address_hex(&Felt252::from_hex("0xABCDEF").unwrap()),
            "0x0000000000000000000000000000000000abcdef"
        );
        let config = crate::config::ServerConfig {
            contract_address: Felt252::from_u64(0x1234),
            native_billing: Some(crate::test_support::native_config()),
            ..Default::default()
        };
        let oracle = NativeBillingOracle::for_server(&config).unwrap();
        assert_eq!(
            oracle.contract_address,
            "0x0000000000000000000000000000000000001234"
        );
        assert_eq!(oracle.chain_id, config.chain_id);
        let error = NativeBillingOracle::for_server(&crate::config::ServerConfig::default())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("native ETH billing configuration is required"));
        assert!(!format!("{:?}", crate::test_support::native_config()).contains("127.0.0.1:9"));
    }

    #[test]
    fn quote_identity_is_exact() {
        let mut q = quote();
        let c = NativeBillingConfig {
            rpc_url: "https://example.com".into(),
            feed_address: q.feed_address.clone(),
            decimals: 8,
            max_age_seconds: 3600,
        };
        assert!(q.validate_identity(&c, 11155111).is_ok());
        q.expires_at += 1;
        assert!(q.validate_identity(&c, 11155111).is_err());
    }

    #[tokio::test]
    async fn issuance_authorization_requires_an_explicit_unspent_vault_response() {
        use axum::{routing::post, Json, Router};
        use std::sync::{Arc, Mutex};

        let chain = Arc::new(Mutex::new(json!("0xaa36a7")));
        let response = Arc::new(Mutex::new(json!({
            "jsonrpc":"2.0", "id":1, "result":format!("0x{:064x}", 0)
        })));
        let calls = Arc::new(Mutex::new(Vec::<Value>::new()));
        let app = Router::new().route("/", post({
            let chain = chain.clone();
            let response = response.clone();
            let calls = calls.clone();
            move |Json(request): Json<Value>| {
                let chain = chain.clone();
                let response = response.clone();
                let calls = calls.clone();
                async move {
                    calls.lock().unwrap().push(request.clone());
                    if request["method"] == "eth_chainId" {
                        Json(json!({"jsonrpc":"2.0", "id":1, "result":chain.lock().unwrap().clone()}))
                    } else {
                        Json(response.lock().unwrap().clone())
                    }
                }
            }
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let vault = "0x0000000000000000000000000000000000000001";
        let oracle = NativeBillingOracle::new(
            NativeBillingConfig {
                rpc_url,
                feed_address: quote().feed_address,
                decimals: 8,
                max_age_seconds: 3600,
            },
            11155111,
            vault.into(),
        )
        .unwrap();
        let nullifier = Felt252::from_u64(123);
        oracle.assert_request_unspent(&nullifier).await.unwrap();
        {
            let requests = calls.lock().unwrap();
            assert_eq!(requests.len(), 2);
            assert_eq!(requests[0]["method"], "eth_chainId");
            assert_eq!(requests[1]["method"], "eth_call");
            // Independent known selector and ABI word, rather than repeating
            // the production encoder, guard the queried mapping and key.
            assert_eq!(
                requests[1]["params"],
                json!([
                    {"to":vault, "data":format!("0xaad24061{:064x}", 123)}, "latest"
                ])
            );
        }
        *response.lock().unwrap() =
            json!({"jsonrpc":"2.0", "id":1, "result":format!("0x{:064x}", 1)});
        assert!(matches!(
            oracle.assert_request_unspent(&nullifier).await,
            Err(ServerError::NullifierUsed)
        ));
        for malformed in [
            json!({"jsonrpc":"2.0", "id":1, "result":"0x"}),
            json!({"jsonrpc":"2.0", "id":1, "result":"0x0"}),
            json!({"jsonrpc":"2.0", "id":1, "result":format!("0x{:064x}", 2)}),
            json!({"jsonrpc":"2.0", "id":1, "result":format!("0x{}", "f".repeat(64))}),
            json!({"jsonrpc":"2.0", "id":1, "result":format!("0x{}", "0".repeat(128))}),
            json!({"jsonrpc":"2.0", "id":1, "result":false}),
            json!({"jsonrpc":"2.0", "id":1, "error":{"code":-32000}}),
            json!({"jsonrpc":"2.0", "id":2, "result":format!("0x{:064x}", 0)}),
        ] {
            *response.lock().unwrap() = malformed;
            let error = oracle.assert_request_unspent(&nullifier).await.unwrap_err();
            assert!(matches!(error, ServerError::Internal(_)));
            assert!(error.is_retriable());
        }
        *response.lock().unwrap() =
            json!({"jsonrpc":"2.0", "id":1, "result":format!("0x{:064x}", 0)});
        for wrong_chain in [
            json!("0x1"),
            json!("0xaa36a8"),
            json!(11155111),
            json!("junk"),
        ] {
            *chain.lock().unwrap() = wrong_chain;
            let before = calls.lock().unwrap().len();
            assert!(matches!(
                oracle.assert_request_unspent(&nullifier).await,
                Err(ServerError::Internal(_))
            ));
            assert_eq!(calls.lock().unwrap().len(), before + 1);
        }
        task.abort();
        let _ = task.await;
        assert!(matches!(
            oracle.assert_request_unspent(&nullifier).await,
            Err(ServerError::Internal(_))
        ));
    }

    #[tokio::test]
    async fn oracle_checks_chain_vault_round_and_freshness() {
        use axum::{routing::post, Json, Router};
        use std::sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        };
        let price = Arc::new(AtomicU64::new(250_012_345_678));
        let response_price = price.clone();
        let round_state = Arc::new(AtomicU64::new(0));
        let response_round_state = round_state.clone();
        let app = Router::new().route(
            "/",
            post(move |Json(request): Json<Value>| {
                let price = response_price.clone();
                let round_state = response_round_state.clone();
                async move {
                    let data = request["params"][0]["data"].as_str().unwrap_or("");
                    let result = if request["method"] == "eth_chainId" {
                        "0xaa36a7".to_string()
                    } else if data == "0x313ce567" {
                        format!("0x{:064x}", 8)
                    } else if data == "0x4d1352fd" {
                        format!("0x{:064x}", 1_000_000_000)
                    } else {
                        let state = round_state.load(Ordering::SeqCst);
                        let started = match state {
                            1 => 0,
                            2 => 1_700_000_001,
                            _ => 1_700_000_000,
                        };
                        let answered = if state == 3 { 122 } else { 123 };
                        format!(
                            "0x{:064x}{:064x}{:064x}{:064x}{:064x}",
                            123,
                            price.load(Ordering::SeqCst),
                            started,
                            1_700_000_000u64,
                            answered
                        )
                    };
                    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let rpc_url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let config = NativeBillingConfig {
            rpc_url,
            feed_address: quote().feed_address,
            decimals: 8,
            max_age_seconds: 3600,
        };
        let oracle = NativeBillingOracle::new(
            config.clone(),
            11155111,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        for incomplete_state in 1..=3 {
            round_state.store(incomplete_state, Ordering::SeqCst);
            assert!(oracle.quote(1_700_000_001).await.is_err());
        }
        round_state.store(0, Ordering::SeqCst);
        let saved = oracle.quote(1_700_000_001).await.unwrap();
        oracle.validate(&saved, 1_700_000_002).await.unwrap();
        assert!(oracle.validate(&saved, 1_700_003_600).await.is_err());
        assert!(oracle.validate(&saved, 1_700_003_601).await.is_err());
        assert!(oracle.validate(&saved, 1_699_999_999).await.is_err());
        price.store(300_000_000_000, Ordering::SeqCst);
        assert!(oracle.validate(&saved, 1_700_000_003).await.is_err());
        let wrong_chain = NativeBillingOracle::new(
            config,
            1,
            "0x0000000000000000000000000000000000000001".into(),
        )
        .unwrap();
        assert!(wrong_chain.quote(1_700_000_001).await.is_err());
        task.abort();
    }
}
