//! Native ETH quote checks. Never trust the payment server's conversion alone.
use crate::{config::AuthConfig, error::AuthError};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Quote {
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
fn invalid() -> AuthError {
    AuthError::Wallet(
        "native ETH billing quote is invalid, stale, or disagrees with the finalized oracle".into(),
    )
}
fn decimal(value: &str) -> Result<u128, AuthError> {
    if value.is_empty()
        || value.len() > 39
        || !value.bytes().all(|b| b.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}
fn lowercase_address(value: &str) -> bool {
    value.len() == 42
        && value.starts_with("0x")
        && value[2..]
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value[2..].bytes().any(|b| b != b'0')
}
impl Quote {
    /// Checks that depend only on the quote and the chain it was bound to. A
    /// saved request's quote is proof-bound: comparing it with pins changed
    /// since (feed, decimals, maximum age) would strand its receipt.
    pub fn validate_intrinsic(&self, chain_id: u64) -> Result<(), AuthError> {
        let round = decimal(&self.round_id)?;
        let answer = decimal(&self.answer)?;
        if self.asset != "native_eth"
            || self.units_per_eth != 1_000_000_000
            || self.chain_id != chain_id
            || !lowercase_address(&self.feed_address)
            // budget_units and usd_micros assume an 8-decimal answer.
            || self.decimals != 8
            || round == 0
            || round >= 1u128 << 80
            || answer == 0
            || answer > 1_000_000_000_000_000_000
            || self.updated_at == 0
            || self.expires_at <= self.updated_at
            || self.expires_at - self.updated_at > 86400
        {
            return Err(invalid());
        }
        Ok(())
    }
    /// Whether the live native billing configuration, or its pinned feed,
    /// decimals or maximum age, would refuse this quote, whatever the clock.
    pub fn conflicts_with_pins(&self, config: &AuthConfig) -> bool {
        config.billing_asset != "native_eth"
            || config.billing_unit != "gwei"
            || config.native_asset_wei_per_unit != "1000000000"
            || config.demo_billing_token_address.is_some()
            || config.native_price_feed_decimals != 8
            || config.native_price_max_age_seconds == 0
            || config.native_price_max_age_seconds > 86400
            || self.feed_address != config.native_price_feed_address.to_ascii_lowercase()
            || self.decimals != config.native_price_feed_decimals
            || self
                .updated_at
                .checked_add(config.native_price_max_age_seconds)
                != Some(self.expires_at)
    }
    /// New admissions only: also require the live pinned feed, decimals and
    /// maximum age, and an unexpired quote.
    pub fn validate(&self, config: &AuthConfig) -> Result<(), AuthError> {
        self.validate_intrinsic(config.chain_id)?;
        if self.conflicts_with_pins(config)
            || self.updated_at > crate::service::now_seconds()
            || self.expires_at <= crate::service::now_seconds()
        {
            return Err(invalid());
        }
        Ok(())
    }
    pub fn budget_units(&self, micro_usd: u128) -> Result<u128, AuthError> {
        if ![1_000_000, 2_000_000, 3_000_000, 4_500_000, 6_000_000].contains(&micro_usd) {
            return Err(invalid());
        }
        let numerator = micro_usd
            .checked_mul(100_000_000_000_000_000u128)
            .ok_or_else(invalid)?;
        let denominator = decimal(&self.answer)?
            .checked_mul(1_000_000)
            .ok_or_else(invalid)?;
        let units = numerator / denominator + u128::from(numerator % denominator != 0);
        if units == 0 || units > 9_007_199_254_740_991 {
            return Err(invalid());
        }
        Ok(units)
    }
    pub fn usd_micros(&self, units: u128) -> Result<u128, AuthError> {
        if units == 0 || units > 9_007_199_254_740_991 {
            return Err(invalid());
        }
        let value = units
            .checked_mul(decimal(&self.answer)?)
            .and_then(|n| n.checked_mul(1_000_000))
            .ok_or_else(invalid)?
            / 100_000_000_000_000_000u128;
        if value == 0 || value > 9_007_199_254_740_991 {
            return Err(invalid());
        }
        Ok(value)
    }
}
async fn json_response(mut response: reqwest::Response) -> Result<Value, AuthError> {
    if !response.status().is_success() {
        return Err(invalid());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| invalid())? {
        if body.len() + chunk.len() > 65536 {
            return Err(invalid());
        }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&body).map_err(|_| invalid())
}
async fn rpc(config: &AuthConfig, method: &str, params: Value) -> Result<Value, AuthError> {
    let url = config.demo_rpc_url.as_ref().ok_or_else(invalid)?;
    let body = json_response(
        crate::service::fresh_private_http()?
            .post(url)
            .timeout(std::time::Duration::from_secs(20))
            .json(&json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}))
            .send()
            .await
            .map_err(|_| invalid())?,
    )
    .await?;
    if body["jsonrpc"] != "2.0" || body["id"] != 1 || body.get("error").is_some() {
        return Err(invalid());
    }
    body.get("result").cloned().ok_or_else(invalid)
}
fn hex_u128(value: &Value) -> Result<u128, AuthError> {
    let text = value
        .as_str()
        .and_then(|v| v.strip_prefix("0x"))
        .ok_or_else(invalid)?;
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    u128::from_str_radix(text.trim_start_matches('0').trim(), 16)
        .or_else(|_| {
            if text.bytes().all(|b| b == b'0') {
                Ok(0)
            } else {
                Err(())
            }
        })
        .map_err(|_| invalid())
}
fn block_identity(block: &Value) -> Result<(&str, &str), AuthError> {
    let number = block["number"].as_str().ok_or_else(invalid)?;
    hex_u128(&block["number"])?;
    let hash = block["hash"].as_str().ok_or_else(invalid)?;
    if !hash.starts_with("0x")
        || hash.len() != 66
        || !hash[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    Ok((number, hash))
}
pub(crate) async fn verified_quote(config: &AuthConfig) -> Result<Quote, AuthError> {
    let response = zkapi_client::testnet_auth::request(
        config.chain_id,
        &config.protocol_server_url,
        reqwest::Method::GET,
        format!(
            "{}/v2/billing/quote",
            config.protocol_server_url.trim_end_matches('/')
        ),
    )?
    .timeout(std::time::Duration::from_secs(20))
    .send()
    .await
    .map_err(|_| invalid())?;
    let proposed = json_response(zkapi_client::testnet_auth::check_response(response)?).await?;
    let quote: Quote = serde_json::from_value(proposed).map_err(|_| invalid())?;
    quote.validate(config)?;
    if hex_u128(&rpc(config, "eth_chainId", json!([])).await?)? != config.chain_id as u128 {
        return Err(invalid());
    }
    let block = rpc(config, "eth_getBlockByNumber", json!(["finalized", false])).await?;
    let (number, hash) = block_identity(&block)?;
    let vault = format!(
        "0x{}",
        config.contract_address.as_bytes()[12..]
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
    for (data, expected) in [("0x4d1352fd", 1_000_000_000u128), ("0x631b2f10", 0)] {
        let result = rpc(
            config,
            "eth_call",
            json!([{"to":vault,"data":data},"latest"]),
        )
        .await?;
        if result.as_str().is_none_or(|s| s.len() != 66) || hex_u128(&result)? != expected {
            return Err(invalid());
        }
    }
    let decimals = rpc(
        config,
        "eth_call",
        json!([{"to":config.native_price_feed_address,"data":"0x313ce567"},number]),
    )
    .await?;
    if hex_u128(&decimals)? != quote.decimals as u128 {
        return Err(invalid());
    }
    let encoded = rpc(
        config,
        "eth_call",
        json!([{"to":config.native_price_feed_address,"data":"0xfeaf968c"},number]),
    )
    .await?;
    let encoded = encoded.as_str().ok_or_else(invalid)?;
    if encoded.len() != 322
        || !encoded.starts_with("0x")
        || !encoded[2..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        return Err(invalid());
    }
    let words = (0..5)
        .map(|i| {
            hex_u128(&json!(format!(
                "0x{}",
                &encoded[2 + i * 64..2 + (i + 1) * 64]
            )))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if words[0] != decimal(&quote.round_id)?
        || words[1] != decimal(&quote.answer)?
        || words[2] == 0
        || words[2] > words[3]
        || words[3] != quote.updated_at as u128
        || words[4] < words[0]
    {
        return Err(invalid());
    }
    let canonical = rpc(config, "eth_getBlockByNumber", json!([number, false])).await?;
    let (_, canonical_hash) = block_identity(&canonical)?;
    if !canonical_hash.eq_ignore_ascii_case(hash)
        || hex_u128(&rpc(config, "eth_chainId", json!([])).await?)? != config.chain_id as u128
    {
        return Err(invalid());
    }
    Ok(quote)
}
pub(crate) fn saved_quote(config: &AuthConfig, payload: &str) -> Result<Option<Quote>, AuthError> {
    let mut value: Value = serde_json::from_str(payload).map_err(|_| invalid())?;
    let object = value.as_object_mut().ok_or_else(invalid)?;
    let quote = object
        .remove("billing_quote")
        .map(serde_json::from_value::<Quote>)
        .transpose()
        .map_err(|_| invalid())?;
    let authorization: zkapi_types::wire::OpenRouterLeaseAuthorization =
        serde_json::from_value(value).map_err(|_| invalid())?;
    if authorization != Default::default() {
        return Err(invalid());
    }
    match (&*config.billing_asset, &quote) {
        ("native_eth", Some(quote)) => quote.validate_intrinsic(config.chain_id)?,
        ("native_eth", None) => return Err(invalid()),
        (_, Some(_)) => return Err(invalid()),
        _ => {}
    }
    Ok(quote)
}
/// A saved native request quoted under pins that have changed since, whose
/// quote has expired by the local clock. The server checks a new admission's
/// pins before its freshness, so it refuses such a request with
/// invalid_request rather than native_quote_expired. Only the server's expiry
/// acknowledgement may retire it.
pub(crate) fn expired_under_earlier_pins(config: &AuthConfig, payload: &str) -> bool {
    matches!(saved_quote(config, payload), Ok(Some(quote))
        if quote.conflicts_with_pins(config)
            && quote.expires_at <= crate::service::now_seconds())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (AuthConfig, Quote) {
        let config = AuthConfig {
            billing_asset: "native_eth".into(),
            billing_unit: "gwei".into(),
            native_asset_wei_per_unit: "1000000000".into(),
            native_price_feed_address: format!("0x{}", "12".repeat(20)),
            native_price_feed_decimals: 8,
            native_price_max_age_seconds: 3600,
            ..Default::default()
        };
        let updated = crate::service::now_seconds() - 60;
        let quote = Quote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: config.chain_id,
            feed_address: config.native_price_feed_address.clone(),
            round_id: "123".into(),
            answer: "250000000000".into(),
            decimals: 8,
            updated_at: updated,
            expires_at: updated + 3600,
        };
        (config, quote)
    }
    /// Each native-price pin a release may change, one at a time.
    fn later_pins(config: &AuthConfig) -> [(&'static str, AuthConfig); 3] {
        let mut feed = config.clone();
        feed.native_price_feed_address = format!("0x{}", "34".repeat(20));
        let mut max_age = config.clone();
        max_age.native_price_max_age_seconds = 4500;
        let mut decimals = config.clone();
        decimals.native_price_feed_decimals = 18;
        [
            ("feed address", feed),
            ("maximum age", max_age),
            ("feed decimals", decimals),
        ]
    }
    #[test]
    fn native_budget_and_saved_quote_bindings_are_exact() {
        let (config, quote) = fixture();
        quote.validate(&config).unwrap();
        assert_eq!(quote.budget_units(1_000_000).unwrap(), 400_000);
        assert_eq!(quote.usd_micros(400_000).unwrap(), 1_000_000);
        assert!(quote.budget_units(7_000_000).is_err());
        let mut changed = quote.clone();
        changed.answer = "300000000001".into();
        assert_eq!(changed.budget_units(1_000_000).unwrap(), 333_334);
        let payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        assert_eq!(saved_quote(&config, &payload).unwrap(), Some(quote.clone()));
        assert!(saved_quote(
            &config,
            r#"{"mode":"openrouter_ephemeral_lease","version":1}"#
        )
        .is_err());
        for (field, value) in [
            ("chain_id", json!(111)),
            ("feed_address", json!(format!("0x{}", "34".repeat(20)))),
            ("answer", json!("0")),
            ("round_id", json!("0123")),
            ("units_per_eth", json!(1)),
            ("expires_at", json!(0)),
            // Intrinsically valid, but not the pinned 3600 s maximum age.
            ("expires_at", json!(quote.updated_at + 4500)),
        ] {
            let mut value_quote = serde_json::to_value(&quote).unwrap();
            value_quote[field] = value;
            assert!(serde_json::from_value::<Quote>(value_quote)
                .unwrap()
                .validate(&config)
                .is_err());
        }
        let mut expired = quote.clone();
        expired.updated_at = 1;
        expired.expires_at = 3601;
        assert!(expired.validate(&config).is_err());
        expired.validate_intrinsic(config.chain_id).unwrap();
        // A round stamped in the future is refused, even with the pinned span.
        let mut future = quote.clone();
        future.updated_at = crate::service::now_seconds() + 600;
        future.expires_at = future.updated_at + 3600;
        future.validate_intrinsic(config.chain_id).unwrap();
        assert!(!future.conflicts_with_pins(&config));
        assert!(future.validate(&config).is_err());
    }
    #[test]
    fn saved_quote_is_checked_intrinsically_not_against_later_pins() {
        let (config, quote) = fixture();
        let payload =
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string();
        // A feed migration, a new maximum age or new feed decimals applies to
        // new admissions only. Each pin alone refuses admission.
        for (pin, later) in later_pins(&config) {
            assert!(quote.conflicts_with_pins(&later), "{pin}");
            assert!(quote.validate(&later).is_err(), "{pin}");
            assert_eq!(
                saved_quote(&later, &payload).unwrap(),
                Some(quote.clone()),
                "{pin}"
            );
        }
        assert!(!quote.conflicts_with_pins(&config));
        let feed = |byte: &str| format!("0x{}", byte.repeat(20));
        let mut other_chain = config.clone();
        other_chain.chain_id = 111;
        assert!(saved_quote(&other_chain, &payload).is_err());
        for (field, value, valid) in [
            ("feed_address", json!(feed("34")), true),
            ("expires_at", json!(quote.updated_at + 4500), true),
            ("chain_id", json!(111), false),
            ("feed_address", json!(feed("AB")), false),
            ("feed_address", json!(feed("00")), false),
            ("feed_address", json!("0x1234"), false),
            ("decimals", json!(18), false),
            ("answer", json!("0"), false),
            ("round_id", json!("0123"), false),
            ("units_per_eth", json!(1), false),
            ("updated_at", json!(0), false),
            ("expires_at", json!(quote.updated_at), false),
            ("expires_at", json!(quote.updated_at + 86_401), false),
        ] {
            let mut value_quote = serde_json::to_value(&quote).unwrap();
            value_quote[field] = value.clone();
            let changed: Quote = serde_json::from_value(value_quote).unwrap();
            assert_eq!(
                changed.validate_intrinsic(config.chain_id).is_ok(),
                valid,
                "{field} {value}"
            );
        }
    }
    #[test]
    fn only_an_expired_quote_under_changed_pins_asks_the_server_to_expire_it() {
        let (config, quote) = fixture();
        let payload = |quote: &Quote| {
            json!({"mode":"openrouter_ephemeral_lease","version":1,"billing_quote":quote})
                .to_string()
        };
        let mut expired = quote.clone();
        expired.updated_at = 1;
        expired.expires_at = 3601;
        // Under unchanged pins the server itself answers native_quote_expired.
        assert!(!expired_under_earlier_pins(&config, &payload(&expired)));
        for (pin, later) in later_pins(&config) {
            assert!(
                expired_under_earlier_pins(&later, &payload(&expired)),
                "{pin}"
            );
            // Before expiry the server cannot confirm it was never admitted.
            assert!(
                !expired_under_earlier_pins(&later, &payload(&quote)),
                "{pin}"
            );
        }
        // Only a valid saved native quote for this chain qualifies.
        let [(_, mut later), ..] = later_pins(&config);
        let no_quote = r#"{"mode":"openrouter_ephemeral_lease","version":1}"#;
        assert!(!expired_under_earlier_pins(&later, no_quote));
        later.chain_id = 111;
        assert!(!expired_under_earlier_pins(&later, &payload(&expired)));
    }
    #[tokio::test]
    async fn oracle_requires_finalized_round_chain_vault_and_canonical_block() {
        use axum::{
            routing::{get, post},
            Json, Router,
        };
        use std::sync::{
            atomic::{AtomicU8, Ordering},
            Arc,
        };
        let (mut config, quote) = fixture();
        let mode = Arc::new(AtomicU8::new(0));
        let quote_response = quote.clone();
        let rpc_quote = quote.clone();
        let modes = mode.clone();
        let router=Router::new().route("/v2/billing/quote",get(move||{let q=quote_response.clone();async move {Json(json!(q))}}))
            .route("/rpc",post(move|Json(body):Json<Value>|{let q=rpc_quote.clone();let mode=modes.load(Ordering::SeqCst);async move {
                let result=match body["method"].as_str().unwrap() {
                    "eth_chainId"=>json!(if mode==1{"0x2"}else{"0x1"}),
                    "eth_getBlockByNumber"=>json!({"number":"0x10","hash":format!("0x{}",if mode==2 && body["params"][0]=="0x10"{"bb".repeat(32)}else{"aa".repeat(32)})}),
                    "eth_call"=>match body["params"][0]["data"].as_str().unwrap() {
                        "0x4d1352fd"=>json!(format!("0x{:064x}",if mode==3{0}else{1_000_000_000u128})),
                        "0x631b2f10"=>json!(format!("0x{:064x}",if mode==4{1}else{0})),
                        "0x313ce567"=>json!(format!("0x{:064x}",if mode==5{9}else{8})),
                        "0xfeaf968c"=>json!(format!("0x{:064x}{:064x}{:064x}{:064x}{:064x}",if mode==6{124}else{123},250_000_000_000u128,q.updated_at-1,q.updated_at,123)),_=>panic!("unexpected call")},_=>panic!("unexpected method")};
                Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
            }}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        config.protocol_server_url = url.clone();
        config.demo_rpc_url = Some(format!("{url}/rpc"));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        assert_eq!(verified_quote(&config).await.unwrap(), quote);
        for value in 1..=6 {
            mode.store(value, Ordering::SeqCst);
            assert!(verified_quote(&config).await.is_err(), "mode {value}");
        }
        server.abort();
    }
}
