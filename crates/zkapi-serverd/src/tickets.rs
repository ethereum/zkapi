//! Fixed-price tickets: an explicit alternative to metered leases.
//!
//! A ticket buys one OA-org runtime key with a tier's spending allowance and
//! lifetime for a fixed USD price. The purchase authorization (the proof's
//! payload) carries the tier's exact terms, the frozen native quote and the
//! price in gwei at that quote. The server checks these against its catalog
//! before reserving, issues the key, and in the same call settles the request
//! at exactly that price and signs its successor. Nothing waits for inference,
//! key expiry or usage receipts, so a wallet can buy its next ticket (and run
//! its next request) while earlier keys are still in use.

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;
use zkapi_types::wire::{TicketAuthorization, TicketTermsV1, TICKET_MODE};

use crate::error::ServerError;
use crate::native_billing::{NativeBillingQuote, MAX_SAFE_UNITS};

pub const TICKET_CATALOG_VERSION: u16 = 1;
pub use zkapi_types::wire::TICKET_CHARGE_BASIS as CHARGE_BASIS;
const MAX_TIERS: usize = 32;
const MAX_TIER_NAME_BYTES: usize = 64;

/// The tiers this server sells (`--ticket-catalog`). Operators mirror the OA
/// org's tier definitions: name, ticket count, credit limit and duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketCatalog {
    tiers: Vec<TicketTermsV1>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    version: u16,
    tiers: Vec<TicketTermsV1>,
}

impl TicketCatalog {
    pub fn from_json(text: &str) -> anyhow::Result<Self> {
        let file: CatalogFile = serde_json::from_str(text)
            .map_err(|error| anyhow::anyhow!("invalid ticket catalog: {error}"))?;
        anyhow::ensure!(
            file.version == TICKET_CATALOG_VERSION,
            "ticket catalog version must be {TICKET_CATALOG_VERSION}"
        );
        let catalog = Self { tiers: file.tiers };
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).map_err(|error| {
            anyhow::anyhow!("cannot read ticket catalog {}: {error}", path.display())
        })?;
        Self::from_json(&text)
    }

    fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            !self.tiers.is_empty() && self.tiers.len() <= MAX_TIERS,
            "a ticket catalog lists 1 to {MAX_TIERS} tiers"
        );
        let mut ids = BTreeSet::new();
        let mut counts = BTreeSet::new();
        for tier in &self.tiers {
            anyhow::ensure!(
                ids.insert(tier.tier_id),
                "ticket tier {} is listed twice",
                tier.tier_id
            );
            // Clients map a model's OA ticket count to exactly one tier.
            anyhow::ensure!(
                counts.insert(tier.oa_tickets),
                "two ticket tiers cost {} OA tickets",
                tier.oa_tickets
            );
            validate_terms(tier).map_err(|error| anyhow::anyhow!("{error}"))?;
        }
        Ok(())
    }

    pub fn tiers(&self) -> &[TicketTermsV1] {
        &self.tiers
    }

    pub fn tier(&self, tier_id: u32) -> Option<&TicketTermsV1> {
        self.tiers.iter().find(|tier| tier.tier_id == tier_id)
    }

    pub fn max_duration_seconds(&self) -> u64 {
        self.tiers
            .iter()
            .map(|tier| tier.duration_seconds)
            .max()
            .unwrap_or_default()
    }

    pub fn max_credit_limit_micro_usd(&self) -> u64 {
        self.tiers
            .iter()
            .map(|tier| tier.credit_limit_micro_usd)
            .max()
            .unwrap_or_default()
    }
}

/// Terms that any ticket, sold now or reserved earlier, must satisfy.
fn validate_terms(terms: &TicketTermsV1) -> Result<(), ServerError> {
    let invalid = |detail: &str| {
        Err(ServerError::InvalidRequest(format!(
            "ticket tier {}: {detail}",
            terms.tier_id
        )))
    };
    if terms.tier_name.is_empty()
        || terms.tier_name.len() > MAX_TIER_NAME_BYTES
        || terms.tier_name.trim() != terms.tier_name
        || !terms
            .tier_name
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return invalid("the name must be 1 to 64 printable ASCII characters");
    }
    if terms.oa_tickets == 0 {
        return invalid("the OA ticket count must be positive");
    }
    if terms.price_micro_usd == 0 || u128::from(terms.price_micro_usd) > MAX_SAFE_UNITS {
        return invalid("the price must be positive and browser-safe");
    }
    if terms.credit_limit_micro_usd == 0
        || u128::from(terms.credit_limit_micro_usd) > MAX_SAFE_UNITS
    {
        return invalid("the credit limit must be positive and browser-safe");
    }
    if terms.duration_seconds == 0 || !terms.duration_seconds.is_multiple_of(60) {
        return invalid("the duration must be a positive whole number of minutes");
    }
    Ok(())
}

/// Parse a ticket purchase authorization (the payload without its
/// `billing_quote`). None when the payload is not in ticket mode.
pub fn parse_authorization(
    payload: &serde_json::Value,
) -> Result<Option<TicketAuthorization>, ServerError> {
    if payload.get("mode").and_then(serde_json::Value::as_str) != Some(TICKET_MODE) {
        return Ok(None);
    }
    let authorization: TicketAuthorization = serde_json::from_value(payload.clone())
        .map_err(|_| ServerError::InvalidRequest("invalid ticket authorization".into()))?;
    if authorization.version != 1 {
        return Err(ServerError::InvalidRequest(
            "unsupported ticket authorization version".into(),
        ));
    }
    validate_terms(&authorization.ticket)?;
    Ok(Some(authorization))
}

/// The fixed charge of a ticket in gwei: its USD price converted at the
/// bound quote (rounded up, as every native charge), which the authorization
/// must state exactly and the proof's solvency bound must cover.
pub fn price_units(
    authorization: &TicketAuthorization,
    quote: &NativeBillingQuote,
    solvency_bound: u128,
) -> Result<u128, ServerError> {
    let units = quote.charge_units(u128::from(authorization.ticket.price_micro_usd))?;
    if units != u128::from(authorization.price_units) {
        return Err(ServerError::TicketTermsMismatch(format!(
            "the ticket price is {units} gwei at the bound quote, not {}",
            authorization.price_units
        )));
    }
    if units == 0 || units > solvency_bound {
        return Err(ServerError::InvalidRequest(
            "the request's solvency bound does not cover the ticket price".into(),
        ));
    }
    Ok(units)
}

/// Admission only: the tier must be on sale now with exactly these terms.
pub fn check_on_sale(catalog: &TicketCatalog, terms: &TicketTermsV1) -> Result<(), ServerError> {
    match catalog.tier(terms.tier_id) {
        Some(current) if current == terms => Ok(()),
        Some(_) => Err(ServerError::TicketTermsMismatch(format!(
            "ticket tier {} is sold at other terms; read GET /v2/tickets",
            terms.tier_id
        ))),
        None => Err(ServerError::TicketTermsMismatch(format!(
            "this server sells no ticket tier {}",
            terms.tier_id
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn instant() -> TicketTermsV1 {
        TicketTermsV1 {
            tier_id: 1,
            tier_name: "Instant".into(),
            oa_tickets: 4,
            price_micro_usd: 560_000,
            credit_limit_micro_usd: 3_000_000,
            duration_seconds: 3_600,
        }
    }

    fn catalog_json(tiers: &[TicketTermsV1]) -> String {
        serde_json::json!({"version": 1, "tiers": tiers}).to_string()
    }

    /// The documented example mirrors the staging OA tiers at the OA
    /// ticket-pack price, and fits the Sepolia settlement timing.
    #[test]
    fn the_example_catalog_is_valid() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../docker/aws/ticket-catalog.example.json");
        let catalog = TicketCatalog::load(&path).unwrap();
        let counts: Vec<_> = catalog.tiers().iter().map(|tier| tier.oa_tickets).collect();
        assert_eq!(counts, [1, 3, 5]);
        for tier in catalog.tiers() {
            assert_eq!(
                tier.price_micro_usd,
                u64::from(tier.oa_tickets) * 140_000,
                "{}",
                tier.tier_name
            );
        }
        let sepolia = crate::config::PARAMETER_SETS[1];
        crate::config::OpenRouterLeaseConfig {
            ttl_seconds: catalog.max_duration_seconds(),
            ..sepolia.lease_config(crate::test_support::lease_config().source)
        }
        .validate_settlement_timing(sepolia.challenge_period_seconds)
        .unwrap();
    }

    #[test]
    fn catalog_accepts_distinct_valid_tiers() {
        let mut thinking = instant();
        thinking.tier_id = 2;
        thinking.tier_name = "Thinking".into();
        thinking.oa_tickets = 2;
        let catalog = TicketCatalog::from_json(&catalog_json(&[instant(), thinking])).unwrap();
        assert_eq!(catalog.tier(2).unwrap().oa_tickets, 2);
        assert_eq!(catalog.max_duration_seconds(), 3_600);
        assert!(catalog.tier(3).is_none());
    }

    #[test]
    fn catalog_refuses_ambiguous_or_invalid_tiers() {
        assert!(TicketCatalog::from_json(&catalog_json(&[])).is_err());
        assert!(TicketCatalog::from_json(&catalog_json(&[instant(), instant()])).is_err());
        let mut same_count = instant();
        same_count.tier_id = 9;
        assert!(TicketCatalog::from_json(&catalog_json(&[instant(), same_count])).is_err());
        for broken in [
            TicketTermsV1 {
                price_micro_usd: 0,
                ..instant()
            },
            TicketTermsV1 {
                credit_limit_micro_usd: 0,
                ..instant()
            },
            TicketTermsV1 {
                duration_seconds: 90,
                ..instant()
            },
            TicketTermsV1 {
                tier_name: " padded".into(),
                ..instant()
            },
            TicketTermsV1 {
                oa_tickets: 0,
                ..instant()
            },
        ] {
            assert!(TicketCatalog::from_json(&catalog_json(&[broken])).is_err());
        }
        assert!(TicketCatalog::from_json(
            &serde_json::json!({"version": 2, "tiers": [instant()]}).to_string()
        )
        .is_err());
        assert!(TicketCatalog::from_json(
            &serde_json::json!({"version": 1, "tiers": [instant()], "extra": 1}).to_string()
        )
        .is_err());
    }

    #[test]
    fn authorization_parses_only_ticket_mode_and_refuses_extra_fields() {
        let metered = serde_json::json!({"mode": "openrouter_ephemeral_lease", "version": 1});
        assert!(parse_authorization(&metered).unwrap().is_none());
        let ticket = serde_json::json!({
            "mode": TICKET_MODE, "version": 1, "ticket": instant(), "price_units": 1
        });
        assert_eq!(
            parse_authorization(&ticket).unwrap().unwrap().ticket,
            instant()
        );
        let mut extra = ticket.clone();
        extra["prompt"] = "hello".into();
        assert!(parse_authorization(&extra).is_err());
        let mut version = ticket.clone();
        version["version"] = 2.into();
        assert!(parse_authorization(&version).is_err());
        let mut terms = ticket;
        terms["ticket"]["duration_seconds"] = 61.into();
        assert!(parse_authorization(&terms).is_err());
    }

    #[test]
    fn price_must_equal_the_conversion_at_the_bound_quote() {
        // $1000/ETH: one micro-USD is one gwei.
        let quote = crate::test_support::lease_quote(1_000);
        let authorization = |price_units| TicketAuthorization {
            mode: TICKET_MODE.into(),
            version: 1,
            ticket: instant(),
            price_units,
        };
        assert_eq!(
            price_units(&authorization(560_000), &quote, 1_000_000).unwrap(),
            560_000
        );
        assert!(matches!(
            price_units(&authorization(559_999), &quote, 1_000_000),
            Err(ServerError::TicketTermsMismatch(_))
        ));
        assert!(matches!(
            price_units(&authorization(560_000), &quote, 559_999),
            Err(ServerError::InvalidRequest(_))
        ));
    }

    #[test]
    fn only_current_terms_are_on_sale() {
        let catalog = TicketCatalog::from_json(&catalog_json(&[instant()])).unwrap();
        assert!(check_on_sale(&catalog, &instant()).is_ok());
        let cheaper = TicketTermsV1 {
            price_micro_usd: 1,
            ..instant()
        };
        assert!(matches!(
            check_on_sale(&catalog, &cheaper),
            Err(ServerError::TicketTermsMismatch(_))
        ));
        let unknown = TicketTermsV1 {
            tier_id: 7,
            ..instant()
        };
        assert!(check_on_sale(&catalog, &unknown).is_err());
    }
}
