//! Live dashboard feed for the zkAPI server.
//!
//! Events expose lease authorizations, proof bindings, aggregate upstream cost
//! and whole-gwei settlement, recorded when a request settles. Inference
//! prompts stay between the client and its leased upstream key, and the
//! unauthenticated feed carries nothing of the successor state: no commitment,
//! anchor or server blinding. This bounded feed is observability only and does
//! not affect protocol state.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use tokio::sync::broadcast;
use zkapi_types::wire::CurvePointWire;
use zkapi_types::Felt252;

use crate::settlement::UsageInfo;

/// One fully-detailed request as the server saw it.
#[derive(Debug, Clone, Serialize)]
pub struct DashboardEvent {
    pub seq: u64,
    pub ts_ms: u64,
    pub client_request_id: String,
    pub billing_label: String,

    // --- zk authentication / payment proof ---
    pub request_nullifier: Felt252,
    pub active_root: Felt252,
    pub anon_commitment: CurvePointWire,
    pub solvency_bound: u128,
    pub solvency_bound_usd: f64,
    pub proof_backend: String,
    pub proof_public_output_hash: Felt252,
    pub proof_size_bytes: usize,

    // --- prompt-free lease authorization ---
    pub request_raw: String,

    // --- upstream response ---
    pub response_code: u16,
    pub response_text: String,
    pub response_hash: Felt252,

    // --- aggregate upstream cost and gwei billing ---
    pub usage: Option<UsageInfo>,
    pub charge_applied: u128,
    pub charge_usd: f64,

    // --- timing ---
    pub upstream_ms: u64,
    pub total_ms: u64,
}

/// Running totals across all requests seen this process lifetime.
#[derive(Debug, Clone, Default, Serialize)]
pub struct DashboardTotals {
    pub request_count: u64,
    pub total_gwei_charged: u128,
    pub total_cost_usd: f64,
}

/// Durable lease-settlement health, counted with raw SQL so that rows the
/// settler cannot decode are included. Operator-only.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct SettlementCounts {
    /// Leases still to be settled.
    pub pending: u64,
    /// Settled leases whose successor is not signed because an exit consumed
    /// the request's nullifier (O7), awaiting the exit's defeat.
    pub exit_deferred: u64,
    /// Settled leases whose successor is never signed (ExitedUnsigned).
    pub exited_unsigned: u64,
    /// Non-terminal leases with at least one failed settlement attempt.
    pub retrying: u64,
    pub provisioning: u64,
    /// Corrupt bindings cancelled without a signature.
    pub cancelled: u64,
    /// Rows whose status no settler recognizes.
    pub unknown_status: u64,
    /// Settlement reviews not yet acknowledged.
    pub open_reviews: u64,
    /// Provider keys of terminal leases still queued for deletion.
    pub pending_key_cleanups: u64,
    /// Seconds until the nearest pending settlement deadline (0 if past).
    pub next_deadline_in_seconds: Option<u64>,
}

/// One non-terminal lease on the operator settlement page.
#[derive(Debug, Clone, Serialize)]
pub struct PendingLeaseView {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub key_source: String,
    pub status: String,
    pub delivered: Option<bool>,
    /// Set before finalization only on a lease committed to a zero charge:
    /// "unissued" (never delivered) or "operator_conceded" (reopened with a
    /// concession).
    pub charge_basis: Option<String>,
    pub expires_at: u64,
    pub settle_after: u64,
    pub settlement_deadline: Option<u64>,
    pub seconds_until_deadline: Option<u64>,
    pub attempts: u64,
    pub first_error_at: Option<u64>,
    pub last_error: Option<String>,
}

/// A settlement review; gwei and micro-USD amounts are decimal strings.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementReviewView {
    pub client_request_id: String,
    pub request_nullifier: Felt252,
    pub key_source: String,
    pub reason: String,
    pub charge_basis: Option<String>,
    pub detail: String,
    pub reported_usage_micro_usd: Option<String>,
    pub charge_applied: Option<String>,
    pub solvency_bound: String,
    pub created_at: u64,
    pub acknowledged_at: Option<u64>,
}

/// GET /v1/dashboard/settlement.
#[derive(Debug, Clone, Serialize)]
pub struct SettlementOverview {
    pub generated_at: u64,
    pub settlement_deadline_seconds: Option<u64>,
    pub counts: SettlementCounts,
    pub pending: Vec<PendingLeaseView>,
    pub reviews: Vec<SettlementReviewView>,
}

/// Bounded in-memory feed + broadcast hub.
pub struct DashboardHub {
    tx: broadcast::Sender<DashboardEvent>,
    recent: Mutex<VecDeque<DashboardEvent>>,
    totals: Mutex<DashboardTotals>,
    seq: Mutex<u64>,
    capacity: usize,
    pub started_ms: u64,
}

impl DashboardHub {
    pub fn new(capacity: usize) -> Self {
        let (tx, _rx) = broadcast::channel(256);
        Self {
            tx,
            recent: Mutex::new(VecDeque::with_capacity(capacity)),
            totals: Mutex::new(DashboardTotals::default()),
            seq: Mutex::new(0),
            capacity,
            started_ms: now_ms(),
        }
    }

    /// Allocate the next monotonic sequence number for an event.
    pub fn next_seq(&self) -> u64 {
        let mut seq = self.seq.lock().unwrap();
        *seq += 1;
        *seq
    }

    /// Record an event: update totals, append to the ring buffer, broadcast.
    pub fn record(&self, event: DashboardEvent) {
        {
            let mut totals = self.totals.lock().unwrap();
            totals.request_count += 1;
            totals.total_gwei_charged = totals
                .total_gwei_charged
                .saturating_add(event.charge_applied);
            totals.total_cost_usd += event.charge_usd;
        }
        {
            let mut recent = self.recent.lock().unwrap();
            if recent.len() >= self.capacity {
                recent.pop_front();
            }
            recent.push_back(event.clone());
        }
        // A send error just means no subscribers; that's fine.
        let _ = self.tx.send(event);
    }

    pub fn subscribe(&self) -> broadcast::Receiver<DashboardEvent> {
        self.tx.subscribe()
    }

    pub fn recent(&self) -> Vec<DashboardEvent> {
        self.recent.lock().unwrap().iter().cloned().collect()
    }

    pub fn totals(&self) -> DashboardTotals {
        self.totals.lock().unwrap().clone()
    }
}

/// Mask bearer-style API keys (`sk-...`) before they reach the dashboard feed
/// so a secret bearer token never lands in a dashboard, screen-share, or log.
pub fn redact_secrets(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(pos) = rest.find("sk-") {
        result.push_str(&rest[..pos]);
        let after = &rest[pos..];
        let end = after
            .char_indices()
            .find(|&(idx, c)| idx >= 3 && !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
            .map(|(idx, _)| idx)
            .unwrap_or(after.len());
        if end > 12 {
            result.push_str("sk-***REDACTED***");
        } else {
            result.push_str(&after[..end]);
        }
        rest = &after[end..];
    }
    result.push_str(rest);
    result
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_bearer_keys() {
        let s = r#"{"api_key":"sk-or-v1-3527c84aabcdef0123456789","request_id":"49802767d5a1"}"#;
        let red = redact_secrets(s);
        assert!(!red.contains("sk-or-v1-3527"), "key not redacted: {red}");
        assert!(red.contains("sk-***REDACTED***"));
        assert!(red.contains("49802767d5a1"), "request id should survive");
        // Short non-key strings are untouched.
        assert_eq!(redact_secrets("sk-1"), "sk-1");
        // Unicode content is preserved around a redaction.
        let u = redact_secrets("héllo sk-proj-ABCDEFGHIJKLMNOP wörld");
        assert!(u.contains("héllo") && u.contains("wörld") && u.contains("REDACTED"));
    }

    #[test]
    fn hub_tracks_totals_and_ring_buffer() {
        let hub = DashboardHub::new(2);
        for i in 0..3 {
            hub.record(sample_event(hub.next_seq(), i + 1));
        }
        let totals = hub.totals();
        assert_eq!(totals.request_count, 3);
        assert_eq!(totals.total_gwei_charged, 6); // 1 + 2 + 3
                                                  // Ring buffer capped at 2.
        assert_eq!(hub.recent().len(), 2);
    }

    /// §5.1: the unauthenticated feed carries nothing of the successor.
    #[test]
    fn events_carry_no_successor_state() {
        let event = serde_json::to_value(sample_event(1, 1)).unwrap();
        for field in [
            "next_anchor",
            "blind_delta_srv",
            "next_commitment",
            "next_state_signature",
        ] {
            assert!(event.get(field).is_none(), "{field}");
        }
    }

    fn sample_event(seq: u64, charge: u128) -> DashboardEvent {
        DashboardEvent {
            seq,
            ts_ms: 0,
            client_request_id: format!("req-{seq}"),
            billing_label: "direct:openrouter-ephemeral".to_string(),
            request_nullifier: Felt252::from_u64(seq),
            active_root: Felt252::ZERO,
            anon_commitment: CurvePointWire {
                x: Felt252::ZERO,
                y: Felt252::ZERO,
            },
            solvency_bound: 1_000_000,
            solvency_bound_usd: 1.0,
            proof_backend: "groth16_bn254".to_string(),
            proof_public_output_hash: Felt252::ZERO,
            proof_size_bytes: 100,
            request_raw: "{}".to_string(),
            response_code: 200,
            response_text: "{}".to_string(),
            response_hash: Felt252::ZERO,
            usage: None,
            charge_applied: charge,
            charge_usd: 0.000001 * charge as f64,
            upstream_ms: 0,
            total_ms: 0,
        }
    }
}
