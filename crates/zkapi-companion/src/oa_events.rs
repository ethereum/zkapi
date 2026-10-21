//! Bounded operational accounting for the authenticated local Go bridge.
//!
//! This is deliberately not a durable ledger. It retains no provider keys,
//! note identifiers, proofs, or response payloads. Only the caller of verified
//! wallet recovery may record a settlement.

use std::collections::VecDeque;
use std::sync::Mutex;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zkapi_types::wire::RequestResponseV2;

const EVENT_LIMIT: usize = 128;

#[derive(Clone, Serialize)]
pub(crate) struct SessionEvent {
    sequence: u64,
    kind: &'static str,
    session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    charge_units: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    balance_units: Option<String>,
}

#[derive(Serialize)]
pub(crate) struct SessionEventsSnapshot {
    version: u32,
    instance_id: String,
    first_sequence: u64,
    next_sequence: u64,
    events: Vec<SessionEvent>,
}

pub(crate) struct SessionEvents {
    instance_id: String,
    queue: Mutex<EventQueue>,
}

struct EventQueue {
    next_sequence: u64,
    events: VecDeque<SessionEvent>,
}

impl SessionEvents {
    pub(crate) fn new() -> Self {
        Self {
            instance_id: uuid::Uuid::new_v4().simple().to_string(),
            queue: Mutex::new(EventQueue {
                next_sequence: 1,
                events: VecDeque::new(),
            }),
        }
    }

    pub(crate) fn snapshot(&self) -> SessionEventsSnapshot {
        let queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        SessionEventsSnapshot {
            version: 1,
            instance_id: self.instance_id.clone(),
            first_sequence: queue
                .events
                .front()
                .map_or(queue.next_sequence, |event| event.sequence),
            next_sequence: queue.next_sequence,
            events: queue.events.iter().cloned().collect(),
        }
    }

    pub(crate) fn started(&self, request_id: &str) {
        self.record("started", request_id, None, None);
    }

    /// Call only after wallet.recover() has verified and installed the signed
    /// next state, while still holding the wallet mutex. This preserves event
    /// ordering when issuance resumes immediately after settlement.
    pub(crate) fn settled(&self, response: &RequestResponseV2, balance: Option<u128>) {
        let Some(balance) = balance else { return };
        // Other authenticated request kinds can also use wallet recovery.
        // Match only the two server-defined lease settlement payload types;
        // no raw response text enters the feed.
        let Ok(payload) = serde_json::from_str::<serde_json::Value>(&response.response_payload)
        else {
            return;
        };
        if !matches!(
            payload.get("type").and_then(serde_json::Value::as_str),
            Some("oa_org_ephemeral_lease_settlement" | "openrouter_ephemeral_lease_settlement")
        ) {
            return;
        }
        self.record(
            "settled",
            &response.client_request_id,
            Some(response.charge_applied.to_string()),
            Some(balance.to_string()),
        );
    }

    fn record(
        &self,
        kind: &'static str,
        request_id: &str,
        charge_units: Option<String>,
        balance_units: Option<String>,
    ) {
        let session_id = format!("{:x}", Sha256::digest(request_id.as_bytes()));
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // Recovery is serialized and consumes its durable journal once. This
        // additional bounded guard makes repeated observations idempotent and
        // prevents a late start from following an already observed settlement.
        if queue.events.iter().any(|event| {
            event.session_id == session_id && (kind == "started" || event.kind == kind)
        }) {
            return;
        }
        let sequence = queue.next_sequence;
        queue.next_sequence += 1;
        queue.events.push_back(SessionEvent {
            sequence,
            kind,
            session_id,
            charge_units,
            balance_units,
        });
        if queue.events.len() > EVENT_LIMIT {
            queue.events.pop_front();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn settled_response(id: &str, charge: u128) -> RequestResponseV2 {
        serde_json::from_value(json!({
            "status":"finalized", "client_request_id":id, "request_nullifier":"0x0",
            "response_code":200,
            "response_payload":json!({"type":"oa_org_ephemeral_lease_settlement", "secret_payload":"not exported"}).to_string(),
            "response_hash":"0x0", "charge_applied":charge,
            "next_commitment":{"x":"0x0","y":"0x1"}, "next_anchor":"0x1", "blind_delta_srv":"0x0",
            "next_state_signature":{"r_x":"0x0","r_y":"0x1","s":"0x0"}
        })).unwrap()
    }

    #[test]
    fn session_events_order_zero_charge_dedup_and_redaction() {
        let events = SessionEvents::new();
        let empty = events.snapshot();
        assert_eq!((empty.first_sequence, empty.next_sequence), (1, 1));
        events.started("private-request-id");
        events.started("private-request-id");
        events.settled(&settled_response("private-request-id", 0), Some(u128::MAX));
        events.settled(&settled_response("private-request-id", 0), Some(u128::MAX));
        events.started("private-request-id");
        events.started("next-session");
        let snapshot = events.snapshot();
        assert_eq!(snapshot.instance_id.len(), 32);
        assert!(snapshot
            .instance_id
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit()));
        assert_eq!((snapshot.first_sequence, snapshot.next_sequence), (1, 4));
        assert_eq!(
            snapshot
                .events
                .iter()
                .map(|event| (event.sequence, event.kind))
                .collect::<Vec<_>>(),
            vec![(1, "started"), (2, "settled"), (3, "started")]
        );
        assert_eq!(snapshot.events[0].session_id, snapshot.events[1].session_id);
        assert_eq!(snapshot.events[1].charge_units.as_deref(), Some("0"));
        assert_eq!(
            snapshot.events[1].balance_units.as_deref(),
            Some(u128::MAX.to_string().as_str())
        );
        let output = serde_json::to_string(&snapshot).unwrap();
        for secret in [
            "private-request-id",
            "secret_payload",
            "not exported",
            "next_anchor",
            "response_payload",
        ] {
            assert!(!output.contains(secret));
        }
        let start = serde_json::to_value(&snapshot.events[0]).unwrap();
        assert_eq!(start.as_object().unwrap().len(), 3);
    }

    #[test]
    fn session_events_bounded_history_and_instance_reset() {
        let events = SessionEvents::new();
        for id in 0..140 {
            events.started(&id.to_string());
        }
        let snapshot = events.snapshot();
        assert_eq!(snapshot.events.len(), EVENT_LIMIT);
        assert_eq!((snapshot.first_sequence, snapshot.next_sequence), (13, 141));
        assert_eq!(snapshot.events.last().unwrap().sequence, 140);
        let restarted = SessionEvents::new().snapshot();
        assert_ne!(snapshot.instance_id, restarted.instance_id);
        assert_eq!((restarted.first_sequence, restarted.next_sequence), (1, 1));
    }

    #[test]
    fn session_events_accept_settlements_with_charge_basis_and_reason() {
        // Hardened servers keep the per-key-source payload types and add only
        // charge_basis and settlement_reason (plus usage detail) fields.
        let events = SessionEvents::new();
        for (index, payload) in [
            json!({"type":"oa_org_ephemeral_lease_settlement", "charge_basis":"measured",
                "charged_usage_credits":"5"}),
            json!({"type":"openrouter_ephemeral_lease_settlement", "charge_basis":"clamped",
                "reported_usage_micro_usd":"900", "charged_usage_micro_usd":"500"}),
            json!({"type":"oa_org_ephemeral_lease_settlement", "charge_basis":"worst_case",
                "settlement_reason":"settlement_deadline"}),
            json!({"type":"openrouter_ephemeral_lease_settlement", "charge_basis":"worst_case",
                "settlement_reason":"unsettleable", "billing_quote":{"asset":"native_eth"}}),
        ]
        .into_iter()
        .enumerate()
        {
            let mut response = settled_response(&format!("lease-{index}"), 5);
            response.response_payload = payload.to_string();
            events.settled(&response, Some(10));
        }
        let snapshot = events.snapshot();
        assert_eq!(snapshot.events.len(), 4);
        assert!(snapshot.events.iter().all(|event| event.kind == "settled"
            && event.charge_units.as_deref() == Some("5")
            && event.balance_units.as_deref() == Some("10")));
        let output = serde_json::to_string(&snapshot).unwrap();
        for private in [
            "charge_basis",
            "worst_case",
            "settlement_reason",
            "billing_quote",
        ] {
            assert!(!output.contains(private));
        }
    }

    #[test]
    fn session_events_skip_nonlease_and_unknown_balance() {
        let events = SessionEvents::new();
        let mut response = settled_response("receipt", 123);
        events.settled(&response, None);
        response.response_payload = "{}".into();
        events.settled(&response, Some(456));
        response.response_payload = "invalid".into();
        events.settled(&response, Some(456));
        assert!(events.snapshot().events.is_empty());
        // Restart recovery may legitimately have no retained start event.
        events.settled(&settled_response("receipt", 123), Some(456));
        let event = &events.snapshot().events[0];
        assert_eq!(event.kind, "settled");
        assert_eq!(event.charge_units.as_deref(), Some("123"));
        assert_eq!(event.balance_units.as_deref(), Some("456"));
    }
}
