//! Fixed-price tickets through the processor, with real Groth16 request
//! proofs, a mock price feed and vault RPC, and a mock OA org whose
//! `request_key` replays one key per upstream request ID (as the org does).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::post;
use axum::{Json, Router};
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use zkapi_types::wire::{TicketAuthorization, TicketTermsV1, TICKET_MODE};
use zkapi_types::Felt252;

use super::*;
use crate::config::{OpenRouterLeaseConfig, OpenRouterLeaseSourceConfig, ServerConfig};
use crate::nullifier_store::NullifierStore;
use crate::signer::ServerSigner;
use crate::test_support::{processor_note, setup_directory, TestNote};
use crate::tickets::TicketCatalog;

const VAULT: &str = "0x0000000000000000000000000000000000000001";
const FEED: &str = "0x694aa1769357215de4fac081bf1f309adc325306";
/// $1000/ETH with 8 decimals: one micro-USD is one gwei.
const ANSWER: u128 = 100_000_000_000;
const DEPOSIT: u128 = 5_000_000;
const CAP: u128 = 100_000;

fn seeds() -> (Felt252, Felt252) {
    (Felt252::from_u64(21), Felt252::from_u64(22))
}

fn instant() -> TicketTermsV1 {
    TicketTermsV1 {
        tier_id: 1,
        tier_name: "Instant".into(),
        oa_tickets: 4,
        price_micro_usd: 560_000,
        credit_limit_micro_usd: 3_000_000,
        duration_seconds: 3_600,
    }
}

fn premium() -> TicketTermsV1 {
    TicketTermsV1 {
        tier_id: 3,
        tier_name: "Premium".into(),
        oa_tickets: 3,
        price_micro_usd: 420_000,
        credit_limit_micro_usd: 4_000_000,
        duration_seconds: 3_600,
    }
}

#[derive(Default)]
struct Mock {
    /// Nullifiers the vault reports used.
    spent: bool,
    /// Fail the next OA request_key with a 503 (an ambiguous outcome).
    fail_next_create: bool,
    /// Issue the key, then lose the reply (the org issued it).
    lose_next_reply: bool,
    policy_reject: bool,
    /// Fail every vault usedNullifiers read after this many.
    fail_nullifier_reads_after: Option<usize>,
    nullifier_reads: usize,
    creates: usize,
    replays: usize,
    /// One key per upstream request ID: (key, hash, expires_at).
    issued: HashMap<String, (String, String, u64)>,
    /// Bodies of request_key calls, without secrets.
    bodies: Vec<Value>,
    updated_at: u64,
}

type MockState = Arc<Mutex<Mock>>;

fn word(value: u128) -> String {
    format!("{value:064x}")
}

async fn rpc(State(state): State<MockState>, Json(body): Json<Value>) -> Json<Value> {
    let mut state = state.lock().unwrap();
    let result = match body["method"].as_str().unwrap() {
        "eth_chainId" => json!("0x1"),
        "eth_call" => {
            let to = body["params"][0]["to"].as_str().unwrap().to_lowercase();
            let data = body["params"][0]["data"].as_str().unwrap().to_string();
            let used = Keccak256::digest(b"usedNullifiers(uint256)");
            let round = || {
                format!(
                    "0x{}{}{}{}{}",
                    word(123),
                    word(ANSWER),
                    word(u128::from(state.updated_at)),
                    word(u128::from(state.updated_at)),
                    word(123)
                )
            };
            if to == FEED && data == "0x313ce567" {
                json!(format!("0x{}", word(8)))
            } else if to == FEED && (data == "0xfeaf968c" || data.starts_with("0x9a6fc8f5")) {
                json!(round())
            } else if to == VAULT && data == "0x4d1352fd" {
                json!(format!("0x{}", word(1_000_000_000)))
            } else if to == VAULT && data.starts_with(&format!("0x{}", hex::encode(&used[..4]))) {
                state.nullifier_reads += 1;
                if state
                    .fail_nullifier_reads_after
                    .is_some_and(|limit| state.nullifier_reads > limit)
                {
                    return Json(json!({"jsonrpc":"2.0","id":1,
                        "error":{"code":-32000,"message":"unavailable"}}));
                }
                json!(format!("0x{}", word(u128::from(state.spent))))
            } else {
                panic!("unexpected eth_call {to} {data}");
            }
        }
        method => panic!("unexpected RPC {method}"),
    };
    Json(json!({"jsonrpc":"2.0","id":1,"result":result}))
}

async fn request_key(
    State(state): State<MockState>,
    Json(body): Json<Value>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let mut state = state.lock().unwrap();
    state.bodies.push(body.clone());
    if state.fail_next_create {
        state.fail_next_create = false;
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"detail":"station unavailable"})),
        ));
    }
    if state.policy_reject {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"detail":"duration_minutes exceeds zkAPI policy"})),
        ));
    }
    let id = body["client_request_id"].as_str().unwrap().to_string();
    let duration = body["duration_minutes"].as_u64().unwrap();
    let replayed = state.issued.contains_key(&id);
    let count = state.issued.len();
    let (key, hash, expires_at) = state
        .issued
        .entry(id)
        .or_insert_with(|| {
            (
                format!("runtime-key-{count}"),
                format!("key-hash-{count}"),
                current_timestamp() + duration * 60,
            )
        })
        .clone();
    if replayed {
        state.replays += 1;
    } else {
        state.creates += 1;
    }
    if state.lose_next_reply {
        state.lose_next_reply = false;
        return Err((
            StatusCode::BAD_GATEWAY,
            Json(json!({"detail":"reply lost"})),
        ));
    }
    Ok(Json(
        json!({"source":"oa_org", "replayed": replayed, "key": key, "key_hash": hash,
        "credit_limit": body["credit_limit"], "duration_minutes": duration,
        "expires_at_unix": expires_at, "station_id":"station",
        "station_recently_attested": true, "station_signature":"ab".repeat(64),
        "org_signature":"cd".repeat(64), "verifier_url":"https://verifier.example",
        "openrouter_api_base":"https://openrouter.ai/api/v1"}),
    ))
}

struct Harness {
    processor: RequestProcessor,
    state: MockState,
    note: TestNote,
    server: tokio::task::JoinHandle<()>,
    url: String,
}

fn catalog() -> Arc<TicketCatalog> {
    Arc::new(
        TicketCatalog::from_json(
            &json!({"version": 1, "tiers": [instant(), premium()]}).to_string(),
        )
        .unwrap(),
    )
}

fn processor_at(
    store: Arc<NullifierStore>,
    url: &str,
    catalog: Option<Arc<TicketCatalog>>,
) -> RequestProcessor {
    let signer = Arc::new(ServerSigner::new(&seeds().0, &seeds().1));
    let mut processor = RequestProcessor::try_new(
        ServerConfig {
            request_charge_cap: CAP,
            contract_address: Felt252::from_u64(1),
            native_billing: Some(crate::native_billing::NativeBillingConfig {
                rpc_url: format!("{url}/rpc"),
                feed_address: FEED.into(),
                decimals: 8,
                max_age_seconds: 4500,
            }),
            proof_setup_dir: setup_directory(),
            openrouter_leases: Some(OpenRouterLeaseConfig {
                source: OpenRouterLeaseSourceConfig::OaOrg {
                    org_base_url: url.into(),
                    shared_secret: "test-secret".into(),
                },
                ttl_seconds: 300,
                settlement_grace_seconds: 0,
                settlement_poll_seconds: 1,
                settlement_deadline_seconds: crate::config::DEFAULT_SETTLEMENT_DEADLINE_SECONDS,
            }),
            ticket_catalog: catalog,
            ..Default::default()
        },
        store,
        signer,
        Felt252::ZERO,
    )
    .unwrap();
    processor.oa_org = Some(Arc::new(
        OaOrgProvisioner::new(url.into(), "test-secret".into()).unwrap(),
    ));
    processor
}

async fn harness_with(store: Arc<NullifierStore>, catalog: Option<Arc<TicketCatalog>>) -> Harness {
    let state = Arc::new(Mutex::new(Mock {
        updated_at: current_timestamp() - 10,
        ..Mock::default()
    }));
    let app = Router::new()
        .route("/rpc", post(rpc))
        .route("/api/zkapi/request_key", post(request_key))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let processor = processor_at(store, &url, catalog);
    let note = processor_note(&processor, seeds(), DEPOSIT);
    Harness {
        processor,
        state,
        note,
        server,
        url,
    }
}

async fn harness() -> Harness {
    harness_with(
        Arc::new(NullifierStore::in_memory().unwrap()),
        Some(catalog()),
    )
    .await
}

impl Harness {
    fn quote(&self) -> NativeBillingQuote {
        let updated_at = self.state.lock().unwrap().updated_at;
        NativeBillingQuote {
            asset: "native_eth".into(),
            units_per_eth: 1_000_000_000,
            chain_id: 1,
            feed_address: FEED.into(),
            round_id: "123".into(),
            answer: ANSWER.to_string(),
            decimals: 8,
            updated_at,
            expires_at: updated_at + 4500,
        }
    }

    /// The purchase payload: mode, version, terms, price and quote.
    fn payload(&self, terms: &TicketTermsV1, price_units: u64) -> String {
        let mut payload = serde_json::to_value(TicketAuthorization {
            mode: TICKET_MODE.into(),
            version: 1,
            ticket: terms.clone(),
            price_units,
        })
        .unwrap();
        payload["billing_quote"] = serde_json::to_value(self.quote()).unwrap();
        payload.to_string()
    }

    fn prepare(
        &self,
        id: &str,
        terms: &TicketTermsV1,
        price_units: u64,
        bound: u128,
    ) -> crate::test_support::PreparedTestRequest {
        let now = current_timestamp();
        let prepared = self
            .note
            .prepare_request(id, self.payload(terms, price_units), now, bound);
        self.processor
            .update_root(prepared.request.public_inputs.active_root);
        prepared
    }

    fn buy_prepared(
        &self,
        id: &str,
        terms: &TicketTermsV1,
    ) -> crate::test_support::PreparedTestRequest {
        let price = terms.price_micro_usd;
        self.prepare(id, terms, price, u128::from(price).max(CAP))
    }

    fn lease(&self, id: &str) -> OpenRouterLeaseRecord {
        self.processor.store.lookup_openrouter_lease(id).unwrap()
    }
}

fn successor(issued: &IssuedOpenRouterLease) -> &RequestResponseV2 {
    issued
        .request_response
        .as_ref()
        .expect("a ticket returns its successor")
}

#[tokio::test]
async fn a_ticket_settles_at_its_fixed_price_and_returns_its_signed_successor() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("ticket-one", &instant());
    let issued = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    assert_eq!(issued.ticket.as_ref(), Some(&instant()));
    assert_eq!(issued.key_source, "oa_org");
    assert_eq!(issued.lease.api_key, "runtime-key-0");
    assert_eq!(issued.lease.spending_limit_usd, 3.0);
    let response = successor(&issued).clone();
    assert_eq!(response.charge_applied, 560_000);
    let payload: Value = serde_json::from_str(&response.response_payload).unwrap();
    assert_eq!(payload["type"], "zkapi_ticket_settlement");
    assert_eq!(payload["charge_basis"], "ticket");
    assert_eq!(payload["ticket"], serde_json::to_value(instant()).unwrap());
    assert_eq!(payload["price_units"], "560000");
    assert_eq!(
        payload["billing_quote"],
        serde_json::to_value(h.quote()).unwrap()
    );
    // The org was asked for the tier's allowance and lifetime, never the
    // proof-bound budget.
    let body = h.state.lock().unwrap().bodies[0].clone();
    assert_eq!(body["credit_limit"], 3.0);
    assert_eq!(body["credit_limit_credits"], 3_000_000);
    assert_eq!(body["duration_minutes"], 60);
    // The client's S1–S6 checks accept it; the balance falls by the price.
    h.note.complete(&prepared, &response).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT - 560_000);
    let lease = h.lease("ticket-one");
    assert_eq!(lease.status, "finalized");
    assert_eq!(lease.charge_basis.as_deref(), Some("ticket"));
    assert_eq!(lease.delivered, Some(true));
    assert_eq!(lease.charge_applied, Some(560_000));
    let record = h
        .processor
        .store
        .lookup_by_nullifier(&prepared.request.public_inputs.request_nullifier)
        .unwrap();
    assert_eq!(record.status, NullifierStatus::Finalized);
    assert_eq!(record.settled_basis.as_deref(), Some("ticket"));
    // Recovery serves the same signed successor.
    let recovered = h.processor.recover_now("ticket-one").unwrap();
    assert_eq!(recovered.nullifier_status, "finalized");
    assert_eq!(
        recovered.request_response.unwrap().next_state_signature,
        response.next_state_signature
    );
    // The settlement sweep never charges it again.
    h.processor.settle_due_openrouter_leases().await;
    assert_eq!(h.lease("ticket-one").charge_applied, Some(560_000));
}

/// The next ticket is bought from the installed successor at once: no
/// retirement, usage receipt or expiry of the first key is involved, and
/// each ticket has its own key.
#[tokio::test]
async fn tickets_chain_immediately_and_each_has_its_own_key() {
    let mut h = harness().await;
    let mut keys = Vec::new();
    let mut expected = DEPOSIT;
    for (step, terms) in [instant(), premium(), instant()].iter().enumerate() {
        let id = format!("chain-{step}");
        let prepared = h.buy_prepared(&id, terms);
        let issued = h
            .processor
            .issue_openrouter_lease(&prepared.request)
            .await
            .unwrap();
        h.note.complete(&prepared, successor(&issued)).unwrap();
        expected -= u128::from(terms.price_micro_usd);
        assert_eq!(h.note.state.balance, expected);
        keys.push(issued.lease.api_key.clone());
        // The earlier keys are untouched: still active, still unexpired.
        assert!(issued.lease.expires_at > current_timestamp() + 3_000);
    }
    keys.dedup();
    assert_eq!(keys.len(), 3);
    assert_eq!(h.state.lock().unwrap().creates, 3);
}

/// A lost purchase response is retried with the exact saved request: the
/// same successor and the same key, replayed by the org, never a second
/// charge or a second key; a restart in between changes nothing.
#[tokio::test]
async fn exact_retries_and_restarts_never_charge_twice_or_mint_a_second_key() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.db");
    let h = harness_with(
        Arc::new(NullifierStore::new(&path).unwrap()),
        Some(catalog()),
    )
    .await;
    let prepared = h.buy_prepared("lost-reply", &instant());
    let first = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    let second = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    assert_eq!(second.lease.api_key, first.lease.api_key);
    assert_eq!(
        successor(&second).next_state_signature,
        successor(&first).next_state_signature
    );
    // Restart: a new processor on the same database.
    let Harness {
        processor,
        state,
        note,
        server: _server,
        url,
    } = h;
    drop(processor);
    let restarted = processor_at(
        Arc::new(NullifierStore::new(&path).unwrap()),
        &url,
        Some(catalog()),
    );
    restarted.update_root(prepared.request.public_inputs.active_root);
    let third = restarted
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    assert_eq!(third.lease.api_key, first.lease.api_key);
    assert_eq!(successor(&third).charge_applied, 560_000);
    assert_eq!(
        successor(&third).next_commitment,
        successor(&first).next_commitment
    );
    {
        let state = state.lock().unwrap();
        assert_eq!(state.creates, 1);
        assert_eq!(state.replays, 2);
    }
    let lease = restarted
        .store
        .lookup_openrouter_lease("lost-reply")
        .unwrap();
    assert_eq!(lease.charge_applied, Some(560_000));
    let mut note = note;
    note.complete(&prepared, successor(&third)).unwrap();
    assert_eq!(note.state.balance, DEPOSIT - 560_000);
    // Restarted retirement or settlement of the paid ticket changes nothing.
    restarted.settle_due_openrouter_leases().await;
    assert_eq!(
        restarted
            .store
            .lookup_openrouter_lease("lost-reply")
            .unwrap()
            .charge_applied,
        Some(560_000)
    );
}

#[tokio::test]
async fn a_spent_state_cannot_buy_a_second_ticket() {
    let h = harness().await;
    let prepared = h.buy_prepared("first", &instant());
    h.processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    // The same state (and nullifier) under another request ID or terms.
    let again = h.buy_prepared("second", &premium());
    assert_eq!(
        again.request.public_inputs.request_nullifier,
        prepared.request.public_inputs.request_nullifier
    );
    assert!(matches!(
        h.processor.issue_openrouter_lease(&again.request).await,
        Err(ServerError::Replay)
    ));
    // The same request ID with another body.
    let mut changed = prepared.request.clone();
    changed.proof.proof = crate::test_support::fake_proof(4);
    assert!(matches!(
        h.processor.issue_openrouter_lease(&changed).await,
        Err(ServerError::Replay)
    ));
    assert_eq!(h.state.lock().unwrap().creates, 1);
}

#[tokio::test]
async fn invalid_tiers_prices_and_bounds_reserve_nothing() {
    let h = harness().await;
    let refused = |prepared: crate::test_support::PreparedTestRequest| {
        let processor = &h.processor;
        async move {
            let error = processor
                .issue_openrouter_lease(&prepared.request)
                .await
                .err()
                .expect("refused");
            assert!(processor
                .store
                .lookup_by_nullifier(&prepared.request.public_inputs.request_nullifier)
                .is_none());
            error
        }
    };
    // A price that is not the conversion at the bound quote.
    assert!(matches!(
        refused(h.prepare("cheap", &instant(), 1, CAP)).await,
        ServerError::TicketTermsMismatch(_)
    ));
    // A tier this server does not sell.
    let unknown = TicketTermsV1 {
        tier_id: 9,
        oa_tickets: 9,
        ..instant()
    };
    assert!(matches!(
        refused(h.buy_prepared("unknown", &unknown)).await,
        ServerError::TicketTermsMismatch(_)
    ));
    // A known tier at other terms (a larger allowance for the same price).
    let richer = TicketTermsV1 {
        credit_limit_micro_usd: 50_000_000,
        ..instant()
    };
    assert!(matches!(
        refused(h.buy_prepared("richer", &richer)).await,
        ServerError::TicketTermsMismatch(_)
    ));
    // A solvency bound that does not cover the price.
    assert!(matches!(
        refused(h.prepare("unbacked", &instant(), 560_000, 559_999)).await,
        ServerError::InvalidRequest(_)
    ));
    assert_eq!(h.state.lock().unwrap().bodies.len(), 0);
}

#[tokio::test]
async fn a_server_without_a_catalog_sells_no_tickets_and_meters_as_before() {
    let h = harness_with(Arc::new(NullifierStore::in_memory().unwrap()), None).await;
    let prepared = h.buy_prepared("no-catalog", &instant());
    assert!(matches!(
        h.processor.issue_openrouter_lease(&prepared.request).await,
        Err(ServerError::TicketTermsMismatch(_))
    ));
    assert!(h.processor.ticket_catalog().is_none());
    // A metered lease from the same wallet still opens and is not settled
    // at purchase.
    let now = current_timestamp();
    let payload = json!({"mode":"openrouter_ephemeral_lease","version":1,
        "billing_quote": h.quote()})
    .to_string();
    let metered = h.note.prepare_request("metered", payload, now, 1_000_000);
    h.processor
        .update_root(metered.request.public_inputs.active_root);
    let issued = h
        .processor
        .issue_openrouter_lease(&metered.request)
        .await
        .unwrap();
    assert!(issued.request_response.is_none() && issued.ticket.is_none());
    assert_eq!(issued.lease.spending_limit_usd, 1.0);
    assert_eq!(h.lease("metered").status, "active");
    assert!(h.lease("metered").charge_basis.is_none());
}

#[tokio::test]
async fn a_ticket_and_a_metered_lease_alternate_on_one_note() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("ticket-first", &instant());
    let issued = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    h.note.complete(&prepared, successor(&issued)).unwrap();
    // A metered lease from the ticket's successor, settled from usage.
    let now = current_timestamp();
    let payload = json!({"mode":"openrouter_ephemeral_lease","version":1,
        "billing_quote": h.quote()})
    .to_string();
    let metered = h
        .note
        .prepare_request("metered-next", payload, now, 1_000_000);
    h.processor
        .update_root(metered.request.public_inputs.active_root);
    h.processor
        .issue_openrouter_lease(&metered.request)
        .await
        .unwrap();
    h.processor
        .settle_request_for_test(
            &metered.request,
            SettlementResult {
                status_code: 200,
                payload: json!({"billing_quote": h.quote(), "usage_credits": 1234}).to_string(),
                charge_applied: 1_234,
                usage: None,
                billing_label: "metered".into(),
            },
        )
        .unwrap();
    let response = h.processor.sign_settled(&metered.request).unwrap();
    h.note.complete(&metered, &response).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT - 560_000 - 1_234);
    // And a ticket again from the metered successor.
    let next = h.buy_prepared("ticket-again", &premium());
    let issued = h
        .processor
        .issue_openrouter_lease(&next.request)
        .await
        .unwrap();
    h.note.complete(&next, successor(&issued)).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT - 560_000 - 1_234 - 420_000);
}

/// An ambiguous org failure leaves the ticket unpaid and undelivered; the
/// exact retry gets the key and pays once.
#[tokio::test]
async fn an_ambiguous_issuance_is_paid_once_on_retry() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("ambiguous", &instant());
    h.state.lock().unwrap().fail_next_create = true;
    assert!(h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .is_err());
    let lease = h.lease("ambiguous");
    assert_eq!(lease.status, "provisioning");
    assert!(lease.charge_basis.is_none());
    assert_eq!(lease.delivered, Some(false));
    // The org issued a key but the reply was lost.
    h.state.lock().unwrap().lose_next_reply = true;
    assert!(h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .is_err());
    assert!(h.lease("ambiguous").charge_basis.is_none());
    let issued = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    h.note.complete(&prepared, successor(&issued)).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT - 560_000);
    let state = h.state.lock().unwrap();
    assert_eq!((state.creates, state.replays), (1, 1));
}

/// The vault read after issuance fails: the key is activated but neither
/// delivered nor charged. The retry delivers that same key and charges once;
/// a failure while signing after the charge is retried without a charge.
#[tokio::test]
async fn failures_around_the_charge_never_double_charge() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("activated", &instant());
    // Reads: before issuance (1), before the charge (2).
    h.state.lock().unwrap().fail_nullifier_reads_after = Some(1);
    assert!(h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .is_err());
    let lease = h.lease("activated");
    assert_eq!(lease.status, "active");
    assert_eq!(lease.delivered, Some(false));
    assert!(lease.charge_basis.is_none());
    // Signing fails after the charge (the test chain is unavailable).
    h.state.lock().unwrap().fail_nullifier_reads_after = None;
    h.processor.test_chain().unavailable = true;
    assert!(h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .is_err());
    let lease = h.lease("activated");
    assert_eq!(lease.charge_basis.as_deref(), Some("ticket"));
    assert_eq!(lease.delivered, Some(true));
    h.processor.test_chain().unavailable = false;
    let issued = h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .unwrap();
    assert_eq!(issued.lease.api_key, "runtime-key-0");
    h.note.complete(&prepared, successor(&issued)).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT - 560_000);
    assert_eq!(h.state.lock().unwrap().creates, 1);
}

/// A key the org issued but this server never delivered settles at zero,
/// and an exact retry afterwards gets no key and no charge.
#[tokio::test]
async fn an_undelivered_ticket_settles_at_zero_and_is_never_delivered_later() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("abandoned", &instant());
    h.state.lock().unwrap().fail_nullifier_reads_after = Some(1);
    assert!(h
        .processor
        .issue_openrouter_lease(&prepared.request)
        .await
        .is_err());
    h.state.lock().unwrap().fail_nullifier_reads_after = None;
    // Its settlement deadline passes (the sweep holds the issuance lock).
    h.processor.store.execute_for_test(
        "UPDATE openrouter_leases SET settle_after = 0, settlement_deadline_at = 0",
        [],
    );
    h.processor.settle_due_openrouter_leases().await;
    h.processor.sign_settled_now();
    let lease = h.lease("abandoned");
    assert_eq!(lease.status, "finalized");
    assert_eq!(lease.charge_basis.as_deref(), Some("unissued"));
    assert!(matches!(
        h.processor.issue_openrouter_lease(&prepared.request).await,
        Err(ServerError::TicketUnissued)
    ));
    let response = h
        .processor
        .recover_now("abandoned")
        .unwrap()
        .request_response
        .unwrap();
    assert_eq!(response.charge_applied, 0);
    h.note.complete(&prepared, &response).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT);
}

#[tokio::test]
async fn an_org_policy_rejection_settles_at_zero() {
    let mut h = harness().await;
    let prepared = h.buy_prepared("rejected", &instant());
    h.state.lock().unwrap().policy_reject = true;
    assert!(matches!(
        h.processor.issue_openrouter_lease(&prepared.request).await,
        Err(ServerError::OaKeyPolicyRejected)
    ));
    let response = h
        .processor
        .recover_now("rejected")
        .unwrap()
        .request_response
        .unwrap();
    assert_eq!(response.charge_applied, 0);
    assert!(matches!(
        h.processor.issue_openrouter_lease(&prepared.request).await,
        Err(ServerError::TicketUnissued)
    ));
    h.note.complete(&prepared, &response).unwrap();
    assert_eq!(h.note.state.balance, DEPOSIT);
}

#[tokio::test]
async fn a_withdrawn_state_buys_nothing() {
    let h = harness().await;
    let prepared = h.buy_prepared("withdrawn", &instant());
    h.state.lock().unwrap().spent = true;
    assert!(matches!(
        h.processor.issue_openrouter_lease(&prepared.request).await,
        Err(ServerError::NullifierUsed)
    ));
    assert_eq!(h.state.lock().unwrap().bodies.len(), 0);
    assert!(h.lease("withdrawn").charge_basis.is_none());
}

#[tokio::test]
async fn the_catalog_lists_the_tiers_on_sale() {
    let h = harness().await;
    let catalog = h.processor.ticket_catalog().unwrap();
    assert_eq!(catalog.version, 1);
    assert_eq!(catalog.key_source, "oa_org");
    assert_eq!(catalog.tiers, vec![instant(), premium()]);
}
