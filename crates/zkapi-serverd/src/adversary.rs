//! Adversarial server behaviours for drills and acceptance tests (§5.5,
//! §10.7 B): `zkapi --adversary <mode> serverd ...`. This module exists only
//! in builds with the `adversary` cargo feature, which no release or Docker
//! build enables; a release binary rejects the flag.
//!
//! * `withhold`: settle every request but never sign its successor;
//!   recovery keeps answering `reserved`.
//! * `born-spent`: sign successors at anchor 1 (genesis).
//! * `reuse-anchor`: sign every successor at the first anchor this process
//!   signed.
//! * `random-anchor`: sign successors at a random anchor.
//! * `overcharge`: charge one unit above the request's solvency bound.
//! * `lie-expired`: answer every expiry check `expired_unaccepted`, also for
//!   a reserved request (whose proof the server keeps).
//! * `hang`: hold every HTTP connection open, drip a byte at a time, then
//!   answer 429 or 503 with a long `Retry-After`.

use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use axum::{
    body::Body,
    http::{header, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use zkapi_proof::compact::random_field;
use zkapi_types::wire::ApiRequestV2;
use zkapi_types::Felt252;

use crate::error::ServerError;
use crate::nullifier_store::SettledCharge;
use crate::successor::{
    build_adversarial_successor, derived_anchor, Deployment, SignedSuccessor, StateSigner,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum AdversaryMode {
    Withhold,
    BornSpent,
    ReuseAnchor,
    RandomAnchor,
    Overcharge,
    LieExpired,
    Hang,
}

static MODE: OnceLock<AdversaryMode> = OnceLock::new();
/// The anchor `reuse-anchor` reuses: the first one this process signed.
static REUSED_ANCHOR: Mutex<Option<Felt252>> = Mutex::new(None);
/// Seconds between the bytes a hanging response drips, and how long it
/// drips before it ends.
pub const HANG_DRIP_SECONDS: u64 = 5;
pub const HANG_TOTAL_SECONDS: u64 = 600;
/// The `Retry-After` of a hanging response.
pub const HANG_RETRY_AFTER_SECONDS: u64 = 86_400;

/// Set the process's adversary mode, once, before the server starts.
pub fn set(mode: AdversaryMode) -> anyhow::Result<()> {
    MODE.set(mode)
        .map_err(|_| anyhow::anyhow!("the adversary mode is already set"))?;
    tracing::warn!(
        ?mode,
        "ADVERSARY MODE: this server deliberately misbehaves (drill build)"
    );
    Ok(())
}

pub fn mode() -> Option<AdversaryMode> {
    MODE.get().copied()
}

/// The successor an adversary signs instead of the honest one, if its mode
/// changes successors.
pub(crate) fn successor<S: StateSigner + ?Sized>(
    mode: Option<AdversaryMode>,
    signer: &S,
    deployment: &Deployment,
    request: &ApiRequestV2,
    settled: &SettledCharge,
    now: u64,
) -> Option<Result<SignedSuccessor, ServerError>> {
    let public = &request.public_inputs;
    let honest = derived_anchor(&public.request_nullifier);
    let (charge, anchor) = match mode? {
        AdversaryMode::BornSpent => (settled.charge, Felt252::ONE),
        AdversaryMode::RandomAnchor => (settled.charge, random_field()),
        AdversaryMode::ReuseAnchor => {
            let mut reused = REUSED_ANCHOR
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (settled.charge, *reused.get_or_insert(honest))
        }
        AdversaryMode::Overcharge => (public.solvency_bound.saturating_add(1), honest),
        AdversaryMode::Withhold | AdversaryMode::LieExpired | AdversaryMode::Hang => return None,
    };
    Some(build_adversarial_successor(
        signer,
        deployment,
        request,
        settled,
        (charge, anchor),
        now,
    ))
}

/// `hang`: every request is held open while a byte drips every
/// `drip`, for `total`, then the response ends; its status alternates
/// between 429 and 503, with `Retry-After` a day away.
pub async fn hang_layer(request: Request<Body>, next: Next) -> Response {
    if mode() != Some(AdversaryMode::Hang) {
        return next.run(request).await;
    }
    hang_response(
        Duration::from_secs(HANG_DRIP_SECONDS),
        Duration::from_secs(HANG_TOTAL_SECONDS),
    )
}

pub(crate) fn hang_response(drip: Duration, total: Duration) -> Response {
    static COUNT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let status = if COUNT
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        .is_multiple_of(2)
    {
        StatusCode::TOO_MANY_REQUESTS
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let drips = (total.as_millis() / drip.as_millis().max(1)).max(1) as u64;
    let stream = futures_util::stream::unfold(0u64, move |sent| async move {
        if sent >= drips {
            return None;
        }
        tokio::time::sleep(drip).await;
        Some((
            Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b" ")),
            sent + 1,
        ))
    });
    Response::builder()
        .status(status)
        .header(header::RETRY_AFTER, HANG_RETRY_AFTER_SECONDS.to_string())
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from_stream(stream))
        .expect("a static response")
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_proof::compact::CompactSigner;

    fn settled() -> SettledCharge {
        SettledCharge {
            charge: 1,
            basis: "measured".into(),
            response_code: 200,
            response_payload: "{}".into(),
            settled_at: 0,
        }
    }

    async fn request() -> ApiRequestV2 {
        crate::watcher::tests::finalized_v2_request().await.1
    }

    #[tokio::test]
    async fn adversarial_successors_break_the_rules_a_client_checks() {
        let request = request().await;
        let public = &request.public_inputs;
        let deployment = Deployment {
            protocol_version: public.protocol_version,
            chain_id: public.chain_id,
            contract_address: public.contract_address,
        };
        let signer = CompactSigner::try_from_seed(&Felt252::from_u64(0x5eed)).unwrap();
        let honest = derived_anchor(&public.request_nullifier);
        let successor = |mode| {
            successor(Some(mode), &signer, &deployment, &request, &settled(), 0)
                .unwrap()
                .unwrap()
                .response
        };
        // S4 fails: anchor 1, a random anchor.
        assert_eq!(
            successor(AdversaryMode::BornSpent).next_anchor,
            Felt252::ONE
        );
        let random = successor(AdversaryMode::RandomAnchor).next_anchor;
        assert_ne!(random, honest);
        assert_ne!(random, Felt252::ONE);
        // S3 fails: a charge above the request's bound.
        let over = successor(AdversaryMode::Overcharge);
        assert_eq!(over.charge_applied, public.solvency_bound + 1);
        assert_eq!(over.next_anchor, honest);
        // The first anchor this process signs is reused for every later one.
        let first = successor(AdversaryMode::ReuseAnchor).next_anchor;
        assert_eq!(successor(AdversaryMode::ReuseAnchor).next_anchor, first);
        // The other modes, and honest servers, sign nothing here.
        for mode in [
            Some(AdversaryMode::Withhold),
            Some(AdversaryMode::LieExpired),
            Some(AdversaryMode::Hang),
            None,
        ] {
            assert!(successor_none(mode, &signer, &deployment, &request));
        }
    }

    fn successor_none(
        mode: Option<AdversaryMode>,
        signer: &CompactSigner,
        deployment: &Deployment,
        request: &ApiRequestV2,
    ) -> bool {
        successor(mode, signer, deployment, request, &settled(), 0).is_none()
    }

    #[tokio::test]
    async fn a_hanging_response_drips_and_answers_429_or_503_with_a_long_retry_after() {
        let started = std::time::Instant::now();
        let mut statuses = Vec::new();
        for _ in 0..2 {
            let response = hang_response(Duration::from_millis(50), Duration::from_millis(200));
            statuses.push(response.status());
            assert_eq!(
                response.headers()[header::RETRY_AFTER],
                HANG_RETRY_AFTER_SECONDS.to_string()
            );
            let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap();
            assert_eq!(body.len(), 4, "one byte per drip");
        }
        statuses.sort();
        assert_eq!(
            statuses,
            [
                StatusCode::TOO_MANY_REQUESTS,
                StatusCode::SERVICE_UNAVAILABLE
            ]
        );
        assert!(started.elapsed() >= Duration::from_millis(400));
    }
}
