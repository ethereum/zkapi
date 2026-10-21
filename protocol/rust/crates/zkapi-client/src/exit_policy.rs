//! Exit decisions of circuit `zkapi-v2-concession-v1` (design §6.3 C4 and
//! §6.4 E0–E6) as pure functions of local facts.
//!
//! Nothing here reads the network or the clock: callers pass `now`, the
//! server's readings and chain facts in, so the companion and the browser SDK
//! decide identically on the same inputs. `tests/vectors/exit-rules.json`
//! holds the shared vectors both implementations must reproduce.

use serde::{Deserialize, Serialize};

/// E0: the latest an operator HTTP call made in exit mode may take, connect
/// and full body included. A timeout, 5xx or 429 counts as unreachable and
/// `Retry-After` is ignored.
pub const CALL_TIMEOUT_SECONDS: u64 = 20;
/// E0: the most one E1 recovery pass may take.
pub const RECOVERY_BUDGET_SECONDS: u64 = 120;
/// E0: `must_initiate_by = E_low − 43,200`.
pub const INITIATE_MARGIN_SECONDS: u64 = 43_200;
/// E2 step 2: within this long of `must_initiate_by` a fresh state escapes
/// with nothing conceded instead of asking for a clearance.
pub const MUTUAL_CUTOFF_SECONDS: u64 = 3_600;
/// E3: the slack after a request's settlement deadline before escaping.
pub const SETTLEMENT_GRACE_SECONDS: u64 = 900;
/// C4: `now + W + 900 + 3,600 > must_initiate_by` refuses new requests.
pub const NEAR_EXPIRY_MARGIN_SECONDS: u64 = 900 + 3_600;
/// A record whose latest server reading is `unknown` is resolved once that
/// reading was taken this long after the request's `request_time`: the
/// server rejects a stale `request_time`, so it can no longer reserve it.
pub const UNKNOWN_READING_RESOLVES_AFTER_SECONDS: u64 = 1_200;
/// E3's `unsettled_request_escape_after_seconds` knob: default and clamp.
pub const DEFAULT_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 43_200;
pub const MIN_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 3_600;
pub const MAX_UNSETTLED_ESCAPE_AFTER_SECONDS: u64 = 604_800;
/// E6: a released exit proof is dead once a finalized block's timestamp is
/// past its `valid_until` by more than this.
pub const LOCK_RELEASE_MARGIN_SECONDS: u64 = 900;
/// C3: a kept ownership proof is resent only while it stays valid this long.
pub const OWNERSHIP_RESEND_MARGIN_SECONDS: u64 = 5;

/// Archive dispositions (they match the SDK's `zkapiRequestArchive.mjs`).
pub mod disposition {
    pub const PENDING: &str = "pending";
    pub const INSTALLED: &str = "installed";
    pub const SUPERSEDED: &str = "superseded";
    pub const INVALID_SUCCESSOR: &str = "invalid_successor";
    pub const LATE_SUCCESSOR: &str = "late_successor";
    pub const DISCARDED_STALE_ROOT: &str = "discarded_stale_root";
    pub const DISCARDED_EXPIRED_UNACCEPTED: &str = "discarded_expired_unaccepted";
    pub const DISCARDED_SUPERSEDED_UNACCEPTED: &str = "discarded_superseded_unaccepted";
    pub const DISCARDED_CLEARANCE_RESERVED: &str = "discarded_clearance_reserved";
    pub const ABANDONED_FOR_ESCAPE: &str = "abandoned_for_escape";
    pub const EVICTED: &str = "evicted";
}

/// `E_low`: the note's local `expiry_ts`, raised to the smaller of the two
/// `effectiveExpiry` reads only when the user configured an exit RPC and
/// both it and the pinned RPC report a later time. `expiry_ts` is a lower
/// bound of `effectiveExpiry`, so the result is never too late.
pub fn e_low(expiry_ts: u64, pinned_rpc: Option<u64>, exit_rpc: Option<u64>) -> u64 {
    match (pinned_rpc, exit_rpc) {
        (Some(pinned), Some(exit)) if pinned > expiry_ts && exit > expiry_ts => pinned.min(exit),
        _ => expiry_ts,
    }
}

/// E0: the latest second at which an exit decision may start.
pub fn must_initiate_by(e_low: u64) -> u64 {
    e_low.saturating_sub(INITIATE_MARGIN_SECONDS)
}

/// C4: whether a new request must be refused with `note_near_expiry`.
/// `settlement_window` is the build-pinned `settlement_window_seconds` (W).
pub fn note_near_expiry(now: u64, settlement_window: u64, must_initiate_by: u64) -> bool {
    now.saturating_add(settlement_window)
        .saturating_add(NEAR_EXPIRY_MARGIN_SECONDS)
        > must_initiate_by
}

/// E3's knob, clamped to 3,600–604,800 seconds; `None` is the default.
pub fn unsettled_escape_after(configured: Option<u64>) -> u64 {
    configured
        .unwrap_or(DEFAULT_UNSETTLED_ESCAPE_AFTER_SECONDS)
        .clamp(
            MIN_UNSETTLED_ESCAPE_AFTER_SECONDS,
            MAX_UNSETTLED_ESCAPE_AFTER_SECONDS,
        )
}

/// The server's `nullifier_status` for a request's nullifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerReading {
    Unknown,
    Reserved,
    Finalized,
    ClearanceReserved,
    ExitDeferred,
    ExitedUnsigned,
    /// The server could not be asked (timeout, 5xx, 429, invalid answer).
    Unavailable,
}

impl ServerReading {
    /// Map a `RecoveryResponseV2.nullifier_status`. Anything unrecognised is
    /// `Unavailable`, which never resolves a record.
    pub fn from_nullifier_status(status: &str) -> Self {
        match status {
            "unknown" => Self::Unknown,
            "reserved" => Self::Reserved,
            "finalized" => Self::Finalized,
            "clearance_reserved" => Self::ClearanceReserved,
            "exit_deferred" => Self::ExitDeferred,
            "exited_unsigned" => Self::ExitedUnsigned,
            _ => Self::Unavailable,
        }
    }
}

/// One server reading and the second it was taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reading {
    pub status: ServerReading,
    pub observed_at: u64,
}

/// A request released (transmitted, or possibly transmitted) at the state
/// being exited, as the exit decision sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedRecord {
    /// The record's latest disposition (`pending` for the request journal).
    pub disposition: String,
    /// The request's public `request_time` (seconds).
    pub request_time: u64,
    /// When the record was created (seconds).
    pub created_at: u64,
    /// The latest server reading of the request's nullifier, if any.
    #[serde(default)]
    pub reading: Option<Reading>,
}

/// The record classes of §6.4 E1 (they match `zkapiRequestArchive.mjs`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordClass {
    /// The server cannot have reserved it, or can no longer.
    ResolvedUnreserved,
    /// The server may hold a reservation for it.
    Unresolved,
    /// Settled one way or the other: installed, superseded, a late successor.
    Terminal,
}

/// Classify one released record.
///
/// `invalid_successor` is terminal for the archive, but the exit decision
/// treats it like a withheld successor (§6.1): the server reserved and
/// finalized that request, so the state is handled by E3. It is therefore
/// classified `Unresolved` here.
pub fn classify(record: &ReleasedRecord) -> RecordClass {
    use disposition::*;
    match record.disposition.as_str() {
        INSTALLED | SUPERSEDED | LATE_SUCCESSOR => RecordClass::Terminal,
        INVALID_SUCCESSOR => RecordClass::Unresolved,
        DISCARDED_STALE_ROOT
        | DISCARDED_EXPIRED_UNACCEPTED
        | DISCARDED_SUPERSEDED_UNACCEPTED
        | DISCARDED_CLEARANCE_RESERVED => RecordClass::ResolvedUnreserved,
        _ => match record.reading {
            Some(Reading {
                status: ServerReading::Unknown,
                observed_at,
            }) if observed_at
                >= record
                    .request_time
                    .saturating_add(UNKNOWN_READING_RESOLVES_AFTER_SECONDS) =>
            {
                RecordClass::ResolvedUnreserved
            }
            Some(Reading {
                status: ServerReading::ClearanceReserved,
                ..
            }) => RecordClass::ResolvedUnreserved,
            // pending, evicted, abandoned_for_escape, any other disposition,
            // and readings reserved, finalized without an install,
            // exit_deferred, exited_unsigned, unavailable, a fresh unknown,
            // or none at all.
            _ => RecordClass::Unresolved,
        },
    }
}

/// E2's fresh state: nothing was released (`bound_at_state == 0`), or every
/// released record is resolved and unreserved (terminal records at the state
/// do not count). By the §6.2 write order a released request always has a
/// bound, so a zero bound beside an unresolved record is inconsistent data;
/// like the SDK, the bound decides. The mutual close it leads to is safe
/// either way: a server holding a reservation answers `nullifier_used`, and
/// the decision waits from that record (E2 step 4).
pub fn state_is_fresh(bound_at_state: u128, records: &[ReleasedRecord]) -> bool {
    bound_at_state == 0
        || records
            .iter()
            .all(|record| classify(record) != RecordClass::Unresolved)
}

/// How the mutual close (E2 step 3) ended when it did not produce a close.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutualOutcome {
    /// `POST /v2/withdraw/clearance` answered `nullifier_used`: the server
    /// claims a reservation at this state (E2 step 4).
    NullifierUsed,
    /// Any other refusal, or the server was unreachable (E2 step 5).
    RefusedOrUnreachable,
}

/// A user's explicit choice to exit before `T` (E3 "forced early exit").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EarlyExit {
    /// Concede nothing (the default for a forced early exit).
    ConcedeNothing,
    /// Concede `bound_at_state`: no on-chain record of the last request, but
    /// up to `bound_at_state − actual charge` may be forfeited.
    ConcedeBound,
}

/// Everything the exit decision depends on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExitFacts {
    pub now: u64,
    pub must_initiate_by: u64,
    /// W, the build-pinned `settlement_window_seconds`.
    pub settlement_window: u64,
    /// E3's knob after `unsettled_escape_after`.
    pub unsettled_escape_after: u64,
    pub bound_at_state: u128,
    /// Every request released at the state.
    pub records: Vec<ReleasedRecord>,
    /// The server's `settlement_deadline` for the state's nullifier, if it
    /// reported one.
    #[serde(default)]
    pub settlement_deadline_reported: Option<u64>,
    /// The charge of a `Finalized` response for this state's nullifier that
    /// passes S1, S2, S4 and S6 but cannot be installed (ε or journal lost).
    #[serde(default)]
    pub lost_epsilon_charge: Option<u128>,
    /// How an attempted mutual close ended, if one was attempted.
    #[serde(default)]
    pub mutual_outcome: Option<MutualOutcome>,
    /// The user's explicit early-exit choice, if any.
    #[serde(default)]
    pub early_exit: Option<EarlyExit>,
}

/// Why an escape concedes what it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EscapeReason {
    /// E2 step 2: too close to `must_initiate_by` for a clearance.
    MutualCutoff,
    /// E2 step 5: the clearance was refused (not `nullifier_used`) or the
    /// server was unreachable.
    MutualRefused,
    /// E3: the server finalized the state but its successor cannot be
    /// installed; concede `min(charge, bound_at_state)` at once.
    LostEpsilon,
    /// E3: at or after `T`, concede `bound_at_state`.
    AtDeadline,
    /// E3: the user exits before `T`.
    ForcedEarly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ExitDecision {
    /// E2 step 3: ownership proof, clearance, close.
    Mutual,
    /// E4 with this concession.
    Escape {
        conceded: u128,
        reason: EscapeReason,
    },
    /// E3: wait until `until`, then decide again.
    Wait { until: u64 },
}

/// E3's `T` for the newest released record created at `created_at`:
/// `min(min(settlement_deadline_reported, created_at + W) + 900,
///      created_at + unsettled_escape_after, must_initiate_by)`.
pub fn escape_deadline(
    created_at: u64,
    settlement_window: u64,
    settlement_deadline_reported: Option<u64>,
    unsettled_escape_after: u64,
    must_initiate_by: u64,
) -> u64 {
    let settled_by = created_at.saturating_add(settlement_window);
    let settled_by =
        settlement_deadline_reported.map_or(settled_by, |reported| reported.min(settled_by));
    settled_by
        .saturating_add(SETTLEMENT_GRACE_SECONDS)
        .min(created_at.saturating_add(unsettled_escape_after))
        .min(must_initiate_by)
}

/// E2 and E3: what to do from the newest installed state.
pub fn decide(facts: &ExitFacts) -> ExitDecision {
    let bound = facts.bound_at_state;
    let newest_release = |unresolved_only: bool| {
        facts
            .records
            .iter()
            .filter(|record| !unresolved_only || classify(record) == RecordClass::Unresolved)
            .map(|record| record.created_at)
            .max()
    };
    let wait_or_escape = |created_at: u64| -> ExitDecision {
        let deadline = escape_deadline(
            created_at,
            facts.settlement_window,
            facts.settlement_deadline_reported,
            facts.unsettled_escape_after,
            facts.must_initiate_by,
        );
        if facts.now >= deadline {
            return ExitDecision::Escape {
                conceded: bound,
                reason: EscapeReason::AtDeadline,
            };
        }
        match facts.early_exit {
            Some(EarlyExit::ConcedeNothing) => ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::ForcedEarly,
            },
            Some(EarlyExit::ConcedeBound) => ExitDecision::Escape {
                conceded: bound,
                reason: EscapeReason::ForcedEarly,
            },
            None => ExitDecision::Wait { until: deadline },
        }
    };
    // E3 "lost ε": may be done at once, whatever the state's records say.
    if let Some(charge) = facts.lost_epsilon_charge {
        return ExitDecision::Escape {
            conceded: charge.min(bound),
            reason: EscapeReason::LostEpsilon,
        };
    }
    if state_is_fresh(bound, &facts.records) {
        // E2.
        if facts.now >= facts.must_initiate_by.saturating_sub(MUTUAL_CUTOFF_SECONDS) {
            return ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualCutoff,
            };
        }
        return match facts.mutual_outcome {
            None => ExitDecision::Mutual,
            // E2 step 4: the server claims a reservation; E3 from the newest
            // released record. With no record of a release there is nothing
            // to wait for: T is now, and the escape concedes the bound (zero
            // when nothing left this device), as the SDK does. Anchoring T at
            // `now` instead would move it on every new decision.
            Some(MutualOutcome::NullifierUsed) => match newest_release(false) {
                Some(created_at) => wait_or_escape(created_at),
                None => ExitDecision::Escape {
                    conceded: bound,
                    reason: EscapeReason::AtDeadline,
                },
            },
            Some(MutualOutcome::RefusedOrUnreachable) => ExitDecision::Escape {
                conceded: 0,
                reason: EscapeReason::MutualRefused,
            },
        };
    }
    // E3: a released request is unresolved.
    wait_or_escape(newest_release(true).unwrap_or(facts.now))
}

/// The concession range C3 allows in escape mode: `[0, bound_at_state]`.
pub fn concession_allowed(conceded: u128, bound_at_state: u128) -> bool {
    conceded <= bound_at_state
}

/// C3, mode `mutual`: the ownership proof (kind 2) a clearance request at a
/// state carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipProofAction {
    /// The state's live ownership proof, sent again.
    Resend,
    /// None: the state's ownership proof is too near its expiry to resend
    /// but the server may still accept it; another is made once it expired.
    Wait,
    /// A new ownership proof.
    New,
}

/// C3: at most one live ownership proof per state, across exit locks (a
/// user may cancel the lock one was made under, E6). `newest_valid_until`
/// is the newest `valid_until` of the state's ownership proofs sent so far.
pub fn ownership_proof_action(newest_valid_until: Option<u64>, now: u64) -> OwnershipProofAction {
    match newest_valid_until {
        Some(valid_until) if valid_until > now.saturating_add(OWNERSHIP_RESEND_MARGIN_SECONDS) => {
            OwnershipProofAction::Resend
        }
        Some(valid_until) if valid_until >= now => OwnershipProofAction::Wait,
        _ => OwnershipProofAction::New,
    }
}

/// A released exit proof, as E6 sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasedExit {
    /// 0 escape, 1 mutual close, 2 ownership proof.
    pub kind: u8,
    pub valid_until: u64,
}

/// The vault's view of the note (`notes(noteId).status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteChainStatus {
    Active,
    PendingWithdrawal,
    Closed,
}

/// E6: the local second after which every released kind-0 or kind-1 proof
/// is dead (the largest `valid_until + 900`), or `None` when none was
/// released.
pub fn lock_dead_after(released: &[ReleasedExit]) -> Option<u64> {
    released
        .iter()
        .filter(|proof| proof.kind <= 1)
        .map(|proof| {
            proof
                .valid_until
                .saturating_add(LOCK_RELEASE_MARGIN_SECONDS)
        })
        .max()
}

/// E6: whether `exit_lock` may be released. `note` was read at a finalized
/// block whose timestamp is `finalized_block_timestamp`; `now` is this
/// device's clock; `status_trusted` says the reading came from a source the
/// operator does not control (the owner's exit RPC), not the pinned RPC.
///
/// A chain reading alone never releases a lock whose escape or close proof
/// may still land: the device's own clock must also be past every released
/// proof's `valid_until + 900`, whoever answered the reading. A `Closed`
/// reading releases such a lock earlier only when it is trusted (the SDK's
/// `exitLockReleasable`, pinned by the shared vectors).
pub fn lock_releasable(
    released: &[ReleasedExit],
    user_cancels: bool,
    note: NoteChainStatus,
    finalized_block_timestamp: Option<u64>,
    now: u64,
    status_trusted: bool,
) -> bool {
    let dead_after = lock_dead_after(released);
    let locally_dead = dead_after.is_some_and(|after| now > after);
    if note == NoteChainStatus::Closed && (dead_after.is_none() || status_trusted || locally_dead) {
        return true;
    }
    let Some(dead_after) = dead_after else {
        return user_cancels;
    };
    locally_dead
        && note == NoteChainStatus::Active
        && finalized_block_timestamp.is_some_and(|timestamp| timestamp > dead_after)
}

/// E5: what a finalized or credited escape payout shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PayoutMatch {
    /// `paid == B − c_final`. `concession_exceeded_bound` is the alert of a
    /// payout below `B − bound_at_state`; the record still closes.
    Matches {
        conceded_final: u128,
        concession_exceeded_bound: bool,
    },
    Mismatch,
}

/// E5: accept a payout `paid` of an escape from a state with balance
/// `state_balance`, initiated conceding `conceded_at_init`, whose concession
/// was raised to each of `raises` (`EscapeConcessionRaised.conceded` between
/// initiation and finalization), iff `paid == B − c_final` with `c_final` the
/// largest of them, and `paid <= B − conceded_at_init`. `bound_at_state`,
/// when known, only decides the alert.
pub fn match_escape_payout(
    paid: u128,
    state_balance: u128,
    conceded_at_init: u128,
    raises: &[u128],
    bound_at_state: Option<u128>,
) -> PayoutMatch {
    let conceded_final = raises.iter().copied().fold(conceded_at_init, u128::max);
    let Some(expected) = state_balance.checked_sub(conceded_final) else {
        return PayoutMatch::Mismatch;
    };
    if paid != expected || conceded_at_init > state_balance {
        return PayoutMatch::Mismatch;
    }
    PayoutMatch::Matches {
        conceded_final,
        concession_exceeded_bound: bound_at_state
            .is_some_and(|bound| paid < state_balance.saturating_sub(bound)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(
        disposition: &str,
        request_time: u64,
        reading: Option<(ServerReading, u64)>,
    ) -> ReleasedRecord {
        ReleasedRecord {
            disposition: disposition.into(),
            request_time,
            created_at: request_time,
            reading: reading.map(|(status, observed_at)| Reading {
                status,
                observed_at,
            }),
        }
    }

    #[test]
    fn e_low_is_raised_only_when_both_rpcs_report_later() {
        assert_eq!(e_low(100, None, None), 100);
        assert_eq!(e_low(100, Some(500), None), 100);
        assert_eq!(e_low(100, Some(500), Some(90)), 100);
        assert_eq!(e_low(100, Some(500), Some(300)), 300);
        assert_eq!(must_initiate_by(100_000), 100_000 - 43_200);
        assert_eq!(must_initiate_by(10), 0);
    }

    #[test]
    fn near_expiry_uses_the_pinned_window_and_margins() {
        let by = 1_000_000;
        assert!(!note_near_expiry(by - 21_905 - 4_500, 21_905, by));
        assert!(note_near_expiry(by - 21_905 - 4_499, 21_905, by));
    }

    /// E6: a chain reading (the pinned RPC's, say) whose finalized block is
    /// far past a released escape's valid_until never releases the lock
    /// while this device's clock says the proof can still land.
    #[test]
    fn a_lock_waits_for_the_local_clock_whatever_the_chain_reports() {
        let escape = [ReleasedExit {
            kind: 0,
            valid_until: 10_000,
        }];
        let active = NoteChainStatus::Active;
        assert_eq!(lock_dead_after(&escape), Some(10_900));
        assert!(!lock_releasable(
            &escape,
            false,
            active,
            Some(u64::MAX),
            10_900,
            false
        ));
        assert!(!lock_releasable(
            &escape,
            false,
            active,
            Some(u64::MAX),
            10_900,
            true
        ));
        assert!(lock_releasable(
            &escape,
            false,
            active,
            Some(10_901),
            10_901,
            false
        ));
        assert!(!lock_releasable(
            &escape,
            false,
            active,
            Some(10_900),
            99_999,
            false
        ));
        let closed = NoteChainStatus::Closed;
        assert!(!lock_releasable(
            &escape, false, closed, None, 10_000, false
        ));
        assert!(lock_releasable(&escape, false, closed, None, 10_000, true));
        assert!(lock_releasable(&escape, false, closed, None, 10_901, false));
        let ownership = [ReleasedExit {
            kind: 2,
            valid_until: 10_000,
        }];
        assert_eq!(lock_dead_after(&ownership), None);
        assert!(lock_releasable(&ownership, false, closed, None, 0, false));
        assert!(lock_releasable(&ownership, true, active, None, 0, false));
        assert!(!lock_releasable(
            &ownership,
            false,
            active,
            Some(99_999),
            99_999,
            false
        ));
    }

    #[test]
    fn unknown_readings_resolve_only_after_twenty_minutes() {
        let fresh = record("pending", 1_000, Some((ServerReading::Unknown, 2_199)));
        assert_eq!(classify(&fresh), RecordClass::Unresolved);
        let late = record("pending", 1_000, Some((ServerReading::Unknown, 2_200)));
        assert_eq!(classify(&late), RecordClass::ResolvedUnreserved);
        let reserved = record("discarded", 1_000, Some((ServerReading::Reserved, 9_000)));
        assert_eq!(classify(&reserved), RecordClass::Unresolved);
        assert_eq!(
            classify(&record("installed", 0, None)),
            RecordClass::Terminal
        );
        assert_eq!(
            classify(&record("invalid_successor", 0, None)),
            RecordClass::Unresolved
        );
        assert_eq!(
            classify(&record("discarded_stale_root", 0, None)),
            RecordClass::ResolvedUnreserved
        );
    }

    #[test]
    fn the_payout_matcher_follows_the_largest_raise() {
        assert_eq!(
            match_escape_payout(700, 1_000, 100, &[200, 300], Some(400)),
            PayoutMatch::Matches {
                conceded_final: 300,
                concession_exceeded_bound: false
            }
        );
        assert_eq!(
            match_escape_payout(900, 1_000, 100, &[300], Some(400)),
            PayoutMatch::Mismatch
        );
        assert_eq!(
            match_escape_payout(500, 1_000, 0, &[500], Some(400)),
            PayoutMatch::Matches {
                conceded_final: 500,
                concession_exceeded_bound: true
            }
        );
    }
}
