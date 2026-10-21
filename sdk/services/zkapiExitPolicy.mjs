// The exit rules of the concession exit (design §6.3 C1–C5 and §6.4 E0–E7)
// as pure functions over local data. Nothing here reads the network or the
// clock: callers pass `now` (seconds) and every server or chain reading.
//
// The browser runtime (browserWalletRuntime.js) applies these under its one
// Web Lock (C1); the companion wallet (zkapi-client exit_policy) implements
// the same table. Both reproduce the shared vectors in
// protocol/rust/crates/zkapi-client/tests/vectors/exit-rules.json
// (sdk/test/zkapi-exit-rules-vectors.test.mjs).

import { REQUEST_EVIDENCE_TYPE, REQUEST_JOURNAL_TYPE, lastDefinitiveObservation } from './zkapiRequestArchive.mjs';

// E0. Nothing here depends on operator data.
export const EXIT_TIMING = Object.freeze({
    // One operator HTTP call in exit mode (connect and full body). A timeout,
    // a 5xx or a 429 counts as unreachable; Retry-After is ignored.
    callTimeoutMs: 20_000,
    // One E1 recovery pass.
    recoveryBudgetMs: 120_000,
    // One Merkle path rebuild from the vault's logs (§6.6), across every RPC
    // it tries: long enough for a full mainnet history in 2,000-block
    // ranges, short enough that a stalling RPC cannot hold an exit.
    rebuildBudgetMs: 300_000,
    // must_initiate_by = E_low − 12 h.
    mustInitiateMarginSeconds: 43_200,
    // C4: refuse new requests when now + W + 900 + 3600 > must_initiate_by.
    nearExpiryMarginSeconds: 900 + 3_600,
    // E2.2: within an hour of must_initiate_by a fresh state escapes (c = 0).
    escapeOnlyMarginSeconds: 3_600,
    // E3.1: slack after the reported (or pinned) settlement deadline.
    settlementSlackSeconds: 900,
    // An 'unknown' reading this long after request_time is final: the server
    // never newly accepts a request whose request_time is that old.
    unknownSettledAfterSeconds: 1_200,
    // valid_until = now + VALIDITY.
    exitProofValiditySeconds: 10_800,
    // The server accepts a kind-2 proof while now <= valid_until <= now + 3,600
    // at its own clock, read one proving time later. The client stays this
    // far below that bound, so a clock up to five minutes fast still closes
    // cooperatively instead of falling back to an escape.
    ownershipProofValiditySeconds: 3_600,
    ownershipProofSkewMarginSeconds: 300,
    // C3: a state's ownership proof is sent again only while it stays valid
    // for longer than this; inside it the client waits for it to expire.
    ownershipResendMarginSeconds: 5,
    // E6: a released proof is dead once a finalized block is later than
    // valid_until + 900.
    lockReleaseMarginSeconds: 900
});

// unsettled_request_escape_after_seconds keeps its default and clamp (E3.1).
export const UNSETTLED_ESCAPE_AFTER_SECONDS = Object.freeze({ default: 43_200, minimum: 3_600, maximum: 604_800 });

export const WITHDRAWAL_KIND = Object.freeze({ escape: 0, mutual: 1, ownership: 2 });
export const EXIT_LOCK_MODES = Object.freeze(['mutual', 'escape']);

export const RECORD_CLASS = Object.freeze({
    TERMINAL: 'terminal',
    RESOLVED: 'resolved_unreserved',
    UNRESOLVED: 'unresolved'
});

// Readings that mean the server holds (or held) a reservation at the
// nullifier: its operator can raise an escape from this state up to the
// state's bound.
const RESERVING_READINGS = new Set(['reserved', 'finalized', 'exit_deferred', 'exited_unsigned']);
const RESOLVED_DISPOSITIONS = new Set(['discarded_stale_root', 'discarded_expired_unaccepted',
    'discarded_clearance_reserved']);
// installed and superseded, and late_successor: a valid successor that
// arrived after an exit proof was released (E4.6). It is settled: it installs
// once the lock is released (E6), and the operator's evidence at the state's
// nullifier can raise an escape at most to its charge (§6.4 record classes).
const TERMINAL_DISPOSITIONS = new Set(['installed', 'superseded', 'late_successor']);
// A correctly signed successor that failed S3, S4 or S5: handled exactly like
// a withheld successor (§6.1). The server finalized the nullifier, so for exit
// decisions the state holds a reservation (E3).
const FINALIZED_DISPOSITIONS = new Set(['invalid_successor']);

function exitError(message, code, data = undefined) {
    return Object.assign(new Error(message), { code, ...(data ? { data } : {}) });
}

function seconds(value, label) {
    const number = Number(value);
    if (!Number.isSafeInteger(number) || number < 0) throw exitError(`${label} must be a non-negative integer.`, 'exit_input_invalid');
    return number;
}

function amount(value, label) {
    let parsed;
    try {
        parsed = BigInt(value);
    } catch {
        throw exitError(`${label} must be an integer amount.`, 'exit_input_invalid');
    }
    if (parsed < 0n) throw exitError(`${label} must not be negative.`, 'exit_input_invalid');
    return parsed;
}

function feltEqual(left, right) {
    try {
        return BigInt(left) === BigInt(right);
    } catch {
        return false;
    }
}

/**
 * E_low: the note's own expiry_ts, a proven lower bound of effectiveExpiry.
 * It is raised to the smaller of two effectiveExpiry reads only when the user
 * configured an exit RPC and both that RPC and the pinned RPC report a larger
 * value, so neither RPC alone can make the client start late.
 */
export function lowExpiry(expiryTs, { exitRpcExpiry = null, pinnedRpcExpiry = null } = {}) {
    const local = seconds(expiryTs, 'expiry_ts');
    if (exitRpcExpiry == null || pinnedRpcExpiry == null) return local;
    const exitRead = Number(exitRpcExpiry);
    const pinnedRead = Number(pinnedRpcExpiry);
    if (!Number.isSafeInteger(exitRead) || !Number.isSafeInteger(pinnedRead)) return local;
    return exitRead > local && pinnedRead > local ? Math.min(exitRead, pinnedRead) : local;
}

/** The latest second at which an exit decision may still start: E_low − 12 h (never below 0). */
export function mustInitiateBy(eLow) {
    return Math.max(0, seconds(eLow, 'E_low') - EXIT_TIMING.mustInitiateMarginSeconds);
}

/** C4: a new request would leave too little time to exit after it settles. */
export function nearExpiry({ now, settlementWindowSeconds, mustInitiateBy: deadline }) {
    return seconds(now, 'now') + seconds(settlementWindowSeconds, 'settlement window')
        + EXIT_TIMING.nearExpiryMarginSeconds > seconds(deadline, 'must_initiate_by');
}

/** The unsettled-request escape knob with its default and clamp. */
export function unsettledEscapeAfterSeconds(configured) {
    if (!Number.isSafeInteger(configured)) return UNSETTLED_ESCAPE_AFTER_SECONDS.default;
    return Math.min(Math.max(configured, UNSETTLED_ESCAPE_AFTER_SECONDS.minimum), UNSETTLED_ESCAPE_AFTER_SECONDS.maximum);
}

/** A record's request_time (seconds), or its local creation time. */
function requestTimeSeconds(record) {
    const requestTime = Number(record?.journal?.prepared_request?.public_inputs?.request_time);
    if (Number.isSafeInteger(requestTime) && requestTime > 0) return requestTime;
    const created = Number(record?.journal?.created_at_ms || record?.createdAt || 0);
    return Math.floor(created / 1_000);
}

/** When a request record left the device, in seconds (its journal's created_at). */
export function recordCreatedAtSeconds(record) {
    const created = Number(record?.journal?.created_at_ms || record?.createdAt || 0);
    return Math.floor(created / 1_000);
}

/**
 * The class of a request archive record for exit decisions (§6.4, matching
 * zkapiRequestArchive.mjs):
 * - terminal: installed, superseded, late_successor;
 * - resolved-unreserved: discarded_stale_root, discarded_expired_unaccepted,
 *   discarded_clearance_reserved, or a record whose newest nullifier reading
 *   is 'unknown' taken at least 1,200 s after its request_time, or
 *   'clearance_reserved' (the nullifier is reserved for a close, so no
 *   request can be);
 * - unresolved: everything else (pending, evicted, abandoned_for_escape, a
 *   newest reading of reserved, finalized, exit_deferred, exited_unsigned or
 *   none), and invalid_successor (handled like a withheld successor, §6.1).
 */
export function exitRecordClass(record) {
    if (record?.type === REQUEST_EVIDENCE_TYPE) return RECORD_CLASS.UNRESOLVED;
    if (record?.type !== REQUEST_JOURNAL_TYPE) return RECORD_CLASS.TERMINAL;
    const disposition = record.disposition;
    if (TERMINAL_DISPOSITIONS.has(disposition)) return RECORD_CLASS.TERMINAL;
    if (FINALIZED_DISPOSITIONS.has(disposition)) return RECORD_CLASS.UNRESOLVED;
    if (RESOLVED_DISPOSITIONS.has(disposition)) return RECORD_CLASS.RESOLVED;
    // The newest reading of a status the server reports for a nullifier
    // (never a failed read, nor an /expire answer).
    const reading = lastDefinitiveObservation(record);
    if (!reading) return RECORD_CLASS.UNRESOLVED;
    if (RESERVING_READINGS.has(reading.status)) return RECORD_CLASS.UNRESOLVED;
    if (reading.status === 'clearance_reserved') return RECORD_CLASS.RESOLVED;
    if (reading.status === 'unknown') {
        return Number(reading.at) >= (requestTimeSeconds(record) + EXIT_TIMING.unknownSettledAfterSeconds) * 1_000
            ? RECORD_CLASS.RESOLVED : RECORD_CLASS.UNRESOLVED;
    }
    return RECORD_CLASS.UNRESOLVED;
}

/** Every request record of one note state (any disposition), newest first. */
export function requestRecordsAtState(records, { deploymentId, noteId, anchor }) {
    return (records || []).filter(record => record?.type === REQUEST_JOURNAL_TYPE
        && record.deploymentId === deploymentId && Number(record.noteId) === Number(noteId)
        && feltEqual(record.anchor, anchor))
        .sort((left, right) => recordCreatedAtSeconds(right) - recordCreatedAtSeconds(left));
}

/**
 * Whether a state is fresh for E2: no request proof left the device at it
 * (bound_at_state == 0), or every released record there is
 * resolved-unreserved. Also reports the unresolved records and the release
 * times: `newestCreatedAt`, of every request released at the state whatever
 * its class (E2.4 waits from it after nullifier_used), and
 * `newestUnresolvedCreatedAt`, of the unresolved ones (E3's created_at).
 */
export function stateExitStatus({ boundAtState, records }) {
    const bound = amount(boundAtState ?? 0, 'bound_at_state');
    const live = (records || []).filter(record => exitRecordClass(record) !== RECORD_CLASS.TERMINAL);
    const unresolved = live.filter(record => exitRecordClass(record) === RECORD_CLASS.UNRESOLVED);
    const released = live.filter(record => record.type === REQUEST_JOURNAL_TYPE);
    const newest = list => list.filter(record => record?.type === REQUEST_JOURNAL_TYPE)
        .reduce((latest, record) => Math.max(latest, recordCreatedAtSeconds(record)), 0) || null;
    return {
        fresh: bound === 0n || unresolved.length === 0,
        boundAtState: bound,
        unresolved,
        released,
        newestCreatedAt: newest(records || []),
        newestUnresolvedCreatedAt: newest(unresolved),
        // A defeat at this state already flagged its nullifier: this device
        // is not the newest (EscapeWithdrawalChallenged).
        challenged: live.some(record => record.type === REQUEST_EVIDENCE_TYPE)
    };
}

/**
 * E3.1: T = min(min(settlement_deadline_reported, created_at + W) + 900,
 * created_at + unsettled_request_escape_after_seconds, must_initiate_by).
 */
export function escapeAt({ createdAt, settlementDeadline = null, settlementWindowSeconds, unsettledAfterSeconds,
    mustInitiateBy: deadline }) {
    const created = seconds(createdAt, 'created_at');
    const pinned = created + seconds(settlementWindowSeconds, 'settlement window');
    const reported = settlementDeadline == null ? null : Number(settlementDeadline);
    const settlement = Number.isSafeInteger(reported) && reported > 0 ? Math.min(reported, pinned) : pinned;
    return Math.min(settlement + EXIT_TIMING.settlementSlackSeconds,
        created + unsettledEscapeAfterSeconds(unsettledAfterSeconds),
        seconds(deadline, 'must_initiate_by'));
}

/**
 * The exit decision for a state (E2, E3), given the user's request:
 * 'mutual' (withdraw, cooperatively when possible) or 'escape' (unilateral
 * exit now). Returns { action: 'mutual' | 'escape' | 'wait', conceded, rule,
 * escapeAt? }.
 *
 * - Fresh state: a mutual close (E2), or an escape with c = 0 when asked for
 *   or within an hour of must_initiate_by.
 * - Unresolved state (E3): lost ε (a finalized, signed response at N_k the
 *   wallet cannot install) concedes min(charge, b) at once; at or after T an
 *   escape concedes b; before T a forced escape concedes 0 by default, or b
 *   when the user chose it ('bound'); a mutual request waits for T and never
 *   asks for a clearance.
 */
export function chooseExit({ request, now, mustInitiateBy: deadline, status, escapeAtSeconds = null,
    lostEpsilonCharge = null, earlyConcession = 'zero' }) {
    if (!['mutual', 'escape'].includes(request)) throw exitError('Choose a withdrawal mode.', 'exit_input_invalid');
    const current = seconds(now, 'now');
    const bound = status.boundAtState;
    if (status.fresh) {
        if (request === 'mutual' && current < seconds(deadline, 'must_initiate_by') - EXIT_TIMING.escapeOnlyMarginSeconds) {
            return { action: 'mutual', conceded: 0n, rule: 'E2' };
        }
        return { action: 'escape', conceded: 0n, rule: request === 'mutual' ? 'E2.deadline' : 'E2.escape' };
    }
    if (lostEpsilonCharge != null) {
        const charge = amount(lostEpsilonCharge, 'reported charge');
        return { action: 'escape', conceded: charge < bound ? charge : bound, rule: 'E3.lost_epsilon' };
    }
    const T = escapeAtSeconds == null ? null : seconds(escapeAtSeconds, 'T');
    if (T == null || current >= T) return { action: 'escape', conceded: bound, rule: 'E3.T', escapeAt: T };
    if (request === 'escape') {
        if (!['zero', 'bound'].includes(earlyConcession)) {
            throw exitError('Choose the forced-exit concession: zero or bound.', 'exit_input_invalid');
        }
        return { action: 'escape', conceded: earlyConcession === 'bound' ? bound : 0n, rule: 'E3.forced', escapeAt: T };
    }
    return { action: 'wait', conceded: null, rule: 'E3.wait', escapeAt: T };
}

/**
 * E2 and E3 as one decision, the companion's exit_policy::decide over the
 * browser's records (both pinned by the shared vectors). `request` is
 * 'mutual' or 'escape'; `status` is stateExitStatus at the state;
 * `clearanceOutcome` is how this state's clearance ended, if it was asked:
 * 'nullifier_used' (the server claims a reservation, E2.4) or 'refused' (any
 * other refusal or unreachability, E2.5). Returns { action: 'mutual' |
 * 'escape' | 'wait', conceded, rule, escapeAt? }.
 *
 * - Lost ε (E3): a finalized response at the state the wallet cannot install
 *   concedes min(charge, b) at once, whatever the records say.
 * - Fresh state (E2): within an hour of must_initiate_by an escape conceding
 *   nothing; after nullifier_used, E3 from the newest release at the state
 *   (with none, an escape conceding b at once); after any other clearance
 *   failure an escape conceding nothing; else a mutual close, or an escape
 *   conceding nothing when the user asks for one.
 * - Unresolved state (E3), from the newest unresolved release: at or after T
 *   an escape conceding b; before T an escape the user forces concedes 0 by
 *   default or b ('bound'), and a mutual request waits for T.
 */
export function decideExit({ request, now, mustInitiateBy: deadline, status, settlementWindowSeconds,
    unsettledAfterSeconds, settlementDeadline = null, lostEpsilonCharge = null, earlyConcession = 'zero',
    clearanceOutcome = null }) {
    if (!['mutual', 'escape'].includes(request)) throw exitError('Choose a withdrawal mode.', 'exit_input_invalid');
    if (!['zero', 'bound'].includes(earlyConcession)) {
        throw exitError('Choose the forced-exit concession: zero or bound.', 'exit_input_invalid');
    }
    const current = seconds(now, 'now');
    const last = seconds(deadline, 'must_initiate_by');
    const bound = status.boundAtState;
    if (lostEpsilonCharge != null) {
        const charge = amount(lostEpsilonCharge, 'reported charge');
        return { action: 'escape', conceded: charge < bound ? charge : bound, rule: 'E3.lost_epsilon' };
    }
    const waitOrEscape = createdAt => {
        const T = escapeAt({ createdAt, settlementDeadline, settlementWindowSeconds, unsettledAfterSeconds,
            mustInitiateBy: last });
        if (current >= T) return { action: 'escape', conceded: bound, rule: 'E3.T', escapeAt: T };
        if (request === 'escape') {
            return { action: 'escape', conceded: earlyConcession === 'bound' ? bound : 0n, rule: 'E3.forced', escapeAt: T };
        }
        return { action: 'wait', conceded: null, rule: 'E3.wait', escapeAt: T };
    };
    if (!status.fresh) return waitOrEscape(status.newestUnresolvedCreatedAt ?? current);
    if (current >= last - EXIT_TIMING.escapeOnlyMarginSeconds) {
        return { action: 'escape', conceded: 0n, rule: request === 'mutual' ? 'E2.deadline' : 'E2.escape' };
    }
    if (clearanceOutcome === 'nullifier_used') {
        if (status.newestCreatedAt == null) return { action: 'escape', conceded: bound, rule: 'E3.T', escapeAt: current };
        return waitOrEscape(status.newestCreatedAt);
    }
    if (clearanceOutcome != null) return { action: 'escape', conceded: 0n, rule: 'E2.fallback' };
    if (request === 'escape') return { action: 'escape', conceded: 0n, rule: 'E2.escape' };
    return { action: 'mutual', conceded: 0n, rule: 'E2' };
}

/**
 * E2.4/E2.5: after a mutual close's clearance failed. nullifier_used means
 * the server claims a reservation: decide again as an unresolved state (E3).
 * Any other refusal or unreachability escapes with c = 0.
 */
export function afterClearanceFailure(error) {
    if (error?.code === 'nullifier_used') return { action: 'reconsider', rule: 'E2.nullifier_used' };
    // The client's own C3 refusals are not server answers: they never turn
    // a mutual request into an escape (only a server refusal does, E2.5).
    if (LOCAL_CLEARANCE_REFUSALS.has(error?.code)) return { action: 'refuse', rule: 'C3' };
    return { action: 'escape', conceded: 0n, rule: 'E2.fallback' };
}

const LOCAL_CLEARANCE_REFUSALS = new Set(['ownership_proof_sent', 'ownership_proof_wait', 'exit_locked', 'exit_lock_state',
    'exit_lock_mode', 'conceded_exceeds_bound']);

/**
 * C3: the ownership proof (kind 2) a clearance request at a state carries,
 * from the newest valid_until of the state's ownership proofs sent so far
 * (null when none): at most one live proof per state, across exit locks (a
 * user may cancel the lock one was made under, E6). 'resend' the live one
 * while it stays valid for longer than the resend margin; 'wait' inside the
 * margin, while the server may still accept it; 'new' once it expired.
 */
export function ownershipProofAction(newestValidUntil, now) {
    const current = seconds(now, 'now');
    if (newestValidUntil == null) return 'new';
    const validUntil = seconds(newestValidUntil, 'valid_until');
    if (validUntil > current + EXIT_TIMING.ownershipResendMarginSeconds) return 'resend';
    return validUntil >= current ? 'wait' : 'new';
}

// What the server answered to a released ownership proof (kind 2).
export const CLEARANCE_OUTCOMES = Object.freeze(['granted', 'nullifier_used', 'refused', 'unreachable', 'invalid']);

/**
 * The lock with the server's answer to its released ownership proof, so a
 * retry decides as the first attempt did (E2.4, E2.5) without a second one.
 */
export function recordClearanceOutcome(lock, { outcome, code = null }) {
    if (!CLEARANCE_OUTCOMES.includes(outcome)) throw exitError('Unknown clearance outcome.', 'exit_input_invalid');
    let marked = false;
    const released = (lock.released || []).map(entry => {
        if (marked || Number(entry.kind) !== WITHDRAWAL_KIND.ownership) return entry;
        marked = true;
        return { ...entry, outcome, ...(code ? { code: String(code) } : {}) };
    });
    return { ...lock, released };
}

/**
 * The answer to the lock's released ownership proof: null when none was
 * released, 'unknown' when one left but no answer was recorded (a crash or
 * an abort in between), else one of CLEARANCE_OUTCOMES.
 */
export function ownershipOutcome(lock) {
    const entry = (lock?.released || []).find(item => Number(item.kind) === WITHDRAWAL_KIND.ownership);
    if (!entry) return null;
    return CLEARANCE_OUTCOMES.includes(entry.outcome) ? entry.outcome : 'unknown';
}

// ---- exit_lock (C3, E6) ----

/** A new exit lock at a state: { noteId, anchor, mode, since, released: [] }. */
export function newExitLock({ noteId, anchor, mode, now }) {
    if (!EXIT_LOCK_MODES.includes(mode)) throw exitError('An exit lock mode is mutual or escape.', 'exit_input_invalid');
    return { noteId: Number(noteId), anchor: String(anchor), mode, since: seconds(now, 'now'), released: [] };
}

function lockAtState(lock, { noteId, anchor }) {
    return Boolean(lock) && Number(lock.noteId) === Number(noteId) && feltEqual(lock.anchor, anchor);
}

/** The kind 0 and kind 1 proofs a lock released: the ones that can land on chain. */
export function releasedExitProofs(lock) {
    return (lock?.released || []).filter(entry => [WITHDRAWAL_KIND.escape, WITHDRAWAL_KIND.mutual].includes(Number(entry.kind)));
}

/**
 * C3: which proofs a held lock allows. While it is held the client makes no
 * request proofs; only proofs of the lock's mode at the lock's state:
 * mode mutual allows at most one kind-2 ownership proof and kind-1 closes,
 * mode escape allows kind-0 escapes with 0 <= c <= bound_at_state. Returns
 * null when allowed, else a refusal code.
 */
export function exitLockRefusal(lock, { noteId, anchor, proof, conceded = 0, boundAtState = 0 }) {
    if (!lock) return null;
    if (proof === 'request') return 'exit_locked';
    if (!lockAtState(lock, { noteId, anchor })) return 'exit_lock_state';
    const kind = WITHDRAWAL_KIND[proof];
    if (kind == null) return 'exit_lock_mode';
    if (lock.mode === 'mutual') {
        if (kind === WITHDRAWAL_KIND.escape) return 'exit_lock_mode';
        if (kind === WITHDRAWAL_KIND.ownership
            && (lock.released || []).some(entry => Number(entry.kind) === WITHDRAWAL_KIND.ownership)) {
            return 'ownership_proof_sent';
        }
        return null;
    }
    if (kind !== WITHDRAWAL_KIND.escape) return 'exit_lock_mode';
    const value = amount(conceded, 'conceded');
    return value <= amount(boundAtState, 'bound_at_state') ? null : 'conceded_exceeds_bound';
}

/**
 * A lock switched to `mode`. mutual → escape is always allowed (E2.5). escape
 * → mutual only while no kind-0 or kind-1 proof was released (as a cancel
 * followed by a new lock would be).
 */
export function switchExitLock(lock, mode) {
    if (!EXIT_LOCK_MODES.includes(mode)) throw exitError('An exit lock mode is mutual or escape.', 'exit_input_invalid');
    if (lock.mode === mode) return lock;
    if (mode === 'mutual' && releasedExitProofs(lock).length) {
        throw exitError('An escape proof for this balance may still land, so it can only exit by escape until that proof expires.',
            'exit_lock_mode');
    }
    return { ...lock, mode };
}

/**
 * The lock with one more released proof (appended before the proof leaves
 * the process: to a wallet, RPC, eth_call, eth_estimateGas or the server).
 */
export function recordReleasedProof(lock, { kind, validUntil, conceded = 0, nullifier = null, at }) {
    const entry = {
        kind: Number(kind),
        valid_until: seconds(validUntil, 'valid_until'),
        conceded: String(amount(conceded, 'conceded')),
        ...(nullifier != null ? { nullifier: String(nullifier) } : {}),
        at: seconds(at, 'release time')
    };
    return { ...lock, released: [...(lock.released || []), entry] };
}

/** The hash of a released proof's transaction, once it is known. */
export function recordReleasedTransaction(lock, { validUntil, kind, transactionHash }) {
    let marked = false;
    const released = (lock.released || []).map(entry => {
        if (marked || Number(entry.kind) !== Number(kind) || Number(entry.valid_until) !== Number(validUntil)) return entry;
        marked = true;
        return { ...entry, txHash: String(transactionHash).toLowerCase() };
    });
    return { ...lock, released };
}

/**
 * The local second after which every kind-0 or kind-1 proof the lock
 * released is dead (max valid_until + 900), or null when none was released.
 */
export function exitLockDeadAfter(lock) {
    const exits = releasedExitProofs(lock);
    if (!exits.length) return null;
    return Math.max(...exits.map(entry => Number(entry.valid_until))) + EXIT_TIMING.lockReleaseMarginSeconds;
}

/**
 * E6: whether the lock may be released.
 * - the note is Closed;
 * - no kind-0 or kind-1 proof was ever released and the user cancels;
 * - every released kind-0 or kind-1 proof is dead (a finalized block's
 *   timestamp is greater than its valid_until + 900), and the note is Active
 *   with no pending exit.
 *
 * A chain reading alone never releases a lock whose exit proof may still
 * land: the local clock (`now`, seconds) must also be past every released
 * proof's valid_until + 900. A Closed reading releases such a lock earlier
 * only when it came from a source the operator does not control
 * (`statusTrusted`: the user's exit RPC).
 */
export function exitLockReleasable(lock, { noteStatus = null, finalizedTimestamp = null, cancel = false, now = null,
    statusTrusted = false } = {}) {
    if (!lock) return { releasable: true, reason: 'no_lock' };
    const deadAfter = exitLockDeadAfter(lock);
    const current = now == null ? NaN : Number(now);
    const locallyDead = deadAfter != null && Number.isSafeInteger(current) && current > deadAfter;
    if (noteStatus === 'closed' && (deadAfter == null || statusTrusted || locallyDead)) {
        return { releasable: true, reason: 'closed' };
    }
    if (deadAfter == null) {
        return cancel ? { releasable: true, reason: 'cancelled' } : { releasable: false, reason: 'held' };
    }
    if (!locallyDead) return { releasable: false, reason: 'proof_live', releasableAfter: deadAfter };
    if (noteStatus !== 'active') return { releasable: false, reason: noteStatus === 'pending_withdrawal' ? 'pending_exit' : 'note_status_unknown' };
    const finalized = finalizedTimestamp == null ? NaN : Number(finalizedTimestamp);
    if (!Number.isSafeInteger(finalized) || finalized <= 0) return { releasable: false, reason: 'finality_unknown' };
    if (finalized > deadAfter) return { releasable: true, reason: 'proofs_expired' };
    return { releasable: false, reason: 'proof_live', releasableAfter: deadAfter };
}

// ---- E5: payout matching after a raise ----

/**
 * Whether an escape's finalized or credited amount f' matches its record:
 * f' == B − c_final, where c_final is the maximum of concededAtInit and every
 * EscapeConcessionRaised.conceded between initiation and finalization, and
 * f' <= B − concededAtInit. When the raises could not be read (`raises`
 * null), f' is accepted within those bounds. When b is known and
 * f' < B − b, the record still closes with the alert concession_exceeded_bound.
 */
export function matchEscapePayout({ stateBalance, concededAtInit, boundAtState = null, raises = null, amount: paid }) {
    const B = amount(stateBalance, 'state balance');
    const cInit = amount(concededAtInit, 'initial concession');
    const value = amount(paid, 'payout');
    if (cInit > B) return { accepted: false, reason: 'record_invalid' };
    let cFinal = cInit;
    if (Array.isArray(raises)) {
        for (const raise of raises) {
            const conceded = amount(raise?.conceded ?? raise, 'raised concession');
            if (conceded > cFinal) cFinal = conceded;
        }
    }
    const upper = B - cInit;
    const exact = Array.isArray(raises);
    const accepted = value <= upper && (!exact || (cFinal <= B && value === B - cFinal));
    const bound = boundAtState == null ? null : amount(boundAtState, 'bound_at_state');
    const alert = accepted && bound != null && value < (B > bound ? B - bound : 0n) ? 'concession_exceeded_bound' : null;
    return {
        accepted,
        exact,
        concededFinal: exact ? cFinal : B - value,
        alert,
        reason: accepted ? null : 'payout_mismatch'
    };
}

// An escape's gas (§1.5: about 0.55–0.62M), for the G1 exit-cost warning.
export const ESCAPE_GAS_ESTIMATE = 620_000n;

/** An escape's estimated network fee in ledger units at `gasPriceWei`, rounded up. */
export function escapeCostUnits({ gasPriceWei, weiPerUnit }) {
    const price = amount(gasPriceWei, 'gas price');
    const scale = amount(weiPerUnit, 'wei per unit');
    if (scale === 0n) throw exitError('The ledger unit must be positive.', 'exit_input_invalid');
    return (ESCAPE_GAS_ESTIMATE * price + scale - 1n) / scale;
}

/** The G1 warning of §2.3: the payout floor B − b is below three exit costs. */
export function exitCostWarning({ stateBalance, boundAtState, exitCostUnits }) {
    const B = amount(stateBalance, 'state balance');
    const b = amount(boundAtState ?? 0, 'bound_at_state');
    const floor = B > b ? B - b : 0n;
    const cost = amount(exitCostUnits, 'exit cost');
    return floor < cost * 3n ? { floor, cost } : null;
}
