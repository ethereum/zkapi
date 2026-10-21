// The exit decision table of design §6.3–§6.4 (C3, C4, E0–E6) and the
// payout matchers (E5), as pure functions.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    ESCAPE_GAS_ESTIMATE, EXIT_TIMING, RECORD_CLASS, afterClearanceFailure, chooseExit, escapeAt, escapeCostUnits, exitCostWarning, exitLockRefusal,
    exitLockDeadAfter, exitLockReleasable, exitRecordClass, lowExpiry, matchEscapePayout, mustInitiateBy, nearExpiry, newExitLock,
    ownershipOutcome, recordClearanceOutcome, recordReleasedProof, recordReleasedTransaction, releasedExitProofs, requestRecordsAtState, stateExitStatus,
    switchExitLock, unsettledEscapeAfterSeconds
} from '../services/zkapiExitPolicy.mjs';
import { buildRequestJournalRecord, requestObservation } from '../services/zkapiRequestArchive.mjs';

const REQUEST_TIME = 1_800_000_000;
const STATE = { note_id: 7, current_anchor: '0x1234' };

function record({ id = 'r1', disposition = 'pending', readings = [], requestTime = REQUEST_TIME, anchor = '0x1234' } = {}) {
    const journal = {
        exists: true, client_request_id: id, nullifier: '0x99', payload_hash: '0x1', user_rerandomization: '0x2',
        created_at_ms: requestTime * 1_000,
        prepared_request: { client_request_id: id, public_inputs: { request_time: requestTime, solvency_bound: 300 } }
    };
    return buildRequestJournalRecord({
        deploymentId: 'd', state: { ...STATE, current_anchor: anchor }, journal, disposition,
        observations: readings.map(([status, at, extra = {}]) => requestObservation(status, 'exit', at * 1_000, extra)),
        now: requestTime * 1_000
    });
}

test('E0: E_low is the local expiry_ts unless both RPCs report a later effectiveExpiry', () => {
    assert.equal(lowExpiry(2_000_000_000), 2_000_000_000);
    // One RPC alone never moves it, however late it claims expiry is.
    assert.equal(lowExpiry(2_000_000_000, { exitRpcExpiry: 2_100_000_000 }), 2_000_000_000);
    assert.equal(lowExpiry(2_000_000_000, { pinnedRpcExpiry: 2_100_000_000 }), 2_000_000_000);
    // Both later: the smaller of the two.
    assert.equal(lowExpiry(2_000_000_000, { exitRpcExpiry: 2_100_000_000, pinnedRpcExpiry: 2_050_000_000 }), 2_050_000_000);
    // A lying RPC that reports an earlier expiry cannot move it either.
    assert.equal(lowExpiry(2_000_000_000, { exitRpcExpiry: 1_900_000_000, pinnedRpcExpiry: 2_050_000_000 }), 2_000_000_000);
    assert.equal(mustInitiateBy(2_000_000_000), 2_000_000_000 - 43_200);
    assert.equal(EXIT_TIMING.callTimeoutMs, 20_000);
    assert.equal(EXIT_TIMING.recoveryBudgetMs, 120_000);
    assert.equal(EXIT_TIMING.exitProofValiditySeconds, 10_800);
    assert.equal(EXIT_TIMING.ownershipProofValiditySeconds, 3_600);
});

test('C4: a request is refused when its settlement could run past must_initiate_by', () => {
    const deadline = 2_000_000_000;
    const W = 21_905;
    assert.equal(nearExpiry({ now: deadline - W - 4_500, settlementWindowSeconds: W, mustInitiateBy: deadline }), false);
    assert.equal(nearExpiry({ now: deadline - W - 4_499, settlementWindowSeconds: W, mustInitiateBy: deadline }), true);
});

test('record classes match the archive dispositions and the readings of §6.4', () => {
    // Terminal.
    for (const disposition of ['installed', 'superseded']) {
        assert.equal(exitRecordClass(record({ disposition })), RECORD_CLASS.TERMINAL, disposition);
    }
    // Resolved-unreserved by disposition.
    for (const disposition of ['discarded_stale_root', 'discarded_expired_unaccepted', 'discarded_clearance_reserved']) {
        assert.equal(exitRecordClass(record({ disposition })), RECORD_CLASS.RESOLVED, disposition);
    }
    // Unresolved by disposition, with no reading.
    for (const disposition of ['pending', 'evicted', 'abandoned_for_escape']) {
        assert.equal(exitRecordClass(record({ disposition })), RECORD_CLASS.UNRESOLVED, disposition);
    }
    // A correctly signed successor that failed S3–S5 is handled like a
    // withheld one (§6.1); a valid one held back by an exit lock (E4.6) is
    // settled: it installs once the lock is released (§6.4).
    assert.equal(exitRecordClass(record({ disposition: 'invalid_successor' })), RECORD_CLASS.UNRESOLVED);
    assert.equal(exitRecordClass(record({ disposition: 'late_successor' })), RECORD_CLASS.TERMINAL);
    // 'unknown' counts only 1,200 s after request_time.
    assert.equal(exitRecordClass(record({ readings: [['unknown', REQUEST_TIME + 1_199]] })), RECORD_CLASS.UNRESOLVED);
    assert.equal(exitRecordClass(record({ readings: [['unknown', REQUEST_TIME + 1_200]] })), RECORD_CLASS.RESOLVED);
    // A failed read after it does not undo it; a later reservation does.
    assert.equal(exitRecordClass(record({ readings: [['unknown', REQUEST_TIME + 1_300], ['unavailable', REQUEST_TIME + 1_400]] })),
        RECORD_CLASS.RESOLVED);
    for (const status of ['reserved', 'finalized', 'exit_deferred', 'exited_unsigned']) {
        assert.equal(exitRecordClass(record({ readings: [['unknown', REQUEST_TIME + 1_300], [status, REQUEST_TIME + 1_400]] })),
            RECORD_CLASS.UNRESOLVED, status);
    }
    assert.equal(exitRecordClass(record({ readings: [['unavailable', REQUEST_TIME + 5_000]] })), RECORD_CLASS.UNRESOLVED);
    assert.equal(exitRecordClass(record({ readings: [['clearance_reserved', REQUEST_TIME + 10]] })), RECORD_CLASS.RESOLVED);
});

test('E2 freshness: no bound, or every released record resolved-unreserved', () => {
    const unresolved = record({ id: 'a' });
    const resolved = record({ id: 'b', disposition: 'discarded_stale_root', requestTime: REQUEST_TIME + 60 });
    assert.equal(stateExitStatus({ boundAtState: 0, records: [unresolved] }).fresh, true);
    assert.equal(stateExitStatus({ boundAtState: 300, records: [resolved] }).fresh, true);
    const status = stateExitStatus({ boundAtState: 300, records: [unresolved, resolved, record({ id: 'c', disposition: 'installed' })] });
    assert.equal(status.fresh, false);
    assert.deepEqual(status.unresolved.map(entry => entry.clientRequestId), ['a']);
    assert.equal(status.newestCreatedAt, REQUEST_TIME + 60, 'the newest released record, resolved or not');
    assert.equal(status.boundAtState, 300n);
    // Records of another state never count.
    const records = [unresolved, record({ id: 'other', anchor: '0x99' })];
    assert.deepEqual(requestRecordsAtState(records, { deploymentId: 'd', noteId: 7, anchor: '0x1234' })
        .map(entry => entry.clientRequestId), ['a']);
});

test('E3: T is the earliest of settlement + 900, the escape knob and must_initiate_by', () => {
    const base = { createdAt: 1_000_000, settlementWindowSeconds: 21_905, unsettledAfterSeconds: 43_200,
        mustInitiateBy: 2_000_000 };
    assert.equal(escapeAt(base), 1_000_000 + 21_905 + 900);
    // A reported deadline earlier than the pinned window wins; a later one never does.
    assert.equal(escapeAt({ ...base, settlementDeadline: 1_010_000 }), 1_010_900);
    assert.equal(escapeAt({ ...base, settlementDeadline: 1_900_000 }), 1_000_000 + 21_905 + 900);
    // The knob is clamped to 3,600–604,800.
    assert.equal(escapeAt({ ...base, settlementWindowSeconds: 100_000, unsettledAfterSeconds: 60 }), 1_003_600);
    assert.equal(unsettledEscapeAfterSeconds(10_000_000), 604_800);
    assert.equal(unsettledEscapeAfterSeconds(undefined), 43_200);
    assert.equal(escapeAt({ ...base, mustInitiateBy: 1_005_000 }), 1_005_000);
});

test('E2–E3 decision table, including the choice of the conceded amount', () => {
    const deadline = 2_000_000;
    const fresh = { fresh: true, boundAtState: 300n };
    const pending = { fresh: false, boundAtState: 300n };
    const T = 1_500_000;
    const decide = (overrides) => chooseExit({ now: 1_000_000, mustInitiateBy: deadline, escapeAtSeconds: T, ...overrides });
    // E2: fresh state, mutual close, or an escape conceding nothing.
    assert.deepEqual(decide({ request: 'mutual', status: fresh }), { action: 'mutual', conceded: 0n, rule: 'E2' });
    assert.deepEqual(decide({ request: 'escape', status: fresh }), { action: 'escape', conceded: 0n, rule: 'E2.escape' });
    // E2.2: within an hour of must_initiate_by, escape with c = 0.
    assert.deepEqual(decide({ request: 'mutual', status: fresh, now: deadline - 3_600 }),
        { action: 'escape', conceded: 0n, rule: 'E2.deadline' });
    assert.equal(decide({ request: 'mutual', status: fresh, now: deadline - 3_601 }).action, 'mutual');
    // E3 before T: a mutual request waits and asks for no clearance.
    assert.deepEqual(decide({ request: 'mutual', status: pending }),
        { action: 'wait', conceded: null, rule: 'E3.wait', escapeAt: T });
    // Forced early exit: c = 0 by default, b when the user chose it.
    assert.deepEqual(decide({ request: 'escape', status: pending }),
        { action: 'escape', conceded: 0n, rule: 'E3.forced', escapeAt: T });
    assert.equal(decide({ request: 'escape', status: pending, earlyConcession: 'bound' }).conceded, 300n);
    assert.throws(() => decide({ request: 'escape', status: pending, earlyConcession: 'all' }), /zero or bound/);
    // At or after T: c = b, whatever was requested.
    for (const request of ['mutual', 'escape']) {
        assert.deepEqual(decide({ request, status: pending, now: T }),
            { action: 'escape', conceded: 300n, rule: 'E3.T', escapeAt: T });
    }
    // Lost ε: c = min(reported charge, b), at once.
    assert.deepEqual(decide({ request: 'mutual', status: pending, lostEpsilonCharge: 120 }),
        { action: 'escape', conceded: 120n, rule: 'E3.lost_epsilon' });
    assert.equal(decide({ request: 'escape', status: pending, lostEpsilonCharge: 900 }).conceded, 300n,
        'a server charge never raises the concession above the bound');
    // E2 after a refused clearance.
    assert.deepEqual(afterClearanceFailure({ code: 'nullifier_used' }), { action: 'reconsider', rule: 'E2.nullifier_used' });
    for (const error of [{ code: 'stale_root' }, { status: 503 }, new Error('timeout'), null]) {
        assert.deepEqual(afterClearanceFailure(error), { action: 'escape', conceded: 0n, rule: 'E2.fallback' });
    }
    // The client's own C3 refusals are no server answer: never an escape.
    for (const code of ['ownership_proof_sent', 'exit_locked', 'exit_lock_state', 'exit_lock_mode']) {
        assert.deepEqual(afterClearanceFailure({ code }), { action: 'refuse', rule: 'C3' }, code);
    }
});

test('E2.4/E2.5: the answer to a lock\'s ownership proof is kept with it', () => {
    let lock = newExitLock({ noteId: 7, anchor: '0x12', mode: 'mutual', now: 100 });
    assert.equal(ownershipOutcome(lock), null, 'no ownership proof released');
    lock = recordReleasedProof(lock, { kind: 2, validUntil: 3_700, at: 100 });
    assert.equal(ownershipOutcome(lock), 'unknown', 'released, answer not recorded');
    const answered = recordClearanceOutcome(lock, { outcome: 'nullifier_used', code: 'nullifier_used' });
    assert.equal(ownershipOutcome(answered), 'nullifier_used');
    assert.deepEqual(answered.released[0], { kind: 2, valid_until: 3_700, conceded: '0', at: 100,
        outcome: 'nullifier_used', code: 'nullifier_used' });
    assert.throws(() => recordClearanceOutcome(lock, { outcome: 'maybe' }), { code: 'exit_input_invalid' });
    // Later releases (a close or an escape proof) keep it.
    assert.equal(ownershipOutcome(recordReleasedProof(answered, { kind: 0, validUntil: 9_000, at: 200 })), 'nullifier_used');
});

test('C3: a held lock freezes requests and allows only its own mode at its own state', () => {
    const at = { noteId: 7, anchor: '0x1234' };
    const mutual = newExitLock({ ...at, mode: 'mutual', now: 100 });
    assert.equal(exitLockRefusal(null, { ...at, proof: 'request' }), null);
    assert.equal(exitLockRefusal(mutual, { ...at, proof: 'request' }), 'exit_locked');
    assert.equal(exitLockRefusal(mutual, { noteId: 7, anchor: '0x99', proof: 'mutual' }), 'exit_lock_state');
    // Mode mutual: at most one ownership proof, and close proofs.
    assert.equal(exitLockRefusal(mutual, { ...at, proof: 'ownership' }), null);
    const sent = recordReleasedProof(mutual, { kind: 2, validUntil: 3_700, at: 100 });
    assert.equal(exitLockRefusal(sent, { ...at, proof: 'ownership' }), 'ownership_proof_sent');
    assert.equal(exitLockRefusal(sent, { ...at, proof: 'mutual' }), null);
    assert.equal(exitLockRefusal(sent, { ...at, proof: 'escape' }), 'exit_lock_mode');
    // E2.5: mutual → escape is always allowed, and then only escapes.
    const escape = switchExitLock(sent, 'escape');
    assert.equal(escape.mode, 'escape');
    assert.equal(exitLockRefusal(escape, { ...at, proof: 'mutual' }), 'exit_lock_mode');
    assert.equal(exitLockRefusal(escape, { ...at, proof: 'ownership' }), 'exit_lock_mode');
    assert.equal(exitLockRefusal(escape, { ...at, proof: 'escape', conceded: 300, boundAtState: 300 }), null);
    assert.equal(exitLockRefusal(escape, { ...at, proof: 'escape', conceded: 301, boundAtState: 300 }), 'conceded_exceeds_bound');
    // Back to mutual only while no kind-0 or kind-1 proof was released.
    assert.equal(switchExitLock(escape, 'mutual').mode, 'mutual');
    const released = recordReleasedProof(escape, { kind: 0, validUntil: 10_900, conceded: 300, at: 101 });
    assert.throws(() => switchExitLock(released, 'mutual'), { code: 'exit_lock_mode' });
    assert.deepEqual(releasedExitProofs(released).map(entry => entry.kind), [0]);
    const withHash = recordReleasedTransaction(released, { kind: 0, validUntil: 10_900, transactionHash: `0x${'AB'.repeat(32)}` });
    assert.equal(withHash.released.at(-1).txHash, `0x${'ab'.repeat(32)}`);
});

test('E6: the lock is released only when the note closed, on cancel before any exit proof, or after valid_until', () => {
    const at = { noteId: 7, anchor: '0x1234' };
    const lock = newExitLock({ ...at, mode: 'mutual', now: 100 });
    assert.deepEqual(exitLockReleasable(lock, {}), { releasable: false, reason: 'held' });
    assert.deepEqual(exitLockReleasable(lock, { cancel: true }), { releasable: true, reason: 'cancelled' });
    assert.equal(exitLockDeadAfter(lock), null);
    // An ownership proof alone never lands on chain.
    const owned = recordReleasedProof(lock, { kind: 2, validUntil: 3_700, at: 100 });
    assert.equal(exitLockReleasable(owned, { cancel: true }).releasable, true);
    assert.deepEqual(exitLockReleasable(owned, { noteStatus: 'closed' }), { releasable: true, reason: 'closed' });
    const escaped = recordReleasedProof(switchExitLock(owned, 'escape'), { kind: 0, validUntil: 10_900, at: 110 });
    assert.equal(exitLockDeadAfter(escaped), 11_800);
    const late = { now: 11_801 };
    assert.equal(exitLockReleasable(escaped, { cancel: true, ...late }).releasable, false, 'a released escape outlives a cancel');
    assert.deepEqual(exitLockReleasable(escaped, { noteStatus: 'active', finalizedTimestamp: 10_900 + 900, ...late }),
        { releasable: false, reason: 'proof_live', releasableAfter: 11_800 });
    assert.deepEqual(exitLockReleasable(escaped, { noteStatus: 'active', finalizedTimestamp: 11_801, ...late }),
        { releasable: true, reason: 'proofs_expired' });
    // Not while an exit is pending, nor without a finalized block.
    assert.equal(exitLockReleasable(escaped, { noteStatus: 'pending_withdrawal', finalizedTimestamp: 99_999, ...late }).releasable, false);
    assert.equal(exitLockReleasable(escaped, { noteStatus: 'active', ...late }).reason, 'finality_unknown');
    assert.deepEqual(exitLockReleasable(escaped, { noteStatus: 'closed', ...late }), { releasable: true, reason: 'closed' });
    // A chain reading alone (a pinned RPC that lies about finality or about
    // a close) never releases a proof the local clock still holds live; a
    // Closed reading from the user's own exit RPC does.
    for (const now of [null, 11_000, 11_800]) {
        assert.deepEqual(exitLockReleasable(escaped, { noteStatus: 'active', finalizedTimestamp: 99_999, now }),
            { releasable: false, reason: 'proof_live', releasableAfter: 11_800 }, `now ${now}`);
        assert.equal(exitLockReleasable(escaped, { noteStatus: 'closed', now }).releasable, false, `closed at ${now}`);
    }
    assert.deepEqual(exitLockReleasable(escaped, { noteStatus: 'closed', now: 11_000, statusTrusted: true }),
        { releasable: true, reason: 'closed' });
    // The latest of several released proofs decides.
    const twice = recordReleasedProof(escaped, { kind: 0, validUntil: 20_000, at: 200 });
    assert.equal(exitLockReleasable(twice, { noteStatus: 'active', finalizedTimestamp: 11_801, ...late }).releasable, false);
    assert.equal(exitLockReleasable(twice, { noteStatus: 'active', finalizedTimestamp: 20_901, now: 20_901 }).releasable, true);
});

test('E5: payouts match B − c_final after raises, bounded by the state bound', () => {
    const base = { stateBalance: 1_000, concededAtInit: 0, boundAtState: 300 };
    // No raise: the initiated payout.
    assert.deepEqual(matchEscapePayout({ ...base, raises: [], amount: 1_000 }),
        { accepted: true, exact: true, concededFinal: 0n, alert: null, reason: null });
    // After raises the final payout follows the largest concession.
    const raised = matchEscapePayout({ ...base, raises: [{ conceded: 120 }, { conceded: 200 }], amount: 800 });
    assert.equal(raised.accepted, true);
    assert.equal(raised.concededFinal, 200n);
    assert.equal(matchEscapePayout({ ...base, raises: [{ conceded: 200 }], amount: 900 }).accepted, false,
        'the pre-raise amount no longer matches');
    assert.equal(matchEscapePayout({ ...base, raises: [], amount: 1_001 }).accepted, false);
    // A payout below B − b closes with an alert.
    const exceeded = matchEscapePayout({ ...base, raises: [{ conceded: 400 }], amount: 600 });
    assert.equal(exceeded.accepted, true);
    assert.equal(exceeded.alert, 'concession_exceeded_bound');
    // Unreadable raises: accepted within [?, B − c_init], never above it.
    assert.deepEqual(matchEscapePayout({ ...base, concededAtInit: 50, raises: null, amount: 900 }),
        { accepted: true, exact: false, concededFinal: 100n, alert: null, reason: null });
    assert.equal(matchEscapePayout({ ...base, concededAtInit: 50, raises: null, amount: 951 }).accepted, false);
    // An unknown bound raises no alert.
    assert.equal(matchEscapePayout({ stateBalance: 1_000, concededAtInit: 0, raises: [{ conceded: 900 }], amount: 100 }).alert, null);
    // The G1 exit-cost warning: B − b below three escape costs.
    assert.deepEqual(exitCostWarning({ stateBalance: 1_000, boundAtState: 300, exitCostUnits: 250 }), { floor: 700n, cost: 250n });
    assert.equal(exitCostWarning({ stateBalance: 1_000, boundAtState: 300, exitCostUnits: 233 }), null);
    // An escape's fee in gwei ledger units, rounded up.
    assert.equal(ESCAPE_GAS_ESTIMATE, 620_000n);
    assert.equal(escapeCostUnits({ gasPriceWei: 10_000_000_000n, weiPerUnit: '1000000000' }), 6_200_000n);
    assert.equal(escapeCostUnits({ gasPriceWei: 1n, weiPerUnit: 1_000_000_000 }), 1n);
    assert.throws(() => escapeCostUnits({ gasPriceWei: 1n, weiPerUnit: 0 }), { code: 'exit_input_invalid' });
});
