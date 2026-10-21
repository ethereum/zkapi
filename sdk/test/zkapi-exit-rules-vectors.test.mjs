// The shared exit-rule vectors (design §11: S1–S6, C1–C5 and E0–E7 parity
// with the companion wallet), protocol/rust/crates/zkapi-client/tests/
// vectors/exit-rules.json. The companion's zkapi-client (shared_vectors.rs),
// zkapi-companion (the exit kit) and zkapi-clientd (the payout matcher)
// reproduce the same file. Every section is consumed here through the SDK's
// own code: the pure exit policy the runtime decides with, the shipped
// WebAssembly's successor checks, and the exit-kit opener. A section or a
// constant this test does not know fails it, so the file cannot grow past
// the SDK unnoticed.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
    EXIT_TIMING, UNSETTLED_ESCAPE_AFTER_SECONDS, decideExit, exitLockRefusal, exitLockReleasable, exitRecordClass,
    lowExpiry, matchEscapePayout, mustInitiateBy, nearExpiry, ownershipProofAction, stateExitStatus,
    unsettledEscapeAfterSeconds
} from '../services/zkapiExitPolicy.mjs';
import { REQUEST_JOURNAL_TYPE } from '../services/zkapiRequestArchive.mjs';
import { openExitKit } from '../services/zkapiExitKit.mjs';

const sdk = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const root = path.resolve(sdk, '..');
const vectors = JSON.parse(fs.readFileSync(path.join(root, 'protocol/rust/crates/zkapi-client/tests/vectors/exit-rules.json'), 'utf8'));

const SECTIONS = ['schema', 'description', 'constants', 'e_low', 'must_initiate_by', 'near_expiry', 'unsettled_escape_after',
    'classify', 'decide', 'lock_releasable', 'payout', 'concession_allowed', 'ownership_proof', 'successor_checks', 'exit_kit'];

test('the vector file has exactly the sections this test reproduces', () => {
    assert.equal(vectors.schema, 2);
    assert.deepEqual(Object.keys(vectors).sort(), [...SECTIONS].sort());
});

test('E0 and C3 constants', () => {
    const sdkConstants = {
        call_timeout_seconds: EXIT_TIMING.callTimeoutMs / 1_000,
        recovery_budget_seconds: EXIT_TIMING.recoveryBudgetMs / 1_000,
        initiate_margin_seconds: EXIT_TIMING.mustInitiateMarginSeconds,
        mutual_cutoff_seconds: EXIT_TIMING.escapeOnlyMarginSeconds,
        settlement_grace_seconds: EXIT_TIMING.settlementSlackSeconds,
        near_expiry_margin_seconds: EXIT_TIMING.nearExpiryMarginSeconds,
        unknown_reading_resolves_after_seconds: EXIT_TIMING.unknownSettledAfterSeconds,
        default_unsettled_escape_after_seconds: UNSETTLED_ESCAPE_AFTER_SECONDS.default,
        min_unsettled_escape_after_seconds: UNSETTLED_ESCAPE_AFTER_SECONDS.minimum,
        max_unsettled_escape_after_seconds: UNSETTLED_ESCAPE_AFTER_SECONDS.maximum,
        lock_release_margin_seconds: EXIT_TIMING.lockReleaseMarginSeconds,
        exit_proof_validity_seconds: EXIT_TIMING.exitProofValiditySeconds,
        ownership_proof_validity_seconds: EXIT_TIMING.ownershipProofValiditySeconds,
        ownership_resend_margin_seconds: EXIT_TIMING.ownershipResendMarginSeconds,
    };
    assert.deepEqual(Object.keys(vectors.constants).sort(), Object.keys(sdkConstants).sort());
    for (const [name, value] of Object.entries(vectors.constants)) assert.equal(sdkConstants[name], value, name);
});

test('E0: E_low, must_initiate_by, the escape-after knob, and C4 near expiry', () => {
    for (const vector of vectors.e_low) {
        assert.equal(lowExpiry(vector.expiry_ts, { exitRpcExpiry: vector.exit_rpc, pinnedRpcExpiry: vector.pinned_rpc }),
            vector.expected, JSON.stringify(vector));
    }
    for (const vector of vectors.must_initiate_by) assert.equal(mustInitiateBy(vector.e_low), vector.expected);
    for (const vector of vectors.unsettled_escape_after) {
        assert.equal(unsettledEscapeAfterSeconds(vector.configured ?? undefined), vector.expected);
    }
    for (const vector of vectors.near_expiry) {
        assert.equal(nearExpiry({ now: vector.now, settlementWindowSeconds: vector.settlement_window,
            mustInitiateBy: vector.must_initiate_by }), vector.expected, JSON.stringify(vector));
    }
});

// A vector record (`{disposition, request_time, created_at, reading?}`, in
// seconds) as the browser archives it.
function archived(record, index) {
    return {
        type: REQUEST_JOURNAL_TYPE,
        deploymentId: 'vectors',
        noteId: 0,
        anchor: '0x1',
        clientRequestId: `vector-${index}`,
        disposition: record.disposition,
        journal: {
            client_request_id: `vector-${index}`,
            created_at_ms: record.created_at * 1_000,
            prepared_request: { public_inputs: { request_time: record.request_time } }
        },
        createdAt: record.created_at * 1_000,
        serverObservations: record.reading
            ? [{ status: record.reading.status, context: 'exit', at: record.reading.observed_at * 1_000 }]
            : []
    };
}

const CLASSES = { terminal: 'terminal', resolved_unreserved: 'resolved_unreserved', unresolved: 'unresolved' };

test('E1–E3 record classes', () => {
    vectors.classify.forEach((vector, index) => {
        assert.equal(exitRecordClass(archived(vector.record, index)), CLASSES[vector.expected], JSON.stringify(vector.record));
    });
});

// The SDK's rule names for the companion's escape reasons.
const REASONS = {
    'E2.deadline': 'mutual_cutoff',
    'E2.fallback': 'mutual_refused',
    'E3.lost_epsilon': 'lost_epsilon',
    'E3.T': 'at_deadline',
    'E3.forced': 'forced_early'
};

test('E2–E3 decisions, with E2.4/E2.5 clearance outcomes and forced early exits', () => {
    for (const { name, facts, expected } of vectors.decide) {
        const status = stateExitStatus({ boundAtState: facts.bound_at_state, records: facts.records.map(archived) });
        const decision = decideExit({
            // Without an early-exit choice the user asked to withdraw (E2's
            // mutual close when the state allows); with one, to escape now.
            request: facts.early_exit ? 'escape' : 'mutual',
            now: facts.now,
            mustInitiateBy: facts.must_initiate_by,
            status,
            settlementWindowSeconds: facts.settlement_window,
            unsettledAfterSeconds: facts.unsettled_escape_after,
            settlementDeadline: facts.settlement_deadline_reported ?? null,
            lostEpsilonCharge: facts.lost_epsilon_charge ?? null,
            earlyConcession: facts.early_exit === 'concede_bound' ? 'bound' : 'zero',
            clearanceOutcome: { nullifier_used: 'nullifier_used', refused_or_unreachable: 'refused' }[facts.mutual_outcome] ?? null
        });
        let actual;
        if (decision.action === 'mutual') actual = { action: 'mutual' };
        else if (decision.action === 'wait') actual = { action: 'wait', until: decision.escapeAt };
        else actual = { action: 'escape', conceded: Number(decision.conceded), reason: REASONS[decision.rule] };
        assert.deepEqual(actual, expected, name);
    }
});

test('C3: the concession range and the ownership proof of a state', () => {
    const lock = { noteId: 0, anchor: '0x1', mode: 'escape', since: 0, released: [] };
    for (const vector of vectors.concession_allowed) {
        const refusal = exitLockRefusal(lock, { noteId: 0, anchor: '0x1', proof: 'escape', conceded: vector.conceded,
            boundAtState: vector.bound_at_state });
        assert.equal(refusal === null, vector.expected, JSON.stringify(vector));
    }
    for (const vector of vectors.ownership_proof) {
        assert.equal(ownershipProofAction(vector.newest_valid_until, vector.now), vector.expected, vector.name);
    }
});

test('E6: lock release', () => {
    // Each vector carries the device clock (`now`) and whether the note
    // reading came from the owner's exit RPC (`status_trusted`), so a client
    // that releases on the chain reading alone fails here.
    for (const vector of vectors.lock_releasable) {
        assert.ok(Number.isSafeInteger(vector.now) && typeof vector.status_trusted === 'boolean', vector.name);
        const lock = { noteId: 0, anchor: '0x1', mode: 'escape', since: 0,
            released: vector.released.map(entry => ({ kind: entry.kind, valid_until: entry.valid_until })) };
        const verdict = exitLockReleasable(lock, { noteStatus: vector.note, finalizedTimestamp: vector.finalized_block_timestamp,
            cancel: vector.user_cancels, now: vector.now, statusTrusted: vector.status_trusted });
        assert.equal(verdict.releasable, vector.expected, JSON.stringify(vector));
    }
});

test('E5: payout matching after raises', () => {
    for (const vector of vectors.payout) {
        const matched = matchEscapePayout({ stateBalance: vector.state_balance, concededAtInit: vector.conceded_at_init,
            boundAtState: vector.bound_at_state, raises: vector.raises, amount: vector.paid });
        const actual = matched.accepted
            ? { result: 'matches', conceded_final: Number(matched.concededFinal),
                concession_exceeded_bound: matched.alert === 'concession_exceeded_bound' }
            : { result: 'mismatch' };
        assert.deepEqual(actual, vector.expected, JSON.stringify(vector));
    }
});

test('S1–S6: the shipped WebAssembly installs, archives as invalid_successor or rejects each response', async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = async input => {
        const url = new URL(String(input));
        if (url.protocol === 'file:') {
            return new Response(fs.readFileSync(fileURLToPath(url)), { headers: { 'content-type': 'application/wasm' } });
        }
        return new Response('', { status: 404 });
    };
    try {
        const { execute } = await import('../services/zkapiWasmWorker.js');
        const checks = vectors.successor_checks;
        const config = {
            protocol_version: 2, chain_id: checks.state.chain_id, contract_address: checks.state.contract_address,
            request_charge_cap: 1_000, policy_charge_cap: 1_000, policy_enabled: false,
            state_signing_key: checks.state_signing_key, clearance_signing_key: checks.state_signing_key
        };
        assert.ok(checks.cases.length >= 15);
        for (const vector of checks.cases) {
            const args = { state: checks.state, journal: vector.journal ?? checks.journal, response: vector.response };
            let outcome;
            let installed = null;
            try {
                const next = await execute('completeResponse', { config, args });
                outcome = 'install';
                installed = next;
            } catch (error) {
                outcome = String(error?.message || error).startsWith('invalid_successor') ? 'invalid_successor' : 'reject';
            }
            assert.equal(outcome, vector.expected, vector.name);
            if (vector.installed) {
                assert.equal(BigInt(installed.current_balance), BigInt(vector.installed.current_balance), vector.name);
                assert.equal(BigInt(installed.current_anchor), BigInt(vector.installed.current_anchor), vector.name);
                assert.equal(BigInt(installed.prev_anchor), BigInt(vector.installed.prev_anchor), vector.name);
                assert.equal(BigInt(installed.balance_blinding), BigInt(vector.installed.balance_blinding), vector.name);
                assert.equal(BigInt(installed.bound_at_state), BigInt(vector.installed.bound_at_state), vector.name);
            }
        }
    } finally {
        globalThis.fetch = originalFetch;
    }
});

test('E7: the shared exit kit opens with its passphrase only and holds the expected state', async () => {
    const shared = vectors.exit_kit;
    const kit = JSON.parse(fs.readFileSync(path.join(root, shared.fixture), 'utf8'));
    await assert.rejects(openExitKit(kit, shared.wrong_passphrase));
    const payload = await openExitKit(kit, shared.passphrase);
    const expected = shared.expected;
    assert.equal(payload.format, expected.format);
    assert.equal(payload.trusted_deployment.deployment_id, expected.deployment_id);
    assert.equal(payload.trusted_deployment.contract_address, expected.contract_address);
    assert.equal(payload.note.note_id, expected.note_id);
    assert.equal(String(payload.note.deposit_amount), expected.deposit_amount);
    assert.equal(String(payload.note.current_balance), expected.current_balance);
    assert.equal(BigInt(payload.note.current_anchor), BigInt(expected.current_anchor));
    assert.equal(String(payload.bound_at_state), expected.bound_at_state);
    assert.equal(payload.state_seq, expected.state_seq);
    assert.equal(payload.exported_at, expected.exported_at);
    assert.equal(BigInt(payload.merkle_path.active_root), BigInt(expected.merkle_path_root));
    assert.equal(payload.merkle_path.siblings.length, expected.merkle_path_siblings);
});
