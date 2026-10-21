import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, HttpError,
    createHarness, destinationBytes, memoryIndexedDb, noteState, nullifierFor, selectorOf
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { contractEstimateError } = await import('../services/zkapiContractError.mjs');

const RECORD_ID = `${DEPLOYMENT}:11155111:${VAULT}:7`;
const SIGNATURE = Object.freeze({ r: '0x51', s: '0x52' });
const records = () => store.listBrowserRequestArchive(DEPLOYMENT);
const clearanceFor = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { ...SIGNATURE } });

async function freshWallet(options = {}, state = noteState()) {
    indexedDB.clear();
    const harness = createHarness(BrowserWalletRuntime, options);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await harness.runtime.reload();
    return harness;
}

async function discardFirstRequest(h) {
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root');
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
    return (await records())[0];
}

const escapeProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'escape');
// Kind-2 ownership proofs: no destination, no concession, never submittable.
const ownershipProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'ownership');
const NO_DESTINATION = Array(20).fill(0);
const mutualProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'mutual');
const clearancePosts = h => h.serverCalls('POST', '/v2/withdraw/clearance');
const markerOf = async () => {
    const marker = (await store.readBrowserWallet()).preparedWithdrawal;
    return marker && { phase: marker.phase, mode: marker.mode, clearanceReserved: marker.clearanceReserved,
        withdrawalNullifier: marker.withdrawalNullifier };
};
const RESERVING = Object.freeze({ phase: 'reserving', mode: 'mutual', clearanceReserved: true,
    withdrawalNullifier: nullifierFor(GENESIS_ANCHOR) });

test('mutual clearance sends a kind-2 ownership proof for the same nullifier and no destination', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    let markerBeforeProof = 'not observed';
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation === 'prepareWithdrawal' && payload.args.mode === 'ownership') {
            markerBeforeProof = (await store.readBrowserWallet()).preparedWithdrawal;
        }
        return call(operation, payload);
    };
    let atPost = null;
    h.server.clearance = async body => {
        atPost = { body, saved: await store.readBrowserWallet(), proofs: h.workerOperations('prepareWithdrawal').length };
        return clearanceFor(body);
    };
    const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);

    const [ownership] = ownershipProofs(h);
    assert.equal(ownership.payload.args.clearance, undefined);
    assert.equal(ownership.payload.args.destination, undefined, 'the ownership proof names no destination');
    assert.equal(ownership.payload.args.conceded, undefined);
    const validity = ownership.payload.args.valid_until - Math.floor(Date.now() / 1000);
    assert.ok(validity > 3_250 && validity <= 3_300, 'an ownership proof is valid for one hour less a skew margin');
    assert.equal(markerBeforeProof, null, 'local proving precedes the withdrawal-only marker');
    const { body, saved } = atPost;
    assert.deepEqual(Object.keys(body).sort(), ['ownership_proof', 'withdrawal_nullifier']);
    assert.equal(body.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    assert.deepEqual(Object.keys(body.ownership_proof).sort(), ['proof', 'public_inputs']);
    assert.equal(body.ownership_proof.public_inputs.kind, 2);
    assert.equal(body.ownership_proof.public_inputs.withdrawal_nullifier, body.withdrawal_nullifier);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, NO_DESTINATION);
    assert.equal(body.ownership_proof.public_inputs.final_balance, 5_000_000);
    assert.equal(body.ownership_proof.proof.backend, 'groth16_bn254');
    assert.equal(atPost.proofs, 1, 'only the ownership proof exists when the server is asked');
    assert.equal(saved.preparedWithdrawal.phase, 'reserving', 'the marker is durable before the reservation');

    const [mutual] = mutualProofs(h);
    assert.deepEqual(mutual.payload.args.clearance, clearanceFor(body));
    assert.equal(plan.mode, 'mutual');
    assert.deepEqual(plan.clearance, clearanceFor(body));
    const persisted = await store.readBrowserWallet();
    assert.deepEqual(persisted.preparedWithdrawal.clearance, plan.clearance);
    assert.equal(JSON.stringify(persisted).includes(body.ownership_proof.proof.proof), false,
        'the ownership proof itself is never persisted');
});

test('a client clock a few minutes fast still gets its clearance (the server checks now <= valid_until <= now + 3600)', async () => {
    for (const skewSeconds of [0, 15, 30, 120, 290]) {
        const h = await freshWallet({ clearanceOwnershipProof: 'required' });
        // The server's clock is behind the client's, and it reads the proof
        // one proving time (here 10 s) after the client started it.
        h.server.clearance = body => {
            const serverNow = Math.floor(Date.now() / 1000) - skewSeconds + 10;
            const validUntil = Number(body.ownership_proof.public_inputs.valid_until);
            if (!(serverNow <= validUntil && validUntil <= serverNow + 3_600)) {
                throw new HttpError('The ownership proof is not fresh.', 400, 'invalid_ownership_proof');
            }
            return clearanceFor(body);
        };
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual', `a clock ${skewSeconds} s fast closes cooperatively`);
    }
});

test('a local ownership-proof failure never makes the note withdrawal-only', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    h.worker.failWithdrawal = new Error('proof generation failed');
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /proof generation failed/);
    assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
    assert.equal(clearancePosts(h).length, 0);
});

test('a mismatched ownership proof fails closed before any server reservation', async () => {
    const other = `0x${'56'.repeat(20)}`;
    for (const change of [{ chain_id: 1 }, { contract_address: other }, { state_signing_key_x: '0x1' },
        { clearance_signing_key_y: '0x1' }, { withdrawal_nullifier: '0x1' }, { note_id: 8 },
        { active_root: '0x1' }, { final_balance: 1 }, { destination: destinationBytes(other) },
        { kind: 0 }, { kind: 1 }, { conceded: 1 }, { next_nullifier: '0x5' }, { valid_until: 1 },
        { valid_until: Math.floor(Date.now() / 1000) + 7_200 }, { destination: destinationBytes(DESTINATION) },
        { protocol_version: 1 }, { request_nullifier: '0x1' },
        { authorization_tag: '0x1' }]) {
        const h = await freshWallet({ vaultRevision: 2 });
        h.worker.mutate = plan => { if (plan.mode === 'ownership') Object.assign(plan.public_inputs, change); };
        h.server.clearance = body => clearanceFor(body);
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), /does not match/);
        assert.equal(clearancePosts(h).length, 0);
        assert.equal((await store.readBrowserWallet()).preparedWithdrawal, null);
    }
});

test('a request proof is never sent as an ownership proof', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const archived = await discardFirstRequest(h);
    h.server.clearance = body => clearanceFor(body);
    await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    const [{ body }] = clearancePosts(h);
    for (const field of ['request_nullifier', 'authorization_tag', 'anonymous_commitment_x', 'solvency_bound', 'request_time']) {
        assert.equal(field in body.ownership_proof.public_inputs, false);
    }
    assert.notEqual(body.ownership_proof.proof.proof, archived.journal.prepared_request.proof.proof);
    assert.equal(body.ownership_proof.public_inputs.withdrawal_nullifier, archived.journal.nullifier);
});

// The gateway that withheld a lease POST at this state holds a request proof
// for its nullifier. On a vault whose challenge burns the nullifier, it could
// submit an ownership proof as an escape and challenge it with that request.
// An upgraded server refuses a proof-less request without reserving anything
// when it requires a proof or when its shared legacy budget is spent.
const proofOnlyServer = (h, status = 400, code = 'clearance_ownership_required') => {
    h.server.clearance = body => {
        if (!body.ownership_proof) throw new HttpError('Nothing was reserved.', status, code, { retriable: status === 503 });
        return clearanceFor(body);
    };
};
const LEGACY_REFUSALS = [[400, 'clearance_ownership_required'], [503, 'legacy_clearance_capacity']];

// The reference gateway's own answer to a throttled POST, before the API.
const gatewayThrottle = () => new HttpError('Too many requests from this network source; retry the same request later.',
    429, 'gateway_rate_limited', { retriable: true, retry_after_seconds: 5 });
const withRecordedBackoff = h => {
    const sleeps = [];
    h.runtime.postClearance = (body, nullifier, signal) => BrowserWalletRuntime.prototype.postClearance.call(
        h.runtime, body, nullifier, signal, { sleep: async milliseconds => { sleeps.push(milliseconds); } });
    return sleeps;
};

// The gateway that answers 429 may also read the body: it holds the ownership
// proof of a mutual close (an escape at nullifier N to the real destination).
// If the note then sent a request proof at N, that gateway could submit the
// escape on a strict vault and challenge it with the request, which burns N.
// A server with legacy clearance on reserves a proof-less request, so only an
// error code that says nothing was reserved may roll the marker back. A bare
// 5xx or a lost connection can follow the reservation.
const LOST_ANSWERS = [
    ['a network error', () => new TypeError('Failed to fetch')],
    ['a 502 without an error code', () => new HttpError('Bad gateway', 502, undefined)],
    ['a 503 without an error code', () => new HttpError('Service unavailable', 503, undefined)],
    ['a 504 without an error code', () => new HttpError('Gateway timeout', 504, undefined)],
    ['500 internal_error', () => new HttpError('The server failed.', 500, 'internal_error')]
];

test('a persisted clearance is reused without a second ownership proof or server request', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    h.server.clearance = body => clearanceFor(body);
    const first = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    h.chain.root = '0x79';
    const second = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    // The vault accepts any root it ever held: the close proof is reused.
    assert.equal(second.public_inputs.active_root, first.public_inputs.active_root);
    assert.deepEqual(second.proof, first.proof);
    assert.deepEqual(second.clearance, first.clearance);
    // A mutual lock may always become an escape (E2.5).
    const escape = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.deepEqual(escape.clearance, first.clearance, 'an escape carries the clearance');
    assert.equal(escapeProofs(h).at(-1).payload.args.clearance, undefined, 'the WASM never sees a clearance on an escape');
    assert.equal(escapeProofs(h).at(-1).payload.args.conceded, 0);
    // C3: once an escape proof was released the note exits only by escape
    // until that proof is dead.
    const back = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(back.mode, 'escape');
    assert.deepEqual(back.proof, escape.proof);
    assert.equal(clearancePosts(h).length, 1);
    assert.equal(ownershipProofs(h).length, 1, 'one ownership proof');
    assert.equal(escapeProofs(h).length, 1, 'and one real escape proof');
    assert.deepEqual((await store.readBrowserWallet()).exitLock.released.map(entry => entry.kind), [2, 1, 0]);

    // A forced re-proof of the close reuses the persisted clearance.
    const again = await freshWallet();
    again.server.clearance = body => clearanceFor(body);
    await again.runtime.prepareWithdrawal('mutual', DESTINATION);
    again.chain.root = '0x7a';
    const reproved = await again.runtime.prepareWithdrawal('mutual', DESTINATION, { reprove: true });
    assert.equal(reproved.public_inputs.active_root, '0x7a');
    assert.equal(clearancePosts(again).length, 1);
    assert.equal(ownershipProofs(again).length, 1);
});

// The shared vectors' ownership_proof rule (C3): at most one live kind-2
// proof per state, across exit locks.
test('C3: under a new lock, the state\'s live ownership proof is sent again; one about to expire waits; an expired one is replaced', async () => {
    const restore = Date.now;
    // A first clearance whose answer is lost (the call is aborted mid-POST):
    // the lock keeps the released ownership proof and nothing else, so the
    // user may cancel it (E6).
    const lostAnswer = async () => {
        const h = await freshWallet({ clearanceOwnershipProof: 'required' });
        const sent = [];
        const controller = new AbortController();
        h.server.clearance = body => {
            sent.push(body.ownership_proof);
            controller.abort();
            return new Promise(() => {});
        };
        await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION, { signal: controller.signal }));
        assert.deepEqual((await store.readBrowserWallet()).exitLock.released.map(entry => entry.kind), [2]);
        assert.equal((await h.runtime.cancelExit()).reason, 'cancelled');
        assert.equal((await store.readBrowserWallet()).exitLock, null);
        h.server.clearance = body => { sent.push(body.ownership_proof); return clearanceFor(body); };
        return { h, sent };
    };

    // While it stays valid, the next mutual close sends the same proof again.
    const resent = await lostAnswer();
    const plan = await resent.h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(plan.mode, 'mutual');
    assert.equal(ownershipProofs(resent.h).length, 1, 'no second ownership proof');
    assert.equal(resent.sent.length, 2);
    assert.deepEqual(resent.sent[1], resent.sent[0]);
    assert.equal(mutualProofs(resent.h).length, 1);

    // Within the resend margin it waits; once expired, a new one is made.
    const expiring = await lostAnswer();
    const validUntil = Number(expiring.sent[0].public_inputs.valid_until);
    try {
        Date.now = () => (validUntil - 3) * 1_000;
        await assert.rejects(expiring.h.runtime.prepareWithdrawal('mutual', DESTINATION),
            error => error.code === 'ownership_proof_wait' && error.data.retry_after === 4);
        assert.equal(ownershipProofs(expiring.h).length, 1);
        assert.equal(expiring.sent.length, 1, 'nothing was sent');
        assert.equal((await store.readBrowserWallet()).exitLock, null, 'the refused attempt left no lock');
        Date.now = () => (validUntil + 1) * 1_000;
        const renewed = await expiring.h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(renewed.mode, 'mutual');
    } finally {
        Date.now = restore;
    }
    assert.equal(ownershipProofs(expiring.h).length, 2, 'a new proof once the first expired');
    assert.equal(expiring.sent.length, 2);
    assert.ok(Number(expiring.sent[1].public_inputs.valid_until) > validUntil);
});

test('a persisted clearance is never reused after the note state changes', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' });
    const archived = await discardFirstRequest(h);
    h.server.clearance = body => clearanceFor(body);
    const first = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(first.clearance.withdrawal_nullifier, nullifierFor(GENESIS_ANCHOR));
    // A receipt that arrives while the close proof is live never installs
    // (C3): it is archived as late_successor and the live plan stays.
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
        request_response: h.receiptFor(archived.journal) });
    const kept = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.deepEqual(kept.proof, first.proof);
    assert.equal((await records()).find(record => record.clientRequestId === archived.clientRequestId).disposition,
        'late_successor');
    // E6: once the close proof is dead at a finalized block, the lock is
    // released and the late successor installs.
    h.chain.finalizedTimestamp = first.public_inputs.valid_until + 901;
    const restore = Date.now;
    Date.now = () => (first.public_inputs.valid_until + 901) * 1_000;
    try {
        await h.runtime.cancelExit();
    } finally {
        Date.now = restore;
    }
    assert.equal((await store.readBrowserWallet()).state.current_anchor, '0x9999');
    const second = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(second.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal(second.clearance.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal(clearancePosts(h).at(-1).body.withdrawal_nullifier, nullifierFor('0x9999'));

    const stale = await freshWallet({ clearanceOwnershipProof: 'required' }, noteState({ current_anchor: '0x2222' }));
    const oldNullifier = nullifierFor(GENESIS_ANCHOR);
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), preparedWithdrawal: {
        phase: 'prepared', mode: 'mutual', operationId: 'legacy', noteId: 7, destination: DESTINATION,
        withdrawalNullifier: oldNullifier, clearanceReserved: true,
        clearance: { status: 'ok', withdrawal_nullifier: oldNullifier, signature: { ...SIGNATURE } } } });
    await stale.runtime.reload();
    stale.server.clearance = body => clearanceFor(body);
    const plan = await stale.runtime.prepareWithdrawal('mutual', DESTINATION);
    assert.equal(clearancePosts(stale).length, 1, 'a clearance for an older state is ignored');
    assert.equal(plan.clearance.withdrawal_nullifier, nullifierFor('0x2222'));
});

test('background mutual sends the ownership proof and persists its clearance', async () => {
    const h = await freshWallet({ clearanceOwnershipProof: 'required' }, noteState({ note_id: 8, current_anchor: '0x8888' }));
    const state = noteState();
    const nullifier = nullifierFor(state.current_anchor);
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', destination: DESTINATION, phase: 'parked',
        clearanceReserved: true, state, finalBalance: state.current_balance, withdrawalNullifier: nullifier,
        preparedWithdrawal: { phase: 'reserving', mode: 'mutual', noteId: 7, operationId: 'old',
            destination: DESTINATION, clearanceReserved: true, withdrawalNullifier: nullifier } });
    await h.runtime.reload();
    h.server.clearance = body => clearanceFor(body);
    const plan = await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: h.chain.root });
    const [{ body }] = clearancePosts(h);
    assert.equal(body.withdrawal_nullifier, nullifier);
    assert.equal(body.ownership_proof.public_inputs.note_id, 7);
    assert.deepEqual(body.ownership_proof.public_inputs.destination, NO_DESTINATION);
    assert.equal(plan.public_inputs.kind, 1);
    const saved = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
    assert.deepEqual(saved.preparedWithdrawal.clearance, clearanceFor(body));
    assert.equal((await store.readBrowserWallet()).state.note_id, 8, 'the selected chat note is untouched');

    h.chain.root = '0x79';
    await h.runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: '0x79' });
    assert.equal(clearancePosts(h).length, 1, 'the persisted clearance is reused');
    assert.equal(ownershipProofs(h).length, 1);
    assert.equal(mutualProofs(h).length, 2);
});

test('a withdrawal proof is reused at any root until near its valid_until', async () => {
    const h = await freshWallet();
    const first = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    const validity = first.public_inputs.valid_until - Math.floor(Date.now() / 1000);
    assert.ok(validity > 10_700 && validity <= 10_800, 'an exit proof is valid for three hours');
    assert.equal(first.public_inputs.kind, 0);
    assert.equal(first.siblings, undefined, 'exits carry no Merkle path');
    h.chain.root = '0x78';
    const reused = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(h).length, 1, 'no new proof');
    assert.deepEqual(reused, first);

    const reproved = await h.runtime.prepareWithdrawal('escape', DESTINATION, { reprove: true });
    assert.equal(escapeProofs(h).length, 2);
    assert.equal(reproved.public_inputs.active_root, '0x78');

    // A proof close to its valid_until is never handed out again.
    const saved = await store.readBrowserWallet();
    await store.writeBrowserWallet({ ...saved, preparedWithdrawal: { ...saved.preparedWithdrawal,
        public_inputs: { ...saved.preparedWithdrawal.public_inputs, valid_until: Math.floor(Date.now() / 1000) + 600 } } });
    await h.runtime.reload();
    const fresh = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(escapeProofs(h).length, 3);
    assert.ok(fresh.public_inputs.valid_until > Math.floor(Date.now() / 1000) + 10_000);
});

test('vault errors decode from selectors computed from their signatures', () => {
    for (const [signature, code] of [['UnknownRoot()', 'unknown_root'], ['ChallengedNullifier()', 'challenged_nullifier'],
        ['InvalidDestination()', 'invalid_destination'], ['Paused()', 'vault_paused'], ['StaleRoot()', 'stale_root'],
        ['SupersededState()', 'superseded_state'], ['ProofExpired()', 'proof_expired'],
        ['WrongWithdrawalKind()', 'wrong_withdrawal_kind']]) {
        const error = contractEstimateError({ message: 'execution reverted', data: { originalError: { data: selectorOf(signature) } } });
        assert.equal(error.code, code, signature);
        assert.equal(error.selector, selectorOf(signature));
    }
    assert.match(contractEstimateError({ data: selectorOf('Paused()') }).message, /paused/i);
});


test('only a close the server granted can be set aside; every other withdrawal-only balance must exit first', async () => {
    for (const [label, answer] of [
        ['nullifier_used', () => { throw new HttpError('The nullifier is used.', 409, 'nullifier_used'); }],
        ['refused', () => { throw new HttpError('Invalid ownership proof.', 400, 'invalid_ownership_proof'); }],
        ['unreachable', () => { throw new HttpError('Unavailable', 503, 'service_unavailable'); }]
    ]) {
        const h = await freshWallet({ clearanceOwnershipProof: 'required' });
        await discardFirstRequest(h);
        h.server.clearance = answer;
        // nullifier_used waits for T; the others escape with c = 0 (E2.5).
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION).catch(error => error);
        assert.equal(label === 'nullifier_used' ? plan.code : plan.mode, label === 'nullifier_used' ? 'request_settlement_pending' : 'escape', label);
        const before = await store.readBrowserWallet();
        assert.equal(before.preparedWithdrawal.clearanceReserved, true, `${label}: withdrawal-only`);
        assert.equal(h.runtime.snapshot().config.prepared_withdrawal.clearance_granted, false, label);
        await assert.rejects(h.runtime.parkPreparedWithdrawal(), { code: 'park_requires_clearance' }, label);
        // The store refuses it too, in the same transaction that would park it.
        await assert.rejects(store.parkBrowserWithdrawal({ recordId: RECORD_ID, noteId: 7, mode: 'mutual' }),
            { code: 'park_requires_clearance' }, label);
        assert.deepEqual(await store.readBrowserWallet(), before, `${label}: the balance stays selected`);
        assert.deepEqual(await store.listBrowserWithdrawals(DEPLOYMENT), [], label);
        // The client tells the user to withdraw, not to set the balance aside.
        const client = new ZkapiClient();
        client.config = h.runtime.snapshot().config;
        await assert.rejects(client.cancelPreparedWithdrawal(), /can only be withdrawn.*escape hatch needs nothing from the server/, label);
    }
});

test('a granted close set aside shows its deadlines and closes later without the operator, from the deposit-time path', async () => {
    const depositPath = { active_root: '0x51', siblings: Array.from({ length: 32 }, (_, index) => `0x${(index + 1).toString(16)}`) };
    const soon = Math.floor(Date.now() / 1_000) + 43_200 + 3 * 86_400;
    for (const [expiry, near] of [[2_000_000_000, false], [soon, true]]) {
        const h = await freshWallet({ clearanceOwnershipProof: 'required' }, noteState({ deposit_path: depositPath, expiry_ts: expiry }));
        h.server.clearance = body => clearanceFor(body);
        const plan = await h.runtime.prepareWithdrawal('mutual', DESTINATION);
        assert.equal(plan.mode, 'mutual');
        assert.equal(h.runtime.snapshot().config.prepared_withdrawal.clearance_granted, true);
        const record = await h.runtime.parkPreparedWithdrawal();
        assert.equal(record.phase, 'parked');
        assert.equal((await store.readBrowserWallet()).state, null);
        const [summary] = h.runtime.snapshot().withdrawals;
        assert.equal(summary.expiry, expiry * 1_000);
        assert.equal(summary.must_initiate_by, (expiry - 43_200) * 1_000);
        assert.equal(summary.exit_deadline_near, near, `expiry ${expiry}`);
        assert.equal(summary.state, undefined, 'no private state in the snapshot');
        // Later, with the indexer and the server gone: the kept clearance and
        // the deposit-time path close it.
        h.runtime.treePath = () => assert.fail('no indexer for a set-aside close with a saved path');
        h.server.clearance = () => assert.fail('no second clearance');
        const posts = clearancePosts(h).length;
        const background = await h.runtime.prepareBackgroundWithdrawal(record.recordId, { expectedActiveRoot: '0x99' });
        assert.equal(background.mode, 'mutual');
        assert.equal(background.pathSource, 'deposit');
        assert.equal(background.public_inputs.active_root, '0x51');
        assert.equal(background.public_inputs.final_balance, 5_000_000);
        assert.equal(clearancePosts(h).length, posts);
        // After an UnknownRoot refusal of that root, another one is used.
        h.runtime.treePath = async noteId => ({ active_root: '0x99', note_id: noteId,
            siblings: Array.from({ length: 32 }, (_, index) => `0x99${index.toString(16)}`) });
        const again = await h.runtime.prepareBackgroundWithdrawal(record.recordId, { expectedActiveRoot: '0x99', refusedRoot: '0x51' });
        assert.equal(again.pathSource, 'indexer');
        assert.equal(again.public_inputs.active_root, '0x99');
    }
});
