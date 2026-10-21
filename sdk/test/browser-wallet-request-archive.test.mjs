import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { nativeFunding, nativeQuote } from './helpers/native-fixtures.mjs';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, HttpError,
    createHarness, keccak256Hex, memoryIndexedDb, noteState, nullifierFor, word
} from './helpers/request-archive-harness.mjs';
import { deployedProfile } from './helpers/deployed-profile.mjs';

// Real store and runtime over a transactional IndexedDB; only the protocol
// server, the pinned vault RPC and the proof worker are observed fakes.
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const archive = await import('../services/zkapiRequestArchive.mjs');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { default: walletCodec } = await import('../wallet.js');

const records = () => store.listBrowserRequestArchive(DEPLOYMENT);
const RECORD_ID = `${DEPLOYMENT}:11155111:${VAULT}:7`;

async function freshWallet(options = {}, state = noteState()) {
    indexedDB.clear();
    const harness = createHarness(BrowserWalletRuntime, options);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await harness.runtime.reload();
    return harness;
}

function journalFor(state, clientRequestId, { requestTime = Math.floor(Date.now() / 1000), createdAt = Date.now() } = {}) {
    const nullifier = nullifierFor(state.current_anchor);
    const request = {
        client_request_id: clientRequestId,
        payload: JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: nativeQuote() }),
        payload_hash: '0xabc',
        public_inputs: { request_nullifier: nullifier, request_time: requestTime, solvency_bound: 1_000_000 },
        proof: { backend: 'groth16_bn254', proof: `request-proof-${clientRequestId}` }
    };
    return { exists: true, client_request_id: clientRequestId, nullifier, payload_hash: '0xabc',
        user_rerandomization: '0xfeed', created_at_ms: createdAt, prepared_request: request };
}

const pendingRecord = (state, clientRequestId, options = {}) => archive.buildRequestJournalRecord({
    deploymentId: DEPLOYMENT, state, journal: journalFor(state, clientRequestId), ...options
});

// A transmitted request whose stale_root the chain and the server both corroborate.
async function discardFirstRequest(h) {
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root', { latest_root: '0x78' });
    };
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'stale_root' });
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_stale_root');
    return record;
}

const withoutRetryDelays = runtime => {
    runtime.recoverStaleRootRequest = (request, error, onProgress, signal) =>
        BrowserWalletRuntime.prototype.recoverStaleRootRequest.call(runtime, request, error, onProgress, signal,
            { delays: [1, 1], sleep: async () => {} });
};

test('prepared request journal and its archive record commit atomically before transmission', async () => {
    const h = await freshWallet();
    let atPost = null;
    h.server.leasePost = async body => {
        atPost = { saved: await store.readBrowserWallet(), archived: await records(), body };
        return h.activeLease(body);
    };
    const lease = await h.runtime.issueLease('chat');
    assert.ok(atPost, 'the lease request reached the server');
    const { saved, archived, body } = atPost;
    assert.equal(saved.journal.client_request_id, lease.client_request_id);
    assert.deepEqual(saved.journal.prepared_request, body);
    assert.equal(archived.length, 1);
    assert.equal(archived[0].type, 'request_journal');
    assert.equal(archived[0].disposition, 'pending');
    assert.equal(archived[0].source, 'prepared');
    assert.deepEqual(archived[0].journal, saved.journal);
    assert.equal(archived[0].anchor, archive.feltKey(GENESIS_ANCHOR));
    assert.equal(archived[0].nullifier, archive.feltKey(nullifierFor(GENESIS_ANCHOR)));
    assert.equal(archived[0].createdAt, saved.journal.created_at_ms);
    assert.equal('state' in archived[0], false, 'archive records never hold the note state or secret');
});

test('stale_root is not trusted without server corroboration', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    h.server.leasePost = () => {
        h.chain.root = '0x78';
        throw new HttpError('The proof root is stale.', 409, 'stale_root', { latest_root: '0x78' });
    };
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.issueLease('chat'), error => error.code === 'stale_root'
        && error.journalRetained === true && error.nullifierStatus === 'reserved');
    const saved = await store.readBrowserWallet();
    assert.ok(saved.journal, 'an unsigned error string never discards the transmitted journal');
    const [record] = await records();
    assert.equal(record.disposition, 'pending');
    assert.deepEqual(archive.lastObservation(record), { ...archive.lastObservation(record), status: 'reserved', context: 'stale_root' });

    // A reserved request leaves the state unresolved (design §6.4 E3): a
    // mutual request waits for T and asks for no clearance; the lock it set
    // is released again because nothing was released.
    h.server.leaseStatus = () => ({ status: 'revoking' });
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), error =>
        error.code === 'request_settlement_pending' && error.data.escape_at > Date.now());
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    assert.equal(h.serverCalls('POST', '/v2/withdraw/clearance').length, 0);
    const kept = await store.readBrowserWallet();
    assert.ok(kept.journal);
    assert.equal(kept.exitLock, null);
});

test('corroborated stale_root discards the journal but never the archive; honest retry still works', async () => {
    const h = await freshWallet();
    const discarded = await discardFirstRequest(h);
    assert.equal((await store.readBrowserWallet()).journal, null);
    assert.equal(archive.lastObservation(discarded).status, 'unknown');
    assert.equal(archive.lastObservation(discarded).context, 'stale_root');
    assert.ok(discarded.journal.user_rerandomization, 'a discarded record keeps its rerandomization for a later receipt');
    assert.ok(h.chain.reads.includes('0xfdab463d'), 'the pinned vault root was read first');

    h.server.leasePost = body => h.activeLease(body);
    const lease = await h.runtime.issueLease('chat');
    assert.notEqual(lease.client_request_id, discarded.clientRequestId);
    const after = await records();
    assert.deepEqual(after.map(record => record.disposition).sort(), ['discarded_stale_root', 'pending']);
    assert.equal(new Set(after.map(record => record.anchor)).size, 1, 'the honest retry proves at the same note state');
});

test('a stale_root the pinned vault contradicts keeps the journal and retries the identical request', async () => {
    const h = await freshWallet();
    withoutRetryDelays(h.runtime);
    const bodies = [];
    h.server.leasePost = (body, raw) => {
        bodies.push(raw);
        if (bodies.length < 3) throw new HttpError('The proof root is stale.', 409, 'stale_root');
        return h.activeLease(body);
    };
    const lease = await h.runtime.issueLease('chat');
    assert.equal(bodies.length, 3);
    assert.ok(bodies.every(body => body === bodies[0]), 'the byte-identical request is retried');
    assert.equal(lease.client_request_id, JSON.parse(bodies[0]).client_request_id);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 0, 'the chain witness needs no server corroboration');

    const lagging = await freshWallet();
    withoutRetryDelays(lagging.runtime);
    lagging.server.leasePost = () => { throw new HttpError('The proof root is stale.', 409, 'stale_root'); };
    await assert.rejects(lagging.runtime.issueLease('chat'), error => error.code === 'stale_root'
        && error.journalRetained === true);
    assert.ok((await store.readBrowserWallet()).journal);
    assert.equal((await records())[0].disposition, 'pending');
    assert.equal(lagging.serverCalls('GET', '/v2/nullifiers/').length, 0);
});

test('a flagged nullifier read through the RPC only warns: the escape is still proved (E4.5)', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.chain.challenged.add(BigInt(nullifierFor(GENESIS_ANCHOR)));
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(h.workerOperations('prepareWithdrawal').length, 1, 'an advisory read never blocks');
    assert.deepEqual(plan.warnings.map(warning => [warning.code, warning.field]), [['nullifier_flagged', 'withdrawal_nullifier']]);
    // The discarded request is resolved-unreserved: the escape concedes nothing.
    assert.equal(plan.public_inputs.conceded, 0);
});

test('clearance_reserved discard is archived and leaves a withdrawal-only marker', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'clearance_reserved' });
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.preparedWithdrawal.phase, 'reserving');
    assert.equal(saved.preparedWithdrawal.mode, 'mutual');
    assert.equal(saved.preparedWithdrawal.clearanceReserved, true);
    assert.equal(saved.preparedWithdrawal.withdrawalNullifier, nullifierFor(GENESIS_ANCHOR),
        'the marker carries the current state’s own nullifier');
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_clearance_reserved');
    assert.equal(archive.lastObservation(record).status, 'clearance_reserved');
});

test('a later-finalized response completes from the archived rerandomization', async () => {
    const h = await freshWallet();
    const first = (await discardFirstRequest(h)).journal;
    h.server.leasePost = () => { throw new HttpError('Replay detected.', 409, 'replay'); };
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'replay' });
    const second = (await store.readBrowserWallet()).journal;
    assert.notEqual(second.client_request_id, first.client_request_id);

    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(first) });
    assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
    const [completion] = h.worker.completions;
    assert.equal(completion.journal.client_request_id, first.client_request_id);
    assert.equal(completion.journal.user_rerandomization, first.user_rerandomization);
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.state.current_anchor, '0x9999');
    assert.equal(saved.state.current_balance, 5_000_000 - 25_000);
    const byId = Object.fromEntries((await records()).map(record => [record.clientRequestId, record]));
    assert.equal(byId[first.client_request_id].disposition, 'installed');
    assert.equal(byId[first.client_request_id].installedNextAnchor, archive.feltKey('0x9999'));
    assert.equal(byId[second.client_request_id].disposition, 'superseded');
    for (const record of Object.values(byId)) {
        assert.equal(record.compacted, true);
        assert.equal(record.journal.prepared_request, undefined);
        assert.equal(record.journal.user_rerandomization, undefined);
    }
    assert.deepEqual(h.runtime.snapshot().config.unresolved_requests, []);
});

test('a receipt without a saved journal reports receipt_unrecoverable instead of a replay', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    const foreign = journalFor(noteState(), 'request-from-another-device');
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(foreign) });
    h.server.leasePost = body => h.activeLease(body);
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'receipt_unrecoverable',
        message: /its request journal is gone/ });
    assert.equal(h.workerOperations('prepareRequest').length, 1, 'no new request proof is made at a finalized state');
});

test('a state the server reports reserved never receives another request proof', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'request_settlement_pending' });
    assert.equal(h.workerOperations('prepareRequest').length, 1);
});

test('a failing archive sweep never blocks a new chat, and page load never sweeps', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    h.server.calls.length = 0;
    await h.runtime.recoverPending({ retireLostKey: true, quiet: true });
    assert.equal(h.server.calls.length, 0, 'startup recovery without a journal sends no nullifier to the server');
    h.server.nullifier = () => { throw new Error('network down'); };
    h.server.leasePost = body => h.activeLease(body);
    const lease = await h.runtime.issueLease('chat');
    assert.ok(lease.api_key);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 1, 'the user action swept once, quietly');
});

test('store refuses to drop an unarchived transmitted journal without a state install', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    const before = await store.readBrowserWallet();
    const { journal, state } = before;
    await assert.rejects(store.writeBrowserWallet({ ...before, journal: null }),
        error => error.code === 'request_journal_unarchived'
            && /archive records its outcome/.test(error.message));
    assert.deepEqual(await store.readBrowserWallet(), before, 'a rejected write changes nothing');
    await assert.rejects(store.writeBrowserWallet({ ...before,
        journal: { ...journal, client_request_id: 'replacement' } }), /archive records its outcome/);

    const discard = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state, journal,
        disposition: 'discarded_stale_root', observations: [archive.requestObservation('unknown', 'stale_root')] });
    const committed = await store.commitBrowserWallet({ ...before, journal: null }, { requestArchive: [discard] });
    assert.equal(committed.runtime.journal, null);
    assert.equal(committed.requestArchive.find(record => record.archiveId === discard.archiveId).disposition,
        'discarded_stale_root', 'the merged records come back from the same transaction');

    indexedDB.clear();
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal });
    await assert.rejects(store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: null }),
        /archive records its outcome/);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state: { ...state, current_anchor: '0x9999' }, journal: null });
    assert.equal((await store.readBrowserWallet()).journal, null, 'a verified install advances the state');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: { signedTransaction: 'legacy-shape' } });
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, state, journal: null });
});

test('an existing runtime journal migrates into the archive on first read, exempt from the bound', async () => {
    indexedDB.clear();
    const state = noteState();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) =>
        pendingRecord(state, `filler-${index}`)));
    const journal = journalFor(state, 'old-build-request');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state, journal });
    const before = await store.readBrowserWallet();
    const snapshot = await store.readBrowserWalletSnapshot(DEPLOYMENT);
    const migrated = snapshot.requestArchive.find(record => record.clientRequestId === 'old-build-request');
    assert.equal(migrated.source, 'migrated_runtime_journal');
    assert.equal(migrated.disposition, 'pending');
    assert.deepEqual(migrated.journal, journal);
    assert.equal(snapshot.requestArchive.filter(archive.isUnresolved).length, 17);
    assert.deepEqual(await store.readBrowserWallet(), before, 'the runtime slot is untouched');
    const h = createHarness(BrowserWalletRuntime);
    await h.runtime.reload();
    assert.equal(h.runtime.requestArchive.length, 17, 'reload never fails on the migration');
    assert.equal((await records()).length, 17, 'the migration is idempotent');
});

test('the per-state bound fails closed before proving, and eviction only sets expired corroborated discards aside', async () => {
    const h = await freshWallet();
    const state = noteState();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) => pendingRecord(state, `pending-${index}`)));
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'one-too-many')]),
        { code: 'request_archive_limit' });
    await h.runtime.reload();
    await assert.rejects(h.runtime.prepareLeaseRequest(), { code: 'request_archive_limit' });
    assert.equal(h.workerOperations('prepareRequest').length, 0, 'the bound is checked before proving');
    await store.putBrowserRequestArchive([pendingRecord(noteState({ current_anchor: '0x4321' }), 'other-state')]);

    indexedDB.clear();
    const requestTime = Math.floor(Date.now() / 1000) - 7_200;
    const late = requestTime * 1000 + 1_300_000;
    const discarded = (index, observedAt, {
        status = 'unknown', context = 'stale_root', disposition = 'discarded_stale_root'
    } = {}) => archive.buildRequestJournalRecord({
        deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, `stale-${index}`, { requestTime, createdAt: requestTime * 1000 + index }),
        disposition,
        observations: [archive.requestObservation(status, context, observedAt)]
    });
    await store.putBrowserRequestArchive([
        ...Array.from({ length: 15 }, (_, index) => discarded(index, requestTime * 1000 + 60_000)),
        discarded(15, late)
    ]);
    const merged = await store.putBrowserRequestArchive([pendingRecord(state, 'fresh')], { deploymentId: DEPLOYMENT });
    const evicted = merged.find(record => record.clientRequestId === 'stale-15');
    assert.equal(evicted.disposition, 'evicted');
    assert.ok(archive.isUnresolved(evicted) && !evicted.compacted && evicted.journal.user_rerandomization
        && evicted.journal.prepared_request, 'an evicted record keeps its full journal');
    assert.equal(merged.find(record => record.clientRequestId === 'stale-0').disposition, 'discarded_stale_root',
        'a discard observed inside the acceptance window is never evicted');
    assert.equal(merged.find(record => record.clientRequestId === 'fresh').disposition, 'pending');
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'again')]), { code: 'request_archive_limit' });

    // An /expire answer only echoes the request, so it never qualifies a
    // record for eviction, however late it was saved.
    indexedDB.clear();
    await store.putBrowserRequestArchive(Array.from({ length: 16 }, (_, index) => discarded(index, late,
        { status: 'unaccepted', context: 'recovery', disposition: 'discarded_expired_unaccepted' })));
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'after-unaccepted')]),
        { code: 'request_archive_limit' });

    // The hard ceiling counts evicted records: at 64 retained records nothing
    // more is set aside, and the next request is refused before proving.
    indexedDB.clear();
    await store.putBrowserRequestArchive([
        ...Array.from({ length: 47 }, (_, index) => discarded(100 + index, late, { disposition: 'evicted' })),
        ...Array.from({ length: 16 }, (_, index) => discarded(index, late))
    ]);
    const full = await store.putBrowserRequestArchive([pendingRecord(state, 'last-slot')], { deploymentId: DEPLOYMENT });
    assert.equal(full.length, archive.REQUEST_ARCHIVE_LIMITS.retainedPerAnchor);
    assert.equal(full.filter(record => record.disposition === 'evicted').length, 48);
    // Waiting helps only if the server settles one of them, and the refusal
    // says so instead of asking the user to wait.
    const atCeiling = error => {
        assert.equal(error.code, 'request_archive_limit');
        assert.match(error.message, /no new chat can start from it\. Chats resume only if the server settles one of them; otherwise withdraw this balance\./);
        assert.doesNotMatch(error.message, /Wait/);
        return true;
    };
    await assert.rejects(store.putBrowserRequestArchive([pendingRecord(state, 'beyond')]), atCeiling);
    assert.deepEqual(await records(), full, 'nothing is evicted or discarded at the ceiling');
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await h.runtime.reload();
    await assert.rejects(h.runtime.prepareLeaseRequest(), atCeiling);
    assert.equal(h.workerOperations('prepareRequest').length, 0);
});

test('an /expire answer is saved as unaccepted, never as a nullifier reading', async () => {
    const h = await freshWallet();
    h.server.leasePost = () => { throw new HttpError('Quote expired.', 409, 'native_quote_expired'); };
    h.server.expire = body => ({ status: 'expired_unaccepted', client_request_id: body.client_request_id,
        request_nullifier: body.public_inputs.request_nullifier, payload_hash: body.payload_hash });
    await assert.rejects(h.runtime.issueLease('chat'), { code: 'native_quote_expired' });
    const [record] = await records();
    assert.equal(record.disposition, 'discarded_expired_unaccepted');
    assert.ok(record.journal.user_rerandomization);
    assert.deepEqual(record.serverObservations.map(({ status, context }) => ({ status, context })),
        [{ status: 'unaccepted', context: 'recovery' }], 'the echo is not an unknown nullifier reading');
    assert.equal(archive.lastDefinitiveObservation(record), null);
    assert.equal(h.serverCalls('GET', '/v2/nullifiers/').length, 0, 'no nullifier was read on this path');
});

// The gateway rewriter of the journal-discard review: the honest server
// reserves the first request it sees at this state (J1) and later finalizes
// it, while every lease POST is rewritten to native_quote_expired, every
// /expire echoes the client's own identifiers and every nullifier read says
// unknown. Eviction must never cost J1 its private rerandomization.
{
    test('forged discards past the per-state cap never cost a reserved request its receipt', async t => {
        const h = await freshWallet();
        const realNow = Date.now;
        let elapsed = 0;
        t.mock.method(Date, 'now', () => realNow() + elapsed);
        let reserved = null;
        let rewriting = true;
        h.server.leasePost = body => {
            reserved ??= body;
            if (rewriting) throw new HttpError('Quote expired.', 409, 'native_quote_expired');
            return h.activeLease(body);
        };
        h.server.expire = body => ({ status: 'expired_unaccepted', client_request_id: body.client_request_id,
            request_nullifier: body.public_inputs.request_nullifier, payload_hash: body.payload_hash });
        h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
        const forgedDiscards = async count => {
            for (let chat = 0; chat < count; chat += 1) {
                await assert.rejects(h.runtime.issueLease('chat'), { code: 'native_quote_expired' });
            }
        };
        const dispositions = async () => Object.fromEntries((await records())
            .map(record => [record.clientRequestId, record.disposition]));

        await forgedDiscards(16);
        // 21 minutes later every discard looks expired and corroborated, so
        // the next chat evicts J1 from the per-state cap, not from the archive.
        elapsed = 21 * 60_000;
        await forgedDiscards(1);
        const evicted = (await records()).find(record => record.clientRequestId === reserved.client_request_id);
        assert.equal(evicted.disposition, 'evicted');
        assert.ok(archive.isUnresolved(evicted) && evicted.journal.user_rerandomization != null
            && evicted.journal.prepared_request, 'eviction keeps the full journal of a request at the current state');

        // Keep forging, 21 minutes apart, up to the hard per-state ceiling.
        await forgedDiscards(15);
        for (const minutes of [42, 63]) {
            elapsed = minutes * 60_000;
            await forgedDiscards(16);
        }
        const retained = await records();
        assert.equal(retained.length, archive.REQUEST_ARCHIVE_LIMITS.retainedPerAnchor);
        assert.equal(retained.filter(record => record.disposition === 'evicted').length, 48);
        assert.ok(retained.every(record => archive.isUnresolved(record)
            && record.journal.user_rerandomization != null && record.journal.prepared_request));
        const before = await dispositions();
        elapsed = 84 * 60_000;
        const proofs = h.workerOperations('prepareRequest').length;
        await assert.rejects(h.runtime.issueLease('chat'), { code: 'request_archive_limit' });
        assert.equal(h.workerOperations('prepareRequest').length, proofs, 'the ceiling refuses before proving');
        assert.deepEqual(await dispositions(), before, 'nothing is evicted or discarded at the ceiling');

        // The rewriter stops; the honest server finalizes J1 and reports it.
        rewriting = false;
        h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized',
            request_response: h.receiptFor({ client_request_id: reserved.client_request_id,
                nullifier: reserved.public_inputs.request_nullifier, prepared_request: reserved }) });
        const lease = await h.runtime.issueLease('chat');
        assert.deepEqual(h.worker.completions.map(completion => completion.journal.client_request_id),
            [reserved.client_request_id], 'the reserved request’s receipt installs from its evicted journal');
        const saved = await store.readBrowserWallet();
        assert.equal(saved.state.current_anchor, '0x9999');
        assert.equal(saved.state.current_balance, 5_000_000 - 25_000);
        assert.equal(saved.journal.client_request_id, lease.client_request_id, 'the next chat proves at the signed next state');
        const settled = (await records()).filter(record => record.anchor === archive.feltKey(GENESIS_ANCHOR));
        assert.equal(settled.length, 64);
        assert.ok(settled.every(record => record.compacted && !archive.isUnresolved(record)));
        assert.equal(settled.find(record => record.clientRequestId === reserved.client_request_id).disposition, 'installed');
    });
}

test('an evicted request still marks its state transmitted and installs its later receipt', async () => {
    const h = await freshWallet({}, noteState({ bound_at_state: 1_000_000 }));
    const state = noteState();
    const journal = journalFor(state, 'evicted');
    await store.putBrowserRequestArchive([archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
        journal, disposition: 'evicted' })]);
    await h.runtime.reload();
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'reserved' });
    // Unresolved (E3): a mutual request waits for T.
    await assert.rejects(h.runtime.prepareWithdrawal('mutual', DESTINATION), { code: 'request_settlement_pending' });
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    assert.deepEqual(h.runtime.snapshot().config.unresolved_requests.map(entry => [entry.disposition, entry.class]),
        [['evicted', 'unresolved']]);

    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal) });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'), 'the escape is at the signed next state');
    assert.equal(plan.public_inputs.conceded, 0, 'the next state is fresh');
    assert.equal(h.worker.completions[0].journal.user_rerandomization, journal.user_rerandomization);
    assert.equal((await records())[0].disposition, 'installed');
});

test('terminal records are compacted and pruned to 256 per deployment without touching note archives', async () => {
    indexedDB.clear();
    const state = noteState();
    indexedDB.stores.get('archives').set('note-archive', { archiveId: 'note-archive', reason: 'closed',
        deploymentId: DEPLOYMENT, state, archivedAt: 1 });
    await store.putBrowserRequestArchive([pendingRecord(state, 'unresolved')]);
    await store.putBrowserRequestArchive(Array.from({ length: 300 }, (_, index) => {
        const done = noteState({ current_anchor: `0x${(0x10000 + index).toString(16)}` });
        return archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state: done,
            journal: journalFor(done, `done-${index}`), disposition: 'superseded' });
    }));
    const all = await records();
    const done = all.filter(record => record.clientRequestId?.startsWith('done-'));
    assert.equal(done.length, 256);
    assert.ok(done.every(record => record.compacted && record.journal.prepared_request === undefined
        && record.journal.user_rerandomization === undefined));
    assert.equal(all.filter(archive.isUnresolved).length, 1, 'unresolved records are never pruned');
    assert.ok(indexedDB.stores.get('archives').has('note-archive'));
});

test('repeated evidence and a discarded migrated journal merge as partial patches', () => {
    const state = noteState();
    const evidence = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 7,
        anchor: state.current_anchor, nullifier: nullifierFor(state.current_anchor),
        evidence: { transactionHash: `0x${'ab'.repeat(32)}`, blockNumber: 10 }, now: 100 });
    const again = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 7,
        anchor: state.current_anchor, nullifier: nullifierFor(state.current_anchor), now: 200 });
    const merged = archive.mergeRequestArchiveRecord(evidence, again, 300);
    assert.equal(merged.createdAt, 100, 'the original createdAt is kept');
    assert.deepEqual(merged.sources, ['escape_challenged']);
    assert.equal(merged.evidence.blockNumber, 10);

    const migrated = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, 'migrated'), source: 'migrated_runtime_journal', now: 100 });
    const discard = archive.buildRequestJournalRecord({ deploymentId: DEPLOYMENT, state,
        journal: journalFor(state, 'migrated'), disposition: 'discarded_stale_root', now: 200 });
    const discarded = archive.mergeRequestArchiveRecord(migrated, discard, 300);
    assert.equal(discarded.source, 'migrated_runtime_journal');
    assert.equal(discarded.disposition, 'discarded_stale_root');
    const installed = archive.mergeRequestArchiveRecord(discarded,
        { archiveId: discarded.archiveId, disposition: 'installed', installedNextAnchor: word(9) }, 400);
    assert.equal(installed.disposition, 'installed');
    assert.equal(installed.journal.user_rerandomization, undefined, 'terminal compaction is exempt from identity rules');
    const late = archive.mergeRequestArchiveRecord(installed, { archiveId: installed.archiveId, disposition: 'pending' }, 500);
    assert.equal(late.disposition, 'installed', 'a disposition only moves forward');
    assert.throws(() => archive.mergeRequestArchiveRecord(migrated, { ...discard, nullifier: '0x1' }, 600),
        { code: 'request_archive_conflict' });
    const observations = Array.from({ length: 12 }, (_, index) => archive.requestObservation('unavailable', 'recovery', 1_000 + index));
    const bounded = archive.mergeRequestArchiveRecord(migrated, { archiveId: migrated.archiveId, serverObservations: observations }, 700);
    assert.equal(bounded.serverObservations.length, 8);
    assert.equal(bounded.serverObservations.at(-1).at, 1_011);
});

test('a receipt claim stands until a later unknown or clearance_reserved reading, and is never trimmed', () => {
    const state = noteState();
    const claim = (at, extra = { receipt: true }) => archive.requestObservation('finalized', 'escape', at, extra);
    const reading = (status, at) => archive.requestObservation(status, 'escape', at);
    const recordWith = (serverObservations, id = 'r') => ({ ...pendingRecord(state, id), serverObservations });
    const standing = (...records) => archive.standingReceiptClaim(records);

    assert.equal(standing(), null);
    assert.equal(standing(recordWith([reading('finalized', 1), reading('reserved', 2)])), null,
        'finalized without a receipt is no claim');
    assert.deepEqual(standing(recordWith([claim(1), reading('reserved', 2), reading('unavailable', 3),
        reading('finalized', 4), reading('unaccepted', 5)])), claim(1));
    assert.deepEqual(standing(recordWith([claim(1, { clientRequestId: 'named' })])), claim(1, { clientRequestId: 'named' }));
    for (const status of ['unknown', 'clearance_reserved']) {
        assert.equal(standing(recordWith([claim(1), reading(status, 2)])), null, `${status} contradicts the claim`);
        assert.deepEqual(standing(recordWith([reading(status, 1), claim(2)])), claim(2));
    }
    // Across the records of one state. These observations carry no save-order
    // stamp (as an older build saved them), so their times order them.
    assert.equal(standing(recordWith([claim(1)], 'a'), recordWith([reading('unknown', 2)], 'b')), null);
    assert.deepEqual(standing(recordWith([reading('unknown', 1)], 'a'), recordWith([claim(2)], 'b')), claim(2));

    // Trimming keeps the newest eight observations and, ahead of them, the
    // newest claim or contradicting reading: a standing claim is never trimmed.
    const base = recordWith([]);
    const failures = from => Array.from({ length: 12 }, (_, index) => reading('unavailable', from + index));
    const kept = archive.mergeRequestArchiveRecord(base,
        { archiveId: base.archiveId, serverObservations: [reading('unknown', 1), claim(2), ...failures(10)] }, 100);
    assert.equal(kept.serverObservations.length, 9);
    assert.deepEqual(kept.serverObservations[0], claim(2));
    assert.deepEqual(kept.serverObservations.slice(1).map(observation => observation.at), [14, 15, 16, 17, 18, 19, 20, 21]);
    const again = archive.mergeRequestArchiveRecord(kept, { archiveId: kept.archiveId, serverObservations: failures(30) }, 200);
    assert.deepEqual(again.serverObservations[0], claim(2), 'the claim keeps its place through later merges');
    assert.deepEqual(again.serverObservations.slice(1).map(observation => observation.at), [34, 35, 36, 37, 38, 39, 40, 41]);
    const ended = archive.mergeRequestArchiveRecord(base,
        { archiveId: base.archiveId, serverObservations: [claim(1), reading('unknown', 2), ...failures(10)] }, 300);
    assert.deepEqual(ended.serverObservations.map(observation => observation.at), [2, 14, 15, 16, 17, 18, 19, 20, 21],
        'a contradicted claim is trimmed, and the reading that contradicted it is kept');
    assert.equal(ended.serverObservations[0].status, 'unknown');
    assert.equal(archive.standingReceiptClaim([ended]), null);
});

// Round-3 review: the contradicting reading may be saved on one record only
// (the override's refusal, a stale_root or clearance_reserved discard). It
// must outlive trimming exactly as long as a claim on another record does.
test('a reading that ends a receipt claim on one record keeps it ended when both records are trimmed', () => {
    const state = noteState();
    const claim = at => archive.requestObservation('finalized', 'escape', at,
        { receipt: true, clientRequestId: 'not-held-by-this-browser' });
    const reading = (status, at) => archive.requestObservation(status, 'override', at);
    const merge = (record, serverObservations, at) =>
        archive.mergeRequestArchiveRecord(record, { archiveId: record.archiveId, serverObservations }, at);
    for (const status of ['unknown', 'clearance_reserved']) {
        let a = merge(pendingRecord(state, 'archived'), [claim(2_000)], 2_000);
        let b = merge(pendingRecord(state, 'live'), [claim(2_000), reading(status, 3_000)], 3_000);
        assert.equal(archive.standingReceiptClaim([a, b]), null);
        for (let index = 0; index < 12; index += 1) {
            const failed = [reading('unavailable', 4_000 + index)];
            a = merge(a, failed, 4_000 + index);
            b = merge(b, failed, 4_000 + index);
        }
        assert.deepEqual(a.serverObservations[0], claim(2_000), 'the claim still stands on its own record');
        assert.deepEqual(b.serverObservations[0], reading(status, 3_000), `the ${status} reading is kept`);
        assert.equal(archive.standingReceiptClaim([a, b]), null, `${status} still ends the claim`);
        assert.equal(archive.standingReceiptClaim([b, a]), null, 'in either record order');
        // A later claim on either record stands again.
        a = merge(a, [claim(5_000)], 5_000);
        assert.deepEqual(archive.standingReceiptClaim([a, b]), claim(5_000));
    }
});

// mulberry32: a 32-bit integer generator that draws from its high bits, so
// every bound is reached evenly.
function mulberry32(seed) {
    let state = seed | 0;
    return bound => {
        state = (state + 0x6d2b79f5) | 0;
        let mixed = Math.imul(state ^ (state >>> 15), 1 | state);
        mixed = (mixed + Math.imul(mixed ^ (mixed >>> 7), 61 | mixed)) ^ mixed;
        return Math.floor((((mixed ^ (mixed >>> 14)) >>> 0) / 4_294_967_296) * bound);
    };
}

// Saves observations on records[targets] as the store does in one write: each
// appended observation is stamped in save order over every record held, then
// merged. Returns the stamped observations, one list per target.
function saveObservations(records, targets, observations, now = 1_000) {
    const stamped = archive.sequenceObservationUpdates(records,
        targets.map(index => ({ archiveId: records[index].archiveId, serverObservations: observations })));
    targets.forEach((index, position) => {
        records[index] = archive.mergeRequestArchiveRecord(records[index], stamped[position], now);
    });
    return stamped.map(update => update.serverObservations);
}

test('the last save decides the standing claim, and trimming never changes it, the newest eight observations or the newest reading in them', () => {
    const state = noteState();
    const limit = archive.REQUEST_ARCHIVE_LIMITS.observationsPerRecord;
    const random = mulberry32(0x5eed);
    const kinds = [
        ['unavailable'], ['unaccepted'], ['reserved'], ['finalized'],
        ['finalized', { receipt: true }], ['finalized', { clientRequestId: 'foreign' }],
        ['unknown'], ['clearance_reserved']
    ];
    // The kinds that neither make nor end a receipt claim.
    const quiet = [0, 1, 2, 3];
    const contexts = ['escape', 'override', 'recovery', 'stale_root', 'clearance'];
    const decisive = observation => archive.isReceiptClaim(observation)
        || ['unknown', 'clearance_reserved'].includes(observation.status);
    const key = observation => [observation.status, observation.context, observation.at, observation.seq,
        observation.receipt, observation.clientRequestId].join('|');
    const sameReading = (left, right, message) => assert.deepEqual(left ?? null, right ?? null, message);
    const seen = { all: 0, one: 0, subset: 0, multiple: 0, joined: 0, legacy: 0, earlier: 0, multiRecord: 0,
        standing: 0, ended: 0, endedElsewhere: 0, clockDisagrees: 0, pinned: 0 };
    const drawn = kinds.map(() => 0);
    for (let sequence = 0; sequence < 300; sequence += 1) {
        const maxRecords = 1 + random(4);
        const trimmed = [];      // what the store keeps
        const full = [];         // every observation each record was given
        const saves = [];        // every stamped save, in save order
        // A quarter of the sequences begin with observations an older build
        // saved without a stamp; they order before every stamped one.
        let legacySteps = random(4) === 0 ? 1 + random(20) : 0;
        // During an outage most reads fail or decide nothing, which pushes the
        // deciding reading out of a record's newest eight.
        let outage = false;
        let at = 1_000;
        const make = () => {
            const kind = outage && random(8) ? quiet[random(quiet.length)] : random(kinds.length);
            drawn[kind] += 1;
            const [status, extra = {}] = kinds[kind];
            return archive.requestObservation(status, contexts[random(contexts.length)], at, extra);
        };
        const apply = (targets, observations) => {
            if (legacySteps > 0) {
                for (const index of targets) {
                    trimmed[index] = archive.mergeRequestArchiveRecord(trimmed[index],
                        { archiveId: trimmed[index].archiveId, serverObservations: observations }, at);
                    full[index].push(...observations);
                    seen.legacy += observations.length;
                }
                return;
            }
            saveObservations(trimmed, targets, observations, at).forEach((stamped, position) => {
                full[targets[position]].push(...stamped);
                saves.push(...stamped.map(observation => ({ index: targets[position], observation })));
            });
        };
        const join = initial => {
            trimmed.push(pendingRecord(state, `r${trimmed.length}`));
            full.push([]);
            if (initial.length) apply([trimmed.length - 1], initial);
        };
        join([]);
        for (let step = 0; step < 60; step += 1) {
            // The clock: mostly later, sometimes the same millisecond, often
            // earlier, and now and then far back (a fast clock corrected).
            const move = random(10);
            const before = at;
            at = Math.max(1, move < 5 ? at + 1 + random(40) : move < 6 ? at
                : move < 9 ? at - 1 - random(40) : at - 1 - random(5_000));
            if (at < before) seen.earlier += 1;
            if (random(6) === 0) outage = !outage;
            if (trimmed.length < maxRecords && random(8) === 0) {
                // A record that joins the state late, sometimes with its own first observation.
                seen.joined += 1;
                join(random(3) === 0 ? [make()] : []);
            } else {
                const observations = Array.from({ length: random(6) === 0 ? 2 + random(3) : 1 }, make);
                if (observations.length > 1) seen.multiple += 1;
                // Saved on every record (a sweep or a gate), on one (a refusal or
                // a discard) or on some.
                const mode = random(3);
                const targets = mode === 0 ? trimmed.map((_, index) => index)
                    : mode === 1 ? [random(trimmed.length)]
                        : trimmed.map((_, index) => index).filter(() => random(2));
                seen[['all', 'one', 'subset'][mode]] += 1;
                apply(targets, observations);
            }
            if (legacySteps > 0) legacySteps -= 1;

            // Any record order: the store returns key order, memory may differ.
            const order = trimmed.map((_, index) => index);
            for (let index = order.length - 1; index > 0; index -= 1) {
                const other = random(index + 1);
                [order[index], order[other]] = [order[other], order[index]];
            }
            const standing = archive.standingReceiptClaim(order.map(index => trimmed[index]));
            sameReading(standing, archive.standingReceiptClaim(order.map(index => ({ serverObservations: full[index] }))),
                'trimming never changes the standing claim');
            // Save order decides, never the clock: the last claim or
            // contradicting reading saved with a stamp, on any record.
            const last = saves.findLast(save => decisive(save.observation));
            if (last) {
                const expected = archive.isReceiptClaim(last.observation) ? last.observation : null;
                sameReading(standing, expected, 'the reading saved last decides');
                const byClock = order.flatMap(index => full[index]).filter(decisive)
                    .sort((left, right) => left.at - right.at).at(-1);
                if (archive.isReceiptClaim(byClock) !== Boolean(expected)) seen.clockDisagrees += 1;
                if (!expected) {
                    seen.ended += 1;
                    // A claim still newest on another record than the one that ended it.
                    if (full.some((all, index) => index !== last.index && archive.isReceiptClaim(all.findLast(decisive)))) {
                        seen.endedElsewhere += 1;
                    }
                }
            }
            if (standing) seen.standing += 1;
            if (trimmed.length > 1) seen.multiRecord += 1;

            trimmed.forEach((record, index) => {
                const kept = record.serverObservations;
                const all = full[index];
                assert.ok(kept.length <= limit + 1, 'at most nine observations');
                assert.deepEqual(kept.slice(-limit), all.slice(-limit), 'the newest eight are never displaced');
                let cursor = 0;
                for (const observation of kept) {
                    while (cursor < all.length && key(all[cursor]) !== key(observation)) cursor += 1;
                    assert.ok(cursor < all.length, 'kept observations stay in order');
                    cursor += 1;
                }
                // Ahead of the newest eight: exactly the record's newest claim
                // or contradicting reading in save order, when it is older.
                if (all.every(observation => observation.seq)) {
                    const newest = all.findLast(decisive);
                    const inWindow = newest && all.slice(-limit).includes(newest);
                    assert.equal(kept.length, all.length > limit && newest && !inWindow ? limit + 1 : Math.min(all.length, limit));
                    if (kept.length > limit) {
                        assert.deepEqual(kept[0], newest, 'the kept older observation is the newest claim or contradiction');
                        seen.pinned += 1;
                    }
                }
                // The newest nullifier reading among the newest eight, else
                // only the kept claim or contradicting reading.
                const window = archive.lastDefinitiveObservation({ serverObservations: all.slice(-limit) });
                const newestReading = archive.lastDefinitiveObservation(record);
                if (window) sameReading(newestReading, window);
                else assert.ok(newestReading == null || newestReading === kept[0]);
            });
        }
    }
    // The generator reaches every case this test claims to cover (about half
    // of what this seed gives), so a degenerate generator fails here.
    const minimums = { all: 3_000, one: 3_000, subset: 3_000, multiple: 1_500, joined: 200, legacy: 600,
        earlier: 3_000, multiRecord: 6_000, standing: 4_000, ended: 4_000, endedElsewhere: 900,
        clockDisagrees: 3_000, pinned: 1_500 };
    for (const [name, minimum] of Object.entries(minimums)) {
        assert.ok(seen[name] >= minimum, `${name}: ${seen[name]} < ${minimum}`);
    }
    drawn.forEach((count, kind) => assert.ok(count >= 800, `${JSON.stringify(kinds[kind])} drawn ${count} times`));
});

// Round-4 review: only a receipt claim or a reading that ends one is kept
// ahead of the newest eight, never a later receipt-less 'finalized' or
// 'reserved' reading.
test('a receipt-less finalized or a reserved reading after a contradiction never takes its place', () => {
    const state = noteState();
    const claim = at => archive.requestObservation('finalized', 'escape', at,
        { receipt: true, clientRequestId: 'not-held-by-this-browser' });
    const reading = (status, at) => archive.requestObservation(status, 'override', at);
    for (const contradiction of ['unknown', 'clearance_reserved']) {
        for (const later of ['finalized', 'reserved']) {
            const records = [pendingRecord(state, 'archived'), pendingRecord(state, 'live')];
            saveObservations(records, [0, 1], [claim(2_000)]);
            // The claim is ended on the live record alone, which then reads a
            // receipt-less 'finalized' or 'reserved' before eight failed reads.
            const [[ended]] = saveObservations(records, [1], [reading(contradiction, 3_000)]);
            saveObservations(records, [1], [reading(later, 3_001)]);
            for (let index = 0; index < 8; index += 1) {
                saveObservations(records, [0, 1], [reading('unavailable', 4_000 + index)]);
            }
            const [archived, live] = records;
            assert.ok(archive.isReceiptClaim(archived.serverObservations[0]), 'the claim stays on its own record');
            assert.equal(live.serverObservations.length, archive.REQUEST_ARCHIVE_LIMITS.observationsPerRecord + 1);
            assert.deepEqual(live.serverObservations[0], ended, `the ${contradiction} reading is kept, not ${later}`);
            assert.ok(live.serverObservations.slice(1).every(observation => observation.status === 'unavailable'));
            assert.equal(archive.standingReceiptClaim(records), null, `${contradiction} still ends the claim`);
            assert.equal(archive.standingReceiptClaim([live, archived]), null, 'in either record order');
        }
    }
});

// Round-4 review: a clock that ran fast or stepped back must not reorder a
// claim and the reading that ends it.
test('save order, not the device clock, decides whether a receipt claim stands', () => {
    const state = noteState();
    const NOW = 1_700_000_000_000;
    const FAST = NOW + 3 * 86_400_000;
    const limit = archive.REQUEST_ARCHIVE_LIMITS.observationsPerRecord;
    const claim = at => archive.requestObservation('finalized', 'escape', at,
        { receipt: true, clientRequestId: 'not-held-by-this-browser' });
    const reading = (status, at) => archive.requestObservation(status, 'stale_root', at);

    // The stamp is one above every saved one, in update and array order. A
    // stamp an update carries is replaced, `at` is kept, and a patch without
    // observations is left alone. Only a positive integer is a stamp.
    const held = [{ serverObservations: [{ ...reading('unknown', NOW), seq: 41 }, reading('unavailable', NOW)] }, {}];
    assert.equal(archive.highestObservationSeq(held), 41);
    assert.equal(archive.highestObservationSeq([]), 0);
    const patch = { archiveId: 'patch', disposition: 'superseded' };
    const stamped = archive.sequenceObservationUpdates(held, [
        { archiveId: 'a', serverObservations: [reading('unknown', FAST), { ...claim(NOW), seq: 7 }] },
        patch,
        { archiveId: 'b', serverObservations: [reading('unavailable', 1)] }
    ]);
    assert.deepEqual(stamped[0].serverObservations.map(observation => [observation.seq, observation.at]),
        [[42, FAST], [43, NOW]]);
    assert.equal(stamped[1], patch);
    assert.deepEqual(stamped[2].serverObservations.map(observation => observation.seq), [44]);
    for (const seq of [0, -1, 1.5, '2x', null]) {
        assert.equal(archive.requestObservation('unknown', 'escape', NOW, { seq }).seq, undefined);
    }
    assert.equal(archive.requestObservation('unknown', 'escape', NOW, { seq: 3 }).seq, 3);

    // 'unknown' saved while the clock ran fast, then a claim saved after the
    // clock was corrected: the claim stands at once, across two records ...
    const pair = [pendingRecord(state, 'archived'), pendingRecord(state, 'live')];
    saveObservations(pair, [1], [reading('unknown', FAST)]);
    const [[across]] = saveObservations(pair, [0], [claim(NOW)]);
    assert.deepEqual(archive.standingReceiptClaim(pair), across);
    // ... and on one record, where it is kept ahead of the newest eight
    // instead of the fast-dated reading.
    const single = [pendingRecord(state, 'single')];
    saveObservations(single, [0], [reading('unknown', FAST)]);
    const [[own]] = saveObservations(single, [0], [claim(NOW)]);
    assert.deepEqual(archive.standingReceiptClaim(single), own);
    for (let index = 0; index < limit; index += 1) saveObservations(single, [0], [reading('unavailable', NOW + index)]);
    assert.equal(single[0].serverObservations.length, limit + 1);
    assert.deepEqual(single[0].serverObservations[0], own);
    assert.deepEqual(archive.standingReceiptClaim(single), own);
    // A reading saved after the claim ends it, although its clock is behind.
    saveObservations(single, [0], [reading('clearance_reserved', NOW - 86_400_000)]);
    assert.equal(archive.standingReceiptClaim(single), null);
    saveObservations(pair, [1], [reading('unknown', NOW - 86_400_000)]);
    assert.equal(archive.standingReceiptClaim(pair), null);

    // An older build saved no stamp: its observations come before every
    // stamped one, by time among themselves.
    const legacy = observations => ({ ...pendingRecord(state, 'legacy'), serverObservations: observations });
    const later = observation => ({ ...pendingRecord(state, 'stamped'), serverObservations: [{ ...observation, seq: 1 }] });
    assert.equal(archive.standingReceiptClaim([legacy([claim(FAST)]), later(reading('unknown', NOW))]), null);
    assert.deepEqual(archive.standingReceiptClaim([legacy([reading('unknown', FAST)]), later(claim(NOW))]),
        { ...claim(NOW), seq: 1 });
    assert.deepEqual(archive.standingReceiptClaim([legacy([reading('unknown', NOW), claim(NOW + 1)])]), claim(NOW + 1));
    assert.equal(archive.standingReceiptClaim([legacy([claim(NOW), reading('unknown', NOW + 1)])]), null);
    const otherLegacy = observations => ({ ...pendingRecord(state, 'other-legacy'), serverObservations: observations });
    assert.deepEqual(archive.standingReceiptClaim([legacy([claim(NOW + 1)]), otherLegacy([reading('unknown', NOW)])]),
        claim(NOW + 1), 'by time across records, whatever their order');
    assert.equal(archive.standingReceiptClaim([otherLegacy([reading('unknown', NOW + 1)]), legacy([claim(NOW)])]), null);
    // Stamped observations appended to such a record keep its claim ahead of
    // the newest eight, not the older build's fast-dated reading.
    const upgraded = [legacy([reading('unknown', FAST)])];
    const [[upgradedClaim]] = saveObservations(upgraded, [0], [claim(NOW)]);
    for (let index = 0; index < limit; index += 1) saveObservations(upgraded, [0], [reading('unavailable', NOW + index)]);
    assert.deepEqual(upgraded[0].serverObservations[0], upgradedClaim);
    assert.deepEqual(archive.standingReceiptClaim(upgraded), upgradedClaim);
});

test('the store stamps every saved observation in save order, across records and writes', async t => {
    indexedDB.clear();
    const state = noteState();
    const [archived, live] = ['archived', 'live'].map(id => pendingRecord(state, id));
    await store.putBrowserRequestArchive([archived, live]);
    const realNow = Date.now();
    const fast = realNow + 3 * 86_400_000;
    let clock = fast;
    t.mock.method(Date, 'now', () => clock);
    const save = (record, observation) => store.putBrowserRequestArchive([{
        archiveId: record.archiveId, serverObservations: [observation]
    }]);
    // The live record reads three failures and then 'unknown' while the clock
    // runs fast; the last update carries a stamp of its own.
    for (let index = 0; index < 3; index += 1) {
        await save(live, archive.requestObservation('unavailable', 'escape', fast + index));
    }
    await save(live, { ...archive.requestObservation('unknown', 'stale_root', fast + 3), seq: 1_000_000 });
    // The clock is corrected, and the archived record saves a receipt claim.
    clock = realNow;
    await save(archived, archive.requestObservation('finalized', 'escape', realNow,
        { receipt: true, clientRequestId: 'not-held-by-this-browser' }));
    let saved = await records();
    const byId = id => saved.find(record => record.clientRequestId === id);
    assert.deepEqual(byId('live').serverObservations.map(observation => [observation.seq, observation.at]),
        [[1, fast], [2, fast + 1], [3, fast + 2], [4, fast + 3]], 'a carried stamp is replaced and `at` is kept');
    assert.deepEqual(byId('archived').serverObservations.map(observation => observation.seq), [5]);
    assert.equal(archive.standingReceiptClaim(saved)?.seq, 5, 'the claim saved last stands although its clock is behind');
    // One write that saves a reading on both records stamps each copy in
    // turn. Saved after the claim, it ends it, although its clock is behind.
    clock = realNow - 60_000;
    await store.putBrowserRequestArchive([archived, live].map(record => ({
        archiveId: record.archiveId, serverObservations: [archive.requestObservation('unknown', 'escape', clock)]
    })));
    saved = await records();
    assert.deepEqual([byId('archived'), byId('live')].map(record => record.serverObservations.at(-1).seq), [6, 7]);
    assert.equal(archive.standingReceiptClaim(saved), null);
});

test('worst-case and clamped receipts install with their proof-bound quote after a manifest pin change', async () => {
    for (const basis of ['worst_case', 'clamped']) {
        const h = await freshWallet();
        await h.runtime.prepareLeaseRequest();
        const journal = (await store.readBrowserWallet()).journal;
        const bound = journal.prepared_request.public_inputs.solvency_bound;
        h.runtime.config.funding = { ...h.runtime.config.funding, native_price_max_age_seconds: 4_500 };
        h.server.leaseStatus = () => ({ status: 'finalized' });
        h.server.requests = () => ({ request_response: h.receiptFor(journal, {
            billingQuote: { ...h.quote, answer: '200000000000' } }) });
        await assert.rejects(h.runtime.recoverPending({ retireLostKey: true }), /changed the authorized/);
        const charge = basis === 'worst_case' ? bound : bound - 1;
        h.server.requests = () => ({ request_response: h.receiptFor(journal, { charge,
            payload: { charge_basis: basis, ...(basis === 'worst_case' ? { settlement_reason: 'settlement_deadline' } : {}) } }) });
        assert.equal(await h.runtime.recoverPending({ retireLostKey: true }), true);
        assert.equal((await store.readBrowserWallet()).state.current_balance, 5_000_000 - charge);
        const settlement = h.runtime.snapshot().config.last_settlement;
        assert.equal(settlement.charge_basis, basis);
        assert.equal(settlement.charge_applied, charge);
        assert.equal(settlement.settlement_reason, basis === 'worst_case' ? 'settlement_deadline' : null);
    }
});

test('a journaled request made under older price pins settles unused instead of failing', async () => {
    const h = await freshWallet();
    await h.runtime.prepareLeaseRequest();
    const journal = (await store.readBrowserWallet()).journal;
    const newFunding = { ...h.runtime.config.funding, native_price_max_age_seconds: 4_500 };
    h.runtime.config.funding = newFunding;
    h.runtime.nativeBillingQuote = async () => nativeQuote(newFunding);
    const verified = [];
    h.runtime.verifyLease = async (...args) => { verified.push(args); };
    h.server.leasePost = body => h.activeLease(body);
    h.server.leaseStatus = () => { throw new HttpError('Not found', 404, 'not_found'); };
    h.server.requests = id => {
        assert.equal(id, journal.client_request_id);
        return { request_response: h.receiptFor(journal, { charge: 0 }) };
    };
    const lease = await h.runtime.issueLease('chat');
    assert.notEqual(lease.client_request_id, journal.client_request_id, 'the old-pin key is never exposed');
    assert.deepEqual(verified[0][6], { proofBoundQuote: true });
    assert.equal(verified[0][2], journal.client_request_id);
    assert.equal(h.runtime.activeLease.client_request_id, lease.client_request_id);
});

test('restored defeated escape records evidence: this device is not the newest until a receipt moves it on', async () => {
    const h = await freshWallet();
    const first = (await discardFirstRequest(h)).journal;
    const state = (await store.readBrowserWallet()).state;
    const nullifier = nullifierFor(state.current_anchor);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null });
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'escape', phase: 'restored', chainStatus: 'active',
        destination: DESTINATION, finalBalance: state.current_balance, state, withdrawalNullifier: nullifier,
        startBlockNumber: 100, challengeEvidence: { noteId: 7, nullifier: word(nullifier),
            transactionHash: `0x${'cd'.repeat(32)}`, blockNumber: 120, finalizedBlock: 200, observedAt: 1 } });
    const background = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
    await store.restoreBrowserWithdrawal(RECORD_ID, { deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT }, background.revision);
    const evidence = (await records()).find(record => record.type === 'request_evidence');
    assert.equal(evidence.anchor, archive.feltKey(state.current_anchor));
    assert.deepEqual(evidence.sources, ['escape_challenged']);
    assert.equal(evidence.evidence.transactionHash, `0x${'cd'.repeat(32)}`);

    await h.runtime.reload();
    h.server.nullifier = () => ({ status: 'not_found', nullifier_status: 'unknown' });
    // A defeat needs a request from this state's successor: another device
    // spent it (design §6.4 E5). Neither exit is attempted from here.
    for (const mode of ['escape', 'mutual']) {
        await assert.rejects(h.runtime.prepareWithdrawal(mode, DESTINATION), { code: 'device_not_newest' });
    }
    assert.equal(h.workerOperations('prepareWithdrawal').length, 0);
    assert.equal(h.serverCalls('POST', '/v2/withdraw/clearance').length, 0);
    assert.equal(h.runtime.snapshot().config.exit.device_not_newest, true);

    // This device's own earlier request settles: E1 installs its receipt and
    // the escape is made from the signed next state.
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), exitLock: null });
    await h.runtime.reload();
    h.server.nullifier = () => ({ status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(first) });
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.public_inputs.withdrawal_nullifier, nullifierFor('0x9999'));
    assert.equal((await records()).find(record => record.type === 'request_evidence').disposition, 'superseded');
});

test('challenge evidence is never inferred from a reorged-out start, another nullifier or a canceled transaction', async () => {
    const h = await freshWallet({ vaultRevision: 2 });
    const state = (await store.readBrowserWallet()).state;
    const nullifier = nullifierFor(state.current_anchor);
    for (const challengeEvidence of [undefined, { noteId: 7, nullifier: word('0x1'), blockNumber: 120 },
        { noteId: 8, nullifier: word(nullifier), blockNumber: 120 }]) {
        await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null });
        await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
            contractAddress: VAULT, noteId: 7, mode: 'escape', phase: 'restored', chainStatus: 'active',
            destination: DESTINATION, finalBalance: state.current_balance, state, withdrawalNullifier: nullifier,
            startBlockNumber: 100, ...(challengeEvidence ? { challengeEvidence } : {}) });
        const background = (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
        await store.restoreBrowserWithdrawal(RECORD_ID, { deploymentId: DEPLOYMENT, chainId: 11155111,
            contractAddress: VAULT }, background.revision);
        assert.equal((await records()).length, 0);
    }

    await h.runtime.reload();
    const attempt = { operationId: 'late', transactionHash: `0x${'ef'.repeat(32)}`, noteId: 7, mode: 'escape',
        clearanceReserved: true, withdrawalNullifier: nullifier, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, destination: DESTINATION, status: 'submitted_late', observedAt: 1 };
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), lateWithdrawalAttempts: [attempt] });
    await h.runtime.resolveLateChallengedWithdrawalAttempt(attempt);
    assert.equal((await records()).length, 0, 'a replaced or canceled late transaction is not challenge evidence');

    const client = new ZkapiClient();
    client.config = { funding: { contract_address: VAULT, chain_id: 11155111 } };
    const topic = keccak256Hex('EscapeWithdrawalChallenged(uint32,uint256,uint256)');
    assert.equal(walletCodec.ABI.escapeChallengedEvent, topic);
    const challenged = { address: VAULT, topics: [topic, word(7)], data: `${word(nullifier)}${word(1).slice(2)}`,
        blockNumber: '0x78', transactionHash: `0x${'cd'.repeat(32)}`, removed: false };
    let logs = [challenged];
    const queries = [];
    client.setWalletProvider({ request: async ({ method, params }) => {
        assert.equal(method, 'eth_getLogs');
        queries.push(params[0]);
        return logs;
    } });
    const record = { mode: 'escape', noteId: 7, withdrawalNullifier: nullifier, startBlockNumber: 100 };
    const found = await client.finalizedEscapeChallenge(record, 200);
    assert.deepEqual({ ...found, observedAt: 0 }, { noteId: 7, nullifier: word(nullifier),
        transactionHash: `0x${'cd'.repeat(32)}`, blockNumber: 120, finalizedBlock: 200, observedAt: 0 });
    assert.deepEqual(queries[0], { address: VAULT, topics: [topic, word(7)], fromBlock: '0x64', toBlock: '0xc8' });
    for (const variant of [[], [{ ...challenged, data: `${word('0x1')}${word(1).slice(2)}` }],
        [{ ...challenged, removed: true }], [{ ...challenged, blockNumber: '0x12c' }],
        [{ ...challenged, address: `0x${'99'.repeat(20)}` }], [{ ...challenged, topics: [topic, word(8)] }]]) {
        logs = variant;
        assert.equal(await client.finalizedEscapeChallenge(record, 200), null);
    }
    client.setWalletProvider({ request: async () => { throw new Error('log range too large'); } });
    assert.equal(await client.finalizedEscapeChallenge(record, 200), null);
    assert.equal(await client.finalizedEscapeChallenge({ ...record, mode: 'mutual' }, 200), null);
});

test('closing or sanitizing a note supersedes its transmitted requests', async () => {
    const h = await freshWallet();
    await discardFirstRequest(h);
    await store.archiveBrowserWallet('withdrawn', 7);
    const [closed] = await records();
    assert.equal(closed.disposition, 'superseded');
    assert.equal(closed.journal.user_rerandomization, undefined);

    indexedDB.clear();
    const state = noteState();
    await store.putBrowserRequestArchive([pendingRecord(state, 'background-note'),
        pendingRecord(noteState({ note_id: 8 }), 'another-note')]);
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT, chainId: 11155111,
        contractAddress: VAULT, noteId: 7, mode: 'mutual', phase: 'closed_unconfirmed', destination: DESTINATION,
        state, finalBalance: 1 });
    await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'closed', chainStatus: 'closed' }, { sanitize: true });
    const byId = Object.fromEntries((await records()).map(record => [record.clientRequestId, record]));
    assert.equal(byId['background-note'].disposition, 'superseded');
    assert.equal(byId['another-note'].disposition, 'pending');
});

// Byte-for-byte copies of sdk/services/browserWalletStore.js at 045b444 (the
// last build without the request archive) and of the one module it imports,
// vendored so this check never depends on git history.
const LEGACY_STORE_FIXTURE = new URL('./fixtures/legacy-store-045b444/', import.meta.url);
const LEGACY_STORE_SHA256 = Object.freeze({
    'browserWalletStore.js': 'c27189f8d0ff66c00a6bf10b1c743c2449eeae0a2ead8ef513556026527cb3a9',
    'zkapiWithdrawalRecovery.mjs': '4d54c9f44d9674631edf8e84a7db7e266d23492f6302820322ef8fbd21151d05'
});

test('old-build compatibility: request records leave deposit history and note archives unchanged', async () => {
    indexedDB.clear();
    const state = noteState();
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    assert.ok(indexedDB.versions.length > 0 && indexedDB.versions.every(version => version === 3),
        'the shared database version is never bumped');
    const baseline = (await store.readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    const evidence = archive.buildRequestEvidenceRecord({ deploymentId: DEPLOYMENT, noteId: 9,
        anchor: '0x99', nullifier: nullifierFor('0x99') });
    await store.putBrowserRequestArchive([pendingRecord(state, 'compat-request'), evidence]);
    assert.deepEqual((await store.readBrowserWalletSnapshot(DEPLOYMENT)).deposits, baseline);
    assert.equal(indexedDB.stores.get('deposits').size, baseline.length);

    // A missing or edited fixture fails here; it is never skipped.
    for (const [file, sha256] of Object.entries(LEGACY_STORE_SHA256)) {
        const bytes = await readFile(new URL(file, LEGACY_STORE_FIXTURE));
        assert.equal(createHash('sha256').update(bytes).digest('hex'), sha256, `${file} is the frozen 045b444 copy`);
    }
    const legacy = await import(new URL('browserWalletStore.js', LEGACY_STORE_FIXTURE).href);
    assert.deepEqual((await legacy.readBrowserWalletSnapshot(DEPLOYMENT)).deposits, baseline);
    await legacy.archiveBrowserWallet('closed', 7);
    const after = await records();
    assert.equal(after.length, 2, 'an older build never rewrites or drops request records');
    assert.ok(after.every(record => archive.isUnresolved(record)));
    assert.deepEqual((await legacy.readBrowserWalletSnapshot(DEPLOYMENT)).deposits.map(row => row.noteId),
        baseline.map(row => row.noteId));
});

test('a failing automatic settlement backs off instead of polling every two seconds', async t => {
    t.mock.timers.enable({ apis: ['setTimeout'] });
    const runtime = new BrowserWalletRuntime();
    runtime.activeLease = { settle_after: 0, inFlight: 0 };
    const delays = [];
    const schedule = runtime.scheduleSettlement.bind(runtime);
    runtime.scheduleSettlement = delay => { delays.push(delay); return schedule(delay); };
    runtime.retireActiveLease = async () => { throw new Error('settlement unavailable'); };
    runtime.scheduleSettlement(0);
    for (let round = 0; round < 7; round += 1) {
        t.mock.timers.tick(delays.at(-1));
        await new Promise(resolve => setImmediate(resolve));
    }
    assert.deepEqual(delays, [0, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000]);
    runtime.activeLease = null;
    t.mock.timers.tick(60_000);
});

test('capabilities come only from the build-pinned trust anchor: vault revision 3, required ownership proofs', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { vault_revision: 2, clearance_ownership_proof: 'optional' };
    runtime.browserConfig = { trusted_deployment: {} };
    assert.deepEqual(runtime.vaultCapabilities(), { vaultRevision: 3, exitConcession: true, payoutCredits: true,
        sendOwnershipProof: true });

    const config = deployedProfile();
    const funding = nativeFunding();
    const trusted = { ...config.trusted_deployment, ...funding, rpc_url: funding.demo_rpc_url, billing_token_address: null };
    const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
        proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
            withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
        privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
    runtime.browserConfig = { ...config, trusted_deployment: trusted };
    assert.doesNotThrow(() => runtime.validateManifestTrust(manifest));
    // A served manifest cannot change them: only the pinned profile counts.
    assert.doesNotThrow(() => runtime.validateManifestTrust({ ...manifest, vault_revision: 2, clearance_ownership_proof: 'optional' }));
    for (const change of [{ vault_revision: 0 }, { vault_revision: '3' }, { vault_revision: 2 },
        { clearance_ownership_proof: 'always' }, { clearance_ownership_proof: 'optional' }]) {
        runtime.browserConfig = { ...config, trusted_deployment: { ...trusted, ...change } };
        assert.throws(() => runtime.validateManifestTrust(manifest), /invalid trusted/, JSON.stringify(change));
    }
});
