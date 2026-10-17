// Activation (vault revision 4): a deposit only records its note, and a
// later NotesActivated batch puts the note's leaf in the request tree. A
// confirmed note can exit at once but proves requests only once activated
// (noteId < activationCursor()). Over the real runtime and store: the
// request path refuses an unactivated note with note_not_activated and its
// queue position, the snapshot reports the activation, the client waits a
// bounded time for it (longer while the queue moves, not at all while the
// vault is paused), and a deposit's slot is predicted from nextNoteId().
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, createHarness, memoryIndexedDb, noteState, within
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');

const INDEXER = 'https://indexer.example';
const NOTE_ID = 7;
const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;

/**
 * The harness's wallet with note 7, the real request path (treePath) over a
 * scripted indexer snapshot, and the vault's activationCursor() from the
 * harness chain. The indexer serves only the tree for parts=tree, as a
 * current one does (`indexer.honorsParts`), or everything, as an older one.
 */
async function wallet({ indexerCursor = 8, vaultCursor = 8 } = {}) {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: noteState({ note_id: NOTE_ID }) });
    await h.runtime.reload();
    delete h.runtime.treePath;
    h.runtime.config.funding.indexer_url = INDEXER;
    h.chain.activationCursor = BigInt(vaultCursor);
    const indexer = { cursor: indexerCursor, snapshots: 0, roots: 0, honorsParts: true, urls: [] };
    // The indexer's snapshot: tree leaves for ids 0..next_note_id, zero at and
    // above the activation cursor, and the recorded notes beside them.
    indexer.snapshot = () => ({
        root: '0x77', next_note_id: 9, leaves: Array.from({ length: 9 }, (_, id) => id < indexer.cursor ? `0x${id + 1}` : '0x0'),
        ...(indexer.cursor == null ? {} : { activation_cursor: indexer.cursor }),
        block_number: 100, block_hash: '0xb0',
        note_leaves: Array.from({ length: 9 }, (_, id) => `0x${id + 1}`), notes: []
    });
    const remoteJson = h.runtime.remoteJson;
    h.runtime.remoteJson = async (url, init = {}) => {
        if (url.startsWith(`${INDEXER}/v1/tree/snapshot`)) {
            indexer.snapshots += 1;
            indexer.urls.push(url);
            const parts = new URL(url).searchParams.get('parts');
            const { note_leaves: noteLeaves, notes, ...tree } = indexer.snapshot();
            return parts === 'tree' && indexer.honorsParts ? tree : { ...tree, note_leaves: noteLeaves, notes };
        }
        if (url === `${INDEXER}/v1/tree/root`) {
            indexer.roots += 1;
            return { root: '0x77', next_note_id: 9, activation_cursor: indexer.cursor, block: 100 };
        }
        return remoteJson(url, init);
    };
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation !== 'treePath') return call(operation, payload);
        h.worker.calls.push({ operation, payload: structuredClone(payload) });
        return { active_root: payload.snapshot.root, note_id: payload.noteId,
            siblings: Array.from({ length: 32 }, (_, index) => `0x77${index.toString(16)}`) };
    };
    return { ...h, indexer };
}

const treePaths = h => h.workerOperations('treePath');

test('an activated note proves requests from the snapshot, which the WebAssembly checks against its cursor', async () => {
    const h = await wallet();
    const path = await h.runtime.treePath(NOTE_ID);
    assert.equal(path.active_root, '0x77');
    const [{ payload }] = treePaths(h);
    // Only the tree the root commits to, with its cursor, reaches the worker.
    assert.deepEqual(Object.keys(payload.snapshot).sort(), ['activation_cursor', 'leaves', 'next_note_id', 'root']);
    assert.equal(payload.snapshot.activation_cursor, 8);
    assert.equal(payload.requireExisting, true);
    // The snapshot alone proved the activation: the vault was not asked.
    assert.equal(h.chain.reads.filter(read => read === '0x93e0ce4e').length, 0);
    assert.deepEqual(h.runtime.snapshot().config.activation, { note_id: NOTE_ID, status: 'activated', activated: true,
        activation_cursor: 8, queue_position: null, source: 'indexer', checked_at: h.runtime.activation.checked_at,
        vault_paused: null, exits_reopen_at: null });
});

test('the request path asks the indexer for the tree only, the same request for every note, and reads an older indexer\'s full snapshot the same', async () => {
    const h = await wallet();
    await h.runtime.treePath(NOTE_ID);
    await h.runtime.treePath(3);
    assert.deepEqual(h.indexer.urls, [`${INDEXER}/v1/tree/snapshot?parts=tree`, `${INDEXER}/v1/tree/snapshot?parts=tree`],
        'nothing in the request names the note');
    // An older indexer ignores parts and serves the recorded notes too.
    h.indexer.honorsParts = false;
    await h.runtime.treePath(NOTE_ID);
    const [lean, , full] = treePaths(h).map(call => call.payload);
    assert.deepEqual(full, lean, 'the worker gets the same tree either way');
    assert.deepEqual(Object.keys(full.snapshot).sort(), ['activation_cursor', 'leaves', 'next_note_id', 'root']);
});

test('a note above the activation cursor is refused with note_not_activated and its queue position, the vault\'s cursor first', async () => {
    // The vault activated more notes than the indexer has mirrored, but not this one.
    const h = await wallet({ indexerCursor: 4, vaultCursor: 6 });
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => {
        assert.equal(error.code, 'note_not_activated');
        assert.equal(error.status, 409);
        assert.deepEqual(error.data, { retriable: true, note_id: NOTE_ID, activation_cursor: 6, queue_position: 1,
            vault_paused: false, exits_reopen_at: null });
        assert.match(error.message, /can be withdrawn at any time/);
        assert.match(error.message, /1 note is ahead of it in the activation queue/);
        return true;
    });
    assert.equal(treePaths(h).length, 0, 'no path is derived for a leaf the tree does not hold');
    const activation = h.runtime.snapshot().config.activation;
    assert.equal(activation.status, 'activating');
    assert.equal(activation.queue_position, 1);
    assert.equal(activation.source, 'vault');
    // Next in the queue.
    h.chain.activationCursor = 7n;
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => error.data.queue_position === 0
        && /It is next in the activation queue/.test(error.message));
    // The vault cannot be read: the indexer's cursor gives the position.
    h.runtime.vaultWord = async () => { throw new Error('pinned RPC down'); };
    h.runtime.activation = null;
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => error.code === 'note_not_activated'
        && error.data.activation_cursor === 4 && error.data.queue_position === 3);
    assert.equal(h.runtime.snapshot().config.activation.source, 'indexer');
});

test('a note the vault activated but the indexer has not mirrored yet is indexer_root_lag, and a snapshot without a cursor is not trusted for it', async () => {
    const lagging = await wallet({ indexerCursor: 5, vaultCursor: 8 });
    await assert.rejects(lagging.runtime.treePath(NOTE_ID), error => error.code === 'indexer_root_lag'
        && error.status === 503 && error.data.retriable === true);
    assert.equal(treePaths(lagging).length, 0);
    assert.equal(lagging.runtime.snapshot().config.activation.status, 'activated', 'the vault says so');
    // An indexer that reports no cursor proves nothing: the vault decides.
    const silent = await wallet({ indexerCursor: null, vaultCursor: 3 });
    await assert.rejects(silent.runtime.treePath(NOTE_ID), error => error.code === 'note_not_activated'
        && error.data.queue_position === 4);
    // And when the vault cannot be read either, nothing is claimed.
    silent.runtime.vaultWord = async () => { throw new Error('pinned RPC down'); };
    silent.runtime.activation = null;
    await assert.rejects(silent.runtime.treePath(NOTE_ID), error => error.code === 'activation_unavailable'
        && error.status === 503 && error.data.retriable === true);
    assert.equal(silent.runtime.snapshot().config.activation.status, 'unknown');
    assert.equal(treePaths(silent).length, 0);
});

test('a chat from an unactivated note fails fast, before any proof, journal or lease, and the note still exits', async () => {
    const h = await wallet({ indexerCursor: 2, vaultCursor: 2 });
    h.server.leasePost = () => assert.fail('no lease is requested for an unactivated note');
    const progress = [];
    await assert.rejects(h.runtime.issueLease('chat', (phase, message) => progress.push(phase)), { code: 'note_not_activated' });
    assert.equal(h.workerOperations('prepareRequest').length, 0, 'nothing was proved');
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.state.bound_at_state ?? 0, 0);
    assert.deepEqual(await store.listBrowserRequestArchive(DEPLOYMENT), []);
    assert.equal(h.runtime.snapshot().config.activation.queue_position, 5);
    // Exits never wait for activation.
    const plan = await h.runtime.prepareWithdrawal('escape', DESTINATION);
    assert.equal(plan.mode, 'escape');
    // Once a batch covers the note, the same chat proves and is sent.
    const later = await wallet({ indexerCursor: 8, vaultCursor: 8 });
    later.server.leasePost = body => later.activeLease(body);
    await later.runtime.issueLease('chat');
    assert.equal(later.workerOperations('prepareRequest').length, 1);
    assert.equal(later.workerOperations('prepareRequest')[0].payload.args.active_root, '0x77');
});

test('refreshActivation reads the vault cursor through the wallet, then the pinned RPC, then the indexer; a vault activation is kept', async () => {
    const h = await wallet({ indexerCursor: 3, vaultCursor: 5 });
    let changes = 0;
    h.runtime.addEventListener('change', () => { changes += 1; });
    const walletCalls = [];
    const onChain = cursor => async request => {
        walletCalls.push(request.method === 'eth_call' ? request.params[0].data : request.method);
        if (request.method === 'eth_chainId') return '0xaa36a7';
        if (request.params[0].data === '0x5c975abb') return word(0);
        assert.equal(request.params[0].data, '0x93e0ce4e');
        return word(cursor);
    };
    let summary = await h.runtime.refreshActivation({ walletRequest: onChain(6) });
    assert.deepEqual([summary.status, summary.activation_cursor, summary.queue_position, summary.source], ['activating', 6, 1, 'vault']);
    assert.equal(summary.vault_paused, false, 'an unactivated note\'s reading says whether the vault is paused');
    assert.deepEqual(walletCalls, ['eth_chainId', '0x93e0ce4e', 'eth_chainId', '0x5c975abb']);
    assert.equal(h.chain.reads.filter(read => read === '0x93e0ce4e').length, 0, 'the wallet answered');
    assert.equal(changes, 1);
    // A wallet on another chain is not used: the pinned RPC answers.
    summary = await h.runtime.refreshActivation({ walletRequest: async request => request.method === 'eth_chainId' ? '0x1'
        : assert.fail('a wallet on another chain is never asked') });
    assert.equal(summary.activation_cursor, 6, 'a lower reading (the pinned RPC\'s 5) never moves the cursor back');
    assert.equal(h.chain.reads.filter(read => read === '0x93e0ce4e').length, 1);
    assert.equal(changes, 1, 'nothing changed');
    // Without a readable vault the indexer's cursor is used.
    const vaultWord = h.runtime.vaultWord;
    h.runtime.vaultWord = async () => { throw new Error('pinned RPC down'); };
    h.indexer.cursor = 7;
    summary = await h.runtime.refreshActivation();
    assert.deepEqual([summary.status, summary.activation_cursor, summary.queue_position, summary.source], ['activating', 7, 0, 'indexer']);
    assert.equal(summary.vault_paused, null, 'unknown without the vault');
    assert.equal(h.indexer.roots, 1);
    h.indexer.cursor = 8;
    summary = await h.runtime.refreshActivation();
    assert.deepEqual([summary.status, summary.source], ['activated', 'indexer']);
    assert.equal(changes, 3);
    // An activation only the indexer reported is read again, and the vault's
    // lower cursor (the indexer's head view was reorged away) replaces it.
    h.runtime.vaultWord = vaultWord;
    summary = await h.runtime.refreshActivation();
    assert.deepEqual([summary.status, summary.activation_cursor, summary.queue_position, summary.source], ['activating', 5, 2, 'vault']);
    assert.equal(changes, 4);
    // Once the vault shows it activated, that is final: no further reads.
    h.chain.activationCursor = 8n;
    assert.deepEqual([(await h.runtime.refreshActivation()).status, h.runtime.activation.source], ['activated', 'vault']);
    h.runtime.vaultWord = async () => assert.fail('a note the vault activated is not read again');
    h.runtime.remoteJson = async () => assert.fail('a note the vault activated is not read again');
    assert.equal((await h.runtime.refreshActivation()).status, 'activated');
    // Nothing readable: unknown, never activated.
    const unknown = await wallet();
    unknown.runtime.vaultWord = async () => { throw new Error('pinned RPC down'); };
    unknown.runtime.remoteJson = async () => { throw new Error('indexer down'); };
    assert.equal((await unknown.runtime.refreshActivation()).status, 'unknown');
    // No note, no activation.
    indexedDB.clear();
    await unknown.runtime.reload();
    assert.equal(unknown.runtime.snapshot().config.activation, null);
    assert.equal(await unknown.runtime.refreshActivation(), null);
});

test('a vault reading lowers a cursor only the indexer reported, so a reorged activation is refused as not activated, not as indexer lag', async () => {
    // The indexer's head view showed a batch covering note 7 (cursor 8)...
    const h = await wallet({ indexerCursor: 8, vaultCursor: 8 });
    await h.runtime.treePath(NOTE_ID);
    assert.deepEqual([h.runtime.activation.activation_cursor, h.runtime.activation.source], [8, 'indexer']);
    // ...then a reorg dropped it: the indexer and the vault both read 4.
    h.indexer.cursor = 4;
    h.chain.activationCursor = 4n;
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => {
        assert.equal(error.code, 'note_not_activated');
        assert.equal(error.data.activation_cursor, 4);
        assert.equal(error.data.queue_position, 3);
        return true;
    });
    const activation = h.runtime.snapshot().config.activation;
    assert.deepEqual([activation.status, activation.activation_cursor, activation.queue_position, activation.source],
        ['activating', 4, 3, 'vault'], 'the snapshot no longer claims the activation');
    // Without a readable vault, a lower indexer reading does not undo an
    // indexer activation (a lagging indexer).
    const lagging = await wallet({ indexerCursor: 8, vaultCursor: 8 });
    await lagging.runtime.treePath(NOTE_ID);
    lagging.indexer.cursor = 5;
    lagging.runtime.vaultWord = async () => { throw new Error('pinned RPC down'); };
    await assert.rejects(lagging.runtime.treePath(NOTE_ID), { code: 'indexer_root_lag' });
    assert.equal(lagging.runtime.snapshot().config.activation.status, 'activated');
});

test('a lower pinned reading never moves a vault activation back, but the request path reports the fresh reading', async () => {
    const h = await wallet({ indexerCursor: 4, vaultCursor: 4 });
    // The wallet's RPC saw the batch covering note 7.
    const summary = await h.runtime.refreshActivation({ walletRequest: async request => request.method === 'eth_chainId'
        ? '0xaa36a7' : word(8) });
    assert.deepEqual([summary.status, summary.source], ['activated', 'vault']);
    // The pinned RPC (and the indexer) still read 4: the request is refused
    // from that reading, while the snapshot keeps the vault's activation.
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => error.code === 'note_not_activated'
        && error.data.activation_cursor === 4 && error.data.queue_position === 3);
    assert.deepEqual([h.runtime.activation.activation_cursor, h.runtime.activation.source], [8, 'vault']);
});

test('a chat served from the indexer keeps an activation the vault showed, which is then not read again', async () => {
    const h = await wallet({ indexerCursor: 8, vaultCursor: 8 });
    assert.equal((await h.runtime.refreshActivation()).source, 'vault');
    await h.runtime.treePath(NOTE_ID);
    h.indexer.cursor = 9;
    await h.runtime.treePath(NOTE_ID);
    assert.deepEqual([h.runtime.activation.activation_cursor, h.runtime.activation.source], [8, 'vault']);
    const reads = h.chain.reads.length;
    assert.equal((await h.runtime.refreshActivation()).status, 'activated');
    assert.equal(h.chain.reads.length, reads, 'no vault read for a note the vault activated');
    assert.equal(h.indexer.roots, 0);
});

test('a paused vault\'s refusal and activation say so, with when withdrawals reopen, and claim no withdrawal', async () => {
    const pausedAt = Math.floor(Date.now() / 1000) - 3_600;
    const h = await wallet({ indexerCursor: 4, vaultCursor: 4 });
    h.runtime.browserConfig.trusted_deployment.max_pause_duration = 604_800;
    h.chain.paused = 1n;
    h.chain.pausedAt = BigInt(pausedAt);
    const reopenAt = (pausedAt + 604_800) * 1_000;
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => {
        assert.equal(error.code, 'note_not_activated');
        assert.equal(error.data.vault_paused, true);
        assert.equal(error.data.exits_reopen_at, reopenAt);
        assert.equal(error.data.queue_position, 3);
        assert.match(error.message, /the vault is paused by its owner/);
        assert.match(error.message, /Withdrawals reopen when it is unpaused, at the latest/);
        assert.doesNotMatch(error.message, /can be withdrawn at any time/);
        return true;
    });
    let activation = h.runtime.snapshot().config.activation;
    assert.deepEqual([activation.status, activation.vault_paused, activation.exits_reopen_at], ['activating', true, reopenAt]);
    // refreshActivation reads the pause too, and reports its end.
    let changes = 0;
    h.runtime.addEventListener('change', () => { changes += 1; });
    h.chain.paused = 0n;
    activation = await h.runtime.refreshActivation();
    assert.deepEqual([activation.status, activation.vault_paused, activation.exits_reopen_at], ['activating', false, null]);
    assert.equal(changes, 1, 'the pause ending is a change');
    // Past the pause limit exits are open again, though nothing activates.
    h.chain.paused = 1n;
    h.chain.pausedAt = BigInt(pausedAt - 604_800);
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => error.data.vault_paused === true
        && /Its pause limit has passed, so the balance can be withdrawn/.test(error.message));
    // An unreadable pause claims nothing either way.
    h.runtime.vaultWord = async data => {
        if (data === '0x93e0ce4e') return 4n;
        throw new Error('pause unreadable');
    };
    await assert.rejects(h.runtime.treePath(NOTE_ID), error => error.data.vault_paused === null
        && /can be withdrawn at any time/.test(error.message));
});

test('a deposit\'s slot comes from nextNoteId(): the wallet\'s reading when given, else the pinned RPC', async () => {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime);
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: null });
    await h.runtime.reload();
    h.runtime.prewarmRequestProver = async () => {};
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => operation === 'generateDeposit'
        ? { secret: '0x5ec', registration_commitment: '0xc0' } : call(operation, payload);
    h.chain.nextNoteId = 41n;
    const draft = await h.runtime.prepareDepositQuote(1_000, 40n);
    assert.equal(draft.next_note_id, 40, 'the wallet\'s reading');
    assert.equal(h.chain.reads.filter(read => read === '0x7a2043a3').length, 0);
    for (const field of ['active_root', 'zero_path']) assert.equal(field in draft, false, field);
    await assert.rejects(h.runtime.prepareDepositQuote(1_000, 2n ** 32n), /invalid next note id/);
    const plan = await h.runtime.prepareDeposit(1_000, { preparedOperationId: draft.operationId });
    assert.equal(plan.next_note_id, 40);
    const rebased = await h.runtime.refreshPendingDeposit(1_000, null, { expectedOperationId: plan.operationId });
    assert.equal(rebased.next_note_id, 41, 'the pinned RPC\'s nextNoteId()');
    assert.equal(h.chain.reads.filter(read => read === '0x7a2043a3').length, 1);
});

/** The shared runtime and a client whose chats wait for activation within a short bound. */
function activationClient(t, { waitMs = 400, pollMs = 20, maxWaitMs } = {}) {
    const client = new ZkapiClient();
    client.initialized = true;
    client.browserMode = true;
    client.activationTimingOverrides = { waitMs, pollMs, ...(maxWaitMs == null ? {} : { maxWaitMs }) };
    t.mock.method(client, 'ensureTestnetAccess', async () => {});
    return client;
}

const notActivated = position => Object.assign(new Error('This balance is still being activated.'), {
    code: 'note_not_activated', status: 409, data: { retriable: true, note_id: NOTE_ID, activation_cursor: NOTE_ID - position,
        queue_position: position } });

test('a chat waits for its note\'s activation, reporting the queue, and starts once the vault activated it', async t => {
    const client = activationClient(t);
    const access = { apiKey: 'key', release() {} };
    let attempts = 0;
    t.mock.method(sharedRuntime, 'acquireEphemeralKey', async () => {
        attempts += 1;
        if (attempts === 1) throw notActivated(2);
        return access;
    });
    const readings = [{ status: 'activating', queue_position: 1 }, { status: 'activating', queue_position: 0 }, { status: 'activated' }];
    t.mock.method(sharedRuntime, 'refreshActivation', async () => readings.shift());
    const progress = [];
    const result = await within(2_000, client.acquireInferenceAccess('chat', { onProgress: event => progress.push(event) }),
        'a chat waiting for activation');
    assert.equal(result, access);
    assert.equal(attempts, 2, 'the key is asked for again once, after the activation');
    const activating = progress.filter(event => event.phase === 'activating').map(event => event.message);
    assert.deepEqual(activating, [
        'Your deposit is confirmed and waits for activation (2 deposits ahead)…',
        'Your deposit is confirmed and waits for activation (1 deposit ahead)…',
        'Your deposit is confirmed and is being activated for private chats…'
    ]);
    assert.equal(progress.at(-1).phase, 'ready');
});

test('a chat whose note stays unactivated past the bound reports note_not_activated; an indexer catching up is retried', async t => {
    const client = activationClient(t, { waitMs: 150, pollMs: 20 });
    let attempts = 0;
    t.mock.method(sharedRuntime, 'acquireEphemeralKey', async () => {
        attempts += 1;
        throw notActivated(3);
    });
    t.mock.method(sharedRuntime, 'refreshActivation', async () => ({ status: 'activating', queue_position: 3 }));
    const progress = [];
    const started = Date.now();
    await assert.rejects(within(2_000, client.acquireInferenceAccess('chat', { onProgress: event => progress.push(event) }),
        'a chat past the activation bound'), error => {
        assert.equal(error.code, 'note_not_activated');
        assert.match(error.shortMessage, /not activated for private chats yet.*3 deposits are ahead of it/);
        return true;
    });
    assert.ok(Date.now() - started < 1_000);
    assert.ok(progress.some(event => event.phase === 'activating'));
    assert.equal(progress.at(-1).phase, 'error');
    assert.equal(progress.at(-1).failedPhase, 'activating');
    // Another refusal is not waited on.
    attempts = 0;
    sharedRuntime.acquireEphemeralKey.mock.mockImplementation(async () => {
        attempts += 1;
        throw Object.assign(new Error('Lease refused.'), { code: 'lease_pending' });
    });
    await assert.rejects(client.acquireInferenceAccess('chat'), { code: 'lease_pending' });
    assert.equal(attempts, 1);
    // The indexer catching up with an activated note is retried, without vault reads.
    attempts = 0;
    sharedRuntime.refreshActivation.mock.mockImplementation(async () => assert.fail('no activation read while the indexer catches up'));
    sharedRuntime.acquireEphemeralKey.mock.mockImplementation(async () => {
        attempts += 1;
        if (attempts < 3) throw Object.assign(new Error('Catching up.'), { code: 'indexer_root_lag', status: 503 });
        return { apiKey: 'key', release() {} };
    });
    assert.equal((await client.acquireInferenceAccess('chat')).apiKey, 'key');
    assert.equal(attempts, 3);
});

test('a chat behind a moving queue waits past waitMs while the cursor advances, but never past maxWaitMs', async t => {
    // The worker lands one batch per cycle: every poll the cursor advances.
    const client = activationClient(t, { waitMs: 120, pollMs: 20, maxWaitMs: 2_000 });
    const access = { apiKey: 'key', release() {} };
    let attempts = 0;
    t.mock.method(sharedRuntime, 'acquireEphemeralKey', async () => {
        attempts += 1;
        if (attempts === 1) throw notActivated(12);
        return access;
    });
    let cursor = NOTE_ID - 12;
    const reading = () => {
        const position = NOTE_ID - cursor;
        return position <= 0 ? { status: 'activated', activation_cursor: cursor }
            : { status: 'activating', activation_cursor: cursor, queue_position: position };
    };
    // One advance every third poll: about 60 ms apart, 12 advances in all,
    // so the note activates long after the first waitMs.
    let polls = 0;
    t.mock.method(sharedRuntime, 'refreshActivation', async () => {
        polls += 1;
        if (polls % 3 === 0) cursor += 1;
        return reading();
    });
    const started = Date.now();
    assert.equal(await within(3_000, client.acquireInferenceAccess('chat'), 'a chat behind a moving queue'), access);
    assert.ok(Date.now() - started > 120, 'it waited past waitMs');
    assert.equal(attempts, 2);
    // A queue that keeps moving but never reaches the note stops at maxWaitMs.
    const capped = activationClient(t, { waitMs: 60, pollMs: 10, maxWaitMs: 250 });
    sharedRuntime.acquireEphemeralKey.mock.mockImplementation(async () => { throw notActivated(1_000); });
    let far = NOTE_ID - 1_000;
    sharedRuntime.refreshActivation.mock.mockImplementation(async () => {
        far += 1;
        return { status: 'activating', activation_cursor: far, queue_position: NOTE_ID - far };
    });
    const cappedStart = Date.now();
    await assert.rejects(within(2_000, capped.acquireInferenceAccess('chat'), 'a capped activation wait'), { code: 'note_not_activated' });
    const elapsed = Date.now() - cappedStart;
    assert.ok(elapsed >= 200 && elapsed < 1_000, `stopped at maxWaitMs (${elapsed} ms)`);
});

test('a chat from a note of a paused vault is refused at once, with the pause and no claim that it can be withdrawn', async t => {
    const client = activationClient(t, { waitMs: 2_000, pollMs: 20 });
    const reopenAt = Date.now() + 86_400_000;
    let attempts = 0;
    t.mock.method(sharedRuntime, 'acquireEphemeralKey', async () => {
        attempts += 1;
        const error = notActivated(2);
        Object.assign(error.data, { vault_paused: true, exits_reopen_at: reopenAt });
        throw error;
    });
    t.mock.method(sharedRuntime, 'refreshActivation', async () => assert.fail('a paused vault is not waited on'));
    const started = Date.now();
    await assert.rejects(client.acquireInferenceAccess('chat'), error => {
        assert.equal(error.code, 'note_not_activated');
        assert.match(error.shortMessage, /the vault is paused by its owner and activates it only once unpaused/);
        assert.ok(error.shortMessage.includes(`at the latest ${new Date(reopenAt).toLocaleString()}.`), error.shortMessage);
        assert.doesNotMatch(error.shortMessage, /can already be withdrawn/);
        return true;
    });
    assert.equal(attempts, 1);
    assert.ok(Date.now() - started < 1_000);
    // A pause seen while waiting ends the wait: the key is asked once more,
    // and that refusal (paused) reaches the host.
    attempts = 0;
    sharedRuntime.acquireEphemeralKey.mock.mockImplementation(async () => {
        attempts += 1;
        const error = notActivated(2);
        if (attempts > 1) Object.assign(error.data, { vault_paused: true, exits_reopen_at: null });
        throw error;
    });
    sharedRuntime.refreshActivation.mock.mockImplementation(async () => ({ status: 'activating', queue_position: 2, vault_paused: true }));
    await assert.rejects(within(1_000, client.acquireInferenceAccess('chat'), 'a wait that sees a pause'), error =>
        /Withdrawals reopen at the latest when its pause limit ends/.test(error.shortMessage));
    assert.equal(attempts, 2);
});

test('the background reconcile follows the activation of a confirmed note until it is activated', async t => {
    const client = activationClient(t);
    t.mock.method(client, 'refresh', async () => client.snapshot());
    client.wallet = { has_note: true, note: { note_id: NOTE_ID } };
    let reads = 0;
    t.mock.method(sharedRuntime, 'refreshActivation', async () => { reads += 1; return { status: 'activating' }; });
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'ethereum');
    delete globalThis.ethereum;
    try {
        client.config = { funding: { chain_id: 11155111 }, activation: { status: 'activating' } };
        assert.equal(await client.reconcileBrowserWalletInBackground(), false, 'no wallet to reconcile the rest with');
        assert.equal(reads, 1, 'the vault cursor is read without a wallet');
        client.config = { ...client.config, activation: { status: 'activated', source: 'indexer' } };
        await client.reconcileBrowserWalletInBackground();
        assert.equal(reads, 2, 'an activation only the indexer reported is read again');
        client.config = { ...client.config, activation: { status: 'activated', source: 'vault' } };
        await client.reconcileBrowserWalletInBackground();
        assert.equal(reads, 2, 'a note the vault activated is not read again');
    } finally {
        if (saved) Object.defineProperty(globalThis, 'ethereum', saved);
    }
});
