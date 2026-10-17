import { nativeFunding } from './helpers/native-fixtures.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';

const clone = value => value === undefined ? undefined : structuredClone(value);

// A transactional IndexedDB boundary: writes remain private to a transaction
// until completion, including when an injected history write fails. The tests
// exercise the real wallet store and runtime rather than source-code patterns.
function memoryIndexedDb() {
    const stores = new Map([
        ['runtime', new Map()], ['archives', new Map()], ['withdrawals', new Map()]
    ]);
    const keyPaths = new Map([['archives', 'archiveId'], ['withdrawals', 'recordId']]);
    let version = 2;
    let failDepositWrite = false;
    const database = {
        close() {},
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) {
            stores.set(name, new Map());
            keyPaths.set(name, options.keyPath);
        },
        transaction(names, mode) {
            const allowed = Array.isArray(names) ? names : [names];
            const working = new Map(allowed.map(name => [name, new Map(stores.get(name))]));
            let timer;
            const transaction = {
                aborted: false, completed: false, pending: 0,
                abort() {
                    if (this.aborted || this.completed) return;
                    this.aborted = true;
                    clearTimeout(timer);
                    setTimeout(() => this.onabort?.(), 0);
                },
                scheduleCompletion() {
                    clearTimeout(timer);
                    if (this.aborted || this.pending) return;
                    timer = setTimeout(() => {
                        if (this.aborted || this.pending) return;
                        if (mode === 'readwrite') {
                            for (const [name, values] of working) stores.set(name, values);
                        }
                        this.completed = true;
                        this.oncomplete?.();
                    }, 0);
                },
                objectStore(name) {
                    if (!working.has(name)) throw new Error(`Unknown object store: ${name}`);
                    const values = working.get(name);
                    const request = operation => {
                        const pending = {};
                        transaction.pending += 1;
                        queueMicrotask(() => {
                            try {
                                if (transaction.aborted) return;
                                pending.result = operation();
                                pending.onsuccess?.();
                            } catch (error) {
                                pending.error = error;
                                transaction.error = error;
                                pending.onerror?.();
                                transaction.abort();
                            } finally {
                                transaction.pending -= 1;
                                transaction.scheduleCompletion();
                            }
                        });
                        return pending;
                    };
                    return {
                        get: key => request(() => clone(values.get(key))),
                        getAll: () => request(() => [...values.values()].map(clone)),
                        put: (value, key) => request(() => {
                            if (name === 'deposits' && failDepositWrite) {
                                failDepositWrite = false;
                                throw new Error('Simulated history storage failure');
                            }
                            const resolved = key ?? value[keyPaths.get(name)];
                            values.set(resolved, clone(value));
                            return resolved;
                        }),
                        delete: key => request(() => values.delete(key))
                    };
                }
            };
            return transaction;
        }
    };
    return {
        stores,
        clear() { for (const values of stores.values()) values.clear(); },
        failNextDepositWrite() { failDepositWrite = true; },
        open(_name, requestedVersion) {
            const request = {};
            queueMicrotask(() => {
                request.result = database;
                if (requestedVersion > version) {
                    const oldVersion = version;
                    version = requestedVersion;
                    request.onupgradeneeded?.({ oldVersion, newVersion: version });
                }
                request.onsuccess?.();
            });
            return request;
        }
    };
}

const values = new Map();
globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value))
};
globalThis.sessionStorage = globalThis.localStorage;
globalThis.window = new EventTarget();
globalThis.window.location = { search: '', hostname: 'localhost' };
globalThis.indexedDB = memoryIndexedDb();
const {
    archiveBrowserWallet, readBrowserWallet, readBrowserWalletSnapshot, recordBrowserExpiryClaims,
    updateBrowserWithdrawal, writeBrowserWallet
} = await import('../services/browserWalletStore.js');
const { default: singleton } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { ABI, abiWord } = await import('../wallet.js');

const DEPLOYMENT = 'deployment:sepolia';
const OTHER_DEPLOYMENT = 'deployment:mainnet';
const HASH = `0x${'ab'.repeat(32)}`;
const REPLACED_HASH = `0x${'cd'.repeat(32)}`;
const state = (noteId = 7, amount = 2_000_000) => ({
    note_id: noteId, deposit_amount: amount, current_balance: 123,
    secret: 'private-note-secret', current_commitment: 'private-commitment'
});
const plan = (overrides = {}) => ({
    operationId: 'deposit-operation', next_note_id: 7, amount: 2_000_000,
    secret: 'private-note-secret', commitment: '0x123', phase: 'submitted',
    createdAt: 1000, transactionHash: REPLACED_HASH, ...overrides
});
function seedRuntime(value) {
    indexedDB.stores.get('runtime').set('active', clone({ deploymentId: DEPLOYMENT, ...value }));
}
function makeRuntime() {
    const runtime = new singleton.constructor();
    runtime.manifest = { deployment_id: DEPLOYMENT };
    runtime.config = { wallet_core: {}, funding: nativeFunding() };
    runtime.init = async () => runtime.snapshot();
    runtime.walletStatus = async () => ({ has_note: Boolean(runtime.runtime.state) });
    runtime.worker = { call: async (method, payload) => {
        assert.equal(method, 'confirmDeposit');
        return state(payload.args.note_id, payload.args.amount);
    } };
    return runtime;
}
const confirmArgs = (extra = {}) => ({
    operationId: 'deposit-operation', secret: 'private-note-secret',
    note_id: 7, amount: 2_000_000, commitment: '0x123', expiry_ts: 9999,
    ...extra
});
function assertSanitized(records) {
    assert.doesNotMatch(JSON.stringify(records), /private-note-secret|private-commitment|proof|clearance|0x123/);
}

test.beforeEach(() => indexedDB.clear());

test('v2 migration recovers original deposits from notes, archives and withdrawal states without invented dates', async () => {
    seedRuntime({ state: state(), updatedAt: 98765 });
    const original = clone(indexedDB.stores.get('runtime').get('active'));
    indexedDB.stores.get('archives').set('old', {
        archiveId: `${DEPLOYMENT}:6:4000`, archivedAt: 4001, state: state(6, 5_000_000)
    });
    indexedDB.stores.get('archives').set('duplicate', {
        archiveId: `${DEPLOYMENT}:7:7000`, archivedAt: 7000, state: state()
    });
    indexedDB.stores.get('archives').set('other', {
        archiveId: `${OTHER_DEPLOYMENT}:7:4000`, archivedAt: 4000, state: state(7, 9_000_000)
    });
    indexedDB.stores.get('withdrawals').set('withdrawal', {
        recordId: 'withdrawal', deploymentId: DEPLOYMENT, createdAt: 3000,
        state: state(5, 4_000_000), phase: 'parked'
    });
    indexedDB.stores.get('withdrawals').set('no-original-amount', {
        recordId: 'no-original-amount', deploymentId: DEPLOYMENT,
        state: { note_id: 4, current_balance: 55 }
    });
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.deepEqual(snapshot.deposits.map(row => row.amount).sort(), [2_000_000, 4_000_000, 5_000_000]);
    assert.equal(snapshot.deposits.length, 3);
    for (const row of snapshot.deposits) {
        assert.equal(row.status, 'confirmed');
        assert.equal(row.createdAt, null);
        assert.equal(row.confirmedAt, null);
        assert.equal(row.transactionHash, null);
    }
    assertSanitized(snapshot.deposits);
    assert.deepEqual(indexedDB.stores.get('runtime').get('active'), original);
    indexedDB.stores.get('runtime').clear();
    indexedDB.stores.get('archives').clear();
    indexedDB.stores.get('withdrawals').clear();
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits, snapshot.deposits);
    assert.equal((await readBrowserWalletSnapshot(OTHER_DEPLOYMENT)).deposits[0].amount, 9_000_000);
});

test('confirmed deposits retain actual receipt identity across spending, closure, replacement and runtime reload', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH.toUpperCase().replace('0X', '0x') }));
    const confirmed = runtime.snapshot().deposits;
    assert.equal(confirmed.length, 1);
    assert.equal(confirmed[0].status, 'confirmed');
    assert.equal(confirmed[0].transactionHash, HASH);
    assert.equal(confirmed[0].createdAt, 1000);
    assert.ok(confirmed[0].confirmedAt > 1000);
    assert.equal(confirmed[0].operationId, 'deposit-operation');
    assert.equal((await readBrowserWallet()).pendingDeposit, null);
    await writeBrowserWallet({ ...(await readBrowserWallet()), state: { ...state(), current_balance: 1 } });
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits, confirmed);
    await archiveBrowserWallet('closed', 7);
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, state: state(8, 3_000_000) });
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.equal(reloaded.snapshot().deposits.length, 2);
    assert.deepEqual(reloaded.snapshot().deposits.find(row => row.noteId === 7), confirmed[0]);
    assertSanitized(reloaded.snapshot().deposits);
});

test('exact deposit commit succeeds independently of worker status and survives reload', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    runtime.walletStatus = async () => { throw new Error('Status worker unavailable'); };
    const result = await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH }));
    assert.deepEqual(result, {
        status: 'confirmed', operationId: 'deposit-operation', noteId: 7,
        amount: 2_000_000, transactionHash: HASH
    });
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.equal(reloaded.snapshot().runtime.pendingDeposit, null);
    assert.equal(reloaded.snapshot().runtime.state.note_id, 7);
    assert.equal(reloaded.snapshot().deposits[0].status, 'confirmed');
    assert.equal(reloaded.snapshot().deposits[0].transactionHash, HASH);
});

// The vault's activation reading after a confirmation: note 7 is activated.
const ACTIVATED = Object.freeze({ note_id: 7, status: 'activated', activated: true, activation_cursor: 8, queue_position: null });

function confirmationClient(t, runtime) {
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    t.mock.method(singleton, 'confirmDeposit', runtime.confirmDeposit.bind(runtime));
    t.mock.method(singleton, 'snapshot', runtime.snapshot.bind(runtime));
    t.mock.method(singleton, 'walletStatus', async () => { throw new Error('Status worker unavailable'); });
    t.mock.method(singleton, 'refreshActivation', async () => ({ ...ACTIVATED }));
    // The vault's notes(7): the receipt's note.
    t.mock.method(client, 'readBrowserNote', async () => ({
        status: 1, amount: 2_000_000n, commitment: '0x123', expiryTs: 9999
    }));
    return client;
}

function depositReceipt() {
    const vault = `0x${'12'.repeat(20)}`;
    return { vault, receipt: { status: '0x1', transactionHash: HASH, logs: [{
        address: vault, topics: [ABI.noteDeposited, '0x7', '0x123'],
        data: `0x${[2_000_000, 9999].map(abiWord).join('')}`
    }] } };
}

for (const recovery of [false, true]) {
    test(`${recovery ? 'vault recovery' : 'receipt confirmation'} stays successful after commit when the balance refresh fails`, async t => {
        seedRuntime({ pendingDeposit: plan() });
        const runtime = makeRuntime();
        const client = confirmationClient(t, runtime);
        const statuses = [];
        let result;
        if (recovery) {
            t.mock.method(singleton, 'pendingDeposit', async () => plan());
            t.mock.method(singleton, 'treePath', async () => assert.fail('a deposit recovery waits for no tree'));
            result = await client.recoverBrowserDeposit(message => statuses.push(message));
        } else {
            const { vault, receipt } = depositReceipt();
            result = await client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message));
        }
        assert.equal(result.status, 'confirmed');
        assert.equal(result.balanceRefreshPending, true);
        assert.equal(result.noteId, 7);
        assert.equal(result.amount, 2_000_000);
        assert.match(statuses.at(-1), /saved.*display will refresh/);
        assert.match(client.lastError.message, /Status worker unavailable/);
        assert.equal(client.config.pending_deposit, null);
        assert.equal(client.deposits[0].status, 'confirmed');
        const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
        assert.equal(persisted.runtime.pendingDeposit, null);
        assert.equal(persisted.runtime.state.note_id, 7);
        assert.equal(persisted.deposits[0].status, 'confirmed');
        // Ordinary read-only refresh recovers the display without another
        // confirmation, proof, signing request or transaction.
        t.mock.method(singleton, 'walletStatus', async () => ({ has_note: true, note: state() }));
        await client.refresh({ quiet: true });
        assert.equal(client.lastError, null);
        assert.equal(client.wallet.has_note, true);
        assert.equal(client.config.pending_deposit, null);
    });
}

test('a confirmed deposit whose balance is below three escape fees ends with the G1 warning', async t => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    const client = confirmationClient(t, runtime);
    t.mock.method(singleton, 'refreshExitCost', runtime.refreshExitCost.bind(runtime));
    const previous = globalThis.ethereum;
    globalThis.ethereum = { request: async ({ method }) => {
        if (method === 'eth_chainId') return `0x${Number(runtime.config.funding.chain_id).toString(16)}`;
        if (method === 'eth_gasPrice') return '0x3b9aca00';
        throw new Error(`unexpected wallet RPC ${method}`);
    } };
    try {
        const statuses = [];
        const { vault, receipt } = depositReceipt();
        const result = await client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message));
        assert.equal(result.status, 'confirmed');
        assert.match(statuses.at(-1), /as little as 0\.000000123 ETH, less than three times the estimated network fee of an escape \(0\.00062 ETH/);
        assert.deepEqual(runtime.snapshot().config.exit.exit_cost_warning,
            { floor: '123', cost: '620000', gas_price_wei: '1000000000' });
    } finally {
        globalThis.ethereum = previous;
    }
});

test('a confirmed deposit is not held by a wallet whose gas price read never answers (G1 is advisory)', async t => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    runtime.exitTimingOverrides = { callTimeoutMs: 50 };
    const client = confirmationClient(t, runtime);
    t.mock.method(singleton, 'refreshExitCost', runtime.refreshExitCost.bind(runtime));
    const previous = globalThis.ethereum;
    let asked = 0;
    globalThis.ethereum = { request: async ({ method }) => {
        if (method === 'eth_chainId') return `0x${Number(runtime.config.funding.chain_id).toString(16)}`;
        if (method === 'eth_gasPrice') {
            asked += 1;
            return new Promise(() => {});
        }
        throw new Error(`unexpected wallet RPC ${method}`);
    } };
    try {
        const statuses = [];
        const { vault, receipt } = depositReceipt();
        let timer;
        const result = await Promise.race([
            client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message)),
            new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('the deposit did not return')), 3_000); })
        ]).finally(() => clearTimeout(timer));
        assert.equal(result.status, 'confirmed');
        assert.equal(asked, 1);
        assert.ok(!statuses.some(message => /less than three times the estimated network fee/.test(message)), 'no warning');
        assert.equal(runtime.snapshot().config.exit.exit_cost_warning, null);
    } finally {
        globalThis.ethereum = previous;
    }
});

for (const failure of ['worker', 'storage', 'old-note']) {
    test(`a ${failure} failure before this deposit commit is never classified as confirmed`, async t => {
        seedRuntime({ pendingDeposit: plan(), ...(failure === 'old-note' ? { state: state(6) } : {}) });
        const runtime = makeRuntime();
        const client = confirmationClient(t, runtime);
        let refreshes = 0;
        t.mock.method(client, 'refresh', async () => { refreshes += 1; });
        if (failure === 'worker') runtime.worker.call = async () => { throw new Error('Invalid confirmation'); };
        if (failure === 'storage') indexedDB.failNextDepositWrite();
        const { vault, receipt } = depositReceipt();
        await assert.rejects(client.confirmBrowserDepositReceipt(plan(), receipt, vault, () => {}),
            failure === 'worker' ? /Invalid confirmation/ : failure === 'storage' ? /history storage failure/ : /already has an active/);
        assert.equal(refreshes, 0, 'only an actual successful commit reaches best-effort display refresh');
        const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
        assert.equal(persisted.runtime.pendingDeposit.operationId, plan().operationId);
        assert.ok(!persisted.deposits.some(row => row.noteId === 7 && row.status === 'confirmed'));
    });
}

test('unsigned preparations are omitted and durable wallet/receipt recovery remains pending until confirmation', async () => {
    const pending = plan({ phase: 'prepared', transactionHash: null });
    seedRuntime({ pendingDeposit: pending });
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.length, 0);
    for (const phase of ['awaiting_wallet', 'ambiguous', 'submitted', 'dropped_or_pending']) {
        await writeBrowserWallet({ deploymentId: DEPLOYMENT, pendingDeposit: {
            ...pending, phase, ...(phase === 'submitted' ? { transactionHash: HASH } : {})
        } });
        const reloaded = makeRuntime();
        await reloaded.reload();
        const rows = reloaded.snapshot().deposits;
        assert.equal(rows.length, 1);
        assert.equal(rows[0].status, 'pending');
        assert.equal(rows[0].pendingPhase, phase);
        assert.equal(rows[0].confirmedAt, null);
        assert.equal(reloaded.snapshot().config.pending_deposit.operation_id, pending.operationId);
        assertSanitized(rows);
        assert.equal(indexedDB.stores.get('deposits').size, 0);
    }
    // Definite wallet rejection returns the same plan to the unsigned stage.
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, pendingDeposit: pending });
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.length, 0);
});

test('failed confirmation and failed atomic history write retain pending recovery and never record a deposit', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    await assert.rejects(runtime.confirmDeposit(confirmArgs({ amount: 1 })), /does not match/);
    runtime.worker.call = async () => { throw new Error('Invalid confirmation'); };
    await assert.rejects(runtime.confirmDeposit(confirmArgs()), /Invalid confirmation/);
    runtime.worker.call = async () => state();
    indexedDB.failNextDepositWrite();
    await assert.rejects(runtime.confirmDeposit(confirmArgs({ transactionHash: HASH })), /history storage failure/);
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(snapshot.runtime.state, null);
    assert.equal(snapshot.runtime.pendingDeposit.secret, plan().secret);
    assert.equal(snapshot.deposits.length, 1);
    assert.equal(snapshot.deposits[0].status, 'pending');
    assert.equal(indexedDB.stores.get('deposits').size, 0);
    // The unchanged durable plan can be confirmed successfully after retry.
    await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH }));
    assert.equal(runtime.snapshot().deposits[0].status, 'confirmed');
});

test('vault-state recovery does not mislabel a replaced or unresolved saved hash as the mined transaction', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    await runtime.confirmDeposit(confirmArgs());
    assert.equal(runtime.snapshot().deposits[0].transactionHash, null);
    assert.equal(runtime.snapshot().deposits[0].status, 'confirmed');
});

test('withdrawal finality preserves legacy deposit metadata before sanitizing the last recovery state', async () => {
    indexedDB.stores.get('withdrawals').set('old-return', {
        recordId: 'old-return', deploymentId: DEPLOYMENT, revision: 1,
        state: state(1, 8_000_000), phase: 'closed_unconfirmed',
        proof: 'private-proof', withdrawalNullifier: 'private-nullifier',
        createdAt: 4000, transactionHash: HASH
    });
    await updateBrowserWithdrawal('old-return', { phase: 'closed' }, { sanitize: true });
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(snapshot.withdrawals[0].state, undefined);
    assert.equal(snapshot.deposits.length, 1);
    assert.equal(snapshot.deposits[0].amount, 8_000_000);
    assert.equal(snapshot.deposits[0].transactionHash, null, 'withdrawal hash is not a deposit receipt');
    assert.equal(snapshot.deposits[0].createdAt, null, 'withdrawal date is not a deposit date');
    assertSanitized(snapshot.deposits);
});

test('late replacement attempts deduplicate without turning pending deposits into success or mixing deployments', async () => {
    seedRuntime({ pendingDeposit: plan(), lateDepositAttempts: [
        { operationId: 'deposit-operation', deploymentId: DEPLOYMENT, noteId: 7,
            amount: 2_000_000, status: 'reverted', transactionHash: REPLACED_HASH, observedAt: 2000 },
        { operationId: 'other', deploymentId: OTHER_DEPLOYMENT, noteId: 7,
            amount: 9_000_000, status: 'submitted_late', transactionHash: HASH,
            secret: 'private-note-secret', observedAt: 2001 }
    ] });
    const rows = (await readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, 'pending');
    assert.equal(rows[0].amount, 2_000_000);
    const other = (await readBrowserWalletSnapshot(OTHER_DEPLOYMENT)).deposits;
    assert.equal(other.length, 1);
    assert.equal(other[0].status, 'pending');
    assert.equal(other[0].amount, 9_000_000);
    assertSanitized(other);
});

test('different operations sharing a vault slot retain separate attempts while rebased attempts stay one row', async () => {
    const late = { operationId: 'old-operation', deploymentId: DEPLOYMENT, noteId: 7,
        amount: 1_000_000, status: 'submitted_late', transactionHash: REPLACED_HASH, observedAt: 800 };
    seedRuntime({ pendingDeposit: plan(), lateDepositAttempts: [late, {
        ...late, operationId: 'deposit-operation', noteId: 6, amount: 2_000_000
    }] });
    const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(snapshot.deposits.length, 2);
    assert.equal(snapshot.deposits.find(row => row.operationId === 'deposit-operation').noteId, 7);
    assert.equal(snapshot.deposits.find(row => row.operationId === 'old-operation').amount, 1_000_000);
    assert.equal(new Set(snapshot.deposits.map(row => row.recordId)).size, 2);
    const runtime = makeRuntime();
    await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH }));
    const rows = runtime.snapshot().deposits;
    assert.equal(rows.length, 2);
    assert.equal(rows.find(row => row.operationId === 'deposit-operation').status, 'confirmed');
    assert.equal(rows.find(row => row.operationId === 'old-operation').status, 'pending');
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.deepEqual(reloaded.snapshot().deposits, rows);
});

const EXPIRY_TS = 2_000_000;
const BLOCK_HASH = `0x${'ef'.repeat(32)}`;
const expiryClaim = (extra = {}) => ({
    noteId: 7, amount: 2_000_000, transactionHash: HASH,
    blockHash: BLOCK_HASH, blockNumber: 50, claimedAt: EXPIRY_TS * 1000,
    ...extra
});

test('expiry metadata migrates from active, archived and background states and preserves unknown legacy expiry', async () => {
    seedRuntime({ state: { ...state(), expiry_ts: EXPIRY_TS } });
    indexedDB.stores.get('archives').set('old-expiry', {
        archiveId: `${DEPLOYMENT}:8:4000`, archivedAt: 4001,
        state: { ...state(8), expiry_ts: EXPIRY_TS + 1 }
    });
    indexedDB.stores.get('withdrawals').set('expiry-withdrawal', {
        recordId: 'expiry-withdrawal', deploymentId: DEPLOYMENT,
        state: { ...state(9), expiry_ts: EXPIRY_TS + 2 }
    });
    indexedDB.stores.get('deposits').set(`${DEPLOYMENT}:deposit:7`, {
        recordId: `${DEPLOYMENT}:deposit:7`, deploymentId: DEPLOYMENT,
        type: 'deposit', status: 'confirmed', noteId: 7, amount: 2_000_000,
        transactionHash: HASH, confirmedAt: 1000
    });
    indexedDB.stores.get('deposits').set(`${DEPLOYMENT}:deposit:10`, {
        recordId: `${DEPLOYMENT}:deposit:10`, deploymentId: DEPLOYMENT,
        type: 'deposit', status: 'confirmed', noteId: 10, amount: 2_000_000
    });
    const rows = (await readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    assert.deepEqual(new Map(rows.map(row => [row.noteId, row.expiryTs])), new Map([
        [7, EXPIRY_TS], [8, EXPIRY_TS + 1], [9, EXPIRY_TS + 2], [10, null]
    ]));
    assert.equal(rows.find(row => row.noteId === 7).transactionHash, HASH);
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, state: state() });
    indexedDB.stores.get('archives').clear();
    indexedDB.stores.get('withdrawals').clear();
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits, rows);
    assert.deepEqual(await recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim({ noteId: 10 })]), []);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.find(row => row.noteId === 10).expiryClaim, undefined);
});

test('expiry claims persist sanitized evidence without changing selected wallet or private recovery state', async () => {
    seedRuntime({ state: { ...state(), expiry_ts: EXPIRY_TS },
        journal: { privateRecovery: 'private-note-secret' },
        lease: { sessionId: 'chat-a', client_request_id: 'request-a' },
        preparedWithdrawal: { proof: 'private-proof' } });
    const before = await readBrowserWallet();
    const runtime = makeRuntime();
    let notifications = 0;
    runtime.addEventListener('change', () => { notifications += 1; });
    const updated = await runtime.rememberExpiryClaims([expiryClaim({
        transactionHash: HASH.toUpperCase().replace('0X', '0x'),
        blockHash: BLOCK_HASH.toUpperCase().replace('0X', '0x'),
        secret: 'private-note-secret', proof: 'private-proof', state: state(),
        withdrawalNullifier: 'private-nullifier'
    })]);
    assert.equal(updated.length, 1);
    assert.deepEqual(updated[0].expiryClaim, {
        transactionHash: HASH, blockHash: BLOCK_HASH, blockNumber: 50,
        claimedAt: EXPIRY_TS * 1000, amount: 2_000_000
    });
    assert.deepEqual(await readBrowserWallet(), before);
    assert.equal(indexedDB.stores.get('archives').size, 0, 'recording evidence never archives a note');
    assert.equal(notifications, 1);
    assert.deepEqual(await runtime.rememberExpiryClaims([expiryClaim()]), []);
    assert.equal(notifications, 1, 'repeated observations do not create duplicate updates');
    const reloaded = makeRuntime();
    const history = await reloaded.getDepositHistory();
    assertSanitized(history);
    assert.deepEqual(history[0].expiryClaim, updated[0].expiryClaim);
    history[0].expiryClaim.amount = 1;
    assert.equal(reloaded.snapshot().deposits[0].expiryClaim.amount, 2_000_000,
        'public snapshots cannot mutate nested runtime evidence');
    await writeBrowserWallet({ ...before, state: { ...before.state, current_balance: 1 } });
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits[0].expiryClaim, updated[0].expiryClaim);
});

test('expiry claims reject mismatched evidence atomically and cannot create or cross deployment history', async () => {
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, state: { ...state(), expiry_ts: EXPIRY_TS } });
    indexedDB.stores.get('deposits').set(`${OTHER_DEPLOYMENT}:deposit:7`, {
        recordId: `${OTHER_DEPLOYMENT}:deposit:7`, deploymentId: OTHER_DEPLOYMENT,
        type: 'deposit', status: 'confirmed', noteId: 7, amount: 2_000_000, expiryTs: EXPIRY_TS
    });
    const before = clone([...indexedDB.stores.get('deposits').entries()]);
    for (const changes of [
        { amount: 1 }, { transactionHash: '0x123' }, { blockHash: '0x123' },
        { blockNumber: 0 }, { blockNumber: 1.5 }, { claimedAt: EXPIRY_TS * 1000 - 1 },
        { claimedAt: null }, { noteId: -1 }, { deploymentId: OTHER_DEPLOYMENT }
    ]) {
        await assert.rejects(recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim(), expiryClaim(changes)]),
            /invalid deployment or note identity|does not match/);
        assert.deepEqual([...indexedDB.stores.get('deposits').entries()], before);
    }
    assert.deepEqual(await recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim({ noteId: 55 })]), []);
    assert.deepEqual(await recordBrowserExpiryClaims('unrelated-deployment', [expiryClaim()]), []);
    await recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim()]);
    assert.equal((await readBrowserWalletSnapshot(OTHER_DEPLOYMENT)).deposits[0].expiryClaim, undefined);
    await assert.rejects(recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim({ transactionHash: REPLACED_HASH })]),
        /different finalized expiry claim/);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits[0].expiryClaim.transactionHash, HASH);
});

test('an expiry history storage failure retains all recovery state and leaves the observation retryable', async () => {
    await writeBrowserWallet({ deploymentId: DEPLOYMENT,
        state: { ...state(), expiry_ts: EXPIRY_TS }, journal: { recovery: 'private-note-secret' } });
    const before = await readBrowserWalletSnapshot(DEPLOYMENT);
    indexedDB.failNextDepositWrite();
    await assert.rejects(recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim()]), /history storage failure/);
    assert.deepEqual(await readBrowserWalletSnapshot(DEPLOYMENT), before);
    assert.equal((await recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim()])).length, 1);
});

test('explicit claimed-note archive preserves private recovery material and durable payment evidence', async () => {
    await writeBrowserWallet({ deploymentId: DEPLOYMENT,
        state: { ...state(), expiry_ts: EXPIRY_TS },
        journal: { recovery: 'private-note-secret' },
        lease: { sessionId: 'chat-a', client_request_id: 'request-a' },
        preparedWithdrawal: { proof: 'private-proof' } });
    const before = await readBrowserWallet();
    await assert.rejects(archiveBrowserWallet('expiry-claimed', 7), /no matching confirmed expiry claim/);
    assert.deepEqual(await readBrowserWallet(), before);
    await recordBrowserExpiryClaims(DEPLOYMENT, [expiryClaim()]);
    await assert.rejects(archiveBrowserWallet('expiry-claimed', 8), /selected private note changed/);
    const runtime = makeRuntime();
    runtime.activeLease = { sessionId: 'chat-a', inFlight: 1 };
    await assert.rejects(runtime.archiveNote('expiry-claimed', 7), /Finish the current response/);
    assert.deepEqual(await readBrowserWallet(), before);
    runtime.activeLease.inFlight = 0;
    await runtime.archiveNote('expiry-claimed', 7);
    const archives = [...indexedDB.stores.get('archives').values()];
    assert.equal(archives.length, 1);
    for (const field of ['state', 'journal', 'lease', 'preparedWithdrawal', 'pendingDeposit']) {
        assert.deepEqual(archives[0][field], before[field]);
    }
    const empty = await readBrowserWallet();
    assert.equal(empty.state, null);
    assert.equal(empty.journal, null);
    assert.equal(empty.lease, null);
    assert.equal(runtime.activeLease, null);
    await writeBrowserWallet({ deploymentId: DEPLOYMENT, state: { ...state(8), expiry_ts: EXPIRY_TS + 1 } });
    const rows = (await readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    assert.equal(rows.length, 2);
    assert.equal(rows.find(row => row.noteId === 7).expiryClaim.transactionHash, HASH);
    assertSanitized(rows);
});


function quoteRuntime() {
    const runtime = makeRuntime();
    runtime.config.funding = { billing_asset: 'native_eth', chain_id: 11155111, contract_address: `0x${'22'.repeat(20)}` };
    let generation = 0;
    runtime.worker = { call: async operation => {
        assert.equal(operation, 'generateDeposit');
        return { secret: `private-note-secret-${++generation}`, registration_commitment: `0x${generation}` };
    } };
    // nextNoteId() through the pinned RPC, when the caller read none.
    runtime.vaultWord = async data => {
        assert.equal(data, '0x7a2043a3');
        return 1n;
    };
    runtime.prewarmRequestProver = async () => {};
    return runtime;
}

test('prefunding drafts persist and rebase across reload without pending deposits, payment history or secret regeneration', async () => {
    const first = quoteRuntime();
    const draft = await first.prepareDepositQuote(123, 1n);
    assert.equal((await readBrowserWallet()).depositQuote.operationId, draft.operationId);
    assert.equal((await readBrowserWallet()).pendingDeposit, null);
    assert.equal(first.snapshot().config.pending_deposit, null);
    assert.equal(first.snapshot().deposits.length, 0);
    const reloaded = quoteRuntime();
    reloaded.worker.call = () => assert.fail('Reusing a quote must not generate a second note');
    const refreshed = await reloaded.prepareDepositQuote(123, 2n);
    assert.equal(refreshed.operationId, draft.operationId);
    assert.equal(refreshed.secret, draft.secret);
    assert.equal(refreshed.commitment, draft.commitment);
    assert.equal(refreshed.next_note_id, 2);
    assert.equal('active_root' in refreshed || 'zero_path' in refreshed, false, 'a deposit carries no path');
    assert.equal((await readBrowserWallet()).pendingDeposit, null);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits.length, 0);
});

test('changing a quote amount atomically replaces only the draft and rejects an old explicit action', async () => {
    const runtime = quoteRuntime();
    const first = await runtime.prepareDepositQuote(123, 1n);
    const replacement = await runtime.prepareDepositQuote(456, 2n);
    assert.notEqual(first.operationId, replacement.operationId);
    assert.notEqual(first.secret, replacement.secret);
    await assert.rejects(runtime.prepareDeposit(123, { preparedOperationId: first.operationId }), /changed in another tab/);
    assert.equal((await readBrowserWallet()).pendingDeposit, null);
    const promoted = await runtime.prepareDeposit(456, { preparedOperationId: replacement.operationId });
    assert.equal(promoted.operationId, replacement.operationId);
    assert.equal(promoted.secret, replacement.secret);
    assert.equal(promoted.phase, 'prepared');
    assert.equal((await readBrowserWallet()).depositQuote, null);
    await assert.rejects(runtime.prepareDeposit(123, { preparedOperationId: replacement.operationId }), /amount does not match/);
    assert.equal((await runtime.prepareDepositQuote(456, 2n)).operationId, replacement.operationId);
    await assert.rejects(runtime.prepareDepositQuote(123, 2n), /amount is fixed/);
    assert.equal((await readBrowserWallet()).pendingDeposit.amount, 456);
});

test('concurrent tabs cannot promote a superseded quote or refresh and claim a different deposit', async () => {
    const first = quoteRuntime();
    const second = quoteRuntime();
    const [older, newer] = await Promise.all([first.prepareDepositQuote(123, 1n), second.prepareDepositQuote(456, 2n)]);
    await assert.rejects(first.prepareDeposit(123, { preparedOperationId: older.operationId }), /changed in another tab/);
    const current = await second.prepareDeposit(456, { preparedOperationId: newer.operationId });
    await assert.rejects(first.refreshPendingDeposit(456, 2n, { expectedOperationId: older.operationId }), /changed in another tab/);
    await assert.rejects(first.claimPendingDepositSubmission(older.operationId), /changed in another tab/);
    const claimed = await second.claimPendingDepositSubmission(current.operationId);
    assert.equal(claimed.plan.secret, newer.secret);
    assert.equal(claimed.plan.next_note_id, newer.next_note_id);
    assert.equal((await readBrowserWallet()).pendingDeposit.submissionId, claimed.submissionId);
    await assert.rejects(first.claimPendingDepositSubmission(current.operationId), /already awaiting/);
});

test('an ordinary wallet deposit discards an unused address quote and active notes never prepare another quote', async () => {
    const runtime = quoteRuntime();
    const draft = await runtime.prepareDepositQuote(123, 1n);
    const ordinary = await runtime.prepareDeposit(123);
    assert.notEqual(ordinary.operationId, draft.operationId);
    assert.equal((await readBrowserWallet()).depositQuote, null);
    await assert.rejects(runtime.prepareDeposit(123, { preparedOperationId: draft.operationId }), /changed in another tab/);
    seedRuntime({ state: state() });
    await assert.rejects(runtime.prepareDepositQuote(456, 2n), /Recover/);
});

test('actual receipt fee and funding account survive reload and closure without becoming private history', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = makeRuntime();
    const fee = { transactionHash: HASH, feeWei: '123000000000', gasUsed: '123', effectiveGasPrice: '1000000000',
        fundingAddress: `0x${'11'.repeat(20)}`, receiptBlockNumber: 1234, receiptBlockHash: `0x${'22'.repeat(32)}` };
    await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH, receiptMetadata: fee }));
    const original = runtime.snapshot().deposits[0];
    for (const [key, value] of Object.entries(fee)) assert.equal(original[key], value);
    assertSanitized([original]);
    const reloaded = makeRuntime();
    await reloaded.reload();
    assert.deepEqual(reloaded.snapshot().deposits[0], original);
    await archiveBrowserWallet('closed', 7);
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).deposits[0], original);
});

test('incomplete or arithmetically invalid fee metadata is omitted instead of displayed as zero', async () => {
    for (const fee of [null, { feeWei: '0' }, { transactionHash: HASH, feeWei: '12', gasUsed: '123', effectiveGasPrice: '1000000000',
        fundingAddress: `0x${'11'.repeat(20)}`, receiptBlockNumber: 1234, receiptBlockHash: `0x${'22'.repeat(32)}` }]) {
        indexedDB.clear();
        seedRuntime({ pendingDeposit: plan() });
        const runtime = makeRuntime();
        await runtime.confirmDeposit(confirmArgs({ transactionHash: HASH, receiptMetadata: fee }));
        assert.equal(runtime.snapshot().deposits[0].feeWei, undefined);
        assert.equal(runtime.snapshot().deposits[0].fundingAddress, undefined);
    }
});


test('a proven pre-broadcast failure can refresh its funding quote without changing the pending operation', async () => {
    const runtime = quoteRuntime();
    const draft = await runtime.prepareDepositQuote(123, 1n);
    await runtime.prepareDeposit(123, { preparedOperationId: draft.operationId });
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, true);
    const claim = await runtime.claimPendingDepositSubmission(draft.operationId);
    await runtime.rememberPendingDepositSubmissionMetadata(claim, { from: `0x${'11'.repeat(20)}`, nonce: 0 });
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, false);
    await assert.rejects(runtime.prepareDepositQuote(123, 2n), /Recover/);
    await runtime.markPendingDepositRetryable(null, claim);
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, true);
    const fresh = await runtime.prepareDepositQuote(123, 2n);
    assert.equal(fresh.operationId, draft.operationId);
    assert.equal(fresh.secret, draft.secret);
    assert.equal(fresh.commitment, draft.commitment);
    assert.equal(fresh.next_note_id, 2);
    assert.equal((await readBrowserWallet()).depositQuote, null);
    assert.equal((await runtime.prepareDeposit(123, { preparedOperationId: draft.operationId })).operationId, draft.operationId);
});

test('signed, ambiguous, legacy, exact-retry and uncertain prepared attempts never become funding quotes', async () => {
    for (const change of [
        { phase: 'submitted', transactionHash: HASH },
        { phase: 'ambiguous' }, { phase: 'retry_exact' },
        { phase: 'prepared', submissionId: 'claim' },
        { phase: 'prepared', transactionHashes: [HASH] },
        { phase: 'prepared', transactionAttempts: [{ hash: HASH }] },
        { phase: 'prepared', ambiguousSubmissions: [{ submissionId: 'old' }] },
        { phase: 'prepared', legacyRecovery: true },
        { phase: 'prepared', submissionFrom: `0x${'11'.repeat(20)}`, submissionNonce: 0 }
    ]) {
        indexedDB.clear();
        seedRuntime({ pendingDeposit: plan({ transactionHash: null, ...change }) });
        const runtime = quoteRuntime();
        await runtime.reload();
        assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, false);
        await assert.rejects(runtime.prepareDepositQuote(2_000_000, 2n), /Recover/);
        assert.deepEqual((await readBrowserWallet()).pendingDeposit, plan({ transactionHash: null, ...change }));
    }
});

test('explicit retry fee review keeps the exact uncertain calldata across quotes and pre-broadcast failures', async () => {
    const runtime = quoteRuntime();
    const pending = plan({ transactionHash: null, phase: 'ambiguous', submissionId: 'unknown-send',
        submissionFrom: `0x${'11'.repeat(20)}`, submissionNonce: 0 });
    seedRuntime({ pendingDeposit: pending });
    await assert.rejects(runtime.prepareDepositQuote(pending.amount, 999n), /Recover/);
    const authorized = await runtime.authorizePendingDepositRetry({ forFundingQuote: true });
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, true);
    runtime.vaultWord = async () => assert.fail('Uncertain exact retry must never rebase its slot');
    const quoted = await runtime.prepareDepositQuote(pending.amount, 999n);
    assert.deepEqual(quoted, authorized);
    assert.equal(quoted.next_note_id, pending.next_note_id);
    assert.equal((await runtime.prepareDeposit(pending.amount, { preparedOperationId: pending.operationId })).phase, 'retry_exact');
    const claim = await runtime.claimPendingDepositSubmission(pending.operationId, { from: `0x${'11'.repeat(20)}` });
    assert.equal(claim.plan.phase, 'awaiting_wallet');
    assert.equal(claim.retryNonce, 0, 'the retry reuses the unknown send\'s nonce');
    await runtime.markPendingDepositRetryable(null, claim);
    assert.equal((await readBrowserWallet()).pendingDeposit.phase, 'retry_exact');
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, true);
    assert.equal((await runtime.prepareDepositQuote(pending.amount, 123n)).next_note_id, pending.next_note_id);
    assert.equal((await readBrowserWallet()).pendingDeposit.ambiguousSubmissions[0].submissionId, 'unknown-send');
});

test('an existing exact retry needs an explicit fee review before it can be quoted', async () => {
    const runtime = quoteRuntime();
    const pending = plan({ transactionHash: null, phase: 'retry_exact', legacyRecovery: true,
        ambiguousSubmissions: [{ submissionId: 'old-unknown-send', from: `0x${'11'.repeat(20)}`, nonce: 3 }],
        retryFrom: `0x${'11'.repeat(20)}`, retryNonce: 3 });
    seedRuntime({ pendingDeposit: pending });
    await runtime.reload();
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, false);
    await assert.rejects(runtime.prepareDepositQuote(pending.amount, 1n), /Recover/);
    await runtime.authorizePendingDepositRetry({ forFundingQuote: true });
    assert.equal(runtime.snapshot().config.pending_deposit.funding_quote_available, true);
    runtime.vaultWord = async () => assert.fail('Do not rebase a legacy exact retry');
    assert.equal((await runtime.prepareDepositQuote(pending.amount, 999n)).next_note_id, pending.next_note_id);
});

test('an unresolved late callback blocks both prepared and authorized exact funding quotes', async () => {
    const runtime = quoteRuntime();
    for (const phase of ['prepared', 'retry_exact']) {
        const pending = plan({ transactionHash: null, phase, fundingQuoteRetryAuthorized: true,
            ...(phase === 'retry_exact' ? { ambiguousSubmissions: [{ submissionId: 'old', from: `0x${'11'.repeat(20)}`, nonce: 3 }],
                retryFrom: `0x${'11'.repeat(20)}`, retryNonce: 3 } : {}) });
        seedRuntime({ pendingDeposit: pending, lateDepositAttempts: [{ operationId: pending.operationId,
            status: 'submitted_late', transactionHash: HASH }] });
        await runtime.reload();
        assert.equal(runtime.canQuotePendingDeposit(pending), false);
        await assert.rejects(runtime.prepareDepositQuote(pending.amount, 999n), /Recover/);
        if (phase === 'retry_exact') await assert.rejects(runtime.authorizePendingDepositRetry({ forFundingQuote: true }), /unresolved/);
    }
});

test('legacy or token wallet state cannot be relabeled as a native ETH wallet', async () => {
    for (const legacy of [
        { deploymentId: null },
        { deploymentId: OTHER_DEPLOYMENT },
        { billingAsset: 'erc20' }
    ]) {
        seedRuntime({ state: state(), ...legacy });
        const before = clone(indexedDB.stores.get('runtime').get('active'));
        const runtime = makeRuntime();
        await assert.rejects(runtime.reload(), /Switch back to that deployment/);
        assert.deepEqual(indexedDB.stores.get('runtime').get('active'), before);
        assert.equal(runtime.runtime, null);
    }
});

// Phase D item 1: the background reconcile (15 s interval, window focus when
// the MetaMask popup closes) can confirm the pending deposit from the vault
// while the foreground waits for its receipt. Both orders are the same single
// confirmation; only a different note refuses.
const RECEIPT_METADATA = {
    transactionHash: HASH, fundingAddress: `0x${'34'.repeat(20)}`,
    feeWei: String(21_000n * 1_000_000_000n), gasUsed: '21000', effectiveGasPrice: '1000000000',
    receiptBlockNumber: 42, receiptBlockHash: BLOCK_HASH
};


function raceRuntime() {
    const runtime = makeRuntime();
    // The real wasm state names the note secret `secret_s`.
    runtime.worker = { call: async (method, payload) => {
        assert.equal(method, 'confirmDeposit');
        return { ...state(payload.args.note_id, payload.args.amount), secret_s: payload.args.secret };
    } };
    return runtime;
}

function raceClient(t, runtime) {
    const client = confirmationClient(t, runtime);
    t.mock.method(singleton, 'walletStatus', async () => ({ has_note: Boolean(runtime.runtime.state) }));
    t.mock.method(singleton, 'pendingDeposit', runtime.pendingDeposit.bind(runtime));
    t.mock.method(singleton, 'treePath', async () => assert.fail('a deposit confirmation waits for no tree'));
    t.mock.method(singleton, 'refreshExitCost', async () => null);
    return client;
}

function gate() {
    let open;
    const opened = new Promise(resolve => { open = resolve; });
    return { opened, open };
}

test('a background vault recovery that confirms first leaves the foreground receipt confirmation successful and fills in its receipt', async t => {
    // The vault recovery cannot know the mined hash: the saved one was replaced.
    seedRuntime({ pendingDeposit: plan() });
    const runtime = raceRuntime();
    const client = raceClient(t, runtime);
    const receiptRead = gate();
    const metadataHeld = gate();
    t.mock.method(client, 'readDepositReceiptMetadata', async (_plan, receipt) => {
        if (receipt.transactionHash !== HASH) return null;
        receiptRead.open();
        await metadataHeld.opened;
        return { ...RECEIPT_METADATA };
    });
    const { vault, receipt } = depositReceipt();
    const statuses = [];
    // Foreground: the receipt arrived; its metadata read is held open.
    const foreground = client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message));
    await receiptRead.opened;
    // Background: the reconcile confirms the same note from the vault.
    const recovered = await client.recoverBrowserDeposit(() => {});
    assert.equal(recovered.status, 'confirmed');
    const recoveredRow = runtime.snapshot().deposits.find(row => row.noteId === 7);
    assert.equal(recoveredRow.transactionHash, null, 'the vault recovery could not know the mined hash');
    assert.equal(recoveredRow.feeWei, undefined);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.state.registration_commitment, '0x123',
        'the vault recovery saves the registration commitment the vault recorded');
    const confirmedAt = recoveredRow.confirmedAt;
    metadataHeld.open();
    const result = await foreground;
    assert.equal(result.status, 'confirmed');
    assert.equal(result.balanceRefreshPending, false);
    assert.equal(result.noteId, 7);
    assert.equal(result.amount, 2_000_000);
    assert.equal(result.transactionHash, HASH);
    assert.equal(statuses.at(-1), 'Private balance is ready.');
    assert.equal(client.lastError, null);
    assert.equal(client.config.pending_deposit, null);
    assert.equal(client.wallet.has_note, true);
    // One confirmed row, now carrying the receipt the foreground saw.
    const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(persisted.runtime.pendingDeposit, null);
    assert.equal(persisted.runtime.state.note_id, 7);
    assert.equal(persisted.runtime.state.registration_commitment, '0x123');
    assert.equal(persisted.deposits.length, 1);
    const row = persisted.deposits[0];
    assert.equal(row.status, 'confirmed');
    assert.equal(row.operationId, 'deposit-operation');
    assert.equal(row.transactionHash, HASH);
    assert.equal(row.feeWei, RECEIPT_METADATA.feeWei);
    assert.equal(row.receiptBlockHash, BLOCK_HASH);
    assert.equal(row.createdAt, 1000);
    assert.equal(row.confirmedAt, confirmedAt, 'the first confirmation time is kept');
    assert.deepEqual(client.deposits, persisted.deposits);
    assertSanitized(persisted.deposits);
});

test('a background recovery after the foreground confirmed is a no-op, also when it read the plan before the commit', async t => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = raceRuntime();
    const client = raceClient(t, runtime);
    t.mock.method(client, 'readDepositReceiptMetadata', async (_plan, receipt) =>
        receipt.transactionHash === HASH ? { ...RECEIPT_METADATA } : null);
    // The background read the pending plan and is checking the vault; the
    // foreground's own notes() read answers at once.
    const noteRead = gate();
    const noteHeld = gate();
    let backgroundRead = true;
    client.readBrowserNote.mock.mockImplementation(async () => {
        if (backgroundRead) {
            backgroundRead = false;
            noteRead.open();
            await noteHeld.opened;
        }
        return { status: 1, amount: 2_000_000n, commitment: '0x123', expiryTs: 9999 };
    });
    const background = client.recoverBrowserDeposit(() => {});
    await noteRead.opened;
    const { vault, receipt } = depositReceipt();
    const result = await client.confirmBrowserDepositReceipt(plan(), receipt, vault, () => {});
    assert.equal(result.status, 'confirmed');
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.state.registration_commitment, '0x123');
    const confirmed = (await readBrowserWalletSnapshot(DEPLOYMENT)).deposits;
    assert.equal(confirmed[0].transactionHash, HASH);
    noteHeld.open();
    assert.equal((await background).status, 'confirmed');
    // Sequential order: nothing pending, nothing read, nothing written.
    client.readBrowserNote.mock.mockImplementation(async () => { throw new Error('no vault read expected'); });
    assert.equal(await client.recoverBrowserDeposit(() => {}), null);
    const after = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.deepEqual(after.deposits, confirmed);
    assert.equal(after.runtime.state.note_id, 7);
    assert.equal(after.runtime.state.registration_commitment, '0x123');
    assert.equal(after.runtime.pendingDeposit, null);
});

// The vault numbers a note when its deposit is included: a deposit another
// one overtook is recorded after the slot predicted from nextNoteId().
function overtakenReceipt(noteId = 9) {
    const { vault, receipt } = depositReceipt();
    receipt.logs[0].topics[1] = `0x${abiWord(noteId)}`;
    return { vault, receipt };
}
const recordOf = (noteId, changes = {}) => ({ noteId, status: 1, amount: 2_000_000n, commitment: '0x123', expiryTs: 9999, ...changes });

test('a deposit another one overtook is confirmed at the note id its receipt names, once the vault records it there', async t => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = raceRuntime();
    const client = raceClient(t, runtime);
    const reads = [];
    client.readBrowserNote.mock.mockImplementation(async noteId => {
        reads.push(Number(noteId));
        return Number(noteId) === 9 ? recordOf(9) : recordOf(Number(noteId), { commitment: '0x999' });
    });
    t.mock.method(client, 'readDepositReceiptMetadata', async () => ({ ...RECEIPT_METADATA }));
    singleton.refreshActivation.mock.mockImplementation(async () => ({ note_id: 9, status: 'activating', activated: false,
        activation_cursor: 7, queue_position: 2 }));
    const { vault, receipt } = overtakenReceipt(9);
    const statuses = [];
    const result = await client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message));
    assert.equal(result.status, 'confirmed');
    assert.equal(result.noteId, 9);
    assert.deepEqual(reads, [9], 'the receipt\'s note record is the one checked');
    assert.equal(result.activation.status, 'activating');
    assert.equal(statuses.at(-1),
        'Deposit confirmed. Private chats start once the vault activates this balance (2 deposits ahead in the queue); it can already be withdrawn.');
    const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(persisted.runtime.state.note_id, 9);
    assert.equal(persisted.runtime.pendingDeposit, null);
    assert.equal(persisted.deposits[0].noteId, 9);
});

test('a deposit confirmed while the vault is paused says that activation and withdrawals wait for the pause', async t => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = raceRuntime();
    const client = raceClient(t, runtime);
    client.readBrowserNote.mock.mockImplementation(async noteId => recordOf(Number(noteId)));
    t.mock.method(client, 'readDepositReceiptMetadata', async () => ({ ...RECEIPT_METADATA }));
    singleton.refreshActivation.mock.mockImplementation(async () => ({ note_id: 7, status: 'activating', activated: false,
        activation_cursor: 7, queue_position: 0, vault_paused: true, exits_reopen_at: null }));
    const { vault, receipt } = depositReceipt();
    const statuses = [];
    const result = await client.confirmBrowserDepositReceipt(plan(), receipt, vault, message => statuses.push(message));
    assert.equal(result.status, 'confirmed');
    assert.equal(statuses.at(-1), 'Deposit confirmed. The vault is paused by its owner, so private chats start only once it is '
        + 'unpaused and activates this balance. Withdrawals reopen at the latest when its pause limit ends.');
});

test('a receipt whose vault record is another note, or not visible yet, confirms nothing', async t => {
    for (const [label, record, expected] of [
        ['not visible yet', recordOf(9, { status: 0, commitment: `0x${'0'.repeat(64)}`, amount: 0n }), /latest vault read has not caught up/],
        ['another commitment', recordOf(9, { commitment: '0x999' }), /record of the mined deposit does not match/],
        ['another expiry', recordOf(9, { expiryTs: 10_000 }), /record of the mined deposit does not match/],
        ['no longer active', recordOf(9, { status: 3 }), /no longer active/]
    ]) {
        indexedDB.clear();
        seedRuntime({ pendingDeposit: plan() });
        const runtime = raceRuntime();
        const client = raceClient(t, runtime);
        client.readBrowserNote.mock.mockImplementation(async () => record);
        const { vault, receipt } = overtakenReceipt(9);
        await assert.rejects(client.confirmBrowserDepositReceipt(plan(), receipt, vault, () => {}), expected, label);
        const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
        assert.equal(persisted.runtime.pendingDeposit.operationId, 'deposit-operation', `${label}: still pending`);
        assert.equal(persisted.runtime.state ?? null, null, label);
    }
});

test('recovery finds an overtaken deposit through its receipt instead of treating its predicted slot as taken', async t => {
    seedRuntime({ pendingDeposit: plan({ transactionHash: HASH }) });
    const runtime = raceRuntime();
    const client = raceClient(t, runtime);
    t.mock.method(singleton, 'pendingDeposit', async () => plan({ transactionHash: HASH }));
    client.readBrowserNote.mock.mockImplementation(async noteId =>
        Number(noteId) === 9 ? recordOf(9) : recordOf(Number(noteId), { commitment: '0x999' }));
    t.mock.method(client, 'readDepositReceiptMetadata', async () => ({ ...RECEIPT_METADATA }));
    t.mock.method(client, 'findDepositNote', async () => assert.fail('the receipt names the note'));
    const { receipt } = overtakenReceipt(9);
    client.config = { ...runtime.config, funding: { ...runtime.config.funding, contract_address: depositReceipt().vault } };
    client.setWalletProvider({ request: async ({ method, params }) => {
        assert.equal(method, 'eth_getTransactionReceipt');
        assert.equal(params[0], HASH);
        return receipt;
    } });
    const statuses = [];
    const result = await client.recoverBrowserDeposit(message => statuses.push(message));
    assert.equal(result.status, 'confirmed');
    assert.equal(result.noteId, 9);
    assert.equal(result.receipt, receipt);
    assert.equal(statuses.at(-1), 'Deposit recovered. Private balance is ready.');
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.state.note_id, 9);
});

// Without a readable receipt (the transaction still pending, replaced by a
// wallet speed-up, or a failed read) a deposit whose predicted slot another
// one took may still be included at a later id. It stays pending until its
// nonce went to another transaction, and is found there by its commitment.
const FROM = `0x${'34'.repeat(20)}`;
const FINALIZED = '0x64';
const unrecorded = noteId => recordOf(noteId, { status: 0, amount: 0n, commitment: `0x${'0'.repeat(64)}` });

function pendingRecoveryClient(t, chain, pending = {}) {
    seedRuntime({ pendingDeposit: plan({ transactionHash: HASH, transactionHashes: [HASH],
        transactionAttempts: [{ hash: HASH, from: FROM, nonce: 5 }], ...pending }) });
    const runtime = raceRuntime();
    runtime.config.funding = { ...runtime.config.funding, contract_address: depositReceipt().vault };
    const client = raceClient(t, runtime);
    client.config = runtime.config;
    t.mock.method(singleton, 'markPendingDepositRetryable', runtime.markPendingDepositRetryable.bind(runtime));
    t.mock.method(singleton, 'markPendingDepositMissingReceipts', runtime.markPendingDepositMissingReceipts.bind(runtime));
    t.mock.method(singleton, 'rememberPendingDepositSearch', runtime.rememberPendingDepositSearch.bind(runtime));
    t.mock.method(client, 'readDepositReceiptMetadata', async () => ({ ...RECEIPT_METADATA }));
    chain.reads = [];
    chain.calls = [];
    client.readBrowserNote.mock.mockImplementation(async (noteId, blockTag = 'latest') => {
        chain.reads.push([Number(noteId), blockTag]);
        return chain.note(Number(noteId), blockTag);
    });
    client.setWalletProvider({ request: async ({ method, params }) => {
        chain.calls.push(method);
        if (method === 'eth_getTransactionReceipt') {
            assert.equal(params[0], HASH);
            return chain.receipt;
        }
        if (method === 'eth_getBlockByNumber') return { number: FINALIZED };
        if (method === 'eth_getTransactionCount') {
            assert.deepEqual(params, [FROM, FINALIZED]);
            return chain.transactionCount;
        }
        return assert.fail(`unexpected wallet call ${method}`);
    } });
    return { runtime, client };
}

test('a receipt-less deposit overtaken at its predicted slot stays pending and is confirmed where it is later recorded', async t => {
    // Its mined receipt becomes readable, or never does (a speed-up replaced the saved hash).
    for (const receiptReadable of [true, false]) {
        indexedDB.clear();
        const chain = { receipt: null, transactionCount: '0x5', mined: false };
        // Another deposit took slots 7 and 8 (finalized); this one is still in the mempool.
        chain.note = noteId => noteId < 9 ? recordOf(noteId, { commitment: '0x999' })
            : noteId === 9 && chain.mined ? recordOf(9) : unrecorded(noteId);
        const { client } = pendingRecoveryClient(t, chain);
        const first = await client.recoverBrowserDeposit(() => {});
        assert.equal(first.status, 'dropped_or_pending');
        assert.equal(first.transactionHash, HASH);
        let persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
        assert.deepEqual(persisted.runtime.pendingDeposit.transactionHashes, [HASH], 'the hash is kept while its nonce is unused');
        assert.equal(persisted.runtime.pendingDeposit.transactionAttempts.length, 1);
        assert.equal(persisted.runtime.pendingDeposit.secret, 'private-note-secret');
        assert.equal(persisted.runtime.state ?? null, null);
        assert.deepEqual(chain.reads.filter(([, blockTag]) => blockTag === FINALIZED).map(([noteId]) => noteId), [7, 8, 9, 9],
            'the finalized records from the predicted slot on are searched, and the nonce check resumes after them');
        assert.equal(persisted.runtime.pendingDeposit.noteSearchFrom, 9, 'the plan keeps where the finalized search stopped');
        chain.reads = [];

        // The transaction is included after another deposit: note 9.
        chain.mined = true;
        chain.transactionCount = '0x6';
        if (receiptReadable) chain.receipt = overtakenReceipt(9).receipt;
        const second = await client.recoverBrowserDeposit(() => {});
        assert.equal(second.status, 'confirmed', `receipt readable: ${receiptReadable}`);
        assert.equal(second.noteId, 9);
        persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
        assert.equal(persisted.runtime.state.note_id, 9);
        assert.equal(persisted.runtime.pendingDeposit, null);
        assert.equal(persisted.deposits.length, 1);
        assert.equal(persisted.deposits[0].noteId, 9);
        assert.equal(persisted.deposits[0].transactionHash, receiptReadable ? HASH : null);
        if (!receiptReadable) {
            assert.deepEqual(chain.reads, [[7, 'latest'], [9, FINALIZED], [9, 'latest']],
                'the second search starts where the first stopped');
        }
    }
});

test('a saved deposit transaction is given up only once its nonce went to another transaction by finality', async t => {
    // The nonce was used and the vault recorded no note of this deposit by
    // the finalized block (a cancel): only then is the hash released.
    const chain = { receipt: null, transactionCount: '0x6' };
    chain.note = noteId => noteId === 7 ? recordOf(7, { commitment: '0x999' }) : unrecorded(noteId);
    const { client } = pendingRecoveryClient(t, chain);
    const released = await client.recoverBrowserDeposit(() => {});
    assert.equal(released.status, 'prepared');
    const persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(persisted.runtime.pendingDeposit.phase, 'prepared');
    assert.equal(persisted.runtime.pendingDeposit.transactionHashes, undefined);
    assert.equal(persisted.runtime.pendingDeposit.secret, 'private-note-secret');
    assert.deepEqual(chain.reads.filter(([, blockTag]) => blockTag === FINALIZED).map(([noteId]) => noteId), [7, 8, 8],
        'the finalized search reads from the predicted slot to the first unrecorded id; the nonce check resumes there');

    // A used nonce whose transaction recorded this deposit at a later id is
    // not given up, whatever holds the predicted slot.
    for (const [label, note, transactionCount, consumed] of [
        ['recorded after the slot', id => id === 8 ? recordOf(8) : id < 8 ? recordOf(id, { commitment: '0x999' }) : unrecorded(id), '0x6', false],
        ['nonce unused', id => id === 7 ? recordOf(7, { commitment: '0x999' }) : unrecorded(id), '0x5', false],
        ['slot taken, never recorded', id => id === 7 ? recordOf(7, { commitment: '0x999' }) : unrecorded(id), '0x6', true]
    ]) {
        chain.note = note;
        chain.transactionCount = transactionCount;
        const status = await client.browserDepositNonceConsumed({ from: FROM, nonce: 5 }, plan());
        assert.equal(status.consumed, consumed, label);
        assert.equal(status.checkedBlock, 100, label);
    }
});

// 2,000 other deposits were recorded after the predicted slot 7.
const OTHERS_END = 7 + 2_000;

test('a search for an overtaken deposit\'s note reads a bounded run of records per pass and goes on where it stopped', async t => {
    // The deposit was recorded far after its slot, and no receipt is readable.
    const chain = { receipt: null, transactionCount: '0x6' };
    chain.note = noteId => noteId === 1_500 ? recordOf(1_500) : noteId < OTHERS_END
        ? recordOf(noteId, { commitment: '0x999' }) : unrecorded(noteId);
    const { client } = pendingRecoveryClient(t, chain);
    const first = await client.recoverBrowserDeposit(() => {});
    assert.equal(first.status, 'dropped_or_pending');
    assert.equal(chain.reads.length, 1 + 1_024, 'the predicted slot, then at most 1,024 finalized records');
    assert.ok(!chain.calls.includes('eth_getTransactionCount'), 'a search behind the finalized records gives nothing up');
    let persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.deepEqual(persisted.transactionHashes, [HASH]);
    assert.equal(persisted.noteSearchFrom, 7 + 1_024);

    chain.reads = [];
    const second = await client.recoverBrowserDeposit(() => {});
    assert.equal(second.status, 'confirmed');
    assert.equal(second.noteId, 1_500);
    assert.deepEqual(chain.reads[1], [7 + 1_024, FINALIZED], 'the second pass reads no record twice');
    persisted = await readBrowserWalletSnapshot(DEPLOYMENT);
    assert.equal(persisted.runtime.state.note_id, 1_500);
    assert.equal(persisted.runtime.pendingDeposit, null);
});

test('a cancelled deposit transaction is given up however many deposits followed its slot', async t => {
    // Its nonce went to another transaction, and the vault never recorded it.
    const chain = { receipt: null, transactionCount: '0x6' };
    chain.note = noteId => noteId < OTHERS_END ? recordOf(noteId, { commitment: '0x999' }) : unrecorded(noteId);
    const { client } = pendingRecoveryClient(t, chain);
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'dropped_or_pending');
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit.transactionHashes, [HASH]);
    assert.equal((await client.browserDepositNonceConsumed({ from: FROM, nonce: 5 }, plan())).consumed, false,
        'a nonce check whose search stops short gives nothing up');
    const released = await client.recoverBrowserDeposit(() => {});
    assert.equal(released.status, 'prepared');
    const persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.phase, 'prepared');
    assert.equal(persisted.transactionHashes, undefined);
    assert.equal(persisted.noteSearchFrom, OTHERS_END);
    assert.equal(persisted.secret, 'private-note-secret');
});

test('a never-broadcast deposit plan is not searched for, and is rebased however many deposits followed its slot', async t => {
    // A wallet rejection left it prepared: no hash, attempt or submission.
    const chain = { receipt: null, transactionCount: '0x6' };
    chain.note = noteId => noteId < OTHERS_END ? recordOf(noteId, { commitment: '0x999' }) : unrecorded(noteId);
    const { runtime, client } = pendingRecoveryClient(t, chain, { phase: 'prepared', transactionHash: undefined,
        transactionHashes: undefined, transactionAttempts: undefined });
    assert.deepEqual(await client.recoverBrowserDeposit(() => {}), { status: 'prepared' });
    assert.deepEqual(chain.reads, [[7, 'latest']], 'only the predicted slot is read');
    assert.deepEqual(chain.calls, [], 'no receipt, finality or nonce is read');
    const rebased = await runtime.refreshPendingDeposit(2_000_000, OTHERS_END, { expectedOperationId: 'deposit-operation' });
    assert.equal(rebased.next_note_id, OTHERS_END);
    assert.equal(rebased.commitment, '0x123');
});

test('another deposit taking the predicted slot resolves no unknown wallet submission', async t => {
    const chain = { receipt: null, transactionCount: '0x6' };
    chain.note = noteId => noteId === 7 ? recordOf(7, { commitment: '0x999' }) : unrecorded(noteId);
    const pending = { transactionHash: null, transactionHashes: undefined, transactionAttempts: undefined,
        phase: 'ambiguous', submissionId: 'unknown-send' };
    const { runtime, client } = pendingRecoveryClient(t, chain, pending);
    const result = await client.recoverBrowserDeposit(() => {});
    assert.equal(result.status, 'ambiguous');
    const persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.phase, 'ambiguous', 'the unknown send may still be included at a later id');
    assert.equal(persisted.submissionId, 'unknown-send');
    assert.equal(persisted.next_note_id, 7);
    assert.equal(persisted.resolvedAmbiguousSubmissionIds, undefined);
    assert.equal(runtime.canQuotePendingDeposit(persisted), false);
});

// deposit(bytes32,uint128) records a repeated commitment as another note, so
// an explicit retry of an unknown send must not be able to execute beside it.
const OTHER_ACCOUNT = `0x${'56'.repeat(20)}`;

function retryRecoveryClient(t, chain, pending) {
    const harness = pendingRecoveryClient(t, chain, { transactionHash: null, transactionHashes: undefined,
        transactionAttempts: undefined, ...pending });
    const { runtime, client } = harness;
    t.mock.method(singleton, 'resolvePendingDepositRetryNonce', runtime.resolvePendingDepositRetryNonce.bind(runtime));
    t.mock.method(singleton, 'authorizePendingDepositRetry', runtime.authorizePendingDepositRetry.bind(runtime));
    t.mock.method(client, 'deposit', async () => 'retry-sent');
    // The wallet's pending count says whether a transaction holds the nonce.
    client.setWalletProvider({ request: async ({ method, params }) => {
        chain.calls.push(method);
        if (method === 'eth_getBlockByNumber') return { number: FINALIZED };
        if (method === 'eth_getTransactionCount') {
            assert.equal(params[0], FROM);
            return params[1] === 'pending' ? chain.pendingCount : chain.transactionCount;
        }
        return assert.fail(`unexpected wallet call ${method}`);
    } });
    return harness;
}

test('an explicit retry of an unknown send reuses its sender and nonce, so both cannot be recorded', async t => {
    // The provider accepted the send at nonce 5 but returned no hash.
    const chain = { transactionCount: '0x5', pendingCount: '0x6' };
    chain.note = noteId => unrecorded(noteId);
    const { runtime, client } = retryRecoveryClient(t, chain, { phase: 'ambiguous', submissionId: 'unknown-send',
        submissionFrom: FROM, submissionNonce: 5 });
    // A transaction at nonce 5 is still pending: no retry or retry fee review is authorized.
    await assert.rejects(client.retryUnknownDeposit(() => {}), error => /nonce 5 .* may still be pending/.test(error.message)
        && error.broadcastPossible === false);
    await assert.rejects(client.prepareDepositRetry(() => {}), /nonce 5 .* may still be pending/);
    let persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.phase, 'ambiguous');
    assert.equal(persisted.submissionId, 'unknown-send');
    assert.equal(persisted.submissionNonce, 5);

    // The wallet holds nothing at nonce 5 any more: the retry is pinned to it.
    chain.pendingCount = '0x5';
    assert.equal(await client.retryUnknownDeposit(() => {}), 'retry-sent');
    persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.phase, 'retry_exact');
    assert.equal(persisted.retryFrom, FROM);
    assert.equal(persisted.retryNonce, 5);
    assert.deepEqual(persisted.ambiguousSubmissions.map(({ submissionId, from, nonce }) => ({ submissionId, from, nonce })),
        [{ submissionId: 'unknown-send', from: FROM, nonce: 5 }]);
    assert.equal(persisted.resolvedAmbiguousSubmissionIds, undefined);

    // Another account cannot send it, and nothing is claimed.
    await assert.rejects(runtime.claimPendingDepositSubmission(persisted.operationId, { from: OTHER_ACCOUNT }),
        new RegExp(`Connect the MetaMask account ${FROM}`));
    await assert.rejects(runtime.claimPendingDepositSubmission(persisted.operationId), /Connect the MetaMask account/);
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit, persisted);

    const claim = await runtime.claimPendingDepositSubmission(persisted.operationId, { from: FROM });
    assert.equal(claim.retryNonce, 5);
    assert.equal(claim.commitment, '0x123');
    // A fresh nonce would let both sends execute: the wallet request is refused before it is made.
    await assert.rejects(runtime.rememberPendingDepositSubmissionMetadata(claim, { from: FROM, nonce: 6 }), /must reuse nonce 5/);
    await runtime.rememberPendingDepositSubmissionMetadata(claim, { from: FROM, nonce: 5 });

    // A rejected retry prompt keeps the pin for the next attempt.
    await runtime.markPendingDepositRetryable(null, claim);
    persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.submissionId, undefined);
    assert.equal(persisted.retryNonce, 5);
    assert.equal(runtime.canQuotePendingDeposit(persisted), false);
    const again = await runtime.claimPendingDepositSubmission(persisted.operationId, { from: FROM });
    assert.equal(again.retryNonce, 5);
});

test('an unknown send\'s nonce is given up only once it went to another transaction by finality with no note recorded', async t => {
    const chain = { transactionCount: '0x5', pendingCount: '0x6' };
    chain.note = noteId => unrecorded(noteId);
    const { runtime, client } = retryRecoveryClient(t, chain, { phase: 'retry_exact', retryFrom: FROM, retryNonce: 5,
        ambiguousSubmissions: [{ submissionId: 'unknown-send', from: FROM, nonce: 5 }] });
    // Not used at the finalized block: the pin stays.
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'retry_exact');
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit.retryNonce, 5);
    // Used by finality, but this deposit was recorded at note 7: confirmed, not given up.
    chain.transactionCount = '0x6';
    chain.note = noteId => noteId === 7 ? recordOf(7) : unrecorded(noteId);
    const recorded = structuredClone(indexedDB.stores.get('runtime').get('active'));
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'confirmed');
    indexedDB.stores.get('runtime').set('active', recorded);
    await runtime.reload();

    // Used by finality by another transaction, and no note recorded: neither send can execute.
    chain.note = noteId => unrecorded(noteId);
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'retry_exact');
    const persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.retryFrom, undefined);
    assert.equal(persisted.retryNonce, undefined);
    assert.deepEqual(persisted.resolvedAmbiguousSubmissionIds, ['unknown-send']);
    const claim = await runtime.claimPendingDepositSubmission(persisted.operationId, { from: OTHER_ACCOUNT });
    assert.equal(claim.retryNonce, null, 'the retry takes a fresh nonce');
    await runtime.markPendingDepositRetryable(null, claim);
    assert.equal((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit.phase, 'prepared');
    assert.equal(runtime.canQuotePendingDeposit(), true, 'a resolved unknown send no longer blocks a funding quote');
});

test('an unknown send without a saved nonce is retried only when it never reached the wallet', async t => {
    // The prompt was closed before the send's nonce was saved, so no wallet
    // request was made, and authorizing the retry revokes the old claim.
    const chain = { transactionCount: '0x5', pendingCount: '0x9' };
    chain.note = noteId => unrecorded(noteId);
    const { runtime, client } = retryRecoveryClient(t, chain, { phase: 'ambiguous', submissionId: 'closed-prompt' });
    assert.equal(await client.retryUnknownDeposit(() => {}), 'retry-sent');
    assert.ok(!chain.calls.includes('eth_getTransactionCount'), 'no nonce to check');
    let persisted = (await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit;
    assert.equal(persisted.retryNonce, undefined);
    assert.deepEqual(persisted.resolvedAmbiguousSubmissionIds, ['closed-prompt']);
    const oldClaim = { operationId: persisted.operationId, submissionId: 'closed-prompt', noteId: 7, amount: 2_000_000,
        commitment: '0x123', deploymentId: DEPLOYMENT, chainId: runtime.config.funding.chain_id,
        contractAddress: runtime.config.funding.contract_address };
    await assert.rejects(runtime.rememberPendingDepositSubmissionMetadata(oldClaim, { from: FROM, nonce: 5 }),
        /changed before its nonce was saved/, 'the old claim can no longer reach the wallet');
    const claim = await runtime.claimPendingDepositSubmission(persisted.operationId, { from: OTHER_ACCOUNT });
    assert.equal(claim.retryNonce, null);
    await runtime.markPendingDepositRetryable(null, claim);

    // A send recorded with its nonce lost may still execute beside any retry:
    // nothing is quoted or claimed, and no recovery can release it.
    indexedDB.clear();
    seedRuntime({ pendingDeposit: plan({ transactionHash: null, phase: 'retry_exact', fundingQuoteRetryAuthorized: true,
        ambiguousSubmissions: [{ submissionId: 'unknown-send', startedAt: 1, authorizedAt: 2 }] }) });
    await runtime.reload();
    persisted = runtime.runtime.pendingDeposit;
    assert.equal(runtime.canQuotePendingDeposit(persisted), false);
    await assert.rejects(runtime.claimPendingDepositSubmission(persisted.operationId, { from: FROM }),
        error => error.code === 'deposit_retry_nonce_unknown');
    chain.transactionCount = '0x9';
    assert.equal((await client.recoverBrowserDeposit(() => {})).status, 'retry_exact');
    await assert.rejects(runtime.claimPendingDepositSubmission(persisted.operationId, { from: FROM }),
        error => error.code === 'deposit_retry_nonce_unknown');
    assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT)).runtime.pendingDeposit, persisted);
});

test('a confirmation naming a different note than the active one still refuses', async () => {
    seedRuntime({ pendingDeposit: plan() });
    const runtime = raceRuntime();
    await runtime.confirmDeposit(confirmArgs());
    const before = await readBrowserWalletSnapshot(DEPLOYMENT);
    for (const [label, args] of [
        ['another note id', confirmArgs({ note_id: 8 })],
        ['another amount', confirmArgs({ amount: 3_000_000 })],
        ['another secret', confirmArgs({ secret: 'another-secret' })],
        ['another operation', confirmArgs({ operationId: 'other-operation' })],
        ['no operation', confirmArgs({ operationId: undefined })]
    ]) {
        await assert.rejects(runtime.confirmDeposit({ ...args, transactionHash: HASH }),
            /already has an active private note/, label);
    }
    assert.deepEqual(await readBrowserWalletSnapshot(DEPLOYMENT), before);
});
