import assert from 'node:assert/strict';
import test from 'node:test';

// Exercise the real persisted wallet/runtime transitions. This small IndexedDB
// adapter supplies asynchronous requests and transaction completion in Node.
function memoryIndexedDb() {
    const stores = new Map();
    const keyPaths = new Map();
    let opened = false;
    const database = {
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) {
            stores.set(name, new Map());
            keyPaths.set(name, options.keyPath);
        },
        transaction(names) {
            const allowed = new Set(Array.isArray(names) ? names : [names]);
            let pending = 0;
            let timer;
            let ended = false;
            const transaction = {
                abort() {
                    ended = true;
                    clearTimeout(timer);
                    setTimeout(() => transaction.onabort?.(), 0);
                },
                objectStore(name) {
                    assert.ok(allowed.has(name));
                    const values = stores.get(name);
                    const request = operation => {
                        const result = {};
                        pending += 1;
                        queueMicrotask(() => {
                            try {
                                result.result = operation();
                                result.onsuccess?.();
                            } catch (error) {
                                result.error = error;
                                result.onerror?.();
                            } finally {
                                pending -= 1;
                                clearTimeout(timer);
                                timer = setTimeout(() => {
                                    if (!pending && !ended) {
                                        ended = true;
                                        transaction.oncomplete?.();
                                    }
                                }, 0);
                            }
                        });
                        return result;
                    };
                    return {
                        get: key => request(() => structuredClone(values.get(key))),
                        getAll: () => request(() => structuredClone([...values.values()])),
                        put: (value, key) => request(() => {
                            const identity = key ?? value[keyPaths.get(name)];
                            values.set(identity, structuredClone(value));
                            return identity;
                        })
                    };
                }
            };
            return transaction;
        }
    };
    return {
        clear: () => { for (const store of stores.values()) store.clear(); },
        open() {
            const request = {};
            queueMicrotask(() => {
                request.result = database;
                if (!opened) {
                    opened = true;
                    request.onupgradeneeded?.();
                }
                request.onsuccess?.();
            });
            return request;
        }
    };
}

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, removeItem() {}, setItem() {} };
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const { writeBrowserWallet, listBrowserWithdrawals, readBrowserWalletSnapshot } = await import('../services/browserWalletStore.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');

const DEPLOYMENT_ID = 'zkapi-ef-mainnet-groth16-v2-20260812';
const VAULT = '0xef88012d1A7F9d44e5f5afB8bC5e611Dc3283709';
const TX_HASH = '0x34e298c17052af34acbbd1f1fd0e910f023af7938c5ff1656dd4bd669140ae48';
// Public receipt block from the reported mainnet withdrawal. Its transfer was
// already successful while Ethereum's finalized checkpoint was still behind.
const CLOSE_BLOCK = 0x18b6939;
const hex = value => `0x${value.toString(16)}`;
const RECEIPT = {
    transactionHash: TX_HASH,
    blockNumber: '0x18b6939',
    blockHash: '0xd8584ca1d526460b1799409453794b3ce971da47d4d1f04a1942c0ab468c2d69',
    from: '0x68674ae1f6188391da867255d9ae0e099fc354c5',
    to: VAULT.toLowerCase(),
    status: '0x1',
    logs: [{
        address: VAULT.toLowerCase(),
        topics: [
            '0x1f43fa4711ca18e1d26398f26bf598bd3a62992cdd0e84f055f2bb506e9d7031',
            '0x0000000000000000000000000000000000000000000000000000000000000012'
        ],
        data: '0x09746fb71de2848ed9b2828b4861feba222a8790a2344d2f3976d46f2fbff3cf00000000000000000000000000000000000000000000000000000000001e195700000000000000000000000068674ae1f6188391da867255d9ae0e099fc354c5'
    }]
};

async function scenario({ finalitySupported = true, selected = false, parked = false } = {}) {
    indexedDB.clear();
    const config = { funding: { chain_id: 1, contract_address: VAULT } };
    runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    runtime.config = config;
    runtime.init = async () => runtime.snapshot();
    const returned = zkapiWallet.parseWithdrawalReceipt(RECEIPT, VAULT, 'mutual');
    assert.equal(returned.noteId, 18n);
    assert.equal(returned.finalBalance, 1_972_567n);
    const state = { note_id: Number(returned.noteId), current_balance: Number(returned.finalBalance), secret: 'synthetic-test-secret' };
    await writeBrowserWallet({
        deploymentId: DEPLOYMENT_ID,
        state,
        preparedWithdrawal: {
            mode: 'mutual',
            phase: 'prepared',
            noteId: state.note_id,
            operationId: 'retained-close-authorization',
            clearanceReserved: true,
            // Only a close the server granted can be set aside.
            ...(parked ? { submissionOutcome: 'rejected_before_broadcast', withdrawalNullifier: '0x777',
                clearance: { withdrawal_nullifier: '0x777', signature: { r: '0x1', s: '0x2' } } } : { transactionHash: TX_HASH }),
            destination: returned.destination,
            public_inputs: { note_id: state.note_id, final_balance: state.current_balance }
        }
    });
    await runtime.reload();
    if (parked) await runtime.parkPreparedWithdrawal();
    else if (!selected) await runtime.detachClosedWithdrawal({
        mode: 'mutual',
        noteId: state.note_id,
        destination: returned.destination,
        finalBalance: state.current_balance,
        transactionHash: TX_HASH,
        closeBlockNumber: CLOSE_BLOCK,
        lastObservedBlock: CLOSE_BLOCK
    });
    const chain = {
        finalized: CLOSE_BLOCK - 19,
        head: CLOSE_BLOCK + 1,
        status: parked ? 1 : 3,
        receipt: structuredClone(RECEIPT),
        historicalReads: [],
        methods: []
    };
    globalThis.ethereum = {
        async request({ method, params }) {
            chain.methods.push(method);
            if (method === 'eth_chainId') return '0x1';
            if (method === 'eth_blockNumber') return hex(chain.head);
            if (method === 'eth_getTransactionReceipt') {
                assert.deepEqual(params, [TX_HASH]);
                return structuredClone(chain.receipt);
            }
            if (method === 'eth_getBlockByNumber') {
                assert.deepEqual(params, ['finalized', false]);
                if (!finalitySupported) throw new Error('Unsupported block tag');
                return { number: hex(chain.finalized) };
            }
            if (method === 'eth_call') {
                assert.equal(params[0].to, VAULT);
                assert.equal(params[0].data, `0x9f18e4ed${zkapiWallet.abiWord(state.note_id)}`);
                chain.historicalReads.push(params[1]);
                return `0x${[0, 0, 0, chain.status].map(zkapiWallet.abiWord).join('')}`;
            }
            throw new Error(`Recovery must not open MetaMask: ${method}`);
        }
    };
    const reloadClient = async () => {
        const client = new ZkapiClient();
        client.browserMode = true;
        client.config = config;
        client.refresh = async () => {
            await runtime.reload();
            client.withdrawals = runtime.snapshot().withdrawals;
            client.wallet = { has_note: Boolean(runtime.runtime.state), note: runtime.runtime.state };
            return client.snapshot();
        };
        await client.refresh();
        return client;
    };
    const record = async () => (await listBrowserWithdrawals(DEPLOYMENT_ID))[0];
    return { chain, state, reloadClient, record };
}

test('canceled mutual close stays set aside through polls, reloads and funding a newer balance', async () => {
    const { chain, state, reloadClient, record } = await scenario({ parked: true });
    const beforeOld = structuredClone(await record());
    await writeBrowserWallet({
        deploymentId: DEPLOYMENT_ID,
        state: { note_id: 19, current_balance: 5_000_000, secret: 'new-note-test-secret' },
        lease: { session_id: 'new-chat', testSentinel: true },
        journal: { testSentinel: 'new-note-journal' }
    });
    const beforeCurrent = (await readBrowserWalletSnapshot(DEPLOYMENT_ID)).runtime;
    for (let poll = 0; poll < 3; poll += 1) {
        chain.head += 10;
        const client = await reloadClient();
        await client.syncEscapeWithdrawals();
        const old = await record();
        assert.equal(old.phase, 'parked');
        assert.equal(old.error, null);
        assert.deepEqual(old.state, state);
        assert.deepEqual(old.preparedWithdrawal, beforeOld.preparedWithdrawal);
        assert.deepEqual((await readBrowserWalletSnapshot(DEPLOYMENT_ID)).runtime, beforeCurrent);
    }
    assert.ok(!chain.methods.includes('eth_getBlockByNumber'), 'no finality wait for a transaction that never existed');
    assert.ok(!chain.methods.includes('eth_sendTransaction'));
});

test('already-misclassified canceled mutual close repairs on reload without erasing recovery', async () => {
    const { chain, state, reloadClient, record } = await scenario({ parked: true });
    const original = await record();
    await runtime.updateWithdrawal(original.recordId, {
        phase: 'challenged_unconfirmed', chainStatus: 'active',
        challengeObservedBlock: chain.head, lastObservedBlock: chain.head,
        finalityCheckedBlock: chain.finalized, finalizedBlockNumber: chain.finalized,
        error: 'The escape was challenged.'
    });
    const client = await reloadClient();
    await client.reconcileBrowserWithdrawalsOnLoad();
    const repaired = await record();
    assert.equal(repaired.phase, 'parked');
    assert.equal(repaired.chainStatus, 'active');
    assert.equal(repaired.error, null);
    assert.ok(!repaired.challengeObservedBlock);
    assert.deepEqual(repaired.state, state);
    assert.deepEqual(repaired.preparedWithdrawal, original.preparedWithdrawal);
    assert.ok(!chain.methods.includes('eth_getBlockByNumber'));
});

test('successful mainnet return survives reload and finishes at the finalized boundary', async () => {
    const { chain, state, reloadClient, record } = await scenario();
    let client = await reloadClient();
    assert.equal(client.note, null, 'a returned note no longer blocks funding a new balance');
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    assert.equal((await record()).phase, 'closed_unconfirmed');
    assert.equal((await record()).payoutVerified, true, 'matching mutual-close receipt proves a payout');
    assert.deepEqual((await record()).state, state, 'retain recovery material before finality');
    assert.equal((await record()).transactionHash, TX_HASH);

    // Opening another page must resume reconciliation from durable state,
    // without resetting the close block to the newer chain head.
    chain.head += 100;
    chain.finalized = CLOSE_BLOCK - 1;
    client = await reloadClient();
    assert.equal(await client.reconcileBrowserWithdrawalsOnLoad(), true);
    assert.equal((await record()).phase, 'closed_unconfirmed');
    assert.equal((await record()).closeBlockNumber, CLOSE_BLOCK);

    chain.finalized = CLOSE_BLOCK;
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    const completed = await record();
    assert.equal(completed.phase, 'closed');
    assert.equal(completed.payoutVerified, true, 'receipt evidence survives durable finality sanitation');
    assert.equal(completed.finalizedBlockNumber, CLOSE_BLOCK);
    assert.equal(completed.state, undefined);
    assert.equal(completed.preparedWithdrawal, undefined);
    assert.ok(chain.historicalReads.includes(hex(CLOSE_BLOCK)));
    assert.ok(!chain.methods.includes('eth_sendTransaction'));
    assert.ok(!chain.methods.includes('eth_requestAccounts'));
});

test('providers without finalized support retain recovery until 64 confirmations', async () => {
    const { chain, state, reloadClient, record } = await scenario({ finalitySupported: false });
    const client = await reloadClient();
    chain.head = CLOSE_BLOCK + 63;
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    assert.equal((await record()).phase, 'closed_unconfirmed');
    assert.deepEqual((await record()).state, state);
    chain.head += 1;
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    assert.equal((await record()).phase, 'closed');
    assert.equal((await record()).finalitySource, 'confirmations');
});

test('a pre-finality reorg preserves the mutual-close authorization for recovery', async () => {
    const { chain, state, reloadClient, record } = await scenario();
    chain.status = 1;
    const client = await reloadClient();
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    const pending = await record();
    assert.equal(pending.phase, 'recovery_unconfirmed');
    assert.deepEqual(pending.state, state);
    assert.equal(pending.preparedWithdrawal.clearanceReserved, true);
    chain.finalized = chain.head;
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    const restored = await record();
    assert.equal(restored.phase, 'parked');
    assert.deepEqual(restored.state, state);
    assert.equal(restored.clearanceReserved, true);
    assert.equal(restored.error, null, 'a mutual-close recovery is not an escape challenge');
});

test('reopening an already-finalized mainnet return uses its matching receipt block', async () => {
    const { chain, reloadClient, record } = await scenario({ selected: true });
    chain.head = CLOSE_BLOCK + 100;
    chain.finalized = CLOSE_BLOCK + 50;
    const client = await reloadClient();
    assert.equal((await client.syncWithdrawal()).status, 'closed');
    assert.equal((await record()).payoutVerified, true, 'selected-note detachment persists matched receipt evidence');
    assert.equal((await record()).closeBlockNumber, CLOSE_BLOCK,
        'refreshing an old return must not start a fresh finality wait');
    const reopened = await reloadClient();
    assert.equal(await reopened.reconcileBrowserWithdrawalsOnLoad(), true);
    assert.equal((await record()).phase, 'closed');
    assert.equal((await record()).payoutVerified, true);
    assert.equal((await record()).state, undefined);
});

test('an unrelated successful receipt cannot accelerate close finality', async () => {
    const { chain, state, reloadClient, record } = await scenario({ selected: true });
    chain.head = CLOSE_BLOCK + 100;
    chain.finalized = CLOSE_BLOCK + 50;
    chain.receipt.logs[0].topics[1] = `0x${zkapiWallet.abiWord(19)}`;
    const client = await reloadClient();
    assert.equal((await client.syncWithdrawal()).status, 'closed');
    assert.equal((await record()).payoutVerified, false, 'canonical closure does not prove a user payout');
    assert.equal((await record()).closeBlockNumber, chain.head);
    assert.equal(await client.reconcileBrowserWithdrawalsOnLoad(), true);
    assert.equal((await record()).phase, 'closed_unconfirmed');
    assert.deepEqual((await record()).state, state);
    chain.finalized = chain.head;
    assert.equal(await client.reconcileBrowserWalletInBackground(), true);
    assert.equal((await record()).phase, 'closed');
    assert.equal((await record()).payoutVerified, false, 'finality alone must not invent a payout');
});

test('matched escape-finalization evidence persists through background recovery and finality', async () => {
    const { chain, reloadClient, record } = await scenario();
    const pending = await record();
    assert.equal(pending.payoutVerified, false, 'a detached Closed observation starts without payout evidence');
    await runtime.updateWithdrawal(pending.recordId, {
        mode: 'escape', preparedWithdrawal: null,
        transactionHash: null, transactionHashes: [],
        finalizeTransactionHash: TX_HASH, finalizeTransactionHashes: [TX_HASH]
    });
    chain.receipt.logs[0].topics[0] = zkapiWallet.ABI.escapeFinalizedEvent;
    const client = await reloadClient();
    await client.syncEscapeWithdrawals();
    assert.equal((await record()).phase, 'closed_unconfirmed');
    assert.equal((await record()).payoutVerified, true);
    chain.finalized = CLOSE_BLOCK;
    await client.reconcileBrowserWalletInBackground();
    const closed = await record();
    assert.equal(closed.phase, 'closed');
    assert.equal(closed.payoutVerified, true);
    assert.equal(closed.state, undefined);
    assert.equal(closed.finalizeTransactionHash, undefined);
    assert.ok(!chain.methods.includes('eth_sendTransaction'));
});
