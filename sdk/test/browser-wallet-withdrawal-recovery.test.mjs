import { nativeFunding } from './helpers/native-fixtures.mjs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { registerHooks } from 'node:module';

// Keep recovery tests focused on durable state; the separate codec suite tests ABI serialization.
const codecUrl = new URL('../wallet.js', import.meta.url).href;
registerHooks({
    load(url, context, nextLoad) {
        if (url !== codecUrl) return nextLoad(url, context);
        return { format: 'module', shortCircuit: true, source: `
            import codec from ${JSON.stringify(codecUrl + '?real')};
            export * from ${JSON.stringify(codecUrl + '?real')};
            export default { ...codec, encodeWithdrawal: () => '0xdeadbeef' };
        ` };
    }
});

const clone = value => value === undefined ? undefined : structuredClone(value);

function memoryStorage() {
    const values = new Map();
    return {
        clear: () => values.clear(),
        getItem: key => values.has(key) ? values.get(key) : null,
        removeItem: key => values.delete(key),
        setItem: (key, value) => values.set(key, String(value))
    };
}

// browserWalletStore deliberately uses IndexedDB transactions for atomic
// recovery. This small behavioral fake lets the tests execute those exported
// store operations instead of asserting against their source text.
function memoryIndexedDb() {
    const stores = new Map();
    const keyPaths = new Map();
    let opened = false;

    const request = (transaction, operation) => {
        const pending = {};
        transaction.pending += 1;
        queueMicrotask(() => {
            try {
                pending.result = operation();
                pending.onsuccess?.({ target: pending });
            } catch (error) {
                pending.error = error;
                pending.onerror?.({ target: pending });
            } finally {
                transaction.pending -= 1;
                transaction.scheduleCompletion();
            }
        });
        return pending;
    };

    const database = {
        version: 2,
        close() {},
        objectStoreNames: {
            contains: name => stores.has(name)
        },
        createObjectStore(name, options = {}) {
            stores.set(name, new Map());
            keyPaths.set(name, options.keyPath || null);
        },
        transaction(names) {
            const allowed = new Set(Array.isArray(names) ? names : [names]);
            const transaction = {
                aborted: false,
                completed: false,
                completionTimer: null,
                pending: 0,
                abort() {
                    this.aborted = true;
                    clearTimeout(this.completionTimer);
                    setTimeout(() => this.onabort?.(), 0);
                },
                scheduleCompletion() {
                    clearTimeout(this.completionTimer);
                    if (this.aborted || this.completed || this.pending !== 0) return;
                    this.completionTimer = setTimeout(() => {
                        if (this.aborted || this.completed || this.pending !== 0) return;
                        this.completed = true;
                        this.oncomplete?.();
                    }, 0);
                },
                objectStore(name) {
                    if (!allowed.has(name) || !stores.has(name)) {
                        throw new Error(`Unknown object store: ${name}`);
                    }
                    const values = stores.get(name);
                    return {
                        get(key) {
                            return request(transaction, () => clone(values.get(key)));
                        },
                        getAll() {
                            return request(transaction, () => [...values.values()].map(clone));
                        },
                        put(value, explicitKey) {
                            return request(transaction, () => {
                                const keyPath = keyPaths.get(name);
                                const key = explicitKey ?? (keyPath ? value[keyPath] : undefined);
                                if (key === undefined) throw new Error(`Missing key for ${name}`);
                                values.set(key, clone(value));
                                return key;
                            });
                        },
                        delete(key) {
                            return request(transaction, () => values.delete(key));
                        }
                    };
                }
            };
            return transaction;
        }
    };

    return {
        clear() {
            for (const values of stores.values()) values.clear();
        },
        open() {
            const pending = {};
            queueMicrotask(() => {
                pending.result = database;
                if (!opened) {
                    opened = true;
                    pending.onupgradeneeded?.({ target: pending });
                }
                pending.onsuccess?.({ target: pending });
            });
            return pending;
        }
    };
}

const localStorage = memoryStorage();
const sessionStorage = memoryStorage();
const indexedDB = memoryIndexedDb();
const browserWindow = new EventTarget();
browserWindow.location = {
    hostname: 'localhost',
    href: 'http://localhost/funding/?zkapiMode=browser',
    origin: 'http://localhost',
    search: '?zkapiMode=browser'
};
browserWindow.setInterval = setInterval;
browserWindow.clearInterval = clearInterval;

globalThis.localStorage = localStorage;
globalThis.sessionStorage = sessionStorage;
globalThis.indexedDB = indexedDB;
globalThis.window = browserWindow;
globalThis.location = browserWindow.location;

globalThis.zkapiWallet = (await import('../wallet.js')).default;

const {
    authorizeBrowserWithdrawalFinalizationRetry,
    claimBrowserWithdrawalFinalization,
    detachBrowserClosedWithdrawal,
    detachBrowserEscapeWithdrawal,
    listBrowserWithdrawals,
    markBrowserWithdrawalFinalizationAmbiguous,
    putBrowserWithdrawal,
    readBrowserWallet,
    readBrowserWalletSnapshot,
    releaseBrowserWithdrawalFinalization,
    rememberBrowserWithdrawalFinalization,
    restoreBrowserWithdrawal,
    updateBrowserWithdrawal,
    writeBrowserWallet
} = await import('../services/browserWalletStore.js');
const {
    BrowserWalletRuntime,
    default: browserWalletRuntime
} = await import('../services/browserWalletRuntime.js');
const { default: zkapiClient } = await import('../services/zkapiClient.js');

const DEPLOYMENT_ID = 'recovery-test';
const VAULT_ADDRESS = `0x${'12'.repeat(20)}`;
const DESTINATION = `0x${'34'.repeat(20)}`;

test('fresh default deployments preserve and reject old durable wallets', async () => {
    for (const network of ['mainnet', 'sepolia']) {
        for (const pending of [
            { state: { note_id: 7, current_balance: 1_000_000 } },
            { state: null, pendingDeposit: { operationId: 'saved-deposit' } },
            { state: null, journal: { signedTransaction: 'saved-bytes' } },
            { state: null, lease: { session: 'saved-lease' } }
        ]) {
            indexedDB.clear();
            const before = await writeBrowserWallet(baseRuntime({
                ...pending,
                deploymentId: `retired-${network}`,
                billingAsset: 'native_eth'
            }));
            const runtime = new BrowserWalletRuntime();
            runtime.manifest = { deployment_id: `zkapi-native-eth-${network}-note-bound-v1-fresh-20260930` };
            await assert.rejects(runtime.reload(), /Switch back to that deployment/);
            assert.deepEqual(await readBrowserWallet(), before);
            assert.equal(runtime.worker, null);
        }
    }

    indexedDB.clear();
    const before = await writeBrowserWallet(baseRuntime({
        deploymentId: 'zkapi-native-eth-sepolia-note-bound-v1-fresh-20260930',
        billingAsset: 'native_eth'
    }));
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = {
        deployment_id: before.deploymentId,
        protocol_server_url: 'https://zkapi-sepolia.openanonymity.ai'
    };
    await runtime.reload();
    assert.deepEqual(await readBrowserWallet(), before);
    assert.deepEqual(runtime.runtime, before);
});

function baseRuntime(overrides = {}) {
    const { state: stateOverride, ...runtimeOverrides } = overrides;
    return {
        version: 1,
        deploymentId: DEPLOYMENT_ID,
        journal: null,
        pendingDeposit: null,
        preparedWithdrawal: null,
        lease: null,
        updatedAt: 1,
        ...runtimeOverrides,
        state: stateOverride === null ? null : {
            note_id: 7,
            current_balance: 1_000_000,
            current_anchor: '0x1234',
            expiry_ts: 2_000_000_000,
            // The deposit-time path: exits need no indexer (Amendment A1).
            deposit_path: { active_root: '0x1', siblings: Array(32).fill('0x0') },
            ...(stateOverride || {})
        }
    };
}

function durableState(initial) {
    return { value: clone(initial) };
}

function attachDurableRuntime(runtime, durable) {
    runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    runtime.config = {
        funding: {
            chain_id: 11155111,
            contract_address: VAULT_ADDRESS,
            protocol_server_url: 'https://protocol.example'
        },
        proving_keys: { withdrawal: { url: 'https://example.test/withdrawal.pk' } },
        wallet_core: {}
    };
    runtime.runtime = clone(durable.value);
    runtime.withdrawals = [];
    runtime.init = async () => runtime.snapshot();
    runtime.reload = async () => {
        runtime.runtime = clone(durable.value);
        return runtime.runtime;
    };
    runtime.commit = async next => {
        durable.value = {
            ...clone(next),
            deploymentId: DEPLOYMENT_ID,
            updatedAt: Number(durable.value.updatedAt || 0) + 1
        };
        runtime.runtime = clone(durable.value);
        return runtime.runtime;
    };
    runtime.releaseBackgroundWithdrawalStartSubmission = async (submission, options = {}) => {
        const released = options.replacementUnknown
            ? await runtime.releasePreparedWithdrawalReplacementClaim(
                submission,
                options.message || null
            )
            : await runtime.markPreparedWithdrawalRetryable(null, submission);
        return released ? { location: 'selected', runtime: clone(durable.value) } : null;
    };
    return runtime;
}

function patch(target, replacements) {
    const originals = new Map(Object.keys(replacements).map(key => [key, {
        owned: Object.hasOwn(target, key),
        value: target[key]
    }]));
    Object.assign(target, replacements);
    return () => {
        for (const [key, original] of originals) {
            if (original.owned) target[key] = original.value;
            else delete target[key];
        }
    };
}

function pendingEscape(overrides = {}) {
    return {
        recordId: `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`,
        deploymentId: DEPLOYMENT_ID,
        chainId: 11155111,
        contractAddress: VAULT_ADDRESS,
        mode: 'escape',
        phase: 'pending',
        noteId: 7,
        destination: DESTINATION,
        finalBalance: 1_000_000,
        challengeDeadline: Math.floor(Date.now() / 1_000) - 1,
        ...overrides
    };
}

function withdrawalReceipt({
    mode,
    transactionHash,
    noteId = 7,
    finalBalance = 1_000_000,
    destination = DESTINATION,
    blockNumber = 100,
    challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600
}) {
    const topic = mode === 'mutual'
        ? globalThis.zkapiWallet.ABI.mutualCloseEvent
        : globalThis.zkapiWallet.ABI.escapeInitiatedEvent;
    const words = [
        globalThis.zkapiWallet.abiWord(99n),
        globalThis.zkapiWallet.abiWord(BigInt(finalBalance)),
        globalThis.zkapiWallet.addressWord(destination)
    ];
    if (mode === 'escape') {
        words.push(
            globalThis.zkapiWallet.abiWord(BigInt(challengeDeadline)),
            globalThis.zkapiWallet.abiWord(101n)
        );
    }
    return {
        status: '0x1',
        blockNumber: `0x${Number(blockNumber).toString(16)}`,
        transactionHash,
        logs: [{
            address: VAULT_ADDRESS,
            topics: [topic, `0x${globalThis.zkapiWallet.abiWord(BigInt(noteId))}`],
            data: `0x${words.join('')}`
        }]
    };
}

function useStoreBackedSingletonRuntime() {
    browserWalletRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
    browserWalletRuntime.config = {
        funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
    };
    return patch(browserWalletRuntime, {
        init: async () => browserWalletRuntime.snapshot(),
        reload: async () => {
            const snapshot = await readBrowserWalletSnapshot(DEPLOYMENT_ID);
            browserWalletRuntime.runtime = snapshot.runtime;
            browserWalletRuntime.withdrawals = snapshot.withdrawals;
            return browserWalletRuntime.runtime;
        },
        commit: async next => {
            browserWalletRuntime.runtime = await writeBrowserWallet({
                ...next,
                deploymentId: DEPLOYMENT_ID
            });
            return browserWalletRuntime.runtime;
        },
        releaseBackgroundWithdrawalStartSubmission: (submission, options = {}) =>
            BrowserWalletRuntime.prototype.releaseBackgroundWithdrawalStartSubmission.call(
                browserWalletRuntime,
                submission,
                options
            )
    });
}

test('browser withdrawal recovery invariants', async t => {
    await t.test('transaction nonce metadata is journaled before MetaMask can broadcast', async () => {
        const transactionHash = `0x${'ab'.repeat(32)}`;
        const requestOrder = [];
        let preparedMetadata = null;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    requestOrder.push(method);
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_estimateGas') return '0x5208';
                    if (method === 'eth_getTransactionCount') return '0x9';
                    if (method === 'eth_sendTransaction') {
                        assert.deepEqual(preparedMetadata, {
                            from: DESTINATION.toLowerCase(),
                            nonce: 9
                        });
                        assert.equal(params[0].nonce, '0x9');
                        return transactionHash;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            config: {
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            },
            waitForReceipt: async hash => ({
                status: '0x1',
                transactionHash: hash
            })
        });

        try {
            const result = await zkapiClient.sendContractTransaction(
                DESTINATION,
                VAULT_ADDRESS,
                '0xdeadbeef',
                hash => assert.equal(hash, transactionHash),
                metadata => {
                    preparedMetadata = metadata;
                    requestOrder.push('journal-committed');
                }
            );
            assert.equal(result.transactionHash, transactionHash);
            assert.ok(
                requestOrder.indexOf('journal-committed')
                    < requestOrder.indexOf('eth_sendTransaction'),
                'the durable nonce callback must finish before MetaMask receives the transaction'
            );
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('MetaMask numeric and compatible nonce quantities preserve pre-broadcast journaling', async () => {
        const variants = [
            { value: 0, expected: 0 },
            { value: 1n, expected: 1 },
            { value: '17', expected: 17 },
            { value: ' 0X12 ', expected: 18 },
            { value: { result: '0x13' }, expected: 19 },
            { value: { _hex: '0x14' }, expected: 20 },
            { value: { hex: '0x15' }, expected: 21 }
        ];
        let current = variants[0];
        let preparedMetadata = null;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_chainId') return '0x1';
                    if (method === 'eth_estimateGas') return '0x5208';
                    if (method === 'eth_getTransactionCount') return current.value;
                    if (method === 'eth_sendTransaction') {
                        assert.deepEqual(preparedMetadata, {
                            from: DESTINATION.toLowerCase(),
                            nonce: current.expected
                        });
                        assert.equal(params[0].nonce, `0x${current.expected.toString(16)}`);
                        return `0x${current.expected.toString(16).padStart(64, '0')}`;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            config: {
                funding: {
                    chain_id: 1,
                    contract_address: VAULT_ADDRESS
                }
            },
            waitForReceipt: async hash => ({ status: '0x1', transactionHash: hash })
        });

        try {
            for (const variant of variants) {
                current = variant;
                preparedMetadata = null;
                await zkapiClient.sendContractTransaction(
                    DESTINATION,
                    VAULT_ADDRESS,
                    '0xdeadbeef',
                    null,
                    metadata => { preparedMetadata = metadata; }
                );
            }
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('invalid pending nonce is definitely pre-broadcast', async () => {
        let walletOpened = false;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_estimateGas') return '0x5208';
                    if (method === 'eth_getTransactionCount') {
                        return { result: '0x1', error: { code: -32000 } };
                    }
                    if (method === 'eth_sendTransaction') {
                        walletOpened = true;
                        return `0x${'ab'.repeat(32)}`;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            config: {
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            }
        });

        try {
            let failure;
            await assert.rejects(
                () => zkapiClient.sendContractTransaction(
                    DESTINATION,
                    VAULT_ADDRESS,
                    '0xdeadbeef',
                    null,
                    () => {}
                ),
                error => {
                    failure = error;
                    return /invalid pending transaction nonce/i.test(error.message);
                }
            );
            assert.equal(walletOpened, false);
            assert.equal(failure.transactionStage, 'journal');
            assert.equal(failure.broadcastPossible, false);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a canceled deposit releases only its wallet claim and remains retryable', async () => {
        const durable = durableState(baseRuntime({
            state: null,
            pendingDeposit: {
                phase: 'prepared',
                operationId: 'cancelled-deposit',
                next_note_id: 7,
                amount: 5_000_000,
                commitment: '0x1234',
                secret: 'durable-note-secret'
            }
        }));
        const runtime = attachDurableRuntime(new BrowserWalletRuntime(), durable);
        const first = await runtime.claimPendingDepositSubmission();
        await runtime.rememberPendingDepositSubmissionMetadata(first, {
            from: DESTINATION,
            nonce: 0
        });
        await runtime.markPendingDepositRetryable(null, first);

        assert.equal(durable.value.pendingDeposit.phase, 'prepared');
        assert.equal(durable.value.pendingDeposit.submissionId, undefined);
        assert.equal(durable.value.pendingDeposit.submissionFrom, undefined);
        assert.equal(durable.value.pendingDeposit.submissionNonce, undefined);
        assert.equal(durable.value.pendingDeposit.secret, 'durable-note-secret');

        const retry = await runtime.claimPendingDepositSubmission();
        assert.equal(retry.status, 'claimed');
        assert.notEqual(retry.submissionId, first.submissionId);
    });

    await t.test('two tabs cannot own the same deposit wallet prompt', async () => {
        const durable = durableState(baseRuntime({
            state: null,
            pendingDeposit: {
                phase: 'prepared',
                operationId: 'cross-tab-deposit',
                next_note_id: 7,
                amount: 5_000_000,
                commitment: '0x1234',
                secret: 'durable-note-secret'
            }
        }));
        const firstTab = attachDurableRuntime(new BrowserWalletRuntime(), durable);
        const secondTab = attachDurableRuntime(new BrowserWalletRuntime(), durable);
        const results = await Promise.allSettled([
            firstTab.claimPendingDepositSubmission(),
            secondTab.claimPendingDepositSubmission()
        ]);

        assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
        const rejected = results.find(result => result.status === 'rejected');
        assert.equal(rejected?.reason?.code, 'deposit_wallet_pending');
        assert.match(rejected?.reason?.message || '', /already awaiting MetaMask/i);
    });

    await t.test('definite provider refusal after nonce journaling cannot strand a withdrawal', async () => {
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_estimateGas') return '0x5208';
                    if (method === 'eth_getTransactionCount') return '0x15';
                    if (method === 'eth_sendTransaction') {
                        throw Object.assign(
                            new Error('Invalid transaction parameters: explicit nonce unsupported'),
                            { code: -32602 }
                        );
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            },
            withdrawal: null
        });

        try {
            for (const mode of ['escape', 'mutual']) {
                const durable = durableState(baseRuntime({
                    preparedWithdrawal: {
                        phase: 'prepared',
                        mode,
                        operationId: `provider-refusal-${mode}`,
                        noteId: 7,
                        destination: DESTINATION,
                        clearanceReserved: mode === 'mutual',
                        proof: `${mode}-proof`,
                        public_inputs: { note_id: 7, final_balance: 1_000_000 }
                    }
                }));
                attachDurableRuntime(browserWalletRuntime, durable);
                const submission = await browserWalletRuntime.claimPreparedWithdrawalSubmission();
                let failure;
                await assert.rejects(
                    () => zkapiClient.sendContractTransaction(
                        DESTINATION,
                        VAULT_ADDRESS,
                        '0xdeadbeef',
                        null,
                        metadata => browserWalletRuntime
                            .rememberPreparedWithdrawalSubmissionMetadata(submission, metadata)
                    ),
                    error => {
                        failure = error;
                        return error.code === -32602;
                    }
                );
                assert.equal(failure.broadcastPossible, false);
                assert.equal(durable.value.preparedWithdrawal.submissionNonce, 21);

                await zkapiClient.recoverFailedWithdrawalSubmission({
                    mode,
                    error: failure,
                    submittedHash: null,
                    submission,
                    from: DESTINATION
                });
                assert.equal(durable.value.state.note_id, 7);
                if (mode === 'escape') {
                    assert.equal(durable.value.preparedWithdrawal, null);
                } else {
                    assert.equal(durable.value.preparedWithdrawal.phase, 'prepared');
                    assert.equal(durable.value.preparedWithdrawal.submissionId, undefined);
                    assert.equal(durable.value.preparedWithdrawal.submissionNonce, undefined);
                    assert.equal(durable.value.preparedWithdrawal.clearanceReserved, true);
                }
            }
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a hashless selected withdrawal claim recovers after reload from its finalized nonce', async () => {
        const durable = durableState(baseRuntime({
            preparedWithdrawal: {
                phase: 'prepared',
                mode: 'escape',
                operationId: 'hashless-withdrawal',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'escape-proof',
                public_inputs: { note_id: 7, final_balance: 1_000_000 }
            }
        }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const submission = await browserWalletRuntime.claimPreparedWithdrawalSubmission();
        await browserWalletRuntime.rememberPreparedWithdrawalSubmissionMetadata(submission, {
            from: DESTINATION,
            nonce: 11
        });
        assert.equal(durable.value.preparedWithdrawal.submissionNonce, 11);

        // Model a tab close after eth_sendTransaction was handed to MetaMask but
        // before its hash callback ran. A new runtime has only the durable WAL.
        attachDurableRuntime(browserWalletRuntime, durable);
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') return { number: '0x90' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION.toLowerCase(), '0x90']);
                        return '0xc';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: {
                phase: 'awaiting_wallet',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                transactionHash: null,
                clearanceReserved: false
            },
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => ({
                status: 'active',
                note_id: noteId,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 160
            }),
            refresh: async () => {
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.wallet;
                return zkapiClient.snapshot();
            }
        });

        try {
            const result = await zkapiClient.syncWithdrawal();
            assert.equal(result.status, 'active');
            assert.equal(durable.value.preparedWithdrawal, null);
            assert.equal(durable.value.state.note_id, 7);
            assert.equal(zkapiClient.withdrawalBlocksChat, false);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a hashless finalization claim recovers after reload from its finalized nonce', async () => {
        indexedDB.clear();
        const withdrawal = await putBrowserWithdrawal(pendingEscape());
        const submission = await claimBrowserWithdrawalFinalization(
            withdrawal.recordId,
            'tab-before-reload'
        );
        await browserWalletRuntime.rememberWithdrawalFinalizationSubmissionMetadata(
            withdrawal.recordId,
            submission,
            { from: DESTINATION, nonce: 13 }
        );

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') return { number: '0xa0' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION.toLowerCase(), '0xa0']);
                        return '0xe';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => ({
                status: 'pending_withdrawal',
                note_id: noteId,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 170
            }),
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.withdrawals = browserWalletRuntime.snapshot().withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, withdrawal.recordId);
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.finalizeSubmissionId, undefined);
            assert.equal(stored.finalizeSubmissionFrom, undefined);
            assert.equal(stored.finalizeSubmissionNonce, undefined);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a hashless deposit claim recovers after reload from its finalized nonce', async () => {
        const durable = durableState(baseRuntime({
            state: null,
            pendingDeposit: {
                phase: 'prepared',
                operationId: 'hashless-deposit',
                next_note_id: 7,
                amount: 5_000_000,
                commitment: '0x1234',
                secret: 'durable-note-secret'
            }
        }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const submission = await browserWalletRuntime.claimPendingDepositSubmission();
        await browserWalletRuntime.rememberPendingDepositSubmissionMetadata(submission, {
            from: DESTINATION,
            nonce: 17
        });
        assert.equal(durable.value.pendingDeposit.submissionNonce, 17);

        attachDurableRuntime(browserWalletRuntime, durable);
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') return { number: '0xb0' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION.toLowerCase(), '0xb0']);
                        return '0x12';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            readBrowserNote: async (noteId, blockTag = null) => ({
                noteId,
                commitment: `0x${'00'.repeat(32)}`,
                amount: 0n,
                expiryTs: 0,
                status: 0,
                observedBlock: blockTag ? Number(BigInt(blockTag)) : 180
            }),
            refresh: async () => {
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.wallet;
                return zkapiClient.snapshot();
            }
        });

        try {
            const result = await zkapiClient.recoverBrowserDeposit();
            assert.equal(result.status, 'prepared');
            assert.equal(durable.value.pendingDeposit.phase, 'prepared');
            assert.equal(durable.value.pendingDeposit.submissionId, undefined);
            assert.equal(durable.value.pendingDeposit.submissionFrom, undefined);
            assert.equal(durable.value.pendingDeposit.submissionNonce, undefined);
            assert.equal(durable.value.pendingDeposit.secret, 'durable-note-secret');
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('independent payout destination survives wallet cancellation and client/runtime reload', async () => {
        localStorage.clear();
        const durable = durableState(baseRuntime());
        attachDurableRuntime(browserWalletRuntime, durable);
        browserWalletRuntime.settleActiveLease = async () => null;
        browserWalletRuntime.recoverPending = async () => false;
        browserWalletRuntime.treePath = async () => ({ active_root: '0x1', siblings: [] });
        browserWalletRuntime.remoteJson = async (url, init = {}) => {
            assert.match(url, /\/v2\/withdraw\/clearance$/);
            assert.equal(init.method, 'POST');
            return { signature: 'server-clearance', withdrawal_nullifier: '0x777' };
        };
        // A kind-2 ownership proof (its checks run in the clearance tests).
        browserWalletRuntime.generateOwnershipProof = async () => ({
            public_inputs: { kind: 2, valid_until: Math.floor(Date.now() / 1_000) + 3_600 }, proof: { proof: 'ownership' }
        });
        browserWalletRuntime.worker = {
            async call(operation, payload) {
                if (operation === 'withdrawalNullifier') return '0x777';
                assert.equal(operation, 'prepareWithdrawal');
                return {
                    mode: payload.args.mode,
                    proof: 'proof-before-wallet',
                    public_inputs: {
                        active_root: payload.args.active_root,
                        note_id: 7,
                        final_balance: 1_000_000,
                        withdrawal_nullifier: '0x777',
                        kind: { escape: 0, mutual: 1, ownership: 2 }[payload.args.mode],
                        conceded: payload.args.conceded ?? 0,
                        valid_until: payload.args.valid_until
                    }
                };
            }
        };

        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                credits_per_usd: 1_000_000,
                prepared_withdrawal: null,
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            },
            wallet: {
                has_note: true,
                note: { note_id: 7, current_balance: 1_000_000 }
            },
            withdrawal: null,
            withdrawals: [],
            settleActiveLease: async () => null,
            connectWallet: async () => `0x${'11'.repeat(20)}`,
            readContractUint: async () => 1n,
            sendContractTransaction: async (from) => {
                assert.equal(from, `0x${'11'.repeat(20)}`);
                throw Object.assign(new Error('User rejected the request in MetaMask.'), { code: 4001 });
            },
            refresh: async () => zkapiClient.snapshot()
        });

        let rejection;
        try {
            await assert.rejects(
                () => zkapiClient.withdraw('mutual', () => {}, { destination: DESTINATION }),
                error => {
                    rejection = error;
                    return error.code === 4001;
                }
            );

            assert.equal(rejection.withdrawalNeedsAction, true);
            assert.match(rejection.shortMessage, /safely ready to withdraw/i);
            assert.equal(durable.value.preparedWithdrawal.phase, 'prepared');
            assert.equal(durable.value.preparedWithdrawal.mode, 'mutual');
            assert.equal(durable.value.preparedWithdrawal.clearanceReserved, true);
            assert.equal(durable.value.preparedWithdrawal.destination, DESTINATION);
            assert.equal(durable.value.preparedWithdrawal.proof, 'proof-before-wallet');
            assert.equal(durable.value.preparedWithdrawal.submissionId, undefined);

            const reloadedRuntime = attachDurableRuntime(new BrowserWalletRuntime(), durable);
            await reloadedRuntime.reload();
            assert.equal(
                reloadedRuntime.snapshot().config.prepared_withdrawal.clearance_reserved,
                true
            );

            const { default: reloadedClient } = await import(
                `../services/zkapiClient.js?withdrawal-reload=${Date.now()}`
            );
            assert.deepEqual(reloadedClient.withdrawal, {
                phase: 'prepared',
                mode: 'mutual',
                noteId: 7,
                destination: DESTINATION,
                transactionHash: null,
                clearanceReserved: true
            });
            await assert.rejects(
                () => zkapiClient.withdraw('mutual', () => {}, { destination: `0x${'22'.repeat(20)}` }),
                /already bound to a different destination/
            );
            // A retry without an explicit destination must never redirect the
            // payout to the gas-paying account, even after the UI reloads.
            await assert.rejects(() => zkapiClient.withdraw('mutual'), { code: 4001 });
            assert.equal(durable.value.preparedWithdrawal.destination, DESTINATION);
        } finally {
            restoreClient();
        }
    });

    await t.test('canceling an unsubmitted escape clears its plan but keeps the exit lock until the proof expires', async () => {
        localStorage.clear();
        const durable = durableState(baseRuntime());
        attachDurableRuntime(browserWalletRuntime, durable);
        browserWalletRuntime.settleActiveLease = async () => null;
        browserWalletRuntime.recoverPending = async () => false;
        browserWalletRuntime.treePath = async () => assert.fail('an escape uses the saved deposit path');
        // The stale-device pre-check finds no evidence at N⁺.
        browserWalletRuntime.remoteJson = async url => {
            assert.match(url, /\/v2\/nullifiers\/0x5777\/evidence$/);
            throw Object.assign(new Error('Not found'), { status: 404, code: 'not_found' });
        };
        browserWalletRuntime.vaultWord = async () => 0n;
        browserWalletRuntime.worker = {
            async call(operation, payload) {
                if (operation === 'withdrawalNullifier') return '0x777';
                if (operation === 'successorNullifier') return '0x5777';
                assert.equal(operation, 'prepareWithdrawal');
                return {
                    mode: payload.args.mode,
                    proof: 'escape-proof-before-wallet',
                    public_inputs: {
                        active_root: payload.args.active_root,
                        note_id: 7,
                        final_balance: 1_000_000,
                        withdrawal_nullifier: '0x777',
                        kind: { escape: 0, mutual: 1, ownership: 2 }[payload.args.mode],
                        conceded: payload.args.conceded ?? 0,
                        valid_until: payload.args.valid_until
                    }
                };
            }
        };

        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                credits_per_usd: 1_000_000,
                prepared_withdrawal: null,
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            },
            wallet: {
                has_note: true,
                note: { note_id: 7, current_balance: 1_000_000 }
            },
            withdrawal: null,
            withdrawals: [],
            settleActiveLease: async () => null,
            connectWallet: async () => DESTINATION,
            readContractUint: async () => 1n,
            sendContractTransaction: async () => {
                throw Object.assign(new Error('User rejected the request in MetaMask.'), { code: 4001 });
            },
            refresh: async () => {
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config.prepared_withdrawal = snapshot.config.prepared_withdrawal;
                zkapiClient.config.exit = snapshot.config.exit;
                zkapiClient.wallet = snapshot.wallet;
                return snapshot;
            }
        });

        let rejection;
        try {
            await assert.rejects(
                () => zkapiClient.performWithdrawal('escape'),
                error => {
                    rejection = error;
                    return error.code === 4001;
                }
            );
            assert.match(rejection.shortMessage, /no funds moved/i);
            assert.match(rejection.shortMessage, /until that proof expires/i);
            assert.equal(durable.value.preparedWithdrawal, null);
            assert.equal(zkapiClient.withdrawal, null);
            assert.equal(zkapiClient.config.prepared_withdrawal, null);
            // E6: the escape proof reached the wallet, so the exit lock keeps
            // the balance frozen until that proof is dead.
            assert.equal(durable.value.exitLock.mode, 'escape');
            assert.deepEqual(durable.value.exitLock.released.map(entry => entry.kind), [0]);
            assert.equal(zkapiClient.withdrawalBlocksChat, true);

            const reloadedRuntime = attachDurableRuntime(new BrowserWalletRuntime(), durable);
            await reloadedRuntime.reload();
            assert.equal(reloadedRuntime.snapshot().config.prepared_withdrawal, null);
            assert.equal(reloadedRuntime.snapshot().config.exit.lock.exit_proofs_released, 1);
        } finally {
            restoreClient();
        }
    });

    await t.test('transaction-hash CAS retains concurrent late wallet broadcasts', async () => {
        const hashA = `0x${'aa'.repeat(32)}`;
        const hashB = `0x${'bb'.repeat(32)}`;
        const durable = durableState(baseRuntime({
            preparedWithdrawal: {
                phase: 'awaiting_wallet',
                mode: 'mutual',
                operationId: 'withdrawal-operation',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: true,
                submissionId: 'new-wallet-owner',
                submissionOwner: 'new-tab'
            }
        }));
        const runtime = attachDurableRuntime(new BrowserWalletRuntime(), durable);
        const reference = submissionId => ({
            submissionId,
            operationId: 'withdrawal-operation',
            noteId: 7,
            mode: 'mutual',
            destination: DESTINATION,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        });

        await Promise.all([
            runtime.rememberPreparedWithdrawalTransaction(hashA, reference('expired-wallet-owner')),
            runtime.rememberPreparedWithdrawalTransaction(hashB, reference('new-wallet-owner'))
        ]);

        assert.equal(durable.value.preparedWithdrawal.phase, 'submitted');
        assert.deepEqual(
            new Set(durable.value.preparedWithdrawal.transactionHashes),
            new Set([hashA, hashB])
        );
        assert.equal(durable.value.preparedWithdrawal.concurrentSubmissionObserved, true);

        await runtime.markPreparedWithdrawalRetryable(hashA, reference('expired-wallet-owner'));
        assert.equal(durable.value.preparedWithdrawal.phase, 'submitted');
        assert.equal(durable.value.preparedWithdrawal.transactionHash, hashB);
        assert.deepEqual(durable.value.preparedWithdrawal.transactionHashes, [hashB]);
    });

    await t.test('a stale deposit-slot check cannot clear a newer MetaMask claim or hash', async () => {
        const oldHash = `0x${'0b'.repeat(32)}`;
        const newHash = `0x${'0c'.repeat(32)}`;
        const oldPlan = {
            phase: 'submitted',
            operationId: 'old-deposit',
            next_note_id: 8,
            amount: 5_000_000,
            commitment: '0x1234',
            transactionHash: oldHash,
            transactionHashes: [oldHash]
        };
        const newerPlan = {
            phase: 'submitted',
            operationId: 'new-deposit',
            next_note_id: 9,
            amount: 6_000_000,
            commitment: '0x5678',
            submissionId: 'new-wallet-prompt',
            transactionHash: newHash,
            transactionHashes: [newHash]
        };
        const durable = durableState(baseRuntime({
            state: null,
            pendingDeposit: newerPlan
        }));
        const runtime = attachDurableRuntime(new BrowserWalletRuntime(), durable);

        await assert.rejects(
            () => runtime.resolvePendingDepositSlotConflict({
                operationId: oldPlan.operationId,
                noteId: oldPlan.next_note_id,
                amount: oldPlan.amount,
                commitment: oldPlan.commitment,
                phase: oldPlan.phase,
                submissionId: null,
                transactionHashes: oldPlan.transactionHashes
            }),
            /pending deposit changed/i
        );
        assert.deepEqual(durable.value.pendingDeposit, newerPlan);
    });

    await t.test('a detached pending escape remains visible without blocking a funded chat', () => {
        const backgroundEscape = {
            recordId: `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`,
            deploymentId: DEPLOYMENT_ID,
            mode: 'escape',
            phase: 'pending',
            noteId: 7,
            destination: DESTINATION,
            challengeDeadline: Math.floor(Date.now() / 1_000) + 3_600
        };
        const restoreClient = patch(zkapiClient, {
            config: { ux_proposal: 'quiet', prepared_withdrawal: null },
            wallet: { has_note: true, note: { note_id: 8, current_balance: 2_000_000 } },
            withdrawal: null,
            withdrawals: [backgroundEscape],
            activities: [],
            loading: false,
            lastError: null
        });
        try {
            assert.equal(zkapiClient.withdrawalBlocksChat, false);
            assert.deepEqual(zkapiClient.openWithdrawals, [backgroundEscape]);

        } finally {
            restoreClient();
        }
    });

    await t.test('background reconciliation isolates failures so other withdrawals still advance', async () => {
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    assert.equal(method, 'eth_chainId');
                    return '0xaa36a7';
                }
            }
        });
        const calls = [];
        const restoreClient = patch(zkapiClient, {
            backgroundReconciliationPromise: null,
            browserMode: true,
            config: {
                pending_deposit: { phase: 'submitted' },
                prepared_withdrawal: { phase: 'submitted' },
                funding: { chain_id: 11155111 }
            },
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: { phase: 'submitted' },
            withdrawals: [pendingEscape()],
            refresh: async () => {
                calls.push('refresh');
                return zkapiClient.snapshot();
            },
            recoverBrowserDeposit: async () => {
                calls.push('deposit');
                throw new Error('deposit RPC unavailable');
            },
            syncLateWithdrawalAttempts: async () => {
                calls.push('late');
                return [];
            },
            syncWithdrawal: async () => {
                calls.push('selected');
                throw new Error('selected receipt malformed');
            },
            syncEscapeWithdrawals: async () => {
                calls.push('background');
                return [];
            }
        });

        try {
            const originalWarn = console.warn;
            console.warn = () => {};
            let complete;
            try {
                complete = await zkapiClient.reconcileBrowserWalletInBackground();
            } finally {
                console.warn = originalWarn;
            }
            assert.equal(complete, false);
            assert.deepEqual(calls, [
                'refresh',
                'deposit',
                'late',
                'refresh',
                'selected',
                'background'
            ]);
            assert.equal(zkapiClient.backgroundReconciliationPromise, null);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('one unreadable late withdrawal cannot starve the next receipt', async () => {
        const badHash = `0x${'08'.repeat(32)}`;
        const revertedHash = `0x${'09'.repeat(32)}`;
        const durable = durableState(baseRuntime({
            lateWithdrawalAttempts: [{
                operationId: 'bad-late-withdrawal',
                submissionId: 'bad-wallet-window',
                noteId: 7,
                mode: 'escape',
                destination: DESTINATION,
                finalBalance: 1_000_000,
                deploymentId: DEPLOYMENT_ID,
                chainId: 11155111,
                contractAddress: VAULT_ADDRESS,
                transactionHash: badHash,
                status: 'submitted_late'
            }, {
                operationId: 'reverted-late-withdrawal',
                submissionId: 'reverted-wallet-window',
                noteId: 8,
                mode: 'escape',
                destination: DESTINATION,
                finalBalance: 2_000_000,
                deploymentId: DEPLOYMENT_ID,
                chainId: 11155111,
                contractAddress: VAULT_ADDRESS,
                transactionHash: revertedHash,
                status: 'submitted_late'
            }]
        }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') {
                        return { number: '0x65' };
                    }
                    assert.equal(method, 'eth_getTransactionReceipt');
                    if (params[0] === badHash) {
                        return withdrawalReceipt({ mode: 'escape', transactionHash: badHash });
                    }
                    if (params[0] === revertedHash) {
                        return {
                            status: '0x0',
                            blockNumber: '0x65',
                            blockHash: `0x${'65'.repeat(32)}`
                        };
                    }
                    throw new Error(`Unexpected hash: ${params[0]}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                funding: {
                    chain_id: 11155111,
                    contract_address: VAULT_ADDRESS
                }
            },
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                throw new Error('historical state unavailable');
            },
            refresh: async () => zkapiClient.snapshot()
        });

        try {
            const statuses = [];
            const results = await zkapiClient.syncLateWithdrawalAttempts(message => statuses.push(message));
            assert.deepEqual(results.map(result => result.status), ['error', 'reverted']);
            assert.match(statuses.at(-1), /needs attention/i);
            assert.doesNotMatch(statuses.join('\n'), /Recovered a withdrawal/i);
            const bad = durable.value.lateWithdrawalAttempts.find(attempt =>
                attempt.operationId === 'bad-late-withdrawal');
            const reverted = durable.value.lateWithdrawalAttempts.find(attempt =>
                attempt.operationId === 'reverted-late-withdrawal');
            assert.equal(bad.status, 'submitted_late');
            assert.match(bad.error, /historical state unavailable/i);
            assert.equal(reverted.status, 'reverted');
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a challenged escape with reserved clearance restores as withdrawal-only', async () => {
        indexedDB.clear();
        const preparedWithdrawal = {
            phase: 'submitted',
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            withdrawalNullifier: '0x777',
            clearanceReserved: true,
            proof: 'stale-proof',
            public_inputs: {
                active_root: '0xold-root',
                note_id: 7,
                withdrawal_nullifier: '0x777'
            },
            transactionHash: `0x${'cc'.repeat(32)}`
        };
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal }));

        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const detached = await detachBrowserEscapeWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            phase: 'pending',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            challengeDeadline: Math.floor(Date.now() / 1_000) + 3_600
        });
        assert.equal(detached.withdrawal.clearanceReserved, true);
        assert.equal((await readBrowserWallet()).state, null);
        assert.equal((await listBrowserWithdrawals(DEPLOYMENT_ID)).length, 1);

        const challenged = await updateBrowserWithdrawal(
            recordId,
            { phase: 'restored', restoredAt: Date.now() },
            { expectedRevision: detached.withdrawal.revision, expectedPhase: 'pending' }
        );
        const restored = await restoreBrowserWithdrawal(recordId, {
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        }, challenged.revision);

        assert.equal(restored.state.note_id, 7);
        assert.equal(restored.preparedWithdrawal.phase, 'prepared');
        assert.equal(restored.preparedWithdrawal.mode, 'escape');
        assert.equal(restored.preparedWithdrawal.clearanceReserved, true);
        assert.equal(restored.preparedWithdrawal.withdrawalNullifier, '0x777');
        assert.equal(restored.preparedWithdrawal.proof, undefined);
        assert.equal(restored.preparedWithdrawal.public_inputs, undefined);
        assert.equal(restored.preparedWithdrawal.transactionHash, undefined);
        assert.deepEqual(await listBrowserWithdrawals(DEPLOYMENT_ID), []);
    });

    await t.test('canceling MetaMask finalization releases its durable claim back to pending', async () => {
        indexedDB.clear();
        const withdrawal = await putBrowserWithdrawal(pendingEscape());
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { funding: { contract_address: VAULT_ADDRESS } },
            withdrawals: [withdrawal],
            connectWallet: async () => DESTINATION,
            sendContractTransaction: async () => {
                throw Object.assign(new Error('User rejected finalization.'), { code: 4001 });
            },
            refresh: async () => zkapiClient.snapshot()
        });

        let rejection;
        try {
            await assert.rejects(
                () => zkapiClient.performFinalizeEscape(withdrawal.recordId),
                error => {
                    rejection = error;
                    return error.code === 4001;
                }
            );
            assert.match(rejection.shortMessage, /still safe and can be finalized later/i);

            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.finalizeSubmissionId, undefined);
            assert.equal(stored.finalizeSubmissionOwner, undefined);
            assert.equal(stored.finalizeSubmissionStartedAt, undefined);
            assert.equal(stored.finalizeTransactionHash, undefined);
        } finally {
            restoreClient();
            restoreRuntime();
        }
    });

    await t.test('a returned finalization hash remains durable after provider failure and reload', async () => {
        indexedDB.clear();
        const transactionHash = `0x${'dd'.repeat(32)}`;
        const withdrawal = await putBrowserWithdrawal(pendingEscape());
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    assert.equal(method, 'eth_getTransactionReceipt');
                    throw new Error('Provider unavailable during recovery check.');
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { funding: { contract_address: VAULT_ADDRESS } },
            withdrawals: [withdrawal],
            connectWallet: async () => DESTINATION,
            sendContractTransaction: async (_from, _to, _data, onSubmitted) => {
                await onSubmitted(transactionHash);
                throw new Error('Provider disconnected after broadcasting.');
            },
            refresh: async () => zkapiClient.snapshot()
        });

        try {
            await assert.rejects(
                () => zkapiClient.performFinalizeEscape(withdrawal.recordId),
                /disconnected after broadcasting/i
            );
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'finalizing');
            assert.equal(stored.finalizeTransactionHash, transactionHash);
            assert.deepEqual(stored.finalizeTransactionHashes, [transactionHash]);

            const reloadedRuntime = new BrowserWalletRuntime();
            reloadedRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
            reloadedRuntime.config = {
                funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
            };
            await reloadedRuntime.reload();
            assert.equal(reloadedRuntime.withdrawals[0].finalizeTransactionHash, transactionHash);
            assert.deepEqual(
                reloadedRuntime.snapshot().withdrawals[0].finalizeTransactionHashes,
                [transactionHash]
            );
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('late cross-tab finalization hashes survive takeover and selective revert recovery', async () => {
        indexedDB.clear();
        const hashA = `0x${'ee'.repeat(32)}`;
        const hashB = `0x${'ff'.repeat(32)}`;
        const withdrawal = await putBrowserWithdrawal(pendingEscape());
        const firstClaim = await claimBrowserWithdrawalFinalization(
            withdrawal.recordId,
            'first-tab',
            120_000
        );
        await markBrowserWithdrawalFinalizationAmbiguous(
            withdrawal.recordId,
            firstClaim,
            'provider result unknown'
        );
        await authorizeBrowserWithdrawalFinalizationRetry(withdrawal.recordId);
        const takeover = await claimBrowserWithdrawalFinalization(withdrawal.recordId, 'second-tab');
        assert.notEqual(firstClaim.submissionId, takeover.submissionId);

        // The takeover broadcasts first; the original MetaMask window returns
        // later. Both hashes must remain recoverable despite claim ownership.
        await rememberBrowserWithdrawalFinalization(
            withdrawal.recordId,
            hashB,
            takeover
        );
        await rememberBrowserWithdrawalFinalization(
            withdrawal.recordId,
            hashA,
            firstClaim
        );
        let [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
        assert.deepEqual(stored.finalizeTransactionHashes, [hashB, hashA]);
        assert.equal(stored.concurrentFinalizationObserved, true);

        await releaseBrowserWithdrawalFinalization(withdrawal.recordId, {
            transactionHash: hashA
        });
        [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
        assert.equal(stored.phase, 'finalizing');
        assert.equal(stored.finalizeTransactionHash, hashB);
        assert.deepEqual(stored.finalizeTransactionHashes, [hashB]);
    });

    await t.test('a stale update cannot regress a closed withdrawal to pending', async () => {
        indexedDB.clear();
        const closed = await putBrowserWithdrawal(pendingEscape({
            phase: 'closed',
            closedAt: Date.now()
        }));

        await assert.rejects(
            () => updateBrowserWithdrawal(
                closed.recordId,
                { phase: 'pending', error: 'stale chain response' },
                { expectedRevision: closed.revision, expectedPhase: 'closed' }
            ),
            /completed withdrawal cannot return to an earlier phase/i
        );
        const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
        assert.equal(stored.phase, 'closed');
        assert.equal(stored.revision, closed.revision);
        assert.equal(stored.error, undefined);
    });

    await t.test('Active-chain sync preserves a live foreign-tab escape claim with no hash', async () => {
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            submissionId: 'foreign-wallet-prompt',
            submissionOwner: 'other-tab',
            submissionStartedAt: Date.now()
        };
        const durable = durableState(baseRuntime({ preparedWithdrawal }));
        attachDurableRuntime(browserWalletRuntime, durable);
        assert.notEqual(browserWalletRuntime.ownerId, preparedWithdrawal.submissionOwner);

        const localMirror = {
            phase: 'prepared',
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            transactionHash: null,
            clearanceReserved: false
        };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                prepared_withdrawal: {
                    phase: 'awaiting_wallet',
                    mode: 'escape',
                    note_id: 7,
                    destination: DESTINATION,
                    transaction_hash: null,
                    clearance_reserved: false
                }
            },
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: localMirror,
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return { status: 'active', note_id: 7, challenge_deadline: null };
            },
            refresh: async () => zkapiClient.snapshot()
        });

        try {
            const statuses = [];
            const result = await zkapiClient.syncWithdrawal(message => statuses.push(message));
            assert.equal(result.status, 'awaiting_wallet');
            assert.match(statuses.at(-1), /MetaMask may still be open/i);
            assert.equal(durable.value.state.note_id, 7);
            assert.deepEqual(durable.value.preparedWithdrawal, preparedWithdrawal);
            assert.equal(zkapiClient.note.note_id, 7);
            assert.deepEqual(zkapiClient.withdrawal, localMirror);
        } finally {
            restoreClient();
        }
    });

    await t.test('a challenged escape cannot erase a newer hashless MetaMask claim', async () => {
        const challengedHash = `0x${'0a'.repeat(32)}`;
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            operationId: 'shared-escape-operation',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            proof: 'escape-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000
            },
            transactionHash: challengedHash,
            transactionHashes: [challengedHash],
            submissionId: 'newer-wallet-prompt',
            submissionOwner: 'newer-tab',
            submissionStartedAt: Date.now()
        };
        const durable = durableState(baseRuntime({ preparedWithdrawal }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    assert.equal(method, 'eth_getTransactionReceipt');
                    assert.equal(params[0], challengedHash);
                    return withdrawalReceipt({
                        mode: 'escape',
                        transactionHash: challengedHash,
                        blockNumber: 100
                    });
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                prepared_withdrawal: {
                    phase: 'awaiting_wallet',
                    mode: 'escape',
                    note_id: 7,
                    destination: DESTINATION,
                    transaction_hash: challengedHash,
                    clearance_reserved: false
                },
                funding: { contract_address: VAULT_ADDRESS }
            },
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: {
                phase: 'submitted',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                transactionHash: challengedHash,
                clearanceReserved: false
            },
            readBrowserWithdrawalStatus: async () => ({
                status: 'active',
                note_id: 7,
                challenge_deadline: null,
                observed_block: 101
            }),
            refresh: async () => zkapiClient.snapshot()
        });

        try {
            const statuses = [];
            const result = await zkapiClient.syncWithdrawal(message => statuses.push(message));
            assert.equal(result.status, 'awaiting_wallet');
            assert.match(statuses.at(-1), /another MetaMask request is still open/i);
            assert.equal(durable.value.state.note_id, 7);
            assert.equal(durable.value.preparedWithdrawal.submissionId, 'newer-wallet-prompt');
            assert.deepEqual(durable.value.preparedWithdrawal.transactionHashes, [challengedHash]);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a challenged selected escape moves atomically to background and survives a pending reorg', async () => {
        indexedDB.clear();
        const transactionHash = `0x${'0d'.repeat(32)}`;
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'submitted',
                mode: 'escape',
                operationId: 'challenge-finality-operation',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'escape-proof',
                public_inputs: {
                    note_id: 7,
                    final_balance: 1_000_000
                },
                transactionHash,
                transactionHashes: [transactionHash]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const receipt = withdrawalReceipt({
            mode: 'escape',
            transactionHash,
            blockNumber: 100
        });
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params?.[0], transactionHash);
                        return receipt;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        let canonical = {
            status: 'active',
            note_id: 7,
            observed_block: 101
        };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: {
                phase: 'submitted',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                transactionHash,
                clearanceReserved: false
            },
            withdrawals: [],
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return canonical;
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.wallet;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const result = await zkapiClient.syncWithdrawal();
            assert.equal(result.status, 'active');
            assert.equal(result.finalityPending, true);
            assert.equal((await readBrowserWallet()).state, null);
            let [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'challenged_unconfirmed');
            assert.equal(stored.state.note_id, 7);
            assert.equal(stored.transactionHash, transactionHash);
            assert.equal(zkapiClient.withdrawalBlocksChat, false);

            canonical = {
                status: 'pending_withdrawal',
                note_id: 7,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                observed_block: 102
            };
            zkapiClient.withdrawals = [stored];
            await zkapiClient.syncEscapeWithdrawals(() => {}, stored.recordId);
            [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.chainStatus, 'pending_withdrawal');
            assert.equal(stored.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('Active-chain sync removes only a reverted hash while another remains pending', async () => {
        const revertedHash = `0x${'10'.repeat(32)}`;
        const pendingHash = `0x${'20'.repeat(32)}`;
        const preparedWithdrawal = {
            phase: 'submitted',
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            transactionHash: revertedHash,
            transactionHashes: [revertedHash, pendingHash]
        };
        const durable = durableState(baseRuntime({ preparedWithdrawal }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') {
                        return { number: '0x64' };
                    }
                    assert.equal(method, 'eth_getTransactionReceipt');
                    if (params[0] === revertedHash) {
                        return {
                            status: '0x0',
                            blockNumber: '0x64',
                            blockHash: `0x${'10'.repeat(32)}`
                        };
                    }
                    if (params[0] === pendingHash) return null;
                    throw new Error(`Unexpected hash: ${params[0]}`);
                }
            }
        });
        const localMirror = {
            phase: 'submitted',
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            transactionHash: revertedHash,
            clearanceReserved: false
        };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                prepared_withdrawal: {
                    phase: 'submitted',
                    mode: 'escape',
                    note_id: 7,
                    destination: DESTINATION,
                    transaction_hash: revertedHash,
                    clearance_reserved: false
                }
            },
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: localMirror,
            readBrowserWithdrawalStatus: async () => ({
                status: 'active',
                note_id: 7,
                challenge_deadline: null
            }),
            refresh: async () => zkapiClient.snapshot()
        });

        try {
            const result = await zkapiClient.syncWithdrawal();
            assert.equal(result.status, 'dropped_or_pending');
            assert.equal(result.transaction_hash, pendingHash);
            assert.equal(durable.value.state.note_id, 7);
            assert.equal(durable.value.preparedWithdrawal.phase, 'dropped_or_pending');
            assert.equal(durable.value.preparedWithdrawal.transactionHash, pendingHash);
            assert.deepEqual(durable.value.preparedWithdrawal.transactionHashes, [pendingHash]);
            assert.equal(zkapiClient.note.note_id, 7);
            assert.deepEqual(zkapiClient.withdrawal, localMirror);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a missing withdrawal receipt can be replaced with the exact original nonce', async () => {
        indexedDB.clear();
        const oldHash = `0x${'22'.repeat(32)}`;
        const replacementHash = `0x${'23'.repeat(32)}`;
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'submitted',
                mode: 'escape',
                operationId: 'replace-missing-withdrawal',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'exact-saved-proof',
                public_inputs: { note_id: 7, final_balance: 1_000_000 },
                transactionHash: oldHash,
                transactionHashes: [oldHash],
                transactionAttempts: [{
                    hash: oldHash,
                    operationId: 'replace-missing-withdrawal',
                    submissionId: 'original-wallet-prompt',
                    from: DESTINATION,
                    nonce: 4
                }]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let canonicalPhase = 'active';
        let replacementNonce = null;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params?.[0], oldHash);
                        return null;
                    }
                    if (method === 'eth_getBlockByNumber') return { number: '0x64' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x64']);
                        return '0x4';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: {
                phase: 'submitted',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                transactionHash: oldHash,
                clearanceReserved: false
            },
            withdrawals: [],
            connectWallet: async () => DESTINATION,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => canonicalPhase === 'active'
                ? {
                    status: 'active',
                    note_id: noteId,
                    observed_block: blockTag ? Number(BigInt(blockTag)) : 120
                }
                : {
                    status: 'pending_withdrawal',
                    note_id: noteId,
                    destination: DESTINATION,
                    final_balance: 1_000_000,
                    challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                    observed_block: 125
                },
            sendContractTransaction: async (
                from,
                _to,
                _data,
                onSubmitted,
                onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                replacementNonce = preparedNonce;
                await onPrepared({ from, nonce: preparedNonce });
                await onSubmitted(replacementHash);
                return withdrawalReceipt({
                    mode: 'escape',
                    transactionHash: replacementHash
                });
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const missing = await zkapiClient.syncWithdrawal();
            assert.equal(missing.status, 'dropped_or_pending');
            assert.equal(missing.replacement_available, true);
            let persisted = await readBrowserWallet();
            assert.equal(persisted.preparedWithdrawal.phase, 'dropped_or_pending');
            assert.deepEqual(persisted.preparedWithdrawal.transactionHashes, [oldHash]);

            canonicalPhase = 'pending_withdrawal';
            const replaced = await zkapiClient.retryDroppedWithdrawal();
            assert.equal(replacementNonce, 4);
            assert.equal(replaced.status, 'pending_withdrawal');
            persisted = await readBrowserWallet();
            const [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.deepEqual(
                record.preparedWithdrawal.transactionHashes,
                [oldHash, replacementHash]
            );
            assert.equal(record.preparedWithdrawal.transactionAttempts.length, 2);
            assert.equal(record.phase, 'pending');
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a hashless replacement timeout releases only its same-nonce claim', async () => {
        indexedDB.clear();
        const oldHash = `0x${'24'.repeat(32)}`;
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'dropped_or_pending',
                mode: 'escape',
                operationId: 'hashless-replacement',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'saved-proof',
                public_inputs: { note_id: 7, final_balance: 1_000_000 },
                transactionHash: oldHash,
                transactionHashes: [oldHash],
                transactionAttempts: [{
                    hash: oldHash,
                    operationId: 'hashless-replacement',
                    submissionId: 'first-prompt',
                    from: DESTINATION,
                    nonce: 6
                }]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            withdrawal: null,
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.config = browserWalletRuntime.snapshot().config;
                return zkapiClient.snapshot();
            }
        });

        try {
            const submission = await browserWalletRuntime
                .claimPreparedWithdrawalReplacement(DESTINATION);
            const timeout = Object.assign(
                new Error('Provider timed out after accepting the request.'),
                { broadcastPossible: true }
            );
            await zkapiClient.recoverFailedWithdrawalSubmission({
                mode: 'escape',
                error: timeout,
                submittedHash: null,
                submission,
                submissionMetadata: {
                    from: DESTINATION,
                    nonce: submission.replacementNonce
                },
                from: DESTINATION
            });

            const persisted = await readBrowserWallet();
            assert.equal(persisted.preparedWithdrawal.phase, 'dropped_or_pending');
            assert.equal(persisted.preparedWithdrawal.submissionId, undefined);
            assert.deepEqual(persisted.preparedWithdrawal.transactionHashes, [oldHash]);
            assert.equal(persisted.preparedWithdrawal.transactionAttempts.length, 1);
            const secondClaim = await browserWalletRuntime
                .claimPreparedWithdrawalReplacement(DESTINATION);
            assert.equal(secondClaim.replacementNonce, 6);
            assert.notEqual(secondClaim.submissionId, submission.submissionId);
        } finally {
            restoreClient();
            restoreRuntime();
        }
    });

    await t.test('recovery retries a returned hash after a one-shot journal failure', async () => {
        indexedDB.clear();
        const oldHash = `0x${'25'.repeat(32)}`;
        const newHash = `0x${'26'.repeat(32)}`;
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'dropped_or_pending',
                mode: 'escape',
                operationId: 'journal-retry-replacement',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'saved-proof',
                public_inputs: { note_id: 7, final_balance: 1_000_000 },
                transactionHash: oldHash,
                transactionHashes: [oldHash],
                transactionAttempts: [{
                    hash: oldHash,
                    operationId: 'journal-retry-replacement',
                    submissionId: 'first-prompt',
                    from: DESTINATION,
                    nonce: 8
                }]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const submission = await browserWalletRuntime
            .claimPreparedWithdrawalReplacement(DESTINATION);
        const originalRemember = browserWalletRuntime
            .rememberPreparedWithdrawalTransaction.bind(browserWalletRuntime);
        let journalCalls = 0;
        const restoreRemember = patch(browserWalletRuntime, {
            rememberPreparedWithdrawalTransaction: async (...args) => {
                journalCalls += 1;
                if (journalCalls === 1) throw new Error('temporary IndexedDB failure');
                return originalRemember(...args);
            }
        });
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params?.[0], newHash);
                        return null;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            withdrawal: null,
            submittedTransactionMetadata: async () => null,
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.config = browserWalletRuntime.snapshot().config;
                return zkapiClient.snapshot();
            }
        });

        try {
            await assert.rejects(
                () => browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                    newHash,
                    submission,
                    { from: DESTINATION, nonce: submission.replacementNonce }
                ),
                /temporary IndexedDB failure/
            );
            const sendFailure = Object.assign(new Error('hash callback failed'), {
                transactionHash: newHash,
                broadcastPossible: true
            });
            await zkapiClient.recoverFailedWithdrawalSubmission({
                mode: 'escape',
                error: sendFailure,
                submittedHash: newHash,
                submission,
                submissionMetadata: {
                    from: DESTINATION,
                    nonce: submission.replacementNonce
                },
                from: DESTINATION
            });
            const persisted = await readBrowserWallet();
            assert.equal(journalCalls, 2);
            assert.deepEqual(
                persisted.preparedWithdrawal.transactionHashes,
                [oldHash, newHash]
            );
            assert.equal(persisted.preparedWithdrawal.submissionId, undefined);
            assert.equal(persisted.preparedWithdrawal.transactionAttempts.length, 2);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRemember();
            restoreRuntime();
        }
    });

    await t.test('a finalized replacement nonce releases a canceled selected withdrawal hash', async () => {
        const canceledHash = `0x${'0e'.repeat(32)}`;
        const preparedWithdrawal = {
            phase: 'submitted',
            mode: 'escape',
            operationId: 'canceled-withdrawal',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            proof: 'escape-proof',
            public_inputs: { note_id: 7, final_balance: 1_000_000 },
            transactionHash: canceledHash,
            transactionHashes: [canceledHash],
            transactionAttempts: [{
                hash: canceledHash,
                operationId: 'canceled-withdrawal',
                submissionId: 'old-wallet-prompt',
                from: DESTINATION,
                nonce: 5
            }]
        };
        const durable = durableState(baseRuntime({ preparedWithdrawal }));
        attachDurableRuntime(browserWalletRuntime, durable);
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    if (method === 'eth_getBlockByNumber') {
                        assert.equal(params?.[0], 'finalized');
                        return { number: '0x78' };
                    }
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x78']);
                        return '0x6';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: {
                prepared_withdrawal: {
                    phase: 'submitted',
                    mode: 'escape',
                    note_id: 7,
                    destination: DESTINATION,
                    transaction_hash: canceledHash,
                    clearance_reserved: false
                },
                funding: { contract_address: VAULT_ADDRESS }
            },
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: {
                phase: 'submitted',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                transactionHash: canceledHash,
                clearanceReserved: false
            },
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => ({
                status: 'active',
                note_id: noteId,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 130
            }),
            refresh: async () => {
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config.prepared_withdrawal = snapshot.config.prepared_withdrawal;
                zkapiClient.wallet = snapshot.wallet;
                return zkapiClient.snapshot();
            }
        });

        try {
            const result = await zkapiClient.syncWithdrawal();
            assert.equal(result.status, 'active');
            assert.equal(durable.value.state.note_id, 7);
            assert.equal(durable.value.preparedWithdrawal, null);
            assert.equal(zkapiClient.withdrawalBlocksChat, false);
        } finally {
            restoreClient();
            restoreEthereum();
        }
    });

    await t.test('a finalized replacement nonce releases a canceled escape finalization hash', async () => {
        indexedDB.clear();
        const canceledHash = `0x${'0f'.repeat(32)}`;
        const withdrawal = await putBrowserWithdrawal(pendingEscape({
            phase: 'finalizing',
            chainStatus: 'pending_withdrawal',
            state: baseRuntime().state,
            finalizeTransactionHash: canceledHash,
            finalizeTransactionHashes: [canceledHash],
            finalizeAttempts: [{
                hash: canceledHash,
                operationId: 'canceled-finalization',
                submissionId: 'old-finalization-prompt',
                generation: 1,
                from: DESTINATION,
                nonce: 9
            }]
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    if (method === 'eth_getBlockByNumber') return { number: '0x8c' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x8c']);
                        return '0xa';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS }) },
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: [withdrawal],
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => ({
                status: 'pending_withdrawal',
                note_id: noteId,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 145
            }),
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.withdrawals = browserWalletRuntime.snapshot().withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, withdrawal.recordId);
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.finalizeTransactionHash, undefined);
            assert.deepEqual(stored.finalizeTransactionHashes || [], []);
            assert.equal(stored.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('Active-chain background sync waits for finality before parking a challenged escape', async () => {
        indexedDB.clear();
        const withdrawal = await putBrowserWithdrawal(pendingEscape({
            clearanceReserved: true,
            state: baseRuntime().state,
            preparedWithdrawal: {
                phase: 'submitted',
                mode: 'escape',
                noteId: 7,
                destination: DESTINATION,
                withdrawalNullifier: '0x777',
                clearanceReserved: true
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let finalizedBlock = 99;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') {
                        assert.equal(params?.[0], 'finalized');
                        return { number: `0x${finalizedBlock.toString(16)}` };
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { prepared_withdrawal: null },
            wallet: { has_note: true, note: { note_id: 8, current_balance: 2_000_000 } },
            withdrawals: [withdrawal],
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return {
                    status: 'active',
                    note_id: 7,
                    challenge_deadline: null,
                    observed_block: 100
                };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.withdrawals = browserWalletRuntime.snapshot().withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [result] = await zkapiClient.syncEscapeWithdrawals(() => {}, withdrawal.recordId);
            assert.equal(result.status, 'active');
            let [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'challenged_unconfirmed');
            assert.equal(stored.state.note_id, 7);

            finalizedBlock = 100;
            zkapiClient.withdrawals = [stored];
            await zkapiClient.syncEscapeWithdrawals(() => {}, withdrawal.recordId);
            [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'parked');
            assert.notEqual(stored.phase, 'restored');
            assert.equal(stored.clearanceReserved, true);
            assert.match(stored.error, /remains withdrawal-only/i);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('closed-unconfirmed escape retains recovery state until its close block is finalized', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime());
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const { withdrawal } = await detachBrowserClosedWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            closeBlockNumber: 100,
            lastObservedBlock: 100
        });
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let finalizedBlock = 99;
        let finalizedReads = 0;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') {
                        assert.equal(params?.[0], 'finalized');
                        finalizedReads += 1;
                        return { number: `0x${finalizedBlock.toString(16)}` };
                    }
                    if (method === 'eth_blockNumber') return '0x69';
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS }) },
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: [withdrawal],
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return { status: 'closed', note_id: 7, observed_block: 105 };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.withdrawals = browserWalletRuntime.snapshot().withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            let [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'closed_unconfirmed');
            assert.equal(stored.state.note_id, 7);
            assert.ok(finalizedReads > 0, 'finality must be read from the chain');
            assert.equal(stored.payoutVerified, false, 'a Closed note alone is not an escape payout receipt');

            finalizedBlock = 100;
            zkapiClient.withdrawals = [stored];
            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'closed');
            assert.equal(stored.state, undefined);
            assert.equal(stored.payoutVerified, false, 'finality cannot convert an unknown closure into a refund');
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a reorg from closed-unconfirmed back to pending keeps the escape recoverable', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime());
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const { withdrawal } = await detachBrowserClosedWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            challengeDeadline: Math.floor(Date.now() / 1_000) + 3_600,
            closeBlockNumber: 100,
            lastObservedBlock: 100
        });
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: { funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS }) },
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: [withdrawal],
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return {
                    status: 'pending_withdrawal',
                    note_id: 7,
                    destination: DESTINATION,
                    final_balance: 1_000_000,
                    challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                    observed_block: 101
                };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                zkapiClient.withdrawals = browserWalletRuntime.snapshot().withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.chainStatus, 'pending_withdrawal');
            assert.equal(stored.state.note_id, 7);
        } finally {
            restoreClient();
            restoreRuntime();
        }
    });

    await t.test('a late initial withdrawal hash survives reload and a reverted receipt retires it', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        const transactionHash = `0x${'31'.repeat(32)}`;
        const submission = {
            submissionId: 'late-wallet-owner',
            operationId: 'late-withdrawal-operation',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        };

        const late = await lateRuntime.rememberPreparedWithdrawalTransaction(
            transactionHash,
            submission
        );
        assert.equal(late.late, true);
        let persisted = await readBrowserWallet();
        assert.equal(persisted.lateWithdrawalAttempts.length, 1);
        assert.equal(persisted.lateWithdrawalAttempts[0].status, 'submitted_late');

        await lateRuntime.reload();
        assert.equal(
            lateRuntime.snapshot().config.late_withdrawal_attempts[0].transaction_hash,
            transactionHash
        );

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();

        let receiptReads = 0;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params?.[0], transactionHash);
                        receiptReads += 1;
                        return {
                            status: '0x0',
                            blockNumber: '0x64',
                            blockHash: `0x${'64'.repeat(32)}`,
                            logs: []
                        };
                    }
                    if (method === 'eth_getBlockByNumber') {
                        return { number: '0x64' };
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.reconcileBrowserWithdrawalsOnLoad();
            persisted = await readBrowserWallet();
            assert.ok(receiptReads > 0, 'late transactions must be checked after reload');
            assert.equal(persisted.lateWithdrawalAttempts[0].status, 'reverted');
            assert.deepEqual(browserWalletRuntime.snapshot().config.late_withdrawal_attempts, []);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('an unfinalized reverted late withdrawal survives a reorg into success', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
        const transactionHash = `0x${'37'.repeat(32)}`;
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        await lateRuntime.rememberPreparedWithdrawalTransaction(transactionHash, {
            submissionId: 'reorg-wallet-owner',
            operationId: 'reorg-late-withdrawal',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        });

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let canonicalPhase = 'reverted';
        const successfulReceipt = withdrawalReceipt({
            mode: 'escape',
            transactionHash,
            blockNumber: 101,
            challengeDeadline
        });
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params?.[0], transactionHash);
                        return canonicalPhase === 'reverted'
                            ? {
                                status: '0x0',
                                blockNumber: '0x64',
                                blockHash: `0x${'aa'.repeat(32)}`,
                                logs: []
                            }
                            : successfulReceipt;
                    }
                    if (method === 'eth_getBlockByNumber') {
                        return { number: '0x63' };
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            readBrowserWithdrawalStatus: async noteId => ({
                status: 'pending_withdrawal',
                note_id: noteId,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: challengeDeadline,
                observed_block: 105
            }),
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.wallet;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            let [result] = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(result.status, 'reverted_unconfirmed');
            let persisted = await readBrowserWallet();
            assert.equal(persisted.state.note_id, 7);
            assert.equal(
                persisted.lateWithdrawalAttempts[0].status,
                'reverted_unconfirmed'
            );

            canonicalPhase = 'succeeded';
            [result] = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(result.status, 'pending_withdrawal');
            persisted = await readBrowserWallet();
            const [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.equal(persisted.lateWithdrawalAttempts[0].status, 'detached');
            assert.equal(record.phase, 'pending');
            assert.equal(record.transactionHash, transactionHash);
            assert.equal(record.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a mined late mutual close becomes closed-unconfirmed before its note is forgotten', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
        const transactionHash = `0x${'41'.repeat(32)}`;
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        await lateRuntime.rememberPreparedWithdrawalTransaction(transactionHash, {
            submissionId: 'late-mutual-wallet-owner',
            operationId: 'late-mutual-operation',
            noteId: 7,
            mode: 'mutual',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            clearanceReserved: true,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        });

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const receipt = withdrawalReceipt({ mode: 'mutual', transactionHash });
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_getTransactionReceipt') return receipt;
                    if (method === 'eth_getBlockByNumber') return { number: '0x63' };
                    if (method === 'eth_blockNumber') return '0x64';
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => {
                assert.equal(noteId, 7);
                assert.notEqual(blockTag, '0x64', 'the close block is not finalized yet');
                return { status: 'closed', note_id: 7, observed_block: 100 };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.reconcileBrowserWithdrawalsOnLoad();
            const persisted = await readBrowserWallet();
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.ok(
                ['closed', 'detached'].includes(persisted.lateWithdrawalAttempts[0].status),
                'the mined attempt must leave the active late-attempt queue'
            );
            assert.deepEqual(browserWalletRuntime.snapshot().config.late_withdrawal_attempts, []);
            assert.equal(stored.phase, 'closed_unconfirmed');
            assert.equal(stored.mode, 'mutual');
            assert.equal(stored.transactionHash, transactionHash);
            assert.equal(stored.closeBlockNumber, 100);
            assert.equal(stored.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a mined late escape joins its background record without replacing a fresh note', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime());
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        await detachBrowserEscapeWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            phase: 'pending',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            challengeDeadline,
            startBlockNumber: 90,
            lastObservedBlock: 90
        });
        await writeBrowserWallet(baseRuntime({
            state: { note_id: 8, current_balance: 2_000_000 }
        }));

        const transactionHash = `0x${'51'.repeat(32)}`;
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        await lateRuntime.rememberPreparedWithdrawalTransaction(transactionHash, {
            submissionId: 'late-escape-wallet-owner',
            operationId: 'late-escape-operation',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        });

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const receipt = withdrawalReceipt({
            mode: 'escape',
            transactionHash,
            challengeDeadline
        });
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    if (method === 'eth_chainId') return '0xaa36a7';
                    if (method === 'eth_getTransactionReceipt') return receipt;
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 8, current_balance: 2_000_000 } },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            readBrowserWithdrawalStatus: async noteId => {
                assert.equal(noteId, 7);
                return {
                    status: 'pending_withdrawal',
                    note_id: 7,
                    destination: DESTINATION,
                    final_balance: 1_000_000,
                    challenge_deadline: challengeDeadline,
                    observed_block: 105
                };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.reconcileBrowserWithdrawalsOnLoad();
            const persisted = await readBrowserWallet();
            const [stored] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state.note_id, 8);
            assert.equal(persisted.state.current_balance, 2_000_000);
            assert.equal(persisted.lateWithdrawalAttempts[0].status, 'detached');
            assert.equal(stored.recordId, recordId);
            assert.equal(stored.phase, 'pending');
            assert.equal(stored.transactionHash, transactionHash);
            assert.ok(stored.startBlockNumber >= 100);
            assert.ok(stored.lastObservedBlock >= 100);
            assert.equal(stored.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a replacement hash can move an escape on-chain when the saved hash has no receipt', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
        const staleHash = `0x${'51'.repeat(32)}`;
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        await lateRuntime.rememberPreparedWithdrawalTransaction(staleHash, {
            submissionId: 'replaced-wallet-owner',
            operationId: 'replaced-operation',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        });

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            readBrowserWithdrawalStatus: async () => ({
                status: 'pending_withdrawal',
                note_id: 7,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: challengeDeadline,
                observed_block: 110
            }),
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.wallet;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [result] = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(result.status, 'pending_withdrawal');
            assert.equal(result.replaced, true);
            const persisted = await readBrowserWallet();
            const [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.equal(persisted.lateWithdrawalAttempts[0].status, 'detached');
            assert.equal(record.phase, 'pending');
            assert.equal(record.challengeDeadline, challengeDeadline);
            assert.equal(record.transactionHash, null);
            assert.equal(record.canonicalRecovery, true);
            assert.equal(record.state.note_id, 7);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('late receipt recovery follows canonical state without discarding note recovery', async () => {
        for (const [scenario, receiptFor] of [
            ['missing', () => null],
            ['mismatched', transactionHash => withdrawalReceipt({
                mode: 'escape',
                transactionHash,
                noteId: 8
            })]
        ]) {
            indexedDB.clear();
            await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
            const transactionHash = `0x${(scenario === 'missing' ? '61' : '71').repeat(32)}`;
            const lateRuntime = new BrowserWalletRuntime();
            lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
            lateRuntime.config = {
                funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
            };
            await lateRuntime.reload();
            await lateRuntime.rememberPreparedWithdrawalTransaction(transactionHash, {
                submissionId: `late-${scenario}-wallet-owner`,
                operationId: `late-${scenario}-operation`,
                noteId: 7,
                mode: 'escape',
                destination: DESTINATION,
                finalBalance: 1_000_000,
                deploymentId: DEPLOYMENT_ID,
                chainId: 11155111,
                contractAddress: VAULT_ADDRESS
            });

            const restoreRuntime = useStoreBackedSingletonRuntime();
            await browserWalletRuntime.reload();
            const restoreEthereum = patch(globalThis, {
                ethereum: {
                    async request({ method }) {
                        if (method === 'eth_chainId') return '0xaa36a7';
                        if (method === 'eth_getTransactionReceipt') {
                            return receiptFor(transactionHash);
                        }
                        throw new Error(`Unexpected wallet method: ${method}`);
                    }
                }
            });
            const restoreClient = patch(zkapiClient, {
                browserMode: true,
                config: browserWalletRuntime.snapshot().config,
                wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
                withdrawal: null,
                withdrawals: [],
                readBrowserWithdrawalStatus: async () => scenario === 'missing'
                    ? {
                        status: 'active',
                        note_id: 7,
                        challenge_deadline: null,
                        observed_block: 105
                    }
                    : {
                        status: 'pending_withdrawal',
                        note_id: 7,
                        destination: DESTINATION,
                        final_balance: 1_000_000,
                        challenge_deadline: Math.floor(Date.now() / 1_000) + 3_600,
                        observed_block: 105
                    },
                refresh: async () => {
                    await browserWalletRuntime.reload();
                    const snapshot = browserWalletRuntime.snapshot();
                    zkapiClient.config = snapshot.config;
                    zkapiClient.withdrawals = snapshot.withdrawals;
                    return zkapiClient.snapshot();
                }
            });

            try {
                await zkapiClient.reconcileBrowserWithdrawalsOnLoad();
                const persisted = await readBrowserWallet();
                const records = await listBrowserWithdrawals(DEPLOYMENT_ID);
                if (scenario === 'missing') {
                    assert.equal(persisted.state, null);
                    assert.equal(persisted.lateWithdrawalAttempts[0].status, 'detached');
                    assert.equal(
                        browserWalletRuntime.snapshot().config.late_withdrawal_attempts.length,
                        0
                    );
                    assert.equal(records.length, 1);
                    assert.equal(records[0].phase, 'submitted_unconfirmed');
                    assert.equal(records[0].transactionHash, transactionHash);
                    assert.equal(records[0].state.note_id, 7);
                } else {
                    assert.equal(persisted.state, null);
                    assert.equal(persisted.lateWithdrawalAttempts[0].status, 'detached');
                    assert.equal(
                        browserWalletRuntime.snapshot().config.late_withdrawal_attempts.length,
                        0
                    );
                    assert.equal(records.length, 1);
                    assert.equal(records[0].phase, 'pending');
                    assert.equal(records[0].canonicalRecovery, true);
                    assert.equal(records[0].transactionHash, null);
                    assert.equal(records[0].state.note_id, 7);
                }
            } finally {
                restoreClient();
                restoreEthereum();
                restoreRuntime();
            }
        }
    });

    await t.test('a missing late receipt stays nonblocking in background until canonical transition', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ preparedWithdrawal: null }));
        const transactionHash = `0x${'81'.repeat(32)}`;
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const lateRuntime = new BrowserWalletRuntime();
        lateRuntime.manifest = { deployment_id: DEPLOYMENT_ID };
        lateRuntime.config = {
            funding: nativeFunding({ chain_id: 11155111, contract_address: VAULT_ADDRESS })
        };
        await lateRuntime.reload();
        await lateRuntime.rememberPreparedWithdrawalTransaction(
            transactionHash,
            {
                submissionId: 'background-late-wallet',
                operationId: 'background-late-operation',
                noteId: 7,
                mode: 'escape',
                destination: DESTINATION,
                finalBalance: 1_000_000,
                deploymentId: DEPLOYMENT_ID,
                chainId: 11155111,
                contractAddress: VAULT_ADDRESS
            },
            { from: DESTINATION, nonce: 3 }
        );

        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let canonicalStatus = 'active';
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    if (method === 'eth_getBlockByNumber') return { number: '0x1f4' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x1f4']);
                        return '0x3';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const statusFor = (noteId, blockTag = null) => canonicalStatus === 'active'
            ? {
                status: 'active',
                note_id: noteId,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 600
            }
            : {
                status: 'pending_withdrawal',
                note_id: noteId,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: challengeDeadline,
                observed_block: 605
            };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) => statusFor(noteId, blockTag),
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [detached] = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(detached.status, 'submitted_unconfirmed');
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'submitted_unconfirmed');
            assert.equal(record.state.note_id, 7);
            assert.equal((await readBrowserWallet()).state, null);
            assert.equal(zkapiClient.withdrawalBlocksChat, false);

            // A new selected note can coexist; even deep Active finality must
            // not restore the old note while its nonce remains unconsumed.
            await writeBrowserWallet(baseRuntime({
                state: { note_id: 8, current_balance: 2_000_000 }
            }));
            await zkapiClient.refresh({ quiet: true });
            await zkapiClient.syncEscapeWithdrawals(() => {}, record.recordId);
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'submitted_unconfirmed');
            assert.equal((await readBrowserWallet()).state.note_id, 8);
            assert.equal(zkapiClient.withdrawalBlocksChat, false);

            canonicalStatus = 'pending_withdrawal';
            await zkapiClient.syncEscapeWithdrawals(() => {}, record.recordId);
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'pending');
            assert.equal(record.challengeDeadline, challengeDeadline);
            assert.equal(record.state.note_id, 7);
            assert.equal((await readBrowserWallet()).state.note_id, 8);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('submitted-unconfirmed transfer atomically aggregates selected and late same-note attempts', async () => {
        indexedDB.clear();
        const selectedHashA = `0x${'82'.repeat(32)}`;
        const selectedHashB = `0x${'83'.repeat(32)}`;
        const lateHashA = `0x${'84'.repeat(32)}`;
        const lateHashB = `0x${'85'.repeat(32)}`;
        const submittedFrom = DESTINATION.toLowerCase();
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const lateAttempts = [lateHashA, lateHashB].map((transactionHash, index) => ({
            operationId: `late-operation-${index}`,
            submissionId: `late-submission-${index}`,
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            transactionHash,
            from: submittedFrom,
            nonce: 17,
            observedAt: 100 + index,
            status: 'submitted_late'
        }));
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            operationId: 'selected-operation',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            proof: 'escape-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000
            },
            transactionHash: selectedHashA,
            transactionHashes: [selectedHashA, selectedHashB],
            transactionAttempts: [selectedHashA, selectedHashB].map((hash, index) => ({
                hash,
                operationId: 'selected-operation',
                submissionId: `selected-submission-${index}`,
                from: submittedFrom,
                nonce: 17,
                observedAt: 90 + index
            })),
            submissionId: 'current-hashless-submission',
            submissionOwner: 'current-tab',
            submissionStartedAt: 110,
            submissionFrom: submittedFrom,
            submissionNonce: 17
        };
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal,
            lateWithdrawalAttempts: lateAttempts
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();

        try {
            await browserWalletRuntime.transferLateWithdrawalAttempt(lateAttempts[0], {
                recordId,
                mode: 'escape',
                phase: 'submitted_unconfirmed',
                chainStatus: 'active',
                noteId: 7,
                destination: DESTINATION,
                finalBalance: 1_000_000,
                transactionHash: lateHashA,
                lastObservedBlock: 120,
                clearanceReserved: false,
                error: null
            });

            const persisted = await readBrowserWallet();
            const [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.equal(persisted.preparedWithdrawal, null);
            assert.equal(record.state.note_id, 7);
            assert.deepEqual(record.preparedWithdrawal, preparedWithdrawal);
            assert.deepEqual(
                new Set(record.transactionHashes),
                new Set([selectedHashA, selectedHashB, lateHashA, lateHashB])
            );
            const attemptsByHash = new Map(record.transactionAttempts.map(attempt => [
                attempt.hash,
                attempt
            ]));
            for (const hash of [selectedHashA, selectedHashB, lateHashA, lateHashB]) {
                assert.equal(attemptsByHash.get(hash).from, submittedFrom);
                assert.equal(attemptsByHash.get(hash).nonce, 17);
            }
            assert.equal(record.startSubmissionId, 'current-hashless-submission');
            assert.equal(record.startSubmissionFrom, submittedFrom);
            assert.equal(record.startSubmissionNonce, 17);
            assert.deepEqual(
                persisted.lateWithdrawalAttempts.map(attempt => ({
                    hash: attempt.transactionHash,
                    status: attempt.status,
                    backgroundRecordId: attempt.backgroundRecordId
                })),
                [lateHashA, lateHashB].map(hash => ({
                    hash,
                    status: 'detached',
                    backgroundRecordId: recordId
                }))
            );
        } finally {
            restoreRuntime();
        }
    });

    await t.test('a transfer retires only a versioned claim that lost the pre-broadcast nonce race', async () => {
        indexedDB.clear();
        const lateHash = `0x${'92'.repeat(32)}`;
        const lateAttempt = {
            operationId: 'earlier-transfer-operation',
            submissionId: 'earlier-transfer-submission',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            clearanceReserved: false,
            withdrawalNullifier: '0x1010',
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            transactionHash: lateHash,
            from: DESTINATION,
            nonce: 52,
            observedAt: 100,
            status: 'submitted_late'
        };
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'prepared',
                mode: 'escape',
                operationId: 'fresh-pre-nonce-operation',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                withdrawalNullifier: '0x2020',
                proof: 'fresh-pre-nonce-proof',
                public_inputs: {
                    note_id: 7,
                    final_balance: 1_000_000,
                    withdrawal_nullifier: '0x2020'
                }
            },
            lateWithdrawalAttempts: [lateAttempt]
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();

        try {
            const submission = await browserWalletRuntime
                .claimPreparedWithdrawalSubmission();
            let persisted = await readBrowserWallet();
            assert.equal(persisted.preparedWithdrawal.submissionId, submission.submissionId);
            assert.equal(persisted.preparedWithdrawal.submissionNonceJournalRequired, true);
            assert.equal(persisted.preparedWithdrawal.submissionFrom, undefined);
            assert.equal(persisted.preparedWithdrawal.submissionNonce, undefined);

            await browserWalletRuntime.transferLateWithdrawalAttempt(lateAttempt, {
                recordId: `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`,
                mode: 'escape',
                phase: 'submitted_unconfirmed',
                chainStatus: 'active',
                noteId: 7,
                destination: DESTINATION,
                finalBalance: 1_000_000,
                transactionHash: lateHash,
                lastObservedBlock: 120,
                clearanceReserved: false,
                error: null
            });

            persisted = await readBrowserWallet();
            const [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.state, null);
            assert.equal(persisted.preparedWithdrawal, null);
            assert.equal(record.startSubmissionId, null);
            assert.equal(record.startOperationId, 'fresh-pre-nonce-operation');
            assert.equal(record.startSubmissionFrom, null);
            assert.equal(record.startSubmissionNonce, null);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.submissionNonceJournalRequired, undefined);
            assert.equal(record.preparedWithdrawal.submissionOutcome,
                'rejected_before_broadcast');
            assert.equal(record.dismissedStartSubmissionClaims.at(-1).submissionId,
                submission.submissionId);
            assert.equal(record.dismissedStartSubmissionClaims.at(-1).reason,
                'migrated_before_nonce_journal');
            assert.equal(record.startRecoveryPending, true);
            assert.deepEqual(record.transactionHashes, [lateHash]);

            await assert.rejects(
                browserWalletRuntime.rememberPreparedWithdrawalSubmissionMetadata(
                    submission,
                    { from: DESTINATION, nonce: 53 }
                ),
                /wallet claim changed before its nonce was saved/i
            );
            const [afterRejectedCallback] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(afterRejectedCallback.startRecoveryPending, true);
            assert.deepEqual(afterRejectedCallback.transactionHashes, [lateHash]);
        } finally {
            restoreRuntime();
        }
    });

    await t.test('a definite rejection releases a hashless start claim after late transfer', async () => {
        indexedDB.clear();
        const lateHash = `0x${'86'.repeat(32)}`;
        const newerDestination = `0x${'56'.repeat(20)}`;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const submission = {
            status: 'claimed',
            transactionHash: null,
            operationId: 'newer-start-operation',
            submissionId: 'newer-start-submission',
            noteId: 7,
            mode: 'escape',
            destination: newerDestination,
            finalBalance: 1_000_000,
            clearanceReserved: false,
            withdrawalNullifier: '0x9876',
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS
        };
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            operationId: submission.operationId,
            noteId: 7,
            destination: newerDestination,
            clearanceReserved: false,
            withdrawalNullifier: submission.withdrawalNullifier,
            proof: 'newer-escape-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000
            },
            submissionId: submission.submissionId,
            submissionOwner: 'newer-tab',
            submissionStartedAt: 100,
            submissionFrom: DESTINATION.toLowerCase(),
            submissionNonce: 18
        };
        const lateAttempt = {
            operationId: 'older-late-operation',
            submissionId: 'older-late-submission',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            clearanceReserved: false,
            withdrawalNullifier: '0x1234',
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            transactionHash: lateHash,
            observedAt: 90,
            status: 'submitted_late'
        };
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal,
            lateWithdrawalAttempts: [lateAttempt]
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.equal(params[0], lateHash);
                        return null;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: true, note: { note_id: 7, current_balance: 1_000_000 } },
            withdrawal: null,
            withdrawals: [],
            readBrowserWithdrawalStatus: async noteId => ({
                status: 'active',
                note_id: noteId,
                observed_block: 120
            }),
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [detached] = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(detached.status, 'submitted_unconfirmed');
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.recordId, recordId);
            assert.equal(record.startSubmissionId, submission.submissionId);
            assert.equal(record.startOperationId, submission.operationId);
            assert.equal(record.destination, DESTINATION);
            assert.equal(record.preparedWithdrawal.destination, newerDestination);
            assert.equal(record.preparedWithdrawal.submissionId, submission.submissionId);
            assert.equal((await readBrowserWallet()).preparedWithdrawal, null);

            await zkapiClient.recoverFailedWithdrawalSubmission({
                mode: 'escape',
                error: Object.assign(new Error('User rejected the request.'), { code: 4001 }),
                submittedHash: null,
                submission,
                submissionMetadata: {
                    from: DESTINATION.toLowerCase(),
                    nonce: 18
                },
                from: DESTINATION
            });

            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startOperationId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.submissionFrom, undefined);
            assert.equal(record.preparedWithdrawal.submissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.phase, 'prepared');
            assert.deepEqual(record.transactionHashes, [lateHash]);
            assert.equal(record.dismissedStartSubmissionClaims.at(-1).submissionId,
                submission.submissionId);

            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionOutcome, 'receipt_missing');
            assert.deepEqual(record.startMissingTransactionHashes, [lateHash]);
            assert.deepEqual(record.startReplacementTransactionHashes, []);
            await assert.rejects(
                browserWalletRuntime.claimBackgroundWithdrawalStartReplacement(
                    recordId,
                    DESTINATION
                ),
                /does not match the retained withdrawal proof/i
            );
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a migrated hashless replacement timeout releases only its same-nonce claim', async () => {
        indexedDB.clear();
        const oldHash = `0x${'8a'.repeat(32)}`;
        const lateHash = `0x${'8b'.repeat(32)}`;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal: {
                phase: 'dropped_or_pending',
                mode: 'escape',
                operationId: 'migrated-replacement-operation',
                noteId: 7,
                destination: DESTINATION,
                clearanceReserved: false,
                proof: 'saved-replacement-proof',
                public_inputs: { note_id: 7, final_balance: 1_000_000 },
                transactionHash: oldHash,
                transactionHashes: [oldHash],
                transactionAttempts: [{
                    hash: oldHash,
                    operationId: 'migrated-replacement-operation',
                    submissionId: 'original-replacement-prompt',
                    from: DESTINATION,
                    nonce: 31
                }]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            withdrawal: null,
            withdrawals: [],
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const submission = await browserWalletRuntime
                .claimPreparedWithdrawalReplacement(DESTINATION);
            assert.equal(submission.replacementNonce, 31);
            await browserWalletRuntime.rememberPreparedWithdrawalTransaction(
                lateHash,
                {
                    submissionId: 'older-late-submission',
                    operationId: 'older-late-operation',
                    noteId: 7,
                    mode: 'escape',
                    destination: DESTINATION,
                    finalBalance: 1_000_000,
                    clearanceReserved: false,
                    withdrawalNullifier: '0x1234',
                    deploymentId: DEPLOYMENT_ID,
                    chainId: 11155111,
                    contractAddress: VAULT_ADDRESS
                },
                { from: DESTINATION, nonce: 30 }
            );
            const persistedBeforeTransfer = await readBrowserWallet();
            const lateAttempt = persistedBeforeTransfer.lateWithdrawalAttempts.find(attempt =>
                attempt.transactionHash === lateHash);
            assert.ok(lateAttempt);
            await browserWalletRuntime.transferLateWithdrawalAttempt(lateAttempt, {
                recordId,
                mode: 'escape',
                phase: 'submitted_unconfirmed',
                chainStatus: 'active',
                noteId: 7,
                destination: DESTINATION,
                finalBalance: 1_000_000,
                transactionHash: lateHash,
                lastObservedBlock: 140,
                clearanceReserved: false,
                error: null
            });

            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal((await readBrowserWallet()).preparedWithdrawal, null);
            assert.equal(record.startSubmissionId, submission.submissionId);
            assert.equal(record.preparedWithdrawal.submissionId, submission.submissionId);

            const timeout = Object.assign(
                new Error('Provider timed out after accepting the replacement request.'),
                { broadcastPossible: true }
            );
            await zkapiClient.recoverFailedWithdrawalSubmission({
                mode: 'escape',
                error: timeout,
                submittedHash: null,
                submission,
                submissionMetadata: {
                    from: DESTINATION,
                    nonce: submission.replacementNonce
                },
                from: DESTINATION
            });

            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startOperationId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.submissionFrom, undefined);
            assert.equal(record.preparedWithdrawal.submissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.phase, 'dropped_or_pending');
            assert.equal(record.preparedWithdrawal.submissionOutcome,
                'replacement_result_unknown');
            assert.deepEqual(
                new Set(record.transactionHashes),
                new Set([oldHash, lateHash])
            );
            assert.deepEqual(record.preparedWithdrawal.transactionHashes, [oldHash]);
            assert.equal(record.preparedWithdrawal.transactionAttempts.length, 1);
            assert.equal(record.preparedWithdrawal.ambiguousReplacements.at(-1).submissionId,
                submission.submissionId);
        } finally {
            restoreClient();
            restoreRuntime();
        }
    });

    await t.test('pending preserves every start WAL entry before a finalized active challenge', async () => {
        indexedDB.clear();
        const knownHash = `0x${'8c'.repeat(32)}`;
        const missingHash = `0x${'8d'.repeat(32)}`;
        const knownFrom = `0x${'57'.repeat(20)}`;
        const missingFrom = `0x${'58'.repeat(20)}`;
        const hashlessFrom = `0x${'59'.repeat(20)}`;
        const knownNonce = 20;
        const missingNonce = 21;
        const hashlessNonce = 22;
        const finalizedTag = '0x2bc';
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            operationId: 'distinct-hashless-operation',
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            withdrawalNullifier: '0x5678',
            proof: 'saved-concurrent-escape-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000
            },
            transactionHash: missingHash,
            transactionHashes: [missingHash],
            transactionAttempts: [{
                hash: missingHash,
                operationId: 'secondary-missing-operation',
                submissionId: 'secondary-missing-submission',
                from: missingFrom,
                nonce: missingNonce,
                observedAt: 105
            }],
            submissionId: 'distinct-hashless-submission',
            submissionOwner: 'newer-wallet-tab',
            submissionStartedAt: 110,
            submissionFrom: hashlessFrom,
            submissionNonce: hashlessNonce
        };
        const knownAttempt = {
            operationId: 'known-success-operation',
            submissionId: 'known-success-submission',
            noteId: 7,
            mode: 'escape',
            destination: DESTINATION,
            finalBalance: 1_000_000,
            clearanceReserved: false,
            withdrawalNullifier: '0x1234',
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            transactionHash: knownHash,
            from: knownFrom,
            nonce: knownNonce,
            observedAt: 100,
            status: 'submitted_late'
        };
        await writeBrowserWallet(baseRuntime({
            preparedWithdrawal,
            lateWithdrawalAttempts: [knownAttempt]
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        await browserWalletRuntime.transferLateWithdrawalAttempt(knownAttempt, {
            recordId,
            mode: 'escape',
            phase: 'submitted_unconfirmed',
            chainStatus: 'active',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            transactionHash: knownHash,
            lastObservedBlock: 480,
            clearanceReserved: false,
            error: null
        });

        let canonicalStatus = 'pending_withdrawal';
        let finalizedActiveReads = 0;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        if (params[0] === knownHash) {
                            return withdrawalReceipt({
                                mode: 'escape',
                                transactionHash: knownHash,
                                blockNumber: 500,
                                challengeDeadline
                            });
                        }
                        assert.equal(params[0], missingHash);
                        return null;
                    }
                    if (method === 'eth_getBlockByNumber') {
                        assert.deepEqual(params, ['finalized', false]);
                        return { number: finalizedTag };
                    }
                    if (method === 'eth_getTransactionCount') {
                        assert.equal(params[1], finalizedTag);
                        if (params[0] === missingFrom) return `0x${missingNonce.toString(16)}`;
                        if (params[0] === hashlessFrom) return `0x${hashlessNonce.toString(16)}`;
                        throw new Error(`Unexpected nonce owner: ${params[0]}`);
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const statusFor = (noteId, blockTag = null) => {
            assert.equal(noteId, 7);
            if (blockTag) {
                assert.equal(blockTag, finalizedTag);
                if (canonicalStatus === 'active') finalizedActiveReads += 1;
            }
            if (canonicalStatus === 'active') {
                return {
                    status: 'active',
                    note_id: noteId,
                    observed_block: blockTag ? Number(BigInt(blockTag)) : 650
                };
            }
            return {
                status: 'pending_withdrawal',
                note_id: noteId,
                destination: DESTINATION,
                final_balance: 1_000_000,
                challenge_deadline: challengeDeadline,
                observed_block: blockTag ? Number(BigInt(blockTag)) : 600
            };
        };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) =>
                statusFor(noteId, blockTag),
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [pending] = await zkapiClient.syncEscapeWithdrawals(
                () => {},
                recordId
            );
            assert.equal(pending.status, 'pending_withdrawal');
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'pending');
            assert.equal(record.startRecoveryPending, true);
            assert.deepEqual(new Set(record.transactionHashes), new Set([
                knownHash,
                missingHash
            ]));
            const attemptsByHash = new Map(record.transactionAttempts.map(attempt => [
                attempt.hash,
                attempt
            ]));
            assert.equal(attemptsByHash.get(knownHash).from, knownFrom);
            assert.equal(attemptsByHash.get(knownHash).nonce, knownNonce);
            assert.equal(attemptsByHash.get(missingHash).from, missingFrom);
            assert.equal(attemptsByHash.get(missingHash).nonce, missingNonce);
            assert.equal(record.startSubmissionId, preparedWithdrawal.submissionId);
            assert.equal(record.startOperationId, preparedWithdrawal.operationId);
            assert.equal(record.startSubmissionFrom, hashlessFrom);
            assert.equal(record.startSubmissionNonce, hashlessNonce);
            assert.deepEqual(record.preparedWithdrawal, preparedWithdrawal);

            canonicalStatus = 'active';
            const [active] = await zkapiClient.syncEscapeWithdrawals(
                () => {},
                recordId
            );
            assert.equal(active.status, 'submitted_unconfirmed');
            assert.equal(finalizedActiveReads, 2);
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'submitted_unconfirmed');
            assert.equal(record.chainStatus, 'active');
            assert.equal(record.startRecoveryPending, true);
            assert.deepEqual(new Set(record.transactionHashes), new Set([
                knownHash,
                missingHash
            ]));
            assert.equal(record.startSubmissionId, preparedWithdrawal.submissionId);
            assert.equal(record.startOperationId, preparedWithdrawal.operationId);
            assert.equal(record.startSubmissionFrom, hashlessFrom);
            assert.equal(record.startSubmissionNonce, hashlessNonce);
            assert.deepEqual(record.preparedWithdrawal, preparedWithdrawal);

            await assert.rejects(
                browserWalletRuntime.restoreWithdrawal(recordId, {
                    expectedRevision: record.revision,
                    observedBlock: record.lastObservedBlock
                }),
                /submitted withdrawal for this balance is still being checked/i
            );
            const [retained] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(retained.recordId, recordId);
            assert.equal(retained.phase, 'submitted_unconfirmed');
            assert.equal((await readBrowserWallet()).state, null);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a dropped background start retries by exact nonce across timeout, reload, and late-hash merge', async () => {
        indexedDB.clear();
        const oldHash = `0x${'8e'.repeat(32)}`;
        const replacementHash = `0x${'8f'.repeat(32)}`;
        const operationId = 'background-exact-nonce-replacement';
        const originalNonce = 37;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const preparedWithdrawal = {
            phase: 'submitted',
            mode: 'escape',
            operationId,
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            withdrawalNullifier: '0x4321',
            proof: 'retained-background-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000,
                withdrawal_nullifier: '0x4321'
            },
            transactionHash: oldHash,
            transactionHashes: [oldHash],
            transactionAttempts: [{
                hash: oldHash,
                operationId,
                submissionId: 'original-background-submission',
                from: DESTINATION,
                nonce: originalNonce,
                observedAt: 100
            }]
        };
        await writeBrowserWallet(baseRuntime({ state: null }));
        await putBrowserWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            phase: 'submitted_unconfirmed',
            chainStatus: 'active',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            state: { note_id: 7, current_balance: 1_000_000 },
            preparedWithdrawal,
            withdrawalNullifier: '0x4321',
            transactionHash: oldHash,
            transactionHashes: [oldHash],
            transactionAttempts: clone(preparedWithdrawal.transactionAttempts),
            startRecoveryPending: true,
            startBlockNumber: 90,
            lastObservedBlock: 100
        });
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let canonicalStatus = 'active';
        let replacementPrompts = 0;
        let sawLateWal = false;
        const finalizedTag = '0x100';
        const challengeDeadline = Math.floor(Date.now() / 1_000) + 3_600;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        if (params[0] === oldHash) return null;
                        if (params[0] === replacementHash) {
                            return withdrawalReceipt({
                                mode: 'escape',
                                transactionHash: replacementHash,
                                blockNumber: 305,
                                challengeDeadline
                            });
                        }
                        throw new Error(`Unexpected receipt hash: ${params[0]}`);
                    }
                    if (method === 'eth_getBlockByNumber') {
                        assert.deepEqual(params, ['finalized', false]);
                        return { number: finalizedTag };
                    }
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, finalizedTag]);
                        return `0x${originalNonce.toString(16)}`;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const statusFor = (noteId, blockTag = null) => {
            if (blockTag) {
                return {
                    status: 'active',
                    note_id: noteId,
                    observed_block: Number(BigInt(blockTag))
                };
            }
            return canonicalStatus === 'active'
                ? {
                    status: 'active',
                    note_id: noteId,
                    observed_block: 300
                }
                : {
                    status: 'pending_withdrawal',
                    note_id: noteId,
                    destination: DESTINATION,
                    final_balance: 1_000_000,
                    challenge_deadline: challengeDeadline,
                    observed_block: 310
                };
        };
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            connectWallet: async () => DESTINATION,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) =>
                statusFor(noteId, blockTag),
            sendContractTransaction: async (
                from,
                _to,
                _data,
                onSubmitted,
                _onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                assert.equal(preparedNonce, originalNonce);
                replacementPrompts += 1;
                if (replacementPrompts === 1) {
                    throw Object.assign(
                        new Error('Provider timed out after accepting the background replacement.'),
                        { broadcastPossible: true }
                    );
                }
                canonicalStatus = 'pending_withdrawal';
                await onSubmitted(replacementHash);
                const afterSubmission = await readBrowserWallet();
                const late = afterSubmission.lateWithdrawalAttempts.find(attempt =>
                    attempt.transactionHash === replacementHash);
                assert.equal(late?.status, 'submitted_late');
                assert.equal(late?.operationId, operationId);
                assert.equal(late?.from, DESTINATION.toLowerCase());
                assert.equal(late?.nonce, originalNonce);
                sawLateWal = true;
                return withdrawalReceipt({
                    mode: 'escape',
                    transactionHash: replacementHash,
                    blockNumber: 305,
                    challengeDeadline
                });
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const [missing] = await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            assert.equal(missing.status, 'submitted_unconfirmed');
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionOutcome, 'receipt_missing');
            assert.deepEqual(record.startMissingTransactionHashes, [oldHash]);
            assert.deepEqual(
                record.startReplacementTransactionHashes,
                [oldHash],
                JSON.stringify(record)
            );

            await assert.rejects(
                () => zkapiClient.retryDroppedBackgroundWithdrawal(recordId),
                /timed out after accepting/
            );
            await browserWalletRuntime.reload();
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.startSubmissionOutcome, 'replacement_result_unknown');
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.phase, 'dropped_or_pending');
            assert.equal(record.preparedWithdrawal.proof, 'retained-background-proof');
            assert.deepEqual(record.transactionHashes, [oldHash]);
            assert.deepEqual(record.preparedWithdrawal.transactionHashes, [oldHash]);

            const result = await zkapiClient.retryDroppedBackgroundWithdrawal(recordId);
            assert.equal(result.status, 'pending_withdrawal');
            assert.equal(replacementPrompts, 2);
            assert.equal(sawLateWal, true);
            await browserWalletRuntime.reload();
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.phase, 'pending');
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.proof, 'retained-background-proof');
            assert.deepEqual(
                new Set(record.transactionHashes),
                new Set([oldHash, replacementHash])
            );
            assert.deepEqual(
                new Set(record.preparedWithdrawal.transactionHashes),
                new Set([oldHash, replacementHash])
            );
            const replacementAttempt = record.transactionAttempts.find(attempt =>
                attempt.hash === replacementHash);
            assert.equal(replacementAttempt?.from, DESTINATION.toLowerCase());
            assert.equal(replacementAttempt?.nonce, originalNonce);
            const persisted = await readBrowserWallet();
            assert.equal(
                persisted.lateWithdrawalAttempts.find(attempt =>
                    attempt.transactionHash === replacementHash)?.status,
                'detached'
            );
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a returned background replacement hash clears its migrated claim before another exact-nonce retry', async () => {
        indexedDB.clear();
        const oldHash = `0x${'90'.repeat(32)}`;
        const replacementHash = `0x${'91'.repeat(32)}`;
        const operationId = 'background-returned-hash-timeout';
        const originalNonce = 43;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const preparedWithdrawal = {
            phase: 'submitted',
            mode: 'escape',
            operationId,
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            withdrawalNullifier: '0x8765',
            proof: 'returned-hash-background-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000,
                withdrawal_nullifier: '0x8765'
            },
            transactionHash: oldHash,
            transactionHashes: [oldHash],
            transactionAttempts: [{
                hash: oldHash,
                operationId,
                submissionId: 'original-returned-hash-submission',
                from: DESTINATION,
                nonce: originalNonce,
                observedAt: 100
            }]
        };
        await writeBrowserWallet(baseRuntime({ state: null }));
        await putBrowserWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            phase: 'submitted_unconfirmed',
            chainStatus: 'active',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            state: { note_id: 7, current_balance: 1_000_000 },
            preparedWithdrawal,
            withdrawalNullifier: '0x8765',
            transactionHash: oldHash,
            transactionHashes: [oldHash],
            transactionAttempts: clone(preparedWithdrawal.transactionAttempts),
            startRecoveryPending: true,
            startBlockNumber: 90,
            lastObservedBlock: 100
        });
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const finalizedTag = '0x180';
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') {
                        assert.ok([oldHash, replacementHash].includes(params[0]));
                        return null;
                    }
                    if (method === 'eth_getBlockByNumber') {
                        assert.deepEqual(params, ['finalized', false]);
                        return { number: finalizedTag };
                    }
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, finalizedTag]);
                        return `0x${originalNonce.toString(16)}`;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        let submittedClaimId = null;
        const activeStatus = (noteId, blockTag = null) => ({
            status: 'active',
            note_id: noteId,
            observed_block: blockTag ? Number(BigInt(blockTag)) : 350
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            connectWallet: async () => DESTINATION,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) =>
                activeStatus(noteId, blockTag),
            sendContractTransaction: async (
                from,
                _to,
                _data,
                onSubmitted,
                _onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                assert.equal(preparedNonce, originalNonce);
                const [claimed] = await listBrowserWithdrawals(DEPLOYMENT_ID);
                submittedClaimId = claimed.startSubmissionId;
                assert.equal(claimed.preparedWithdrawal.submissionId, submittedClaimId);
                await onSubmitted(replacementHash);
                throw Object.assign(
                    new Error('Timed out waiting for the returned background replacement hash.'),
                    {
                        broadcastPossible: true,
                        transactionHash: replacementHash
                    }
                );
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            await assert.rejects(
                () => zkapiClient.retryDroppedBackgroundWithdrawal(recordId),
                /returned background replacement hash/i
            );
            assert.ok(submittedClaimId);
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, submittedClaimId);
            assert.equal(record.preparedWithdrawal.submissionId, submittedClaimId);
            const persistedBeforeTransfer = await readBrowserWallet();
            const lateAttempt = persistedBeforeTransfer.lateWithdrawalAttempts.find(attempt =>
                attempt.transactionHash === replacementHash);
            assert.equal(lateAttempt?.from, DESTINATION.toLowerCase());
            assert.equal(lateAttempt?.nonce, originalNonce);

            const transferred = await zkapiClient.syncLateWithdrawalAttempts();
            assert.equal(transferred[0].status, 'submitted_unconfirmed');
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startOperationId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.proof, 'returned-hash-background-proof');
            assert.deepEqual(
                new Set(record.transactionHashes),
                new Set([oldHash, replacementHash])
            );
            const replacementAttempt = record.transactionAttempts.find(attempt =>
                attempt.hash === replacementHash);
            assert.equal(replacementAttempt?.submissionId, submittedClaimId);
            assert.equal(replacementAttempt?.from, DESTINATION.toLowerCase());
            assert.equal(replacementAttempt?.nonce, originalNonce);

            await zkapiClient.syncEscapeWithdrawals(() => {}, recordId);
            await browserWalletRuntime.reload();
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionOutcome, 'receipt_missing');
            assert.deepEqual(
                new Set(record.startReplacementTransactionHashes),
                new Set([oldHash, replacementHash])
            );
            const nextClaim = await browserWalletRuntime
                .claimBackgroundWithdrawalStartReplacement(recordId, DESTINATION);
            assert.equal(nextClaim.replacementFrom, DESTINATION.toLowerCase());
            assert.equal(nextClaim.replacementNonce, originalNonce);
            assert.notEqual(nextClaim.submissionId, submittedClaimId);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('canceling a takeover of a live hashless background claim keeps its nonce guarded across reload', async () => {
        indexedDB.clear();
        const operationId = 'live-hashless-background-start';
        const originalSubmissionId = 'live-hashless-background-prompt';
        const originalNonce = 47;
        const recordId = `${DEPLOYMENT_ID}:11155111:${VAULT_ADDRESS}:7`;
        const preparedWithdrawal = {
            phase: 'awaiting_wallet',
            mode: 'escape',
            operationId,
            noteId: 7,
            destination: DESTINATION,
            clearanceReserved: false,
            withdrawalNullifier: '0x9988',
            proof: 'live-hashless-background-proof',
            public_inputs: {
                note_id: 7,
                final_balance: 1_000_000,
                withdrawal_nullifier: '0x9988'
            },
            submissionId: originalSubmissionId,
            submissionOwner: 'original-wallet-tab',
            submissionStartedAt: 100,
            submissionFrom: DESTINATION,
            submissionNonce: originalNonce
        };
        await writeBrowserWallet(baseRuntime({ state: null }));
        await putBrowserWithdrawal({
            recordId,
            deploymentId: DEPLOYMENT_ID,
            chainId: 11155111,
            contractAddress: VAULT_ADDRESS,
            mode: 'escape',
            phase: 'submitted_unconfirmed',
            chainStatus: 'active',
            noteId: 7,
            destination: DESTINATION,
            finalBalance: 1_000_000,
            state: { note_id: 7, current_balance: 1_000_000 },
            preparedWithdrawal,
            withdrawalNullifier: '0x9988',
            transactionHash: null,
            transactionHashes: [],
            transactionAttempts: [],
            startRecoveryPending: true,
            startOperationId: operationId,
            startSubmissionId: originalSubmissionId,
            startSubmissionOwner: 'original-wallet-tab',
            startSubmissionStartedAt: 100,
            startSubmissionFrom: DESTINATION,
            startSubmissionNonce: originalNonce,
            lastObservedBlock: 100
        });
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        const finalizedTag = '0x190';
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getBlockByNumber') {
                        assert.deepEqual(params, ['finalized', false]);
                        return { number: finalizedTag };
                    }
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, finalizedTag]);
                        return `0x${originalNonce.toString(16)}`;
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        let takeoverSubmissionId = null;
        const activeStatus = (noteId, blockTag = null) => ({
            status: 'active',
            note_id: noteId,
            observed_block: blockTag ? Number(BigInt(blockTag)) : 420
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawal: null,
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            connectWallet: async () => DESTINATION,
            readBrowserWithdrawalStatus: async (noteId, blockTag = null) =>
                activeStatus(noteId, blockTag),
            sendContractTransaction: async (
                from,
                _to,
                _data,
                _onSubmitted,
                _onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                assert.equal(preparedNonce, originalNonce);
                const [claimed] = await listBrowserWithdrawals(DEPLOYMENT_ID);
                takeoverSubmissionId = claimed.startSubmissionId;
                assert.notEqual(takeoverSubmissionId, originalSubmissionId);
                assert.equal(claimed.preparedWithdrawal.submissionId, takeoverSubmissionId);
                assert.equal(
                    claimed.supersededStartSubmissionClaims.at(-1).submissionId,
                    originalSubmissionId
                );
                throw Object.assign(new Error('User rejected the replacement request.'), {
                    code: 4001,
                    broadcastPossible: false
                });
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = snapshot.runtime.state
                    ? { has_note: true, note: snapshot.runtime.state }
                    : { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await assert.rejects(
                () => zkapiClient.retryDroppedBackgroundWithdrawal(recordId),
                /rejected the replacement/i
            );
            assert.ok(takeoverSubmissionId);
            await browserWalletRuntime.reload();
            let [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startSubmissionId, undefined);
            assert.equal(record.startOperationId, undefined);
            assert.equal(record.startSubmissionFrom, undefined);
            assert.equal(record.startSubmissionNonce, undefined);
            assert.equal(record.startRetryFrom, DESTINATION.toLowerCase());
            assert.equal(record.startRetryNonce, originalNonce);
            assert.equal(record.startRetryOperationId, operationId);
            assert.equal(record.preparedWithdrawal.submissionId, undefined);
            assert.equal(record.preparedWithdrawal.proof, 'live-hashless-background-proof');
            assert.deepEqual(record.transactionHashes, []);
            assert.equal((await readBrowserWallet()).state, null);

            const [stillGuarded] = await zkapiClient.syncEscapeWithdrawals(
                () => {},
                recordId
            );
            assert.equal(stillGuarded.status, 'submitted_unconfirmed');
            [record] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(record.startRecoveryPending, true);
            assert.equal(record.startRetryFrom, DESTINATION.toLowerCase());
            assert.equal(record.startRetryNonce, originalNonce);
            await assert.rejects(
                browserWalletRuntime.restoreWithdrawal(recordId, {
                    expectedRevision: record.revision,
                    observedBlock: record.lastObservedBlock
                }),
                /submitted withdrawal for this balance is still being checked/i
            );

            const retry = await browserWalletRuntime
                .claimBackgroundWithdrawalStartReplacement(recordId, DESTINATION);
            assert.equal(retry.replacementFrom, DESTINATION.toLowerCase());
            assert.equal(retry.replacementNonce, originalNonce);
            assert.notEqual(retry.submissionId, takeoverSubmissionId);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a missing deposit receipt can be replaced with the exact original nonce', async () => {
        indexedDB.clear();
        const oldHash = `0x${'86'.repeat(32)}`;
        const replacementHash = `0x${'87'.repeat(32)}`;
        await writeBrowserWallet(baseRuntime({
            state: null,
            pendingDeposit: {
                phase: 'submitted',
                operationId: 'replace-missing-deposit',
                amount: 1_000_000,
                secret: 'saved-deposit-secret',
                commitment: '0x1',
                next_note_id: 7,
                active_root: '0x2',
                zero_path: Array(32).fill('0x0'),
                transactionHash: oldHash,
                transactionHashes: [oldHash],
                transactionAttempts: [{
                    hash: oldHash,
                    operationId: 'replace-missing-deposit',
                    submissionId: 'original-deposit-prompt',
                    from: DESTINATION,
                    nonce: 23
                }]
            }
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let replacementNonce = null;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    if (method === 'eth_getBlockByNumber') return { number: '0x100' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x100']);
                        return '0x17';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            readBrowserNote: async (noteId, blockTag = 'latest') => ({
                noteId,
                commitment: '0x0',
                amount: 0n,
                expiryTs: 0,
                status: 0,
                observedBlock: blockTag === 'latest' ? null : Number(BigInt(blockTag))
            }),
            connectWallet: async () => DESTINATION,
            sendContractTransaction: async (
                from,
                _to,
                _data,
                onSubmitted,
                onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                replacementNonce = preparedNonce;
                await onPrepared({ from, nonce: preparedNonce });
                await onSubmitted(replacementHash);
                return { status: '0x1', transactionHash: replacementHash };
            },
            confirmBrowserDepositReceipt: async (plan, receipt) => {
                assert.equal(plan.secret, 'saved-deposit-secret');
                assert.equal(receipt.transactionHash, replacementHash);
                return { status: 'confirmed', noteId: 7, amount: 1_000_000 };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            const missing = await zkapiClient.recoverBrowserDeposit();
            assert.equal(missing.status, 'dropped_or_pending');
            assert.equal(missing.replacement_available, true);
            let persisted = await readBrowserWallet();
            assert.equal(persisted.pendingDeposit.phase, 'dropped_or_pending');

            const replaced = await zkapiClient.retryDroppedDeposit();
            assert.equal(replaced.status, 'confirmed');
            assert.equal(replacementNonce, 23);
            persisted = await readBrowserWallet();
            assert.equal(persisted.pendingDeposit.submissionId, undefined);
            assert.deepEqual(
                persisted.pendingDeposit.transactionHashes,
                [oldHash, replacementHash]
            );
            assert.equal(persisted.pendingDeposit.transactionAttempts.length, 2);
            assert.equal(persisted.pendingDeposit.transactionAttempts[1].nonce, 23);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });

    await t.test('a missing escape-finalization receipt can be replaced with the exact original nonce', async () => {
        indexedDB.clear();
        await writeBrowserWallet(baseRuntime({ state: null }));
        const oldHash = `0x${'88'.repeat(32)}`;
        const replacementHash = `0x${'89'.repeat(32)}`;
        let replacementPrompts = 0;
        const record = await putBrowserWithdrawal(pendingEscape({
            phase: 'finalizing',
            chainStatus: 'pending_withdrawal',
            finalizeOperationId: 'replace-missing-finalization',
            finalizeGeneration: 1,
            finalizeTransactionHash: oldHash,
            finalizeTransactionHashes: [oldHash],
            finalizeAttempts: [{
                hash: oldHash,
                operationId: 'replace-missing-finalization',
                submissionId: 'original-finalization-prompt',
                generation: 1,
                from: DESTINATION,
                nonce: 29
            }]
        }));
        const restoreRuntime = useStoreBackedSingletonRuntime();
        await browserWalletRuntime.reload();
        let replacementNonce = null;
        const restoreEthereum = patch(globalThis, {
            ethereum: {
                async request({ method, params }) {
                    if (method === 'eth_getTransactionReceipt') return null;
                    if (method === 'eth_getBlockByNumber') return { number: '0x100' };
                    if (method === 'eth_getTransactionCount') {
                        assert.deepEqual(params, [DESTINATION, '0x100']);
                        return '0x1d';
                    }
                    throw new Error(`Unexpected wallet method: ${method}`);
                }
            }
        });
        const pendingStatus = noteId => ({
            status: 'pending_withdrawal',
            note_id: noteId,
            destination: DESTINATION,
            final_balance: 1_000_000,
            challenge_deadline: record.challengeDeadline,
            observed_block: 300
        });
        const restoreClient = patch(zkapiClient, {
            browserMode: true,
            config: browserWalletRuntime.snapshot().config,
            wallet: { has_note: false, note: null },
            withdrawals: browserWalletRuntime.snapshot().withdrawals,
            readBrowserWithdrawalStatus: async noteId => pendingStatus(noteId),
            connectWallet: async () => DESTINATION,
            sendContractTransaction: async (
                from,
                _to,
                _data,
                onSubmitted,
                onPrepared,
                preparedNonce
            ) => {
                assert.equal(from, DESTINATION);
                replacementNonce = preparedNonce;
                replacementPrompts += 1;
                await onPrepared({ from, nonce: preparedNonce });
                if (replacementPrompts === 1) {
                    throw Object.assign(
                        new Error('Provider timed out after accepting the finalization replacement.'),
                        { broadcastPossible: true }
                    );
                }
                await onSubmitted(replacementHash);
                return { status: '0x1', transactionHash: replacementHash };
            },
            refresh: async () => {
                await browserWalletRuntime.reload();
                const snapshot = browserWalletRuntime.snapshot();
                zkapiClient.config = snapshot.config;
                zkapiClient.wallet = { has_note: false, note: null };
                zkapiClient.withdrawals = snapshot.withdrawals;
                return zkapiClient.snapshot();
            }
        });

        try {
            await zkapiClient.syncEscapeWithdrawals(() => {}, record.recordId);
            let [persisted] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.finalizeSubmissionOutcome, 'receipt_missing');

            await assert.rejects(
                () => zkapiClient.retryDroppedFinalization(record.recordId),
                /timed out after accepting/
            );
            [persisted] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.finalizeSubmissionId, undefined);
            assert.equal(persisted.finalizeSubmissionOutcome, 'replacement_result_unknown');
            assert.deepEqual(persisted.finalizeTransactionHashes, [oldHash]);

            const result = await zkapiClient.retryDroppedFinalization(record.recordId);
            assert.equal(result.status, 'pending_withdrawal');
            assert.equal(replacementNonce, 29);
            assert.equal(replacementPrompts, 2);
            [persisted] = await listBrowserWithdrawals(DEPLOYMENT_ID);
            assert.equal(persisted.finalizeSubmissionId, undefined);
            assert.deepEqual(
                persisted.finalizeTransactionHashes,
                [oldHash, replacementHash]
            );
            assert.equal(persisted.finalizeAttempts.length, 2);
            assert.equal(persisted.finalizeAttempts[1].nonce, 29);
        } finally {
            restoreClient();
            restoreEthereum();
            restoreRuntime();
        }
    });
});
