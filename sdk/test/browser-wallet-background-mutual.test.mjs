import assert from 'node:assert/strict';
import test from 'node:test';

// Serial, copy-on-write transactions model IndexedDB's overlapping-store locks
// and abort rollback. Concurrent claims must execute real exported store code.
function memoryIndexedDb() {
    const stores = new Map();
    const keys = new Map();
    let opened = false;
    let previous = Promise.resolve();
    const database = {
        objectStoreNames: { contains: name => stores.has(name) },
        createObjectStore(name, options = {}) { stores.set(name, new Map()); keys.set(name, options.keyPath); },
        transaction(names) {
            const allowed = Array.isArray(names) ? names : [names];
            let release;
            const ready = previous;
            previous = new Promise(resolve => { release = resolve; });
            let pending = 0;
            let timer;
            let ended = false;
            let values;
            const start = ready.then(() => {
                values = new Map(allowed.map(name => [name, structuredClone(stores.get(name))]));
            });
            const schedule = () => {
                clearTimeout(timer);
                timer = setTimeout(() => {
                    if (ended || pending) return;
                    ended = true;
                    for (const [name, value] of values) stores.set(name, value);
                    transaction.oncomplete?.();
                    release();
                }, 0);
            };
            const transaction = {
                abort() {
                    if (ended) return;
                    ended = true;
                    clearTimeout(timer);
                    start.then(() => { transaction.onabort?.(); release(); });
                },
                objectStore(name) {
                    assert.ok(allowed.includes(name));
                    const request = operation => {
                        const result = {};
                        pending += 1;
                        start.then(() => {
                            if (ended) return;
                            try { result.result = structuredClone(operation(values.get(name))); result.onsuccess?.(); }
                            catch (error) { result.error = error; result.onerror?.(); }
                            finally { pending -= 1; schedule(); }
                        });
                        return result;
                    };
                    return {
                        get: key => request(store => store.get(key)),
                        getAll: () => request(store => [...store.values()]),
                        put: (value, key) => request(store => {
                            const identity = key ?? value[keys.get(name)];
                            store.set(identity, structuredClone(value)); return identity;
                        }),
                        delete: key => request(store => store.delete(key))
                    };
                }
            };
            return transaction;
        }
    };
    return {
        clear: () => { for (const store of stores.values()) store.clear(); },
        open() {
            const result = {};
            queueMicrotask(() => {
                result.result = database;
                if (!opened) { opened = true; result.onupgradeneeded?.(); }
                result.onsuccess?.();
            });
            return result;
        }
    };
}

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };
globalThis.zkapiWallet = (await import('../wallet.js')).default;
const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const VAULT = `0x${'11'.repeat(20)}`;
const DESTINATION = `0x${'22'.repeat(20)}`;
const HASH = `0x${'ab'.repeat(32)}`;
const DEPLOYMENT = 'background-mutual-test';
const RECORD_ID = `${DEPLOYMENT}:1:${VAULT}:7`;

async function setup(shared = false) {
    indexedDB.clear();
    const state = { note_id: 7, current_balance: 1850000, chain_id: 1, contract_address: VAULT, secret: 'old-private-state' };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT,
        state: { note_id: 8, current_balance: 5000000, secret: 'new-private-state' },
        journal: { request: 'new-chat-in-flight' }, lease: { api_key: 'new-key', ownerId: 'other-tab' } });
    await store.putBrowserWithdrawal({ recordId: RECORD_ID, deploymentId: DEPLOYMENT,
        chainId: 1, contractAddress: VAULT, noteId: 7, mode: 'mutual', destination: DESTINATION,
        phase: 'parked', clearanceReserved: true, state, finalBalance: state.current_balance,
        withdrawalNullifier: '0x777', preparedWithdrawal: { phase: 'reserving', mode: 'mutual',
            noteId: 7, operationId: 'old-operation', destination: DESTINATION,
            clearanceReserved: true, withdrawalNullifier: '0x777' } });
    const runtime = shared ? sharedRuntime : Object.create(BrowserWalletRuntime.prototype);
    Object.assign(runtime, { manifest: { deployment_id: DEPLOYMENT }, ownerId: 'this-tab',
        config: { funding: { chain_id: 1, contract_address: VAULT, protocol_server_url: 'https://test.invalid' },
            wallet_core: {}, proving_keys: { withdrawal: 'test-key' } },
        activeLease: { api_key: 'new-key', inFlight: 1 }, init: async () => {}, notify() {},
        treePath: async (note, required, root) => {
            assert.equal(note, 7); assert.equal(required, true);
            return { active_root: root, siblings: [] };
        },
        // Every clearance carries one kind-2 ownership proof (vault revision 3).
        generateOwnershipProof: async ({ nullifier }) => {
            assert.equal(nullifier, '0x777');
            return { public_inputs: { kind: 2, withdrawal_nullifier: nullifier }, proof: { proof: 'ownership' } };
        },
        remoteJson: async (_url, options) => {
            const body = JSON.parse(options.body);
            assert.equal(body.withdrawal_nullifier, '0x777');
            assert.equal(body.ownership_proof.public_inputs.kind, 2);
            return { withdrawal_nullifier: '0x777', signature: { r_x: '0x1', r_y: '0x2', s: '0x3' } };
        },
        worker: { async call(method, args) {
            assert.equal(args.state.note_id, 7);
            if (method === 'withdrawalNullifier') return '0x777';
            assert.equal(method, 'prepareWithdrawal');
            return { mode: 'mutual', proof: 'fresh-proof', public_inputs: {
                note_id: 7, final_balance: state.current_balance, chain_id: 1,
                contract_address: VAULT, active_root: args.args.active_root,
                withdrawal_nullifier: '0x777', destination: [...Buffer.from(DESTINATION.slice(2), 'hex')],
                kind: 1, next_nullifier: '0x0', conceded: 0, valid_until: args.args.valid_until } };
        } }
    });
    await runtime.reload();
    return { runtime, selected: await store.readBrowserWallet(), lease: runtime.activeLease };
}

const prepare = runtime => runtime.prepareBackgroundWithdrawal(RECORD_ID, { expectedActiveRoot: '0x99' });
const record = async () => (await store.listBrowserWithdrawals(DEPLOYMENT))[0];
async function assertIndependent(runtime, selected, lease) {
    assert.deepEqual(await store.readBrowserWallet(), selected);
    assert.equal(runtime.activeLease, lease);
    assert.equal(lease.inFlight, 1);
}

test('prepare and claim old note without changing the selected chat or live lease', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    assert.equal(plan.public_inputs.note_id, 7);
    assert.equal(plan.destination, DESTINATION);
    assert.notEqual(plan.operationId, 'old-operation');
    const claims = await Promise.allSettled([
        runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId),
        runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId)
    ]);
    assert.equal(claims.filter(result => result.status === 'fulfilled').length, 1);
    const claim = claims.find(result => result.status === 'fulfilled').value;
    assert.equal(claim.plan.public_inputs.active_root, '0x99');
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 12 });
    await runtime.markBackgroundWithdrawalAmbiguous(claim, 'Wallet disconnected');
    await runtime.reload();
    assert.equal((await record()).startSubmissionNonce, 12);
    await assert.rejects(() => prepare(runtime), /saved withdrawal/);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    const submitted = await record();
    assert.equal(submitted.transactionHash, HASH);
    assert.equal(submitted.startSubmissionId, undefined);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim, { from: DESTINATION, nonce: 12 });
    assert.equal((await record()).transactionAttempts.length, 1);
    await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'closed_unconfirmed', chainStatus: 'closed' });
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    assert.equal((await record()).phase, 'closed_unconfirmed');
    await assertIndependent(runtime, selected, lease);
});

test('definite rejection restores parked action and late old hash retains the newer claim', async () => {
    const { runtime, selected, lease } = await setup();
    const first = await prepare(runtime);
    const oldClaim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, first.operationId);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(oldClaim, { from: DESTINATION, nonce: 4 });
    await runtime.releaseBackgroundWithdrawalSubmission(oldClaim);
    assert.equal((await record()).phase, 'parked');
    assert.equal((await record()).startRecoveryPending, false);
    const second = await prepare(runtime);
    const newerClaim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, second.operationId);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, oldClaim);
    assert.equal((await record()).startSubmissionId, newerClaim.submissionId);
    await runtime.releaseBackgroundWithdrawalSubmission(newerClaim);
    assert.equal((await record()).startRecoveryPending, true);
    assert.equal((await record()).phase, 'submitted_unconfirmed');
    await assert.rejects(() => prepare(runtime), /saved withdrawal/);
    await assertIndependent(runtime, selected, lease);
});

test('display-only polling cannot discard a proof but a competing prepared plan does', async () => {
    const { runtime, selected, lease } = await setup();
    const worker = runtime.worker.call;
    runtime.worker.call = async (method, args) => {
        if (method === 'prepareWithdrawal') await store.updateBrowserWithdrawal(RECORD_ID, { lastObservedBlock: 100, error: null });
        return worker(method, args);
    };
    await prepare(runtime);
    const oldPlan = (await record()).preparedWithdrawal.operationId;
    runtime.worker.call = async (method, args) => {
        if (method === 'prepareWithdrawal') {
            const current = await record();
            await store.updateBrowserWithdrawal(RECORD_ID, { preparedWithdrawal: { ...current.preparedWithdrawal, operationId: 'competitor' } });
        }
        return worker(method, args);
    };
    await assert.rejects(() => prepare(runtime), /changed while its proof/);
    await assert.rejects(() => runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, oldPlan), /proof changed/);
    await assertIndependent(runtime, selected, lease);
});

test('wrong note, vault, root, nullifier, recipient or amount from worker fails closed', async () => {
    for (const patch of [{ note_id: 8 }, { chain_id: 2 }, { contract_address: DESTINATION },
        { active_root: '0x98' }, { withdrawal_nullifier: '0x778' }, { destination: VAULT },
        { final_balance: 9000000 }, { kind: 0 }, { kind: 2 }, { conceded: 1 }, { next_nullifier: '0x5' }]) {
        const { runtime, selected, lease } = await setup();
        const call = runtime.worker.call;
        runtime.worker.call = async (method, args) => {
            const result = await call(method, args);
            if (method === 'prepareWithdrawal') Object.assign(result.public_inputs, patch);
            return result;
        };
        await assert.rejects(() => prepare(runtime), /does not match/);
        assert.equal((await record()).preparedWithdrawal.operationId, 'old-operation');
        await assertIndependent(runtime, selected, lease);
    }
});

test('repair migrates only synthetic challenge metadata and atomically respects a new late WAL', async () => {
    const { runtime, selected, lease } = await setup();
    let current = await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'challenged_unconfirmed',
        chainStatus: 'active', challengeObservedBlock: 99, finalityCheckedBlock: 98, finalizedBlockNumber: 80 });
    await runtime.repairUnsubmittedBackgroundWithdrawal(RECORD_ID, 100, current.revision);
    assert.equal((await record()).phase, 'parked');
    assert.equal((await record()).challengeObservedBlock, undefined);
    let notifications = 0;
    runtime.notify = () => { notifications += 1; };
    await runtime.repairUnsubmittedBackgroundWithdrawal(RECORD_ID, 100, (await record()).revision);
    assert.equal(notifications, 0, 'unchanged status must not refresh the visible UI');
    await assertIndependent(runtime, selected, lease);
    current = await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'challenged_unconfirmed' });
    await store.writeBrowserWallet({ ...selected, lateWithdrawalAttempts: [{ status: 'submitted_late',
        deploymentId: DEPLOYMENT, chainId: 1, contractAddress: VAULT, noteId: 7, transactionHash: HASH }] });
    assert.equal(await runtime.repairUnsubmittedBackgroundWithdrawal(RECORD_ID, 101, current.revision), null);
    assert.equal((await record()).phase, 'challenged_unconfirmed');
});

test('a different chat may commit during background proving without being overwritten', async () => {
    const { runtime, selected, lease } = await setup();
    const call = runtime.worker.call;
    let newer;
    runtime.worker.call = async (method, args) => {
        if (method === 'prepareWithdrawal') {
            newer = await store.writeBrowserWallet({ ...selected,
                state: { ...selected.state, current_balance: 4990000 }, journal: null,
                pendingDeposit: { transactionHash: 'unrelated-deposit' } });
        }
        return call(method, args);
    };
    await prepare(runtime);
    await assertIndependent(runtime, newer, lease);
});

test('claim identities, saved nonce and unresolved transaction evidence fail closed', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await assert.rejects(() => runtime.rememberBackgroundWithdrawalSubmissionMetadata(
        { ...claim, noteId: 8 }, { from: DESTINATION, nonce: 2 }), /identity changed/);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 2 });
    await assert.rejects(() => runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim,
        { from: DESTINATION, nonce: 3 }), /nonce changed/);
    await assert.rejects(() => runtime.releaseBackgroundWithdrawalSubmission(
        { ...claim, submissionId: 'other-tab' }), /claim changed/);
    await runtime.releaseBackgroundWithdrawalSubmission(claim);
    for (const evidence of [{ transactionHash: HASH }, { finalizeAttempts: [{ hash: HASH }] },
        { startRetryNonce: 0 }, { startBlockNumber: 1 }, { challengeDeadline: 1000 }]) {
        const current = await record();
        await store.putBrowserWithdrawal({ ...current, ...evidence });
        await assert.rejects(() => prepare(runtime), /saved withdrawal/);
        await store.putBrowserWithdrawal(current);
    }
    await assertIndependent(runtime, selected, lease);
});

test('a late hash after canonical terminal cleanup is audited without restoring private state', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 2 });
    await store.updateBrowserWithdrawal(RECORD_ID, { phase: 'closed', chainStatus: 'closed' }, { sanitize: true });
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    assert.equal((await record()).phase, 'closed');
    assert.equal((await record()).startSubmissionId, undefined);
    assert.equal((await record()).startRecoveryPending, false);
    assert.equal((await record()).state, undefined);
    assert.equal((await record()).preparedWithdrawal, undefined);
    assert.deepEqual((await record()).resolvedStartTransactionHistory[0].lateObservedHashes, [HASH]);
    assert.doesNotMatch(JSON.stringify((await record()).resolvedStartTransactionHistory), /secret|proof|withdrawalNullifier/);
    await assertIndependent(runtime, selected, lease);
});

test('an exact-nonce takeover preserves both its claim and the old prompt’s late hash', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const first = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(first, { from: DESTINATION, nonce: 5 });
    await runtime.markBackgroundWithdrawalAmbiguous(first, 'Connection interrupted');
    await store.updateBrowserWithdrawal(RECORD_ID, { chainStatus: 'active' });
    const replacement = await runtime.claimBackgroundWithdrawalStartReplacement(RECORD_ID, DESTINATION);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, first);
    assert.equal((await record()).startSubmissionId, replacement.submissionId);
    assert.equal((await record()).transactionHash, HASH);
    await assertIndependent(runtime, selected, lease);
});

test('only fully finalized resolution clears live hashes for fresh reproof', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 5 });
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    let current = await record();
    const evidence = { resolvedTransactionHashes: [HASH], finalizedBlock: 100, observedBlock: 101 };
    await assert.rejects(() => runtime.resolveBackgroundWithdrawalForRetry(RECORD_ID,
        { ...evidence, expectedRevision: current.revision }), /unresolved/);
    current = await store.updateBrowserWithdrawal(RECORD_ID, {
        chainStatus: 'active', startRecoveryPending: false, startSubmissionOutcome: 'resolved'
    });
    await assert.rejects(() => runtime.resolveBackgroundWithdrawalForRetry(RECORD_ID,
        { ...evidence, expectedRevision: current.revision, resolvedTransactionHashes: [] }), /Every saved/);
    await runtime.resolveBackgroundWithdrawalForRetry(RECORD_ID, { ...evidence, expectedRevision: current.revision });
    const resolved = await record();
    assert.equal(resolved.phase, 'parked');
    assert.equal(resolved.transactionHash, undefined);
    assert.equal(resolved.preparedWithdrawal.proof, undefined);
    assert.equal(resolved.withdrawalNullifier, '0x777');
    assert.doesNotMatch(JSON.stringify(resolved.resolvedStartTransactionHistory), /secret|proof|withdrawalNullifier/);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    assert.equal((await record()).phase, 'parked');
    const next = await prepare(runtime);
    assert.notEqual(next.operationId, plan.operationId);
    await assertIndependent(runtime, selected, lease);
});

test('legacy late-hash transfer for a background replacement preserves the selected live lease', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    const attempt = { ...claim, transactionHash: HASH, from: DESTINATION, nonce: 5,
        status: 'submitted_late', observedAt: Date.now() };
    delete attempt.plan;
    await store.writeBrowserWallet({ ...selected, lateWithdrawalAttempts: [attempt] });
    await runtime.transferLateWithdrawalAttempt(attempt, {
        ...await record(), phase: 'submitted_unconfirmed', chainStatus: 'active'
    });
    const current = await store.readBrowserWallet();
    assert.deepEqual(current.state, selected.state);
    assert.deepEqual(current.journal, selected.journal);
    assert.deepEqual(current.lease, selected.lease);
    assert.equal(runtime.activeLease, lease);
    assert.equal(lease.inFlight, 1);
    assert.equal((await record()).transactionHash, HASH);
});

test('a finalized hashless claim can report its first late hash without reviving a transaction', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 6 });
    const current = await record();
    const resolvedPrepared = { ...current.preparedWithdrawal };
    delete resolvedPrepared.submissionId;
    const ready = await store.updateBrowserWithdrawal(RECORD_ID, {
        chainStatus: 'active', startRecoveryPending: false, startSubmissionOutcome: 'resolved',
        startSubmissionId: null, preparedWithdrawal: resolvedPrepared,
        resolvedStartClaims: [{ submissionId: claim.submissionId, operationId: claim.operationId,
            from: DESTINATION, nonce: 6 }]
    });
    await runtime.resolveBackgroundWithdrawalForRetry(RECORD_ID, {
        expectedRevision: ready.revision, resolvedTransactionHashes: [], finalizedBlock: 100, observedBlock: 101
    });
    await prepare(runtime);
    const preparedOperation = (await record()).preparedWithdrawal.operationId;
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    assert.equal((await record()).phase, 'parked');
    assert.equal((await record()).transactionHash, undefined);
    assert.equal((await record()).preparedWithdrawal.operationId, preparedOperation);
    assert.deepEqual((await record()).resolvedStartTransactionHistory[0].lateObservedHashes, [HASH]);
    await assertIndependent(runtime, selected, lease);
});

// Keep the client's actual reconciliation and IndexedDB/runtime code together:
// only external Ethereum observations are mocked, never the wallet transitions.
async function clientRecoveryScenario({ receipt = null, activeFinalized = true } = {}) {
    const context = await setup(true);
    const chain = { receipt, activeFinalized, head: 120, finalized: activeFinalized ? 120 : 110, nonceBlock: 100,
        nonceChecks: 0, stateChecks: [] };
    globalThis.ethereum = { async request({ method, params }) {
        assert.equal(method, 'eth_getTransactionReceipt', 'Recovery must never request a wallet signature');
        assert.deepEqual(params, [HASH]);
        return structuredClone(chain.receipt);
    } };
    const reloadClient = async () => {
        const client = new ZkapiClient();
        client.browserMode = true;
        client.config = context.runtime.config;
        client.readBrowserWithdrawalStatus = async noteId => {
            assert.equal(noteId, 7);
            return { status: 'active', observed_block: chain.head };
        };
        client.browserTransactionNonceConsumed = async (attempt, noteId, status) => {
            assert.equal(noteId, 7);
            assert.equal(status, 'active');
            assert.equal(attempt.from, DESTINATION);
            assert.equal(attempt.nonce, 6);
            chain.nonceChecks += 1;
            return { consumed: true, checkedBlock: chain.nonceBlock, source: 'finalized' };
        };
        client.browserRevertedReceiptFinality = async (hash, received) => {
            assert.equal(hash, HASH);
            assert.equal(received.status, '0x0');
            return { finalized: true, checkedBlock: 100, source: 'finalized' };
        };
        client.browserWithdrawalStateFinality = async (noteId, status, minimumBlock, observedBlock) => {
            assert.equal(noteId, 7);
            assert.equal(status, 'active');
            assert.equal(observedBlock, chain.head);
            assert.ok(minimumBlock >= chain.nonceBlock);
            chain.stateChecks.push(minimumBlock);
            return { finalized: chain.activeFinalized && chain.finalized >= minimumBlock,
                checkedBlock: chain.finalized, source: 'finalized' };
        };
        client.refresh = async () => {
            await context.runtime.reload();
            client.withdrawals = context.runtime.snapshot().withdrawals;
            client.wallet = { has_note: true, note: context.runtime.runtime.state };
            return client.snapshot();
        };
        await client.refresh();
        return client;
    };
    const plan = await prepare(context.runtime);
    const claim = await context.runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    await context.runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim, { from: DESTINATION, nonce: 6 });
    return { ...context, chain, reloadClient, plan, claim };
}

test('client reconciliation finalizes a reverted old hash and permits fresh proof without touching the new chat', async () => {
    const context = await clientRecoveryScenario({ receipt: { status: '0x0', blockNumber: '0x64' } });
    const { runtime, selected, lease, claim, plan, reloadClient, chain } = context;
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    const client = await reloadClient();
    assert.equal(client.withdrawals[0].backgroundWithdrawalReady, false);
    await client.syncEscapeWithdrawals(() => {}, RECORD_ID);
    const reset = await record();
    assert.equal(reset.phase, 'parked');
    assert.equal(reset.startResolutionBlock, undefined);
    assert.equal(reset.transactionHash, undefined);
    assert.equal(reset.preparedWithdrawal.proof, undefined);
    assert.equal(runtime.snapshot().withdrawals[0].backgroundWithdrawalReady, true);
    assert.deepEqual(reset.resolvedStartTransactionHistory[0].transactionHashes, [HASH]);
    assert.equal(chain.nonceChecks, 1);
    const fresh = await prepare(runtime);
    assert.notEqual(fresh.operationId, plan.operationId);
    const ready = structuredClone(await record());
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    assert.deepEqual(await record(), ready, 'A known finalized hash is an idempotent audit callback');
    await assertIndependent(runtime, selected, lease);
});

test('hashless nonce resolution survives reload until Active finality, then archives a first late hash only', async () => {
    const context = await clientRecoveryScenario({ activeFinalized: false });
    const { runtime, selected, lease, claim, plan, reloadClient, chain } = context;
    await runtime.markBackgroundWithdrawalAmbiguous(claim, 'The wallet connection ended');
    let client = await reloadClient();
    await client.syncEscapeWithdrawals(() => {}, RECORD_ID);
    const waiting = await record();
    assert.equal(waiting.phase, 'recovery_unconfirmed');
    assert.equal(waiting.startSubmissionId, null);
    assert.equal(waiting.preparedWithdrawal.submissionId, undefined);
    assert.equal(waiting.transactionHash, undefined);
    assert.equal(waiting.startRecoveryPending, false);
    assert.equal(waiting.startSubmissionOutcome, 'resolved');
    assert.equal(waiting.startResolutionBlock, 100);
    assert.equal(waiting.resolvedStartClaims[0].submissionId, claim.submissionId);
    assert.equal(client.withdrawals[0].backgroundWithdrawalReady, false);
    await assert.rejects(() => prepare(runtime), /saved withdrawal/);
    await assertIndependent(runtime, selected, lease);

    // No original live claim/hash remains after reload. Durable resolution
    // metadata must nevertheless bring this record through the retry reset.
    chain.head = 130;
    chain.finalized = 125;
    chain.activeFinalized = true;
    client = await reloadClient();
    await client.syncEscapeWithdrawals(() => {}, RECORD_ID);
    const reset = await record();
    assert.equal(reset.phase, 'parked');
    assert.equal(reset.startResolutionBlock, undefined);
    assert.equal(reset.resolvedStartClaims, undefined);
    assert.equal(reset.preparedWithdrawal.proof, undefined);
    assert.equal(client.withdrawals[0].backgroundWithdrawalReady, true);
    assert.equal(chain.nonceChecks, 1, 'A finalized nonce remains resolved across reload');
    assert.deepEqual(chain.stateChecks, [120, 120]);
    assert.deepEqual(reset.resolvedStartTransactionHistory[0].resolvedClaims, [{
        submissionId: claim.submissionId, operationId: claim.operationId, from: DESTINATION, nonce: 6
    }]);
    const fresh = await prepare(runtime);
    assert.notEqual(fresh.operationId, plan.operationId);
    const newPrepared = structuredClone((await record()).preparedWithdrawal);
    await runtime.rememberBackgroundWithdrawalTransaction(HASH, claim);
    const withLateAudit = await record();
    assert.equal(withLateAudit.phase, 'parked');
    assert.equal(withLateAudit.transactionHash, undefined);
    assert.deepEqual(withLateAudit.preparedWithdrawal, newPrepared);
    assert.deepEqual(withLateAudit.resolvedStartTransactionHistory[0].lateObservedHashes, [HASH]);
    assert.doesNotMatch(JSON.stringify(runtime.snapshot().withdrawals), /old-private-state|fresh-proof|0x777/);
    await assertIndependent(runtime, selected, lease);
});

test('an explicit cancel after preflight reload releases only the still-unbroadcast preparation', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    // Closing the page loses the in-memory send, but the exact claim remains.
    await runtime.reload();
    assert.equal(runtime.snapshot().withdrawals[0].backgroundPreparationCancelable, true);
    await runtime.cancelBackgroundWithdrawalPreparation(RECORD_ID);
    const canceled = await record();
    assert.equal(canceled.phase, 'parked');
    assert.equal(canceled.startSubmissionId, undefined);
    assert.equal(canceled.startRecoveryPending, false);
    assert.equal(canceled.preparedWithdrawal.phase, 'prepared');
    assert.equal(canceled.preparedWithdrawal.proof, plan.proof);
    assert.equal(runtime.snapshot().withdrawals[0].backgroundPreparationCancelable, false);
    assert.equal(runtime.snapshot().withdrawals[0].backgroundWithdrawalReady, true);
    await assert.rejects(() => runtime.rememberBackgroundWithdrawalSubmissionMetadata(
        claim, { from: DESTINATION, nonce: 6 }), /claim changed/);
    const fresh = await prepare(runtime);
    const next = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, fresh.operationId);
    assert.notEqual(next.submissionId, claim.submissionId);
    await assertIndependent(runtime, selected, lease);
});

test('nonce persistence and explicit preparation cancellation serialize in either race order', async () => {
    for (const nonceWins of [true, false]) {
        const { runtime, selected, lease } = await setup();
        const plan = await prepare(runtime);
        const claim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
        const metadata = () => runtime.rememberBackgroundWithdrawalSubmissionMetadata(claim,
            { from: DESTINATION, nonce: 6 });
        const cancel = () => store.releaseBrowserBackgroundWithdrawalSubmission(claim, { requireNoNonce: true });
        // Use the atomic exported operations so the overlapping transactions
        // genuinely race, independent of runtime reload scheduling.
        const results = await Promise.allSettled(nonceWins ? [metadata(), cancel()] : [cancel(), metadata()]);
        assert.equal(results[0].status, 'fulfilled');
        assert.equal(results[1].status, 'rejected');
        const saved = await record();
        await runtime.reload();
        if (nonceWins) {
            assert.match(results[1].reason.message, /may already have reached MetaMask/);
            assert.equal(saved.startSubmissionId, claim.submissionId);
            assert.equal(saved.startSubmissionNonce, 6);
            assert.equal(saved.startRecoveryPending, true);
            assert.equal(runtime.snapshot().withdrawals[0].backgroundPreparationCancelable, false);
            await assert.rejects(() => runtime.cancelBackgroundWithdrawalPreparation(RECORD_ID), /may already/);
        } else {
            assert.match(results[1].reason.message, /claim changed/);
            assert.equal(saved.phase, 'parked');
            assert.equal(saved.startSubmissionNonce, undefined);
            assert.equal(saved.startRecoveryPending, false);
        }
        await assertIndependent(runtime, selected, lease);
    }
});

test('preparation cancel rejects legacy claims and every real transaction or predecessor signal', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    const claimed = structuredClone(await record());
    const variants = [
        { independentWithdrawal: false },
        { preparedWithdrawal: { ...claimed.preparedWithdrawal, submissionNonceJournalRequired: false } },
        { startSubmissionNonce: 0 },
        { preparedWithdrawal: { ...claimed.preparedWithdrawal, submissionNonce: 0 } },
        { startSubmissionFrom: DESTINATION },
        { transactionHash: HASH },
        { preparedWithdrawal: { ...claimed.preparedWithdrawal, transactionHashes: [HASH] } },
        { supersededStartSubmissionClaims: [{ submissionId: 'another-claim' }] },
        { ambiguousStartReplacements: [{ nonce: 0 }] },
        { preparedWithdrawal: { ...claimed.preparedWithdrawal, ambiguousSubmissions: [{}] } },
        { finalizeTransactionHash: HASH },
        { startResolutionBlock: 100 },
        { startSubmissionOutcome: 'ambiguous' },
        { preparedWithdrawal: { ...claimed.preparedWithdrawal, submissionId: 'different-claim' } }
    ];
    for (const patch of variants) {
        await store.putBrowserWithdrawal({ ...claimed, ...patch });
        await runtime.reload();
        assert.equal(runtime.snapshot().withdrawals[0].backgroundPreparationCancelable, false);
        await assert.rejects(() => runtime.cancelBackgroundWithdrawalPreparation(RECORD_ID), /may already|claim changed/);
    }
    await store.putBrowserWithdrawal(claimed);
    await store.writeBrowserWallet({ ...selected, lateWithdrawalAttempts: [{ status: 'submitted_late',
        deploymentId: DEPLOYMENT, noteId: 7, transactionHash: HASH }] });
    await runtime.reload();
    assert.equal(runtime.snapshot().withdrawals[0].backgroundPreparationCancelable, false);
    await assert.rejects(() => runtime.cancelBackgroundWithdrawalPreparation(RECORD_ID), /may already/);
    await store.writeBrowserWallet(selected);
    await assertIndependent(runtime, await store.readBrowserWallet(), lease);
});

test('a canceled old preflight cannot broadcast or release a newer wallet claim', async () => {
    const { runtime, selected, lease } = await setup();
    const plan = await prepare(runtime);
    const oldClaim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, plan.operationId);
    let resumeNonce;
    let reachedNonce;
    const nonceReady = new Promise(resolve => { reachedNonce = resolve; });
    const nonceResult = new Promise(resolve => { resumeNonce = resolve; });
    let broadcasts = 0;
    globalThis.ethereum = { async request({ method }) {
        if (method === 'eth_estimateGas') return '0x7a120';
        if (method === 'eth_getTransactionCount') { reachedNonce(); return nonceResult; }
        if (method === 'eth_sendTransaction') { broadcasts += 1; return HASH; }
        throw new Error(`Unexpected wallet request: ${method}`);
    } };
    const client = new ZkapiClient();
    client.assertFundingChain = async () => {};
    const oldSend = client.sendContractTransaction(DESTINATION, VAULT, '0x1234', null,
        metadata => runtime.rememberBackgroundWithdrawalSubmissionMetadata(oldClaim, metadata));
    const rejectedSend = assert.rejects(oldSend, error => {
        assert.match(error.message, /claim changed/);
        assert.equal(error.transactionStage, 'journal');
        assert.equal(error.broadcastPossible, false);
        return true;
    });
    await nonceReady;
    await runtime.cancelBackgroundWithdrawalPreparation(RECORD_ID);
    const fresh = await prepare(runtime);
    const newClaim = await runtime.claimBackgroundWithdrawalSubmission(RECORD_ID, fresh.operationId);
    const before = structuredClone(await record());
    resumeNonce('0x6');
    await rejectedSend;
    assert.equal(broadcasts, 0);
    // The original driver's failure cleanup also cannot release/mark the new
    // claim: both mutations compare the original exact operation and claim.
    await assert.rejects(() => runtime.releaseBackgroundWithdrawalSubmission(oldClaim), /claim changed/);
    await assert.rejects(() => runtime.markBackgroundWithdrawalAmbiguous(oldClaim, 'old request failed'), /claim changed/);
    assert.equal((await record()).startSubmissionId, newClaim.submissionId);
    assert.deepEqual(await record(), before);
    await assertIndependent(runtime, selected, lease);
});
