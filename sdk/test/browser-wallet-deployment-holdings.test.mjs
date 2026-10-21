import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, GENESIS_ANCHOR, VAULT, createHarness, memoryIndexedDb, noteState, nullifierFor
} from './helpers/request-archive-harness.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');

// DEPLOYMENT plays the legacy deployment; the host then pins a hardened one.
const LEGACY = DEPLOYMENT;
const HARDENED = 'hardened-deployment';
// A close whose clearance the server granted: the only kind a user can set aside.
const reserving = () => ({ phase: 'reserving', mode: 'mutual', operationId: 'close', noteId: 7, destination: DESTINATION,
    withdrawalNullifier: nullifierFor(GENESIS_ANCHOR), clearanceReserved: true, createdAt: 1, clearanceOutcome: 'granted',
    clearance: { withdrawal_nullifier: nullifierFor(GENESIS_ANCHOR), signature: { r: '0x1', s: '0x2' } } });

async function legacyWallet(runtimeValue = {}) {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime);
    await store.writeBrowserWallet({ deploymentId: LEGACY, billingAsset: 'native_eth', state: noteState(), ...runtimeValue });
    await h.runtime.reload();
    return h;
}

function hardenedRuntime() {
    const h = createHarness(BrowserWalletRuntime, { vaultRevision: 2 });
    h.runtime.manifest = { deployment_id: HARDENED };
    return h.runtime;
}

test('a set-aside legacy mutual close stays visible to a host and to a runtime pinned elsewhere', async () => {
    const h = await legacyWallet({ preparedWithdrawal: reserving() });
    await h.runtime.parkPreparedWithdrawal();
    const parked = await store.readBrowserWallet();
    assert.equal(parked.state, null, 'the runtime slot holds no note any more');
    assert.equal(store.browserRuntimeHoldsState(parked), false);

    assert.deepEqual(await store.readBrowserWalletHoldings(), [{
        deploymentId: LEGACY,
        runtime: false,
        withdrawals: [{ recordId: `${LEGACY}:11155111:${VAULT}:7`, noteId: 7, mode: 'mutual', phase: 'parked' }]
    }]);

    // A runtime pinned to the newer deployment loads, and says what it cannot reach.
    const runtime = hardenedRuntime();
    await runtime.reload();
    assert.deepEqual(runtime.withdrawals, []);
    const summary = runtime.snapshot();
    assert.deepEqual(summary.withdrawals, []);
    assert.deepEqual(summary.config.other_deployment_withdrawals, [{
        deployment_id: LEGACY, record_id: `${LEGACY}:11155111:${VAULT}:7`, note_id: 7, mode: 'mutual', phase: 'parked'
    }]);
    // The legacy runtime still owns it.
    await h.runtime.reload();
    assert.equal(h.runtime.snapshot().config.other_deployment_withdrawals.length, 0);
    assert.equal(h.runtime.snapshot().withdrawals.length, 1);
});

test('pending, challenged and closing legacy escapes count until a close is final and nothing is finalizing', async () => {
    const h = await legacyWallet();
    const escape = await h.runtime.detachEscapeWithdrawal({ noteId: 7, destination: DESTINATION, finalBalance: 5_000_000,
        challengeDeadline: 2_000_000_000, transactionHash: `0x${'aa'.repeat(32)}`, startBlockNumber: 10 });
    const listed = async () => (await store.readBrowserWalletHoldings())
        .flatMap(entry => entry.withdrawals.map(record => `${entry.deploymentId}:${record.phase}`));
    assert.deepEqual(await listed(), [`${LEGACY}:pending`]);
    for (const [changes, expected] of [
        [{ phase: 'challenged_unconfirmed' }, [`${LEGACY}:challenged_unconfirmed`]],
        [{ phase: 'restored' }, [`${LEGACY}:restored`]],
        [{ phase: 'finalizing' }, [`${LEGACY}:finalizing`]],
        [{ phase: 'closed_unconfirmed' }, [`${LEGACY}:closed_unconfirmed`]],
        [{ phase: 'closed', finalizeTransactionHash: `0x${'bb'.repeat(32)}` }, [`${LEGACY}:closed`]],
        [{ phase: 'closed', finalizeTransactionHash: null, finalizeSubmissionId: 'claim' }, [`${LEGACY}:closed`]],
        [{ phase: 'closed', finalizeTransactionHash: null, finalizeSubmissionId: null }, []]
    ]) {
        await store.putBrowserWithdrawal({ ...(await store.listBrowserWithdrawals())[0], ...changes });
        assert.deepEqual(await listed(), expected, JSON.stringify(changes));
    }
    assert.equal(escape.deploymentId, LEGACY);
});

test('when both deployments hold state the one in the runtime slot is the one that can load first', async () => {
    const h = await legacyWallet({ preparedWithdrawal: reserving() });
    await h.runtime.parkPreparedWithdrawal();
    // The user then funded a note on the newer deployment.
    await store.writeBrowserWallet({ ...(await store.readBrowserWallet()), deploymentId: HARDENED,
        state: noteState({ note_id: 1, current_anchor: '0x4444' }) });
    const holdings = await store.readBrowserWalletHoldings();
    assert.deepEqual(holdings.map(entry => [entry.deploymentId, entry.runtime, entry.withdrawals.length]),
        [[HARDENED, true, 0], [LEGACY, false, 1]]);
    // The legacy profile cannot load until the newer note is withdrawn.
    await assert.rejects(h.runtime.reload(), /contains a wallet for hardened-deployment/);
    await hardenedRuntime().reload();
});

test('the runtime-state rule is the one the deployment guard applies', async () => {
    const quote = { operationId: 'draft', amount: 1 };
    for (const [value, holds] of [
        [{}, false],
        [{ lateWithdrawalAttempts: [{ status: 'closed' }], lateDepositAttempts: [{ status: 'confirmed' }] }, false],
        [{ state: noteState() }, true],
        [{ journal: { exists: true } }, true],
        [{ pendingDeposit: { operationId: 'p' } }, true],
        [{ depositQuote: quote }, true],
        [{ preparedWithdrawal: reserving() }, true],
        [{ lease: { sessionId: 's' } }, true],
        [{ lateWithdrawalAttempts: [{ status: 'submitted' }] }, true],
        [{ lateDepositAttempts: [{ status: 'submitted' }] }, true]
    ]) {
        indexedDB.clear();
        await store.writeBrowserWallet({ deploymentId: LEGACY, billingAsset: 'native_eth', ...value });
        assert.equal(store.browserRuntimeHoldsState(await store.readBrowserWallet()), holds, JSON.stringify(value));
        const holdings = await store.readBrowserWalletHoldings();
        assert.deepEqual(holdings, holds ? [{ deploymentId: LEGACY, runtime: true, withdrawals: [] }] : [],
            JSON.stringify(value));
        const other = hardenedRuntime();
        if (holds) await assert.rejects(other.reload(), /contains a wallet for/);
        else await other.reload();
    }
});

test('an unclaimed escape payout credit is reported without keeping its deployment listed', async () => {
    indexedDB.clear();
    const recordId = `${LEGACY}:11155111:${VAULT}:7`;
    const credited = { recordId, deploymentId: LEGACY, chainId: 11155111, contractAddress: VAULT, mode: 'escape',
        phase: 'closed', chainStatus: 'closed', noteId: 7, destination: DESTINATION, finalBalance: 5_000_000,
        payoutCredited: true, payoutVerified: false, creditedAmount: 5_000_000, payoutCreditEvidence: 'receipt',
        closeBlockNumber: 100 };
    await store.putBrowserWithdrawal(credited);
    const credit = { deploymentId: LEGACY, recordId, noteId: 7, chainId: 11155111, contractAddress: VAULT,
        destination: DESTINATION, creditedAmount: 5_000_000 };
    assert.deepEqual(await store.readBrowserWalletHoldings(), [], 'a final credited escape holds no note');
    assert.deepEqual(await store.readBrowserWalletPayoutCredits(), [credit]);
    assert.deepEqual(store.browserWalletPayoutCredits(await store.readBrowserWalletSnapshot()), [credit]);

    // A runtime pinned to the newer deployment reports it, and deposits stay open there.
    const runtime = hardenedRuntime();
    await runtime.reload();
    const { config } = runtime.snapshot();
    assert.deepEqual(config.other_deployment_withdrawals, []);
    assert.deepEqual(config.other_deployment_credits, [{
        deployment_id: LEGACY, record_id: recordId, note_id: 7, chain_id: 11155111, contract_address: VAULT,
        destination: DESTINATION, credited_amount: 5_000_000
    }]);
    // Its own deployment lists it with its withdrawals, not as another's.
    const legacy = createHarness(BrowserWalletRuntime);
    await legacy.runtime.reload();
    assert.deepEqual(legacy.runtime.snapshot().config.other_deployment_credits, []);
    assert.equal(legacy.runtime.snapshot().withdrawals[0].payoutCredited, true);

    // A delivered, verified or never-credited close is not a credit.
    for (const changes of [{ payoutClaimed: true, payoutVerified: true }, { payoutCredited: false },
        { payoutCredited: undefined, payoutVerified: true }]) {
        await store.putBrowserWithdrawal({ ...credited, ...changes });
        assert.deepEqual(await store.readBrowserWalletPayoutCredits(), [], JSON.stringify(changes));
        await runtime.reload();
        assert.deepEqual(runtime.snapshot().config.other_deployment_credits, [], JSON.stringify(changes));
    }
    // A close still awaiting finality is both an open record and a credit.
    await store.putBrowserWithdrawal({ ...credited, phase: 'closed_unconfirmed' });
    assert.equal((await store.readBrowserWalletHoldings())[0].withdrawals[0].phase, 'closed_unconfirmed');
    assert.equal((await store.readBrowserWalletPayoutCredits()).length, 1);
    assert.equal(store.isUnclaimedPayoutCredit({ ...credited, phase: 'pending' }), false);
});
