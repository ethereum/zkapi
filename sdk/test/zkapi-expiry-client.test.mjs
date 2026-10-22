import assert from 'node:assert/strict';
import test from 'node:test';

const values = new Map();
globalThis.localStorage = {
    getItem: key => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, String(value)),
    removeItem: key => values.delete(key)
};
globalThis.sessionStorage = globalThis.localStorage;
globalThis.window = new EventTarget();
globalThis.window.location = { search: '', hostname: 'localhost', origin: 'http://localhost' };
globalThis.zkapiWallet = (await import('../wallet.js')).default;
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { default: wallet } = await import('../services/browserWalletRuntime.js');
const { EXPIRED_CLAIMED_TOPIC } = await import('../services/zkapiExpiryHistory.mjs');

const DEPLOYMENT = 'expiry-client-test';
const VAULT = `0x${'12'.repeat(20)}`;
const hash = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
const hex = value => `0x${value.toString(16)}`;
const deposit = (noteId = 7, extra = {}) => ({
    recordId: `${DEPLOYMENT}:deposit:${noteId}`, deploymentId: DEPLOYMENT,
    status: 'confirmed', noteId, amount: 2_000_000, expiryTs: 1000, ...extra
});
const claim = (noteId = 7, blockNumber = 12) => ({
    noteId, amount: 2_000_000, transactionHash: hash(100 + noteId),
    blockNumber, blockHash: hash(blockNumber), claimedAt: (1000 + blockNumber) * 1000
});
const log = (noteId = 7, blockNumber = 12) => ({
    address: VAULT, topics: [EXPIRED_CLAIMED_TOPIC, hash(noteId)],
    data: `0x${hash(2_000_000).slice(2)}`,
    removed: false, blockNumber: hex(blockNumber), blockHash: hash(blockNumber),
    transactionHash: hash(100 + noteId)
});
const deferred = () => {
    let resolve;
    const promise = new Promise(yes => { resolve = yes; });
    return { promise, resolve };
};

function harness(t, overrides = {}) {
    const h = { deposits: [deposit()], logs: [log()], head: 20, chainId: 1,
        calls: [], refreshes: 0, currentWallet: { note: { note_id: 7 } }, ...overrides };
    const originalManifest = wallet.manifest;
    const originalEthereum = globalThis.ethereum;
    t.after(() => { wallet.manifest = originalManifest; globalThis.ethereum = originalEthereum; });
    wallet.manifest = { deployment_id: DEPLOYMENT };
    h.client = new ZkapiClient();
    h.client.browserMode = true;
    h.client.config = { funding: { contract_address: VAULT, chain_id: 1 } };
    h.client.wallet = structuredClone(h.currentWallet);
    h.client.deposits = structuredClone(h.deposits);
    h.history = t.mock.method(wallet, 'getDepositHistory', async () => {
        if (h.historyGate) await h.historyGate;
        return structuredClone(h.deposits);
    });
    h.remember = t.mock.method(wallet, 'rememberExpiryClaims', async claims => {
        if (h.saveError) throw h.saveError;
        if (h.saveGate) await h.saveGate;
        for (const record of h.deposits) {
            const found = claims.find(value => value.noteId === record.noteId);
            if (found) {
                const { noteId: _noteId, ...evidence } = found;
                record.expiryClaim = structuredClone(evidence);
            }
        }
        return h.deposits.filter(record => record.expiryClaim);
    });
    h.archive = t.mock.method(wallet, 'archiveNote', async () => {
        if (h.archiveError) throw h.archiveError;
        if (h.archiveGate) await h.archiveGate;
        h.currentWallet = { note: null };
    });
    h.refresh = t.mock.method(h.client, 'refresh', async () => {
        h.refreshes += 1;
        h.client.deposits = structuredClone(h.deposits);
        h.client.wallet = structuredClone(h.currentWallet);
        return h.client.snapshot();
    });
    globalThis.ethereum = { request: async ({ method, params }) => {
        h.calls.push({ method, params: structuredClone(params) });
        if (method === 'eth_chainId') return hex(h.chainId);
        if (method === 'eth_getBlockByNumber') {
            const number = params[0] === 'finalized' ? h.head : Number(BigInt(params[0]));
            return { number: hex(number), hash: hash(number), timestamp: hex(1000 + number) };
        }
        if (method === 'eth_getCode') return Number(BigInt(params[1])) >= 8 ? '0x1234' : '0x';
        if (method === 'eth_getLogs') {
            assert.deepEqual(Object.keys(params[0]).sort(), ['address', 'fromBlock', 'toBlock', 'topics']);
            assert.equal(params[0].address, VAULT);
            assert.deepEqual(params[0].topics, [EXPIRED_CLAIMED_TOPIC]);
            const from = Number(BigInt(params[0].fromBlock));
            const to = Number(BigInt(params[0].toBlock));
            return h.logs.filter(value => Number(BigInt(value.blockNumber)) >= from
                && Number(BigInt(value.blockNumber)) <= to);
        }
        assert.fail(`Unexpected or mutating wallet RPC: ${method}`);
    } };
    return h;
}

const scannedRanges = h => h.calls.filter(call => call.method === 'eth_getLogs')
    .map(call => [Number(BigInt(call.params[0].fromBlock)), Number(BigInt(call.params[0].toBlock))]);

test('concurrent client expiry scans share one metadata read, public scan and durable save', async t => {
    const gate = deferred();
    const h = harness(t, { historyGate: gate.promise });
    const first = h.client.syncExpiryHistory();
    const second = h.client.syncExpiryHistory();
    const third = h.client.syncExpiryHistory();
    assert.equal(h.history.mock.calls.length, 1);
    assert.equal(h.calls.length, 0);
    gate.resolve();
    const results = await Promise.all([first, second, third]);
    assert.deepEqual(results[0].claims, [claim()]);
    assert.equal(results[0], results[1]);
    assert.equal(results[0], results[2]);
    assert.equal(h.remember.mock.calls.length, 1);
    assert.equal(h.refreshes, 1);
    assert.deepEqual(scannedRanges(h), [[0, 20]]);
    assert.equal(h.client.expiryScan.scannedTo, 20);
    assert.equal(h.client.expiryHistory[0].status, 'claimed');
    assert.equal(h.client.expiryHistoryPromise, null);
});

test('no overdue unclaimed deposits means no RPC, wallet prompt or claim save', async t => {
    const h = harness(t);
    for (const deposits of [[], [deposit(7, { expiryTs: Math.floor(Date.now() / 1000) + 86400 })],
        [deposit(7, { expiryTs: null })], [deposit(7, { status: 'pending' })],
        [deposit(7, { expiryClaim: claim() })]]) {
        h.deposits = deposits;
        assert.deepEqual(await h.client.syncExpiryHistory(), { complete: true, claims: [] });
    }
    assert.equal(h.calls.length, 0);
    assert.equal(h.remember.mock.calls.length, 0);
    assert.equal(h.archive.mock.calls.length, 0);

});

test('missing wallet and wrong-chain failures preserve history/cursor and can be retried', async t => {
    const h = harness(t);
    const provider = globalThis.ethereum;
    globalThis.ethereum = undefined;
    await assert.rejects(h.client.syncExpiryHistory(), /Open MetaMask.*No transaction is needed/);
    assert.equal(h.client.expiryScan, undefined);
    assert.equal(h.client.expiryHistoryPromise, null);
    globalThis.ethereum = provider;
    h.chainId = 11155111;
    await assert.rejects(h.client.syncExpiryHistory(), /Switch to the configured network/);
    assert.deepEqual(h.calls.map(call => call.method), ['eth_chainId']);
    assert.equal(h.remember.mock.calls.length, 0);
    assert.equal(h.client.expiryScan, undefined);
    assert.equal(h.client.expiryHistoryPromise, null);
    h.chainId = 1;
    assert.deepEqual((await h.client.syncExpiryHistory()).claims, [claim()]);
});

test('scan cursor advances only after claims are saved and failed saves rescan the same public range', async t => {
    const h = harness(t, { deposits: [deposit(), deposit(8)], logs: [] });
    await h.client.syncExpiryHistory();
    assert.equal(h.client.expiryScan.scannedTo, 20);
    h.head = 30;
    h.logs = [log(7, 25)];
    h.saveError = new Error('Simulated durable metadata failure');
    await assert.rejects(h.client.syncExpiryHistory(), /durable metadata failure/);
    assert.equal(h.client.expiryScan.scannedTo, 20);
    assert.equal(h.deposits[0].expiryClaim, undefined);
    assert.equal(h.client.expiryHistoryPromise, null);
    h.saveError = null;
    assert.deepEqual((await h.client.syncExpiryHistory()).claims, [claim(7, 25)]);
    assert.equal(h.client.expiryScan.scannedTo, 30);
    assert.deepEqual(scannedRanges(h), [[0, 20], [21, 30], [21, 30]]);
    assert.equal(h.remember.mock.calls.length, 2);
    assert.equal(h.deposits[0].expiryClaim.blockNumber, 25);
});

test('confirmed record, amount, expiry and deployment changes invalidate the old scan cursor', async t => {
    const h = harness(t, { logs: [] });
    await h.client.syncExpiryHistory();
    h.head += 1;
    await h.client.syncExpiryHistory();
    assert.deepEqual(scannedRanges(h), [[0, 20], [21, 21]]);
    const changes = [
        () => h.deposits.push(deposit(8)),
        () => { h.deposits[0].expiryTs += 1; },
        () => { h.deposits[0].amount += 1; },
        () => { h.deposits[0].recordId = `${DEPLOYMENT}:imported:7`; },
        () => { h.deposits[1].status = 'pending'; },
        () => { wallet.manifest = { deployment_id: 'replacement-deployment' }; }
    ];
    for (const change of changes) {
        change();
        h.head += 1;
        await h.client.syncExpiryHistory();
        assert.deepEqual(scannedRanges(h).at(-1), [0, h.head]);
    }
    assert.equal(h.client.expiryScan.deploymentId, 'replacement-deployment');
});

test('client scans issue the same public RPC queries for different owned notes and never submit transactions', async t => {
    const h = harness(t, { logs: [log(7, 12), log(8, 13)] });
    await h.client.syncExpiryHistory();
    const firstCalls = structuredClone(h.calls);
    h.calls = [];
    h.deposits = [deposit(8)];
    h.client.expiryScan = null;
    await h.client.syncExpiryHistory();
    assert.deepEqual(h.calls, firstCalls);
    assert.ok(h.calls.every(call => ['eth_chainId', 'eth_getBlockByNumber', 'eth_getLogs', 'eth_getCode'].includes(call.method)));
    assert.doesNotMatch(JSON.stringify(h.calls), new RegExp(`${hash(7)}|${hash(8)}`));
    assert.deepEqual(h.calls.filter(call => call.method === 'eth_getBlockByNumber').map(call => call.params[0]),
        ['finalized', '0xc', '0xd', '0x14']);
    assert.equal(h.archive.mock.calls.length, 0, 'observing a claim must not automatically archive a wallet');
});

test('claimed-balance action requires evidence and delegates exact-note archival without a wallet transaction', async t => {
    const h = harness(t);
    await assert.rejects(h.client.archiveClaimedBalance(), /no verified expiry payment/);
    assert.equal(h.archive.mock.calls.length, 0);
    h.deposits[0].expiryClaim = claim();
    h.client.deposits = structuredClone(h.deposits);
    h.archiveError = new Error('The selected private note changed');
    await assert.rejects(h.client.archiveClaimedBalance(), /selected private note changed/);
    assert.equal(h.refreshes, 0, 'a rejected archive must preserve the current view');
    assert.equal(h.client.note.note_id, 7);
    h.archiveError = null;
    await h.client.archiveClaimedBalance();
    assert.deepEqual(h.archive.mock.calls.map(call => call.arguments), [
        ['expiry-claimed', 7], ['expiry-claimed', 7]
    ]);
    assert.equal(h.refreshes, 1);
    assert.equal(h.client.note, null);
    assert.equal(h.client.expiryHistory[0].status, 'claimed', 'archival retains the payment entry');
    assert.equal(h.calls.length, 0);
});

test('withdrawal reloads persisted expiry evidence before attempting settlement or connecting a wallet', async t => {
    const h = harness(t);
    // The UI still has an unclaimed snapshot; another scan/tab saved the claim.
    h.deposits[0].expiryClaim = claim();
    assert.equal(h.client.noteExpiryClaim, null);
    const beforeWallet = structuredClone(h.client.wallet);
    const settle = t.mock.method(h.client, 'settleActiveLease', async () => {
        assert.fail('A claimed note must not begin private-key settlement');
    });
    const connect = t.mock.method(h.client, 'connectWallet', async () => {
        assert.fail('A claimed note must not open a withdrawal wallet prompt');
    });
    for (const mode of ['mutual', 'escape']) {
        await assert.rejects(h.client.performWithdrawal(mode), /claimed after expiry.*start a new balance/);
    }
    assert.equal(h.history.mock.calls.length, 2);
    assert.equal(settle.mock.calls.length, 0);
    assert.equal(connect.mock.calls.length, 0);
    assert.equal(h.archive.mock.calls.length, 0);
    assert.equal(h.calls.length, 0);
    assert.deepEqual(h.client.wallet, beforeWallet);
});

test('withdrawal replacement checks the prepared note claim before connecting or changing its retry plan', async t => {
    const h = harness(t);
    h.deposits[0].expiryClaim = claim();
    let prepared;
    t.mock.method(wallet, 'currentPreparedWithdrawal', async () => prepared);
    const connect = t.mock.method(h.client, 'connectWallet', async () => {
        assert.fail('A claimed withdrawal must not open a wallet prompt');
    });
    const replacement = t.mock.method(wallet, 'claimPreparedWithdrawalReplacement', async () => {
        assert.fail('A claimed withdrawal must not mutate its replacement plan');
    });
    const send = t.mock.method(h.client, 'sendContractTransaction', async () => {
        assert.fail('A claimed withdrawal must not submit a replacement transaction');
    });
    for (const identity of [{ noteId: 7 }, { public_inputs: { note_id: 7 } }, {}]) {
        prepared = { phase: 'dropped_or_pending', mode: 'mutual', ...identity };
        // A historical plan must guard its own note even after another balance is selected.
        h.client.wallet = { note: { note_id: Object.keys(identity).length ? 8 : 7 } };
        h.client.deposits = [deposit()];
        const beforePlan = structuredClone(prepared);
        const beforeWallet = structuredClone(h.client.wallet);
        await assert.rejects(h.client.retryDroppedWithdrawal(), /claimed after expiry.*start a new balance/);
        assert.deepEqual(prepared, beforePlan);
        assert.deepEqual(h.client.wallet, beforeWallet);
    }
    assert.equal(h.history.mock.calls.length, 3);
    assert.equal(connect.mock.calls.length, 0);
    assert.equal(replacement.mock.calls.length, 0);
    assert.equal(send.mock.calls.length, 0);
    assert.equal(h.calls.length, 0);
});

test('generic closed withdrawal records do not hide actual expiry payments from discovery', async t => {
    const h = harness(t);
    h.client.withdrawals = [{ deploymentId: DEPLOYMENT, noteId: 7,
        phase: 'closed', chainStatus: 'closed', payoutVerified: false }];
    assert.deepEqual((await h.client.syncExpiryHistory()).claims, [claim()]);
    assert.deepEqual(scannedRanges(h), [[0, 20]]);
    assert.equal(h.remember.mock.calls.length, 1);
    assert.equal(h.client.expiryHistory[0].status, 'claimed');
});
