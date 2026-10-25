// The client's exit submission (zkapiClient.performWithdrawal) over the real
// runtime and store: the E4.6 recovery pass right before broadcast, the
// advisory wallet simulation of E4.5 (a refusal warns; the exit is still
// submitted, through the exit RPC's estimate or a fixed gas limit), and exits
// bound to the note's leaf: no path, no root, no indexer and no log scan, so
// only an expired proof is ever proved again. The wallet provider, the
// protocol server, the pinned RPC and the proof worker are observed fakes.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, VAULT, createHarness, derivedAnchor, legacyDepositPath, memoryIndexedDb, noteState, nullifierFor,
    selectorOf, stateNoteLeaf, within
} from './helpers/request-archive-harness.mjs';

const storage = new Map();
globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};
globalThis.zkapiWallet = (await import('../wallet.js')).default;

const store = await import('../services/browserWalletStore.js');
const { default: runtime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');
const { bufferedGasLimit } = await import('../services/zkapiGas.mjs');

const FROM = `0x${'77'.repeat(20)}`;
// The user closes MetaMask: the flow ends right after the send was offered.
const SEND_REFUSED = Object.freeze({ code: 4001, message: 'User rejected the request.' });
const FIXED_EXIT_GAS = '0xf4240';
const revert = selector => ({ code: -32603, message: 'Internal JSON-RPC error.',
    data: { code: 3, message: 'execution reverted', data: selector } });
const NOTE_LEAF_MISMATCH = selectorOf('NoteLeafMismatch()');
const PROOF_EXPIRED = selectorOf('ProofExpired()');
const CHALLENGED = selectorOf('ChallengedNullifier()');
/** A pinned RPC that is gone: an exit never needs it for a path. */
const goneRpc = async ({ method }) => { throw new Error(`the pinned RPC is gone (${method})`); };

/** The shared runtime the client uses, under the harness, and a client over a scripted wallet. */
async function scenario({ state = noteState(), liveRequest = false } = {}) {
    indexedDB.clear();
    storage.clear();
    for (const name of ['exitRpc', 'pinnedRpc']) delete runtime[name];
    runtime.activeLease = null;
    runtime.exitGasPrice = null;
    const h = createHarness(function SharedRuntime() { return runtime; });
    // The encoder takes 256-byte Groth16 proofs.
    h.worker.mutate = plan => { plan.proof.proof = Buffer.alloc(256, h.worker.proofs).toString('base64'); };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state });
    await runtime.reload();
    if (liveRequest) {
        h.server.leasePost = body => h.activeLease(body);
        await runtime.issueLease('chat');
        await runtime.reload();
    }
    const wallet = { estimates: [], sent: [], estimate: () => '0x9c40', atSend: null };
    globalThis.ethereum = {
        async request({ method, params = [] }) {
            if (method === 'eth_chainId') return `0x${Number(h.funding.chain_id).toString(16)}`;
            if (method === 'eth_estimateGas') {
                wallet.estimates.push(params[0]);
                return wallet.estimate(params[0], wallet.estimates.length);
            }
            if (method === 'eth_getTransactionCount') return '0x5';
            if (method === 'eth_gasPrice' && wallet.gasPrice != null) return `0x${BigInt(wallet.gasPrice).toString(16)}`;
            if (method === 'eth_sendTransaction') {
                wallet.sent.push({ ...params[0], atSend: await wallet.atSend?.() });
                throw SEND_REFUSED;
            }
            throw new Error(`unexpected wallet RPC ${method}`);
        }
    };
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    client.wallet = { has_note: true, note: { note_id: state.note_id, current_balance: state.current_balance } };
    for (const name of ['assertBalanceNotClaimed', 'refresh', 'settleActiveLease']) client[name] = async () => {};
    client.connectWallet = async () => FROM;
    client.checkEscapeDestination = async () => ({ destination: DESTINATION, accepts: true, warning: null });
    client.recoverFailedWithdrawalSubmission = async () => null;
    client.submittedTransactionMetadata = async () => null;
    const statuses = [];
    const withdraw = mode => client.performWithdrawal(mode, message => statuses.push(message), { destination: DESTINATION });
    return { h, client, wallet, statuses, withdraw };
}

const escapeProofs = h => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'escape');
const refusedInWallet = error => error.code === 4001;

test('E4.6: a successor that arrives between proving and sending is archived late_successor before the wallet sees the escape', async () => {
    const { h, wallet, statuses, withdraw } = await scenario({ liveRequest: true });
    const saved = await store.readBrowserWallet();
    const { journal, state } = saved;
    // The server settles the request only once the escape proof exists.
    let proved = false;
    const mutate = h.worker.mutate;
    h.worker.mutate = (plan, payload) => {
        mutate(plan, payload);
        if (plan.mode === 'escape') proved = true;
    };
    h.server.nullifier = () => (proved
        ? { status: 'ok', nullifier_status: 'finalized', request_response: h.receiptFor(journal,
            { charge: 25_000, nextAnchor: derivedAnchor(nullifierFor(state.current_anchor)) }) }
        : { status: 'not_found', nullifier_status: 'unknown' });
    wallet.atSend = async () => (await store.listBrowserRequestArchive(DEPLOYMENT)).map(record => record.disposition);
    await assert.rejects(withdraw('escape'), refusedInWallet);
    assert.equal(wallet.sent.length, 1);
    assert.deepEqual(wallet.sent[0].atSend, ['late_successor'], 'the pre-broadcast pass ran before eth_sendTransaction');
    assert.ok(statuses.some(message => /settled private request arrived after the exit proof was made/.test(message)));
    const after = await store.readBrowserWallet();
    assert.equal(after.state.current_anchor, state.current_anchor, 'a live exit proof keeps the successor archived (E6)');
    assert.deepEqual(after.exitLock.released.map(entry => entry.kind), [0]);
});

test('E4.5: a wallet simulation that refuses an escape only warns; the escape is still offered with a fixed gas limit', async () => {
    for (const refusal of [revert(CHALLENGED), { code: -32603, message: 'Internal JSON-RPC error.' },
        { code: -32000, message: 'header not found' }]) {
        const { h, wallet, statuses, withdraw } = await scenario();
        wallet.estimate = () => { throw refusal; };
        await assert.rejects(withdraw('escape'), refusedInWallet, JSON.stringify(refusal));
        assert.equal(wallet.sent.length, 1, 'the escape reached the wallet');
        assert.equal(wallet.sent[0].gas, FIXED_EXIT_GAS);
        assert.equal(wallet.sent[0].to, VAULT);
        assert.ok(statuses.some(message => /simulation refused this escape/.test(message)));
        assert.equal(escapeProofs(h).length, 1, 'a refusal no new proof can cure is not re-proved');
    }
    // A mutual close too: its simulation is advisory as well.
    const close = await scenario();
    close.h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
    close.client.readContractUint = async () => 0x77n;
    close.wallet.estimate = () => { throw revert(CHALLENGED); };
    await assert.rejects(close.withdraw('mutual'), refusedInWallet);
    assert.equal(close.wallet.sent.length, 1);
    assert.equal(close.wallet.sent[0].gas, FIXED_EXIT_GAS);
    assert.ok(close.statuses.some(message => /simulation refused this close/.test(message)));
});

test('E4.5: with an exit RPC set, its estimate replaces a refused wallet simulation', async () => {
    const { wallet, statuses, withdraw } = await scenario({ state: noteState() });
    wallet.estimate = () => { throw { code: -32000, message: 'header not found' }; };
    const estimates = [];
    const exitRpc = chainId => async ({ method, params }) => {
        if (method === 'eth_chainId') return chainId;
        // E0 also reads effectiveExpiry through it.
        if (method === 'eth_call') return `0x${(2_000_000_000).toString(16).padStart(64, '0')}`;
        assert.equal(method, 'eth_estimateGas');
        estimates.push(params[0]);
        return '0x927c0';
    };
    runtime.exitRpc = () => exitRpc('0xaa36a7');
    await assert.rejects(withdraw('escape'), refusedInWallet);
    assert.equal(estimates.length, 1);
    assert.deepEqual(estimates[0], { from: FROM, to: VAULT, data: wallet.estimates[0].data });
    assert.equal(wallet.sent[0].gas, bufferedGasLimit(0x927c0n));
    assert.ok(statuses.some(message => /your exit RPC accepts it/.test(message)));

    // An exit RPC on another chain is never asked for the estimate: the
    // exit goes out with the fixed gas limit instead.
    const other = await scenario({ state: noteState() });
    other.wallet.estimate = () => { throw { code: -32000, message: 'header not found' }; };
    estimates.length = 0;
    runtime.exitRpc = () => exitRpc('0x1');
    await assert.rejects(other.withdraw('escape'), refusedInWallet);
    assert.equal(estimates.length, 0, 'no estimate from another chain');
    assert.equal(other.wallet.sent[0].gas, FIXED_EXIT_GAS);
    assert.ok(!other.statuses.some(message => /your exit RPC accepts it/.test(message)));
});

test('E4.7: an expired-proof simulation re-proves once; a note-leaf refusal is never re-proved and only warns', async () => {
    for (const secondAnswer of ['accepts', 'refuses']) {
        const { h, wallet, withdraw } = await scenario({ state: noteState({ deposit_path: legacyDepositPath('0x51') }) });
        wallet.estimate = (_transaction, count) => {
            if (count === 1 || secondAnswer === 'refuses') throw revert(PROOF_EXPIRED);
            return '0x9c40';
        };
        await assert.rejects(withdraw('escape'), refusedInWallet, secondAnswer);
        const [first, second, third] = escapeProofs(h);
        assert.ok(first && second, 'the expired proof was proved again');
        assert.equal(third, undefined, 'one re-proof per refusal');
        for (const proof of [first, second]) {
            assert.deepEqual(Object.keys(proof.payload.args).sort(), ['conceded', 'destination', 'mode', 'valid_until']);
        }
        assert.equal(wallet.estimates.length, 2);
        assert.equal(wallet.sent.length, 1);
        assert.equal(wallet.sent[0].gas, secondAnswer === 'accepts' ? bufferedGasLimit(0x9c40n) : FIXED_EXIT_GAS);
    }
    // NoteLeafMismatch names no root to refresh: the same proof is offered
    // with a fixed gas limit and a warning (E4.5), never proved again.
    const { h, wallet, statuses, withdraw } = await scenario();
    runtime.pinnedRpc = () => goneRpc;
    wallet.estimate = () => { throw revert(NOTE_LEAF_MISMATCH); };
    await assert.rejects(within(5_000, withdraw('escape'), 'a leaf refusal'), refusedInWallet);
    assert.equal(escapeProofs(h).length, 1);
    assert.equal(wallet.sent.length, 1);
    assert.equal(wallet.sent[0].gas, FIXED_EXIT_GAS);
    assert.ok(statuses.some(message => /another leaf for this private note/.test(message)), 'the refusal is shown');
});

test('an escape reaches the wallet with the indexer and the pinned RPC gone, bound to the note leaf', async () => {
    const state = noteState({ secret_s: '0x5ec' });
    const { h, wallet, withdraw } = await scenario({ state });
    runtime.indexerPath = () => assert.fail('no indexer');
    runtime.rebuildRequestPath = () => assert.fail('no tree rebuild');
    runtime.pinnedRpc = () => goneRpc;
    await assert.rejects(within(5_000, withdraw('escape'), 'an escape without the operator'), refusedInWallet);
    assert.equal(wallet.sent.length, 1);
    const calldata = wallet.sent[0].data;
    assert.equal(calldata.slice(0, 10), '0x8cd67c60');
    assert.equal(BigInt(`0x${calldata.slice(10 + 3 * 64, 10 + 4 * 64)}`), BigInt(stateNoteLeaf(state)), 'word 3 is the leaf');
    assert.equal(BigInt(`0x${calldata.slice(10 + 8 * 64, 10 + 9 * 64)}`), (7n << 192n) | (5_000_000n << 64n) | 2_000_000_000n,
        'word 8 the note fields');
    assert.equal(escapeProofs(h).length, 1);
});

test('G1: a withdrawal warns first when the balance returns less than three escape fees', async () => {
    for (const [gasPrice, warned] of [[10_000_000_000n, true], [1_000_000_000n, false], [null, false]]) {
        const { wallet, statuses, withdraw } = await scenario({ state: noteState() });
        wallet.gasPrice = gasPrice;
        await assert.rejects(withdraw('escape'), refusedInWallet);
        const index = statuses.findIndex(message => /less than three times the estimated network fee of an escape/.test(message));
        assert.equal(index >= 0, warned, `gas price ${gasPrice}`);
        if (warned) {
            assert.match(statuses[index], /as little as 0\.005 ETH.*\(0\.0062 ETH/);
            assert.ok(index < statuses.findIndex(message => /Confirm the escape-hatch start/.test(message)), 'before the wallet prompt');
        }
        assert.equal(wallet.sent.length, 1, 'the warning never blocks the exit');
    }
});

test('G1: a wallet whose gas price read never answers neither delays nor blocks the exit', async () => {
    const { wallet, statuses, withdraw } = await scenario({ state: noteState() });
    const answer = globalThis.ethereum.request;
    let asked = 0;
    globalThis.ethereum.request = async call => {
        if (call.method !== 'eth_gasPrice') return answer(call);
        asked += 1;
        return new Promise(() => {});
    };
    await within(4_000, assert.rejects(withdraw('escape'), refusedInWallet), 'an escape behind a silent gas price read');
    assert.equal(asked, 1, 'the gas price was asked for');
    assert.equal(wallet.sent.length, 1, 'the escape reached the wallet');
    assert.ok(!statuses.some(message => /less than three times the estimated network fee/.test(message)));
});

test('E6 through the client: a cancel after a dead escape reads the note through the wallet provider when the pinned RPC fails', async () => {
    const { client } = await scenario({ state: noteState() });
    await runtime.prepareWithdrawal('escape', DESTINATION);
    const lock = (await store.readBrowserWallet()).exitLock;
    assert.deepEqual(lock.released.map(entry => entry.kind), [0], 'the escape proof was released');
    const later = lock.released[0].valid_until + 901;
    // The real E6 read: the pinned RPC refuses, the wallet reports Active
    // at a finalized block past valid_until + 900.
    delete runtime.exitChainStatus;
    runtime.pinnedRpc = () => async () => { throw new Error('pinned RPC refuses'); };
    const answer = globalThis.ethereum.request;
    const statusReads = [];
    globalThis.ethereum.request = async call => {
        if (call.method === 'eth_getBlockByNumber') {
            statusReads.push('finalized');
            return { number: '0x64', timestamp: `0x${later.toString(16)}` };
        }
        if (call.method === 'eth_call' && call.params[0].data.startsWith('0xd154f5bf')) {
            statusReads.push('note');
            return `0x${[0x1eaf, 1].map(value => value.toString(16).padStart(64, '0')).join('')}`;
        }
        return answer(call);
    };
    client.config = runtime.snapshot().config;
    const statuses = [];
    const restore = Date.now;
    Date.now = () => later * 1_000;
    try {
        assert.equal(await client.cancelPreparedWithdrawal(message => statuses.push(message)), true);
    } finally {
        Date.now = restore;
    }
    assert.deepEqual(statusReads, ['finalized', 'note']);
    assert.equal((await store.readBrowserWallet()).exitLock, null, 'the lock is released');
    assert.match(statuses.at(-1), /ready to use/);
});

test('a set-aside close leaves without the operator, its indexer or the vault logs, reusing its kept clearance', async () => {
    for (const [label, refusal, closesExpected, gas] of [
        ['the wallet accepts', null, 1, bufferedGasLimit(0x9c40n)],
        ['an expired proof re-proves', PROOF_EXPIRED, 3, FIXED_EXIT_GAS]
    ]) {
        const { h, client, wallet, statuses } = await scenario({ state: noteState({ deposit_path: legacyDepositPath('0x51') }) });
        h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
        await runtime.prepareWithdrawal('mutual', DESTINATION);
        const record = await runtime.parkPreparedWithdrawal();
        // The user funds a newer balance; the old one is set aside.
        await store.writeBrowserWallet({ ...(await store.readBrowserWallet()),
            state: noteState({ note_id: 8, current_anchor: '0x4444' }) });
        await runtime.reload();
        // Later the server, its indexer and the pinned RPC are gone.
        h.server.clearance = () => assert.fail('the kept clearance is reused');
        runtime.indexerPath = () => assert.fail('no indexer');
        runtime.pinnedRpc = () => goneRpc;
        client.syncEscapeWithdrawals = async () => [];
        client.readBrowserWithdrawalStatus = async () => ({ status: 'active', observed_block: 100 });
        client.readContractUint = async () => assert.fail('no vault root is read');
        const closes = () => h.workerOperations('prepareWithdrawal').filter(call => call.payload.args.mode === 'mutual').slice(1);
        wallet.estimate = () => {
            if (refusal) throw revert(refusal);
            return '0x9c40';
        };
        await assert.rejects(within(5_000, client.withdrawBackground(record.recordId, message => statuses.push(message)), label),
            refusedInWallet, label);
        assert.equal(closes().length, closesExpected, label);
        for (const close of closes()) assert.deepEqual(Object.keys(close.payload.args).sort(), ['clearance', 'destination', 'mode', 'valid_until']);
        assert.equal(wallet.sent.length, 1, `${label}: the close reached the wallet`);
        assert.equal(wallet.sent[0].gas, gas, label);
        assert.equal((await store.readBrowserWallet()).state.note_id, 8, `${label}: the newer balance stays selected`);
    }
});
