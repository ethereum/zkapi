// The operator's close relay through the real browser runtime, store and
// client (zkapiClient.performWithdrawal with fees 'relay'): the fee request is
// proved and installed like any request, the cooperative close is prepared at
// its successor and handed to the relay with the ticket secret, and the
// withdrawal ends on the vault's MutualClose of exactly that close (whoever
// sent it), or is submitted from the wallet when the relay gives it back. The
// protocol server, the wallet provider and the proof worker are observed
// fakes.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DEPLOYMENT, DESTINATION, SERVER, VAULT, createHarness, derivedAnchor, memoryIndexedDb, noteState, nullifierFor
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
const { MUTUAL_CLOSE_TOPIC, closeRelayTicketHash } = await import('../services/zkapiCloseRelay.mjs');

const FROM = `0x${'77'.repeat(20)}`;
const FEE = 1_000;
const RELAY_TX = `0x${'be'.repeat(32)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');

/** The shared runtime under the harness, with the relay routes added. */
async function scenario() {
    indexedDB.clear();
    storage.clear();
    for (const name of ['exitRpc', 'pinnedRpc']) delete runtime[name];
    runtime.activeLease = null;
    runtime.exitGasPrice = null;
    const h = createHarness(function SharedRuntime() { return runtime; });
    h.worker.mutate = plan => { plan.proof.proof = Buffer.alloc(256, h.worker.proofs).toString('base64'); };
    h.server.clearance = body => ({ status: 'ok', withdrawal_nullifier: body.withdrawal_nullifier, signature: { r: '0x1', s: '0x2' } });
    const relay = { enabled: true, fees: [], submissions: [], status: 'queued', charge: FEE, feeError: null, calls: [] };
    const base = runtime.remoteJson;
    runtime.remoteJson = async (url, init = {}) => {
        const method = init.method || 'GET';
        const path = url.slice(SERVER.length);
        relay.calls.push(`${method} ${path}`);
        if (path === '/v2/withdraw/relay/terms') {
            return relay.enabled ? { enabled: true, fee_units: String(FEE), exit_batcher: `0x${'ba'.repeat(20)}` } : { enabled: false };
        }
        if (method === 'POST' && path === '/v2/withdraw/relay/fee') {
            const request = JSON.parse(init.body);
            relay.fees.push(request);
            if (relay.feeError) throw relay.feeError;
            const payload = JSON.parse(request.payload);
            const journal = (await store.readBrowserWallet()).journal;
            return {
                status: 'ok', client_request_id: request.client_request_id, request_nullifier: journal.nullifier,
                response_code: 200,
                response_payload: JSON.stringify({ status: 'relay_fee_paid', fee_units: payload.fee_units, ticket_hash: payload.ticket_hash }),
                response_hash: '0x1', charge_applied: relay.charge, next_commitment: { x: '0x1', y: '0x2' },
                next_anchor: derivedAnchor(journal.nullifier), blind_delta_srv: '0x3', next_state_signature: 'valid-state-signature'
            };
        }
        if (method === 'POST' && path === '/v2/withdraw/relay') {
            relay.submissions.push(JSON.parse(init.body));
            return { status: 'queued', self_submit: false };
        }
        if (method === 'GET' && path.startsWith('/v2/withdraw/relay/')) {
            return { status: relay.status, self_submit: ['failed', 'expired'].includes(relay.status) };
        }
        return base(url, init);
    };
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', state: noteState() });
    await runtime.reload();
    return { h, relay };
}

/** A client over a scripted wallet provider and chain. */
function clientFor(h, chain) {
    globalThis.ethereum = {
        async request({ method, params = [] }) {
            if (method === 'eth_chainId') return `0x${Number(h.funding.chain_id).toString(16)}`;
            if (method === 'eth_blockNumber') return '0x10';
            if (method === 'eth_getLogs') {
                chain.logReads += 1;
                return chain.logReads >= chain.landAfter ? chain.logs : [];
            }
            if (method === 'eth_getTransactionReceipt') return chain.receipts[params[0]] || null;
            if (method === 'eth_estimateGas') return '0x9c40';
            if (method === 'eth_getTransactionCount') return '0x5';
            if (method === 'eth_sendTransaction') {
                chain.sent.push(params[0]);
                throw { code: 4001, message: 'User rejected the request.' };
            }
            throw new Error(`unexpected wallet RPC ${method}`);
        }
    };
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = runtime.config;
    const state = noteState();
    client.wallet = { has_note: true, note: { note_id: state.note_id, current_balance: state.current_balance } };
    for (const name of ['assertBalanceNotClaimed', 'refresh', 'settleActiveLease']) client[name] = async () => {};
    client.connectWallet = async () => FROM;
    client.readContractUint = async () => BigInt(h.chain.root);
    client.recoverFailedWithdrawalSubmission = async () => null;
    client.submittedTransactionMetadata = async () => null;
    client.confirmMinedWithdrawalStatus = async () => ({ status: 'closed', observed_block: 0x11 });
    // Polls run back to back, an hour before valid_until.
    client.closeRelayTiming = { sleep: async () => {}, pollMs: 0, now: () => chain.now };
    const statuses = [];
    const withdraw = () => client.performWithdrawal('mutual', message => statuses.push(message), { destination: DESTINATION, fees: 'relay' });
    return { client, statuses, withdraw };
}

/**
 * The vault's MutualClose of the close the relay holds, in the relay's batch,
 * after another note's close in the same batch.
 */
function landed(chain, plan) {
    const inputs = plan.public_inputs;
    const closeOf = (noteId, nullifier, finalBalance, destination) => ({
        address: VAULT, removed: false, transactionHash: RELAY_TX,
        topics: [MUTUAL_CLOSE_TOPIC, `0x${word(noteId)}`],
        data: `0x${word(nullifier)}${word(finalBalance)}${word(destination)}`
    });
    const log = closeOf(inputs.note_id, inputs.withdrawal_nullifier, inputs.final_balance, DESTINATION);
    const other = closeOf(Number(inputs.note_id) + 1, 0x1234, 777, `0x${'0d'.repeat(20)}`);
    chain.logs = [log];
    chain.receipts[RELAY_TX] = { transactionHash: RELAY_TX, status: '0x1', blockNumber: '0x11', to: `0x${'ba'.repeat(20)}`, logs: [other, log] };
}

test('the relay fee is one proved request, installed with exactly the fee, and idempotent', async () => {
    const { h, relay } = await scenario();
    const before = await store.readBrowserWallet();
    const paid = await runtime.payCloseRelayFee();
    assert.equal(paid.status, 'paid');
    assert.equal(paid.feeUnits, String(FEE));
    const proofs = h.workerOperations('prepareRequest');
    assert.equal(proofs.length, 1);
    const payload = JSON.parse(proofs[0].payload.args.payload);
    assert.equal(payload.mode, 'close_relay_fee');
    assert.equal(payload.fee_units, String(FEE));
    assert.equal(payload.ticket_hash, paid.ticketHash);
    assert.equal(proofs[0].payload.config.request_charge_cap, FEE, 'the bound is the fee');
    const after = await store.readBrowserWallet();
    assert.equal(after.state.current_balance, before.state.current_balance - FEE);
    assert.equal(after.state.current_anchor, derivedAnchor(nullifierFor(before.state.current_anchor)));
    assert.equal(after.journal, null);
    assert.equal(after.closeRelay.phase, 'paid');
    assert.equal(closeRelayTicketHash(after.closeRelay.secret), paid.ticketHash);
    // Paid once per note.
    assert.deepEqual(await runtime.payCloseRelayFee(), paid);
    assert.equal(relay.fees.length, 1);
    assert.equal(h.workerOperations('prepareRequest').length, 1);
});

test('a relay fee receipt that charges another amount is never installed; no relay refuses before proving', async () => {
    const { h, relay } = await scenario();
    relay.charge = FEE + 1;
    await assert.rejects(runtime.payCloseRelayFee(), /does not match the fee request/);
    const stuck = await store.readBrowserWallet();
    assert.equal(stuck.state.current_balance, noteState().current_balance, 'nothing installed');
    assert.ok(stuck.journal, 'the request stays journaled for recovery');

    const off = await scenario();
    off.relay.enabled = false;
    await assert.rejects(runtime.payCloseRelayFee(), error => error.code === 'relay_disabled');
    assert.equal(off.h.workerOperations('prepareRequest').length, 0);
    assert.equal(h.workerOperations('prepareRequest').length, 1);
});

test('fees relay: the relay lands the close through the batcher and nothing is sent from the wallet', async () => {
    const { h, relay } = await scenario();
    const chain = { logs: [], receipts: {}, sent: [], logReads: 0, landAfter: 3, now: 0 };
    const { statuses, withdraw } = clientFor(h, chain);
    // Land the close once it is prepared and handed over.
    const mutate = h.worker.mutate;
    h.worker.mutate = (plan, payload) => {
        mutate(plan, payload);
        chain.now = Number(plan.public_inputs.valid_until) - 3_600;
        landed(chain, plan);
    };
    const result = await withdraw();
    assert.equal(result.status, 'closed');
    assert.equal(result.receipt.transactionHash, RELAY_TX);
    assert.equal(chain.sent.length, 0, 'nothing was sent from the wallet');
    assert.equal(relay.fees.length, 1);
    assert.equal(relay.submissions.length, 1);
    const submission = relay.submissions[0];
    const fee = JSON.parse(relay.fees[0].payload);
    assert.equal(closeRelayTicketHash(submission.ticket_secret), fee.ticket_hash);
    assert.equal(submission.public_inputs.kind, 1);
    assert.equal(submission.public_inputs.final_balance, noteState().current_balance - FEE, 'the close pays the balance less the fee');
    // The fee came before the close's clearance, which came before the relay.
    const order = ['POST /v2/withdraw/relay/fee', 'POST /v2/withdraw/clearance', 'POST /v2/withdraw/relay']
        .map(call => relay.calls.indexOf(call));
    assert.ok(order[0] >= 0 && order[0] < order[1] && order[1] < order[2], relay.calls.join(', '));
    assert.ok(statuses.some(message => /relay landed this close/.test(message)));
});

test('fees relay: a close the relay gives back is submitted from the wallet', async () => {
    const { h, relay } = await scenario();
    relay.status = 'failed';
    const chain = { logs: [], receipts: {}, sent: [], logReads: 0, landAfter: Infinity, now: 0 };
    const { statuses, withdraw } = clientFor(h, chain);
    const mutate = h.worker.mutate;
    h.worker.mutate = (plan, payload) => {
        mutate(plan, payload);
        chain.now = Number(plan.public_inputs.valid_until) - 3_600;
    };
    await assert.rejects(withdraw(), error => error.code === 4001);
    assert.equal(relay.submissions.length, 1);
    assert.equal(chain.sent.length, 1, 'the wallet was asked to send the close');
    assert.equal(chain.sent[0].to.toLowerCase(), VAULT.toLowerCase());
    assert.ok(statuses.some(message => /relay did not land the close in time/.test(message)));
});

test('fees relay is for cooperative closes only', async () => {
    const client = new ZkapiClient();
    await assert.rejects(client.withdraw('escape', () => {}, { destination: DESTINATION, fees: 'relay' }), TypeError);
});
