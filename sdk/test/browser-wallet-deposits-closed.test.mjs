import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { nativeFunding } from './helpers/native-fixtures.mjs';
import { DEPLOYMENT, VAULT, createHarness, memoryIndexedDb } from './helpers/request-archive-harness.mjs';
import { deployedProfile } from './helpers/deployed-profile.mjs';

globalThis.indexedDB = memoryIndexedDb();
globalThis.window = Object.assign(new EventTarget(), { location: { hostname: 'localhost' } });
globalThis.localStorage = { getItem: () => null, setItem() {}, removeItem() {} };

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime, default: sharedRuntime } = await import('../services/browserWalletRuntime.js');
const { ZkapiClient } = await import('../services/zkapiClient.js');

const HASH = `0x${'44'.repeat(32)}`;

/** A runtime whose build-pinned profile sets `deposits`, over the real store. */
async function wallet(deposits, runtimeValue = {}) {
    indexedDB.clear();
    const h = createHarness(BrowserWalletRuntime);
    if (deposits !== undefined) h.runtime.browserConfig.trusted_deployment.deposits = deposits;
    const generated = [];
    const paths = [];
    const call = h.runtime.worker.call;
    h.runtime.worker.call = async (operation, payload) => {
        if (operation === 'generateDeposit') {
            generated.push(operation);
            return { secret: `secret-${generated.length}`, registration_commitment: `0x${generated.length}` };
        }
        return call(operation, payload);
    };
    h.runtime.nextDepositPath = async root => {
        paths.push(root);
        return { note_id: 3, active_root: `0x${root || 1}`, siblings: Array(32).fill('0x0') };
    };
    h.runtime.prewarmRequestProver = async () => {};
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT, billingAsset: 'native_eth', ...runtimeValue });
    await h.runtime.reload();
    return { ...h, generated, paths };
}

const preparedDeposit = (changes = {}) => ({ operationId: 'before-cutoff', createdAt: 1, phase: 'prepared', amount: 123,
    secret: 'secret-before-cutoff', commitment: '0xc0', next_note_id: 3, active_root: '0x1',
    zero_path: Array(32).fill('0x0'), ...changes });

test('a closed deployment refuses to quote or prepare a new deposit before any note secret exists', async () => {
    const h = await wallet('closed');
    for (const attempt of [() => h.runtime.prepareDepositQuote(123, 1n), () => h.runtime.prepareDeposit(123)]) {
        await assert.rejects(attempt(), error => {
            assert.equal(error.code, 'deposits_closed');
            assert.equal(error.status, 409);
            assert.match(error.message, /no longer accepts new deposits/);
            return true;
        });
    }
    assert.deepEqual(h.generated, [], 'no note secret is generated');
    assert.deepEqual(h.paths, [], 'no deposit path is fetched');
    const saved = await store.readBrowserWallet();
    assert.equal(saved.pendingDeposit, null);
    assert.equal(saved.depositQuote, null);
    assert.equal(h.runtime.snapshot().config.deposits, 'closed');

    const open = await wallet(undefined);
    await open.runtime.prepareDepositQuote(123, 1n);
    assert.equal(open.generated.length, 1);
    assert.equal(open.runtime.snapshot().config.deposits, 'open');
});

test('a closed deployment discards an unused deposit draft and never promotes it', async () => {
    const draft = preparedDeposit({ operationId: 'draft', phase: undefined });
    const h = await wallet('closed', { depositQuote: draft });
    await assert.rejects(h.runtime.prepareDeposit(123, { preparedOperationId: 'draft' }), { code: 'deposits_closed' });
    const saved = await store.readBrowserWallet();
    assert.equal(saved.pendingDeposit, null, 'the draft is not promoted');
    assert.equal(saved.depositQuote, null, 'a draft that can never be sent no longer holds the browser to this deployment');

    // Initialization drops one as well, so it never keeps the host on this profile.
    const loaded = await wallet('closed', { depositQuote: draft });
    assert.equal(await loaded.runtime.discardClosedDepositDraftLocked(), true);
    assert.equal((await store.readBrowserWallet()).depositQuote, null);
    const kept = await wallet('open', { depositQuote: draft });
    assert.equal(await kept.runtime.discardClosedDepositDraftLocked(), false);
    assert.equal((await store.readBrowserWallet()).depositQuote.operationId, 'draft');
});

test('a pending deposit from before the cutoff stays tracked, completable and recoverable', async () => {
    // Never signed: its secret is durable, so it can still be sent and confirmed.
    const h = await wallet('closed', { pendingDeposit: preparedDeposit() });
    assert.equal((await h.runtime.prepareDeposit(123)).operationId, 'before-cutoff');
    const refreshed = await h.runtime.refreshPendingDeposit(123, 2n, { expectedOperationId: 'before-cutoff' });
    assert.equal(refreshed.active_root, '0x2');
    assert.equal(refreshed.secret, 'secret-before-cutoff');
    const claim = await h.runtime.claimPendingDepositSubmission('before-cutoff');
    assert.equal(claim.status, 'claimed');
    assert.equal(h.generated.length, 0);
    // A different amount would be a new deposit.
    const other = await wallet('closed', { pendingDeposit: preparedDeposit() });
    await assert.rejects(other.runtime.prepareDeposit(456), { code: 'deposits_closed' });
    assert.equal((await store.readBrowserWallet()).pendingDeposit.operationId, 'before-cutoff', 'never dropped');

    // Signed: the submitted transaction is still tracked to its receipt.
    const signed = await wallet('closed', { pendingDeposit: preparedDeposit({ phase: 'submitted',
        submissionId: 'claim', transactionHash: HASH, transactionHashes: [HASH] }) });
    const tracked = await signed.runtime.claimPendingDepositSubmission();
    assert.equal(tracked.status, 'submitted');
    assert.equal(tracked.transactionHash, HASH);
    assert.equal(signed.runtime.snapshot().config.pending_deposit.transaction_hash, HASH);
    assert.equal((await signed.runtime.prepareDeposit(123)).operationId, 'before-cutoff');
});

test('the client refuses a new deposit and its USD quote before reading the chain or opening a wallet', async t => {
    const h = await wallet('closed');
    const client = new ZkapiClient();
    client.config = { funding: nativeFunding({ contract_address: VAULT }) };
    t.mock.method(client, 'ensureTestnetAccess', async () => {});
    t.mock.method(client, 'emitChange', () => {});
    t.mock.method(client, 'connectWallet', async () => assert.fail('no wallet prompt for a closed deployment'));
    t.mock.method(globalThis, 'fetch', async () => assert.fail('no chain read for a closed deployment'));
    for (const name of ['init', 'depositsClosed', 'depositsClosedError', 'pendingDeposit']) {
        t.mock.method(sharedRuntime, name, (...args) => h.runtime[name](...args));
    }
    client.initialized = true;
    await assert.rejects(client.quoteDepositUsd('10'), { code: 'deposits_closed' });
    await assert.rejects(client.deposit('0.000000123'), { code: 'deposits_closed' });
    await assert.rejects(client.prepareDepositQuote('0.000000123', { from: `0x${'11'.repeat(20)}` }),
        { code: 'deposits_closed' });
});

test('the trusted deposits setting is validated with the rest of the profile', async () => {
    const config = deployedProfile();
    const funding = nativeFunding();
    const trusted = { ...config.trusted_deployment, ...funding, rpc_url: funding.demo_rpc_url, billing_token_address: null };
    const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
        proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
            withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
        privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
    const runtime = new BrowserWalletRuntime();
    for (const deposits of [undefined, 'open', 'closed']) {
        runtime.browserConfig = { ...config, trusted_deployment: { ...trusted, deposits } };
        assert.doesNotThrow(() => runtime.validateManifestTrust(manifest), String(deposits));
    }
    for (const deposits of ['Closed', true, false, 0, 'paused', null]) {
        runtime.browserConfig = { ...config, trusted_deployment: { ...trusted, deposits } };
        if (deposits === null) {
            assert.doesNotThrow(() => runtime.validateManifestTrust(manifest));
            continue;
        }
        assert.throws(() => runtime.validateManifestTrust(manifest), /invalid trusted deposits/, String(deposits));
    }
    // The served manifest cannot close (or reopen) deposits: only the pinned profile does.
    runtime.browserConfig = { ...config, trusted_deployment: trusted };
    runtime.manifest = { ...manifest, deposits: 'closed' };
    assert.equal(runtime.depositsClosed(), false);
});
