// Exits never wait on the operator or on the pinned RPC (design §1.2(6), E0,
// §7.5 "Operator stalls HTTP"), and every exit first initializes the wallet.
// These tests run the real initialize() over fetch: a missing, slow, changed
// or legacy manifest, a down or hanging pinned RPC, and an operator that holds
// every connection open while a request journal is live. An escape is still
// prepared within the E0 budget; deposits and chats wait for the operator.
// The proof worker is the request-archive harness's observed fake.
import assert from 'node:assert/strict';
import test from 'node:test';
import {
    DESTINATION, createHarness, depositPath, memoryIndexedDb, noteState, within
} from './helpers/request-archive-harness.mjs';
import { deployedProfile } from './helpers/deployed-profile.mjs';
import { nativeFunding, nativeQuote } from './helpers/native-fixtures.mjs';

const storage = new Map();
globalThis.indexedDB = memoryIndexedDb();
globalThis.localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, String(value)),
    removeItem: key => storage.delete(key)
};
globalThis.location = new URL('https://host.example/app/');
globalThis.window = Object.assign(new EventTarget(), { location: globalThis.location });
// Cross-tab change notices are not under test (and would keep the process alive).
delete globalThis.BroadcastChannel;

const store = await import('../services/browserWalletStore.js');
const { BrowserWalletRuntime } = await import('../services/browserWalletRuntime.js');
const { configureBrowserSdk } = await import('../configure.js');

configureBrowserSdk({
    configUrl: 'https://host.example/zkapi/v2c/browser-config.json',
    workerUrl: 'https://host.example/zkapi/v2c/assets/zkapiWasmWorker.js'
});

// Mainnet: no Sepolia password gate in front of the operator.
const PROFILE = deployedProfile('mainnet');
const TRUSTED = PROFILE.trusted_deployment;
const DEPLOYMENT_ID = TRUSTED.deployment_id;
// E0's budgets, shortened: one operator call, one E1 pass, one non-exit call.
const FAST = Object.freeze({ callTimeoutMs: 80, recoveryBudgetMs: 400, operatorCallTimeoutMs: 400 });

/** The operator's manifest, equal to the pins. */
function servedManifest() {
    return {
        protocol_version: 2,
        proof_backend: 'groth16_bn254',
        proof_setup: {
            circuit_id: TRUSTED.circuit_id,
            setup_id: TRUSTED.setup_id,
            request_proving_key_sha256: TRUSTED.request_proving_key_sha256,
            withdrawal_proving_key_sha256: TRUSTED.withdrawal_proving_key_sha256
        },
        deployment_id: TRUSTED.deployment_id,
        contract_address: TRUSTED.contract_address,
        chain_id: TRUSTED.chain_id,
        protocol_server_url: TRUSTED.protocol_server_url,
        indexer_url: TRUSTED.indexer_url,
        billing_asset: TRUSTED.billing_asset,
        billing_unit: TRUSTED.billing_unit,
        native_asset_wei_per_unit: TRUSTED.native_asset_wei_per_unit,
        native_price_feed_address: TRUSTED.native_price_feed_address,
        native_price_feed_decimals: TRUSTED.native_price_feed_decimals,
        native_price_max_age_seconds: TRUSTED.native_price_max_age_seconds,
        rpc_url: TRUSTED.rpc_url,
        billing_token_address: null,
        request_charge_cap: TRUSTED.request_charge_cap,
        state_signing_key: TRUSTED.state_signing_key,
        clearance_signing_key: TRUSTED.clearance_signing_key,
        models: ['model-a'],
        privacy_mode: { openrouter_inference_base: TRUSTED.openrouter_inference_base, verifier_url: TRUSTED.verifier_url }
    };
}

// The network: the host (browser-config.json), the operator (manifest, API,
// indexer, possibly through the host's deployment proxy) and the pinned RPC.
// A hanging answer never settles and ignores its abort signal (the worst
// transport), so only the runtime's own timeouts end it.
const net = { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang', answer: null, calls: [] };
const hang = () => new Promise(() => {});
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
const rpcResult = result => json({ jsonrpc: '2.0', id: 1, result });
globalThis.fetch = async (url, init = {}) => {
    const target = String(url);
    net.calls.push(target);
    if (target.endsWith('/browser-config.json')) {
        return net.browserConfig === 'down' ? new Response('', { status: 503 }) : json(PROFILE);
    }
    if (target.endsWith('/config.json')) {
        if (net.manifest === 'missing') return new Response('', { status: 404 });
        if (net.manifest === 'hang') return hang();
        if (net.manifest === 'changed') return json({ ...servedManifest(), state_signing_key: { x: '0x1', y: '0x2' } });
        if (net.manifest === 'legacy') {
            const legacy = servedManifest();
            legacy.proof_setup.circuit_id = 'zkapi-v2-note-bound-v1';
            return json(legacy);
        }
        return json(servedManifest());
    }
    if (target.startsWith(TRUSTED.rpc_url)) {
        if (net.rpc === 'hang') return hang();
        if (net.rpc === 'down') throw new TypeError('Failed to fetch');
        const { method, params } = JSON.parse(init.body);
        if (method === 'eth_chainId') return rpcResult(`0x${Number(TRUSTED.chain_id).toString(16)}`);
        const word = value => `0x${BigInt(value).toString(16).padStart(64, '0')}`;
        // nativeAssetWeiPerUnit and billingToken: a native-ETH vault.
        if (method === 'eth_call' && params[0].data === '0x4d1352fd') return rpcResult(word(1_000_000_000n));
        if (method === 'eth_call') return rpcResult(word(0));
        return json({ jsonrpc: '2.0', id: 1, error: { code: -32601, message: 'unsupported' } });
    }
    if (net.operator === 'hang') return hang();
    return net.answer(target, init);
};

// The proof worker: the harness's fake (its calls in proofLog), plus the bundle identity.
let proofWorker = null;
let proofLog = null;
globalThis.Worker = class {
    constructor() { this.listeners = {}; }
    addEventListener(type, listener) { this.listeners[type] = listener; }
    postMessage({ id, operation, payload }) {
        const answer = operation === 'identity'
            ? Promise.resolve({ circuit_id: TRUSTED.circuit_id, setup_id: TRUSTED.setup_id })
            : proofWorker.call(operation, payload);
        answer.then(result => this.listeners.message?.({ data: { id, result } }),
            error => this.listeners.message?.({ data: { id, error: error.message } }));
    }
};

/**
 * A wallet of this deployment, as a tab left it: a note with its deposit-time
 * path, and (by default) one request sent from it whose journal is live.
 */
async function savedWallet({ liveRequest = true } = {}) {
    indexedDB.clear();
    storage.clear();
    net.calls.length = 0;
    const seed = createHarness(BrowserWalletRuntime);
    seed.runtime.manifest = { deployment_id: DEPLOYMENT_ID };
    // The request's proof-bound quote is of this profile's feed and chain.
    const funding = nativeFunding({ chain_id: Number(TRUSTED.chain_id), contract_address: TRUSTED.contract_address,
        protocol_server_url: TRUSTED.protocol_server_url, demo_rpc_url: TRUSTED.rpc_url,
        native_price_feed_address: TRUSTED.native_price_feed_address,
        native_price_feed_decimals: TRUSTED.native_price_feed_decimals,
        native_price_max_age_seconds: TRUSTED.native_price_max_age_seconds });
    const quote = nativeQuote(funding);
    seed.runtime.config.funding = funding;
    seed.runtime.config.wallet_core.chain_id = funding.chain_id;
    seed.runtime.nativeBillingQuote = async () => quote;
    proofWorker = seed.runtime.worker;
    proofLog = seed.worker;
    await store.writeBrowserWallet({ deploymentId: DEPLOYMENT_ID, billingAsset: 'native_eth',
        state: noteState({ chain_id: Number(TRUSTED.chain_id), deposit_path: depositPath() }) });
    await seed.runtime.reload();
    if (liveRequest) {
        seed.server.leasePost = body => seed.activeLease(body, { billing_quote: quote });
        await seed.runtime.issueLease('chat');
    }
    return seed;
}

/** A new page: a runtime that initializes for real. */
function reloadedPage(timing = FAST) {
    const runtime = new BrowserWalletRuntime();
    runtime.exitTimingOverrides = { ...timing };
    return runtime;
}

const elapsed = started => Date.now() - started;
const lastWithdrawalProof = () => proofLog.calls.filter(call => call.operation === 'prepareWithdrawal').at(-1);

test('an operator holding every connection open cannot stall initialization or an escape from a live request', async () => {
    await within(5_000, savedWallet(), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    // Long bounds on the startup recovery (its pass and each of its non-exit
    // calls): only the escape stopping it frees the wallet lock in time.
    const runtime = reloadedPage({ ...FAST, recoveryBudgetMs: 10_000, operatorCallTimeoutMs: 10_000 });
    const started = Date.now();
    const snapshot = await within(1_000, runtime.init(), 'initialization');
    assert.ok(elapsed(started) < 1_000, `initialization took ${elapsed(started)} ms`);
    assert.equal(snapshot.config.service.available, true);
    // The startup recovery of the live journal now waits on the operator
    // under the wallet lock...
    assert.ok(runtime.startupRecoveryController, 'the startup recovery is running');
    while (!net.calls.some(url => url.includes('/v2/openrouter/leases/'))) await new Promise(resolve => setTimeout(resolve, 5));
    // ...and the escape stops it, then decides within E0's budgets.
    const plan = await within(3_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape');
    assert.ok(elapsed(started) < 3_000, `the escape took ${elapsed(started)} ms`);
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.public_inputs.kind, 0);
    // A request may be reserved: before T a forced escape concedes 0 (E3).
    assert.equal(plan.decision.rule, 'E3.forced');
    assert.equal(plan.public_inputs.conceded, 0);
    assert.equal(plan.pathSource, 'deposit');
    assert.equal(await within(1_000, runtime.startupRecovery, 'the stopped startup recovery'), false);
    const saved = await store.readBrowserWallet();
    assert.deepEqual(saved.exitLock.released.map(entry => entry.kind), [0]);
    assert.equal(saved.journal, null, 'the live journal moved to the archive (abandoned_for_escape)');
});

test('without an exit, the startup recovery of a hanging operator still ends within the E1 budget', async () => {
    await within(5_000, savedWallet(), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    // Each non-exit call of the pass may take 5 s: only RECOVERY_BUDGET ends it in time.
    const runtime = reloadedPage({ ...FAST, operatorCallTimeoutMs: 5_000 });
    const started = Date.now();
    await within(1_000, runtime.init(), 'initialization');
    assert.equal(await within(FAST.recoveryBudgetMs + 600, runtime.startupRecovery, 'the startup recovery'), false);
    assert.ok(elapsed(started) < FAST.recoveryBudgetMs + 600, `the recovery took ${elapsed(started)} ms`);
    // The lock is free again: another tab's exit runs at once.
    const other = reloadedPage();
    const plan = await within(3_000, other.prepareWithdrawal('escape', DESTINATION), 'the other tab\'s escape');
    assert.equal(plan.mode, 'escape');
});

test('a missing, slow, changed or legacy manifest leaves exits to the pins and refuses deposits and chats', async () => {
    for (const [manifest, code] of [['missing', 'deployment_manifest_unavailable'], ['hang', 'deployment_manifest_unavailable'],
        ['changed', 'deployment_manifest_mismatch'], ['legacy', 'incompatible_proof_circuit']]) {
        await within(5_000, savedWallet(), 'the saved wallet');
        Object.assign(net, { browserConfig: 'ok', manifest, rpc: 'ok', operator: 'hang' });
        const runtime = reloadedPage();
        const started = Date.now();
        const snapshot = await within(1_000, runtime.init(), 'initialization');
        assert.ok(elapsed(started) < 1_000, `${manifest}: initialization took ${elapsed(started)} ms`);
        assert.equal(snapshot.config.service.available, false, manifest);
        assert.equal(snapshot.config.service.code, code, manifest);
        assert.equal(snapshot.config.service.exits, true);
        assert.equal(storage.get('zkapi-browser-deployment'), undefined, 'an unusable manifest is not remembered');
        // The client configuration is the pinned one, whatever was served.
        assert.deepEqual(runtime.config.wallet_core.state_signing_key, TRUSTED.state_signing_key);
        assert.equal(runtime.config.funding.protocol_server_url, TRUSTED.protocol_server_url);

        const plan = await within(3_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape');
        assert.equal(plan.mode, 'escape', manifest);
        assert.deepEqual(lastWithdrawalProof().payload.config.state_signing_key, TRUSTED.state_signing_key,
            'the proof binds the pinned keys');
        assert.ok(elapsed(started) < 3_000, `${manifest}: the escape took ${elapsed(started)} ms`);

        // Deposits and chats need the operator's manifest to match the pins.
        await assert.rejects(within(3_000, runtime.prepareDepositQuote(1_000_000, null), 'the refusal'), { code });
        await assert.rejects(within(3_000, runtime.prepareDeposit(1_000_000), 'the refusal'), { code });
        await assert.rejects(within(3_000, runtime.issueLease('chat'), 'the refusal'), { code });
        await assert.rejects(within(3_000, runtime.verifyDeploymentForDeposit({
            walletRequest: async () => assert.fail('not reached'), depositWei: 1n }), 'the refusal'), { code });
    }
});

test('exit-only mode ends when the operator serves the pinned manifest again', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'missing', rpc: 'ok', operator: 'hang' });
    const runtime = reloadedPage();
    await within(1_000, runtime.init(), 'initialization');
    assert.equal(runtime.snapshot().config.service.available, false);
    assert.deepEqual(runtime.config.funding.models, [], 'the pins carry no model list');
    net.manifest = 'ok';
    await within(1_000, runtime.assertServiceAvailable(), 'the service check');
    assert.equal(runtime.snapshot().config.service.available, true);
    assert.deepEqual(runtime.config.funding.models, ['model-a'], 'the served manifest configures requests again');
    assert.equal(storage.get('zkapi-browser-deployment'), 'https://protocol.example/config.json');
});

test('a down or hanging pinned RPC never blocks initialization or an escape, and refuses deposits', async () => {
    for (const rpc of ['down', 'hang']) {
        await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
        Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc, operator: 'hang' });
        const runtime = reloadedPage();
        const started = Date.now();
        const snapshot = await within(1_000, runtime.init(), 'initialization');
        assert.ok(elapsed(started) < 1_000, `${rpc}: initialization took ${elapsed(started)} ms`);
        assert.equal(snapshot.config.service.available, true, 'the manifest matched');
        const plan = await within(3_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape');
        assert.equal(plan.mode, 'escape', rpc);
        assert.equal(plan.decision.rule, 'E2.escape');
        assert.ok(elapsed(started) < 3_000, `${rpc}: the escape took ${elapsed(started)} ms`);
        // A deposit (or chat) needs the pinned RPC to confirm a native-ETH vault.
        await assert.rejects(within(3_000, runtime.prepareDepositQuote(1_000_000, null), 'the refusal'),
            { code: 'native_vault_unverified' });
    }
});

test('a failed initialization is not kept: the next call initializes again', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'down', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    const runtime = reloadedPage();
    await assert.rejects(within(1_000, runtime.init(), 'initialization'), /browser-config\.json \(503\)/);
    net.browserConfig = 'ok';
    const snapshot = await within(1_000, runtime.init(), 'initialization');
    assert.equal(snapshot.config.service.available, true);
    assert.equal(runtime.initialized, true);
});

test('a healthy operator still finishes an interrupted request after initialization', async () => {
    const seed = await within(5_000, savedWallet(), 'the saved wallet');
    const journal = (await store.readBrowserWallet()).journal;
    const receipt = seed.receiptFor(journal, { charge: 25_000, nextAnchor: '0x9999' });
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'answer' });
    net.answer = target => {
        const path = new URL(target).pathname.replace(/^\/zkapi-deployment/, '');
        if (path === `/v2/openrouter/leases/${journal.client_request_id}`) return json({ status: 'finalized' });
        if (path === `/v2/requests/${journal.client_request_id}`) return json({ request_response: receipt });
        return json({ error: { code: 'not_found' } }, 404);
    };
    const runtime = reloadedPage();
    await within(1_000, runtime.init(), 'initialization');
    assert.equal(await within(1_000, runtime.startupRecovery, 'the startup recovery'), true);
    const saved = await store.readBrowserWallet();
    assert.equal(saved.journal, null);
    assert.equal(saved.state.current_anchor, '0x9999');
    assert.equal(saved.state.current_balance, 5_000_000 - 25_000);
});

test('a hung non-exit call in another tab holds an exit only until its own timeout', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    const chatTab = reloadedPage();
    const exitTab = reloadedPage();
    await within(1_000, chatTab.init(), 'initialization');
    await within(1_000, exitTab.init(), 'initialization');
    // The chat tab prepares a request under the wallet lock; the indexer
    // (the operator) never answers.
    const chat = chatTab.issueLease('chat').then(() => assert.fail('the chat cannot start'), error => error);
    await new Promise(resolve => setTimeout(resolve, 20));
    const started = Date.now();
    const plan = await within(FAST.operatorCallTimeoutMs + 2_000, exitTab.prepareWithdrawal('escape', DESTINATION),
        'the escape');
    assert.equal(plan.mode, 'escape');
    assert.ok(elapsed(started) < FAST.operatorCallTimeoutMs + 2_000, `the exit waited ${elapsed(started)} ms`);
    const error = await within(FAST.operatorCallTimeoutMs + 1_000, chat, 'the chat');
    assert.equal(error.name, 'TimeoutError', String(error));
});

test('the client does not keep a failed start either', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    globalThis.zkapiWallet ||= (await import('../wallet.js')).default;
    const { ZkapiClient } = await import('../services/zkapiClient.js');
    const { default: pageRuntime } = await import('../services/browserWalletRuntime.js');
    pageRuntime.exitTimingOverrides = { ...FAST };
    Object.assign(net, { browserConfig: 'down', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    Object.assign(window, { setInterval, clearInterval });
    const client = new ZkapiClient();
    await assert.rejects(within(1_000, client.init(), 'initialization'), /browser-config\.json \(503\)/);
    net.browserConfig = 'ok';
    const snapshot = await within(1_000, client.init(), 'initialization');
    assert.equal(client.initialized, true);
    assert.equal(snapshot.config.service.available, true);
    clearInterval(client.refreshTimer);
    clearInterval(client.clockTimer);
});

test('an untrusted ?zkapiDeployment link leaves exits to the pins instead of stopping the wallet', async t => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    globalThis.location = new URL('https://host.example/app/?zkapiDeployment=https://evil.example/config.json');
    t.after(() => { globalThis.location = new URL('https://host.example/app/'); });
    const runtime = reloadedPage();
    const snapshot = await within(1_000, runtime.init(), 'initialization');
    assert.equal(snapshot.config.service.code, 'deployment_manifest_untrusted');
    assert.ok(!net.calls.some(url => url.includes('evil.example')), 'the untrusted manifest is never fetched');
    assert.equal((await within(3_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape')).mode, 'escape');
    await assert.rejects(within(3_000, runtime.prepareDepositQuote(1_000_000, null), 'the refusal'),
        { code: 'deployment_manifest_untrusted' });
});

test('a withdrawal in the same tab stops a private key still being issued instead of waiting for it', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    // A long non-exit bound: only the preemption can free the lock in time.
    const runtime = reloadedPage({ ...FAST, operatorCallTimeoutMs: 10_000 });
    await within(1_000, runtime.init(), 'initialization');
    const chat = runtime.ensureLease('chat').then(() => assert.fail('the chat cannot start'), error => error);
    await new Promise(resolve => setTimeout(resolve, 20));
    const started = Date.now();
    const plan = await within(2_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape');
    assert.equal(plan.mode, 'escape');
    assert.ok(elapsed(started) < 2_000, `the exit waited ${elapsed(started)} ms`);
    const error = await within(1_000, chat, 'the stopped chat');
    assert.equal(error.name, 'AbortError', String(error));
});

test('an exit RPC that hangs and ignores its abort signal still ends at E0\'s call timeout', async () => {
    await within(5_000, savedWallet({ liveRequest: false }), 'the saved wallet');
    Object.assign(net, { browserConfig: 'ok', manifest: 'ok', rpc: 'ok', operator: 'hang' });
    const runtime = reloadedPage();
    await within(1_000, runtime.init(), 'initialization');
    // The user's own RPC (net.operator 'hang' answers every other URL).
    runtime.setExitRpcUrl('https://exit-rpc.example/');
    const started = Date.now();
    const plan = await within(3_000, runtime.prepareWithdrawal('escape', DESTINATION), 'the escape');
    assert.equal(plan.mode, 'escape');
    assert.equal(plan.decision.rule, 'E2.escape');
    assert.ok(elapsed(started) < 3_000, `the escape took ${elapsed(started)} ms`);
    assert.ok(net.calls.some(url => url.startsWith('https://exit-rpc.example/')), 'the escape read the exit RPC');
});
