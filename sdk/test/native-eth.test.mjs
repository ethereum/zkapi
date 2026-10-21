import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { configureBrowserSdk } from '../configure.js';
import { ZkapiClient } from '../services/zkapiClient.js';
import { BrowserWalletRuntime, BrowserWalletHttpError } from '../services/browserWalletRuntime.js';
import { assertExternalTransaction } from '../services/zkapiExternalTransactions.mjs';
import { validateNativeQuote, readNativeQuote, nativeUnitsForUsd, nativeUsdMicros,
    nativeDepositValue, parseUnits, formatUnits } from '../services/zkapiNativeEth.mjs';
import codec from '../wallet.js';
import { deployedProfile } from './helpers/deployed-profile.mjs';

const FROM = `0x${'11'.repeat(20)}`;
const VAULT = `0x${'22'.repeat(20)}`;
const FEED = `0x${'33'.repeat(20)}`;
const HASH = `0x${'44'.repeat(32)}`;
const funding = {
    chain_id: 11155111, contract_address: VAULT, billing_asset: 'native_eth', billing_unit: 'gwei',
    native_asset_wei_per_unit: '1000000000', native_price_feed_address: FEED,
    native_price_feed_decimals: 8, native_price_max_age_seconds: 3600,
    demo_rpc_url: 'https://rpc.example', protocol_server_url: 'https://protocol.example'
};
const quote = (changes = {}) => ({ asset: 'native_eth', units_per_eth: 1_000_000_000,
    chain_id: funding.chain_id, feed_address: FEED, round_id: '123', answer: '300000000000',
    decimals: 8, updated_at: Math.floor(Date.now() / 1000) - 60,
    expires_at: Math.floor(Date.now() / 1000) - 60 + 3600, ...changes });
const word = value => BigInt(value).toString(16).padStart(64, '0');

test('USD converts upward to whole gwei and native ledger amounts never use floating point', () => {
    const q = quote();
    assert.equal(nativeUnitsForUsd('10', q), 3_333_334n);
    assert.equal(nativeDepositValue(3_333_334n, funding), 3_333_334_000_000_000n);
    assert.equal(formatUnits(3_333_334n, 9), '0.003333334');
    assert.equal(parseUnits('0.003333334', 9), 3_333_334n);
    assert.equal(nativeUsdMicros(3_333_334n, q), 10_000_002n);
    assert.throws(() => nativeUnitsForUsd('1e3', q));
    assert.throws(() => nativeUnitsForUsd('0', q));
    assert.throws(() => nativeUnitsForUsd('9999999999999999999', q));
    assert.throws(() => parseUnits('0.0000000001', 9));
});

test('native feed quotes reject stale, future, negative, incomplete and mismatched configuration', () => {
    assert.doesNotThrow(() => validateNativeQuote(quote(), funding));
    const now = Math.floor(Date.now() / 1000);
    assert.doesNotThrow(() => validateNativeQuote(quote({ answer: '1000000000000000000',
        updated_at: now, expires_at: now + 3600 }), funding, { now }));
    assert.throws(() => validateNativeQuote(quote({ answer: '1000000000000000001' }), funding, { now }));
    assert.throws(() => validateNativeQuote(quote({ updated_at: now + 1, expires_at: now + 3601 }), funding, { now }));
    for (const change of [{ answer: '0' }, { answer: '-1' }, { answer: String(1n << 255n) },
        { round_id: '0' }, { round_id: String(1n << 80n) }, { feed_address: FROM },
        { chain_id: 1 }, { decimals: 18 }, { units_per_eth: 1e18 }, { expires_at: 1 },
        { updated_at: Date.now(), expires_at: Date.now() + 3600 },
        { updated_at: 1, expires_at: 3601 }]) {
        assert.throws(() => validateNativeQuote(quote(change), funding), /invalid|stale/);
    }
    assert.throws(() => validateNativeQuote(quote(), { ...funding, billing_unit: 'wei' }));
    assert.throws(() => nativeDepositValue(1n, { ...funding, native_asset_wei_per_unit: '1' }));
});

function priceRpc(t, options = {}) {
    const q = quote({ feed_address: (options.feedAddress || FEED).toLowerCase() });
    const calls = [];
    const block = { number: '0x123', hash: HASH };
    t.mock.method(globalThis, 'fetch', async (url, init) => {
        assert.equal(url, funding.demo_rpc_url);
        assert.equal(init.credentials, 'omit');
        const { method, params } = JSON.parse(init.body);
        calls.push({ method, params });
        let result;
        if (method === 'eth_chainId') result = options.chain || '0xaa36a7';
        else if (method === 'eth_getBlockByNumber') {
            assert.ok(params[0] === 'finalized' || params[0] === block.number, 'native prices must never use an unfinalized head');
            result = params[0] === 'finalized' ? block
                : options.reorg ? { ...block, hash: `0x${'ff'.repeat(32)}` } : block;
        }
        else if (method === 'eth_call') {
            assert.ok([options.feedAddress || FEED, VAULT].includes(params[0].to));
            assert.equal(params[1], params[0].to === VAULT ? 'latest' : block.number);
            result = params[0].data === '0x4d1352fd' ? `0x${word(options.vaultScale ?? 1_000_000_000)}`
                : params[0].data === '0x631b2f10' ? `0x${word(options.token ?? 0)}`
                : params[0].data === '0x313ce567' ? `0x${word(options.decimals ?? 8)}`
                : `0x${[options.actualRound || q.round_id, options.answer || q.answer, q.updated_at - 1, q.updated_at,
                    options.answeredRound || options.actualRound || q.round_id].map(word).join('')}`;
        } else assert.fail(`Price reads must never sign: ${method}`);
        return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
    });
    return { q, calls };
}

test('quoteDepositUsd reads pinned Chainlink round using credential-free RPC without a wallet', async t => {
    const { q, calls } = priceRpc(t);
    const client = new ZkapiClient();
    t.mock.method(client, 'emitChange', () => {});
    client.config = { funding };
    assert.equal(client.isNativeEthFunding, true);
    assert.equal(client.formatMoney(3_333_334), '—');
    const result = await client.quoteDepositUsd('10.00');
    assert.equal(result.amount, '3333334');
    assert.equal(result.depositWei, '3333334000000000');
    assert.equal(result.ethAmount, '0.003333334');
    assert.equal(result.usdAmount, '10');
    assert.equal(result.priceUpdatedAt, q.updated_at);
    assert.match(client.formatMoney(3_333_334), /10\.00/);
    assert.equal(client.formatBillingAmount(3_333_334), '0.003333334');
    assert.equal(calls.some(call => call.method === 'eth_requestAccounts'), false);
    client.ethUsdQuote = quote({ answer: '600000000000' });
    assert.match(client.formatMoney(3_333_334), /20\.00/, 'ETH principal stays fixed as USD moves');
    client.ethUsdQuote = quote({ updated_at: 1, expires_at: 3601 });
    assert.equal(client.formatMoney(3_333_334), '—');
});

for (const [label, options] of [['wrong chain', { chain: '0x1' }], ['reorganization', { reorg: true }],
    ['wrong decimals', { decimals: 18 }], ['incomplete round', { answeredRound: '122' }],
    ['wrong vault denomination', { vaultScale: 1 }], ['ERC-20 vault', { token: 1 }]]) {
    test(`native quote fails closed on ${label}`, async t => {
        priceRpc(t, options);
        await assert.rejects(readNativeQuote(funding));
    });
}

test('server billing quote must match the latest finalized feed round and price', async t => {
    const { q, calls } = priceRpc(t);
    assert.deepEqual(await readNativeQuote(funding, { expected: q }), q);
    assert.ok(calls.some(call => call.params[0]?.data === '0xfeaf968c'));
    assert.equal(calls.some(call => call.params[0]?.data?.startsWith('0x9a6fc8f5')), false);
    await assert.rejects(readNativeQuote(funding, { expected: { ...q, answer: '300000000001' } }), /does not match/);
});

test('an unexpired server quote from an older finalized round cannot authorize a new lease', async t => {
    const { q } = priceRpc(t, { actualRound: '124', answer: '400000000000' });
    const runtime = new BrowserWalletRuntime();
    runtime.config = { funding };
    runtime.remoteJson = async () => q;
    await assert.rejects(runtime.nativeBillingQuote(), /does not match/);
    assert.equal(runtime.ethUsdQuote, undefined);
});

test('native deposit preflights and submits payable value once, without token mint or allowance', async t => {
    priceRpc(t);
    const client = new ZkapiClient();
    t.mock.method(client, 'emitChange', () => {});
    client.config = { funding };
    const calls = [];
    client.setWalletProvider({ async request({ method, params }) {
        calls.push({ method, params });
        if (method === 'eth_chainId') return '0xaa36a7';
        if (method === 'eth_getBalance') return '0xde0b6b3a7640000';
        if (method === 'eth_call') return '0x77';
        if (method === 'eth_getTransactionCount') return '0x1';
        if (method === 'eth_estimateGas') return '0x100000';
        if (method === 'eth_sendTransaction') return HASH;
        assert.fail(`Unexpected RPC ${method}`);
    } });
    t.mock.method(client, 'connectWallet', async () => FROM);
    t.mock.method(client, 'refresh', async () => {});
    const plan = { commitment: '0x1', secret: 'local-secret', amount: 3333334, zero_path: Array(32).fill('0x0') };
    const { default: runtime } = await import('../services/browserWalletRuntime.js');
    t.mock.method(runtime, 'pendingDeposit', async () => null);
    // The deployment pins and canary caps are checked before any deposit (zkapi-deployment tests).
    const verified = [];
    t.mock.method(runtime, 'verifyDeploymentForDeposit', async args => { verified.push(args); return { ok: true }; });
    t.mock.method(runtime, 'prepareDeposit', async amount => {
        assert.equal(amount, 3333334);
        assert.equal(verified.length, 1, 'the deployment is verified before the note is prepared');
        return plan;
    });
    t.mock.method(runtime, 'refreshPendingDeposit', async () => plan);
    t.mock.method(runtime, 'claimPendingDepositSubmission', async () => ({ operationId: 'native-deposit', plan }));
    t.mock.method(runtime, 'rememberPendingDepositSubmissionMetadata', async () => {});
    t.mock.method(runtime, 'rememberPendingDepositTransaction', async () => {});
    t.mock.method(client, 'confirmBrowserDepositReceipt', async () => ({ amount: plan.amount }));
    t.mock.method(client, 'waitForReceipt', async () => ({ status: '0x1', transactionHash: HASH,
        logs: [{ address: VAULT, topics: [codec.ABI.noteDeposited, '0x1', '0x1'],
            data: `0x${[3333334, 2_000_000_000, 7].map(word).join('')}` }] }));
    const deposited = await client.deposit('0.003333334');
    assert.equal(deposited.amount, 3333334);
    const estimate = calls.find(call => call.method === 'eth_estimateGas').params[0];
    const send = calls.find(call => call.method === 'eth_sendTransaction').params[0];
    assert.equal(BigInt(send.value), 3333334000000000n);
    assert.equal(send.value, estimate.value);
    assert.equal(send.data, codec.encodeDeposit(plan, 3333334n));
    assert.equal(send.to, VAULT);
    assert.equal(calls.filter(call => call.method === 'eth_sendTransaction').length, 1);
});

test('native external recovery matches exact wei while zero-value legacy and withdrawal calls remain strict', () => {
    const tx = { from: FROM, to: VAULT, data: '0xabcd', nonce: '0x1', value: '0x3b9aca00', chainId: '0xaa36a7' };
    const actual = { ...tx, input: tx.data, hash: HASH };
    assert.equal(assertExternalTransaction(actual, tx, HASH, funding.chain_id, 1_000_000_000n).nonce, 1);
    assert.throws(() => assertExternalTransaction(actual, tx, HASH, funding.chain_id), /does not match/);
    assert.throws(() => assertExternalTransaction({ ...actual, value: '0x0' }, tx, HASH, funding.chain_id, 1_000_000_000n));
    assert.throws(() => assertExternalTransaction(actual, { ...tx, value: '0x0' }, HASH, funding.chain_id, 1_000_000_000n));
});

test('native manifest trust pins asset, denomination, feed, freshness and RPC without changing legacy assets', async () => {
    const config = deployedProfile();
    const trusted = { ...config.trusted_deployment, ...funding, rpc_url: funding.demo_rpc_url, billing_token_address: null };
    const manifest = { ...trusted, protocol_version: 2, proof_backend: 'groth16_bn254',
        proof_setup: { circuit_id: trusted.circuit_id, request_proving_key_sha256: trusted.request_proving_key_sha256,
            withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
        privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
    const runtime = new BrowserWalletRuntime();
    runtime.browserConfig = { ...config, trusted_deployment: trusted };
    assert.doesNotThrow(() => runtime.validateManifest(manifest));
    assert.doesNotThrow(() => runtime.validateManifestTrust(manifest));
    for (const change of [{ billing_asset: 'erc20' }, { billing_unit: 'wei' }, { native_asset_wei_per_unit: '1' },
        { native_price_feed_address: FROM }, { native_price_feed_decimals: 18 },
        { native_price_max_age_seconds: 7200 }, { rpc_url: 'https://hostile-rpc.example' }, { billing_token_address: FROM }]) {
        assert.throws(() => runtime.validateManifestTrust({ ...manifest, ...change }));
    }
    configureBrowserSdk({ configUrl: 'https://app.example/zkapi/browser-config.json' });
    const built = runtime.buildClientConfig(manifest, runtime.browserConfig);
    assert.equal(built.credits_per_usd, null);
    assert.equal(built.funding.billing_asset, 'native_eth');
    assert.equal(built.funding.billing_token_symbol, 'ETH');
    assert.equal(built.funding.billing_token_decimals, 9);
    assert.equal(built.funding.demo_billing_token_address, undefined);
});

test('native lease proves a fixed USD tier with its exact feed quote and keeps pending proof unchanged', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: 'native-tier-test' };
    runtime.config = { funding, wallet_core: {}, request_charge_cap: 1000, proving_keys: { request: {} } };
    runtime.runtime = { state: { note_id: 1, current_balance: 2_000_000, current_anchor: '0x1', expiry_ts: 2_000_000_000 } };
    const q = quote();
    runtime.nativeBillingQuote = async () => q;
    runtime.treePath = async () => ({ active_root: '0x1', siblings: [] });
    runtime.commit = async next => { runtime.runtime = next; };
    let proof;
    runtime.worker = { call: async (_operation, inputs) => {
        proof = inputs;
        const request = { client_request_id: inputs.args.client_request_id, payload: inputs.args.payload,
            public_inputs: { request_nullifier: '0x42', solvency_bound: inputs.config.request_charge_cap } };
        return { request, journal: { client_request_id: request.client_request_id, nullifier: '0x42', prepared_request: request },
            state: { ...inputs.state, bound_at_state: inputs.config.request_charge_cap } };
    } };
    const result = await runtime.prepareLeaseRequest(undefined, null, 4.5);
    assert.equal(runtime.runtime.state.bound_at_state, 1_500_000, 'the bound is committed with the journal');
    assert.equal(result.public_inputs.solvency_bound, 1_500_000);
    assert.deepEqual(JSON.parse(proof.args.payload), { mode: 'openrouter_ephemeral_lease', version: 1, billing_quote: q });
    runtime.nativeBillingQuote = async () => assert.fail('Never reprice an unfinished proof');
    assert.equal(await runtime.prepareLeaseRequest(undefined, null, 1), result);
    runtime.runtime.journal = null;
    runtime.runtime.state.current_balance = 1;
    runtime.nativeBillingQuote = async () => q;
    await assert.rejects(runtime.prepareLeaseRequest(undefined, null, 1), error => error.code === 'insufficient_chat_balance');
});

test('checksummed feed pins produce a canonical lowercase quote in the actual prepared lease payload', async t => {
    const feedAddress = '0x694AA1769357215DE4FAC081bf1f309aDC325306';
    const { q } = priceRpc(t, { feedAddress });
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: 'native-checksum-test' };
    runtime.config = { funding: { ...funding, native_price_feed_address: feedAddress },
        wallet_core: {}, request_charge_cap: 1000, proving_keys: { request: {} } };
    runtime.runtime = { state: { note_id: 1, current_balance: 2_000_000, current_anchor: '0x1', expiry_ts: 2_000_000_000 } };
    runtime.remoteJson = async url => {
        assert.equal(url, `${funding.protocol_server_url}/v2/billing/quote`);
        return q;
    };
    runtime.treePath = async () => ({ active_root: '0x1', siblings: [] });
    runtime.commit = async next => { runtime.runtime = next; };
    runtime.worker = { call: async (_operation, input) => {
        const request = { client_request_id: input.args.client_request_id, payload: input.args.payload,
            public_inputs: { request_nullifier: '0x42', solvency_bound: input.config.request_charge_cap } };
        return { request, journal: { client_request_id: request.client_request_id, nullifier: '0x42', prepared_request: request },
            state: { ...input.state, bound_at_state: input.config.request_charge_cap } };
    } };
    const request = await runtime.prepareLeaseRequest(undefined, null, 1);
    const authorized = JSON.parse(request.payload).billing_quote;
    assert.equal(authorized.feed_address, feedAddress.toLowerCase());
    assert.deepEqual(authorized, q);
    assert.equal(runtime.runtime.journal.prepared_request.payload, request.payload);
});

test('native lease verifies USD cap against the frozen quote, including after market price changes', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { funding, openrouter: { inference_base: 'https://openrouter.ai/api/v1', require_oa_key_source: false } };
    const q = quote();
    const lease = { status: 'active', client_request_id: 'request', api_key: 'fixture',
        expires_at: Math.floor(Date.now() / 1000) + 300, spending_limit_usd: 10.000002,
        openrouter_api_base: 'https://openrouter.ai/api/v1', billing_quote: q };
    runtime.ethUsdQuote = quote({ answer: '600000000000' });
    await runtime.verifyLease(lease, 3333334, 'request', undefined, null, q);
    await assert.rejects(runtime.verifyLease({ ...lease, spending_limit_usd: 20 }, 3333334, 'request', undefined, null, q));
    await assert.rejects(runtime.verifyLease({ ...lease, billing_quote: runtime.ethUsdQuote }, 3333334, 'request', undefined, null, q));
    await assert.rejects(runtime.verifyLease(lease, 3333334, 'request'));
});

function expirationHarness({ price = quote({ updated_at: 1, expires_at: 3601 }) } = {}) {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { funding };
    runtime.manifest = { deployment_id: 'native-expired-test' };
    const request = { client_request_id: 'expired-request', payload_hash: '0x43',
        payload: JSON.stringify({ billing_quote: price }),
        public_inputs: { solvency_bound: Number(nativeUnitsForUsd(1, price)), request_nullifier: '0x42' } };
    const note = { note_id: 1, current_balance: 2_000_000 };
    runtime.runtime = { state: note, journal: { nullifier: '0x42', prepared_request: request } };
    runtime.reload = async () => runtime.runtime;
    runtime.commit = async next => { runtime.runtime = next; };
    const confirmed = { status: 'expired_unaccepted', client_request_id: request.client_request_id,
        request_nullifier: request.public_inputs.request_nullifier, payload_hash: request.payload_hash };
    return { runtime, request, note, original: runtime.runtime, confirmed };
}

test('native expired proof needs an authoritative response bound to the exact saved request', async () => {
    const { runtime, request, original, confirmed } = expirationHarness();
    for (const recovery of [{ status: 'not_found', nullifier_status: 'unknown' }, { status: 'reserved' }]) {
        runtime.remoteJson = async () => recovery;
        assert.equal(await runtime.recoverUnacceptedNativeQuote(request), false);
        assert.equal(runtime.runtime, original);
    }
    for (const change of [{ client_request_id: 'other-request' }, { request_nullifier: '0x99' },
        { payload_hash: '0x99' }, { request_nullifier: null }, { payload_hash: null }]) {
        runtime.remoteJson = async () => ({ ...confirmed, ...change });
        await assert.rejects(runtime.recoverUnacceptedNativeQuote(request), /does not match/);
        assert.equal(runtime.runtime, original);
    }
    runtime.remoteJson = async (url, init) => {
        assert.equal(url, `${funding.protocol_server_url}/v2/openrouter/leases/expired-request/expire`);
        assert.equal(init.method, 'POST');
        assert.equal(init.body, JSON.stringify(request));
        return confirmed;
    };
    assert.equal(await runtime.recoverUnacceptedNativeQuote(request), true);
    assert.equal(runtime.runtime.journal, null);
    assert.equal(runtime.runtime.state, original.state);
});

test('startup unknown-nullifier recovery cannot discard based on an ahead-of-server browser clock', async () => {
    const { runtime, request, original } = expirationHarness();
    const requests = [];
    runtime.remoteJson = async (url, init) => {
        requests.push({ url, method: init?.method || 'GET' });
        if (url.endsWith('/leases/expired-request')) throw new BrowserWalletHttpError('Not found', 404, 'not_found');
        if (url.endsWith('/nullifiers/0x42')) return { status: 'not_found', nullifier_status: 'unknown' };
        assert.ok(url.endsWith('/leases/expired-request/expire'));
        assert.equal(init.body, JSON.stringify(request));
        throw new BrowserWalletHttpError('The request may still be accepted.', 409, 'lease_pending');
    };
    assert.equal(await runtime.recoverPendingLocked({ quiet: true }), false);
    assert.equal(runtime.runtime, original);
    assert.equal(requests.length, 3);
    assert.equal(requests.some(({ url }) => url.endsWith('/leases')), false, 'recovery never issues a key');
});

test('server expiry confirmation works when the browser clock is behind and preserves in-flight uncertainty', async () => {
    const { runtime, request, original, confirmed } = expirationHarness({ price: quote() });
    let release;
    runtime.remoteJson = () => new Promise(resolve => { release = resolve; });
    const recovering = runtime.recoverUnacceptedNativeQuote(request);
    assert.equal(runtime.runtime, original);
    release({ status: 'reserved' });
    assert.equal(await recovering, false);
    assert.equal(runtime.runtime, original);
    runtime.remoteJson = async () => confirmed;
    assert.equal(await runtime.recoverUnacceptedNativeQuote(request), true);
    assert.equal(runtime.runtime.journal, null);
});

test('recovery preserves its journal when authoritative expiry is unavailable or the local request changes', async () => {
    const { runtime, request, original, confirmed } = expirationHarness();
    runtime.remoteJson = async () => { throw new Error('Network unavailable'); };
    await assert.rejects(runtime.recoverUnacceptedNativeQuote(request), /Network unavailable/);
    assert.equal(runtime.runtime, original);
    const next = { ...original, journal: { ...original.journal,
        prepared_request: { ...request, client_request_id: 'newer-request' } } };
    runtime.remoteJson = async () => { runtime.runtime = next; return confirmed; };
    assert.equal(await runtime.recoverUnacceptedNativeQuote(request), false);
    assert.equal(runtime.runtime, next);
});

test('a finalized price update cannot reprice a pending proof until exact superseded-unaccepted recovery succeeds', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: 'native-reprice-test' };
    runtime.config = { funding, wallet_core: {}, request_charge_cap: 1000, proving_keys: { request: {} } };
    const note = { note_id: 1, current_balance: 2_000_000, current_anchor: '0x1', expiry_ts: 2_000_000_000 };
    runtime.runtime = { state: note };
    let current = quote();
    let quoteReads = 0;
    runtime.nativeBillingQuote = async () => { quoteReads++; return current; };
    runtime.treePath = async () => ({ active_root: '0x1', siblings: [] });
    runtime.commit = async next => { runtime.runtime = next; };
    let proofs = 0;
    runtime.worker = { call: async (_operation, input) => {
        const request = { client_request_id: `request-${++proofs}`, payload_hash: `0x${proofs}`,
            payload: input.args.payload, public_inputs: { request_nullifier: '0x42', solvency_bound: input.config.request_charge_cap } };
        return { request, journal: { nullifier: '0x42', prepared_request: request },
            state: { ...input.state, bound_at_state: input.config.request_charge_cap } };
    } };
    const original = await runtime.prepareLeaseRequest(undefined, null, 1);
    current = quote({ round_id: '124', answer: '400000000000' });
    assert.equal(await runtime.prepareLeaseRequest(undefined, null, 1), original);
    assert.equal(quoteReads, 1, 'a market move alone cannot replace the durable proof');
    runtime.remoteJson = async () => { throw new BrowserWalletHttpError('Still reserved', 409, 'lease_pending'); };
    assert.equal(await runtime.recoverUnacceptedNativeQuote(original), false);
    assert.equal(runtime.runtime.journal.prepared_request, original);
    runtime.remoteJson = async (_url, init) => {
        assert.equal(init.body, JSON.stringify(original));
        return { status: 'superseded_unaccepted', client_request_id: original.client_request_id,
            request_nullifier: '0x42', payload_hash: original.payload_hash };
    };
    assert.equal(await runtime.recoverUnacceptedNativeQuote(original), true);
    const fresh = await runtime.prepareLeaseRequest(undefined, null, 1);
    assert.equal(quoteReads, 2);
    assert.equal(proofs, 2);
    // C2: the unaccepted request already fixed this state's bound, so the
    // fresh proof carries the same bound at the new quote; the new price
    // only applies from the next state.
    assert.equal(original.public_inputs.solvency_bound, 333_334);
    assert.equal(fresh.public_inputs.solvency_bound, original.public_inputs.solvency_bound);
    assert.deepEqual(JSON.parse(fresh.payload).billing_quote, current);
    assert.deepEqual(runtime.runtime.state, { ...note, bound_at_state: 333_334 });
});

for (const rejection of ['expired', 'superseded']) for (const selectedTier of [1, 4.5]) test(`${rejection} native issuance at selected tier ${selectedTier} attempts once then requests authoritative recovery`, { timeout: 2_000 }, async () => {
    const { runtime, request, note, confirmed } = expirationHarness();
    confirmed.status = `${rejection}_unaccepted`;
    runtime.recoverPendingLocked = async () => {};
    runtime.prepareLeaseRequest = async () => request;
    const requests = [];
    const error = new BrowserWalletHttpError(`The native ETH quote is ${rejection}.`, 409, `native_quote_${rejection}`, { retriable: true });
    runtime.remoteJson = async (url, init) => {
        requests.push(url);
        assert.equal(init.body, JSON.stringify(request));
        if (url.endsWith('/v2/openrouter/leases')) throw error;
        assert.ok(url.endsWith('/v2/openrouter/leases/expired-request/expire'));
        return confirmed;
    };
    await assert.rejects(runtime.issueLease('chat', undefined, null, selectedTier), candidate => candidate === error);
    assert.deepEqual(requests, [`${funding.protocol_server_url}/v2/openrouter/leases`,
        `${funding.protocol_server_url}/v2/openrouter/leases/expired-request/expire`]);
    assert.equal(runtime.runtime.journal, null);
    assert.equal(runtime.runtime.state, note);
});

test('native settlement validates the frozen billing quote before installing a signed response', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.config = { funding, wallet_core: {} };
    const q = quote();
    runtime.runtime = { journal: { prepared_request: { payload: JSON.stringify({ billing_quote: q }) } } };
    let applied = 0;
    runtime.worker = { call: async () => { applied++; return { current_balance: 123 }; } };
    runtime.commit = async next => { runtime.runtime = next; };
    runtime.remoteJson = async () => ({ request_response: { response_payload: JSON.stringify({ billing_quote: { ...q, answer: '9' } }) } });
    await assert.rejects(runtime.installRecoveredResponse('request'), /changed the authorized/);
    assert.equal(applied, 0);
    runtime.remoteJson = async () => ({ request_response: { response_payload: JSON.stringify({ billing_quote: q }) } });
    assert.equal(await runtime.installRecoveredResponse('request'), true);
    assert.equal(applied, 1);
    assert.equal(runtime.runtime.state.current_balance, 123);
    assert.equal(runtime.runtime.journal, null);
});

test('prefunding quote exposes only the exact public native call and never connects or submits', async t => {
    priceRpc(t);
    const { default: runtime } = await import('../services/browserWalletRuntime.js');
    const client = new ZkapiClient();
    client.initialized = true;
    client.browserMode = true;
    client.config = { funding };
    const calls = [];
    client.setWalletProvider({ request: async ({ method, params }) => {
        calls.push(method);
        if (method === 'eth_chainId') return '0xaa36a7';
        assert.equal(method, 'eth_call', 'quoting cannot connect, sign or broadcast');
        assert.equal(params[0].data, `0x${codec.ABI.currentRoot}`);
        return '0x77';
    } });
    const draft = { operationId: 'prefunding-quote', amount: 3333334, commitment: '0x1', secret: 'never-expose-this',
        next_note_id: 2, active_root: '0x77', zero_path: Array(32).fill('0x0') };
    t.mock.method(runtime, 'prepareDepositQuote', async (amount, root) => {
        assert.equal(amount, 3333334);
        assert.equal(root, 0x77n);
        return draft;
    });
    const result = await client.prepareDepositQuote('0.003333334', { from: FROM });
    assert.deepEqual(result, { operationId: draft.operationId, commitment: draft.commitment, amount: '3333334',
        depositWei: '3333334000000000', chainId: funding.chain_id, contractAddress: VAULT,
        transaction: { from: FROM, to: VAULT, data: codec.encodeDeposit(draft, 3333334n), value: `0x${3333334000000000n.toString(16)}` } });
    assert.doesNotMatch(JSON.stringify(result), /never-expose-this|secret|zero_path|active_root/);
    assert.deepEqual(new Set(calls), new Set(['eth_chainId', 'eth_call']));
    assert.ok(Object.isFrozen(result));
    assert.ok(Object.isFrozen(result.transaction));
    for (const from of [undefined, '0x0', `0x${'00'.repeat(20)}`]) {
        await assert.rejects(client.prepareDepositQuote('0.1', { from }), /valid funding address/);
    }
});

function nativeReceiptHarness() {
    const client = new ZkapiClient();
    client.config = { funding };
    const plan = { operationId: 'deposit', next_note_id: 1, commitment: '0x1', amount: 123,
        active_root: '0x77', zero_path: Array(32).fill('0x0') };
    const blockHash = `0x${'55'.repeat(32)}`;
    const receipt = { status: '0x1', transactionHash: HASH, blockHash, blockNumber: '0x123',
        gasUsed: '0x64', effectiveGasPrice: '0x3b9aca00', logs: [{ address: VAULT,
            topics: [codec.ABI.noteDeposited, '0x1', '0x1'], data: `0x${[123, 2_000_000_000, 7].map(word).join('')}` }] };
    const transaction = { hash: HASH, blockHash, blockNumber: '0x123', from: FROM, to: VAULT,
        chainId: '0xaa36a7', value: `0x${123000000000n.toString(16)}`, input: codec.encodeDeposit(plan, 123n) };
    const chain = { id: '0xaa36a7', blockHash };
    client.setWalletProvider({ request: async ({ method, params }) => {
        if (method === 'eth_chainId') return chain.id;
        if (method === 'eth_getTransactionByHash') { assert.equal(params[0], HASH); return transaction; }
        if (method === 'eth_getBlockByNumber') { assert.equal(params[0], receipt.blockNumber); return { hash: chain.blockHash }; }
        assert.fail(`Unexpected RPC ${method}`);
    } });
    return { client, plan, receipt, transaction, chain };
}

test('deposit fee uses actual mined gas and verified funding sender, with canonical block evidence', async () => {
    const { client, plan, receipt } = nativeReceiptHarness();
    assert.deepEqual(await client.readDepositReceiptMetadata(plan, receipt), { transactionHash: HASH,
        fundingAddress: FROM, feeWei: '100000000000', gasUsed: '100', effectiveGasPrice: '1000000000',
        receiptBlockNumber: 0x123, receiptBlockHash: receipt.blockHash });
});

for (const field of ['value', 'to', 'input', 'from', 'chainId', 'hash', 'blockHash', 'blockNumber']) {
    test(`deposit fee does not trust a receipt whose mined transaction has mismatched ${field}`, async () => {
        const { client, plan, receipt, transaction } = nativeReceiptHarness();
        transaction[field] = field === 'from' ? 'missing' : '0x99';
        assert.equal(await client.readDepositReceiptMetadata(plan, receipt), null);
    });
}

test('reverted, unavailable, reorganized, cross-chain or wrong-note receipt fees remain unavailable', async () => {
    for (const alter of [
        ({ receipt }) => { receipt.status = '0x0'; },
        ({ receipt }) => { delete receipt.gasUsed; },
        ({ receipt }) => { delete receipt.effectiveGasPrice; },
        ({ receipt }) => { receipt.effectiveGasPrice = '-1'; },
        ({ chain }) => { chain.blockHash = `0x${'66'.repeat(32)}`; },
        ({ chain }) => { chain.id = '0x1'; },
        ({ plan }) => { plan.commitment = '0x2'; },
        ({ plan }) => { plan.amount = 456; }
    ]) {
        const fixture = nativeReceiptHarness();
        alter(fixture);
        assert.equal(await fixture.client.readDepositReceiptMetadata(fixture.plan, fixture.receipt), null);
    }
});

test('native deposit recovery saves actual mined fee before the pending journal is cleared', async t => {
    const { default: runtime } = await import('../services/browserWalletRuntime.js');
    const { client, plan, receipt } = nativeReceiptHarness();
    client.browserMode = true;
    plan.transactionHash = HASH;
    t.mock.method(runtime, 'pendingDeposit', async () => plan);
    t.mock.method(runtime, 'treePath', async () => ({}));
    t.mock.method(client, 'readBrowserNote', async () => ({ status: 1, amount: 123n, commitment: '0x1', expiryTs: 2_000_000_000 }));
    t.mock.method(client, 'refresh', async () => {});
    const originalRequest = client.ethereum.request;
    client.ethereum.request = async request => request.method === 'eth_getTransactionReceipt' ? receipt : originalRequest(request);
    let saved;
    t.mock.method(runtime, 'confirmDeposit', async args => { saved = args; });
    const result = await client.recoverBrowserDeposit();
    assert.equal(result.status, 'confirmed');
    assert.equal(result.receipt, receipt);
    assert.equal(result.feeWei, '100000000000');
    assert.equal(saved.transactionHash, HASH);
    assert.equal(saved.receiptMetadata.feeWei, result.feeWei);
    assert.equal(saved.receiptMetadata.fundingAddress, FROM);
});

test('provider fee changes rejected before signing release the SDK claim for a safe new quote', async t => {
    priceRpc(t);
    const { default: runtime } = await import('../services/browserWalletRuntime.js');
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = { funding };
    const plan = { operationId: 'quote-operation', phase: 'prepared', next_note_id: 1,
        commitment: '0x1', secret: 'local-only', amount: 3333334, active_root: '0x77', zero_path: Array(32).fill('0x0') };
    const submission = { operationId: plan.operationId, submissionId: 'claim' };
    t.mock.method(client, 'connectWallet', async () => FROM);
    t.mock.method(client, 'refresh', async () => {});
    t.mock.method(runtime, 'pendingDeposit', async () => null);
    t.mock.method(runtime, 'verifyDeploymentForDeposit', async () => ({ ok: true }));
    t.mock.method(runtime, 'prepareDeposit', async (amount, options) => {
        assert.equal(amount, plan.amount);
        assert.equal(options.preparedOperationId, plan.operationId);
        return plan;
    });
    t.mock.method(runtime, 'refreshPendingDeposit', async (_amount, _root, options) => {
        assert.equal(options.expectedOperationId, plan.operationId);
        return plan;
    });
    t.mock.method(runtime, 'claimPendingDepositSubmission', async expected => {
        assert.equal(expected, plan.operationId);
        return submission;
    });
    t.mock.method(runtime, 'rememberPendingDepositSubmissionMetadata', async () => {});
    t.mock.method(runtime, 'rememberPendingDepositTransaction', async () => assert.fail('No transaction was signed'));
    t.mock.method(runtime, 'markPendingDepositAmbiguous', async () => assert.fail('A known pre-sign rejection is not ambiguous'));
    let released = 0;
    t.mock.method(runtime, 'markPendingDepositRetryable', async (hash, claim) => {
        assert.equal(hash, null);
        assert.equal(claim, submission);
        released += 1;
    });
    client.setWalletProvider({ request: async ({ method }) => {
        if (method === 'eth_chainId') return '0xaa36a7';
        if (method === 'eth_getBalance') return '0xde0b6b3a7640000';
        if (method === 'eth_call') return '0x77';
        if (method === 'eth_estimateGas') return '0x100000';
        if (method === 'eth_getTransactionCount') return '0x0';
        assert.equal(method, 'eth_sendTransaction');
        throw Object.assign(new Error('Network fees changed. Refresh the quote before continuing.'),
            { code: 4100, addressCode: 'address_fee_quote_changed', broadcastPossible: false });
    } });
    await assert.rejects(client.deposit('0.003333334', () => {}, { preparedOperationId: plan.operationId }),
        error => error.code === 4100 && error.broadcastPossible === false && error.transactionStage === 'send');
    assert.equal(released, 1);
});

test('preparing an address retry only checks recovery and authorizes exact fee review without signing', async t => {
    const { default: runtime } = await import('../services/browserWalletRuntime.js');
    const client = new ZkapiClient();
    client.browserMode = true;
    client.config = { funding };
    client.setWalletProvider({ request: async () => assert.fail('The retry preparation must not open the signer') });
    t.mock.method(client, 'recoverBrowserDeposit', async () => ({ status: 'ambiguous' }));
    t.mock.method(runtime, 'pendingDeposit', async () => ({ phase: 'ambiguous' }));
    let authorized = 0;
    t.mock.method(runtime, 'authorizePendingDepositRetry', async options => {
        assert.deepEqual(options, { forFundingQuote: true });
        authorized += 1;
        return { phase: 'retry_exact', operationId: 'saved-operation' };
    });
    t.mock.method(client, 'refresh', async () => {});
    assert.deepEqual(await client.prepareDepositRetry(), { status: 'retry_exact', operationId: 'saved-operation' });
    assert.equal(authorized, 1);
    t.mock.method(client, 'recoverBrowserDeposit', async () => ({ status: 'confirmed', feeWei: '123' }));
    assert.deepEqual(await client.prepareDepositRetry(), { status: 'confirmed', feeWei: '123' });
    assert.equal(authorized, 1);
});

test('token funding never reaches a wallet connection or note preparation', async () => {
    const client = new ZkapiClient();
    client.config = { funding: { ...funding, billing_asset: 'erc20' } };
    client.connectWallet = async () => assert.fail('unsupported funding must fail before wallet connection');
    await assert.rejects(client.performDeposit('1'), /only native ETH deployments are supported/);
    assert.throws(() => nativeDepositValue(1n, client.config.funding), /only native ETH deployments are supported/);
});
