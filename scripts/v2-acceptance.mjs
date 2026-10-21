#!/usr/bin/env node
// Entirely local end-to-end acceptance of circuit zkapi-v2-concession-v1
// (vault revision 3), the §10.7 Phase B drill scenarios that run on a local
// chain, and a gas measurement (docs/v2-acceptance.md).
//
// Real: the contracts (deployed by demo/contracts/script/Deploy.s.sol and
// finalized by scripts/expected-codehashes.mjs), the dev setup's Groth16
// proofs, `zkapi serverd` (a drill build with --adversary modes),
// zkapi-indexerd, zkapi-challenged, the challenge signer sidecar
// (docker/aws/signer), the browser SDK (sdk/, its WebAssembly in Node), the
// clientd companion (zkapi-walletd) and the in-memory wallet driver
// (examples/v2_acceptance_wallet.rs, the browser wallet core natively).
// Mocks: the OpenRouter-style provider and the ETH/USD price feed, both on
// loopback. Anvil runs with Sepolia's chain ID, because the signer signs only
// for 1 and 11155111; nothing leaves loopback.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import fs from 'node:fs/promises';
import { createWriteStream } from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import readline from 'node:readline';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { decodeFailedOp, encodeHandleOps, packUserOperation, startMiniBundler, userOperationHash, vaultCallOf } from './acceptance/mini-bundler.mjs';
import { CANONICAL_ENTRY_POINT, ENTRY_POINT_V070_CODEHASH, SENDER_CREATOR, SENDER_CREATOR_V070_CODEHASH, accountCreationCode, hexToBytes,
    keccak256 } from './expected-codehashes.mjs';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SETUP_DIR = path.join(ROOT, 'protocol/setup/v2-concession-dev');
// Anvil with Sepolia's chain ID: the signer sidecar refuses any other chain
// but mainnet's. Deploy.s.sol treats it as off a local chain, so the drill
// vault's dev setup needs ALLOW_DEV_SETUP=1 there, as on Sepolia.
export const CHAIN_ID = 11155111;
const GWEI = 1_000_000_000n;
const DEPOSIT = 1_000_000; // gwei: 0.001 ETH per note
const CAP = 50_000; // request_charge_cap: every request's solvency bound
const MOCK_USAGE_MICRO_USD = 1_000;
const MOCK_PRICE = 250_000_000_000n; // $2,500 / ETH, eight decimal places.
// One accepted inference ($0.001 at $2,500) costs ceil(1e3 µUSD → gwei) = 400.
export const INFERENCE_CHARGE = Number((BigInt(MOCK_USAGE_MICRO_USD) * GWEI * 100_000_000n + MOCK_PRICE * 1_000_000n - 1n)
    / (MOCK_PRICE * 1_000_000n));
// The SDK agent's spending limit ($1, its default) at the mock price: the
// solvency bound (C2) of every SDK request, 400,000 gwei.
export const SDK_REQUEST_BOUND = Number(1_000_000n * GWEI * 100_000_000n / (MOCK_PRICE * 1_000_000n));
const MODEL = 'local/mock-model';
const PROMPT = 'Reply with the word OK.';
// Drill timing, scaled down so a challenge period is skipped with
// evm_increaseTime. Both daemons' startup checks must hold (drillTiming).
export const TIMING = Object.freeze({
    challengePeriod: 3_600,
    maxPauseDuration: 7_200,
    noteTtl: 30 * 86_400,
    leaseTtl: 60,
    settlementGrace: 1,
    settlementDeadline: 901,
    settlementPoll: 1,
    raiseLead: 1_200,
});
// Skipping a challenge period moves only block time; the daemons' and
// clients' clocks stay on the wall clock. The chain starts this far behind
// it, so that block time and the wall clock meet when the bounded pause ends
// (two skipped periods), before the missed-defeat drill: the challenger
// counts a miss only for server evidence written (wall clock) before the
// escape's deadline (block time). From there block time runs at most one
// challenge period ahead, well within the 3 h validity of every exit proof
// (which clients bound by the wall clock); an SDK judging a deadline then
// gets its device clock moved to block time.
const CHAIN_LAG_SECONDS = 2 * TIMING.challengePeriod;
const MAX_CHAIN_LEAD_SECONDS = 2 * TIMING.challengePeriod;
const INDEXER_CONFIRMATIONS = 2;
// Challenger fee policy: the daemon proposes both EIP-1559 fees within these
// caps; the signer enforces its own copy of them.
const CHALLENGE_MAX_FEE_PER_GAS = 100n * GWEI;
const CHALLENGE_MAX_PRIORITY_FEE_PER_GAS = 10n * GWEI;
const CHALLENGE_PRIORITY_FEE_PER_GAS = 2n * GWEI;
// Anvil's mnemonic: public test keys, funded only on a disposable chain.
const MNEMONIC = 'test test test test test test test test test test test junk';
// Every role has its own account: the deployer/owner, the challenger, the
// treasury, the clients, destinations, a third party and, for gasless
// withdrawals, the mini bundler's sender, the gasless SDK owner and a griefer.
const ANVIL_ACCOUNTS = 13;
// The paymaster's and the factory's EntryPoint stakes and the paymaster's
// initial float (Deploy.s.sol requires them explicitly off local chain IDs).
const PAYMASTER_STAKE_WEI = 100_000_000_000_000_000n;
const PAYMASTER_DEPOSIT_WEI = 1_000_000_000_000_000_000n;
const ANVIL_KEYS = Object.freeze([
    '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80',
    '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d',
]);
const delay = ms => new Promise(resolve => setTimeout(resolve, ms));
const json = value => JSON.stringify(value, (_, v) => typeof v === 'bigint' ? v.toString() : v, 2);
const hex = value => `0x${BigInt(value).toString(16)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const felt = value => `0x${word(value)}`;
// Explicit agents bypass Node's optional global environment-proxy support.
const localAgent = new http.Agent({ keepAlive: false, proxyEnv: {} });

function loopback(url) {
    const parsed = new URL(url);
    assert.equal(parsed.protocol, 'http:', 'this test permits only loopback HTTP');
    assert.equal(parsed.hostname, '127.0.0.1', 'this test never calls public networks');
    assert.equal(parsed.username + parsed.password, '');
    return parsed;
}

async function body(req) {
    const chunks = [];
    let bytes = 0;
    for await (const chunk of req) {
        bytes += chunk.length;
        assert.ok(bytes < 4_194_304, 'oversized local HTTP request');
        chunks.push(chunk);
    }
    return JSON.parse(Buffer.concat(chunks).toString() || '{}');
}

function respond(res, status, value) {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(value));
}

export async function localJSON(url, { method = 'GET', value, headers = {}, timeoutMs = 60_000 } = {}) {
    const parsed = loopback(url);
    return new Promise((resolve, reject) => {
        const outgoing = http.request(parsed, { method, agent: localAgent,
            headers: { 'content-type': 'application/json', ...headers } }, incoming => {
            const chunks = [];
            incoming.on('data', chunk => chunks.push(chunk));
            incoming.on('error', reject);
            incoming.on('end', () => {
                const text = Buffer.concat(chunks).toString();
                try { resolve({ status: incoming.statusCode, headers: incoming.headers, value: text ? JSON.parse(text) : null }); }
                catch { resolve({ status: incoming.statusCode, headers: incoming.headers, value: null, text }); }
            });
        });
        outgoing.setTimeout(timeoutMs, () => outgoing.destroy(new Error('Local HTTP request timed out')));
        outgoing.on('error', reject);
        outgoing.end(value === undefined ? undefined : JSON.stringify(value));
    });
}

// Forwards one JSON-RPC call and relays an upstream error unchanged, so the
// caller sees the node's own {code, message, data} (for example revert data).
export async function proxyJsonRpc(url, call) {
    const upstream = await localJSON(url, { method: 'POST',
        value: { jsonrpc: '2.0', id: call.id, method: call.method, params: call.params ?? [] } });
    assert.equal(upstream.status, 200, `upstream JSON-RPC answered HTTP ${upstream.status}`);
    if (upstream.value.error) {
        const { code, message, data } = upstream.value.error;
        return { jsonrpc: '2.0', id: call.id, error: data === undefined ? { code, message } : { code, message, data } };
    }
    return { jsonrpc: '2.0', id: call.id, result: upstream.value.result };
}

export const CHALLENGE_TRANSACTION_FIELDS = Object.freeze(
    ['data', 'from', 'gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce', 'to']);

// The challenger proposes both EIP-1559 fees within its caps and nothing else:
// no gasPrice, type, value, chainId or access list.
export function challengeFees(tx, maxFeePerGasCap) {
    assert.deepEqual(Object.keys(tx).sort(), CHALLENGE_TRANSACTION_FIELDS,
        'a challenge transaction carries exactly the EIP-1559 send fields');
    for (const field of ['gas', 'maxFeePerGas', 'maxPriorityFeePerGas', 'nonce']) {
        assert.match(tx[field], /^0x(0|[1-9a-f][0-9a-f]*)$/, `${field} must be a canonical hex quantity`);
    }
    const maxFeePerGas = BigInt(tx.maxFeePerGas);
    const maxPriorityFeePerGas = BigInt(tx.maxPriorityFeePerGas);
    assert.ok(maxPriorityFeePerGas > 0n && maxPriorityFeePerGas <= maxFeePerGas && maxFeePerGas <= maxFeePerGasCap,
        'challenge fees must satisfy 0 < maxPriorityFeePerGas <= maxFeePerGas <= the cap');
    return { maxFeePerGas, maxPriorityFeePerGas };
}

// The startup checks of serverd (settlement within half the challenge
// period) and zkapi-challenged (G5 and the raise timing), for TIMING.
export function drillTiming(timing = TIMING) {
    const window = timing.leaseTtl + timing.settlementGrace + timing.settlementDeadline;
    const poll = Math.max(1, timing.settlementPoll);
    const checks = {
        settlement_window_seconds: window,
        deadline_leaves_retries: timing.settlementDeadline >= timing.settlementGrace + 900,
        server_settlement: window + 2 * poll + 600 <= Math.floor(timing.challengePeriod / 2),
        challenger_g5: window + 2 * poll + 600 <= Math.floor(timing.challengePeriod / 2),
        challenger_raise: window + timing.raiseLead + 4 * poll + 1_200 <= timing.challengePeriod,
        bounded_pause: timing.maxPauseDuration >= 2 * timing.challengePeriod,
    };
    return { ...checks, ok: Object.entries(checks).every(([key, value]) => key === 'settlement_window_seconds' || value) };
}

// The bundler URL a profile may publish: the rule every client applies to
// it, so no client refuses a URL another accepts. zkapi-clientd's
// ValidateBundlerURL takes https, or plain http to a loopback host, with no
// credentials, query or fragment (and, finding any of these, refuses the
// whole gasless object); the SDK's bundlerUrl() takes https, or http to
// localhost or 127.0.0.1, with no credentials. A URL must pass both: a
// hosted bundler keyed in its query (`?apikey=...`) would disable every clientd
// user's gasless path.
export const BUNDLER_URL_RULE = 'bundler_url is null or an https URL (or http to localhost or 127.0.0.1) '
    + 'without credentials, query or fragment';
export function isProfileBundlerUrl(value) {
    if (typeof value !== 'string' || /[\s?#\\]/.test(value)) return false;
    const authority = /^(https?):\/\/([^/]+)(\/.*)?$/.exec(value);
    if (!authority || authority[2].includes('@')) return false;
    let url;
    try {
        url = new URL(value);
    } catch {
        return false;
    }
    if (url.username || url.password || url.search || url.hash) return false;
    return url.protocol === 'https:' || (url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname));
}

// The `gasless` object of a profile (gasless withdrawals over ERC-4337,
// design §4.3): the pins of the EntryPoint, its SenderCreator, the paymaster,
// the transit-account factory and the account logic, the 74-byte creation
// code clients derive transit accounts from, the operator's bundler (null
// when none is published), the paymaster's pinned gas policy with the
// defaults clients sign (each inside its [floor, cap], as
// GaslessTestBase._gas derives them and transit-vectors.json pins them), the
// deployment-time policy and fee ceilings (clients read the live ones) and
// the uneconomic rule. Null for a deployment without the paymaster.
export function gaslessProfile(finalized, bundlerUrl = null) {
    if (finalized.withdrawalPaymaster == null) return null;
    assert.ok(bundlerUrl === null || isProfileBundlerUrl(bundlerUrl), BUNDLER_URL_RULE);
    const gp = finalized.paymasterGasPolicy;
    const policy = finalized.paymasterPolicy;
    const ceilings = finalized.paymasterFeeCeilings;
    assert.ok(gp && policy && ceilings, 'a paymaster manifest carries paymasterGasPolicy, paymasterPolicy and paymasterFeeCeilings');
    const gas = (value, name) => {
        assert.ok(Number.isSafeInteger(value) && value >= 0, `paymasterGasPolicy.${name} is a gas figure`);
        return value;
    };
    const wei = (value, name) => {
        assert.match(String(value), /^(0|[1-9][0-9]*)$/, `${name} is a wei amount`);
        return String(value);
    };
    const within = (value, floor, cap, name) => {
        assert.ok(floor <= value && value <= cap, `${name} default ${value} is outside [${floor}, ${cap}]`);
        return value;
    };
    const floors = [0, 1, 2, 3].map(k => gas(gp.callFloor?.[k], `callFloor[${k}]`));
    const caps = [0, 1, 2, 3].map(k => gas(gp.callCap?.[k], `callCap[${k}]`));
    const scalar = name => gas(gp[name], name);
    // Every pin is checked by shape before it is published: finalize treats
    // some of these manifest fields as optional, and a missing one must fail
    // here by name, not reach a profile as the string "undefined".
    const pinned = (name, pattern, what) => {
        const value = finalized[name];
        assert.ok(typeof value === 'string' && pattern.test(value), `${name} is not ${what}`);
        return value.toLowerCase();
    };
    const addr = name => pinned(name, /^0x[0-9a-fA-F]{40}$/, 'an address');
    const hash = name => pinned(name, /^0x[0-9a-fA-F]{64}$/, 'a keccak256');
    const implementation = addr('withdrawalAccountImplementation');
    const creation = pinned('accountCreationCode', /^0x[0-9a-fA-F]{148}$/, 'the 74-byte creation code');
    assert.equal(creation, accountCreationCode(implementation), 'accountCreationCode is not the factory\'s creation code for the account logic');
    assert.equal(hash('accountCreationCodeKeccak256'), keccak256(hexToBytes(creation)), 'accountCreationCodeKeccak256 is not keccak256 of the creation code');
    return {
        entry_point_address: addr('entryPoint'),
        entry_point_runtime_codehash: hash('entryPointRuntimeCodehash'),
        sender_creator_address: addr('senderCreator'),
        sender_creator_runtime_codehash: hash('senderCreatorRuntimeCodehash'),
        withdrawal_paymaster_address: addr('withdrawalPaymaster'),
        withdrawal_paymaster_runtime_codehash: hash('paymasterRuntimeCodehash'),
        withdrawal_account_factory_address: addr('withdrawalAccountFactory'),
        withdrawal_account_factory_runtime_codehash: hash('factoryRuntimeCodehash'),
        withdrawal_account_implementation_address: implementation,
        withdrawal_account_implementation_runtime_codehash: hash('accountImplementationRuntimeCodehash'),
        account_creation_code: creation,
        account_creation_code_keccak256: hash('accountCreationCodeKeccak256'),
        bundler_url: bundlerUrl,
        gas_policy: {
            call_floor: floors,
            call_cap: caps,
            call_default: floors.map((floor, k) => within(floor + Math.floor((caps[k] - floor) / 4), floor, caps[k], `call[${k}]`)),
            postop_floor: scalar('postOpFloor'),
            postop_cap: scalar('postOpCap'),
            postop_default: within(scalar('postOpFloor') + 20_000, scalar('postOpFloor'), scalar('postOpCap'), 'postop'),
            verification_floor: scalar('verificationFloor'),
            verification_floor_init: scalar('verificationFloorInit'),
            verification_cap: scalar('verificationCap'),
            verification_default: within(scalar('verificationFloor') + 20_000, scalar('verificationFloor'), scalar('verificationCap'), 'verification'),
            verification_default_init: within(scalar('verificationFloorInit') + 40_000, scalar('verificationFloorInit'), scalar('verificationCap'),
                'verification_init'),
            pvg_floor: scalar('pvgFloor'),
            pvg_cap: scalar('pvgCap'),
            pm_verification_floor: scalar('pmVerificationFloor'),
            pm_verification_cap: scalar('pmVerificationCap'),
            pm_verification_default: within(scalar('pmVerificationFloor') + 30_000, scalar('pmVerificationFloor'), scalar('pmVerificationCap'),
                'pm_verification'),
            postop_base_gas: scalar('postOpBaseGas'),
            postop_escape_gas: scalar('postOpEscapeGas'),
            postop_finalize_extra_gas: scalar('postOpFinalizeExtraGas'),
            postop_escape_forward_gas: scalar('postOpEscapeForwardGas'),
            eoa_push_gas: scalar('eoaPushGas'),
            new_account_gas: scalar('newAccountGas'),
            payout_push_gas: scalar('payoutPushGas'),
            credit_gas: scalar('creditGas'),
            account_call_overhead_gas: scalar('accountCallOverheadGas'),
            account_call_overhead_escape_gas: scalar('accountCallOverheadEscapeGas'),
            margin_gas: scalar('marginGas'),
            finalize_reserve_gas: scalar('finalizeReserveGas'),
            max_attempts: scalar('maxAttempts'),
        },
        policy: {
            max_sponsored_cost_wei: wei(policy.maxSponsoredCostWei, 'paymasterPolicy.maxSponsoredCostWei'),
            flat_fee_wei: wei(policy.flatFeeWei, 'paymasterPolicy.flatFeeWei'),
            min_escape_net_wei: wei(policy.minEscapeNetWei, 'paymasterPolicy.minEscapeNetWei'),
            escapes_enabled: policy.escapesEnabled === true,
        },
        fee_ceilings: {
            max_fee_wei: wei(ceilings.maxFeeWei, 'paymasterFeeCeilings.maxFeeWei'),
            priority_fee_wei: wei(ceilings.priorityFeeWei, 'paymasterFeeCeilings.priorityFeeWei'),
        },
        uneconomic_fraction_percent: 25,
    };
}

// The deployment profile (§10.3 `trusted_deployment`) of a finalized
// Deploy.s.sol manifest, as serverd, zkapi-challenged, the SDK and the
// companion read it. Only a finalized manifest is a deployment. The `gasless`
// object (services.bundlerUrl names the operator's bundler) is null for a
// deployment made with GASLESS=0; serverd, the indexer and the challenger
// ignore it.
export function trustedDeployment(finalized, services) {
    assert.equal(finalized.deploymentStatus, 'deployed', 'profiles come only from a finalized manifest');
    assert.ok(Number.isSafeInteger(finalized.deployBlock) && finalized.deployBlock > 0, 'finalized manifests carry deployBlock');
    assert.equal(finalized.vaultRevision, 3);
    assert.equal(finalized.concessionEscapeVersion, 1);
    const key = (x, y) => ({ x: felt(x), y: felt(y) });
    return {
        deployment_status: 'deployed',
        deployment_id: services.deploymentId,
        chain_id: finalized.chainId,
        contract_address: finalized.vault.toLowerCase(),
        deploy_block: finalized.deployBlock,
        billing_token_address: null,
        protocol_server_url: services.protocolServerUrl,
        indexer_url: services.indexerUrl,
        request_charge_cap: finalized.requestChargeCap,
        state_signing_key: key(finalized.stateSigningKeyX, finalized.stateSigningKeyY),
        clearance_signing_key: key(finalized.clearanceSigningKeyX, finalized.clearanceSigningKeyY),
        rpc_url: services.rpcUrl,
        billing_asset: finalized.billing_asset,
        billing_unit: finalized.billing_unit,
        native_asset_wei_per_unit: String(finalized.nativeAssetWeiPerUnit),
        native_price_feed_address: services.priceFeed,
        native_price_feed_decimals: 8,
        native_price_max_age_seconds: 4_500,
        circuit_id: finalized.circuitId,
        setup_id: finalized.setupId,
        request_proving_key_sha256: services.keyHashes.requestPk,
        withdrawal_proving_key_sha256: services.keyHashes.withdrawalPk,
        request_verifying_key_sha256: services.keyHashes.requestVk,
        request_vk_keccak256: finalized.requestVkKeccak256,
        withdrawal_vk_keccak256: finalized.withdrawalVkKeccak256,
        vault_runtime_codehash: finalized.vaultRuntimeCodehash,
        proof_adapter_address: finalized.proofAdapter.toLowerCase(),
        adapter_runtime_codehash: finalized.adapterRuntimeCodehash,
        poseidon_library_address: finalized.poseidonLibrary.toLowerCase(),
        poseidon_runtime_codehash: finalized.poseidonRuntimeCodehash,
        challenge_period: finalized.challengePeriod,
        note_ttl: finalized.noteTtl,
        max_pause_duration: finalized.maxPauseDuration,
        settlement_window_seconds: services.settlementWindowSeconds,
        vault_revision: 3,
        exit_concession: 1,
        clearance_ownership_proof: 'required',
        allow_dev_setup: finalized.allowDevSetup,
        canary: null,
        // Never contacted: the drill server issues direct provider keys,
        // not OA-verifier-backed ones, but the profile pins a verifier origin.
        verifier_url: services.verifierUrl,
        openrouter_inference_base: services.inferenceBase,
        gasless: gaslessProfile(finalized, services.bundlerUrl ?? null),
    };
}

// The forward proxy a packaged companion must use (OA_ZKAPI_BRIDGE_TOKEN set):
// only requests carrying the proxy's own basic credentials pass.
export function proxyAuthorized(header, user, password) {
    if (typeof header !== 'string' || !header.startsWith('Basic ')) return false;
    const expected = Buffer.from(`${user}:${password}`).toString('base64');
    const actual = header.slice(6).trim();
    return actual.length === expected.length && Buffer.compare(Buffer.from(actual), Buffer.from(expected)) === 0;
}

// Exported so the accounting mock itself can be tested without starting the chain.
export function mockProvider(managementKey = 'local-only-management-key') {
    const keys = new Map();
    const events = [];
    let pendingCreateFailures = 0;
    const handler = async (req, res) => {
        try {
            const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
            if (pathname === '/v1/chat/completions' && req.method === 'POST') {
                const key = [...keys.values()].find(k => req.headers.authorization === `Bearer ${k.key}`);
                if (!key || key.disabled || key.deleted || Date.parse(key.expires_at) <= Date.now()) {
                    return respond(res, 401, { error: 'invalid or retired local runtime key' });
                }
                const request = await body(req);
                if (request.model !== MODEL || request.stream === true
                    || !Array.isArray(request.messages) || request.messages.length !== 1 || request.messages[0].role !== 'user'
                    || request.messages[0].content !== PROMPT) {
                    return respond(res, 400, { error: 'unexpected acceptance-test inference request' });
                }
                if (key.usage_micro_usd + MOCK_USAGE_MICRO_USD > Math.floor(key.limit * 1_000_000)) {
                    return respond(res, 402, { error: 'local runtime key spending limit reached' });
                }
                key.usage_micro_usd += MOCK_USAGE_MICRO_USD;
                key.calls += 1;
                events.push({ type: 'inference', hash: key.hash, usage_micro_usd: key.usage_micro_usd });
                return respond(res, 200, { id: `local-${key.calls}`, object: 'chat.completion', model: MODEL,
                    choices: [{ index: 0, message: { role: 'assistant', content: 'OK' }, finish_reason: 'stop' }],
                    usage: { prompt_tokens: 6, completion_tokens: 1, total_tokens: 7, cost: MOCK_USAGE_MICRO_USD / 1_000_000 } });
            }
            if (req.headers.authorization !== `Bearer ${managementKey}`) {
                return respond(res, 401, { error: 'local management authentication required' });
            }
            if (pathname === '/v1/keys' && req.method === 'POST') {
                const value = await body(req);
                assert.ok(value.limit > 0 && value.limit <= 1, 'bounded local key limit required');
                assert.equal(value.include_byok_in_limit, true);
                assert.ok(Date.parse(value.expires_at) > Date.now());
                if (pendingCreateFailures > 0) {
                    pendingCreateFailures--;
                    events.push({ type: 'create_failed', name: value.name });
                    return respond(res, 503, { error: 'injected local key creation failure' });
                }
                const hash = randomUUID();
                const key = { ...value, hash, key: `local-runtime-${randomUUID()}`, disabled: false,
                    deleted: false, usage_micro_usd: 0, calls: 0 };
                keys.set(hash, key);
                events.push({ type: 'issued', hash, limit_usd: key.limit });
                return respond(res, 200, { key: key.key, data: { ...value, hash } });
            }
            const match = /^\/v1\/keys\/([0-9a-f-]+)$/.exec(pathname);
            const key = match && keys.get(match[1]);
            if (!key || key.deleted) return respond(res, 404, { error: 'unknown local key' });
            if (req.method === 'PATCH') {
                assert.deepEqual(await body(req), { disabled: true });
                key.disabled = true;
                events.push({ type: 'disabled', hash: key.hash });
            } else if (req.method === 'DELETE') {
                assert.equal(key.disabled, true, 'production settlement must disable before deleting');
                key.deleted = true;
                events.push({ type: 'deleted', hash: key.hash });
                return respond(res, 200, { deleted: true });
            } else if (req.method === 'GET') {
                events.push({ type: 'usage_read', hash: key.hash, usage_micro_usd: key.usage_micro_usd, disabled: key.disabled });
            } else {
                return respond(res, 405, { error: 'unsupported local mock operation' });
            }
            return respond(res, 200, { data: { hash: key.hash, usage: key.usage_micro_usd / 1_000_000,
                byok_usage: 0, disabled: key.disabled } });
        } catch (error) {
            respond(res, 400, { error: error.message });
        }
    };
    return { handler, keys, events, failNextCreate: () => { pendingCreateFailures++; } };
}

// The OA org (station-issued keys) and its verifier, for the clientd
// companion, which accepts only OA org keys: the org mints each key at the
// provider mock and reports its usage once the key has expired (an OA key is
// never revoked early), and the verifier binds the key it is shown.
export function mockOaOrg(provider, options) {
    const issued = new Map();
    const signature = () => randomBytes(64).toString('hex');
    const now = () => Math.floor(Date.now() / 1000);
    const org = async (req, res) => {
        const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
        if (req.headers.authorization !== `Bearer ${options.sharedSecret}`) return respond(res, 401, { detail: 'unauthorized' });
        const value = await body(req);
        if (pathname === '/api/zkapi/request_key') {
            const expiresAt = now() + value.duration_minutes * 60;
            const hash = randomUUID();
            const key = { name: value.client_request_id, limit: value.credit_limit, include_byok_in_limit: true,
                expires_at: new Date(expiresAt * 1000).toISOString(), hash, key: `local-oa-${randomUUID()}`, disabled: false,
                deleted: false, usage_micro_usd: 0, calls: 0 };
            provider.keys.set(hash, key);
            provider.events.push({ type: 'issued', hash, limit_usd: key.limit, source: 'oa_org' });
            issued.set(hash, { expiresAt, limitCredits: value.credit_limit_credits });
            return respond(res, 200, { source: 'oa_org', replayed: false, key: key.key, key_hash: hash, credit_limit: value.credit_limit,
                duration_minutes: value.duration_minutes, expires_at_unix: expiresAt, station_id: 'local-oa-station',
                station_recently_attested: true, station_signature: signature(), org_signature: signature(),
                verifier_url: options.verifierUrl, openrouter_api_base: options.inferenceBase });
        }
        if (pathname === '/api/zkapi/key_usage') {
            const lease = issued.get(value.key_hash);
            const key = provider.keys.get(value.key_hash);
            if (!lease || !key) return respond(res, 404, { detail: 'unknown key' });
            const common = { source: 'oa_org', version: 1, client_request_id: value.client_request_id, key_hash: value.key_hash,
                station_request_id: createHash('sha256').update(value.key_hash).digest('hex') };
            if (now() < lease.expiresAt) return respond(res, 200, { ...common, status: 'pending', retry_after_seconds: 1 });
            provider.events.push({ type: 'usage_read', hash: key.hash, usage_micro_usd: key.usage_micro_usd, source: 'oa_org' });
            return respond(res, 200, { ...common, status: 'finalized', usage_credits: key.usage_micro_usd,
                credit_limit_credits: value.credit_limit_credits, expires_at_unix: lease.expiresAt, closed_at_unix: lease.expiresAt,
                finalized_at_unix: now(), station_id: 'local-oa-station', station_signature: signature(), org_signature: signature() });
        }
        respond(res, 404, { detail: 'not found' });
    };
    const verifier = async (req, res) => {
        const value = await body(req);
        const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
        if (pathname !== '/submit_key' || !value.api_key) return respond(res, 404, { detail: 'not found' });
        return respond(res, 200, { status: 'verified', station_id: value.station_id,
            key_hash: createHash('sha256').update(value.api_key).digest('hex') });
    };
    return { org, verifier, issued };
}

// Collects every receipt's gas by operation (gas.json).
export function gasLedger() {
    const entries = [];
    return {
        entries,
        record(operation, receipt, extra = {}) {
            assert.ok(receipt?.gasUsed, `no receipt for ${operation}`);
            entries.push({ operation, gas_used: Number(BigInt(receipt.gasUsed)), status: Number(BigInt(receipt.status)),
                transaction: receipt.transactionHash, block: Number(BigInt(receipt.blockNumber)), ...extra });
        },
        summary() {
            const byOperation = {};
            for (const entry of entries) {
                const item = byOperation[entry.operation] ??= { count: 0, min: Infinity, max: 0, total: 0 };
                item.count++;
                item.min = Math.min(item.min, entry.gas_used);
                item.max = Math.max(item.max, entry.gas_used);
                item.total += entry.gas_used;
            }
            for (const item of Object.values(byOperation)) item.mean = Math.round(item.total / item.count);
            return byOperation;
        },
    };
}

function options(args) {
    const parsed = { binDir: path.join(ROOT, 'target/acceptance/release'), outputDir: path.join(ROOT, '.zkapi/acceptance'),
        stopAfter: null };
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '--help') return { help: true };
        const key = { '--bin-dir': 'binDir', '--output-dir': 'outputDir', '--stop-after': 'stopAfter' }[args[i]];
        assert.ok(key && args[i + 1], `Unknown or incomplete option: ${args[i]}`);
        parsed[key] = key === 'stopAfter' ? args[++i] : path.resolve(args[++i]);
    }
    return parsed;
}

// A per-run operator seed: 31 random bytes, below the subgroup order and far
// from zero, as the server's seed policy requires.
const randomSeed = () => `0x${randomBytes(31).toString('hex')}`;

// Revert data of a JSON-RPC error, wherever the node put it.
const revertData = error => [error?.data, error?.data?.data, error?.error?.data]
    .find(data => typeof data === 'string' && data.startsWith('0x'));

class RpcCallError extends Error {
    constructor(method, error) {
        super(`${method}: ${JSON.stringify(error)}`);
        this.rpcError = error;
        this.data = revertData(error);
    }
}

async function main() {
    const opts = options(process.argv.slice(2));
    if (opts.help) {
        console.log('Usage: node scripts/v2-acceptance.mjs [--bin-dir target/acceptance/release] [--output-dir .zkapi/acceptance] [--stop-after STEP]\n'
            + 'Runs only disposable loopback services, with mock provider, OA org and price feed. See docs/v2-acceptance.md.\n'
            + '--stop-after ends a development run early, after one of: deploy, stack, honest, stale, clients, mismatch, sdk-honest,\n'
            + 'sdk-close, raise, companion, companion-close, gasless-close, gasless-bundler, gasless-griefing, gasless-replay,\n'
            + 'gasless-fallback, gasless-escape, gasless-sdk-escape, pause, gasless-pause, pause-max, gasless-reopen, anchors,\n'
            + 'lie-expired, withhold, rebuild, hang, missed, late-successor.');
        return;
    }
    const { AbiCoder, Interface, Wallet, getBytes } = await import(
        pathToFileURL(path.join(ROOT, 'docker/aws/signer/node_modules/ethers/lib.esm/index.js')).href);
    const coder = AbiCoder.defaultAbiCoder();
    const started = Date.now();
    const runId = `${new Date().toISOString().replaceAll(':', '-')}-${randomUUID().slice(0, 8)}`;
    const runDir = path.join(opts.outputDir, runId);
    await fs.mkdir(runDir, { recursive: true, mode: 0o700 });
    await fs.chmod(runDir, 0o700);
    const readJSON = async p => JSON.parse(await fs.readFile(p, 'utf8'));
    const save = (name, value) => fs.writeFile(path.join(runDir, name), json(value), { mode: 0o600 });
    // Fresh operator seeds for this run. They reach only the environment of
    // `zkapi signing-keys` and `zkapi serverd`; nothing writes them to the run
    // directory, and the run fails if any saved file contains one.
    const seedEnv = { ZKAPI_STATE_SEED: randomSeed(), ZKAPI_CLEAR_SEED: randomSeed() };
    const children = new Set();
    const servers = new Set();
    const scenarios = [];
    const gas = gasLedger();
    const evidence = {};
    let interrupted = false;
    // The first assertion failure inside a loopback mock or proxy; it fails
    // the run instead of surfacing to a daemon as a transport error.
    let fatal;
    let miner = null;
    const onSignal = () => {
        interrupted = true;
        for (const child of children) child.kill('SIGINT');
    };
    process.on('SIGINT', onSignal);
    process.on('SIGTERM', onSignal);
    const check = () => {
        if (interrupted) throw new Error('Local acceptance test interrupted');
        if (fatal) throw fatal;
    };
    const log = message => console.log(`[${((Date.now() - started) / 1000).toFixed(0).padStart(4)} s] ${message}`);
    async function waitFor(label, fn, timeout = 60_000, interval = 200) {
        const end = Date.now() + timeout;
        let last;
        while (Date.now() < end) {
            check();
            try { const value = await fn(); if (value) return value; } catch (error) { last = error; }
            await delay(interval);
        }
        check();
        throw new Error(`Timeout: ${label}${last ? ` (${last.message})` : ''}`);
    }
    // Each scenario's outcome: PASS with its evidence, or FAIL (which ends the
    // run: later scenarios build on the chain the earlier ones left).
    async function scenario(name, fn) {
        check();
        log(`scenario: ${name}`);
        const begin = Date.now();
        try {
            const result = await fn();
            scenarios.push({ name, status: 'PASS', seconds: (Date.now() - begin) / 1000, ...result });
            await save('scenarios.json', scenarios);
            return result;
        } catch (error) {
            scenarios.push({ name, status: 'FAIL', seconds: (Date.now() - begin) / 1000, error: error.message });
            await save('scenarios.json', scenarios);
            throw error;
        }
    }
    const stopAfter = step => {
        if (opts.stopAfter === step) throw Object.assign(new Error(`stopped after ${step}`), { stopped: true });
    };
    function launch(command, args, logName, { interactive = false, env = {}, cwd = ROOT } = {}) {
        check();
        const out = createWriteStream(path.join(runDir, logName), { flags: 'a', mode: 0o600 });
        // No inherited credentials, network proxies, HOME, or provider settings.
        const child = spawn(command, args, { cwd, env: { PATH: process.env.PATH,
            RUST_LOG: 'warn,zkapi=info,zkapi_serverd=info,zkapi_indexerd=info,zkapi_companion=info,zkapi_walletd=info,r1cs=warn',
            ...env }, stdio: [interactive ? 'pipe' : 'ignore', 'pipe', 'pipe'] });
        if (!interactive) child.stdout.pipe(out);
        child.stderr.pipe(out);
        child.once('error', error => out.write(error.message));
        child.once('close', () => { children.delete(child); out.end(); });
        children.add(child);
        return child;
    }
    // Runs a process that must exit by itself and returns its exit status and
    // output. The event loop keeps serving the loopback mocks meanwhile.
    async function runToExit(command, args, logName, env = {}, { timeout = 300_000, cwd = ROOT } = {}) {
        const child = launch(command, args, logName, { env, cwd });
        let output = '';
        child.stdout.on('data', chunk => { output += chunk; });
        child.stderr.on('data', chunk => { output += chunk; });
        const timer = setTimeout(() => child.kill('SIGKILL'), timeout);
        const [code, signal] = await new Promise((resolve, reject) => {
            child.once('error', reject);
            child.once('close', (exitCode, exitSignal) => resolve([exitCode, exitSignal]));
        });
        clearTimeout(timer);
        return { code, signal, output };
    }
    async function stop(child) {
        if (!child?.pid || child.exitCode !== null || child.signalCode !== null) return;
        const done = new Promise(resolve => child.once('exit', resolve));
        child.kill('SIGINT');
        await Promise.race([done, delay(3000)]);
        if (child.exitCode === null && child.signalCode === null) {
            child.kill('SIGKILL');
            await Promise.race([done, delay(3000)]);
        }
    }
    async function freePort() {
        const server = net.createServer();
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        const port = server.address().port;
        await new Promise(resolve => server.close(resolve));
        return port;
    }
    async function serve(handler, server = http.createServer()) {
        server.on('request', (req, res) => Promise.resolve(handler(req, res)).catch(error => {
            if (!res.headersSent) respond(res, 500, { error: error.message });
            else res.destroy();
        }));
        await new Promise((resolve, reject) => { server.once('error', reject); server.listen(0, '127.0.0.1', resolve); });
        servers.add(server);
        return `http://127.0.0.1:${server.address().port}`;
    }
    async function request(url, { method = 'GET', value, headers = {}, timeoutMs } = {}) {
        check();
        return localJSON(url, { method, value, headers, timeoutMs });
    }
    async function get(url) {
        const result = await request(url);
        assert.equal(result.status, 200, `${new URL(url).pathname}: ${result.value?.error_code ?? result.status} ${JSON.stringify(result.value)}`);
        return result.value;
    }
    let rpcId = 0;
    async function rpcRaw(url, method, params = []) {
        const result = await request(url, { method: 'POST', value: { jsonrpc: '2.0', id: ++rpcId, method, params } });
        assert.equal(result.status, 200, `${method}: HTTP ${result.status}`);
        return result.value;
    }
    async function rpcAt(url, method, params = []) {
        const reply = await rpcRaw(url, method, params);
        if (reply.error) throw new RpcCallError(method, reply.error);
        return reply.result;
    }
    function sha256File(file) {
        return fs.readFile(file).then(bytes => createHash('sha256').update(bytes).digest('hex'));
    }
    const toolEnv = () => Object.fromEntries(['HOME', 'SVM_HOME', 'FOUNDRY_DIR', 'XDG_CACHE_HOME', 'XDG_CONFIG_HOME']
        .filter(name => process.env[name]).map(name => [name, process.env[name]]));

    const sdkAgents = [];
    try {
        log('Starting the local concession-exit acceptance: real contracts, proofs, daemons, signer, SDK and companion; mock provider and price feed.');
        const timing = drillTiming();
        assert.ok(timing.ok, `drill timing fails a daemon startup check: ${json(timing)}`);
        const W = timing.settlement_window_seconds;

        // ---------------------------------------------------------------- keys
        const signingKeysFor = env => spawnSync(path.join(opts.binDir, 'zkapi'), ['signing-keys'], { cwd: ROOT, encoding: 'utf8',
            env: { PATH: process.env.PATH, RUST_LOG: 'warn', ...env } });
        const derived = signingKeysFor(seedEnv);
        assert.equal(derived.status, 0, `zkapi signing-keys failed: ${derived.stderr}`);
        const signingKeys = JSON.parse(derived.stdout);
        const development = signingKeysFor({ ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' });
        assert.notEqual(development.status, 0, 'signing-keys must refuse the published development seeds');
        assert.match(development.stderr, /published development key/);

        // ---------------------------------------------------------------- chain
        const anvilPort = await freePort();
        const rpcUrl = `http://127.0.0.1:${anvilPort}`;
        const genesisTimestamp = Math.floor(Date.now() / 1000) - CHAIN_LAG_SECONDS;
        launch('anvil', ['--host', '127.0.0.1', '--port', String(anvilPort), '--chain-id', String(CHAIN_ID),
            '--mnemonic', MNEMONIC, '--accounts', String(ANVIL_ACCOUNTS), '--timestamp', String(genesisTimestamp), '--slots-in-an-epoch', '1', '--silent'],
            'anvil.log', { env: toolEnv() });
        await waitFor('Anvil startup', async () => await rpcAt(rpcUrl, 'eth_chainId') === hex(CHAIN_ID));
        const rpc = (method, params) => rpcAt(rpcUrl, method, params);
        const accounts = await rpc('eth_accounts');
        const [owner, challengerAccount, treasury] = accounts;
        // Each client and destination has its own account.
        const account = Object.fromEntries(['driver', 'companion', 'sdk', 'destination', 'thirdParty', 'sdkDestination', 'companionDestination',
            'bundler', 'gaslessSdk', 'griefer'].map((name, index) => [name, accounts[3 + index]]));
        assert.ok(Object.values(account).every(Boolean), 'Anvil serves an account for every role');
        // Mines a block every second, so block time follows the wall clock
        // (CHAIN_LAG_SECONDS behind it) and confirmations and the finalized
        // tag (two blocks with --slots-in-an-epoch 1) keep advancing.
        miner = setInterval(() => { void rpc('evm_mine', []).catch(() => {}); }, 1_000);
        const chainNow = async () => Number(BigInt((await rpc('eth_getBlockByNumber', ['latest', false])).timestamp));
        async function skipChain(seconds, label) {
            const before = await chainNow();
            await rpc('evm_increaseTime', [seconds]);
            await rpc('evm_mine', []);
            const after = await chainNow();
            assert.ok(after >= before + seconds, 'the chain clock advanced');
            assert.ok(after <= Math.floor(Date.now() / 1000) + MAX_CHAIN_LEAD_SECONDS, 'block time stays within the exit proofs\' validity');
            (evidence.time_skips ??= []).push({ label, seconds, chain_before: before, chain_after: after,
                wall: Math.floor(Date.now() / 1000) });
            return after;
        }
        async function waitReceipt(hash, timeout = 60_000) {
            return waitFor(`receipt ${hash}`, () => rpc('eth_getTransactionReceipt', [hash]), timeout, 100);
        }
        async function sendTx({ from, to, data, value = 0n, gasLimit }) {
            const tx = { from, to, data, value: hex(value) };
            if (gasLimit) tx.gas = hex(gasLimit);
            return waitReceipt(await rpc('eth_sendTransaction', [tx]));
        }
        const balance = address => rpc('eth_getBalance', [address, 'latest']).then(BigInt);

        // The canonical ERC-4337 EntryPoint v0.7.0 and the SenderCreator it
        // created, etched at their canonical addresses from the pinned
        // runtime fixtures (protocol/VENDORED.md), as on every public chain;
        // Deploy.s.sol, the paymaster's constructor and finalize pin both by
        // keccak256.
        const etched = {};
        for (const [name, address, file, codehash] of [
            ['entry_point', CANONICAL_ENTRY_POINT, 'entrypoint-v0.7.0.runtime.hex', ENTRY_POINT_V070_CODEHASH],
            ['sender_creator', SENDER_CREATOR, 'sender-creator-v0.7.0.runtime.hex', SENDER_CREATOR_V070_CODEHASH]]) {
            const text = (await fs.readFile(path.join(ROOT, 'protocol/contracts/test/fixtures', file), 'utf8')).trim();
            const code = text.startsWith('0x') ? text : `0x${text}`;
            assert.equal(keccak256(hexToBytes(code)), codehash, `${file} is the pinned runtime`);
            await rpc('anvil_setCode', [address, code]);
            const onChain = await rpc('eth_getCode', [address, 'latest']);
            assert.equal(keccak256(hexToBytes(onChain)), codehash, `eth_getCode(${name}) hashes to the pin`);
            etched[name] = { address, runtime_keccak256: codehash, bytes: (onChain.length - 2) / 2 };
        }

        // ---------------------------------------------------------------- deployment
        log('Deploying with demo/contracts/script/Deploy.s.sol and finalizing its manifest on chain.');
        const deployDir = path.join(ROOT, '.demo', `acceptance-${runId}`);
        await fs.mkdir(deployDir, { recursive: true });
        const broadcastDir = path.join(runDir, 'broadcast');
        const deployEnv = {
            ...toolEnv(), FOUNDRY_BROADCAST: broadcastDir,
            PRIVATE_KEY: ANVIL_KEYS[0], OWNER: owner, TREASURY: treasury, CHAIN_ID: String(CHAIN_ID),
            OUTPUT_PATH: path.join(deployDir, 'deployment.json'), SETUP_MANIFEST: path.join(SETUP_DIR, 'manifest.json'),
            STATE_SIGNING_KEY_X: signingKeys.state_signing_key.x, STATE_SIGNING_KEY_Y: signingKeys.state_signing_key.y,
            CLEARANCE_SIGNING_KEY_X: signingKeys.clearance_signing_key.x, CLEARANCE_SIGNING_KEY_Y: signingKeys.clearance_signing_key.y,
            CHALLENGE_PERIOD_SECONDS: String(TIMING.challengePeriod), NOTE_TTL_SECONDS: String(TIMING.noteTtl),
            MAX_PAUSE_DURATION_SECONDS: String(TIMING.maxPauseDuration), REQUEST_CHARGE_CAP: String(CAP),
            // Off a local chain (this Anvil has Sepolia's ID) the single-party
            // dev setup deploys only as a drill vault.
            ALLOW_DEV_SETUP: '1',
            // The gasless-withdrawal paymaster in the same broadcast. Off a
            // local chain (by chain ID) the stakes and the float are explicit;
            // the drill sponsors escape initiations too.
            GASLESS: '1', PAYMASTER_STAKE_WEI: String(PAYMASTER_STAKE_WEI), FACTORY_STAKE_WEI: String(PAYMASTER_STAKE_WEI),
            PAYMASTER_DEPOSIT_WEI: String(PAYMASTER_DEPOSIT_WEI), PAYMASTER_ESCAPES: '1',
        };
        const deployed = await runToExit('forge', ['script', 'script/Deploy.s.sol', '--rpc-url', rpcUrl, '--broadcast'],
            'deploy.log', deployEnv, { cwd: path.join(ROOT, 'demo/contracts') });
        assert.equal(deployed.code, 0, `Deploy.s.sol failed:\n${deployed.output.slice(-3000)}`);
        const pending = await readJSON(path.join(deployDir, 'deployment.json.pending'));
        assert.equal(pending.deploymentStatus, 'pending');
        assert.equal(pending.allowDevSetup, true);
        assert.ok(!('deployBlock' in pending), 'a provisional manifest has no deployBlock');
        const finalizedPath = path.join(deployDir, 'deployment.json');
        const finalizing = await runToExit(process.execPath, [path.join(ROOT, 'scripts/expected-codehashes.mjs'),
            '--deployment', path.join(deployDir, 'deployment.json.pending'), '--rpc', rpcUrl, '--finalize', finalizedPath,
            '--broadcast-log', path.join(broadcastDir, 'Deploy.s.sol', String(CHAIN_ID), 'run-latest.json')], 'finalize.log');
        assert.equal(finalizing.code, 0, `finalize failed:\n${finalizing.output}`);
        const finalized = await readJSON(finalizedPath);
        assert.equal(finalized.deploymentStatus, 'deployed');
        await fs.copyFile(path.join(deployDir, 'deployment.json.pending'), path.join(runDir, 'deployment.json.pending'));
        await fs.copyFile(finalizedPath, path.join(runDir, 'deployment.json'));
        await fs.rm(deployDir, { recursive: true, force: true });
        const vaultAddress = finalized.vault.toLowerCase();
        const deployBlock = finalized.deployBlock;
        assert.equal(await rpc('eth_getCode', [vaultAddress, hex(deployBlock - 1)]), '0x', 'deployBlock is the vault\'s creation block');
        for (const [key, coordinate] of [['state_signing_key', 'x'], ['state_signing_key', 'y'], ['clearance_signing_key', 'x'], ['clearance_signing_key', 'y']]) {
            const field = `${key === 'state_signing_key' ? 'state' : 'clearance'}SigningKey${coordinate.toUpperCase()}`;
            assert.equal(BigInt(finalized[field]), BigInt(signingKeys[key][coordinate]), `${field} pins this run's key`);
        }
        const vaultArtifact = await readJSON(path.join(ROOT, 'protocol/contracts/out/ZkApiVault.sol/ZkApiVault.json'));
        const vault = new Interface(vaultArtifact.abi);
        async function vaultRead(name, args = [], tag = 'latest') {
            const result = vault.decodeFunctionResult(name, await rpc('eth_call', [{ to: vaultAddress, data: vault.encodeFunctionData(name, args) }, tag]));
            return result.length === 1 ? result[0] : result;
        }
        // The custom error a call reverts with, or null when it succeeds.
        async function revertName(data, from = account.thirdParty, to = vaultAddress) {
            try {
                await rpc('eth_call', [{ from, to, data }, 'latest']);
                return null;
            } catch (error) {
                assert.ok(error instanceof RpcCallError && error.data, `no revert data: ${error.message}`);
                return vault.parseError(error.data)?.name ?? error.data.slice(0, 10);
            }
        }
        const vaultEvents = receipt => receipt.logs.filter(entry => entry.address.toLowerCase() === vaultAddress)
            .map(entry => vault.parseLog(entry)).filter(Boolean);
        const eventOf = (receipt, name) => vaultEvents(receipt).find(event => event.name === name);
        async function vaultSend(from, name, args, { value = 0n, gasLimit, operation } = {}) {
            const receipt = await sendTx({ from, to: vaultAddress, data: vault.encodeFunctionData(name, args), value, gasLimit });
            if (operation) gas.record(operation, receipt);
            return receipt;
        }
        async function noteView(noteId) {
            const [commitment, amount, expiry, status] = await vaultRead('notes', [noteId]);
            return { commitment, amount, expiry: Number(expiry), status: Number(status) };
        }
        const NOTE = Object.freeze({ Active: 1, PendingWithdrawal: 2, Closed: 3 });
        assert.equal(await vaultRead('CONCESSION_ESCAPE_VERSION'), 1n);
        assert.equal(await vaultRead('challengePeriod'), BigInt(TIMING.challengePeriod));
        assert.equal(await vaultRead('maxPauseDuration'), BigInt(TIMING.maxPauseDuration));
        assert.equal((await vaultRead('owner')).toLowerCase(), owner.toLowerCase());
        evidence.deployment = { script: 'demo/contracts/script/Deploy.s.sol', finalized_by: 'scripts/expected-codehashes.mjs --finalize',
            vault: vaultAddress, deploy_block: deployBlock, deploy_block_lower_bound: pending.deployBlockLowerBound,
            setup_id: finalized.setupId, allow_dev_setup: finalized.allowDevSetup, circuit_id: finalized.circuitId,
            codehashes: { vault: finalized.vaultRuntimeCodehash, adapter: finalized.adapterRuntimeCodehash,
                poseidon: finalized.poseidonRuntimeCodehash, entry_point: finalized.entryPointRuntimeCodehash,
                sender_creator: finalized.senderCreatorRuntimeCodehash, paymaster: finalized.paymasterRuntimeCodehash,
                factory: finalized.factoryRuntimeCodehash, account_implementation: finalized.accountImplementationRuntimeCodehash },
            etched, gasless: { paymaster: finalized.withdrawalPaymaster, factory: finalized.withdrawalAccountFactory,
                policy: finalized.paymasterPolicy, fee_ceilings: finalized.paymasterFeeCeilings,
                stake_wei: finalized.paymasterStakeWei, deposit_wei: finalized.paymasterInitialDepositWei },
            deploy_transactions: finalized.deployTransactions };
        stopAfter('deploy');

        // ---------------------------------------------------------------- mocks and profiles
        const keyHashes = { requestPk: await sha256File(path.join(SETUP_DIR, 'request.pk')),
            withdrawalPk: await sha256File(path.join(SETUP_DIR, 'withdrawal.pk')), requestVk: await sha256File(path.join(SETUP_DIR, 'request.vk')) };
        const sdkManifest = await readJSON(path.join(ROOT, 'sdk/assets/manifest.json'));
        assert.equal(sdkManifest.setupId, 'dev', 'the shipped WebAssembly is the dev setup\'s');
        for (const [file, hash] of [['request.pk', keyHashes.requestPk], ['withdrawal.pk', keyHashes.withdrawalPk], ['request.vk', keyHashes.requestVk]]) {
            assert.equal(sdkManifest.files[`assets/proofs/${file}`], hash, `sdk/assets/proofs/${file} is the dev setup's`);
        }
        const mock = mockProvider();
        const providerUrl = await serve(mock.handler);
        const feed = '0x0000000000000000000000000000000000001234';
        const quoteTimestamp = Math.floor(Date.now() / 1000) - 1;
        // The pinned RPC of the server (native billing) and of the clients:
        // the ETH/USD feed is mocked, everything else is the actual chain.
        const pinnedRpcMethods = new Map();
        const pinnedRpcUrl = await serve(async (req, res) => {
            const call = await body(req);
            pinnedRpcMethods.set(call.method, (pinnedRpcMethods.get(call.method) ?? 0) + 1);
            const target = call.params?.[0];
            if (call.method === 'eth_call' && target?.to?.toLowerCase() === feed) {
                let result;
                if (target.data === '0x313ce567') result = coder.encode(['uint256'], [8]);
                else if (target.data === '0xfeaf968c' || target.data === `0x9a6fc8f5${word(123)}`) {
                    result = coder.encode(['uint80', 'int256', 'uint256', 'uint256', 'uint80'], [123, MOCK_PRICE, quoteTimestamp, quoteTimestamp, 123]);
                } else {
                    fatal ??= new Error(`unexpected price feed read ${target.data}`);
                    return respond(res, 200, { jsonrpc: '2.0', id: call.id, error: { code: -32000, message: 'unsupported feed read' } });
                }
                return respond(res, 200, { jsonrpc: '2.0', id: call.id, result });
            }
            respond(res, 200, await proxyJsonRpc(rpcUrl, call));
        });

        // The operator's public endpoint in front of serverd: clients only
        // ever see this URL, so serverd can restart (in another adversary
        // mode) behind it, be taken unreachable, or have its answers replaced.
        // In `stream` mode it relays each answer as it arrives and never ends
        // a call itself, so a hanging serverd hangs the client's call.
        const gate = { target: null, mode: 'pass', intercept: null, log: [], stream: false };
        const gateUrl = await serve(async (req, res) => {
            const chunks = [];
            for await (const chunk of req) chunks.push(chunk);
            const payload = Buffer.concat(chunks);
            gate.log.push({ method: req.method, path: req.url, mode: gate.mode, at: Date.now() });
            if (gate.mode === 'down' || !gate.target) {
                res.writeHead(503, { 'content-type': 'application/json' });
                return res.end(JSON.stringify({ error_code: 'service_unavailable', error: 'local operator outage' }));
            }
            if (gate.stream) {
                const outgoing = http.request(new URL(req.url, gate.target), { method: req.method, agent: localAgent,
                    headers: { ...req.headers, host: new URL(gate.target).host } }, incoming => {
                    res.writeHead(incoming.statusCode, incoming.headers);
                    incoming.pipe(res);
                });
                res.on('close', () => outgoing.destroy());
                outgoing.on('error', () => res.destroy());
                outgoing.end(payload);
                return;
            }
            const upstream = await new Promise((resolve, reject) => {
                const outgoing = http.request(new URL(req.url, gate.target), { method: req.method, agent: localAgent,
                    headers: { ...req.headers, host: new URL(gate.target).host } }, incoming => {
                    const parts = [];
                    incoming.on('data', chunk => parts.push(chunk));
                    incoming.on('error', reject);
                    incoming.on('end', () => resolve({ status: incoming.statusCode, headers: incoming.headers, body: Buffer.concat(parts) }));
                });
                outgoing.setTimeout(120_000, () => outgoing.destroy(new Error('gate upstream timed out')));
                outgoing.on('error', reject);
                outgoing.end(payload);
            });
            const answer = gate.intercept ? await gate.intercept({ method: req.method, path: req.url, payload, upstream }) : upstream;
            const headers = { ...answer.headers };
            delete headers['content-length'];
            delete headers['transfer-encoding'];
            res.writeHead(answer.status, headers);
            res.end(answer.body);
        });
        const indexerPort = await freePort();
        const indexerUrl = `http://127.0.0.1:${indexerPort}`;
        // The operator's bundler (scripts/acceptance/mini-bundler.mjs): every
        // profile publishes it as gasless.bundler_url; it bundles from its
        // own Anvil account against the etched EntryPoint.
        const bundler = await startMiniBundler({ rpcUrl, entryPoint: CANONICAL_ENTRY_POINT, account: account.bundler.toLowerCase(), serve,
            gasPolicy: gaslessProfile(finalized).gas_policy, chainId: CHAIN_ID });
        const services = { deploymentId: `acceptance-${CHAIN_ID}-${runId.slice(-8)}`, protocolServerUrl: gateUrl, indexerUrl,
            rpcUrl: pinnedRpcUrl, priceFeed: feed, keyHashes, settlementWindowSeconds: W, inferenceBase: `${providerUrl}/v1`,
            verifierUrl: `${providerUrl}/verifier`, bundlerUrl: bundler.url };
        const trusted = trustedDeployment(finalized, services);
        assert.deepEqual(trusted.state_signing_key, { x: felt(signingKeys.state_signing_key.x), y: felt(signingKeys.state_signing_key.y) });
        assert.equal(trusted.gasless?.bundler_url, bundler.url, 'every profile names the operator\'s bundler');
        assert.equal(trusted.gasless.policy.escapes_enabled, true, 'the drill sponsors escape initiations');
        const manifestPath = path.join(runDir, 'trusted-deployment.json');
        await save('trusted-deployment.json', { trusted_deployment: trusted });

        // ---------------------------------------------------------------- daemons
        log('Daemon order: indexer, zkapi db init, signer, challenger, serverd.');
        const indexerArgs = ['--listen', `127.0.0.1:${indexerPort}`, '--rpc-url', rpcUrl, '--contract-address', vaultAddress,
            '--from-block', String(deployBlock), '--poll-interval-ms', '100', '--chain-id', String(CHAIN_ID),
            '--confirmations', String(INDEXER_CONFIRMATIONS), '--max-head-age-secs', '0', '--cursor-path', path.join(runDir, 'indexer.json')];
        let indexer = launch(path.join(opts.binDir, 'zkapi-indexerd'), indexerArgs, 'indexer.log');
        async function synchronizedTree() {
            const chainRoot = await vaultRead('currentRoot');
            return waitFor('indexer root matches the chain', async () => {
                const snapshot = await get(`${indexerUrl}/v1/tree/snapshot`);
                return BigInt(snapshot.root) === chainRoot && snapshot;
            });
        }
        await synchronizedTree();
        const dbPath = path.join(runDir, 'server.db');
        const zkapi = path.join(opts.binDir, 'zkapi');
        const dbInit = await runToExit(zkapi, ['--proof-setup-dir', SETUP_DIR, 'db', 'init', '--deployment', manifestPath, '--db', dbPath], 'db-init.log');
        assert.equal(dbInit.code, 0, `zkapi db init failed: ${dbInit.output}`);
        assert.equal(JSON.parse(dbInit.output.slice(dbInit.output.indexOf('{'))).result, 'bound');
        // A profile whose vault codehash is not the deployed code: db init binds
        // it (it reads no chain), and serverd refuses to start on it.
        const tamperedManifest = path.join(runDir, 'trusted-deployment-wrong-codehash.json');
        await save(path.basename(tamperedManifest), { trusted_deployment: { ...trusted, vault_runtime_codehash: `0x${'ab'.repeat(32)}` } });

        const signerPort = await freePort();
        const signerUrl = `http://127.0.0.1:${signerPort}`;
        launch(process.execPath, [path.join(ROOT, 'docker/aws/signer/server.mjs')], 'signer.log', { env: {
            ZKAPI_CHALLENGE_CHAIN_ID: String(CHAIN_ID), ZKAPI_CHALLENGE_PRIVATE_KEY: ANVIL_KEYS[1], ZKAPI_CHALLENGE_VAULT: vaultAddress,
            ZKAPI_CHALLENGE_RPC_URL: rpcUrl, ZKAPI_CHALLENGE_PORT: String(signerPort),
            ZKAPI_CHALLENGE_MAX_FEE_PER_GAS_WEI: String(CHALLENGE_MAX_FEE_PER_GAS),
            ZKAPI_CHALLENGE_MAX_PRIORITY_FEE_PER_GAS_WEI: String(CHALLENGE_MAX_PRIORITY_FEE_PER_GAS),
            ZKAPI_CHALLENGE_PRIORITY_FEE_PER_GAS_WEI: String(CHALLENGE_PRIORITY_FEE_PER_GAS),
            ZKAPI_CHALLENGE_RETIRE_ON_MISS: 'true', ZKAPI_CHALLENGE_MAX_RETIREMENTS_PER_DAY: '2' } });
        const signerHealth = await waitFor('signer health', async () => {
            const health = await request(`${signerUrl}/health`);
            return health.status === 200 && health.value;
        });
        assert.equal(signerHealth.sender.toLowerCase(), challengerAccount.toLowerCase());
        assert.equal(signerHealth.vault.toLowerCase(), vaultAddress);

        // Every call the challenger makes reaches the signer through this
        // recorder: each send's fees, decoded call and outcome.
        const challengeSends = [];
        const challengerRpcUrl = await serve(async (req, res) => {
            const call = await body(req);
            let send;
            if (call.method === 'eth_sendTransaction') {
                try {
                    const tx = call.params[0];
                    const parsed = vault.parseTransaction({ data: tx.data });
                    send = { tx, call: parsed?.name, note_id: Number(parsed?.args?.noteId ?? -1),
                        fees: challengeFees(tx, CHALLENGE_MAX_FEE_PER_GAS), at: Date.now() };
                    assert.equal(tx.from.toLowerCase(), challengerAccount.toLowerCase());
                    assert.equal(tx.to.toLowerCase(), vaultAddress);
                    assert.ok(['challengeEscapeWithdrawal', 'raiseEscapeConcession', 'retireClosedLeaf'].includes(send.call), send.call);
                    challengeSends.push(send);
                } catch (error) {
                    fatal ??= error;
                    throw error;
                }
            }
            const reply = await proxyJsonRpc(signerUrl, call);
            if (send) Object.assign(send, reply.error ? { error: reply.error } : { hash: reply.result });
            respond(res, 200, reply);
        });
        const challengerStatusPort = await freePort();
        const challengerStatusUrl = `http://127.0.0.1:${challengerStatusPort}`;
        const challengerCheckpoint = path.join(runDir, 'challenger.json');
        const challengerArgs = ['--rpc-url', challengerRpcUrl, '--indexer-url', indexerUrl, '--sender', challengerAccount,
            '--deployment', manifestPath, '--from-block', String(deployBlock), '--confirmations', '2', '--db-path', dbPath,
            '--checkpoint', challengerCheckpoint, '--proof-setup-dir', SETUP_DIR, '--poll-interval-ms', '200',
            '--max-fee-per-gas-wei', String(CHALLENGE_MAX_FEE_PER_GAS), '--max-priority-fee-per-gas-wei', String(CHALLENGE_MAX_PRIORITY_FEE_PER_GAS),
            '--priority-fee-per-gas-wei', String(CHALLENGE_PRIORITY_FEE_PER_GAS), '--status-listen', `127.0.0.1:${challengerStatusPort}`,
            '--observe-interval-seconds', '1', '--raise-lead-seconds', String(TIMING.raiseLead),
            '--settlement-window-seconds', String(W), '--settlement-poll-seconds', String(TIMING.settlementPoll), '--retire-on-miss', 'true'];
        let challenger = null;
        let challengerStarts = 0;
        async function startChallenger() {
            challenger = launch(path.join(opts.binDir, 'zkapi-challenged'), challengerArgs, `challenger-${++challengerStarts}.log`);
            return waitFor('challenger status', async () => {
                const status = await get(`${challengerStatusUrl}/status`);
                return status.chain?.latest_block != null && status;
            }, 60_000);
        }
        const challengerReady = await startChallenger();
        assert.equal(challengerReady.schema, 'zkapi-challenged-status/v2');
        const challengerStatus = () => get(`${challengerStatusUrl}/status`);

        const serverPort = await freePort();
        const serverUrl = `http://127.0.0.1:${serverPort}`;
        // The OA org and verifier the companion phase uses (the companion
        // accepts only OA org keys); serverd switches to it for that phase.
        const oaSecret = randomBytes(24).toString('hex');
        const oaOptions = { sharedSecret: oaSecret, verifierUrl: null, inferenceBase: `${providerUrl}/v1` };
        const oaOrgMock = mockOaOrg(mock, oaOptions);
        oaOptions.verifierUrl = await serve(oaOrgMock.verifier);
        const oaOrgUrl = await serve(oaOrgMock.org);
        const serverArgs = (listenPort, db, { adversary = null, manifest = manifestPath, keySource = 'openrouter' } = {}) => [
            '--chain-id', String(CHAIN_ID), '--contract-address', vaultAddress, '--request-charge-cap', String(CAP),
            '--proof-setup-dir', SETUP_DIR, ...(adversary ? ['--adversary', adversary] : []), 'serverd',
            '--listen', `127.0.0.1:${listenPort}`, '--openrouter-api-base', providerUrl,
            ...(keySource === 'oa_org' ? ['--oa-org-url', oaOrgUrl] : ['--openrouter-management-key', 'local-only-management-key']),
            '--openrouter-lease-ttl-seconds', String(TIMING.leaseTtl),
            '--openrouter-settlement-grace-seconds', String(TIMING.settlementGrace),
            '--openrouter-settlement-poll-seconds', String(TIMING.settlementPoll),
            '--openrouter-settlement-deadline-seconds', String(TIMING.settlementDeadline),
            '--deployment', manifest, '--native-billing-rpc-url', pinnedRpcUrl, '--native-price-feed-address', feed,
            '--db-path', db, '--indexer-url', indexerUrl, '--root-poll-interval-ms', '100'];
        // Each refused start uses its own database path and must exit non-zero.
        async function refusedStart(label, env, refusal, argsFor = (port, db) => serverArgs(port, db)) {
            const db = path.join(runDir, `refused-${label}.db`);
            const result = await runToExit(zkapi, argsFor(await freePort(), db), `refused-${label}.log`, env, { timeout: 120_000 });
            assert.ok(result.code !== null && result.code !== 0, `${label}: serverd must refuse to start (exit ${result.code}, ${result.signal})`);
            assert.match(result.output, refusal, `${label}: unexpected refusal:\n${result.output.slice(-2000)}`);
            return { exit_code: result.code, refusal: refusal.source };
        }
        const refusedStarts = {
            development_seeds: await refusedStart('development-seeds', { ZKAPI_STATE_SEED: '0x1', ZKAPI_CLEAR_SEED: '0x2' }, /published development key/),
            unpinned_seeds: await refusedStart('unpinned-seeds', { ZKAPI_STATE_SEED: randomSeed(), ZKAPI_CLEAR_SEED: randomSeed() },
                /do not derive the keys the deployment manifest pins/),
            missing_seeds: await refusedStart('missing-seeds', {}, /ZKAPI_STATE_SEED \(or --state-seed\) is required/),
        };
        // The codehash-mismatch profile: bound by db init, refused by serverd.
        const tamperedDb = path.join(runDir, 'refused-codehash.db');
        const tamperedInit = await runToExit(zkapi, ['--proof-setup-dir', SETUP_DIR, 'db', 'init', '--deployment', tamperedManifest, '--db', tamperedDb], 'db-init-codehash.log');
        assert.equal(tamperedInit.code, 0, tamperedInit.output);
        refusedStarts.vault_codehash_mismatch = await refusedStart('codehash', seedEnv, /codehash/i,
            port => serverArgs(port, tamperedDb, { manifest: tamperedManifest }));
        let server = null;
        let serverStarts = 0;
        async function startServer(adversary = null, { keySource = 'openrouter' } = {}) {
            if (server) await stop(server);
            server = launch(zkapi, serverArgs(serverPort, dbPath, { adversary, keySource }),
                `server-${++serverStarts}-${adversary ?? 'honest'}${keySource === 'oa_org' ? '-oa-org' : ''}.log`,
                { env: { ...seedEnv, ...(keySource === 'oa_org' ? { ZKAPI_OA_ORG_SHARED_SECRET: oaSecret } : {}) } });
            gate.target = serverUrl;
            await waitFor('serverd ready at the chain root', async () => {
                const health = await get(`${serverUrl}/health`);
                return BigInt(health.current_root) === await vaultRead('currentRoot') && health;
            }, 90_000);
            const health = await get(`${serverUrl}/health`);
            assert.equal(health.circuit_id, 'zkapi-v2-concession-v1');
            assert.equal(health.exit_concession, 1);
            return health;
        }
        const serverHealth = await startServer();
        const attestation = await get(`${serverUrl}/v1/attestation`);
        assert.equal(BigInt(attestation.state_signing_key.x), BigInt(signingKeys.state_signing_key.x));
        assert.equal(BigInt(attestation.clearance_signing_key.y), BigInt(signingKeys.clearance_signing_key.y));
        evidence.stack = { signer_health: signerHealth, server_health: serverHealth, refused_server_starts: refusedStarts,
            db_init: 'bound', timing: { ...TIMING, ...timing },
            // serverd, the indexer and the challenger read a profile that
            // carries the gasless object and ignore it.
            profile_gasless: { bundler_url: trusted.gasless.bundler_url, paymaster: trusted.gasless.withdrawal_paymaster_address,
                read_by: ['zkapi db init', 'zkapi-challenged', 'zkapi serverd'] } };
        stopAfter('stack');

        // ---------------------------------------------------------------- client drivers
        const config = { protocol_version: 2, chain_id: CHAIN_ID, contract_address: vaultAddress, request_charge_cap: CAP,
            policy_charge_cap: 0, policy_enabled: false, state_signing_key: signingKeys.state_signing_key,
            clearance_signing_key: signingKeys.clearance_signing_key };
        const driverBinary = path.join(opts.binDir, 'examples/v2_acceptance_wallet');
        // The browser wallet core (zkapi-browser, natively) behind a JSONL
        // driver: one in-memory wallet per process.
        async function wallet(name) {
            const child = launch(driverBinary, [SETUP_DIR], `wallet-${name}.log`, { interactive: true });
            const lines = readline.createInterface({ input: child.stdout });
            let nextId = 0;
            const pending = new Map();
            const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
            lines.on('line', line => {
                try {
                    const response = JSON.parse(line);
                    const item = pending.get(response.id);
                    assert.ok(item, 'unexpected wallet response');
                    pending.delete(response.id);
                    if (response.ok) item.resolve(response.result);
                    else item.reject(new Error(`Wallet ${item.command}: ${response.error}`));
                } catch (error) { rejectAll(error); }
            });
            child.once('error', rejectAll);
            child.once('close', code => rejectAll(new Error(`Wallet helper exited (${code})`)));
            const call = async (command, data = {}) => {
                check();
                const id = ++nextId;
                return new Promise((resolve, reject) => {
                    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Wallet ${command} timed out`)); }, 180_000);
                    pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                    child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
                });
            };
            assert.equal((await call('circuit')).circuit_id, 'zkapi-v2-concession-v1');
            await call('init', { config });
            return call;
        }
        const WITHDRAWAL_TUPLE = 'tuple(uint16,uint64,address,uint256,uint256,uint256,uint256,uint256,uint32,uint128,address,uint256,uint8,uint256,uint128,uint64)';
        const wallNow = () => Math.floor(Date.now() / 1000);
        async function treePath(client, noteId) {
            const snapshot = await synchronizedTree();
            return client('tree_path', { args: { snapshot, note_id: noteId, require_existing: true } });
        }
        async function driverDeposit(client, amount = DEPOSIT, from = account.driver) {
            const snapshot = await synchronizedTree();
            const params = await client('deposit_params');
            const merkle = await client('tree_path', { args: { snapshot, note_id: snapshot.next_note_id, require_existing: false } });
            const receipt = await vaultSend(from, 'deposit', [felt(params.registration_commitment), amount, merkle.siblings],
                { value: BigInt(amount) * GWEI, operation: 'deposit' });
            assert.equal(receipt.status, '0x1');
            const deposited = eventOf(receipt, 'NoteDeposited');
            const noteId = Number(deposited.args.noteId);
            const note = await noteView(noteId);
            assert.equal(note.amount, BigInt(amount));
            assert.equal(note.status, NOTE.Active);
            const status = await client('confirm_deposit', { args: { note_id: noteId, amount, expiry_ts: note.expiry } });
            assert.equal(status.state.note.is_genesis, true);
            // Amendment A1: the deposit's own root and siblings prove the note
            // for good; exits need no indexer.
            const depositPath = { active_root: felt(deposited.args.newRoot), siblings: merkle.siblings };
            assert.equal((await client('note_path_matches', { args: { active_root: depositPath.active_root, siblings: depositPath.siblings } })).matches, true);
            return { noteId, receipt, depositPath, expiry: note.expiry };
        }
        const quotePayload = async () => JSON.stringify({ mode: 'openrouter_ephemeral_lease', version: 1,
            billing_quote: await get(`${gateUrl}/v2/billing/quote`) });
        async function inference(lease) {
            const answer = await request(`${lease.openrouter_api_base}/chat/completions`, { method: 'POST',
                headers: { authorization: `Bearer ${lease.api_key}` },
                value: { model: MODEL, messages: [{ role: 'user', content: PROMPT }], max_tokens: 8, stream: false } });
            assert.equal(answer.status, 200, `inference: ${JSON.stringify(answer.value)}`);
            assert.equal(answer.value.choices[0].message.content, 'OK');
        }
        async function retireLease(id, preparedRequest) {
            const retired = await request(`${gateUrl}/v2/openrouter/leases/${id}`, { method: 'POST', value: preparedRequest });
            assert.ok(retired.status === 200 || (retired.status === 409 && retired.value?.error_code === 'lease_settlement_pending'),
                `retirement failed: ${retired.status}/${retired.value?.error_code}`);
        }
        // A request through the operator: proved by the wallet, leased over
        // HTTP, one inference at the provider mock with the issued key.
        async function driverRequest(client, noteId, label, { retire = true, infer = true } = {}) {
            const merkle = await treePath(client, noteId);
            const id = `acceptance-${label}-${randomUUID()}`;
            const prepared = await client('prepare_request', { args: { payload: await quotePayload(), active_root: merkle.active_root,
                merkle_siblings: merkle.siblings, client_request_id: id, request_time: wallNow(), created_at_ms: Date.now() } });
            assert.equal(prepared.bound_at_state, CAP, 'C2: the request fixes the state\'s bound');
            const issued = await request(`${gateUrl}/v2/openrouter/leases`, { method: 'POST', value: prepared.request });
            assert.equal(issued.status, 201, `lease rejected: ${issued.value?.error_code ?? issued.status}`);
            if (infer) await inference(issued.value);
            if (retire) await retireLease(id, prepared.request);
            return { id, request: prepared.request, lease: issued.value, nullifier: prepared.request.public_inputs.request_nullifier, merkle };
        }
        async function settledResponse(id, timeout = 60_000) {
            return waitFor(`settlement of ${id}`, async () => {
                const found = await get(`${gateUrl}/v2/requests/${id}`);
                return found.request_response;
            }, timeout);
        }
        async function honestRequest(client, noteId, label) {
            const sent = await driverRequest(client, noteId, label);
            const response = await settledResponse(sent.id);
            assert.equal(response.charge_applied, INFERENCE_CHARGE);
            const status = await client('complete_response', { response });
            assert.equal(status.pending_request, false);
            return { ...sent, response, status };
        }
        async function driverEscape(client, noteId, { snapshot, conceded = 0, destination = account.destination, validUntil, path: merkle,
            from = account.driver, send = true, operation = 'escape' } = {}) {
            const plan = await client('prepare_withdrawal', { ...(snapshot ? { snapshot } : {}), args: { mode: 'escape', destination,
                conceded, valid_until: validUntil ?? (await chainNow()) + 10_800, active_root: merkle.active_root, merkle_siblings: merkle.siblings } });
            assert.equal(plan.public_inputs.kind, 0);
            assert.ok(plan.calldata.startsWith('0xa38d62aa') && plan.calldata.length === 2 + 836 * 2, 'escape calldata layout');
            if (!send) return { plan };
            const receipt = await sendTx({ from, to: vaultAddress, data: plan.calldata });
            assert.equal(receipt.status, '0x1', 'the escape reverted');
            if (operation) gas.record(operation, receipt, { note_id: noteId, conceded });
            const initiated = eventOf(receipt, 'EscapeWithdrawalInitiated');
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            assert.equal(BigInt(recorded.args.nextNullifier), BigInt(plan.public_inputs.next_nullifier));
            assert.equal(recorded.args.conceded, BigInt(conceded));
            return { plan, receipt, initiated, recorded, deadline: Number(initiated.args.challengeDeadline) };
        }
        async function clearance(client, merkle) {
            const ownership = await client('prepare_withdrawal', { args: { mode: 'ownership', valid_until: wallNow() + 3_000,
                active_root: merkle.active_root, merkle_siblings: merkle.siblings } });
            assert.equal(ownership.public_inputs.kind, 2);
            const granted = await request(`${gateUrl}/v2/withdraw/clearance`, { method: 'POST', value: ownership.clearance_request });
            return { ownership, granted };
        }
        async function driverMutualClose(client, noteId, merkle, destination = account.destination) {
            const { ownership, granted } = await clearance(client, merkle);
            assert.equal(granted.status, 200, `clearance refused: ${JSON.stringify(granted.value)}`);
            const close = await client('prepare_withdrawal', { args: { mode: 'mutual', destination, valid_until: (await chainNow()) + 10_800,
                active_root: merkle.active_root, merkle_siblings: merkle.siblings, clearance: granted.value } });
            assert.ok(close.calldata.startsWith('0x72cd2e44') && close.calldata.length === 2 + 836 * 2, 'close calldata layout');
            const receipt = await sendTx({ from: account.driver, to: vaultAddress, data: close.calldata });
            assert.equal(receipt.status, '0x1', 'the mutual close reverted');
            gas.record('mutual_close', receipt, { note_id: noteId });
            return { ownership, clearance: granted.value, close, receipt };
        }
        async function vaultEventsSince(name, noteId, fromBlock) {
            const topic = vault.getEvent(name).topicHash;
            const logs = await rpc('eth_getLogs', [{ address: vaultAddress, fromBlock: hex(fromBlock), toBlock: 'latest',
                topics: [topic, felt(noteId)] }]);
            return logs.map(entry => ({ ...vault.parseLog(entry), transactionHash: entry.transactionHash,
                blockNumber: Number(BigInt(entry.blockNumber)) }));
        }
        async function waitEvent(name, noteId, fromBlock, timeout = 90_000) {
            const found = await waitFor(`${name} for note ${noteId}`, async () => (await vaultEventsSince(name, noteId, fromBlock))[0], timeout, 300);
            return { event: found, receipt: await rpc('eth_getTransactionReceipt', [found.transactionHash]) };
        }
        // Waits for the challenger to settle every obligation it has.
        async function challengerQuiet(timeout = 90_000) {
            return waitFor('challenger has no unresolved obligation', async () => {
                const status = await challengerStatus();
                return status.obligations.every(item => ['nothing_due', 'expired_nothing_due', 'resolved_unconfirmed'].includes(item.state)
                    || item.state === 'raised') && status;
            }, timeout);
        }
        const balances = async (...addresses) => Object.fromEntries(await Promise.all(addresses.map(async a => [a, await balance(a)])));
        const pendingEscapes = [];
        let expiryNote = null;

        // ================================================================ Phase H: an honest operator
        await scenario('honest flow: deposit, two requests, settle, mutual close', async () => {
            const client = await wallet('honest');
            const note = await driverDeposit(client);
            const before = await balances(vaultAddress, treasury, account.destination);
            const first = await honestRequest(client, note.noteId, 'honest-1');
            const second = await honestRequest(client, note.noteId, 'honest-2');
            const state = second.status.state.note;
            assert.equal(state.current_balance, DEPOSIT - 2 * INFERENCE_CHARGE);
            assert.equal(state.is_genesis, false);
            assert.equal(state.bound_at_state, 0, 'an installed successor resets the bound');
            assert.equal((await get(`${gateUrl}/v2/requests/${first.id}`)).nullifier_status, 'finalized');
            // An ownership proof (kind 2) never lands on chain.
            const { ownership, granted } = await clearance(client, note.depositPath);
            assert.equal(granted.status, 200, `clearance refused: ${JSON.stringify(granted.value)}`);
            const tuple = coder.decode([WITHDRAWAL_TUPLE], ownership.inputs_abi)[0];
            const asEscape = vault.encodeFunctionData('initiateEscapeWithdrawal', [tuple, ownership.proof_hex]);
            const asClose = vault.encodeFunctionData('mutualClose', [tuple, ownership.proof_hex]);
            assert.equal(await revertName(asEscape), 'WrongWithdrawalKind');
            assert.equal(await revertName(asClose), 'WrongWithdrawalKind');
            const rejected = await sendTx({ from: account.thirdParty, to: vaultAddress, data: asEscape, gasLimit: 1_000_000 });
            assert.equal(rejected.status, '0x0');
            gas.record('ownership_proof_on_chain_reverts', rejected);
            const nullifier = ownership.public_inputs.withdrawal_nullifier;
            assert.equal((await get(`${gateUrl}/v2/nullifiers/${nullifier}`)).nullifier_status, 'clearance_reserved');
            // The close proves at the deposit's root (Amendment A1).
            const close = await client('prepare_withdrawal', { args: { mode: 'mutual', destination: account.destination,
                valid_until: (await chainNow()) + 10_800, active_root: note.depositPath.active_root, merkle_siblings: note.depositPath.siblings,
                clearance: granted.value } });
            const receipt = await sendTx({ from: account.driver, to: vaultAddress, data: close.calldata });
            assert.equal(receipt.status, '0x1');
            gas.record('mutual_close', receipt, { note_id: note.noteId });
            const closed = eventOf(receipt, 'MutualClose');
            const payout = DEPOSIT - 2 * INFERENCE_CHARGE;
            assert.equal(closed.args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, account.destination);
            assert.equal((await noteView(note.noteId)).status, NOTE.Closed);
            assert.equal(after[account.destination] - before[account.destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(2 * INFERENCE_CHARGE) * GWEI);
            assert.equal(before[vaultAddress] - after[vaultAddress], BigInt(DEPOSIT) * GWEI);
            assert.equal(await vaultRead('usedNullifiers', [nullifier]), true);
            const final = await client('status');
            assert.equal(final.state.note.current_balance, payout, 'the wallet\'s balance is what the close paid');
            return { note_id: note.noteId, charges: [first.response.charge_applied, second.response.charge_applied],
                payout_gwei: payout, treasury_gwei: 2 * INFERENCE_CHARGE, close_transaction: receipt.transactionHash,
                ownership_proof_on_chain: 'WrongWithdrawalKind (escape and close)', client_final_balance: final.state.note.current_balance };
        });
        stopAfter('honest');

        await scenario('stale exit after spending: defeat, SupersededState, re-escape from an older state and defeat', async () => {
            const client = await wallet('stale');
            const note = await driverDeposit(client);
            const snapshots = [await client('snapshot', { name: 'S0' })];
            const requests = [];
            for (let k = 0; k < 4; k++) {
                requests.push(await honestRequest(client, note.noteId, `stale-${k}`));
                if (k < 3) snapshots.push(await client('snapshot', { name: `S${k + 1}` }));
            }
            // S_k's successor nullifier is S_{k+1}'s nullifier.
            for (let k = 0; k < 3; k++) assert.equal(BigInt(snapshots[k].successor_nullifier), BigInt(snapshots[k + 1].withdrawal_nullifier));
            const before = await balances(vaultAddress, treasury, account.destination);
            // The evidence a stale device's pre-check (E4.2) reads: the operator
            // serves the request at S2's successor, and it verifies. (This
            // wallet core has no exit rules, so it escapes from S2 anyway; the
            // companion scenario runs the pre-check in a real client.)
            const served = await get(`${gateUrl}/v2/nullifiers/${snapshots[2].successor_nullifier}/evidence`);
            assert.equal((await client('verify_request', { args: { public_inputs: served.public_inputs, proof: served.proof.proof } })).valid, true,
                'the evidence at the successor verifies');
            // 1. Escape from S2 after spending S3: defeated by the request at N3.
            const merkle = await treePath(client, note.noteId);
            const fromS2 = await driverEscape(client, note.noteId, { snapshot: 'S2', path: merkle });
            const defeat = await waitEvent('EscapeWithdrawalChallenged', note.noteId, fromS2.receipt.blockNumber);
            gas.record('defeat', defeat.receipt, { note_id: note.noteId });
            assert.equal(BigInt(defeat.event.args.nullifier), BigInt(snapshots[2].withdrawal_nullifier));
            assert.equal((await rpc('eth_getTransactionByHash', [defeat.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            assert.equal((await noteView(note.noteId)).status, NOTE.Active);
            assert.equal(await vaultRead('challengedNullifiers', [snapshots[2].withdrawal_nullifier]), true);
            assert.equal(await vaultRead('usedNullifiers', [snapshots[2].withdrawal_nullifier]), false);
            assert.equal(await vaultRead('usedNullifiers', [snapshots[2].successor_nullifier]), false);
            const sends = challengeSends.filter(send => send.note_id === note.noteId);
            assert.ok(sends.some(send => send.call === 'challengeEscapeWithdrawal' && send.hash === defeat.event.transactionHash),
                'the challenger\'s defeat went through the signer');
            const defeatCall = vault.parseTransaction({ data: (await rpc('eth_getTransactionByHash', [defeat.event.transactionHash])).input });
            assert.equal(BigInt(defeatCall.args.inputs.requestNullifier), BigInt(snapshots[3].withdrawal_nullifier), 'evidence at N3 = N2⁺');
            // The defeat cleared both used flags, so only the indexer's
            // published-nullifier table (the escape's EscapeConcessionRecorded
            // named N3) still tells serverd that N3 is public: the evidence
            // endpoint now refuses it.
            const published = await waitFor('serverd learns from the indexer that N3 is published', async () => {
                const answer = await request(`${gateUrl}/v2/nullifiers/${snapshots[2].successor_nullifier}/evidence`);
                return answer.status === 410 && answer;
            });
            assert.equal(published.value.error_code, 'published');
            const indexerPublished = await get(`${indexerUrl}/v1/nullifiers/${snapshots[2].successor_nullifier}/published`);
            assert.equal(indexerPublished.published, true);
            // 2. From S1: its successor N2 is challenged, so SupersededState.
            const fromS1 = await driverEscape(client, note.noteId, { snapshot: 'S1', path: merkle, send: false });
            assert.equal(await revertName(fromS1.plan.calldata), 'SupersededState');
            const superseded = await sendTx({ from: account.driver, to: vaultAddress, data: fromS1.plan.calldata, gasLimit: 1_000_000 });
            assert.equal(superseded.status, '0x0');
            gas.record('escape_superseded_state_reverts', superseded);
            // 3. From S0 (two states older): recorded, then defeated by the request at N1.
            const fromS0 = await driverEscape(client, note.noteId, { snapshot: 'S0', path: note.depositPath });
            const second = await waitEvent('EscapeWithdrawalChallenged', note.noteId, fromS0.receipt.blockNumber);
            gas.record('defeat', second.receipt, { note_id: note.noteId });
            assert.equal(BigInt(second.event.args.nullifier), BigInt(snapshots[0].withdrawal_nullifier));
            assert.equal(await vaultRead('challengedNullifiers', [snapshots[0].withdrawal_nullifier]), true);
            // 4. S2 again: ChallengedNullifier.
            const again = await driverEscape(client, note.noteId, { snapshot: 'S2', path: merkle, send: false });
            assert.equal(await revertName(again.plan.calldata), 'ChallengedNullifier');
            // Defeats move no funds; the newest state then closes mutually.
            const mid = await balances(vaultAddress, treasury, account.destination);
            assert.equal(mid[vaultAddress], before[vaultAddress]);
            assert.equal(mid[account.destination], before[account.destination]);
            const close = await driverMutualClose(client, note.noteId, await treePath(client, note.noteId));
            const payout = DEPOSIT - 4 * INFERENCE_CHARGE;
            assert.equal(eventOf(close.receipt, 'MutualClose').args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, account.destination);
            assert.equal(after[account.destination] - before[account.destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(4 * INFERENCE_CHARGE) * GWEI);
            assert.equal((await noteView(note.noteId)).status, NOTE.Closed);
            const final = await client('status');
            assert.equal(final.state.note.current_balance, payout);
            return { note_id: note.noteId, evidence_at_s2_successor: 'served (200) and verifies under the request key',
                evidence_after_publication: '410 published (indexer published-nullifier table)',
                defeats: [defeat.event.transactionHash, second.event.transactionHash], superseded_revert: 'SupersededState',
                replay_after_defeat: 'ChallengedNullifier', newest_state_close: close.receipt.transactionHash, payout_gwei: payout,
                client_final_balance: final.state.note.current_balance };
        });
        stopAfter('stale');

        // ---------------------------------------------------------------- the browser SDK
        // The host: browser-config.json (the build-pinned profile), the proof
        // keys the SDK fetches by SHA-256 pin, and the operator's manifest.
        const operatorManifest = { protocol_version: 2, proof_backend: 'groth16_bn254',
            proof_setup: { circuit_id: trusted.circuit_id, setup_id: trusted.setup_id,
                request_proving_key_sha256: trusted.request_proving_key_sha256,
                withdrawal_proving_key_sha256: trusted.withdrawal_proving_key_sha256 },
            deployment_id: trusted.deployment_id, contract_address: trusted.contract_address, chain_id: trusted.chain_id,
            protocol_server_url: trusted.protocol_server_url, indexer_url: trusted.indexer_url, rpc_url: trusted.rpc_url,
            billing_asset: trusted.billing_asset, billing_unit: trusted.billing_unit, billing_token_address: null,
            native_asset_wei_per_unit: trusted.native_asset_wei_per_unit, native_price_feed_address: trusted.native_price_feed_address,
            native_price_feed_decimals: trusted.native_price_feed_decimals, native_price_max_age_seconds: trusted.native_price_max_age_seconds,
            request_charge_cap: trusted.request_charge_cap, state_signing_key: trusted.state_signing_key,
            clearance_signing_key: trusted.clearance_signing_key, models: [MODEL],
            privacy_mode: { openrouter_inference_base: trusted.openrouter_inference_base, verifier_url: trusted.verifier_url } };
        const hostConfigs = new Map();
        const proofFiles = { 'request.pk': 'request.pk', 'withdrawal.pk': 'withdrawal.pk', 'request.vk': 'request.vk' };
        const hostUrl = await serve(async (req, res) => {
            const pathname = new URL(req.url, 'http://127.0.0.1').pathname;
            if (pathname === '/operator/config.json') return respond(res, 200, operatorManifest);
            const configured = /^\/zkapi\/([a-z0-9-]+)\/browser-config\.json$/.exec(pathname);
            if (configured && hostConfigs.has(configured[1])) return respond(res, 200, hostConfigs.get(configured[1]));
            const key = /^\/zkapi\/([a-z0-9-]+)\/proofs\/([a-z.]+)$/.exec(pathname);
            if (key && proofFiles[key[2]]) {
                res.writeHead(200, { 'content-type': 'application/octet-stream' });
                return res.end(await fs.readFile(path.join(ROOT, 'sdk/assets/proofs', proofFiles[key[2]])));
            }
            respond(res, 404, { error: 'not found' });
        });
        const browserConfig = profile => ({ deployment_manifest_url: `${hostUrl}/operator/config.json`,
            allowed_deployment_manifest_urls: [`${hostUrl}/operator/config.json`], trusted_deployment: profile,
            proving_keys_base_url: './proofs/', credits_per_usd: null, billing_token_symbol: 'ETH', billing_token_decimals: 9,
            require_oa_key_source: false });
        hostConfigs.set('v2c', browserConfig(trusted));
        // A build whose profile pins another vault codehash (§10.7 B: the
        // codehash-mismatch profile refuses deposits).
        hostConfigs.set('v2c-mismatch', browserConfig({ ...trusted, vault_runtime_codehash: `0x${'ab'.repeat(32)}` }));
        await save('browser-config.json', hostConfigs.get('v2c'));
        async function sdkAgent(name, { build = 'v2c', walletAccount }) {
            const child = launch(process.execPath, [path.join(ROOT, 'scripts/acceptance/sdk-agent.mjs')], `sdk-${name}.log`, { interactive: true });
            const lines = readline.createInterface({ input: child.stdout });
            let nextId = 0;
            const pending = new Map();
            const rejectAll = error => { for (const item of pending.values()) item.reject(error); pending.clear(); };
            lines.on('line', line => {
                let response;
                try { response = JSON.parse(line); } catch { return; }
                const item = pending.get(response.id);
                if (!item) return;
                pending.delete(response.id);
                if (response.ok) item.resolve(response.result);
                else item.reject(Object.assign(new Error(`SDK ${item.command}: ${response.error.message}`), { sdk: response.error }));
            });
            child.once('error', rejectAll);
            child.once('close', code => rejectAll(new Error(`SDK agent exited (${code})`)));
            const call = async (command, data = {}, timeout = 300_000) => {
                check();
                const id = ++nextId;
                return new Promise((resolve, reject) => {
                    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`SDK ${command} timed out`)); }, timeout);
                    pending.set(id, { command, resolve: value => { clearTimeout(timer); resolve(value); }, reject: error => { clearTimeout(timer); reject(error); } });
                    child.stdin.write(JSON.stringify({ id, command, ...data }) + '\n');
                });
            };
            call.close = async () => { await call('close', {}, 5_000).catch(() => {}); await stop(child); };
            sdkAgents.push(call);
            await call('start', { hostUrl, configUrl: `${hostUrl}/zkapi/${build}/browser-config.json`, walletRpcUrl: rpcUrl, account: walletAccount });
            return call;
        }
        // The SDK's refusal, as an object (its code and data).
        const sdkRefusal = promise => promise.then(value => assert.fail(`expected a refusal, got ${json(value)}`), error => {
            assert.ok(error.sdk, error.message);
            return error.sdk;
        });

        // ---------------------------------------------------------------- the clientd companion
        // zkapi-walletd as zkapi-clientd runs it: a bridge token, and every
        // outbound connection through an authenticated loopback proxy. The
        // proxy tags each request it relays, so the companion's own entrances
        // (startCompanion) can tell relayed requests from direct ones.
        async function forwardProxy(name) {
            const user = 'clientd';
            const password = randomBytes(24).toString('hex');
            const tag = randomBytes(16).toString('hex');
            const record = { requests: 0, refused: 0, bypassed: 0, hosts: new Set(), through: {} };
            const proxy = http.createServer();
            proxy.on('connect', (req, socket) => {
                const [host, port] = req.url.split(':');
                if (!proxyAuthorized(req.headers['proxy-authorization'], user, password) || host !== '127.0.0.1') {
                    record.refused++;
                    socket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
                    return;
                }
                const upstream = net.connect(Number(port), host, () => {
                    socket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
                    upstream.pipe(socket);
                    socket.pipe(upstream);
                });
                upstream.on('error', () => socket.destroy());
                socket.on('error', () => upstream.destroy());
            });
            const url = await serve(async (req, res) => {
                const target = new URL(req.url);
                if (!proxyAuthorized(req.headers['proxy-authorization'], user, password) || target.hostname !== '127.0.0.1') {
                    record.refused++;
                    return respond(res, 403, { error: 'refused by the local proxy' });
                }
                record.requests++;
                record.hosts.add(target.host);
                const headers = { ...req.headers, 'x-acceptance-proxy': tag };
                delete headers['proxy-authorization'];
                delete headers['proxy-connection'];
                await new Promise((resolve, reject) => {
                    const outgoing = http.request(target, { method: req.method, headers, agent: localAgent }, incoming => {
                        res.writeHead(incoming.statusCode, incoming.headers);
                        incoming.pipe(res);
                        incoming.on('end', resolve);
                        incoming.on('error', reject);
                    });
                    outgoing.on('error', error => { if (!res.headersSent) respond(res, 502, { error: error.message }); else res.destroy(); resolve(); });
                    req.pipe(outgoing);
                });
            }, proxy);
            const parsed = new URL(url);
            parsed.username = user;
            parsed.password = password;
            return { url: parsed.href, record, name, tag };
        }
        const companionManifest = { deployment_id: trusted.deployment_id, protocol_version: 2, chain_id: CHAIN_ID,
            rpc_url: trusted.rpc_url, contract_address: vaultAddress, billing_token_address: null, billing_asset: 'native_eth',
            billing_unit: 'gwei', native_asset_wei_per_unit: trusted.native_asset_wei_per_unit, native_price_feed_address: feed,
            native_price_feed_decimals: 8, native_price_max_age_seconds: 4_500, vault_revision: 3, deployment_status: 'deployed',
            exit_concession: 1, settlement_window_seconds: W, deploy_block: deployBlock, protocol_server_url: gateUrl,
            indexer_url: indexerUrl, request_charge_cap: CAP, proof_backend: 'groth16_bn254',
            proof_setup: { circuit_id: trusted.circuit_id, setup_id: trusted.setup_id },
            state_signing_key: trusted.state_signing_key, clearance_signing_key: trusted.clearance_signing_key,
            models: [{ id: MODEL, owned_by: 'local', tags: ['chat'] }] };
        await save('companion-deployment.json', companionManifest);
        async function startCompanion(name, { stateDir = path.join(runDir, `companion-${name}`) } = {}) {
            const token = randomBytes(24).toString('hex');
            const proxy = await forwardProxy(name);
            const port = await freePort();
            const proxyEnv = Object.fromEntries(['HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'https_proxy', 'http_proxy', 'all_proxy']
                .map(key => [key, proxy.url]));
            // The companion reaches the operator, the indexer and both RPCs
            // only through entrances of its own. Each answers only requests
            // its authenticated proxy relayed (tagged): one that reached it
            // directly is refused and counted, so the run shows that no
            // connection bypassed the proxy. (The OA verifier keeps its URL:
            // a lease names it and the companion checks that name.)
            const entrance = (label, upstream) => serve(async (req, res) => {
                if (req.headers['x-acceptance-proxy'] !== proxy.tag) {
                    proxy.record.bypassed++;
                    return respond(res, 403, { error: `${label} reached without the companion's proxy` });
                }
                proxy.record.through[label] = (proxy.record.through[label] ?? 0) + 1;
                const headers = { ...req.headers, host: new URL(upstream).host };
                delete headers['x-acceptance-proxy'];
                await new Promise(resolve => {
                    const outgoing = http.request(new URL(req.url, upstream), { method: req.method, headers, agent: localAgent }, incoming => {
                        res.writeHead(incoming.statusCode, incoming.headers);
                        incoming.pipe(res);
                        incoming.on('end', resolve);
                        incoming.on('error', resolve);
                    });
                    outgoing.on('error', error => { if (!res.headersSent) respond(res, 502, { error: error.message }); else res.destroy(); resolve(); });
                    req.pipe(outgoing);
                });
            });
            const entrances = { operator: await entrance('operator', gateUrl), indexer: await entrance('indexer', indexerUrl),
                exit_rpc: await entrance('exit_rpc', rpcUrl), pinned_rpc: await entrance('pinned_rpc', pinnedRpcUrl) };
            const manifestFile = path.join(runDir, `companion-deployment-${name}.json`);
            await save(path.basename(manifestFile), { ...companionManifest, rpc_url: entrances.pinned_rpc,
                protocol_server_url: entrances.operator, indexer_url: entrances.indexer });
            // The arguments zkapi-clientd passes (CompanionCommand), with the
            // user's own exit RPC (here the Anvil node itself).
            const child = launch(path.join(opts.binDir, 'zkapi-walletd'), ['--require-oa-org-key-source', '--oa-verifier-url', oaOptions.verifierUrl,
                '--openrouter-inference-base', `${providerUrl}/v1`, '--exit-rpc-url', entrances.exit_rpc, 'client', '--deployment', manifestFile,
                '--mode', 'direct-openrouter', '--no-fund', '--listen', `127.0.0.1:${port}`, '--state-dir', stateDir],
            `companion-${name}.log`, { env: { OA_ZKAPI_BRIDGE_TOKEN: token, OA_ZKAPI_CHAIN_ID: String(CHAIN_ID),
                ZKAPI_PROOF_SETUP_DIR: SETUP_DIR, NO_PROXY: '', no_proxy: '', RAYON_NUM_THREADS: '4', ...proxyEnv } });
            const base = `http://127.0.0.1:${port}`;
            const call = async (method, pathname, value, timeoutMs = 300_000) =>
                request(`${base}${pathname}`, { method, value, headers: { authorization: `Bearer ${token}` }, timeoutMs });
            await waitFor('companion ready', async () => (await call('GET', '/health')).status === 200, 60_000);
            const unauthenticated = await request(`${base}/oa/v1/status`);
            assert.equal(unauthenticated.status, 401, 'the companion answers only its bridge token');
            return { child, call, stateDir, proxy, name };
        }
        // Every request the companion made went through its proxy, and each
        // of `needed` saw some.
        function companionTraffic(companion, needed) {
            const { record } = companion.proxy;
            assert.equal(record.bypassed, 0, `${companion.name}: a connection bypassed the companion's proxy`);
            assert.equal(record.refused, 0, `${companion.name}: the proxy refused a request`);
            for (const label of needed) {
                const reached = label === 'verifier' ? record.hosts.has(new URL(oaOptions.verifierUrl).host) : record.through[label] > 0;
                assert.ok(reached, `${companion.name}: nothing reached ${label} through the proxy: ${json(record.through)}`);
            }
            return { proxied_requests: record.requests, through: record.through, bypassed: record.bypassed };
        }
        stopAfter('clients');

        await scenario('codehash-mismatch profile refuses deposits (SDK); serverd refuses the same profile', async () => {
            const sdk = await sdkAgent('mismatch', { build: 'v2c-mismatch', walletAccount: account.sdk });
            const initialized = await sdk('init');
            assert.equal(initialized.service?.available, true, 'the operator\'s manifest matches the build\'s pins');
            const vaultBefore = await balance(vaultAddress);
            const refusal = await sdkRefusal(sdk('deposit', { amount: '0.001' }));
            assert.equal(refusal.code, 'deployment_mismatch', json(refusal));
            const mismatches = refusal.data?.mismatches ?? [];
            assert.ok(mismatches.some(item => item.field === 'vault_runtime_codehash'), json(refusal.data));
            assert.equal(await balance(vaultAddress), vaultBefore, 'nothing was deposited');
            const after = await sdk('snapshot');
            assert.equal(after.note, null, 'the SDK holds no note');
            assert.equal(after.sent.length, 0, 'the wallet signed nothing');
            await sdk.close();
            return { sdk_refusal: refusal.code, mismatched_fields: mismatches.map(item => `${item.field} (${item.source})`),
                serverd_refusal: refusedStarts.vault_codehash_mismatch.refusal, client_final_state: 'no note, no transaction' };
        });
        stopAfter('mismatch');

        await scenario('SDK: deposit with deployment checks, request, settle; indexer down, escape with the deposit-time path', async () => {
            const sdk = await sdkAgent('honest', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const note = deposited.note;
            assert.ok(note, `no note after the deposit: ${json(deposited)}`);
            assert.equal(Number(note.current_balance), DEPOSIT);
            const noteId = Number(note.note_id);
            assert.equal((await noteView(noteId)).status, NOTE.Active);
            const depositTx = deposited.sent.find(item => item.data === vault.getFunction('deposit').selector);
            assert.ok(depositTx, 'the wallet sent the deposit');
            gas.record('deposit', await rpc('eth_getTransactionReceipt', [depositTx.hash]), { client: 'sdk' });
            const chat = await sdk('chat', { sessionId: 'acceptance-sdk', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            const settled = await sdk('settle');
            assert.equal(Number(settled.note.current_balance), DEPOSIT - INFERENCE_CHARGE, json(settled.note));
            // Another deposit moves the root past this note's deposit root.
            // It is the note claimExpired sweeps at the end of the run.
            expiryNote = { client: await wallet('expiry') };
            Object.assign(expiryNote, await driverDeposit(expiryNote.client));
            const depositRoot = (await vaultEventsSince('NoteDeposited', noteId, deployBlock))[0].args.newRoot;
            assert.notEqual(await vaultRead('currentRoot'), depositRoot);
            // The operator's indexer goes down; the escape needs no indexer
            // (Amendment A1: the deposit's root is a known root for good).
            await stop(indexer);
            const before = await balances(vaultAddress, account.sdkDestination);
            const escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination });
            const record = escaped.withdrawals.find(item => Number(item.noteId) === noteId) ?? escaped.withdrawal;
            assert.ok(record, json(escaped));
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, 'the wallet sent the escape');
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            assert.equal(recorded.args.conceded, 0n, 'a fresh state escapes conceding nothing');
            assert.equal(recorded.args.stateBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            const pending = await vaultRead('pendingWithdrawals', [noteId]);
            assert.equal(pending[0], true);
            const root = pending[1];
            assert.equal(root, depositRoot, 'the escape proves at the note\'s deposit root, not the current one');
            assert.equal(await vaultRead('isKnownRoot', [root]), true);
            await save('sdk-honest-escape.json', escaped);
            const pathSource = escaped.result?.pathSource;
            assert.equal(pathSource, 'deposit', 'the SDK took the deposit-time path');
            assert.deepEqual(escaped.result?.decision, { rule: 'E2.escape', conceded: '0' });
            // Restart the indexer from its checkpoint.
            indexer = launch(path.join(opts.binDir, 'zkapi-indexerd'), indexerArgs, 'indexer-2.log');
            await synchronizedTree();
            pendingEscapes.push({ name: 'sdk-honest', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, stateBalance: DEPOSIT - INFERENCE_CHARGE, before });
            return { note_id: noteId, deposit: depositTx.hash, escape: escapeTx.hash, path_source: pathSource,
                decision: escaped.result?.decision ?? null, sdk_statuses: escaped.statuses,
                proof_root: felt(root), proof_root_is_the_deposit_root: true, deposit_root_is_not_current: true, conceded: 0,
                indexer_down_during_escape: true, sdk_settled_balance: Number(settled.note.current_balance) };
        });
        stopAfter('sdk-honest');

        // The Phase C smoke test through the SDK: its own E2 sequence (exit
        // lock, ownership proof, clearance, close proof, mutualClose, payout
        // match), against the real serverd and vault.
        const sdkMutualClose = async (sdk, noteId, destination, payout, stateBalance) => {
            const before = await balances(vaultAddress, treasury, destination);
            const closed = await sdk('withdraw', { mode: 'mutual', destination });
            const closeTx = closed.sent.find(item => item.data === vault.getFunction('mutualClose').selector);
            assert.ok(closeTx, `no mutualClose sent: ${json(closed.statuses)}`);
            assert.ok(!closed.sent.some(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector), 'no escape was sent');
            assert.equal(closed.result?.status, 'closed', json(closed.result));
            const receipt = await waitReceipt(closeTx.hash);
            assert.equal(receipt.status, '0x1', 'the SDK mutual close reverted');
            gas.record('mutual_close', receipt, { client: 'sdk' });
            const event = eventOf(receipt, 'MutualClose');
            assert.equal(Number(event.args.noteId), noteId);
            assert.equal(event.args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, destination);
            assert.equal(after[destination] - before[destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(DEPOSIT - payout) * GWEI);
            assert.equal(before[vaultAddress] - after[vaultAddress], BigInt(DEPOSIT) * GWEI);
            assert.equal((await noteView(noteId)).status, NOTE.Closed);
            // The close's nullifier is the one the clearance reserved.
            assert.equal(await vaultRead('usedNullifiers', [event.args.nullifier]), true);
            assert.equal((await get(`${gateUrl}/v2/nullifiers/${felt(event.args.nullifier)}`)).nullifier_status, 'clearance_reserved');
            const synced = await waitFor('the SDK closes the mutual record', async () => {
                const state = await sdk('sync');
                const record = state.withdrawals.find(item => Number(item.noteId) === noteId);
                return record?.phase === 'closed' && { state, record };
            }, 90_000, 2_000);
            assert.equal(synced.state.note, null, 'the SDK holds no note after the close');
            assert.equal(synced.state.exit_lock, null, 'no exit lock is left');
            return { close: closeTx.hash, payout_gwei: payout, treasury_gwei: DEPOSIT - payout, state_balance: stateBalance,
                statuses: closed.statuses, client_final_state: { phase: synced.record.phase, mode: synced.record.mode, note: null } };
        };
        await scenario('SDK honest close (Phase C smoke): deposit, request, settle, mutual close through the SDK', async () => {
            const sdk = await sdkAgent('close', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const chat = await sdk('chat', { sessionId: 'acceptance-sdk-close', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            const settled = await sdk('settle');
            assert.equal(Number(settled.note.current_balance), DEPOSIT - INFERENCE_CHARGE, json(settled.note));
            const destination = '0x000000000000000000000000000000000000c105';
            const closed = await sdkMutualClose(sdk, noteId, destination, DEPOSIT - INFERENCE_CHARGE, DEPOSIT - INFERENCE_CHARGE);
            await sdk.close();
            return { note_id: noteId, ...closed };
        });
        stopAfter('sdk-close');

        // A destination whose receive() needs more than ESCAPE_PAYOUT_GAS
        // (five fresh SSTOREs): finalization credits it, claimEscapePayout
        // (all gas) pays it.
        const slowReceiver = '0x00000000000000000000000000000000005104e5';
        await rpc('anvil_setCode', [slowReceiver, '0x346000553460015534600255346003553460045500']);
        await scenario('under-concession escape, raised to the settled charge (exit_deferred)', async () => {
            const client = await wallet('raise');
            const note = await driverDeposit(client);
            // A served request: the provider was used, the lease still runs.
            const sent = await driverRequest(client, note.noteId, 'raise', { retire: false });
            const abandoned = await client('abandon_request');
            assert.equal(abandoned.bound_at_state, CAP);
            // The owner concedes less than the request will cost.
            const conceded = 100;
            assert.ok(conceded < INFERENCE_CHARGE);
            const escape = await driverEscape(client, note.noteId, { conceded, destination: slowReceiver, path: note.depositPath });
            assert.equal(escape.recorded.args.stateBalance, BigInt(DEPOSIT));
            // The lease retires; the server settles its charge, but the
            // nullifier is consumed on chain, so it signs no successor (O7).
            await retireLease(sent.id, sent.request);
            const deferred = await waitFor('the request settles as exit_deferred', async () => {
                const found = await get(`${gateUrl}/v2/requests/${sent.id}`);
                return found.nullifier_status === 'exit_deferred' && found;
            }, 60_000);
            assert.equal(deferred.request_response, undefined, 'no successor once the nullifier is published');
            // The challenger raises to the charge (Ω = the settled charge).
            const raised = await waitEvent('EscapeConcessionRaised', note.noteId, escape.receipt.blockNumber);
            gas.record('raise', raised.receipt, { note_id: note.noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            assert.equal(raised.event.args.finalBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            assert.equal((await rpc('eth_getTransactionByHash', [raised.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            const raiseCall = vault.parseTransaction({ data: (await rpc('eth_getTransactionByHash', [raised.event.transactionHash])).input });
            assert.equal(BigInt(raiseCall.args.inputs.requestNullifier), BigInt(sent.nullifier), 'raised with the request at the escaped nullifier');
            const concession = await vaultRead('pendingConcessions', [note.noteId]);
            assert.equal(concession[2], BigInt(INFERENCE_CHARGE));
            assert.equal((await vaultRead('pendingWithdrawals', [note.noteId]))[3], BigInt(DEPOSIT - INFERENCE_CHARGE));
            const status = await client('status');
            assert.equal(status.state.note.bound_at_state, CAP);
            assert.equal(status.archived.at(-1).disposition, 'abandoned_for_escape');
            pendingEscapes.push({ name: 'driver-raise', client: 'driver', wallet: client, noteId: note.noteId, destination: slowReceiver,
                payout: DEPOSIT - INFERENCE_CHARGE, deferred: true, before: await balances(slowReceiver),
                exitedNullifier: escape.plan.public_inputs.withdrawal_nullifier, stateBalance: DEPOSIT });
            return { note_id: note.noteId, conceded_at_init: conceded, raised_to: INFERENCE_CHARGE, raise: raised.event.transactionHash,
                server_status: deferred.nullifier_status };
        });
        stopAfter('raise');

        await scenario('companion: forced early exit conceding 0 while the operator is unreachable, raised to the real charge', async () => {
            // The companion takes only OA org keys: serverd switches its key
            // source (every direct-provider lease has settled).
            await startServer(null, { keySource: 'oa_org' });
            const companion = await startCompanion('forced');
            const bridge = await companion.call('GET', '/oa/v1/status');
            assert.equal(bridge.status, 200);
            assert.equal(bridge.value.exit_concession, 1);
            const plan = await companion.call('POST', '/deposit/prepare', { amount: DEPOSIT });
            assert.equal(plan.status, 200, json(plan.value));
            const receipt = await vaultSend(account.companion, 'deposit', [felt(plan.value.commitment), DEPOSIT, plan.value.zero_path],
                { value: BigInt(DEPOSIT) * GWEI, operation: 'deposit' });
            const deposited = eventOf(receipt, 'NoteDeposited');
            const noteId = Number(deposited.args.noteId);
            assert.equal(noteId, plan.value.next_note_id);
            const note = await noteView(noteId);
            const confirmed = await companion.call('POST', '/deposit/confirm', { secret: plan.value.secret, note_id: noteId, amount: DEPOSIT,
                expiry_ts: note.expiry, deposit_root: felt(deposited.args.newRoot), deposit_siblings: plan.value.zero_path });
            assert.equal(confirmed.status, 200, json(confirmed.value));
            await synchronizedTree();
            // One request, as clientd makes it: an OA bridge lease (the
            // companion proves the request; the verifier binds the key), then
            // the inference with that key.
            const lease = await companion.call('POST', '/oa/v1/lease', { request_limit_micro_usd: 1_000_000 });
            assert.equal(lease.status, 200, json(lease.value));
            assert.equal(lease.value.verified, true, json(lease.value));
            await inference({ openrouter_api_base: lease.value.base_url, api_key: lease.value.api_key });
            // The operator becomes unreachable; the owner exits before T.
            gate.mode = 'down';
            let prepared;
            try {
                const decision = await companion.call('POST', '/oa/v1/withdraw/escape/prepare',
                    { destination: account.companionDestination, early_exit: 'concede_nothing' });
                assert.equal(decision.status, 200, json(decision.value));
                prepared = decision.value.status === 'prepared' ? decision.value : (await companion.call('POST', '/oa/v1/withdraw/escape/prepare',
                    { destination: account.companionDestination, conceded: String(decision.value.conceded ?? '0'), early_exit: 'concede_nothing' })).value;
                assert.equal(prepared.status, 'prepared', json(prepared));
                assert.equal(String(prepared.conceded), '0');
                assert.equal(prepared.path_source, 'deposit', 'the escape proves from the deposit-time path');
            } finally {
                gate.mode = 'pass';
            }
            const escapeReceipt = await sendTx({ from: account.companion, to: vaultAddress, data: prepared.calldata });
            assert.equal(escapeReceipt.status, '0x1');
            gas.record('escape', escapeReceipt, { client: 'companion', conceded: 0 });
            const submitted = await companion.call('POST', '/oa/v1/withdraw/escape/submit', { transaction_hash: escapeReceipt.transactionHash });
            assert.equal(submitted.status, 200, json(submitted.value));
            // The lease expires and settles at its measured usage; its
            // nullifier is spent, so the challenger raises to that charge.
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(escapeReceipt.blockNumber)),
                (TIMING.leaseTtl + 120) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            assert.equal(raised.event.args.finalBalance, BigInt(DEPOSIT - INFERENCE_CHARGE));
            const status = await companion.call('GET', '/oa/v1/withdraw/escape/status');
            assert.equal(status.status, 200, json(status.value));
            // The OA lease settled: serverd returns to direct provider keys.
            await startServer();
            pendingEscapes.push({ name: 'companion-forced', client: 'companion', companion, noteId, destination: account.companionDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, before: await balances(account.companionDestination) });
            return { note_id: noteId, decision: { rule: prepared.reason ?? null, conceded: prepared.conceded, bound: prepared.bound_at_state },
                path_source: prepared.path_source, escape: escapeReceipt.transactionHash, raise: raised.event.transactionHash,
                traffic: companionTraffic(companion, ['operator', 'indexer', 'exit_rpc', 'verifier']),
                escape_status_phase: status.value.phase ?? status.value.record?.phase ?? null };
        });
        stopAfter('companion');

        // The companion's own cooperative close (kind 2, clearance, kind 1),
        // and the stale-device pre-check (E4.2) run by a real client: a copy
        // of the companion's wallet taken before two requests is the stale
        // device, and its escape is refused before any proof leaves it.
        const companionError = answer => answer.value?.error?.code ?? answer.value?.code ?? null;
        async function companionDeposit(companion, amount = DEPOSIT) {
            const plan = await companion.call('POST', '/deposit/prepare', { amount });
            assert.equal(plan.status, 200, json(plan.value));
            const receipt = await vaultSend(account.companion, 'deposit', [felt(plan.value.commitment), amount, plan.value.zero_path],
                { value: BigInt(amount) * GWEI, operation: 'deposit' });
            const deposited = eventOf(receipt, 'NoteDeposited');
            const noteId = Number(deposited.args.noteId);
            const note = await noteView(noteId);
            const confirmed = await companion.call('POST', '/deposit/confirm', { secret: plan.value.secret, note_id: noteId, amount,
                expiry_ts: note.expiry, deposit_root: felt(deposited.args.newRoot), deposit_siblings: plan.value.zero_path });
            assert.equal(confirmed.status, 200, json(confirmed.value));
            await synchronizedTree();
            return noteId;
        }
        async function companionRequest(companion) {
            const lease = await companion.call('POST', '/oa/v1/lease', { request_limit_micro_usd: 1_000_000 });
            assert.equal(lease.status, 200, json(lease.value));
            assert.equal(lease.value.verified, true, json(lease.value));
            await inference({ openrouter_api_base: lease.value.base_url, api_key: lease.value.api_key });
        }
        await scenario('companion: honest close through its mutual route; a stale copy of its wallet is refused (device_not_newest) before proving', async () => {
            await startServer(null, { keySource: 'oa_org' });
            const companion = await startCompanion('close');
            const noteId = await companionDeposit(companion);
            // The stale device: this wallet as it is now (a backup taken at
            // the genesis state).
            const staleDir = path.join(runDir, 'companion-close-stale-copy');
            await fs.cp(companion.stateDir, staleDir, { recursive: true });
            // The newest device spends the genesis state (request at N0), its
            // successor installs, and it spends that state too (request at
            // N1 = N0⁺): the operator now holds evidence at the stale state's
            // successor nullifier.
            await companionRequest(companion);
            const installed = await waitFor('the companion installs the first successor', async () => {
                const recovered = await companion.call('POST', '/wallet/recover', {});
                const wallet = recovered.status === 200 ? recovered.value.wallet : null;
                return wallet && !wallet.pending_request && Number(wallet.note?.current_balance) === DEPOSIT - INFERENCE_CHARGE && wallet;
            }, (TIMING.leaseTtl + 240) * 1000, 2_000);
            await companionRequest(companion);
            // E4.2 through the stale copy's own walletd.
            const stale = await startCompanion('stale', { stateDir: staleDir });
            const staleWallet = await stale.call('GET', '/status');
            assert.equal(Number(staleWallet.value.note.current_balance), DEPOSIT, 'the copy holds the genesis state');
            const refused = await stale.call('POST', '/oa/v1/withdraw/escape/prepare',
                { destination: account.companionDestination, conceded: '0' });
            assert.equal(refused.status, 409, json(refused.value));
            assert.equal(companionError(refused), 'device_not_newest', json(refused.value));
            const staleStatus = await stale.call('GET', '/oa/v1/withdraw/escape/status');
            assert.equal(staleStatus.status, 200, json(staleStatus.value));
            assert.equal(staleStatus.value.exit_lock, null, 'no proof left the stale device and no lock is held');
            assert.equal(staleStatus.value.phase, 'none', 'the stale device saved no escape');
            const staleTraffic = companionTraffic(stale, ['operator']);
            await stop(stale.child);
            // The newest device closes cooperatively once its second request
            // settles: kind-2 ownership proof, clearance, kind-1 close proof.
            const destination = '0x000000000000000000000000000000000000c106';
            const attempts = [];
            const prepared = await waitFor('the companion prepares a mutual close', async () => {
                const answer = await companion.call('POST', '/oa/v1/withdraw/prepare', { destination });
                attempts.push({ status: answer.status, code: companionError(answer) });
                return answer.status === 200 && answer.value;
            }, (TIMING.leaseTtl + 240) * 1000, 5_000).catch(async error => {
                await save('companion-close-attempts.json', attempts); throw error; });
            const pi = prepared.public_inputs;
            assert.equal(Number(pi.kind), 1, json(pi));
            assert.equal(Number(pi.conceded), 0);
            const asHex = value => Array.isArray(value) ? `0x${Buffer.from(value).toString('hex')}` : String(value);
            const asAddress = value => `0x${BigInt(asHex(value)).toString(16).padStart(40, '0')}`;
            const tuple = [pi.protocol_version, pi.chain_id, asAddress(pi.contract_address), asHex(pi.active_root),
                asHex(pi.state_signing_key_x), asHex(pi.state_signing_key_y), asHex(pi.clearance_signing_key_x), asHex(pi.clearance_signing_key_y),
                pi.note_id, BigInt(pi.final_balance), asAddress(pi.destination), asHex(pi.withdrawal_nullifier), pi.kind,
                asHex(pi.next_nullifier), BigInt(pi.conceded), pi.valid_until];
            const proofHex = `0x${Buffer.from(prepared.proof.proof, 'base64').toString('hex')}`;
            // zkapi-clientd signs this call; the harness sends it.
            const before = await balances(vaultAddress, treasury, destination);
            const closeReceipt = await sendTx({ from: account.companion, to: vaultAddress,
                data: vault.encodeFunctionData('mutualClose', [tuple, proofHex]) });
            assert.equal(closeReceipt.status, '0x1', 'the companion mutual close reverted');
            gas.record('mutual_close', closeReceipt, { client: 'companion' });
            const event = eventOf(closeReceipt, 'MutualClose');
            const payout = DEPOSIT - 2 * INFERENCE_CHARGE;
            assert.equal(Number(event.args.noteId), noteId);
            assert.equal(event.args.finalBalance, BigInt(payout));
            const after = await balances(vaultAddress, treasury, destination);
            assert.equal(after[destination] - before[destination], BigInt(payout) * GWEI);
            assert.equal(after[treasury] - before[treasury], BigInt(2 * INFERENCE_CHARGE) * GWEI);
            assert.equal((await noteView(noteId)).status, NOTE.Closed);
            assert.equal(await vaultRead('usedNullifiers', [event.args.nullifier]), true);
            const confirmed = await waitFor('the companion confirms the finalized close', async () => {
                const answer = await companion.call('POST', '/oa/v1/withdraw/confirm', { transaction_hash: closeReceipt.transactionHash });
                return answer.status === 200 && answer.value;
            }, 60_000, 1_000);
            const wallet = await companion.call('GET', '/status');
            assert.equal(wallet.value.has_note, false, `the companion still holds the note: ${json(wallet.value)}`);
            const traffic = companionTraffic(companion, ['operator', 'indexer', 'exit_rpc', 'verifier']);
            await stop(companion.child);
            // The OA leases settled: serverd returns to direct provider keys.
            await startServer();
            return { note_id: noteId, first_successor_balance: Number(installed.note.current_balance),
                stale_device: { refusal: companionError(refused), exit_lock: null, traffic: staleTraffic },
                prepare_attempts: attempts.length, close: closeReceipt.transactionHash, payout_gwei: payout,
                confirm: confirmed.status ?? confirmed, client_final_state: { has_note: wallet.value.has_note }, traffic };
        });
        stopAfter('companion-close');

        // ================================================================ gasless withdrawals (ERC-4337, EntryPoint v0.7.0)
        // A withdrawal whose fee is paid from the payout: the proof names a
        // transit account S = CREATE2(owner, payee); a user operation from S
        // runs the vault call, the paymaster sponsors it (after re-running the
        // vault's checks in validation) and pushes the payout less its
        // measured charge to the payee, which needs no ETH. The operator's
        // bundler is the mini bundler; the SDK and the harness as zkapi-clientd
        // (an ephemeral owner key per withdrawal) are the clients.
        const gaslessPins = trusted.gasless;
        const entryPointAddress = gaslessPins.entry_point_address;
        const paymasterAddress = gaslessPins.withdrawal_paymaster_address;
        const factoryAddress = gaslessPins.withdrawal_account_factory_address;
        const gasPolicy = gaslessPins.gas_policy;
        const artifact = async (file, name) => (await readJSON(path.join(ROOT, 'protocol/contracts/out', file, `${name}.json`)));
        const paymaster = new Interface((await artifact('ZkApiWithdrawalPaymaster.sol', 'ZkApiWithdrawalPaymaster')).abi);
        const accountFactory = new Interface((await artifact('ZkApiWithdrawalAccountFactory.sol', 'ZkApiWithdrawalAccountFactory')).abi);
        const transitAbi = new Interface((await artifact('ZkApiWithdrawalAccount.sol', 'ZkApiWithdrawalAccount')).abi);
        // The Forge suite's self-funded account (test/gasless/GaslessTestBase.sol):
        // a griefer's ERC-4337 account that pays its own gas and calls anything.
        const selfFundedArtifact = await artifact('GaslessTestBase.sol', 'SelfFundedAccount');
        const selfFunded = new Interface(selfFundedArtifact.abi);
        const entryPoint = new Interface([
            'event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)',
            'event UserOperationRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)',
            'event PostOpRevertReason(bytes32 indexed userOpHash, address indexed sender, uint256 nonce, bytes revertReason)',
            'event UserOperationPrefundTooLow(bytes32 indexed userOpHash, address indexed sender, uint256 nonce)',
            'event AccountDeployed(bytes32 indexed userOpHash, address indexed sender, address factory, address paymaster)',
            'function balanceOf(address account) view returns (uint256)',
            'function getNonce(address sender, uint192 key) view returns (uint256)',
            'error FailedOp(uint256 opIndex, string reason)',
            'error FailedOpWithRevert(uint256 opIndex, string reason, bytes inner)',
        ]);
        async function contractRead(iface, to, name, args = []) {
            const result = iface.decodeFunctionResult(name, await rpc('eth_call', [{ to, data: iface.encodeFunctionData(name, args) }, 'latest']));
            return result.length === 1 ? result[0] : result;
        }
        const pmRead = (name, args) => contractRead(paymaster, paymasterAddress, name, args);
        const floatWei = () => contractRead(entryPoint, entryPointAddress, 'balanceOf', [paymasterAddress]);
        const transitOf = async (owner, payee) => {
            const S = (await contractRead(accountFactory, factoryAddress, 'getAddress', [owner, payee])).toLowerCase();
            assert.equal((await pmRead('transitAccount', [owner, payee])).toLowerCase(), S, 'the paymaster derives the same transit account');
            return S;
        };
        const parsedLogs = (iface, address, receipt) => receipt.logs.filter(entry => entry.address.toLowerCase() === address)
            .map(entry => { try { return iface.parseLog(entry); } catch { return null; } }).filter(Boolean);
        // The EntryPoint's and the paymaster's account of one sponsored
        // operation of S in a bundle transaction.
        function sponsoredOutcome(receipt, sender) {
            const own = event => event.args.sender?.toLowerCase() === sender.toLowerCase();
            const ep = parsedLogs(entryPoint, entryPointAddress, receipt);
            const pm = parsedLogs(paymaster, paymasterAddress, receipt);
            const found = (list, name) => list.find(event => event.name === name && own(event)) ?? null;
            return { op: found(ep, 'UserOperationEvent'), revert: found(ep, 'UserOperationRevertReason'), deployed: found(ep, 'AccountDeployed'),
                postOpFailure: ep.find(event => ['PostOpRevertReason', 'UserOperationPrefundTooLow'].includes(event.name)) ?? null,
                sponsored: found(pm, 'Sponsored'), settled: found(pm, 'Settled'), failed: found(pm, 'SponsorshipFailed'),
                stranded: pm.some(event => event.name === 'Stranded' && own(event)), owed: found(pm, 'EscapeInitiationOwed'),
                shortfall: found(pm, 'Shortfall'), credited: pm.find(event => event.name === 'PayoutCredited') ?? null,
                collected: found(pm, 'Collected'), paymasterEvents: pm.map(event => event.name) };
        }
        // The measured charge sits within MARGIN_GAS of what the EntryPoint
        // took from the float (Settled.charged − actualGasCost, at the op's gas price).
        function chargeWithinMargin(outcome) {
            const cost = outcome.op.args.actualGasCost;
            const price = cost / outcome.op.args.actualGasUsed;
            const over = outcome.settled.args.charged - cost;
            assert.ok(over >= 0n, `the charge ${outcome.settled.args.charged} covers the float's cost ${cost}`);
            assert.ok(over <= BigInt(gasPolicy.margin_gas) * price, `the charge exceeds the cost by ${over} wei, more than MARGIN_GAS × ${price}`);
            return { actual_gas_cost: cost.toString(), actual_gas_used: Number(outcome.op.args.actualGasUsed), gas_price: price.toString(),
                charged: outcome.settled.args.charged.toString(), over_cost_wei: over.toString(), margin_wei: (BigInt(gasPolicy.margin_gas) * price).toString() };
        }
        const maxCostOf = op => (BigInt(op.preVerificationGas) + BigInt(op.verificationGasLimit) + BigInt(op.callGasLimit)
            + BigInt(op.paymasterVerificationGasLimit) + BigInt(op.paymasterPostOpGasLimit)) * BigInt(op.maxFeePerGas);
        const freshAddress = () => `0x${randomBytes(20).toString('hex')}`;
        const GASLESS_CLOSE_ETH = '0.02';
        const GASLESS_ESCAPE_UNITS = 50_000_000; // gwei: an escape's payout must also cover the finalization reserve and the minimum net
        // An SDK whose connected account is a fresh role (it owns the transit
        // accounts), with the submission loop's waits shortened as the SDK's
        // own tests shorten them.
        async function gaslessAgent(name) {
            const sdk = await sdkAgent(name, { walletAccount: account.gaslessSdk });
            await sdk('init');
            await sdk('gasless_timing', { timing: { receiptPollMs: 500, logPollMs: 2_000, resendAfterMs: 8_000 } });
            return sdk;
        }
        async function gaslessDeposit(sdk, amount = GASLESS_CLOSE_ETH) {
            const deposited = await sdk('deposit', { amount });
            assert.ok(deposited.note, json(deposited.statuses));
            return { noteId: Number(deposited.note.note_id), units: Number(deposited.note.current_balance),
                deposit: Number(deposited.note.current_balance), sent: deposited.sent.length,
                signatures: deposited.signatures.length };
        }
        const sdkRecord = (state, noteId) => state.withdrawals.find(item => Number(item.noteId) === noteId) ?? null;
        async function sdkClosedRecord(sdk, noteId) {
            return waitFor('the SDK closes the sponsored record', async () => {
                const state = await sdk('sync');
                const record = sdkRecord(state, noteId);
                return record?.phase === 'closed' && { state, record };
            }, 90_000, 2_000);
        }
        // A sponsored close through the SDK and its settlement, asserted the
        // way scenario 24 states it: no wallet transaction, one signature over
        // the operation hash, the vault's MutualClose to S, the paymaster's
        // Settled with the payee paid in the same transaction.
        async function sdkSponsoredClose(sdk, note, payee, { operation, options = {} } = {}) {
            const before = await balances(vaultAddress, treasury, payee, account.gaslessSdk);
            const floatBefore = await floatWei();
            const closed = await sdk('withdraw', { mode: 'mutual', destination: payee, fees: 'payout', ...options });
            assert.equal(closed.result?.status, 'closed', json(closed.result));
            const S = closed.result.transitAccount.toLowerCase();
            assert.equal(closed.sent.length, note.sent, 'the wallet sent no transaction (fees: payout)');
            const signatures = closed.signatures.length - note.signatures;
            assert.ok(signatures >= 1, 'the owner signed the operation (personal_sign)');
            const signedHashes = closed.signatures.slice(note.signatures).map(item => item.message.toLowerCase());
            assert.ok(signedHashes.includes(closed.result.userOpHash), 'personal_sign signed the operation hash');
            const receipt = await rpc('eth_getTransactionReceipt', [closed.result.transactionHash]);
            assert.equal(receipt.status, '0x1');
            assert.equal(receipt.to.toLowerCase(), entryPointAddress, 'a handleOps bundle');
            const outcome = sponsoredOutcome(receipt, S);
            assert.ok(outcome.op?.args.success, `the sponsored close succeeded: ${json(outcome.paymasterEvents)}`);
            assert.equal(outcome.op.args.paymaster.toLowerCase(), paymasterAddress);
            assert.equal(outcome.op.args.userOpHash.toLowerCase(), closed.result.userOpHash);
            assert.equal(outcome.postOpFailure, null, 'postOp never reverts');
            const event = eventOf(receipt, 'MutualClose');
            assert.equal(Number(event.args.noteId), note.noteId);
            assert.equal(event.args.destination.toLowerCase(), S, 'the proof names the transit account');
            const payout = event.args.finalBalance * GWEI;
            const settled = outcome.settled.args;
            assert.equal(Number(settled.kind), 1);
            assert.equal(settled.payee.toLowerCase(), payee.toLowerCase());
            assert.equal(settled.received, payout, 'S forwarded the whole payout');
            assert.equal(settled.owedPaid, 0n);
            assert.equal(settled.paidOut, payout - settled.charged, 'the payee gets P − charged');
            const margin = chargeWithinMargin(outcome);
            const after = await balances(vaultAddress, treasury, payee, account.gaslessSdk);
            assert.equal(after[payee] - before[payee], settled.paidOut, 'the payout address received Settled.paidOut');
            assert.equal(after[account.gaslessSdk], before[account.gaslessSdk], 'the connected account paid nothing');
            assert.equal(before[vaultAddress] - after[vaultAddress], BigInt(note.deposit) * GWEI, 'the vault paid out the whole deposit');
            assert.equal(after[treasury] - before[treasury], BigInt(note.deposit) * GWEI - payout);
            const floatAfter = await floatWei();
            assert.ok(floatAfter >= floatBefore, `the float is replenished: ${floatBefore} → ${floatAfter}`);
            assert.equal(await balance(S), 0n, 'nothing stays in the transit account');
            assert.equal(await pmRead('received', [S]), 0n);
            assert.deepEqual(closed.result.amounts && { charged: closed.result.amounts.chargedWei, paid: closed.result.amounts.paidOutWei },
                { charged: settled.charged.toString(), paid: settled.paidOut.toString() }, 'the SDK reports the settled amounts');
            if (operation) gas.record(operation, receipt, { client: 'sdk', note_id: note.noteId, user_op_hash: closed.result.userOpHash, ...margin });
            const synced = await sdkClosedRecord(sdk, note.noteId);
            assert.equal(synced.state.note, null, 'the SDK holds no note after the close');
            assert.equal(synced.state.exit_lock, null, 'no exit lock is left');
            return { closed, receipt, outcome, S, payout, settled, margin, floatBefore, floatAfter, record: synced.record, signatures,
                walletTransactions: closed.sent.length - note.sent };
        }
        // One SDK (one browser) for the sponsored closes and the SDK escape.
        let gaslessSdk = null;
        const gaslessClient = async () => (gaslessSdk ??= await gaslessAgent('gasless'));
        const gaslessPayee = freshAddress();

        await scenario('gasless close (SDK, fees: payout): a payout address with no ETH receives P − charged; no wallet transaction; the float is replenished', async () => {
            await gaslessClient();
            const note = await gaslessDeposit(gaslessSdk);
            const chat = await gaslessSdk('chat', { sessionId: 'acceptance-gasless', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            const settledRequest = await gaslessSdk('settle');
            note.units = Number(settledRequest.note.current_balance);
            note.sent = settledRequest.sent.length;
            note.signatures = settledRequest.signatures.length;
            assert.equal(await balance(gaslessPayee), 0n, 'the payout address holds no ETH');
            assert.equal(await rpc('eth_getCode', [gaslessPayee, 'latest']), '0x');
            const availability = await gaslessSdk('availability', { mode: 'mutual', destination: gaslessPayee });
            assert.equal(availability.result.available, true, json(availability.result));
            assert.equal(availability.result.bundlerUrl, bundler.url);
            const quote = await gaslessSdk('quote', { mode: 'mutual', destination: gaslessPayee });
            assert.equal(quote.result.available, true, json(quote.result));
            const S = await transitOf(account.gaslessSdk, gaslessPayee);
            assert.equal(availability.result.transitAccount?.toLowerCase(), S, 'availability derives S as the factory does');
            assert.equal(quote.result.transitAccount.toLowerCase(), S, 'the quote derives S as the factory does');
            assert.equal(await rpc('eth_getCode', [S, 'latest']), '0x', 'first use: S is created by the operation');
            const result = await sdkSponsoredClose(gaslessSdk, note, gaslessPayee, { operation: 'gasless_close_first' });
            assert.ok(result.outcome.deployed, 'the operation created S (initCode)');
            assert.equal(result.signatures, 1, 'one personal_sign, over the operation hash');
            assert.notEqual(await rpc('eth_getCode', [S, 'latest']), '0x');
            assert.ok(BigInt(quote.result.minimumReceivedWei) <= result.settled.paidOut, 'the payee got at least the quoted minimum');
            const send = bundler.sends.find(item => item.hash === result.closed.result.userOpHash);
            assert.equal(send?.outcome, 'included', json(bundler.sends));
            return { note_id: note.noteId, payee: gaslessPayee, transit_account: S, user_op_hash: result.closed.result.userOpHash,
                bundle: result.receipt.transactionHash, payout_wei: result.payout.toString(), charged_wei: result.settled.charged.toString(),
                paid_out_wei: result.settled.paidOut.toString(), quoted_minimum_wei: quote.result.minimumReceivedWei, ...result.margin,
                float_before_wei: result.floatBefore.toString(), float_after_wei: result.floatAfter.toString(), wallet_transactions: result.walletTransactions,
                signatures: result.signatures, client_final_state: { phase: result.record.phase, payout_verified: result.record.payoutVerified ?? null, note: null } };
        });
        stopAfter('gasless-close');

        await scenario('gasless bundler outages (SDK): bundler down at the send, then self-bundling from the funded wallet; a dropped operation re-signed with higher fees; forgotten receipts found by the EntryPoint logs', async () => {
            const sdk = await gaslessClient();
            const S = await transitOf(account.gaslessSdk, gaslessPayee);
            // (a) The bundler answers the pre-flight but not the send: the
            // proof is made and the operation journaled, then bundler_unavailable.
            const first = await gaslessDeposit(sdk);
            bundler.hold(['eth_sendUserOperation']);
            let refusal;
            try {
                refusal = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: gaslessPayee, fees: 'payout' }));
            } finally {
                bundler.release();
            }
            assert.equal(refusal.code, 'bundler_unavailable', json(refusal));
            assert.deepEqual(refusal.data?.fallbacks, ['self_bundle', 'direct_call']);
            const held = await sdk('snapshot');
            assert.equal(held.prepared_gasless?.transit?.account?.toLowerCase(), S, 'the plan stays bound to S');
            // Self-bundling: the connected (funded) account sends handleOps
            // itself; the paymaster pays and refunds it as the beneficiary.
            bundler.hold(['eth_sendUserOperation']);
            const walletBefore = await balance(account.gaslessSdk);
            const floatBefore = await floatWei();
            let selfBundled;
            try {
                selfBundled = await sdk('withdraw', { mode: 'mutual', destination: gaslessPayee, fees: 'payout', selfBundle: true });
            } finally {
                bundler.release();
            }
            assert.equal(selfBundled.result?.status, 'closed', json(selfBundled.result));
            const handleOpsTx = selfBundled.sent.slice(first.sent).find(item => item.to?.toLowerCase() === entryPointAddress);
            assert.ok(handleOpsTx, 'the wallet sent handleOps itself');
            assert.equal(selfBundled.sent.length, first.sent + 1, 'one transaction: the bundle');
            const selfReceipt = await waitReceipt(handleOpsTx.hash);
            const selfOutcome = sponsoredOutcome(selfReceipt, S);
            assert.ok(selfOutcome.op?.args.success);
            assert.equal(selfOutcome.deployed, null, 'S existed: no initCode');
            const fee = BigInt(selfReceipt.gasUsed) * BigInt(selfReceipt.effectiveGasPrice);
            const walletAfter = await balance(account.gaslessSdk);
            assert.equal(walletAfter - walletBefore, selfOutcome.op.args.actualGasCost - fee, 'the beneficiary got the operation\'s gas cost back');
            assert.ok(await floatWei() >= floatBefore);
            const selfMargin = chargeWithinMargin(selfOutcome);
            gas.record('gasless_self_bundle', selfReceipt, { client: 'sdk', note_id: first.noteId, refund_wei: selfOutcome.op.args.actualGasCost.toString(), ...selfMargin });
            await sdkClosedRecord(sdk, first.noteId);
            // (b) The mempool drops the operation and then refuses its
            // identical bytes as underpriced: the SDK signs it again with both
            // fee fields raised by 12.5% and journals both hashes.
            const second = await gaslessDeposit(sdk);
            bundler.drop();
            const dropped = await sdkSponsoredClose(sdk, second, gaslessPayee, { operation: 'gasless_close_repeat' });
            assert.equal(dropped.outcome.deployed, null, 'a repeat close from an existing S has no initCode');
            const lost = bundler.sends.find(item => item.outcome === 'accepted_then_dropped');
            assert.ok(lost, json(bundler.sends));
            assert.ok(bundler.sends.some(item => item.hash === lost.hash && item.outcome === 'refused' && /underpriced/.test(item.error?.message)),
                'the identical re-send was refused for its fee');
            const hashes = (dropped.record.userOpHashes || []).map(hash => hash.toLowerCase());
            assert.ok(hashes.includes(lost.hash) && hashes.includes(dropped.closed.result.userOpHash) && hashes.length >= 2,
                `both hashes are journaled: ${json(dropped.record.userOpHashes)}`);
            const lostOp = bundler.ops.get(lost.hash).json;
            const bumpedOp = bundler.ops.get(dropped.closed.result.userOpHash).json;
            assert.ok(BigInt(bumpedOp.maxFeePerGas) * 1000n >= BigInt(lostOp.maxFeePerGas) * 1125n
                && BigInt(bumpedOp.maxPriorityFeePerGas) * 1000n >= BigInt(lostOp.maxPriorityFeePerGas) * 1125n, 'both fees raised by 12.5%');
            // (c) The bundler forgets every receipt: the inclusion is found
            // through the EntryPoint's UserOperationEvent logs.
            const third = await gaslessDeposit(sdk);
            bundler.forgetReceipts();
            const receiptQueries = bundler.requests.filter(item => item.method === 'eth_getUserOperationReceipt').length;
            let forgotten;
            try {
                forgotten = await sdkSponsoredClose(sdk, third, gaslessPayee, { operation: 'gasless_close_repeat' });
            } finally {
                bundler.release();
            }
            assert.ok(bundler.requests.filter(item => item.method === 'eth_getUserOperationReceipt').length > receiptQueries,
                'the SDK asked the bundler, which answered null');
            return { transit_account: S,
                bundler_down: { refusal: refusal.code, fallbacks: refusal.data.fallbacks, self_bundle: handleOpsTx.hash,
                    beneficiary_refund_wei: selfOutcome.op.args.actualGasCost.toString(), wallet_fee_wei: fee.toString() },
                dropped: { lost_hash: lost.hash, bumped_hash: dropped.closed.result.userOpHash, journaled: hashes,
                    max_fee_per_gas: [lostOp.maxFeePerGas, bumpedOp.maxFeePerGas], bundle: dropped.receipt.transactionHash },
                forgotten_receipts: { bundle: forgotten.receipt.transactionHash, found_by: 'EntryPoint UserOperationEvent logs' } };
        });
        stopAfter('gasless-bundler');

        // A griefer's self-funded ERC-4337 account (it pays its own gas), deployed and funded.
        async function selfFundedAccount() {
            const deployData = `${selfFundedArtifact.bytecode.object}${coder.encode(['address'], [entryPointAddress]).slice(2)}`;
            const receipt = await sendTx({ from: account.griefer, to: null, data: deployData });
            assert.equal(receipt.status, '0x1');
            const address = receipt.contractAddress.toLowerCase();
            await sendTx({ from: account.griefer, to: address, data: '0x', value: 50_000_000_000_000_000n });
            return address;
        }
        // Starts a sponsored close through the SDK with the bundler holding
        // accepted operations, and returns it once its operation sits in the mempool.
        async function deferredSponsoredClose(sdk, payee) {
            bundler.defer();
            let ended = null;
            const closing = sdk('withdraw', { mode: 'mutual', destination: payee, fees: 'payout' })
                .then(value => ({ value }), error => ({ error }));
            void closing.then(outcome => { ended = outcome; });
            const end = Date.now() + 300_000;
            let pendingOp;
            while (!(pendingOp = bundler.pending()[0])) {
                check();
                if (ended || Date.now() > end) {
                    bundler.release();
                    throw new Error(`the sponsored close never reached the mempool: ${ended?.error?.message ?? json(ended?.value?.result ?? 'timeout')}`);
                }
                await delay(500);
            }
            bundler.defer(false);
            return { closing, pendingOp };
        }

        await scenario('griefing bundle: a self-funded account replays the close in the operation before the sponsored one; the sponsored close reverts (success false), the float pays at most maxCost at the capped tip, S is stranded, and collectTransitBalance pays the payee', async () => {
            const sdk = await gaslessClient();
            const note = await gaslessDeposit(sdk);
            const payee = freshAddress();
            const S = await transitOf(account.gaslessSdk, payee);
            const { closing, pendingOp } = await deferredSponsoredClose(sdk, payee);
            const vaultCall = vaultCallOf(pendingOp.json.callData);
            assert.ok(vaultCall?.startsWith(vault.getFunction('mutualClose').selector), 'the operation carries the public close calldata');
            const replayer = await selfFundedAccount();
            const replayOp = { sender: replayer, nonce: hex(await contractRead(entryPoint, entryPointAddress, 'getNonce', [replayer, 0])),
                callData: selfFunded.encodeFunctionData('execute', [vaultAddress, vaultCall]), callGasLimit: hex(900_000),
                verificationGasLimit: hex(100_000), preVerificationGas: hex(50_000), maxFeePerGas: pendingOp.json.maxFeePerGas,
                maxPriorityFeePerGas: pendingOp.json.maxPriorityFeePerGas, signature: `0x${'00'.repeat(65)}` };
            const floatBefore = await floatWei();
            const lostBefore = await pmRead('lostWei');
            const attemptsKey = await pmRead('keyFor', [1, BigInt(vault.decodeFunctionData('mutualClose', vaultCall)[0].withdrawalNullifier), 0, S]);
            const { receipt } = await bundler.bundle([replayOp, pendingOp.hash]);
            assert.equal(receipt.status, '0x1', 'both operations passed validation; the bundle lands');
            gas.record('gasless_griefing_bundle', receipt, { note_id: note.noteId, ops: 2 });
            const replayEvent = sponsoredOutcome(receipt, replayer).op;
            assert.ok(replayEvent?.args.success, 'the replay closed the note');
            assert.equal(eventOf(receipt, 'MutualClose').args.destination.toLowerCase(), S, 'the payout went to S all the same');
            const outcome = sponsoredOutcome(receipt, S);
            assert.equal(outcome.op?.args.success, false, 'the sponsored close reverted in execution');
            assert.ok(outcome.revert, 'UserOperationRevertReason carries the vault\'s refusal');
            const accountError = transitAbi.parseError(outcome.revert.args.revertReason);
            assert.equal(accountError?.name, 'VaultCallFailed', `S's call failed: ${outcome.revert.args.revertReason}`);
            assert.equal(vault.parseError(accountError.args[0])?.name, 'NoteNotActive', `the vault refused the closed note: ${accountError.args[0]}`);
            assert.ok(outcome.failed, 'SponsorshipFailed');
            assert.ok(outcome.stranded, 'Stranded(S)');
            assert.equal(outcome.postOpFailure, null);
            const cost = outcome.op.args.actualGasCost;
            // SponsorshipFailed carries the cost postOp was told, before the
            // EntryPoint added postOp's own gas and the unused-gas penalty.
            assert.ok(outcome.failed.args.actualGasCost <= cost, 'SponsorshipFailed reports the cost before postOp');
            assert.ok(cost <= maxCostOf(pendingOp.json), `the float paid ${cost} ≤ maxCost ${maxCostOf(pendingOp.json)}`);
            const ceiling = await pmRead('priorityFeeCeiling');
            assert.ok(BigInt(pendingOp.json.maxPriorityFeePerGas) <= ceiling, 'the tip is within the paymaster\'s ceiling');
            assert.equal(floatBefore - await floatWei(), cost, 'the float paid exactly the operation\'s gas');
            assert.ok(await pmRead('lostWei') - lostBefore >= cost, 'lostWei records it');
            assert.equal(await pmRead('stranded', [S]), true);
            assert.equal(Number(await pmRead('attempts', [attemptsKey])), 1, 'one attempt counted');
            const closed = await closing;
            assert.ok(closed.value, `the SDK settled the reverted operation: ${closed.error?.message}`);
            assert.equal(closed.value.result.status, 'closed', json(closed.value.result));
            assert.equal(closed.value.result.fundsWaitingInTransit, true);
            const payoutWei = BigInt(closed.value.result.transitBalanceWei);
            assert.equal(await balance(S), payoutWei);
            // The sponsored forward of the stranded payout.
            const before = await balances(payee, account.gaslessSdk);
            const collected = await sdk('collect', { recordId: closed.value.result.recordId });
            assert.equal(collected.result?.status, 'collected', json(collected.result));
            const forwardReceipt = await rpc('eth_getTransactionReceipt', [collected.result.transactionHash]);
            const forward = sponsoredOutcome(forwardReceipt, S);
            assert.ok(forward.op?.args.success);
            assert.equal(Number(forward.settled.args.kind), 4);
            assert.equal(forward.settled.args.received, payoutWei);
            const margin = chargeWithinMargin(forward);
            const after = await balances(payee, account.gaslessSdk);
            assert.equal(after[payee] - before[payee], payoutWei - forward.settled.args.charged, 'the payee gets the stranded payout less the forward\'s charge');
            assert.equal(after[account.gaslessSdk], before[account.gaslessSdk]);
            assert.equal(await balance(S), 0n);
            assert.equal(await pmRead('stranded', [S]), false, 'the forward consumed the evidence');
            gas.record('gasless_forward', forwardReceipt, { client: 'sdk', note_id: note.noteId, ...margin });
            return { note_id: note.noteId, transit_account: S, replayer, bundle: receipt.transactionHash, sponsored_success: false,
                float_paid_wei: cost.toString(), max_cost_wei: maxCostOf(pendingOp.json).toString(), tip: pendingOp.json.maxPriorityFeePerGas,
                priority_fee_ceiling: ceiling.toString(), revert_reason: outcome.revert.args.revertReason,
                revert_decoded: `VaultCallFailed(${vault.parseError(accountError.args[0]).name})`, stranded: true,
                forward: collected.result.transactionHash, forward_paid_out_wei: forward.settled.args.paidOut.toString(), ...margin };
        });
        stopAfter('gasless-griefing');

        await scenario('replay before inclusion: a third party lands the public close calldata directly while the sponsored operation waits; the bundle fails validation (the bundler pays, the float and the attempts do not move) and the payout waiting in S is swept to the payee', async () => {
            const sdk = await gaslessClient();
            const note = await gaslessDeposit(sdk);
            const payee = freshAddress();
            const S = await transitOf(account.gaslessSdk, payee);
            const { closing, pendingOp } = await deferredSponsoredClose(sdk, payee);
            bundler.defer();
            const vaultCall = vaultCallOf(pendingOp.json.callData);
            const replay = await sendTx({ from: account.thirdParty, to: vaultAddress, data: vaultCall });
            assert.equal(replay.status, '0x1', 'anyone can land the public calldata');
            assert.equal(eventOf(replay, 'MutualClose').args.destination.toLowerCase(), S);
            const payoutWei = eventOf(replay, 'MutualClose').args.finalBalance * GWEI;
            const attemptsKey = await pmRead('keyFor', [1, BigInt(vault.decodeFunctionData('mutualClose', vaultCall)[0].withdrawalNullifier), 0, S]);
            assert.equal(Number(await pmRead('attempts', [attemptsKey])), 0, 'no attempt before the bundle');
            const floatBefore = await floatWei();
            const bundlerBefore = await balance(account.bundler);
            const flushed = await bundler.flush();
            bundler.release();
            assert.equal(flushed.receipt.status, '0x0', 'on-chain validation refused the operation: the whole bundle reverted');
            assert.deepEqual(flushed.bundle.hashes, [pendingOp.hash], 'the bundle carried the sponsored operation alone');
            // Why the bundle reverted: the same handleOps replayed with
            // eth_call on the state its block left (a reverted bundle changes
            // nothing) answers the EntryPoint's FailedOpWithRevert.
            const bundleTx = await rpc('eth_getTransactionByHash', [flushed.receipt.transactionHash]);
            let failedOp = null;
            try {
                await rpc('eth_call', [{ from: bundleTx.from, to: bundleTx.to, data: bundleTx.input, gas: bundleTx.gas }, flushed.receipt.blockNumber]);
            } catch (error) {
                assert.ok(error instanceof RpcCallError && error.data, `no revert data: ${error.message}`);
                failedOp = decodeFailedOp(error.data);
            }
            assert.ok(failedOp, 'handleOps reverts with FailedOp');
            assert.equal(failedOp.opIndex, 0);
            assert.equal(failedOp.aa, 'AA33', `the paymaster's validation refused the operation: ${json(failedOp)}`);
            assert.equal(failedOp.inner?.slice(0, 10), paymaster.getError('NoteNotActive').selector, `NoteNotActive: ${json(failedOp)}`);
            const bundlerFee = BigInt(flushed.receipt.gasUsed) * BigInt(flushed.receipt.effectiveGasPrice);
            assert.equal(bundlerBefore - await balance(account.bundler), bundlerFee, 'the bundler paid for the failed bundle');
            assert.equal(await floatWei(), floatBefore, 'the float paid nothing');
            assert.equal(Number(await pmRead('attempts', [attemptsKey])), 0, 'the attempts did not move');
            assert.equal(await pmRead('stranded', [S]), false, 'nothing recorded: no sponsored execution happened');
            assert.equal(await balance(S), payoutWei, 'the payout sits in S');
            const failure = await closing;
            const refusal = failure.error?.sdk ?? null;
            assert.equal(refusal?.code, 'note_not_active', `the SDK refuses: the note was closed by someone else: ${json(refusal ?? failure.value?.result)}`);
            // The SDK's own record of the note closed by someone else, with the payout waiting in S.
            const waiting = await waitFor('the SDK records the payout waiting in S', async () => {
                const state = await sdk('sync');
                const record = sdkRecord(state, note.noteId);
                return record && record.transit && { state, record };
            }, 120_000, 2_000).catch(error => { throw new Error(`${error.message}; the withdraw ended ${json(failure.error?.sdk ?? failure.value?.result)}`); });
            const collect = await sdkRefusal(sdk('collect', { recordId: waiting.record.recordId }));
            assert.equal(collect.code, 'transit_not_stranded', json(collect));
            const before = await balances(payee, account.gaslessSdk);
            const sentBefore = (await sdk('snapshot')).sent.length;
            const swept = await sdk('sweep', { recordId: waiting.record.recordId });
            assert.equal(swept.result?.status, 'swept', json(swept.result));
            assert.equal(swept.sent.length - sentBefore, 2, 'two wallet transactions: createAccount, sweep');
            assert.deepEqual(swept.sent.slice(sentBefore).map(item => item.hash.toLowerCase()),
                [swept.result.createTransactionHash.toLowerCase(), swept.result.transactionHash.toLowerCase()], 'createAccount, then sweep');
            const createReceipt = await waitReceipt(swept.result.createTransactionHash);
            const sweepReceipt = await waitReceipt(swept.result.transactionHash);
            const collected = sponsoredOutcome(sweepReceipt, S).collected;
            assert.ok(collected, 'Collected(S)');
            assert.equal(collected.args.received, payoutWei);
            assert.equal(collected.args.paidOut, payoutWei);
            const after = await balances(payee);
            assert.equal(after[payee] - before[payee], payoutWei, 'the payee received the whole payout');
            assert.equal(await balance(S), 0n);
            gas.record('gasless_create_account', createReceipt, { client: 'sdk', note_id: note.noteId });
            gas.record('gasless_sweep', sweepReceipt, { client: 'sdk', note_id: note.noteId });
            return { note_id: note.noteId, transit_account: S, replay: replay.transactionHash, failed_bundle: flushed.receipt.transactionHash,
                bundle_failure: { aa: failedOp.aa, reason: failedOp.reason, inner: failedOp.inner }, attempts: 0,
                bundler_paid_wei: bundlerFee.toString(), float_paid_wei: '0', sdk_withdraw: { code: refusal.code, user_op_sent: refusal.user_op_sent },
                wallet_transactions: 2, collect_refusal: collect.code, sweep: swept.result.transactionHash,
                create_account: swept.result.createTransactionHash, paid_out_wei: payoutWei.toString() };
        });
        stopAfter('gasless-replay');

        await scenario('post-prepare fallback: the bundler stops after the proof; the wallet pays the direct vault call to S (the plan stays bound to S), then sweepTransit creates S and forwards the payout (two transactions)', async () => {
            const sdk = await gaslessClient();
            const note = await gaslessDeposit(sdk);
            const payee = freshAddress();
            const S = await transitOf(account.gaslessSdk, payee);
            bundler.hold(['eth_sendUserOperation']);
            let refusal;
            try {
                refusal = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: payee, fees: 'payout' }));
            } finally {
                bundler.release();
            }
            assert.equal(refusal.code, 'bundler_unavailable', json(refusal));
            const held = await sdk('snapshot');
            assert.equal(held.prepared?.destination?.toLowerCase(), S, 'the proof is bound to S');
            // fees: 'wallet' on the prepared plan: the ordinary vault transaction, destination S.
            const direct = await sdk('withdraw', { mode: 'mutual', destination: payee, fees: 'wallet' });
            const closeTx = direct.sent.slice(note.sent).find(item => item.data === vault.getFunction('mutualClose').selector);
            assert.ok(closeTx, json(direct.statuses));
            const closeReceipt = await waitReceipt(closeTx.hash);
            const closeEvent = eventOf(closeReceipt, 'MutualClose');
            assert.equal(closeEvent.args.destination.toLowerCase(), S);
            const payoutWei = closeEvent.args.finalBalance * GWEI;
            assert.equal(await balance(S), payoutWei);
            assert.equal(await rpc('eth_getCode', [S, 'latest']), '0x');
            const record = await waitFor('the SDK records the payout waiting in S', async () => {
                const state = await sdk('sync');
                const found = sdkRecord(state, note.noteId);
                return found?.transit && found;
            }, 90_000, 2_000);
            const before = await balances(payee);
            const swept = await sdk('sweep', { recordId: record.recordId });
            assert.equal(swept.result?.status, 'swept', json(swept.result));
            assert.ok(swept.result.createTransactionHash, 'S had no code: createAccount first');
            const createReceipt = await waitReceipt(swept.result.createTransactionHash);
            const sweepReceipt = await waitReceipt(swept.result.transactionHash);
            const collected = sponsoredOutcome(sweepReceipt, S).collected;
            assert.ok(collected, 'Collected(S)');
            assert.equal(collected.args.paidOut, payoutWei);
            assert.equal((await balances(payee))[payee] - before[payee], payoutWei);
            assert.equal(swept.sent.length - direct.sent.length, 2, 'two wallet transactions: createAccount, sweep');
            gas.record('gasless_create_account', createReceipt, { client: 'sdk', note_id: note.noteId });
            gas.record('gasless_sweep', sweepReceipt, { client: 'sdk', note_id: note.noteId });
            return { note_id: note.noteId, transit_account: S, refusal: refusal.code, direct_close: closeTx.hash,
                create_account: swept.result.createTransactionHash, sweep: swept.result.transactionHash, paid_out_wei: payoutWei.toString() };
        });
        stopAfter('gasless-fallback');

        // ---------------------------------------------------------------- gasless escapes
        // The harness as zkapi-clientd (design §3.3): an ephemeral owner key
        // per withdrawal, the operation's gas fields from the profile's
        // pinned policy, the fees within the paymaster's ceilings, an
        // EIP-191 signature over the operation hash, the bundler's JSON-RPC.
        async function clientdOperation({ owner, payee, kind, vaultCall, nonceKey }) {
            const S = await transitOf(owner.address, payee);
            const withInitCode = await rpc('eth_getCode', [S, 'latest']) === '0x';
            const nonce = await contractRead(entryPoint, entryPointAddress, 'getNonce', [S, nonceKey]);
            const base = BigInt((await rpc('eth_getBlockByNumber', ['latest', false])).baseFeePerGas);
            const min = (a, b) => (a < b ? a : b);
            const tip = min(BigInt(await rpc('eth_maxPriorityFeePerGas')), await pmRead('priorityFeeCeiling'));
            const maxFee = min(2n * base + tip, await pmRead('maxFeeCeiling'));
            const flatFee = (await pmRead('policy')).flatFeeWei;
            const op = { sender: S, nonce: hex(nonce),
                ...(withInitCode ? { factory: factoryAddress, factoryData: accountFactory.encodeFunctionData('createAccount', [owner.address, payee]) } : {}),
                callData: transitAbi.encodeFunctionData('withdraw', [vaultCall]), callGasLimit: hex(gasPolicy.call_default[kind - 1]),
                verificationGasLimit: hex(withInitCode ? gasPolicy.verification_default_init : gasPolicy.verification_default),
                preVerificationGas: '0x0', maxFeePerGas: hex(maxFee), maxPriorityFeePerGas: hex(tip), paymaster: paymasterAddress,
                paymasterVerificationGasLimit: hex(gasPolicy.pm_verification_default), paymasterPostOpGasLimit: hex(gasPolicy.postop_default),
                paymasterData: `0x${BigInt(flatFee).toString(16).padStart(24, '0')}`, signature: `0x${'00'.repeat(65)}` };
            const bytes = (encodeHandleOps([packUserOperation(op)], account.bundler).length - 2) / 2;
            op.preVerificationGas = hex(Math.min(Math.max(21_000 + 16 * bytes + 10_000, gasPolicy.pvg_floor), gasPolicy.pvg_cap));
            const hash = userOperationHash(packUserOperation(op), entryPointAddress, CHAIN_ID);
            op.signature = (await owner.signMessage(getBytes(hash))).toLowerCase();
            return { op, hash, S, withInitCode, maxCost: maxCostOf(op) };
        }
        async function clientdSend({ op, hash }) {
            const answered = await rpcAt(bundler.url, 'eth_sendUserOperation', [op, entryPointAddress]);
            assert.equal(answered, hash, 'the bundler returns the locally computed hash');
            const included = await waitFor(`the bundler's receipt of ${hash}`, () => rpcAt(bundler.url, 'eth_getUserOperationReceipt', [hash]), 60_000, 300);
            assert.equal(included.userOpHash, hash);
            return rpc('eth_getTransactionReceipt', [included.receipt.transactionHash]);
        }
        const gaslessEscapes = [];

        await scenario('gasless escape as zkapi-clientd (ephemeral owner key): the companion proves an early escape to S, the sponsored initiation records S\'s debt, the challenger raises the concession', async () => {
            await startServer(null, { keySource: 'oa_org' });
            const companion = await startCompanion('gasless');
            const noteId = await companionDeposit(companion, GASLESS_ESCAPE_UNITS);
            await companionRequest(companion);
            const owner = Wallet.createRandom();
            const payee = freshAddress();
            const S = await transitOf(owner.address, payee);
            gate.mode = 'down';
            let prepared;
            try {
                const decision = await companion.call('POST', '/oa/v1/withdraw/escape/prepare', { destination: S, early_exit: 'concede_nothing' });
                assert.equal(decision.status, 200, json(decision.value));
                prepared = decision.value.status === 'prepared' ? decision.value : (await companion.call('POST', '/oa/v1/withdraw/escape/prepare',
                    { destination: S, conceded: String(decision.value.conceded ?? '0'), early_exit: 'concede_nothing' })).value;
                assert.equal(prepared.status, 'prepared', json(prepared));
                assert.equal(String(prepared.conceded), '0');
            } finally {
                gate.mode = 'pass';
            }
            const escapeCall = vault.parseTransaction({ data: prepared.calldata });
            assert.equal(escapeCall.name, 'initiateEscapeWithdrawal');
            assert.equal(escapeCall.args.inputs.destination.toLowerCase(), S, 'the proof names the transit account');
            const nullifier = BigInt(escapeCall.args.inputs.withdrawalNullifier);
            const floatBefore = await floatWei();
            const built = await clientdOperation({ owner, payee, kind: 2, vaultCall: prepared.calldata, nonceKey: nullifier & ((1n << 192n) - 1n) });
            assert.ok(built.withInitCode);
            const receipt = await clientdSend(built);
            const outcome = sponsoredOutcome(receipt, S);
            assert.ok(outcome.op?.args.success, json(outcome.paymasterEvents));
            assert.ok(outcome.deployed, 'S created by the escape operation');
            const initiated = eventOf(receipt, 'EscapeWithdrawalInitiated');
            assert.equal(Number(initiated.args.noteId), noteId);
            const owed = outcome.owed.args.owedWei;
            assert.equal(await pmRead('owed', [S]), owed, 'the initiation is S\'s debt');
            assert.equal(outcome.settled.args.charged, owed);
            assert.equal(outcome.settled.args.received, 0n, 'nothing is paid at initiation');
            assert.equal(await pmRead('escapeSponsored', [noteId]), true);
            assert.equal(await pmRead('escapeNotePlusOne', [S]), BigInt(noteId) + 1n);
            const margin = chargeWithinMargin(outcome); // the recorded debt is the measured charge
            assert.equal(await floatWei() - floatBefore, 0n - outcome.op.args.actualGasCost, 'the float advanced the initiation');
            gas.record('gasless_escape', receipt, { client: 'clientd', note_id: noteId, user_op_hash: built.hash, owed_wei: owed.toString(), ...margin });
            const submitted = await companion.call('POST', '/oa/v1/withdraw/escape/submit', { transaction_hash: receipt.transactionHash });
            assert.equal(submitted.status, 200, json(submitted.value));
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(receipt.blockNumber)), (TIMING.leaseTtl + 120) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            await startServer();
            gaslessEscapes.push({ name: 'clientd-gasless', client: 'clientd', companion, owner, payee, S, noteId, owed,
                finalBalance: GASLESS_ESCAPE_UNITS - INFERENCE_CHARGE });
            return { note_id: noteId, owner: owner.address.toLowerCase(), payee, transit_account: S, user_op_hash: built.hash,
                bundle: receipt.transactionHash, owed_wei: owed.toString(), actual_gas_cost_wei: outcome.op.args.actualGasCost.toString(),
                raise: raised.event.transactionHash, raised_to: INFERENCE_CHARGE };
        });
        stopAfter('gasless-escape');

        let gaslessPauseNote = null;
        await scenario('gasless escape through the SDK: a sponsored initiation (escapes enabled for the drill) records the debt; a second balance is deposited beside it', async () => {
            const sdk = await gaslessClient();
            const note = await gaslessDeposit(sdk, '0.05');
            const payee = freshAddress();
            const S = await transitOf(account.gaslessSdk, payee);
            const escaped = await sdk('withdraw', { mode: 'escape', destination: payee, fees: 'payout' });
            assert.equal(escaped.result?.status, 'pending_withdrawal', json(escaped.result));
            assert.equal(escaped.sent.length, note.sent, 'no wallet transaction');
            const receipt = await rpc('eth_getTransactionReceipt', [escaped.result.transactionHash]);
            const outcome = sponsoredOutcome(receipt, S);
            assert.ok(outcome.op?.args.success);
            const owed = outcome.owed.args.owedWei;
            assert.equal(escaped.result.initiationDebtWei, owed.toString(), 'the SDK records the debt');
            assert.equal(await pmRead('owed', [S]), owed);
            assert.equal(outcome.settled.args.charged, owed, 'the debt is the initiation\'s measured charge');
            const margin = chargeWithinMargin(outcome);
            gas.record('gasless_escape', receipt, { client: 'sdk', note_id: note.noteId, user_op_hash: outcome.op.args.userOpHash.toLowerCase(), owed_wei: owed.toString(), ...margin });
            gaslessEscapes.push({ name: 'sdk-gasless', client: 'sdk', sdk, payee, S, noteId: note.noteId, owed,
                finalBalance: Number((await vaultRead('pendingWithdrawals', [note.noteId]))[3]), recordId: escaped.result.recordId });
            // A second balance beside the pending escape: the pause drill's.
            gaslessPauseNote = await gaslessDeposit(sdk);
            return { note_id: note.noteId, transit_account: S, payee, escape: escaped.result.transactionHash, owed_wei: owed.toString(),
                decision: escaped.result.decision ?? null, second_note: gaslessPauseNote.noteId };
        });
        stopAfter('gasless-sdk-escape');

        // Prepared now, abandoned, replayed after its valid_until.
        const replay = { client: await wallet('replay') };
        Object.assign(replay, await driverDeposit(replay.client));
        replay.abandoned = await driverEscape(replay.client, replay.noteId, { validUntil: (await chainNow()) + 600, path: replay.depositPath, send: false });
        assert.equal(await revertName(replay.abandoned.plan.calldata), null, 'the abandoned proof would still land now');
        // The missed-defeat note: two settled requests, so a request at the
        // genesis state's successor exists.
        const missed = { client: await wallet('missed') };
        Object.assign(missed, await driverDeposit(missed.client));
        missed.genesis = await missed.client('snapshot', { name: 'S0' });
        missed.requests = [await honestRequest(missed.client, missed.noteId, 'missed-0'), await honestRequest(missed.client, missed.noteId, 'missed-1')];

        // ---------------------------------------------------------------- pause
        async function finalizePending(entry) {
            const before = await balances(entry.destination, treasury);
            let receipt;
            if (entry.client === 'sdk') {
                // Skipping time moved only block time: the device clock
                // catches up with it before the SDK judges the deadline.
                const lead = await chainNow() - wallNow();
                const offset = (await entry.sdk('snapshot')).device_clock_offset_seconds;
                if (lead + 60 > offset) await entry.sdk('clock', { offsetSeconds: lead + 60 });
                const finalized = await entry.sdk('finalize', { recordId: null });
                const tx = finalized.sent.find(item => item.data === vault.getFunction('finalizeEscapeWithdrawal').selector);
                assert.ok(tx, `the SDK sent no finalization: ${json(finalized)}`);
                receipt = await waitReceipt(tx.hash);
            } else {
                receipt = await vaultSend(account.thirdParty, 'finalizeEscapeWithdrawal', [entry.noteId]);
            }
            assert.equal(receipt.status, '0x1');
            const finalizedEvent = eventOf(receipt, 'EscapeWithdrawalFinalized');
            const deferredEvent = eventOf(receipt, 'EscapePayoutDeferred');
            gas.record(deferredEvent ? 'finalize_deferred' : 'finalize', receipt, { note_id: entry.noteId });
            assert.equal(finalizedEvent.args.finalBalance, BigInt(entry.payout), `${entry.name}: payout`);
            assert.equal((await noteView(entry.noteId)).status, NOTE.Closed);
            const after = await balances(entry.destination, treasury);
            assert.equal(after[treasury] - before[treasury], BigInt(DEPOSIT - entry.payout) * GWEI, `${entry.name}: treasury share`);
            if (entry.deferred) {
                assert.ok(deferredEvent, `${entry.name}: the push must fail and be credited`);
                assert.equal(after[entry.destination], before[entry.destination]);
                assert.equal(await vaultRead('escapePayoutCredits', [entry.destination]), BigInt(entry.payout) * 1n);
            } else {
                assert.equal(after[entry.destination] - before[entry.destination], BigInt(entry.payout) * GWEI, `${entry.name}: destination`);
            }
            // The wallet core keeps the state it exited from (it has no exit
            // records of its own): the finalized escape is the one it proved,
            // from the state it holds, or (a stale escape) from the snapshot.
            let driverState = null;
            if (entry.client === 'driver') {
                assert.equal(BigInt(finalizedEvent.args.nullifier), BigInt(entry.exitedNullifier), `${entry.name}: the escape the wallet proved`);
                const status = await entry.wallet('status');
                assert.equal(BigInt(status.withdrawal_nullifier) === BigInt(entry.exitedNullifier), !entry.staleSnapshot,
                    `${entry.name}: the wallet holds ${entry.staleSnapshot ? 'a newer state than the stale one it escaped' : 'the state it escaped'}`);
                assert.equal(status.pending_request, false, `${entry.name}: no request is pending`);
                if (!entry.staleSnapshot) {
                    assert.equal(Number(status.state.note.current_balance), entry.stateBalance, `${entry.name}: the escaped balance`);
                }
                driverState = { exited_nullifier: felt(entry.exitedNullifier), wallet_nullifier: felt(status.withdrawal_nullifier),
                    wallet_balance: Number(status.state.note.current_balance), escaped_from: entry.staleSnapshot ?? 'current state' };
            }
            return { receipt, deferred: Boolean(deferredEvent), driverState };
        }
        // An SDK escape record once its payout is final: closed with the
        // concession that was paid (conceded_final), no payout alert, and no
        // note left.
        function sdkFinalState(entry, after) {
            assert.equal(after.state.note, null, `${entry.name}: the SDK holds no note after the payout`);
            assert.equal(String(after.record.concededFinal), String((entry.stateBalance ?? DEPOSIT) - entry.payout), `${entry.name}: concededFinal`);
            assert.equal(after.record.payoutAlert ?? null, null, `${entry.name}: no payout alert`);
            return { phase: after.record.phase, conceded_final: after.record.concededFinal, payout_alert: null,
                payout_credited: after.record.payoutCredited === true };
        }
        await scenario('pause with escapes pending, then finalize while paused (deferred credit and claim; SDK and companion close)', async () => {
            await challengerQuiet();
            const paused = await vaultSend(owner, 'pause', [], { operation: 'pause' });
            assert.equal(paused.status, '0x1');
            assert.equal(await vaultRead('paused'), true);
            // New exits are blocked while paused (until maxPauseDuration).
            const blocked = await driverEscape(replay.client, replay.noteId, { path: replay.depositPath, send: false });
            assert.equal(await revertName(blocked.plan.calldata), 'Paused');
            const deadlines = await Promise.all(pendingEscapes.map(async entry => Number((await vaultRead('pendingWithdrawals', [entry.noteId]))[5])));
            await skipChain(Math.max(...deadlines) - await chainNow() + 5, 'challenge period, while paused');
            const results = {};
            for (const entry of pendingEscapes.splice(0)) {
                const { receipt, deferred, driverState } = await finalizePending(entry);
                results[entry.name] = { finalize: receipt.transactionHash, payout_gwei: entry.payout, deferred };
                if (entry.deferred) {
                    const claimed = await vaultSend(account.thirdParty, 'claimEscapePayout', [entry.destination], { operation: 'claim_escape_payout' });
                    assert.equal(claimed.status, '0x1');
                    assert.equal(await vaultRead('escapePayoutCredits', [entry.destination]), 0n);
                    assert.equal((await balances(entry.destination))[entry.destination] - entry.before[entry.destination], BigInt(entry.payout) * GWEI);
                    results[entry.name].claim = claimed.transactionHash;
                }
                if (entry.client === 'companion') {
                    const closed = await waitFor('the companion records the finalized escape', async () => {
                        const answer = await entry.companion.call('POST', '/oa/v1/withdraw/escape/finalize', { transaction_hash: receipt.transactionHash });
                        return answer.status === 200 && answer.value.status === 'complete' && answer.value;
                    }, 60_000, 1_000);
                    assert.equal(closed.payout, String(entry.payout));
                    assert.equal(closed.conceded_final, String(DEPOSIT - entry.payout));
                    const wallet = await entry.companion.call('GET', '/status');
                    assert.equal(wallet.status, 200);
                    assert.equal(wallet.value.has_note, false, `the companion still holds the note: ${json(wallet.value)}`);
                    assert.equal(wallet.value.note ?? null, null);
                    results[entry.name].client_final_state = { phase: closed.record?.phase ?? closed.status, payout: closed.payout,
                        conceded_final: closed.conceded_final, has_note: wallet.value.has_note };
                }
                if (entry.client === 'sdk') {
                    const after = await waitFor('the SDK closes the escape record', async () => {
                        const state = await entry.sdk('sync');
                        const record = state.withdrawals.find(item => Number(item.noteId) === entry.noteId);
                        return record?.phase === 'closed' && { state, record };
                    }, 90_000, 2_000);
                    results[entry.name].client_final_state = sdkFinalState(entry, after);
                }
                if (entry.client === 'driver') results[entry.name].client_final_state = driverState;
            }
            assert.equal(await vaultRead('paused'), true, 'every finalization ran while paused');
            return { paused: paused.transactionHash, escapes: results };
        });
        stopAfter('pause');

        await scenario('gasless under the pause: sponsored closes refused before any proof (exits_paused); the sponsored finalization (zkapi-clientd) and the forward of a third party\'s finalization (SDK) land while paused, each settling S\'s debt', async () => {
            assert.equal(await vaultRead('paused'), true);
            // (a) A sponsored close is refused in the pre-flight, before the
            // proof binds S, with the time exits reopen.
            const availability = await gaslessSdk('availability', { mode: 'mutual', destination: gaslessPayee });
            assert.equal(availability.result.available, false);
            assert.equal(availability.result.reason, 'exits_paused', json(availability.result));
            const reopenAt = Number(await vaultRead('pausedAt')) + TIMING.maxPauseDuration;
            const beforeRefusal = await gaslessSdk('snapshot');
            const refusal = await sdkRefusal(gaslessSdk('withdraw', { mode: 'mutual', destination: gaslessPayee, fees: 'payout' }));
            assert.equal(refusal.code, 'exits_paused', json(refusal));
            assert.equal(Number(refusal.data?.reopenAt), reopenAt, 'the refusal names when exits reopen');
            const afterRefusal = await gaslessSdk('snapshot');
            assert.equal(afterRefusal.prepared, null, 'nothing was proved');
            assert.equal(afterRefusal.signatures.length, beforeRefusal.signatures.length, 'nothing was signed');
            // Both sponsored escapes are past their deadline.
            const deadlines = await Promise.all(gaslessEscapes.map(async entry => Number((await vaultRead('pendingWithdrawals', [entry.noteId]))[5])));
            const now = await chainNow();
            if (Math.max(...deadlines) >= now) await skipChain(Math.max(...deadlines) - now + 5, 'the gasless escapes\' challenge period, while paused');
            const results = {};
            // (b) zkapi-clientd's sponsored FINALIZE: not gated by the pause.
            const clientd = gaslessEscapes.find(entry => entry.client === 'clientd');
            const pending = await vaultRead('pendingWithdrawals', [clientd.noteId]);
            assert.equal(Number(pending[3]), clientd.finalBalance, 'the raised balance B − c_final');
            const finalize = await clientdOperation({ owner: clientd.owner, payee: clientd.payee, kind: 3,
                vaultCall: vault.encodeFunctionData('finalizeEscapeWithdrawal', [clientd.noteId]), nonceKey: BigInt(pending[2]) & ((1n << 192n) - 1n) });
            assert.equal(finalize.withInitCode, false);
            const before = await balances(clientd.payee, treasury);
            const receipt = await clientdSend(finalize);
            const outcome = sponsoredOutcome(receipt, clientd.S);
            assert.ok(outcome.op?.args.success, json(outcome.paymasterEvents));
            const finalized = eventOf(receipt, 'EscapeWithdrawalFinalized');
            assert.equal(finalized.args.finalBalance, BigInt(clientd.finalBalance));
            const settled = outcome.settled.args;
            assert.equal(Number(settled.kind), 3);
            assert.equal(settled.received, BigInt(clientd.finalBalance) * GWEI);
            assert.equal(settled.owedPaid, clientd.owed, 'the initiation\'s debt is settled first');
            assert.equal(outcome.shortfall, null, 'the raise preceded validation: no shortfall');
            const shortfallWei = await pmRead('shortfallWei');
            assert.equal(shortfallWei, 0n, 'no shortfall was ever written off');
            const paid = BigInt(clientd.finalBalance) * GWEI - clientd.owed - settled.charged;
            assert.equal(settled.paidOut, paid);
            const after = await balances(clientd.payee, treasury);
            assert.equal(after[clientd.payee] - before[clientd.payee], paid, 'the payee receives B − c_final − owed − charge');
            assert.equal(after[treasury] - before[treasury], BigInt(GASLESS_ESCAPE_UNITS - clientd.finalBalance) * GWEI);
            assert.equal(await pmRead('owed', [clientd.S]), 0n);
            assert.equal(await pmRead('escapeNotePlusOne', [clientd.S]), 0n);
            assert.equal(await balance(clientd.S), 0n);
            const margin = chargeWithinMargin(outcome);
            gas.record('gasless_finalize', receipt, { client: 'clientd', note_id: clientd.noteId, ...margin });
            const completed = await waitFor('the companion records the finalized escape', async () => {
                const answer = await clientd.companion.call('POST', '/oa/v1/withdraw/escape/finalize', { transaction_hash: receipt.transactionHash });
                return answer.status === 200 && answer.value.status === 'complete' && answer.value;
            }, 60_000, 1_000);
            assert.equal(completed.payout, String(clientd.finalBalance));
            assert.equal(completed.conceded_final, String(INFERENCE_CHARGE));
            const companionWallet = await clientd.companion.call('GET', '/status');
            assert.equal(companionWallet.value.has_note, false);
            await stop(clientd.companion.child);
            results.clientd = { note_id: clientd.noteId, finalize: receipt.transactionHash, owed_paid_wei: settled.owedPaid.toString(),
                charged_wei: settled.charged.toString(), paid_out_wei: paid.toString(), ...margin,
                shortfall_wei: shortfallWei.toString(), shortfall_note: 'the Shortfall settlement is covered by the Forge suite (PostOp.t.sol) only: the drill\'s raise cannot bring B − c_final below owed + charge',
                companion: { status: completed.status, payout: completed.payout, conceded_final: completed.conceded_final } };
            // (c) A third party finalizes the SDK's sponsored escape: the
            // payout lands in S, and the SDK's finalizeEscape goes straight
            // to the sponsored FORWARD, which settles the debt.
            const sdkEscape = gaslessEscapes.find(entry => entry.client === 'sdk');
            const third = await vaultSend(account.thirdParty, 'finalizeEscapeWithdrawal', [sdkEscape.noteId], { operation: 'finalize' });
            assert.equal(eventOf(third, 'EscapeWithdrawalFinalized').args.destination.toLowerCase(), sdkEscape.S);
            const inTransit = await balance(sdkEscape.S);
            assert.equal(inTransit, BigInt(sdkEscape.finalBalance) * GWEI);
            const lead = await chainNow() - wallNow();
            await gaslessSdk('clock', { offsetSeconds: Math.max(0, lead + 60) });
            const payeeBefore = await balance(sdkEscape.payee);
            const ownerBefore = await balance(account.gaslessSdk);
            const sentBefore = (await gaslessSdk('snapshot')).sent.length;
            const sendsBefore = bundler.sends.length;
            const forwarded = await gaslessSdk('finalize', { recordId: sdkEscape.recordId });
            assert.equal(forwarded.result?.status, 'collected', json(forwarded.result));
            // Straight to FORWARD: no sponsored FINALIZE attempted, no wallet transaction.
            const sendsOfS = bundler.sends.slice(sendsBefore).filter(item => item.sender === sdkEscape.S);
            assert.ok(sendsOfS.length >= 1 && sendsOfS.every(item => item.kind === 4), `only FORWARD operations from S: ${json(sendsOfS)}`);
            assert.ok(!bundler.sends.some(item => item.sender === sdkEscape.S && item.kind === 3), 'S never sent a sponsored FINALIZE');
            assert.equal(forwarded.sent.length, sentBefore, 'the wallet sent no transaction');
            assert.equal(await balance(account.gaslessSdk), ownerBefore, 'the connected account paid nothing');
            const forwardReceipt = await rpc('eth_getTransactionReceipt', [forwarded.result.transactionHash]);
            const forward = sponsoredOutcome(forwardReceipt, sdkEscape.S);
            assert.ok(forward.op?.args.success);
            assert.equal(Number(forward.settled.args.kind), 4);
            assert.equal(forward.settled.args.owedPaid, sdkEscape.owed, 'the forward collects S\'s debt');
            const forwardPaid = inTransit - sdkEscape.owed - forward.settled.args.charged;
            assert.equal(forward.settled.args.paidOut, forwardPaid);
            assert.equal(await balance(sdkEscape.payee) - payeeBefore, forwardPaid);
            assert.equal(await pmRead('owed', [sdkEscape.S]), 0n);
            assert.equal(await balance(sdkEscape.S), 0n);
            const forwardMargin = chargeWithinMargin(forward);
            gas.record('gasless_forward', forwardReceipt, { client: 'sdk', note_id: sdkEscape.noteId, after: 'third-party finalization', ...forwardMargin });
            await gaslessSdk('clock', { offsetSeconds: 0 });
            results.sdk = { note_id: sdkEscape.noteId, third_party_finalize: third.transactionHash, forward: forwarded.result.transactionHash,
                bundler_sends: sendsOfS.map(item => ({ kind: item.kind, outcome: item.outcome })), wallet_transactions: 0,
                owed_paid_wei: forward.settled.args.owedPaid.toString(), paid_out_wei: forwardPaid.toString(), ...forwardMargin };
            assert.equal(await vaultRead('paused'), true, 'all of it while paused');
            return { refusal_before_proof: refusal.code, reopen_at: reopenAt, ...results };
        });
        stopAfter('gasless-pause');

        await scenario('pause past maxPauseDuration: exits reopen while paused; re-pause cooldown; abandoned proof replay after valid_until', async () => {
            const pausedAt = Number(await vaultRead('pausedAt'));
            await skipChain(pausedAt + TIMING.maxPauseDuration - await chainNow() + 1, 'past maxPauseDuration');
            assert.equal(await vaultRead('paused'), true);
            // The paymaster refuses every sponsored close and escape while the
            // vault is paused, also past maxPauseDuration (it cannot read the
            // clock in validation): the SDK still answers exits_paused, with a
            // reopenAt already past. Exits go through the wallet path here.
            const pausedAvailability = await gaslessSdk('availability', { mode: 'mutual', destination: gaslessPayee });
            assert.equal(pausedAvailability.result.available, false);
            assert.equal(pausedAvailability.result.reason, 'exits_paused', json(pausedAvailability.result));
            const staleReopenAt = Number(pausedAvailability.result.data?.reopenAt);
            assert.equal(staleReopenAt, pausedAt + TIMING.maxPauseDuration);
            assert.ok(staleReopenAt < await chainNow(), 'the reopenAt the SDK names has already passed');
            // The abandoned proof is past its valid_until: nobody can land it.
            assert.equal(await revertName(replay.abandoned.plan.calldata), 'ProofExpired');
            const replayed = await sendTx({ from: account.thirdParty, to: vaultAddress, data: replay.abandoned.plan.calldata, gasLimit: 1_000_000 });
            assert.equal(replayed.status, '0x0');
            gas.record('escape_expired_proof_reverts', replayed);
            // A fresh escape lands although the vault is still paused.
            const escape = await driverEscape(replay.client, replay.noteId, { path: replay.depositPath });
            pendingEscapes.push({ name: 'driver-escape-after-pause', client: 'driver', wallet: replay.client, noteId: replay.noteId,
                destination: account.destination, payout: DEPOSIT, exitedNullifier: escape.plan.public_inputs.withdrawal_nullifier,
                stateBalance: DEPOSIT });
            const unpaused = await vaultSend(owner, 'unpause', [], { operation: 'unpause' });
            assert.equal(unpaused.status, '0x1');
            assert.equal(await revertName(vault.encodeFunctionData('pause', []), owner), 'PauseCooldown');
            return { paused_at: pausedAt, gasless_while_paused: { reason: pausedAvailability.result.reason, reopen_at: staleReopenAt,
                wallet_path: 'the escape below lands from the wallet' },
                escape_while_paused: escape.receipt.transactionHash, abandoned_proof: 'ProofExpired',
                repause: 'PauseCooldown' };
        });
        stopAfter('pause-max');

        await scenario('gasless close after the pause: sponsored closes resume once the vault is unpaused', async () => {
            assert.equal(await vaultRead('paused'), false);
            const snapshot = await gaslessSdk('snapshot');
            assert.equal(Number(snapshot.note?.note_id), gaslessPauseNote.noteId, 'the second balance is still held');
            const note = { noteId: gaslessPauseNote.noteId, units: Number(snapshot.note.current_balance), deposit: gaslessPauseNote.deposit,
                sent: snapshot.sent.length,
                signatures: snapshot.signatures.length };
            const result = await sdkSponsoredClose(gaslessSdk, note, gaslessPayee, { operation: 'gasless_close_repeat' });
            await gaslessSdk.close();
            return { note_id: note.noteId, bundle: result.receipt.transactionHash, charged_wei: result.settled.charged.toString(),
                paid_out_wei: result.settled.paidOut.toString(), ...result.margin };
        });
        stopAfter('gasless-reopen');

        // ================================================================ adversarial operators (drill build)
        // A signed successor at a non-derived anchor (S4) or above the bound
        // (S3): the wallet refuses it, and the request circuit cannot spend
        // it. The exit then follows the client rules (design §6.4 E3), which
        // this wallet core does not implement, so the harness applies them
        // (the SDK drill after these takes the decision itself):
        // - S4: the response is treated like a withheld successor (§6.1);
        //   the owner exits before T conceding 0 (E3, forced early exit), and
        //   the challenger raises the concession to the settled charge;
        // - S3: the response passes S1, S2, S4 and S6 but cannot be
        //   installed (lost ε): the escape concedes min(charge, bound), here
        //   the bound, at once, and no raise exceeds it.
        async function refusedSuccessor(mode, check) {
            await startServer(mode);
            const client = await wallet(mode);
            const note = await driverDeposit(client);
            let first = null;
            if (mode === 'reuse-anchor') {
                // The first successor this server signs is the honest one; it
                // then signs every later successor at that same anchor.
                first = await honestRequest(client, note.noteId, `${mode}-first`);
            }
            const sent = await driverRequest(client, note.noteId, mode);
            const response = await settledResponse(sent.id);
            const before = await client('status');
            await assert.rejects(client('complete_response', { response }), new RegExp(`invalid_successor: ${check}`));
            const after = await client('status');
            assert.deepEqual(after.state.note, before.state.note, 'a refused successor changes no state');
            assert.equal(after.archived.at(-1).disposition, 'invalid_successor');
            let spend = null;
            if (check === 'S4') {
                const merkle = await treePath(client, note.noteId);
                spend = await client('spend_refused_successor', { args: { response, active_root: merkle.active_root,
                    merkle_siblings: merkle.siblings, request_time: wallNow() } });
                assert.equal(spend.server_signed, true, 'the drill server signed it');
                assert.equal(spend.circuit_satisfied, false, 'the request circuit cannot spend it (Q6a)');
                assert.notEqual(BigInt(spend.next_anchor), BigInt(spend.derived_anchor));
                if (mode === 'born-spent') {
                    assert.equal(BigInt(spend.next_anchor), 1n);
                    assert.equal(BigInt(spend.forced_nullifier), BigInt(spend.genesis_nullifier), 'anchor 1 names the genesis nullifier: born spent');
                }
                if (mode === 'reuse-anchor') assert.equal(BigInt(spend.next_anchor), BigInt(before.state.note.current_anchor));
            }
            const charge = Number(response.charge_applied);
            const bound = Number(after.state.note.bound_at_state);
            if (check === 'S3') assert.equal(charge, bound + 1, 'overcharge: one unit above the bound');
            const rule = check === 'S4' ? 'E3.forced' : 'E3.lost_epsilon';
            const conceded = check === 'S4' ? 0 : Math.min(charge, bound);
            const balanceBefore = Number(after.state.note.current_balance);
            const escape = await driverEscape(client, note.noteId, { conceded, path: note.depositPath });
            // The concession that is paid: the challenger raises an S4 exit to
            // the settled charge; the lost-ε concession already covers what
            // the bound lets it take.
            let raisedTo = null;
            if (check === 'S4') {
                const raised = await waitEvent('EscapeConcessionRaised', note.noteId, Number(BigInt(escape.receipt.blockNumber)));
                gas.record('raise', raised.receipt, { note_id: note.noteId });
                assert.equal(raised.event.args.conceded, BigInt(charge), 'raised to the settled charge');
                raisedTo = charge;
            }
            const concededFinal = raisedTo ?? conceded;
            assert.ok(concededFinal <= bound, 'no concession exceeds the bound');
            pendingEscapes.push({ name: mode, client: 'driver', wallet: client, noteId: note.noteId, destination: account.destination,
                payout: balanceBefore - concededFinal, exitedNullifier: escape.plan.public_inputs.withdrawal_nullifier,
                stateBalance: balanceBefore });
            return { note_id: note.noteId, server_mode: mode, refused_check: check, charge, bound, rule, conceded_at_init: conceded,
                raised_to: raisedTo, wallet_refusal: spend?.wallet_refusal ?? `invalid_successor: ${check}`,
                circuit_satisfied: spend?.circuit_satisfied ?? null, next_anchor: response.next_anchor, escape: escape.receipt.transactionHash,
                client_state: { balance: Number(after.state.note.current_balance), archived: after.archived.at(-1).disposition } };
        }
        await scenario('born-spent successor (anchor 1): client refuses (S4), circuit cannot spend it; escape before T conceding 0, raised to the charge',
            () => refusedSuccessor('born-spent', 'S4'));
        await scenario('reused-anchor successor: client refuses (S4), circuit cannot spend it; escape before T conceding 0, raised to the charge',
            () => refusedSuccessor('reuse-anchor', 'S4'));
        await scenario('random-anchor successor: client refuses (S4), circuit cannot spend it; escape before T conceding 0, raised to the charge',
            () => refusedSuccessor('random-anchor', 'S4'));
        await scenario('overcharged successor: client refuses (S3), lost ε: escape concedes min(charge, bound) = the bound and no raise exceeds it',
            () => refusedSuccessor('overcharge', 'S3'));
        // The same refusal through the SDK, which takes the exit decision
        // itself: the successor fails S4, is archived invalid_successor and
        // handled like a withheld one (E3). A mutual withdrawal waits for T;
        // the owner exits early, conceding nothing (E3.forced), to a
        // destination that cannot take the payout push, and the challenger
        // raises the concession to the settled charge. The SDK claims the
        // credited payout itself at finalization.
        const slowReceiverSdk = '0x00000000000000000000000000000000005104e6';
        await rpc('anvil_setCode', [slowReceiverSdk, '0x346000553460015534600255346003553460045500']);
        await scenario('random-anchor successor through the SDK: refused (S4), treated as withheld; early escape conceding 0 (E3.forced), raised to the charge; deferred payout claimed by the SDK', async () => {
            await startServer('random-anchor');
            const sdk = await sdkAgent('random-anchor', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const chat = await sdk('chat', { sessionId: 'acceptance-random-anchor', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            // Settling installs nothing: the successor fails S4.
            const settle = await sdk('settle').then(() => null, error => error.sdk ?? { message: error.message });
            const held = await sdk('snapshot');
            const record = held.request_archive.at(-1);
            assert.equal(record?.disposition, 'invalid_successor', json(held.request_archive));
            assert.equal(Number(held.note.current_balance), DEPOSIT, 'a refused successor changes no state');
            const waiting = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: slowReceiverSdk }));
            assert.equal(waiting.code, 'request_settlement_pending', json(waiting));
            const escaped = await sdk('withdraw', { mode: 'escape', destination: slowReceiverSdk });
            assert.deepEqual(escaped.result?.decision, { rule: 'E3.forced', conceded: '0' }, json(escaped.result));
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, json(escaped.statuses));
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            assert.equal(eventOf(receipt, 'EscapeConcessionRecorded').args.conceded, 0n);
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(receipt.blockNumber)));
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE), 'raised to the settled charge');
            pendingEscapes.push({ name: 'sdk-random-anchor', client: 'sdk', sdk, noteId, destination: slowReceiverSdk,
                payout: DEPOSIT - INFERENCE_CHARGE, stateBalance: DEPOSIT, deferred: true, recordId: escaped.result.recordId });
            return { note_id: noteId, settle_refusal: settle?.code ?? null, archived: record.disposition, mutual: waiting.code,
                decision: escaped.result.decision, destination_warning: escaped.result.destinationWarning ?? null,
                escape: escapeTx.hash, raised_to: INFERENCE_CHARGE, client_state: { balance: Number(held.note.current_balance) } };
        });
        stopAfter('anchors');

        await scenario('lying expired_unaccepted: the SDK discards a request the operator reserved and spent; clearance reveals it; escape raised to the real charge', async () => {
            await startServer('lie-expired');
            const sdk = await sdkAgent('lie-expired', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            // The lease reaches serverd, which reserves it and issues a key;
            // the operator keeps the key, spends it, and tells the SDK that its
            // quote expired before acceptance.
            let stolen = null;
            gate.intercept = async ({ method, path: target, upstream }) => {
                if (method === 'POST' && target === '/v2/openrouter/leases' && upstream.status === 201 && !stolen) {
                    stolen = JSON.parse(upstream.body.toString());
                    return { status: 409, headers: { 'content-type': 'application/json' },
                        body: Buffer.from(JSON.stringify({ error_code: 'native_quote_expired', error: 'The ETH/USD quote expired before acceptance.',
                            retriable: false })) };
                }
                return upstream;
            };
            let chat;
            try {
                chat = await sdkRefusal(sdk('chat', { sessionId: 'acceptance-lie', model: MODEL, prompt: PROMPT }));
            } finally {
                gate.intercept = null;
            }
            assert.equal(chat.code, 'native_quote_expired', json(chat));
            assert.ok(stolen?.api_key, 'serverd issued the key');
            await inference(stolen);
            const lied = await sdk('snapshot');
            const record = lied.request_archive.at(-1);
            assert.equal(record?.disposition, 'discarded_expired_unaccepted', json(lied.request_archive));
            assert.equal(lied.wallet?.pending_request, false, 'the lie discarded the journal');
            // The state looks fresh, so the SDK asks for a clearance: the
            // reservation answers nullifier_used, and the state is unresolved.
            const mutual = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination }));
            assert.equal(mutual.code, 'request_settlement_pending', json(mutual));
            // A forced early escape concedes nothing; the operator's raise
            // takes its real charge, never more than the bound.
            const escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination });
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            assert.equal(eventOf(receipt, 'EscapeConcessionRecorded').args.conceded, 0n);
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(receipt.blockNumber)), (TIMING.leaseTtl + 120) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            const status = await get(`${gateUrl}/v2/requests/${stolen.client_request_id}`);
            assert.equal(status.nullifier_status, 'exit_deferred');
            pendingEscapes.push({ name: 'sdk-lie-expired', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, stateBalance: DEPOSIT });
            return { note_id: noteId, sdk_chat: chat.code, archived: record.disposition, archived_observations: record.observations, mutual: mutual.code,
                escape_at_ms: mutual.data?.escape_at ?? null, escape: escapeTx.hash, decision: escaped.result?.decision ?? null,
                raised_to: INFERENCE_CHARGE, server_status: status.nullifier_status };
        });
        stopAfter('lie-expired');

        await scenario('withholding operator: the SDK waits for T, then escapes conceding its bound; no defeat; payout B - b', async () => {
            await startServer('withhold');
            const sdk = await sdkAgent('withhold', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const chat = await sdk('chat', { sessionId: 'acceptance-withhold', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200);
            // The server settles the request but never signs its successor.
            const settle = await sdk('settle').then(() => null, error => error.sdk);
            assert.ok(settle, 'a withheld successor never settles the chat');
            const waiting = await sdkRefusal(sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination }));
            assert.equal(waiting.code, 'request_settlement_pending', json(waiting));
            const escapeAt = Number(waiting.data.escape_at);
            assert.ok(escapeAt > Date.now(), 'T is ahead');
            // The state's bound is the request's: $1 at the mock price.
            const held = await sdk('snapshot');
            assert.equal(Number(held.bound_at_state), SDK_REQUEST_BOUND, `the SDK request fixed the state's bound: ${json(held.bound_at_state)}`);
            // The device clock reaches T (W + 900 s after the request) at once.
            await sdk('clock', { offsetSeconds: Math.ceil((escapeAt - Date.now()) / 1000) + 5 });
            const escaped = await sdk('withdraw', { mode: 'mutual', destination: account.sdkDestination });
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, json(escaped.statuses));
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 'bound' });
            const recorded = eventOf(receipt, 'EscapeConcessionRecorded');
            const bound = BigInt(SDK_REQUEST_BOUND);
            assert.deepEqual(escaped.result?.decision, { rule: 'E3.T', conceded: String(bound) }, 'at T the SDK decides E3.T');
            assert.equal(recorded.args.conceded, bound, 'at T the escape concedes exactly the state\'s bound');
            const stateBalance = Number(recorded.args.stateBalance);
            assert.equal(stateBalance, DEPOSIT);
            // The challenger owes nothing more (Ω = the settled charge ≤ c) and
            // has no successor evidence to defeat with.
            // ("raised" is the status of a concession that covers what is
            // owed, whether or not a raise was ever sent.)
            let seen = null;
            const obligation = await waitFor('the challenger finds the concession covers the withheld request', async () => {
                seen = (await challengerStatus()).obligations.find(item => item.note_id === noteId) ?? null;
                return ['nothing_due', 'raised'].includes(seen?.state) && seen?.evidence === 'settled' && seen;
            }, 120_000).catch(error => { throw new Error(`${error.message}; last seen ${json(seen)}`); });
            assert.equal(obligation.owed, INFERENCE_CHARGE);
            assert.equal(BigInt(obligation.conceded), bound);
            assert.equal(obligation.transaction_hash, null, 'nothing was sent for it');
            // Settled, never signed: the lease row reads 'finalized' between
            // settle and sign, then 'exit_deferred' once the exit is seen.
            assert.ok(['finalized', 'exit_deferred'].includes(obligation.settlement?.lease_status), json(obligation.settlement));
            pendingEscapes.push({ name: 'sdk-withhold', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: stateBalance - Number(bound), stateBalance, noDefeatFrom: Number(BigInt(receipt.blockNumber)) });
            return { note_id: noteId, refusal_before_t: waiting.code, escape_at_ms: escapeAt, device_clock_advanced_s: Math.ceil((escapeAt - Date.now()) / 1000),
                decision: escaped.result?.decision ?? null, conceded: bound.toString(), escape: escapeTx.hash,
                challenger: { state: obligation.state, evidence: obligation.evidence, owed: obligation.owed, detail: obligation.detail } };
        });
        stopAfter('withhold');

        // ---------------------------------------------------------------- operator and indexer outages
        await startServer();
        await scenario('indexer down, then rebuild from logs: an SDK note without its deposit-time path escapes at the rebuilt root', async () => {
            const sdk = await sdkAgent('rebuild', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const depositRoot = (await vaultEventsSince('NoteDeposited', noteId, deployBlock))[0].args.newRoot;
            // A later deposit moves the root; that note escapes too.
            const filler = { client: await wallet('rebuild-filler') };
            Object.assign(filler, await driverDeposit(filler.client));
            const currentRoot = await vaultRead('currentRoot');
            assert.notEqual(currentRoot, depositRoot);
            // The rebuild reads the vault's logs up to the finalized block.
            const fillerBlock = Number(BigInt(filler.receipt.blockNumber));
            await waitFor('the filler deposit is final', async () =>
                Number(BigInt((await rpc('eth_getBlockByNumber', ['finalized', false])).number)) >= fillerBlock, 30_000);
            const dropped = await sdk('drop_deposit_path');
            assert.equal(dropped.dropped, true, 'the SDK had saved a deposit-time path');
            assert.equal(dropped.deposit_path_saved, false);
            await stop(indexer);
            const escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination });
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, json(escaped.statuses));
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0, path: 'rebuild' });
            assert.equal(escaped.result?.pathSource, 'rebuild', 'with no saved path and no indexer the path is rebuilt from the logs');
            assert.deepEqual(escaped.result?.decision, { rule: 'E2.escape', conceded: '0' });
            const pending = await vaultRead('pendingWithdrawals', [noteId]);
            assert.equal(pending[0], true);
            assert.equal(pending[1], currentRoot, 'the escape proves at the root rebuilt from the logs, not the deposit root');
            indexer = launch(path.join(opts.binDir, 'zkapi-indexerd'), indexerArgs, 'indexer-3.log');
            await synchronizedTree();
            const fillerEscape = await driverEscape(filler.client, filler.noteId, { path: filler.depositPath });
            pendingEscapes.push({ name: 'sdk-rebuild', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT, stateBalance: DEPOSIT });
            pendingEscapes.push({ name: 'rebuild-filler', client: 'driver', wallet: filler.client, noteId: filler.noteId,
                destination: account.destination, payout: DEPOSIT, stateBalance: DEPOSIT,
                exitedNullifier: fillerEscape.plan.public_inputs.withdrawal_nullifier });
            return { note_id: noteId, path_source: escaped.result.pathSource, proof_root: felt(pending[1]), deposit_root: felt(depositRoot),
                indexer_down_during_escape: true, escape: escapeTx.hash, decision: escaped.result.decision };
        });
        stopAfter('rebuild');

        await scenario('hang: serverd --adversary hang holds every call; the SDK escapes within its exit budget, before must_initiate_by', async () => {
            const sdk = await sdkAgent('hang', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            const chat = await sdk('chat', { sessionId: 'acceptance-hang', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            // The operator hangs from now on: every connection stays open with
            // nothing useful sent (its health route too).
            await stop(server);
            server = launch(zkapi, serverArgs(serverPort, dbPath, { adversary: 'hang' }), `server-${++serverStarts}-hang.log`, { env: seedEnv });
            await waitFor('the hanging serverd listens', () => new Promise(resolve => {
                const socket = net.connect(serverPort, '127.0.0.1', () => { socket.destroy(); resolve(true); });
                socket.on('error', () => resolve(false));
            }), 90_000);
            const probe = await request(`${serverUrl}/health`, { timeoutMs: 3_000 }).then(answer => `HTTP ${answer.status}`, error => error.message);
            assert.match(probe, /timed out/, 'serverd hangs');
            gate.stream = true;
            let escaped;
            const began = Date.now();
            try {
                escaped = await sdk('withdraw', { mode: 'escape', destination: account.sdkDestination }, 900_000);
            } finally {
                gate.stream = false;
            }
            const seconds = (Date.now() - began) / 1000;
            const escapeTx = escaped.sent.find(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector);
            assert.ok(escapeTx, json(escaped.statuses));
            const receipt = await waitReceipt(escapeTx.hash);
            assert.equal(receipt.status, '0x1');
            gas.record('escape', receipt, { client: 'sdk', conceded: 0 });
            // The request is unresolved and T is ahead: an early exit
            // conceding nothing. Each operator call is bounded (20 s) and each
            // recovery pass (120 s): three passes, the stale-device check and
            // the lease retirement stay below 7 minutes.
            assert.deepEqual(escaped.result?.decision, { rule: 'E3.forced', conceded: '0' }, json(escaped.result));
            assert.ok(seconds < 420, `the escape took ${seconds} s against a hanging operator`);
            const note = await noteView(noteId);
            const initiatedAt = Number(BigInt((await rpc('eth_getBlockByNumber', [receipt.blockNumber, false])).timestamp));
            const mustInitiateBy = note.expiry - 43_200;
            assert.ok(initiatedAt < mustInitiateBy, 'the escape landed before must_initiate_by');
            // The operator comes back and settles the request; the challenger
            // raises the concession to its charge.
            await startServer();
            const raised = await waitEvent('EscapeConcessionRaised', noteId, Number(BigInt(receipt.blockNumber)), (TIMING.leaseTtl + 180) * 1000);
            gas.record('raise', raised.receipt, { note_id: noteId });
            assert.equal(raised.event.args.conceded, BigInt(INFERENCE_CHARGE));
            pendingEscapes.push({ name: 'sdk-hang', client: 'sdk', sdk, noteId, destination: account.sdkDestination,
                payout: DEPOSIT - INFERENCE_CHARGE, stateBalance: DEPOSIT });
            return { note_id: noteId, seconds, probe_of_hanging_health: probe, decision: escaped.result.decision,
                escape: escapeTx.hash, initiated_at: initiatedAt, must_initiate_by: mustInitiateBy, raised_to: INFERENCE_CHARGE,
                statuses: escaped.statuses };
        });
        stopAfter('hang');

        // ================================================================ a missed defeat
        await startServer();
        await scenario('missed defeat (challenger stopped), finalization, then retire-on-miss: retireClosedLeaf through the signer', async () => {
            await challengerQuiet();
            await stop(challenger);
            // A stale escape from the genesis state, whose successor's request
            // is in the server's evidence: a defeat is due, and nobody sends it.
            const escape = await driverEscape(missed.client, missed.noteId, { snapshot: 'S0', path: missed.depositPath });
            assert.equal(BigInt(escape.recorded.args.nextNullifier), BigInt(missed.requests[1].nullifier), 'evidence at N⁺ exists');
            pendingEscapes.push({ name: 'missed-defeat', client: 'driver', wallet: missed.client, noteId: missed.noteId,
                destination: account.destination, payout: DEPOSIT, missed: true, escapeBlock: Number(BigInt(escape.receipt.blockNumber)),
                exitedNullifier: escape.plan.public_inputs.withdrawal_nullifier, staleSnapshot: 'S0' });
            assert.equal(BigInt(escape.plan.public_inputs.withdrawal_nullifier), BigInt(missed.genesis.withdrawal_nullifier));
            return { note_id: missed.noteId, escape: escape.receipt.transactionHash, challenger: 'stopped' };
        });

        await scenario('finalize every pending escape; payouts, treasury shares and client states', async () => {
            const deadlines = await Promise.all(pendingEscapes.map(async entry => Number((await vaultRead('pendingWithdrawals', [entry.noteId]))[5])));
            await skipChain(Math.max(...deadlines) - await chainNow() + 5, 'challenge period');
            const results = {};
            for (const entry of pendingEscapes.splice(0)) {
                const raises = await vaultEventsSince('EscapeConcessionRaised', entry.noteId, deployBlock);
                const { receipt, deferred, driverState } = await finalizePending(entry);
                const defeats = await vaultEventsSince('EscapeWithdrawalChallenged', entry.noteId, deployBlock);
                results[entry.name] = { finalize: receipt.transactionHash, payout_gwei: entry.payout, treasury_gwei: DEPOSIT - entry.payout,
                    raises: raises.map(event => Number(event.args.conceded)), defeats: defeats.length, deferred };
                if (['sdk-withhold', 'missed-defeat', 'sdk-hang', 'sdk-rebuild'].includes(entry.name)) {
                    assert.equal(defeats.length, 0, `${entry.name}: never defeated`);
                }
                if (entry.client === 'sdk') {
                    const after = await waitFor('the SDK closes the escape record', async () => {
                        const state = await entry.sdk('sync');
                        const record = state.withdrawals.find(item => Number(item.noteId) === entry.noteId);
                        return record?.phase === 'closed' && { state, record };
                    }, 90_000, 2_000);
                    results[entry.name].client_final_state = sdkFinalState(entry, after);
                    if (entry.deferred) {
                        // The SDK claims its own credited payout (E5).
                        assert.equal(after.record.payoutCredited, true, `${entry.name}: the SDK records the credit`);
                        const before = await balances(entry.destination);
                        const claimed = await entry.sdk('claim', { recordId: entry.recordId });
                        const claimTx = claimed.sent.find(item => item.data === vault.getFunction('claimEscapePayout').selector);
                        assert.ok(claimTx, `the SDK sent no claim: ${json(claimed.statuses)}`);
                        const claimReceipt = await waitReceipt(claimTx.hash);
                        assert.equal(claimReceipt.status, '0x1');
                        gas.record('claim_escape_payout', claimReceipt, { client: 'sdk' });
                        assert.ok(eventOf(claimReceipt, 'EscapePayoutClaimed'));
                        assert.equal(await vaultRead('escapePayoutCredits', [entry.destination]), 0n);
                        assert.equal((await balances(entry.destination))[entry.destination] - before[entry.destination], BigInt(entry.payout) * GWEI);
                        const settled = await waitFor('the SDK records the delivered credit', async () => {
                            const state = await entry.sdk('sync');
                            const record = state.withdrawals.find(item => Number(item.noteId) === entry.noteId);
                            return record?.payoutClaimed === true && record;
                        }, 60_000, 1_000);
                        results[entry.name].claim = { transaction: claimTx.hash, status: claimed.result?.status ?? null,
                            payout_claimed: settled.payoutClaimed };
                    }
                }
                if (entry.client === 'driver') results[entry.name].client_final_state = driverState;
            }
            return { escapes: results };
        });

        await scenario('retire-on-miss: the restarted challenger reports the missed defeat and retires the closed leaf', async () => {
            const rootBefore = await vaultRead('currentRoot');
            const restartBlock = Number(await rpc('eth_blockNumber'));
            await startChallenger();
            const retired = await waitEvent('ClosedLeafRetired', missed.noteId, restartBlock, 120_000);
            gas.record('retire_closed_leaf', retired.receipt, { note_id: missed.noteId });
            assert.equal((await rpc('eth_getTransactionByHash', [retired.event.transactionHash])).from.toLowerCase(), challengerAccount.toLowerCase());
            assert.ok(challengeSends.some(send => send.call === 'retireClosedLeaf' && send.hash === retired.event.transactionHash),
                'the retirement went through the signer');
            const rootAfter = await vaultRead('currentRoot');
            assert.notEqual(rootAfter, rootBefore);
            assert.equal(BigInt(retired.event.args.newRoot), rootAfter);
            assert.equal(await vaultRead('isKnownRoot', [rootAfter]), true);
            const status = await waitFor('the challenger counts the missed defeat', async () => {
                const current = await challengerStatus();
                return current.escapes_finalized_with_successor_evidence_total >= 1 && current;
            }, 60_000);
            assert.equal(status.last_missed?.note_id, missed.noteId, `the miss recorded is this note's: ${json(status.last_missed)}`);
            assert.equal(status.last_missed?.kind, 'defeat');
            const logs = await Promise.all([...Array(challengerStarts).keys()].map(index =>
                fs.readFile(path.join(runDir, `challenger-${index + 1}.log`), 'utf8').catch(() => '')));
            // The log line names the note and the kind of miss (ANSI styling removed).
            const missLine = new RegExp(`MISSED escape deadline note_id=${missed.noteId} .*missed="defeat"`);
            assert.ok(logs.some(text => text.replace(/\u001b\[[0-9;]*m/g, '').split('\n').some(line => missLine.test(line))),
                'the challenger logs the miss of this note');
            // The retired leaf is gone from the tree: the newest state of the
            // note can no longer prove membership at the current root.
            const snapshot = await synchronizedTree();
            assert.equal(BigInt(snapshot.leaves[missed.noteId]), 0n);
            const atCurrentRoot = await missed.client('tree_path', { args: { snapshot, note_id: missed.noteId, require_existing: true } });
            assert.equal((await missed.client('note_path_matches', { args: { active_root: atCurrentRoot.active_root,
                siblings: atCurrentRoot.siblings } })).matches, false, 'the note\'s leaf is not under the current root');
            const signer = await get(`${signerUrl}/health`);
            assert.equal(signer.retirements_last_24h, 1);
            return { note_id: missed.noteId, retirement: retired.event.transactionHash, new_root: felt(rootAfter),
                missed_defeats_counted: status.escapes_finalized_with_successor_evidence_total, signer_retirements_last_24h: signer.retirements_last_24h,
                last_missed: status.last_missed ?? null };
        });
        stopAfter('missed');

        // E4.6 then E6 (§10.7 B "late successor, then switch"): the operator
        // answers the request only after the owner released an escape proof,
        // which never lands (the owner rejects it in the wallet). The
        // successor is archived as late_successor and the lock holds while
        // the proof could still land. Once the proof is dead on the device's
        // clock and at a finalized block, the lock is released, the late
        // successor installs, and the owner exits from the newer state by a
        // mutual close: B_{k+1}, not an escape from S_k.
        //
        // The device clock is set so that the proof lives 600 s of chain
        // time, and then past its valid_until + 900; block time moves by the
        // same amount, within MAX_CHAIN_LEAD_SECONDS.
        await scenario('late successor, then switch: the successor arrives after an escape proof is released; E6 installs it once the proof is dead, and the owner closes from the newer state', async () => {
            const sdk = await sdkAgent('late', { walletAccount: account.sdk });
            await sdk('init');
            const deposited = await sdk('deposit', { amount: '0.001' });
            const noteId = Number(deposited.note.note_id);
            await sdk('hold_successors', { on: true });
            const chat = await sdk('chat', { sessionId: 'acceptance-late', model: MODEL, prompt: PROMPT });
            assert.equal(chat.status, 200, json(chat));
            const settle = await sdk('settle').then(() => null, error => error.sdk ?? { message: error.message });
            const pendingState = await sdk('snapshot');
            const requestId = pendingState.journal_request_id ?? pendingState.request_archive.at(-1)?.client_request_id;
            assert.ok(requestId, json(pendingState.request_archive));
            // The operator has signed the successor; the SDK has not seen it.
            const signed = await waitFor('the operator signs the successor', async () => {
                const found = await get(`${serverUrl}/v2/requests/${requestId}`);
                return found.request_response && found;
            }, (TIMING.leaseTtl + 180) * 1000, 1_000);
            assert.equal(Number(pendingState.note.current_balance), DEPOSIT);
            // An early escape conceding nothing, whose proof lives 600 s of
            // chain time; the owner rejects it in the wallet.
            const lead = await chainNow() - wallNow();
            await sdk('clock', { offsetSeconds: lead + 600 - 10_800 });
            await sdk('wallet_reject', { selectors: [vault.getFunction('initiateEscapeWithdrawal').selector] });
            const rejected = await sdkRefusal(sdk('withdraw', { mode: 'escape', destination: account.sdkDestination }));
            await sdk('wallet_reject', { selectors: [] });
            const late = await sdk('snapshot');
            assert.equal(late.rejected.length, 1, 'the wallet refused the escape: nothing was broadcast');
            assert.ok(!late.sent.some(item => item.data === vault.getFunction('initiateEscapeWithdrawal').selector));
            const released = late.exit_lock?.released?.find(entry => Number(entry.kind) === 0);
            assert.ok(released, `the escape proof was released: ${json(late.exit_lock)}`);
            const validUntil = Number(released.valid_until);
            assert.ok(validUntil > await chainNow(), 'the released proof could still land');
            assert.ok(late.request_archive.some(entry => entry.disposition === 'late_successor' && entry.client_request_id === requestId),
                `the successor is archived as late_successor: ${json(late.request_archive)}`);
            assert.equal(Number(late.note.current_balance), DEPOSIT, 'the late successor does not install while the proof can land');
            // While the proof can land, a cancel keeps the lock (E6).
            const live = await sdk('cancel');
            assert.ok(live.exit_lock?.released?.length, 'the lock holds while the proof can land');
            assert.equal(Number(live.note.current_balance), DEPOSIT);
            // The proof dies: block time and the device clock pass
            // valid_until + 900.
            await skipChain(validUntil + 930 - await chainNow(), 'past the released proof\'s valid_until + 900');
            await waitFor('a finalized block past the proof\'s life', async () =>
                Number(BigInt((await rpc('eth_getBlockByNumber', ['finalized', false])).timestamp)) > validUntil + 900, 30_000);
            await sdk('clock', { offsetSeconds: validUntil + 960 - wallNow() });
            const dead = await sdk('cancel');
            assert.equal(dead.exit_lock, null, `E6 released the lock: ${json(dead.statuses)}`);
            assert.equal(Number(dead.note.current_balance), DEPOSIT - INFERENCE_CHARGE, 'the late successor installed');
            assert.equal(dead.bound_at_state, '0', 'the successor reset the bound');
            // The switch: a fresh state, closed cooperatively with the
            // device clock back on the wall clock.
            await sdk('clock', { offsetSeconds: 0 });
            await sdk('hold_successors', { on: false });
            const destination = '0x000000000000000000000000000000000000c107';
            const closed = await sdkMutualClose(sdk, noteId, destination, DEPOSIT - INFERENCE_CHARGE, DEPOSIT - INFERENCE_CHARGE);
            assert.equal((await vaultEventsSince('EscapeWithdrawalInitiated', noteId, deployBlock)).length, 0, 'no escape of this note landed');
            await sdk.close();
            return { note_id: noteId, settle_while_held: settle?.code ?? null, held_readings: late.held_readings,
                successor_signed_charge: Number(signed.request_response.charge_applied), escape_refusal: rejected.code ?? rejected.message,
                released_valid_until: validUntil, late_successor: 'archived, then installed by E6', ...closed };
        });
        stopAfter('late-successor');

        await scenario('expiry sweep and pause cooldown end: claimExpired after effectiveExpiry; a pause after PAUSE_COOLDOWN', async () => {
            // Stop the daemons first: block time now runs ahead of the wall clock.
            await stop(challenger);
            await stop(server);
            gate.target = null;
            const expiry = Number(await vaultRead('effectiveExpiry', [expiryNote.noteId]));
            const now = await chainNow();
            await rpc('evm_increaseTime', [expiry - now + 1]);
            await rpc('evm_mine', []);
            const before = await balances(treasury, vaultAddress);
            const claimed = await vaultSend(account.thirdParty, 'claimExpired', [expiryNote.noteId], { operation: 'claim_expired' });
            assert.equal(claimed.status, '0x1');
            assert.ok(eventOf(claimed, 'ExpiredClaimed'));
            assert.equal((await noteView(expiryNote.noteId)).status, NOTE.Closed);
            const after = await balances(treasury, vaultAddress);
            assert.equal(after[treasury] - before[treasury], BigInt(DEPOSIT) * GWEI);
            const paused = await vaultSend(owner, 'pause', [], { operation: 'pause' });
            assert.equal(paused.status, '0x1', 'PAUSE_COOLDOWN has passed');
            await vaultSend(owner, 'unpause', [], { operation: 'unpause' });
            return { note_id: expiryNote.noteId, claim: claimed.transactionHash, treasury_gwei: DEPOSIT, repause_after_cooldown: paused.transactionHash };
        });

        // Every note of the run is closed; the vault holds only what the
        // ledger says it owes.
        assert.equal(await balance(vaultAddress), 0n, 'the vault holds nothing once every note closed and every credit was claimed');
        assert.equal(await vaultRead('treasuryArrears'), 0n);

        evidence.pinned_rpc_methods = Object.fromEntries(pinnedRpcMethods);
        evidence.operator_gate = { requests: gate.log.length, while_down: gate.log.filter(entry => entry.mode === 'down').length };
        evidence.mock_provider = { keys: mock.keys.size, events: mock.events.length,
            oa_org_keys: mock.events.filter(event => event.source === 'oa_org' && event.type === 'issued').length };
        evidence.challenger_sends = challengeSends.map(send => ({ call: send.call, note_id: send.note_id, hash: send.hash ?? null,
            error: send.error ?? null, ...send.fees }));
        // Every operation the operator's bundler was sent, and every bundle it sent.
        evidence.bundler = bundler.summary();
        evidence.paymaster = { float_wei: (await floatWei()).toString(), lost_wei: (await pmRead('lostWei')).toString(),
            shortfall_wei: (await pmRead('shortfallWei')).toString(), total_credits_wei: (await pmRead('totalCredits')).toString(),
            balance_wei: (await balance(paymasterAddress)).toString() };
        assert.equal(BigInt(evidence.paymaster.balance_wei), BigInt(evidence.paymaster.total_credits_wei),
            'the paymaster holds exactly the credits it owes');
        // The operator's own report (docs/deployment.md, gasless runtime):
        // after the drill no debt, stranded balance or EntryPoint alarm is open.
        const statusRun = await runToExit(process.execPath, [path.join(ROOT, 'scripts/paymaster-status.mjs'), '--deployment',
            path.join(runDir, 'deployment.json'), '--rpc', rpcUrl], 'paymaster-status.log');
        assert.equal(statusRun.code, 0, `paymaster-status failed: ${statusRun.output.slice(-2000)}`);
        const paymasterStatus = JSON.parse(statusRun.output.slice(statusRun.output.indexOf('{')));
        await save('paymaster-status.json', paymasterStatus);
        assert.equal(paymasterStatus.open_owed_total_wei, '0', json(paymasterStatus.open_owed));
        assert.deepEqual(paymasterStatus.stranded_open, [], 'every stranded transit account was forwarded or swept');
        assert.deepEqual(paymasterStatus.entry_point_alarms, { post_op_revert_reason: 0, user_operation_prefund_too_low: 0 });
        assert.equal(paymasterStatus.unaccounted_balance_wei, '0');
        assert.ok(paymasterStatus.user_operations.failed >= 1 && paymasterStatus.user_operations.succeeded >= 1, json(paymasterStatus.user_operations));
        evidence.paymaster.status_report = { user_operations: paymasterStatus.user_operations, events: paymasterStatus.events.counts,
            deposit_covers_operations: paymasterStatus.deposit_covers_operations };
        const hashes = {};
        for (const file of [fileURLToPath(import.meta.url), path.join(ROOT, 'crates/zkapi-serverd/examples/v2_acceptance_wallet.rs'),
            path.join(ROOT, 'scripts/acceptance/sdk-agent.mjs'), path.join(ROOT, 'scripts/acceptance/mini-bundler.mjs'),
            ...['entrypoint-v0.7.0.runtime.hex', 'sender-creator-v0.7.0.runtime.hex'].map(file => path.join(ROOT, 'protocol/contracts/test/fixtures', file)),
            ...['zkapi', 'zkapi-indexerd', 'zkapi-challenged', 'zkapi-walletd', 'examples/v2_acceptance_wallet'].map(file => path.join(opts.binDir, file)),
            ...['request.pk', 'request.vk', 'withdrawal.pk', 'withdrawal.vk'].map(file => path.join(SETUP_DIR, file)),
            path.join(ROOT, 'sdk/wasm/zkapi_browser_bg.wasm')]) {
            hashes[path.relative(ROOT, file)] = await sha256File(file).catch(() => null);
        }
        const gitOutput = args => {
            const result = spawnSync('git', args, { cwd: ROOT, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 });
            assert.equal(result.status, 0, `git ${args.join(' ')} failed: ${result.error?.message ?? result.stderr}`);
            return result.stdout;
        };
        const gasReport = { schema: 'zkapi-acceptance-gas/v1', circuit_id: 'zkapi-v2-concession-v1', setup_id: finalized.setupId,
            chain: 'anvil', chain_id: CHAIN_ID, note: 'transaction gasUsed of real calls on a fresh Anvil vault (receipt gas, refunds applied)',
            snapshot: await readJSON(path.join(ROOT, 'protocol/contracts/snapshots/concession-exit-gas.json')).catch(() => null),
            summary: gas.summary(), transactions: gas.entries };
        await save('gas.json', gasReport);
        const result = { passed: true, timestamp: new Date().toISOString(), elapsed_wall_seconds: (Date.now() - started) / 1000,
            source_commit: gitOutput(['rev-parse', 'HEAD']).trim(),
            source_dirty: gitOutput(['status', '--porcelain']).trim().length > 0,
            tracked_source_diff_sha256: createHash('sha256').update(gitOutput(['diff', '--binary', 'HEAD'])).digest('hex'),
            artifact_sha256: hashes,
            network: { chain_id: CHAIN_ID, kind: 'disposable loopback Anvil with Sepolia\'s chain ID', fork: false, public_rpc: false,
                chain_lag_seconds_at_start: CHAIN_LAG_SECONDS },
            coverage: {
                contracts: 'protocol/contracts via demo/contracts/script/Deploy.s.sol, finalized by scripts/expected-codehashes.mjs',
                proof_system: 'protocol/setup/v2-concession-dev (single-party dev setup, drill vault only)',
                server: 'zkapi serverd (drill build: --adversary withhold, born-spent, reuse-anchor, random-anchor, overcharge, lie-expired, hang), SQLite archive bound by zkapi db init',
                indexer: `zkapi-indexerd at ${INDEXER_CONFIRMATIONS} confirmations, stopped and restarted from its checkpoint`,
                challenger: 'zkapi-challenged: defeats, raises and retire-on-miss through the signer sidecar',
                signer: 'docker/aws/signer (EIP-1559, allowlisted calls, retirement budget)',
                clients: { wallet_core: 'examples/v2_acceptance_wallet (zkapi-browser natively; the harness applies the exit rules for it)',
                    sdk: 'sdk/ (zkapiClient + browserWalletRuntime) with sdk/wasm in Node: its own exit decisions, escapes, mutual closes, finalizations and credit claim',
                    companion: 'zkapi-walletd routes the Go clientd calls, escape and mutual close (the harness signs and sends its transactions), every connection through its authenticated proxy' },
                gasless: 'the canonical EntryPoint v0.7.0 and SenderCreator runtimes etched at their addresses (codehash-pinned), the paymaster and its factory from the same Deploy.s.sol broadcast; sponsored closes, escapes, finalizations, forwards and sweeps through the SDK (fees: payout) and the harness as zkapi-clientd (ephemeral owner key)',
                bundler: 'in-process mini bundler (handleOps from an Anvil account); no real bundler tracer',
                erc7562_audit: 'not run here: the Forge suite traces validation (protocol/contracts/test/gasless/Validation.t.sol test_opcodeAudit_*, RealAdapter.t.sol with the real adapter); a real bundler tracer run is a release gate (docs/migration-concession-vault.md)',
                provider: 'loopback mock management and inference HTTP service',
                oracle: 'loopback mock ETH/USD feed; every other read is the actual chain',
                external_provider_verified: false, live_network_verified: false, go_clientd_verified: false },
            scenarios, evidence, gas: gasReport.summary };
        await save('result.json', result);
        // The per-run seeds must not appear in any saved evidence or log.
        const secrets = Object.values(seedEnv).flatMap(seed => [seed, seed.slice(2)]);
        for (const name of await fs.readdir(runDir, { recursive: true })) {
            const file = path.join(runDir, name);
            if (!(await fs.stat(file)).isFile()) continue;
            const content = await fs.readFile(file);
            assert.ok(secrets.every(secret => !content.includes(secret)), `${name} contains an operator seed`);
        }
        for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
        console.log(`PASS: ${scenarios.length} scenarios.\nEvidence: ${runDir}`);
    } catch (error) {
        if (error?.stopped) {
            for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
            console.log(`${error.message}.\nEvidence: ${runDir}`);
        } else {
            await save('failure.json', { passed: false, error: error.message, stack: error.stack, scenarios, evidence });
            for (const item of scenarios) console.log(`${item.status}  ${item.name}`);
            console.error(`FAIL: ${error.message}\nEvidence: ${runDir}`);
            process.exitCode = 1;
        }
    } finally {
        if (miner) clearInterval(miner);
        for (const agent of sdkAgents) await agent.close?.().catch(() => {});
        for (const child of [...children]) await stop(child);
        for (const server of servers) {
            server.closeAllConnections?.();
            await new Promise(resolve => server.close(resolve));
        }
        process.off('SIGINT', onSignal);
        process.off('SIGTERM', onSignal);
    }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
    await main();
}
