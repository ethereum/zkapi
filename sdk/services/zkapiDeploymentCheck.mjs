// Deployment verification before deposits (design §6.5) and the canary caps
// (§10.7 C). The checks read the chain through an EIP-1193 `request`
// function: the user's wallet provider (the one that will sign the deposit)
// and the build-pinned RPC each run them. A mismatch, or a read that fails,
// refuses deposits with deployment_mismatch; exits never depend on it.

import { ABI, GASLESS_ABI } from '../wallet.js';
import { codehash } from './zkapiKeccak.mjs';
import {
    decodeAddressWord, decodeGasPolicy, decodeWord, encodeGetAddress, gaslessPins, sameGasPolicy, transitAccountAddress
} from './zkapiGasless.mjs';

export { gaslessPins };

// keccak256("zkapi-v2-concession-v1"), the adapter's CIRCUIT_ID_HASH.
export const CONCESSION_CIRCUIT_ID_HASH = '0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687';
export const CONCESSION_ESCAPE_VERSION = 1n;
export const ROOT_HISTORY_WINDOW_SECONDS = 86_400n;
const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const WORD = /^0x[0-9a-fA-F]{64}$/;

function checkError(message, code, data = undefined) {
    return Object.assign(new Error(message), { code, ...(data ? { data } : {}) });
}

function lower(value) {
    return String(value ?? '').toLowerCase();
}

function word(value) {
    return `0x${BigInt(value).toString(16).padStart(64, '0')}`;
}

/**
 * The pins a deployment check compares, from a build-pinned trusted
 * deployment profile. A placeholder (not deployed) or a profile missing any
 * of them cannot be checked, so it can take no deposit.
 */
export function deploymentPins(trusted) {
    const t = trusted || {};
    const required = {
        contract_address: t.contract_address,
        vault_runtime_codehash: t.vault_runtime_codehash,
        proof_adapter_address: t.proof_adapter_address,
        adapter_runtime_codehash: t.adapter_runtime_codehash,
        poseidon_library_address: t.poseidon_library_address,
        poseidon_runtime_codehash: t.poseidon_runtime_codehash,
        request_vk_keccak256: t.request_vk_keccak256,
        withdrawal_vk_keccak256: t.withdrawal_vk_keccak256,
        challenge_period: t.challenge_period,
        note_ttl: t.note_ttl,
        max_pause_duration: t.max_pause_duration,
        state_signing_key: t.state_signing_key?.x != null && t.state_signing_key?.y != null ? t.state_signing_key : null,
        clearance_signing_key: t.clearance_signing_key?.x != null && t.clearance_signing_key?.y != null
            ? t.clearance_signing_key : null
    };
    const missing = Object.entries(required).filter(([, value]) => value == null).map(([key]) => key);
    if (t.deployment_status === 'not_deployed' || missing.length) {
        throw checkError(`The build-pinned profile does not pin ${missing.join(', ') || 'a deployed vault'}, so this deployment cannot be verified.`,
            'deployment_unverifiable', { missing });
    }
    for (const key of ['contract_address', 'proof_adapter_address', 'poseidon_library_address']) {
        if (!ADDRESS.test(required[key])) throw checkError(`The profile's ${key} is not an address.`, 'deployment_unverifiable');
    }
    for (const key of ['vault_runtime_codehash', 'adapter_runtime_codehash', 'poseidon_runtime_codehash',
        'request_vk_keccak256', 'withdrawal_vk_keccak256']) {
        if (!WORD.test(required[key])) throw checkError(`The profile's ${key} is not a 32-byte hash.`, 'deployment_unverifiable');
    }
    return required;
}

/**
 * Compare a deployment with its pins through `request`. Returns
 * { ok, source, mismatches: [{ field, expected, actual }] }; an unreadable
 * value is a mismatch with actual null. `chainId` is checked first.
 */
export async function verifyDeployment({ request, trusted, chainId, source = 'rpc' }) {
    const pins = deploymentPins(trusted);
    const mismatches = [];
    const read = async (field, operation) => {
        try {
            return await operation();
        } catch (error) {
            mismatches.push({ field, expected: 'readable', actual: null, error: error?.message || String(error) });
            return undefined;
        }
    };
    const chain = await read('chain_id', () => request({ method: 'eth_chainId', params: [] }));
    if (chain !== undefined && BigInt(chain) !== BigInt(chainId)) {
        mismatches.push({ field: 'chain_id', expected: String(chainId), actual: String(BigInt(chain)) });
        return { ok: false, source, mismatches };
    }
    const code = async (field, address, expected) => {
        const value = await read(field, () => request({ method: 'eth_getCode', params: [address, 'latest'] }));
        if (value === undefined) return;
        const actual = !value || value === '0x' ? null : codehash(value);
        if (lower(actual) !== lower(expected)) mismatches.push({ field, expected: lower(expected), actual });
    };
    const call = async (field, to, selector, expected) => {
        const value = await read(field, () => request({ method: 'eth_call', params: [{ to, data: `0x${selector}` }, 'latest'] }));
        if (value === undefined) return;
        if (!WORD.test(value || '')) {
            mismatches.push({ field, expected: word(expected), actual: value ?? null });
            return;
        }
        if (BigInt(value) !== BigInt(expected)) mismatches.push({ field, expected: word(expected), actual: lower(value) });
    };
    const vault = pins.contract_address;
    const adapter = pins.proof_adapter_address;
    await code('vault_runtime_codehash', vault, pins.vault_runtime_codehash);
    await code('adapter_runtime_codehash', adapter, pins.adapter_runtime_codehash);
    await code('poseidon_runtime_codehash', pins.poseidon_library_address, pins.poseidon_runtime_codehash);
    await call('proofAdapter', vault, ABI.proofAdapter, BigInt(adapter));
    await call('stateSigningKeyX', vault, ABI.stateSigningKeyX, BigInt(pins.state_signing_key.x));
    await call('stateSigningKeyY', vault, ABI.stateSigningKeyY, BigInt(pins.state_signing_key.y));
    await call('clearanceSigningKeyX', vault, ABI.clearanceSigningKeyX, BigInt(pins.clearance_signing_key.x));
    await call('clearanceSigningKeyY', vault, ABI.clearanceSigningKeyY, BigInt(pins.clearance_signing_key.y));
    await call('challengePeriod', vault, ABI.challengePeriod, BigInt(pins.challenge_period));
    await call('noteTtl', vault, ABI.noteTtl, BigInt(pins.note_ttl));
    await call('maxPauseDuration', vault, ABI.maxPauseDuration, BigInt(pins.max_pause_duration));
    await call('CONCESSION_ESCAPE_VERSION', vault, ABI.CONCESSION_ESCAPE_VERSION, CONCESSION_ESCAPE_VERSION);
    await call('ROOT_HISTORY_WINDOW', vault, ABI.ROOT_HISTORY_WINDOW, ROOT_HISTORY_WINDOW_SECONDS);
    await call('CIRCUIT_ID_HASH', adapter, ABI.CIRCUIT_ID_HASH, BigInt(CONCESSION_CIRCUIT_ID_HASH));
    await call('REQUEST_VK_HASH', adapter, ABI.REQUEST_VK_HASH, BigInt(pins.request_vk_keccak256));
    await call('WITHDRAWAL_VK_HASH', adapter, ABI.WITHDRAWAL_VK_HASH, BigInt(pins.withdrawal_vk_keccak256));
    return { ok: mismatches.length === 0, source, mismatches };
}

// ---- gasless withdrawals (design §4.4) ----

/** A fixed (owner, payee) sample whose CREATE2 address the factory must reproduce. */
export const GASLESS_SAMPLE_OWNER = `0x${'0'.repeat(39)}1`;
export const GASLESS_SAMPLE_PAYEE = `0x${'0'.repeat(39)}2`;

/**
 * Compare the gasless contracts with their pins through `request`: the
 * codehashes of the EntryPoint, the SenderCreator, the paymaster and the
 * factory; the paymaster's vault, factory, EntryPoint and WEI_PER_UNIT; the
 * factory's paymaster and account creation code hash; the paymaster's gas
 * policy against the profile's; and factory.getAddress of a sample tuple
 * against the local CREATE2. Returns { ok, source, mismatches } like
 * verifyDeployment. A profile without gasless pins is `ok: false` with a
 * single `gasless` mismatch. Deposits and wallet-paid exits never depend on it.
 */
export async function verifyGaslessDeployment({ request, trusted, chainId, source = 'rpc' }) {
    let pins;
    try {
        pins = gaslessPins(trusted);
    } catch (error) {
        return { ok: false, source, mismatches: [{ field: 'gasless', expected: 'valid pins', actual: null, error: error?.message || String(error) }] };
    }
    if (!pins) return { ok: false, source, mismatches: [{ field: 'gasless', expected: 'pinned', actual: null }] };
    const mismatches = [];
    const read = async (field, operation) => {
        try {
            return await operation();
        } catch (error) {
            mismatches.push({ field, expected: 'readable', actual: null, error: error?.message || String(error) });
            return undefined;
        }
    };
    const chain = await read('chain_id', () => request({ method: 'eth_chainId', params: [] }));
    if (chain !== undefined && BigInt(chain) !== BigInt(chainId)) {
        mismatches.push({ field: 'chain_id', expected: String(chainId), actual: String(BigInt(chain)) });
        return { ok: false, source, mismatches };
    }
    const code = async (field, address, expected) => {
        const value = await read(field, () => request({ method: 'eth_getCode', params: [address, 'latest'] }));
        if (value === undefined) return;
        const actual = !value || value === '0x' ? null : codehash(value);
        if (lower(actual) !== lower(expected)) mismatches.push({ field, expected: lower(expected), actual });
    };
    const call = async (field, to, selector, decode, expected, data = '') => {
        const value = await read(field, () => request({ method: 'eth_call', params: [{ to, data: `0x${selector}${data}` }, 'latest'] }));
        if (value === undefined) return;
        let actual;
        try {
            actual = decode(value);
        } catch (error) {
            mismatches.push({ field, expected: String(expected.label ?? ''), actual: value ?? null, error: error?.message || String(error) });
            return;
        }
        if (!expected(actual)) mismatches.push({ field, expected: String(expected.label ?? ''), actual: typeof actual === 'bigint' ? actual.toString() : actual });
    };
    const equals = (label, test) => Object.assign(test, { label });
    const addressEquals = expected => equals(lower(expected), actual => lower(actual) === lower(expected));
    await code('entry_point_runtime_codehash', pins.entryPoint, pins.entryPointCodehash);
    await code('sender_creator_runtime_codehash', pins.senderCreator, pins.senderCreatorCodehash);
    await code('withdrawal_paymaster_runtime_codehash', pins.paymaster, pins.paymasterCodehash);
    await code('withdrawal_account_factory_runtime_codehash', pins.factory, pins.factoryCodehash);
    if (pins.implementation && pins.implementationCodehash) {
        await code('withdrawal_account_implementation_runtime_codehash', pins.implementation, pins.implementationCodehash);
    }
    await call('paymaster.vault', pins.paymaster, GASLESS_ABI.vault, decodeAddressWord, addressEquals(trusted.contract_address));
    await call('paymaster.factory', pins.paymaster, GASLESS_ABI.factory, decodeAddressWord, addressEquals(pins.factory));
    await call('paymaster.entryPoint', pins.paymaster, GASLESS_ABI.entryPoint, decodeAddressWord, addressEquals(pins.entryPoint));
    const weiPerUnit = BigInt(trusted.native_asset_wei_per_unit ?? 1_000_000_000);
    await call('paymaster.WEI_PER_UNIT', pins.paymaster, GASLESS_ABI.WEI_PER_UNIT, decodeWord, equals(weiPerUnit.toString(), actual => actual === weiPerUnit));
    await call('factory.paymaster', pins.factory, GASLESS_ABI.paymaster, decodeAddressWord, addressEquals(pins.paymaster));
    await call('factory.accountCreationCodeHash', pins.factory, GASLESS_ABI.accountCreationCodeHash,
        value => { if (!WORD.test(value || '')) throw new Error('not a word'); return lower(value); },
        equals(pins.accountCreationCodeKeccak256, actual => actual === pins.accountCreationCodeKeccak256));
    await call('paymaster.gasPolicy', pins.paymaster, GASLESS_ABI.gasPolicy, decodeGasPolicy,
        equals('the profile’s gas_policy', actual => sameGasPolicy(actual, pins.gasPolicy)));
    const sample = transitAccountAddress({
        factory: pins.factory, creationCodeHex: pins.accountCreationCode, entryPoint: pins.entryPoint, vault: trusted.contract_address,
        paymaster: pins.paymaster, owner: GASLESS_SAMPLE_OWNER, payee: GASLESS_SAMPLE_PAYEE
    });
    await call('factory.getAddress', pins.factory, GASLESS_ABI.getAddress, decodeAddressWord, addressEquals(sample),
        encodeGetAddress(GASLESS_SAMPLE_OWNER, GASLESS_SAMPLE_PAYEE).slice(10));
    return { ok: mismatches.length === 0, source, mismatches };
}

/** The refusal of the gasless path after failed checks: `gasless_unavailable`, with the mismatching fields. */
export function gaslessDeploymentError(results) {
    const mismatches = results.flatMap(result => (result.mismatches || []).map(entry => ({ ...entry, source: result.source })));
    return checkError(`The gasless contracts do not match the deployment this app pins (${mismatches.map(entry => `${entry.source}: ${entry.field}`).join(', ')}). The network fee can only be paid from a wallet.`,
        'gasless_unavailable', { reason: 'gasless_deployment_mismatch', mismatches });
}

/** The refusal of a deposit after failed checks. */
export function deploymentMismatchError(results) {
    const mismatches = results.flatMap(result => (result.mismatches || []).map(entry => ({ ...entry, source: result.source })));
    return checkError(`This vault does not match the deployment this app pins (${mismatches.map(entry => `${entry.source}: ${entry.field}`).join(', ')}). Deposits are refused; existing balances can still exit.`,
        'deployment_mismatch', { mismatches });
}

// ---- canary caps ----

function wei(value, label) {
    if (value == null) return null;
    if (!/^(0|[1-9][0-9]*)$/.test(String(value))) throw checkError(`The profile's canary ${label} is not a wei amount.`, 'canary_invalid');
    return BigInt(value);
}

/**
 * The canary caps of a profile while they apply (until null, or a later
 * time): { perNoteMaxWei, aggregateMaxWei, until }, or null.
 */
export function canaryLimits(trusted, nowSeconds) {
    const canary = trusted?.canary;
    if (!canary) return null;
    const until = canary.until == null ? null : Number(canary.until);
    if (until != null && (!Number.isSafeInteger(until) || nowSeconds >= until)) return null;
    return {
        perNoteMaxWei: wei(canary.per_note_max_wei, 'per-note cap'),
        aggregateMaxWei: wei(canary.aggregate_max_wei, 'aggregate cap'),
        until
    };
}

/**
 * Null when a deposit of `depositWei` fits the caps, given the vault's
 * balance read through the wallet provider; else the refusal.
 */
export function canaryRefusal({ limits, depositWei, vaultBalanceWei = null }) {
    if (!limits) return null;
    const amount = BigInt(depositWei);
    if (limits.perNoteMaxWei != null && amount > limits.perNoteMaxWei) {
        return checkError('During its launch period this vault takes at most a limited deposit per balance.',
            'canary_cap_exceeded', { cap: 'per_note', limit_wei: limits.perNoteMaxWei.toString() });
    }
    if (limits.aggregateMaxWei != null) {
        if (vaultBalanceWei == null) {
            return checkError('The vault balance could not be read to check its launch-period limit.',
                'canary_cap_unverified', { cap: 'aggregate' });
        }
        if (BigInt(vaultBalanceWei) + amount > limits.aggregateMaxWei) {
            return checkError('During its launch period this vault holds a limited total, and this deposit would exceed it.',
                'canary_cap_exceeded', { cap: 'aggregate', limit_wei: limits.aggregateMaxWei.toString() });
        }
    }
    return null;
}
