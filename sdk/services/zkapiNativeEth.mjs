import { browserSdkTransport } from '../configure.js';

export const NATIVE_UNITS_PER_ETH = 1_000_000_000n;
export const NATIVE_WEI_PER_UNIT = 1_000_000_000n;
const MAX_SAFE = BigInt(Number.MAX_SAFE_INTEGER);
const ZERO = /^0x0{40}$/i;
const ADDRESS = /^0x[0-9a-f]{40}$/i;
const unsigned = value => /^(?:0|[1-9]\d*)$/.test(String(value));

export function isNativeEthFunding(funding) {
    return funding?.billing_asset === 'native_eth';
}

export function validateNativeFunding(funding) {
    if (!isNativeEthFunding(funding)) {
        throw new Error('Unsupported billing asset: only native ETH deployments are supported. Keep token wallets and their recovery data with their original deployment.');
    }
    if (funding.billing_token_address != null || funding.demo_billing_token_address != null || funding.demo_mint_enabled) {
        throw new Error('Native ETH deployments cannot advertise a billing token or mint.');
    }
    if (funding.billing_unit !== 'gwei'
        || String(funding.native_asset_wei_per_unit) !== String(NATIVE_WEI_PER_UNIT)
        || !ADDRESS.test(funding.contract_address || '') || ZERO.test(funding.contract_address)
        || !ADDRESS.test(funding.native_price_feed_address || '') || ZERO.test(funding.native_price_feed_address)
        || !Number.isSafeInteger(funding.chain_id) || funding.chain_id <= 0
        || funding.native_price_feed_decimals !== 8
        || !Number.isSafeInteger(funding.native_price_max_age_seconds)
        || funding.native_price_max_age_seconds <= 0 || funding.native_price_max_age_seconds > 86_400) {
        throw new Error('The native ETH deployment has invalid asset or price-feed configuration.');
    }
    const rpc = new URL(funding.demo_rpc_url || funding.rpc_url);
    if (rpc.username || rpc.password || (rpc.protocol !== 'https:'
        && !(rpc.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(rpc.hostname)))) {
        throw new Error('The native ETH deployment requires a trusted HTTPS or loopback RPC.');
    }
}

export function parseUnits(value, decimals) {
    const match = String(value).trim().match(new RegExp(`^(\\d+)(?:\\.(\\d{0,${decimals}}))?$`));
    if (!match) throw new Error(`Enter a positive amount with no more than ${decimals} decimal places.`);
    return BigInt(match[1]) * (10n ** BigInt(decimals))
        + BigInt((match[2] || '').padEnd(decimals, '0') || '0');
}

export function formatUnits(value, decimals) {
    const amount = BigInt(value);
    if (amount < 0n) throw new Error('Amounts cannot be negative.');
    const scale = 10n ** BigInt(decimals);
    const fraction = (amount % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
    return `${amount / scale}${fraction ? `.${fraction}` : ''}`;
}

export function validateNativeQuote(quote, funding, { now = Math.floor(Date.now() / 1000), allowExpired = false } = {}) {
    validateNativeFunding(funding);
    if (!quote || quote.asset !== 'native_eth' || quote.units_per_eth !== Number(NATIVE_UNITS_PER_ETH)
        || quote.chain_id !== funding.chain_id
        || String(quote.feed_address).toLowerCase() !== funding.native_price_feed_address.toLowerCase()
        || quote.decimals !== funding.native_price_feed_decimals
        || !unsigned(quote.round_id) || BigInt(quote.round_id) <= 0n || BigInt(quote.round_id) >= (1n << 80n)
        || !unsigned(quote.answer) || BigInt(quote.answer) <= 0n || BigInt(quote.answer) > 1_000_000_000_000_000_000n
        || !Number.isSafeInteger(quote.updated_at) || quote.updated_at <= 0
        || quote.updated_at > now
        || !Number.isSafeInteger(quote.expires_at)
        || quote.expires_at !== quote.updated_at + funding.native_price_max_age_seconds
        || (!allowExpired && quote.expires_at <= now)) {
        throw new Error('The ETH/USD quote is invalid or stale. Please check again.');
    }
    return quote;
}

/**
 * Validate a quote that is already bound into a proved request payload. Its
 * own fields must be internally consistent and on this deployment's chain, but
 * it is deliberately not compared with the current feed, decimals or maximum
 * age pins: those may change after the proof was made, and re-validating a
 * proof-bound value against mutable configuration would strand its receipt.
 * Callers still require sameNativeQuote against the settlement payload.
 */
export function validateProofBoundQuote(quote, funding) {
    if (!quote || quote.asset !== 'native_eth' || quote.units_per_eth !== Number(NATIVE_UNITS_PER_ETH)
        || !Number.isSafeInteger(Number(funding?.chain_id)) || quote.chain_id !== Number(funding.chain_id)
        || !ADDRESS.test(quote.feed_address || '') || ZERO.test(quote.feed_address)
        || !Number.isSafeInteger(quote.decimals) || quote.decimals < 0 || quote.decimals > 36
        || !unsigned(quote.round_id) || BigInt(quote.round_id) <= 0n || BigInt(quote.round_id) >= (1n << 80n)
        || !unsigned(quote.answer) || BigInt(quote.answer) <= 0n || BigInt(quote.answer) > 1_000_000_000_000_000_000n
        || !Number.isSafeInteger(quote.updated_at) || quote.updated_at <= 0
        || !Number.isSafeInteger(quote.expires_at) || quote.expires_at <= quote.updated_at
        || quote.expires_at - quote.updated_at > 86_400) {
        throw new Error('The saved request carries an invalid ETH/USD quote.');
    }
    return quote;
}

export function nativeUnitsForUsd(usd, quote) {
    const micros = parseUnits(usd, 6);
    const numerator = micros * NATIVE_UNITS_PER_ETH * 10n ** BigInt(quote.decimals);
    const denominator = BigInt(quote.answer) * 1_000_000n;
    const amount = (numerator + denominator - 1n) / denominator;
    if (micros <= 0n || amount <= 0n || amount > MAX_SAFE) {
        throw new Error('Choose a smaller positive deposit amount.');
    }
    return amount;
}

export function nativeUsdMicros(amount, quote) {
    const units = BigInt(amount);
    if (units < 0n || units > MAX_SAFE) throw new Error('The native ETH amount exceeds the safe ledger range.');
    return units * BigInt(quote.answer) * 1_000_000n
        / (NATIVE_UNITS_PER_ETH * 10n ** BigInt(quote.decimals));
}

export function nativeDepositValue(amount, funding) {
    validateNativeFunding(funding);
    const units = BigInt(amount);
    if (units <= 0n || units > MAX_SAFE) throw new Error('The native ETH deposit amount is invalid.');
    return units * NATIVE_WEI_PER_UNIT;
}

/**
 * `promise`, or a rejection once `signal` aborts: an RPC call ends at its
 * timeout even through a host transport that ignores the signal (E0).
 */
function untilAborted(promise, signal) {
    if (!signal) return promise;
    if (signal.aborted) return Promise.reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
    return new Promise((resolve, reject) => {
        const aborted = () => reject(signal.reason || new DOMException('The operation was aborted.', 'AbortError'));
        signal.addEventListener('abort', aborted, { once: true });
        promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', aborted));
    });
}

async function rpc(funding, method, params, signal) {
    const response = await untilAborted(browserSdkTransport(funding.demo_rpc_url || funding.rpc_url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit',
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal, cache: 'no-store'
    }, { preferProxy: true }), signal);
    if (!response.ok) throw new Error('The ETH price RPC is unavailable. Please check again.');
    const body = await untilAborted(response.json(), signal);
    if (body.error || body.result == null) {
        const error = new Error('The ETH price RPC could not return a verified quote.');
        // The call itself reverted (code 3 on anvil and current geth; older
        // nodes say so only in the message): an answer about the contract,
        // not an unavailable RPC.
        if (body.error && (Number(body.error.code) === 3 || /revert/i.test(String(body.error.message || '')))) {
            error.code = 'rpc_call_reverted';
            // The revert data (a custom error, FailedOp of an EntryPoint dry
            // run): what a sponsored withdrawal decodes.
            if (body.error.data != null) error.data = body.error.data;
            error.rpcMessage = body.error.message || null;
        }
        throw error;
    }
    return body.result;
}

async function assertNativeVaultAtBlock(funding, blockTag, signal) {
    const [scale, token] = await Promise.all(['0x4d1352fd', '0x631b2f10'].map(data =>
        rpc(funding, 'eth_call', [{ to: funding.contract_address, data }, blockTag], signal)));
    if (!/^0x[0-9a-f]{64}$/i.test(scale) || !/^0x[0-9a-f]{64}$/i.test(token)
        || BigInt(scale) !== NATIVE_WEI_PER_UNIT || BigInt(token) !== 0n) {
        throw new Error('The pinned vault does not accept native ETH in the configured denomination.');
    }
}

/**
 * Read one 32-byte word from the pinned vault through the trusted deployment
 * RPC (never the injected wallet or a server-supplied URL), after checking the
 * chain. Used as an independent chain witness for server claims.
 */
export async function readVaultWord(funding, data, {
    blockTag = 'latest',
    signal = AbortSignal.timeout(20_000)
} = {}) {
    validateNativeFunding(funding);
    if (BigInt(await rpc(funding, 'eth_chainId', [], signal)) !== BigInt(funding.chain_id)) {
        throw new Error('The vault RPC is on the wrong chain.');
    }
    const word = await rpc(funding, 'eth_call', [{ to: funding.contract_address, data }, blockTag], signal);
    if (!/^0x[0-9a-f]{64}$/i.test(word || '')) {
        throw Object.assign(new Error('The vault returned an invalid value.'), { code: 'vault_value_invalid' });
    }
    return BigInt(word);
}

/**
 * An EIP-1193-style `request({ method, params })` over the build-pinned RPC,
 * each call bounded by `timeoutMs`. Exit-mode reads (deployment pins, note
 * status, finality, the tree rebuild) use it or the user's exit RPC.
 */
export function pinnedRpcRequest(funding, { timeoutMs = 20_000, signal = null } = {}) {
    validateNativeFunding(funding);
    return ({ method, params = [] }) => {
        const timeout = AbortSignal.timeout(timeoutMs);
        return rpc(funding, method, params, signal ? AbortSignal.any([signal, timeout]) : timeout);
    };
}

/**
 * The same over a user-configured exit RPC URL (design §6.4 E0, §6.6). It is
 * the user's own endpoint, so it is called directly, never through the host's
 * proxy, and without credentials.
 */
export function urlRpcRequest(url, { timeoutMs = 20_000, signal = null, fetchImpl = null } = {}) {
    const target = exitRpcUrl(url);
    return async ({ method, params = [] }) => {
        const timeout = AbortSignal.timeout(timeoutMs);
        const callSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
        const response = await untilAborted((fetchImpl || globalThis.fetch)(target, {
            method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit', cache: 'no-store',
            body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
            signal: callSignal
        }), callSignal);
        if (!response.ok) throw new Error(`The exit RPC answered HTTP ${response.status}.`);
        const body = await untilAborted(response.json(), callSignal);
        if (body.error) {
            throw Object.assign(new Error(body.error.message || 'The exit RPC returned an error.'), {
                code: Number(body.error.code) === 3 || /revert/i.test(String(body.error.message || '')) ? 'rpc_call_reverted' : body.error.code,
                // The revert data (a custom error, FailedOp of an EntryPoint
                // dry run): what a sponsored withdrawal decodes.
                ...(body.error.data != null ? { data: body.error.data } : {})
            });
        }
        return body.result;
    };
}

/** A validated exit RPC URL: HTTPS, or HTTP on loopback; no credentials. */
export function exitRpcUrl(value) {
    let url;
    try {
        url = new URL(String(value));
    } catch {
        throw Object.assign(new Error('The exit RPC URL is invalid.'), { code: 'exit_rpc_invalid' });
    }
    if (url.username || url.password || (url.protocol !== 'https:'
        && !(url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname)))) {
        throw Object.assign(new Error('The exit RPC must be an HTTPS (or loopback) URL without credentials.'), {
            code: 'exit_rpc_invalid'
        });
    }
    return url.href;
}

export async function assertNativeVault(funding, { signal = AbortSignal.timeout(20_000) } = {}) {
    validateNativeFunding(funding);
    if (BigInt(await rpc(funding, 'eth_chainId', [], signal)) !== BigInt(funding.chain_id)) {
        throw new Error('The native ETH RPC is on the wrong chain.');
    }
    await assertNativeVaultAtBlock(funding, 'latest', signal);
    if (BigInt(await rpc(funding, 'eth_chainId', [], signal)) !== BigInt(funding.chain_id)) {
        throw new Error('The native ETH RPC changed chain.');
    }
}

// Reads only: no injected provider, wallet connection, note preparation, or signing.
// One finalized block pins all feed reads. New server quotes must match its
// latest round; saved requests and settlements retain their original quote.
export async function readNativeQuote(funding, { expected = null, signal = AbortSignal.timeout(20_000) } = {}) {
    validateNativeFunding(funding);
    if (expected) validateNativeQuote(expected, funding);
    const chain = await rpc(funding, 'eth_chainId', [], signal);
    if (BigInt(chain) !== BigInt(funding.chain_id)) throw new Error('The ETH price RPC is on the wrong chain.');
    const block = await rpc(funding, 'eth_getBlockByNumber', ['finalized', false], signal);
    if (!/^0x[0-9a-f]+$/i.test(block?.number || '') || !/^0x[0-9a-f]{64}$/i.test(block?.hash || '')) {
        throw new Error('The ETH price RPC returned an invalid block.');
    }
    await assertNativeVaultAtBlock(funding, 'latest', signal);
    const read = data => rpc(funding, 'eth_call', [{ to: funding.native_price_feed_address, data }, block.number], signal);
    const [decimals, encoded] = await Promise.all([
        read('0x313ce567'),
        read('0xfeaf968c')
    ]);
    if (BigInt(decimals) !== BigInt(funding.native_price_feed_decimals)
        || !/^0x[0-9a-f]{320}$/i.test(encoded || '')) throw new Error('The ETH/USD feed returned invalid data.');
    const [round, answer, started, updated, answered] = encoded.slice(2).match(/.{64}/g).map(word => BigInt(`0x${word}`));
    if (answer >= (1n << 255n) || answered < round || started <= 0n || started > updated || updated > MAX_SAFE) {
        throw new Error('The ETH/USD feed round is incomplete.');
    }
    const quote = validateNativeQuote({ asset: 'native_eth', units_per_eth: Number(NATIVE_UNITS_PER_ETH),
        chain_id: funding.chain_id, feed_address: funding.native_price_feed_address.toLowerCase(),
        round_id: String(round), answer: String(answer), decimals: funding.native_price_feed_decimals,
        updated_at: Number(updated), expires_at: Number(updated) + funding.native_price_max_age_seconds }, funding);
    if (expected && !sameNativeQuote(quote, expected)) throw new Error('The billing quote does not match the pinned ETH/USD feed.');
    const canonical = await rpc(funding, 'eth_getBlockByNumber', [block.number, false], signal);
    const finalChain = await rpc(funding, 'eth_chainId', [], signal);
    if (canonical?.hash?.toLowerCase() !== block.hash.toLowerCase() || BigInt(finalChain) !== BigInt(funding.chain_id)) {
        throw new Error('The ETH price block changed. Please check again.');
    }
    return quote;
}

export function sameNativeQuote(left, right) {
    return ['asset', 'units_per_eth', 'chain_id', 'round_id', 'answer', 'decimals', 'updated_at', 'expires_at']
        .every(key => String(left?.[key]) === String(right?.[key]))
        && String(left?.feed_address).toLowerCase() === String(right?.feed_address).toLowerCase();
}

export function requestBillingQuote(request) {
    try {
        const payload = typeof request?.payload === 'string' ? JSON.parse(request.payload) : request?.payload;
        return payload?.billing_quote || null;
    } catch { return null; }
}
