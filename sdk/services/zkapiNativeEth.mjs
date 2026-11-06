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

async function rpc(funding, method, params, signal) {
    const response = await browserSdkTransport(funding.demo_rpc_url || funding.rpc_url, {
        method: 'POST', headers: { 'content-type': 'application/json' }, credentials: 'omit',
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }), signal, cache: 'no-store'
    }, { preferProxy: true });
    if (!response.ok) throw new Error('The ETH price RPC is unavailable. Please check again.');
    const body = await response.json();
    if (body.error || body.result == null) throw new Error('The ETH price RPC could not return a verified quote.');
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
export async function readNativeQuote(funding, { expected = null, signal = AbortSignal.timeout(20_000), now } = {}) {
    validateNativeFunding(funding);
    // Callers on the lease path pass trusted server seconds; others keep the device clock.
    const timing = now == null ? {} : { now };
    if (expected) validateNativeQuote(expected, funding, timing);
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
        updated_at: Number(updated), expires_at: Number(updated) + funding.native_price_max_age_seconds }, funding, timing);
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
