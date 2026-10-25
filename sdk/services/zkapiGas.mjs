// EIP-7825 rejects any Ethereum transaction whose gas limit exceeds 2^24,
// even when the block gas limit itself is higher. Keep the wallet-provided
// estimate comfortably padded, but never create a transaction the network
// cannot accept.
export const MAX_TRANSACTION_GAS_LIMIT = 1n << 24n;

const GAS_MARGIN_NUMERATOR = 12n;
const GAS_MARGIN_DENOMINATOR = 10n;
const GAS_FIXED_PADDING = 50_000n;

export function bufferedGasLimit(estimate) {
    const value = typeof estimate === 'bigint' ? estimate : BigInt(estimate);
    if (value <= 0n) throw new Error('The wallet returned an invalid gas estimate.');
    const buffered = value * GAS_MARGIN_NUMERATOR / GAS_MARGIN_DENOMINATOR + GAS_FIXED_PADDING;
    if (buffered > MAX_TRANSACTION_GAS_LIMIT) {
        const error = new Error('The simulated transaction exceeds Ethereum’s per-transaction gas limit. Nothing was submitted.');
        error.code = 'transaction_gas_limit_exceeded';
        throw error;
    }
    return `0x${buffered.toString(16)}`;
}

// The gas limit an exit is submitted with when the wallet provider's
// simulation refuses it (design §6.4 E4.5: that simulation is advisory). An
// escape initiation costs about 0.37M gas and a mutual close about 0.31M
// under EIP-2929 storage pricing, and about 0.72M and 0.40M where EIP-8037
// prices each fresh storage slot at about 110,000 (Sepolia).
export const EXIT_FALLBACK_GAS_LIMIT = 1_000_000n;

// ---- The deposit gas limit (vault revision 4, design C.8) ----
//
// A deposit appends its leaf to the vault's frontier: at note id m it hashes
// trailing_ones(m) levels and writes filled[trailing_ones(m)], a fresh slot the
// first time that level is filled (at m = 2^t − 1). An estimate at m does not
// cover a deposit that lands later, behind other deposits, at a costlier index,
// so the limit adds what the worst index in the next DEPOSIT_GAS_WINDOW can
// cost on top of the estimate: 16,500 per extra level, 7,500 once when the
// estimate hashed none, and a fresh slot (the profile's fresh_slot_gas, less
// the 5,000 of the overwrite the estimate already paid) when a first write
// 2^j − 1 (j ≥ 1) lies after m in the window. The sum is padded by 20% and
// capped at DEPOSIT_GAS_CAP.

/** Deposits that may land ahead of this one between the estimate and inclusion. */
export const DEPOSIT_GAS_WINDOW = 64;
/** The deposit gas limit never exceeds this (a deposit costs at most ≈0.74M). */
export const DEPOSIT_GAS_CAP = 1_500_000n;
export const DEPOSIT_GAS_PER_LEVEL = 16_500n;
export const DEPOSIT_GAS_FIRST_LEVEL = 7_500n;
/** The overwrite of an existing filled[] slot, which the estimate paid instead of a fresh slot. */
export const DEPOSIT_GAS_OVERWRITE = 5_000n;

function gasError(message, code) {
    return Object.assign(new Error(message), { code });
}

/** The number of trailing one bits of a non-negative safe integer. */
export function trailingOnes(value) {
    if (!Number.isSafeInteger(value) || value < 0) throw new TypeError('trailingOnes takes a non-negative safe integer.');
    let count = 0;
    let rest = value;
    while (rest % 2 === 1) {
        count += 1;
        rest = (rest - 1) / 2;
    }
    return count;
}

/**
 * The gas a deposit landing anywhere in [m, m + window) may need beyond an
 * estimate made at note id m: { extra, tNow, tMax, firstWrite }.
 */
export function depositGasExtra({ nextNoteId, freshSlotGas, window = DEPOSIT_GAS_WINDOW }) {
    const m = Number(nextNoteId);
    if (!Number.isSafeInteger(m) || m < 0 || m >= 2 ** 32) throw gasError('The vault returned an invalid nextNoteId.', 'deposit_gas_invalid');
    const slot = typeof freshSlotGas === 'bigint' ? freshSlotGas : Number.isSafeInteger(freshSlotGas) ? BigInt(freshSlotGas) : null;
    if (slot == null || slot <= DEPOSIT_GAS_OVERWRITE) {
        throw gasError('The deployment profile does not pin a valid fresh_slot_gas, so no deposit gas limit can be set.', 'deposit_gas_unpinned');
    }
    const tNow = trailingOnes(m);
    let tMax = tNow;
    for (let k = m + 1; k < m + window; k += 1) tMax = Math.max(tMax, trailingOnes(k));
    // A first write of filled[j] happens at 2^j − 1; the estimate already
    // covers one at m itself.
    let firstWrite = false;
    for (let j = 1; 2 ** j - 1 < m + window; j += 1) {
        if (2 ** j - 1 > m) {
            firstWrite = true;
            break;
        }
    }
    const extra = DEPOSIT_GAS_PER_LEVEL * BigInt(tMax - tNow)
        + (tNow === 0 && tMax > 0 ? DEPOSIT_GAS_FIRST_LEVEL : 0n)
        + (firstWrite ? slot - DEPOSIT_GAS_OVERWRITE : 0n);
    return { extra, tNow, tMax, firstWrite };
}

/**
 * The gas limit of a deposit (bigint): min(ceil(1.2 · (estimate + extra)),
 * DEPOSIT_GAS_CAP), with `estimate` the eth_estimateGas answer at latest and
 * `nextNoteId` the vault's nextNoteId() at latest.
 */
export function depositGasLimit({ estimate, nextNoteId, freshSlotGas, window = DEPOSIT_GAS_WINDOW }) {
    const value = typeof estimate === 'bigint' ? estimate : BigInt(estimate);
    if (value <= 0n) throw new Error('The wallet returned an invalid gas estimate.');
    const { extra } = depositGasExtra({ nextNoteId, freshSlotGas, window });
    const padded = (12n * (value + extra) + 9n) / 10n;
    return padded < DEPOSIT_GAS_CAP ? padded : DEPOSIT_GAS_CAP;
}
