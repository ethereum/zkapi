// The deposit gas limit of vault revision 4 (design C.8, docs/deployment.md):
// gasLimit = min(ceil(1.2 · (E + extra)), 1,500,000), where E is the estimate
// at m = nextNoteId and extra covers the costliest index a deposit can land
// at in [m, m + 64): 16,500 per level beyond trailing_ones(m), 7,500 once when
// the estimate hashed no level, and fresh_slot_gas − 5,000 when a first write
// of filled[j] (at 2^j − 1, j ≥ 1) lies in (m, m + 64). The expected values
// below are worked out by hand from that rule.
import assert from 'node:assert/strict';
import test from 'node:test';

import {
    DEPOSIT_GAS_CAP, DEPOSIT_GAS_WINDOW, depositGasExtra, depositGasLimit, trailingOnes
} from '../services/zkapiGas.mjs';

const MAINNET = 22_100;
const SEPOLIA = 110_000;

test('trailing ones', () => {
    for (const [value, ones] of [[0, 0], [1, 1], [2, 0], [3, 2], [6, 0], [7, 3], [63, 6], [64, 0], [95, 5], [255, 8],
        [2 ** 31 - 1, 31], [2 ** 32 - 1, 32], [2 ** 32 + 63, 6]]) {
        assert.equal(trailingOnes(value), ones, String(value));
    }
    assert.throws(() => trailingOnes(-1), TypeError);
    assert.throws(() => trailingOnes(1.5), TypeError);
});

test('the window extra at the brief\'s boundaries', () => {
    assert.equal(DEPOSIT_GAS_WINDOW, 64);
    const cases = [
        // m = 0 (a fresh vault): t_now 0; 63 (six ones) is in the window;
        // 1, 3, …, 63 are first writes after m.
        // 6 · 16,500 + 7,500 + (22,100 − 5,000) = 123,600.
        [0, MAINNET, { extra: 123_600n, tNow: 0, tMax: 6, firstWrite: true }],
        // The same with a 110,000-gas fresh slot (Sepolia, EIP-8037): + 87,900.
        [0, SEPOLIA, { extra: 211_500n, tNow: 0, tMax: 6, firstWrite: true }],
        // m = 1: t_now 1, the estimate already hashed one level (no 7,500);
        // 3 is a first write after m. 5 · 16,500 + 17,100 = 99,600.
        [1, MAINNET, { extra: 99_600n, tNow: 1, tMax: 6, firstWrite: true }],
        // m = 2^k − 1 crossing within the window: m = 60 reaches 63.
        // 6 · 16,500 + 7,500 + 17,100 = 123,600.
        [60, MAINNET, { extra: 123_600n, tNow: 0, tMax: 6, firstWrite: true }],
        // m = 63 = 2^6 − 1 itself: the estimate pays its six levels and its
        // first write of filled[6]; 127 is just outside [63, 127). Nothing extra.
        [63, MAINNET, { extra: 0n, tNow: 6, tMax: 6, firstWrite: false }],
        // m = 64: 127 (seven ones, the first write of filled[7]) is the window's last index.
        // 7 · 16,500 + 7,500 + 17,100 = 140,100.
        [64, MAINNET, { extra: 140_100n, tNow: 0, tMax: 7, firstWrite: true }],
        // m = 128: 191 (six ones) is the costliest, and every filled[] slot up
        // to 7 already exists. 6 · 16,500 + 7,500 = 106,500.
        [128, MAINNET, { extra: 106_500n, tNow: 0, tMax: 6, firstWrite: false }],
        [128, SEPOLIA, { extra: 106_500n, tNow: 0, tMax: 6, firstWrite: false }],
        // m = 200 reaches 255 (eight ones, the first write of filled[8]).
        // 8 · 16,500 + 7,500 + 17,100 = 156,600.
        [200, MAINNET, { extra: 156_600n, tNow: 0, tMax: 8, firstWrite: true }],
        // m = 255: the estimate itself is at the eight-level first write.
        [255, MAINNET, { extra: 0n, tNow: 8, tMax: 8, firstWrite: false }],
        // Near 2^20: 2^20 − 1 (twenty ones) is 9 deposits ahead.
        // 20 · 16,500 + 7,500 + 17,100 = 354,600.
        [2 ** 20 - 10, MAINNET, { extra: 354_600n, tNow: 0, tMax: 20, firstWrite: true }],
        // The costliest index of all, 2^31 − 1: the estimate covers it.
        [2 ** 31 - 1, MAINNET, { extra: 0n, tNow: 31, tMax: 31, firstWrite: false }]
    ];
    for (const [nextNoteId, freshSlotGas, expected] of cases) {
        assert.deepEqual(depositGasExtra({ nextNoteId, freshSlotGas }), expected, `m = ${nextNoteId}, fresh slot ${freshSlotGas}`);
    }
});

test('the limit pads the estimate plus the extra by 20% (rounded up) and is capped at 1,500,000', () => {
    // GasBaseline's deposit #0 (68,327) at m = 0 on mainnet rules:
    // ceil(1.2 · (68,327 + 123,600)) = ceil(230,312.4) = 230,313.
    assert.equal(depositGasLimit({ estimate: 68_327n, nextNoteId: 0, freshSlotGas: MAINNET }), 230_313n);
    // Deposit #63 (136,648 incl. its own first write) adds nothing: ceil(163,977.6).
    assert.equal(depositGasLimit({ estimate: 136_648n, nextNoteId: 63, freshSlotGas: MAINNET }), 163_978n);
    // A hex estimate from the wallet works the same.
    assert.equal(depositGasLimit({ estimate: '0x10ae7', nextNoteId: 0, freshSlotGas: MAINNET }), 230_313n);
    // A fresh slot priced at 110,000 raises the limit by 1.2 · 87,900.
    assert.equal(depositGasLimit({ estimate: 68_327n, nextNoteId: 0, freshSlotGas: SEPOLIA }), 230_313n + 105_480n);
    // Never above the cap.
    assert.equal(DEPOSIT_GAS_CAP, 1_500_000n);
    assert.equal(depositGasLimit({ estimate: 1_400_000n, nextNoteId: 0, freshSlotGas: SEPOLIA }), 1_500_000n);
    assert.equal(depositGasLimit({ estimate: 1_249_999n, nextNoteId: 63, freshSlotGas: MAINNET }), 1_499_999n);
    // A deposit landing anywhere in the window fits the limit computed at m:
    // the costliest index's estimate is m's plus at most `extra`.
    for (const m of [0, 1, 60, 64, 200]) {
        const { extra } = depositGasExtra({ nextNoteId: m, freshSlotGas: MAINNET });
        assert.ok(depositGasLimit({ estimate: 68_327n, nextNoteId: m, freshSlotGas: MAINNET }) >= 68_327n + extra);
    }
});

test('a deposit gas limit needs a pinned fresh-slot gas and a valid note id', () => {
    for (const freshSlotGas of [undefined, null, 0, 5_000, -1, 1.5, '22100']) {
        assert.throws(() => depositGasLimit({ estimate: 1n, nextNoteId: 0, freshSlotGas }), { code: 'deposit_gas_unpinned' },
            String(freshSlotGas));
    }
    for (const nextNoteId of [-1, 2 ** 32, 1.5, Number.NaN]) {
        assert.throws(() => depositGasExtra({ nextNoteId, freshSlotGas: MAINNET }), { code: 'deposit_gas_invalid' }, String(nextNoteId));
    }
    assert.throws(() => depositGasLimit({ estimate: 0n, nextNoteId: 0, freshSlotGas: MAINNET }), /invalid gas estimate/);
});
