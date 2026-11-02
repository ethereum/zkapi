import assert from 'node:assert/strict';
import test from 'node:test';

import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';

test('wallet status never exposes the private anchor or commitment to host subscribers', async () => {
    const runtime = new BrowserWalletRuntime();
    runtime.init = async () => {};
    runtime.runtime = { state: { note_id: 7, secret_s: '0xsecret' }, journal: null };
    runtime.worker = {
        call: async () => ({
            has_note: true,
            pending_request: false,
            note: {
                note_id: 7,
                deposit_amount: 2_000_000,
                current_balance: 1_500_000,
                expiry_ts: 1_800_000_000,
                is_genesis: false,
                current_anchor: '0x1234',
                current_commitment_x: '0xaaaa',
                current_commitment_y: '0xbbbb'
            }
        })
    };

    const status = await runtime.walletStatus();
    assert.deepEqual(status, {
        has_note: true,
        pending_request: false,
        note: {
            note_id: 7,
            deposit_amount: 2_000_000,
            current_balance: 1_500_000,
            expiry_ts: 1_800_000_000,
            is_genesis: false
        }
    });
    assert.doesNotMatch(JSON.stringify(status), /anchor|commitment|secret/);

    runtime.worker.call = async () => ({ has_note: false, pending_request: false, note: null });
    assert.deepEqual(await runtime.walletStatus(), { has_note: false, pending_request: false, note: null });
});
