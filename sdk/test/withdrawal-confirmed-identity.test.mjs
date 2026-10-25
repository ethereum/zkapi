import assert from 'node:assert/strict';
import test from 'node:test';
import { BrowserWalletRuntime } from '../services/browserWalletRuntime.js';

const destination = `0x${'12'.repeat(20)}`;
function replacedRuntime() {
    const runtime = new BrowserWalletRuntime();
    runtime.manifest = { deployment_id: 'identity-test' };
    runtime.reload = async () => {
        runtime.runtime = { state: { note_id: 7 }, preparedWithdrawal: {
            operationId: 'replacement', noteId: 7, mode: 'mutual', destination
        } };
    };
    runtime.commit = async () => assert.fail('must not change the replacement');
    runtime.remoteJson = async () => assert.fail('must not contact the service');
    return runtime;
}

test('exit preparation rejects a replaced note or operation before proof and service calls', async () => {
    for (const expected of [{ expectedNoteId: 8 }, { expectedWithdrawalOperationId: 'displayed' }]) {
        await assert.rejects(replacedRuntime().prepareExitLocked('mutual', destination, expected),
            { code: 'withdrawal_note_changed' });
    }
});

test('submission refuses a replaced operation, note, mode or payout address', async () => {
    for (const expected of [{ operationId: 'displayed' }, { noteId: 8 }, { mode: 'escape' },
        { destination: `0x${'34'.repeat(20)}` }]) {
        await assert.rejects(replacedRuntime().claimPreparedWithdrawalSubmission(expected),
            { code: 'withdrawal_note_changed' });
    }
});
