// The proof worker against the shipped WebAssembly and keys (no mocks of the
// WASM): bundle identity, pinned key loading, one bound per state, the
// successor nullifier, the log rebuild with per-event root checks and the
// stale-device verifier.
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const sdk = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const KEY_ORIGIN = 'https://app.example/zkapi/v2c/proofs/';
const fetched = [];
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    fetched.push(url.href);
    if (url.protocol === 'file:') {
        return new Response(fs.readFileSync(fileURLToPath(url)), { headers: { 'content-type': 'application/wasm' } });
    }
    if (url.href.startsWith(KEY_ORIGIN)) {
        const file = path.join(sdk, 'assets/proofs', url.href.slice(KEY_ORIGIN.length));
        return fs.existsSync(file) ? new Response(fs.readFileSync(file)) : new Response('', { status: 404 });
    }
    return new Response('', { status: 404 });
};
test.after(() => { globalThis.fetch = originalFetch; });

const { execute } = await import('../services/zkapiWasmWorker.js');
const glue = await import('../wasm/zkapi_browser.js');
const manifest = JSON.parse(fs.readFileSync(path.join(sdk, 'assets/manifest.json'), 'utf8'));

const sha256 = file => crypto.createHash('sha256').update(fs.readFileSync(path.join(sdk, 'assets/proofs', file))).digest('hex');
const key = file => ({ url: `${KEY_ORIGIN}${file}`, sha256: sha256(file) });
// The retired Sepolia keys: valid Baby-JubJub points, nothing more.
const config = {
    protocol_version: 2, chain_id: 31337, contract_address: '0x1234',
    request_charge_cap: 500000, policy_charge_cap: 500000, policy_enabled: false,
    state_signing_key: {
        x: '0x25a4453190e930f9716eebcab165170706d31d1b3969d106a50d7ae374a23d61',
        y: '0x1b0f74306dfce1371752a0d7c7d27359c398b8305798492fd1095074c0639953'
    },
    clearance_signing_key: {
        x: '0x2b8dc190013bb10de72398ca462027f21b7a35eb6cb957b9319d76bd3c3c1b7d',
        y: '0xa6744dc1bc99bf78b29d6e76db2a0b5598c79d1ce2377b9044aa9dc323dd963'
    }
};

async function genesisNote(noteId = 0) {
    const deposit = await execute('generateDeposit', {});
    const state = await execute('confirmDeposit', {
        config, args: { secret: deposit.secret, note_id: noteId, amount: 1_000_000, expiry_ts: 4_000_000_000 }
    });
    return { deposit, state };
}

test('the worker runs the shipped bundle of the manifest circuit and setup', async () => {
    assert.deepEqual(await execute('identity', {}),
        { circuit_id: 'zkapi-v2-concession-v1', setup_id: manifest.setupId });
    assert.ok(fetched.some(url => url.endsWith('/wasm/zkapi_browser_bg.wasm')));
});

test('every key is loaded only with its SHA-256 pin', async () => {
    const { state } = await genesisNote();
    const args = { mode: 'ownership', valid_until: 1, active_root: '0x1', merkle_siblings: [] };
    await assert.rejects(execute('prepareWithdrawal', { config, state, args, provingKey: { url: `${KEY_ORIGIN}withdrawal.pk` } }),
        /pinned SHA-256/);
    await assert.rejects(execute('verifyRequest', { publicInputs: {}, proof: '', verifyingKey: { ...key('request.vk'), sha256: '0'.repeat(64) } }),
        /integrity/);
    await assert.rejects(execute('verifyRequest', { publicInputs: {}, proof: '', verifyingKey: { url: `${KEY_ORIGIN}missing.vk`, sha256: '0'.repeat(64) } }),
        /Unable to load/);
    // A withdrawal key is not a request verifying key.
    await assert.rejects(execute('verifyRequest', { publicInputs: {}, proof: '', verifyingKey: key('withdrawal.pk') }));
});

test('the successor nullifier is the nullifier an escape publishes, not the current one', async () => {
    const { state } = await genesisNote(3);
    const nullifier = await execute('withdrawalNullifier', { state });
    const successor = await execute('successorNullifier', { state });
    assert.match(nullifier, /^0x[0-9a-f]+$/);
    assert.match(successor, /^0x[0-9a-f]+$/);
    assert.notEqual(nullifier, successor);
    // Note-bound: the same secret at another note id has other nullifiers.
    const other = { ...state, note_id: 4 };
    assert.notEqual(await execute('withdrawalNullifier', { state: other }), nullifier);
});

test('the log rebuild checks the root after every event and yields the note path', async () => {
    const notes = await Promise.all([0, 1, 2].map(() => execute('generateDeposit', {})));
    const reference = new glue.BrowserNoteTree();
    const events = notes.map((deposit, noteId) => {
        const event = { event: 'note_deposited', note_id: noteId, commitment: deposit.registration_commitment,
            amount: String(1_000_000 + noteId), expiry_ts: 4_000_000_000 };
        return { ...event, root: JSON.parse(reference.apply(JSON.stringify(event))) };
    });
    const retired = { event: 'closed_leaf_retired', note_id: 1 };
    events.push({ ...retired, root: JSON.parse(reference.apply(JSON.stringify(retired))) });
    const path2 = await execute('rebuildTreePath', { events, noteId: 2 });
    assert.deepEqual(path2, JSON.parse(reference.path(2)));
    assert.equal(path2.siblings.length, 32);
    reference.free();
    // A log whose root disagrees with the rebuilt tree stops the rebuild.
    const tampered = events.map((event, index) => index === 1 ? { ...event, root: '0x5' } : event);
    await assert.rejects(execute('rebuildTreePath', { events: tampered, noteId: 2 }), /tree_root_mismatch: the vault log 1/);
    // A retired note has no path, and an out-of-order deposit is refused.
    await assert.rejects(execute('rebuildTreePath', { events, noteId: 1 }), /tree_event_invalid/);
    await assert.rejects(execute('rebuildTreePath', { events: events.slice(1), noteId: 1 }), /tree_event_invalid/);
    // The dense-leaves form agrees once the leaves are known.
    await assert.rejects(execute('treePathFromLeaves', { leaves: ['0x0'], noteId: 0 }), /tree_event_invalid/);
});

test('a request proof fixes the state bound, and only a valid proof verifies under the pinned request.vk', async () => {
    const { deposit, state } = await genesisNote(0);
    const tree = new glue.BrowserNoteTree();
    tree.apply(JSON.stringify({ event: 'note_deposited', note_id: 0, commitment: deposit.registration_commitment,
        amount: '1000000', expiry_ts: 4_000_000_000 }));
    const pathAt = JSON.parse(tree.path(0));
    tree.free();
    const args = id => ({ payload: '{"mode":"test"}', active_root: pathAt.active_root, merkle_siblings: pathAt.siblings,
        client_request_id: id, request_time: 2_000_000_000, created_at_ms: 1 });
    const prepared = await execute('prepareRequest', { config, state, args: args('first'), provingKey: key('request.pk') });
    assert.equal(state.bound_at_state, 0);
    assert.equal(prepared.state.bound_at_state, 500000, 'the returned state records the bound');
    assert.deepEqual({ ...prepared.state, bound_at_state: 0 }, state);
    assert.equal(prepared.journal.nullifier, await execute('withdrawalNullifier', { state }));
    // Another bound at the same state is refused before proving.
    await assert.rejects(execute('prepareRequest', {
        config: { ...config, request_charge_cap: 400000 }, state: prepared.state, args: args('second'), provingKey: key('request.pk')
    }), /^bound_fixed_at_state: /);
    const request = prepared.request;
    const verify = (publicInputs, proof = request.proof.proof) =>
        execute('verifyRequest', { publicInputs, proof, verifyingKey: key('request.vk') });
    assert.equal(await verify(request.public_inputs), true);
    assert.equal(await verify({ ...request.public_inputs, solvency_bound: 499999 }), false);
    assert.equal(await verify({ ...request.public_inputs, request_nullifier: await execute('successorNullifier', { state }) }), false);
    // A proof from elsewhere or of the wrong size is never a verified answer.
    await assert.rejects(verify(request.public_inputs, Buffer.alloc(255).toString('base64')));
});
