// Merkle paths without the operator (design §6.6): the vault's logs, fetched
// with adaptive chunking, rebuilt in the shipped WebAssembly with a root
// check after every root-bearing event, including retirements.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const originalFetch = globalThis.fetch;
globalThis.fetch = async (input) => {
    const url = new URL(String(input));
    if (url.protocol === 'file:') {
        return new Response(fs.readFileSync(fileURLToPath(url)), { headers: { 'content-type': 'application/wasm' } });
    }
    return new Response('', { status: 404 });
};
test.after(() => { globalThis.fetch = originalFetch; });

const { execute } = await import('../services/zkapiWasmWorker.js');
const glue = await import('../wasm/zkapi_browser.js');
const { ABI } = await import('../wallet.js');
const { fetchVaultTreeLogs, rebuildNotePath, treeEventsFromLogs } = await import('../services/zkapiTreeRebuild.mjs');
// The first operation initializes the shared WebAssembly instance.
await execute('identity', {});

const VAULT = `0x${'5a'.repeat(20)}`;
const word = value => BigInt(value).toString(16).padStart(64, '0');
const hex = value => `0x${BigInt(value).toString(16)}`;
const worker = { call: (operation, payload) => execute(operation, payload) };
const config = {
    protocol_version: 2, chain_id: 31337, contract_address: VAULT,
    request_charge_cap: 500, policy_charge_cap: 500, policy_enabled: false,
    state_signing_key: {
        x: '0x25a4453190e930f9716eebcab165170706d31d1b3969d106a50d7ae374a23d61',
        y: '0x1b0f74306dfce1371752a0d7c7d27359c398b8305798492fd1095074c0639953'
    },
    clearance_signing_key: {
        x: '0x2b8dc190013bb10de72398ca462027f21b7a35eb6cb957b9319d76bd3c3c1b7d',
        y: '0xa6744dc1bc99bf78b29d6e76db2a0b5598c79d1ce2377b9044aa9dc323dd963'
    }
};

/**
 * A scripted vault history: deposits of notes 0–4 across blocks 1,000–9,000,
 * a retirement of note 1, and an escape, a challenge and an expiry claim that
 * each report the then-current root. Returns the logs, the reference tree's
 * paths and each note's state.
 */
async function history() {
    const reference = new glue.BrowserNoteTree();
    const logs = [];
    const notes = [];
    let logIndex = 0;
    const push = (blockNumber, topics, data) => logs.push({ address: VAULT, blockNumber: hex(blockNumber),
        logIndex: hex(logIndex++), topics, data: `0x${data.map(word).join('')}`, removed: false });
    for (let noteId = 0; noteId < 5; noteId += 1) {
        const deposit = await execute('generateDeposit', {});
        const amount = 1_000_000 + noteId;
        const expiry = 4_000_000_000;
        const root = JSON.parse(reference.apply(JSON.stringify({ event: 'note_deposited', note_id: noteId,
            commitment: deposit.registration_commitment, amount: String(amount), expiry_ts: expiry })));
        push(1_000 + noteId * 2_000, [ABI.noteDeposited, `0x${word(noteId)}`, `0x${word(deposit.registration_commitment)}`],
            [amount, expiry, root]);
        const state = await execute('confirmDeposit', { config, args: { secret: deposit.secret, note_id: noteId, amount, expiry_ts: expiry } });
        notes.push({ state, depositRoot: root });
        if (noteId === 2) {
            // An escape and its defeat report the current root (no leaf removal).
            const current = JSON.parse(reference.root());
            push(5_100, [ABI.escapeInitiatedEvent, `0x${word(1)}`], [0x11, 900, 0x22, 6_000, current]);
            push(5_200, [ABI.escapeChallengedEvent, `0x${word(1)}`], [0x11, current]);
            const retired = JSON.parse(reference.apply(JSON.stringify({ event: 'closed_leaf_retired', note_id: 1 })));
            push(5_300, [ABI.closedLeafRetiredEvent, `0x${word(1)}`], [retired]);
        }
    }
    push(9_500, [ABI.expiredClaimedEvent, `0x${word(3)}`], [1_000_003, JSON.parse(reference.root())]);
    const paths = Object.fromEntries([0, 2, 3, 4].map(noteId => [noteId, JSON.parse(reference.path(noteId))]));
    reference.free();
    return { logs, paths, notes };
}

/** An RPC that serves `logs` and refuses ranges wider than `maxRange` blocks. */
function scriptedRpc(logs, { finalized = 10_000, maxRange = 500, chainId = 31337 } = {}) {
    const calls = [];
    const request = async ({ method, params }) => {
        calls.push({ method, params });
        if (method === 'eth_chainId') return hex(chainId);
        if (method === 'eth_getBlockByNumber') {
            assert.deepEqual(params, ['finalized', false]);
            return { number: hex(finalized) };
        }
        if (method === 'eth_getLogs') {
            const [{ address, topics, fromBlock, toBlock }] = params;
            assert.equal(address, VAULT);
            const from = Number(BigInt(fromBlock));
            const to = Number(BigInt(toBlock));
            if (to - from + 1 > maxRange) throw Object.assign(new Error(`query exceeds max block range ${maxRange}`), { code: -32005 });
            // Out of order on purpose: the client sorts by (block, log index).
            return logs.filter(log => {
                const block = Number(BigInt(log.blockNumber));
                return block >= from && block <= to && topics[0].includes(log.topics[0]);
            }).reverse();
        }
        throw new Error(`unexpected RPC ${method}`);
    };
    return { request, calls };
}

test('a rebuilt path equals the vault tree, with retirements and every root checked', async () => {
    const { logs, paths, notes } = await history();
    const rpc = scriptedRpc(logs);
    for (const noteId of [0, 2, 4]) {
        const rebuilt = await rebuildNotePath({ request: rpc.request, vault: VAULT, deployBlock: 900, noteId, chainId: 31337, worker });
        assert.deepEqual({ active_root: rebuilt.active_root, note_id: rebuilt.note_id, siblings: rebuilt.siblings }, paths[noteId]);
        assert.equal(rebuilt.finalizedBlock, 10_000);
        assert.equal(rebuilt.events, logs.length);
        // The path leads from the note's own leaf, so it proves exits.
        assert.equal(await execute('notePathMatches', { state: notes[noteId].state, path: rebuilt }), true);
    }
    // A retired note has no path.
    await assert.rejects(rebuildNotePath({ request: rpc.request, vault: VAULT, deployBlock: 900, noteId: 1, worker }),
        /tree_event_invalid/);
    // The deposit-time path of a note stays a path at the root it was saved
    // with, while later deposits and the retirement move the current root.
    const depositTime = new glue.BrowserNoteTree();
    for (const event of treeEventsFromLogs(logs, VAULT).filter(entry => entry.event === 'note_deposited').slice(0, 1)) {
        const { root: _root, ...applied } = event;
        depositTime.apply(JSON.stringify(applied));
    }
    const saved = JSON.parse(depositTime.path(0));
    depositTime.free();
    assert.equal(saved.active_root, notes[0].depositRoot);
    assert.notEqual(saved.active_root, paths[0].active_root);
    assert.equal(await execute('notePathMatches', { state: notes[0].state, path: saved }), true);
    assert.equal(await execute('notePathMatches', { state: notes[2].state, path: saved }), false);
});

test('log ranges start at 2,000 blocks, halve on a range error down to 100, and grow back after accepted ranges', async () => {
    const { logs } = await history();
    const rpc = scriptedRpc(logs, { maxRange: 500 });
    const progress = [];
    const fetched = await fetchVaultTreeLogs({ request: rpc.request, vault: VAULT, fromBlock: 900, toBlock: 10_000,
        onProgress: entry => progress.push(entry) });
    const sizes = rpc.calls.filter(call => call.method === 'eth_getLogs')
        .map(call => Number(BigInt(call.params[0].toBlock)) - Number(BigInt(call.params[0].fromBlock)) + 1);
    assert.deepEqual(sizes.slice(0, 3), [2_000, 1_000, 500], 'halved until the RPC accepts the range');
    assert.ok(fetched.ranges.every(([from, to]) => to - from + 1 <= 500), 'only accepted ranges are kept');
    // After REBUILD_REGROW_AFTER accepted ranges the range doubles again.
    assert.deepEqual(sizes.slice(2, 8), [500, 500, 500, 500, 1_000, 500]);
    assert.deepEqual(fetched.ranges[0], [900, 1_399]);
    assert.equal(fetched.ranges.at(-1)[1], 10_000, 'up to the finalized block, not beyond');
    assert.equal(fetched.logs.length, logs.length);
    assert.deepEqual(fetched.logs.map(log => log.logIndex), logs.map(log => log.logIndex), 'sorted by block and log index');
    assert.ok(progress.length > 0);
    // An RPC that refuses even 100 blocks fails the rebuild.
    await assert.rejects(fetchVaultTreeLogs({ request: scriptedRpc(logs, { maxRange: 50 }).request, vault: VAULT,
        fromBlock: 900, toBlock: 10_000 }), { code: 'tree_logs_unavailable' });
    // A log past the finalized block is never read.
    const late = await rebuildNotePath({ request: scriptedRpc(logs, { finalized: 6_000 }).request, vault: VAULT,
        deployBlock: 900, noteId: 2, worker });
    assert.equal(late.finalizedBlock, 6_000);
    assert.ok(late.events < logs.length);
});

test('a dense stretch narrows the ranges only while it lasts, and a rebuild ends by its deadline', async () => {
    const { logs } = await history();
    // The RPC limits ranges to 200 blocks only up to block 2,000.
    const calls = [];
    const dense = async ({ method, params }) => {
        if (method === 'eth_chainId') return hex(31337);
        if (method === 'eth_getBlockByNumber') return { number: hex(40_000) };
        const from = Number(BigInt(params[0].fromBlock));
        const to = Number(BigInt(params[0].toBlock));
        calls.push(to - from + 1);
        if (from < 2_000 && to - from + 1 > 200) throw new Error('query returned more than 10000 results');
        return logs.filter(log => {
            const block = Number(BigInt(log.blockNumber));
            return block >= from && block <= to;
        });
    };
    const fetched = await fetchVaultTreeLogs({ request: dense, vault: VAULT, fromBlock: 900, toBlock: 40_000 });
    assert.equal(fetched.logs.length, logs.length);
    assert.equal(Math.max(...fetched.ranges.map(([from, to]) => to - from + 1)), 2_000, 'back to full ranges');
    assert.ok(calls.length < 60, `${calls.length} calls; without regrowth about 200`);

    // An RPC that answers each range slowly, or never, ends at the deadline.
    for (const [label, delay] of [['slow', 25], ['silent', null]]) {
        let reads = 0;
        const stalling = async ({ method }) => {
            if (method === 'eth_chainId') return hex(31337);
            if (method === 'eth_getBlockByNumber') return { number: hex(10_000_000) };
            reads += 1;
            if (delay == null) return new Promise(() => {});
            await new Promise(resolve => setTimeout(resolve, delay));
            return [];
        };
        const started = Date.now();
        await assert.rejects(rebuildNotePath({ request: stalling, vault: VAULT, deployBlock: 0, noteId: 0, chainId: 31337, worker,
            deadline: Date.now() + 120 }), { code: 'tree_rebuild_timeout' }, label);
        assert.ok(Date.now() - started < 3_000, label);
        assert.ok(reads >= 1 && reads <= 8, `${label}: ${reads} reads`);
    }
    // A deadline already past fails before any read.
    await assert.rejects(fetchVaultTreeLogs({ request: () => assert.fail('no read'), vault: VAULT, fromBlock: 0, toBlock: 10,
        deadline: Date.now() - 1 }), { code: 'tree_rebuild_timeout' });
});

test('any log whose root differs from the rebuilt tree stops the rebuild', async () => {
    const { logs } = await history();
    const tamper = (predicate, wordIndex) => logs.map(log => {
        if (!predicate(log)) return log;
        const data = log.data.slice(2).match(/.{64}/g);
        data[wordIndex] = word(0x5);
        return { ...log, data: `0x${data.join('')}` };
    });
    // A deposit, the retirement, and each root-reporting event.
    for (const [topic, index] of [[ABI.noteDeposited, 2], [ABI.closedLeafRetiredEvent, 0], [ABI.escapeInitiatedEvent, 4],
        [ABI.escapeChallengedEvent, 1], [ABI.expiredClaimedEvent, 1]]) {
        const rpc = scriptedRpc(tamper(log => log.topics[0] === topic, index), { maxRange: 20_000 });
        await assert.rejects(rebuildNotePath({ request: rpc.request, vault: VAULT, deployBlock: 900, noteId: 4, worker }),
            /tree_root_mismatch/, topic);
    }
    // A removed log is ignored; a note never deposited has no path.
    const removed = logs.map((log, index) => index === logs.length - 1 ? { ...log, removed: true } : log);
    await rebuildNotePath({ request: scriptedRpc(removed).request, vault: VAULT, deployBlock: 900, noteId: 4, worker });
    await assert.rejects(rebuildNotePath({ request: scriptedRpc(logs).request, vault: VAULT, deployBlock: 900, noteId: 9, worker }),
        { code: 'tree_note_missing' });
    // An RPC on another chain is refused before any log is read.
    await assert.rejects(rebuildNotePath({ request: scriptedRpc(logs, { chainId: 1 }).request, vault: VAULT, deployBlock: 900,
        noteId: 4, chainId: 31337, worker }), { code: 'wrong_network' });
});

test('a lost-journal response is checked in the WebAssembly before its charge counts', async () => {
    const deposit = await execute('generateDeposit', {});
    const state = await execute('confirmDeposit', { config, args: { secret: deposit.secret, note_id: 0, amount: 1_000, expiry_ts: 4_000_000_000 } });
    const response = {
        status: 'finalized', client_request_id: 'lost', request_nullifier: '0x5', response_code: 200,
        response_payload: 'ok', response_hash: '0x1', charge_applied: 10,
        next_commitment: { x: '0x1', y: '0x2' }, next_anchor: '0x3', blind_delta_srv: '0x4',
        next_state_signature: { r_x: '0x1', r_y: '0x2', s: '0x3' }
    };
    await assert.rejects(execute('checkUnrecoverableResponse', { config, state, response }), /^Error: response_identity_mismatch|response_identity_mismatch/);
    const nullifier = await execute('withdrawalNullifier', { state });
    await assert.rejects(execute('checkUnrecoverableResponse', { config, state, response: { ...response, request_nullifier: nullifier } }),
        /response_hash_mismatch/);
});
